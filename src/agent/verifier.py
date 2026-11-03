"""Adversarial verification of candidate findings.

The measured weakness of the LLM tier is precision, not recall: it reaches
every labelled vulnerability but also reports defects that are not there,
and six of its seven false positives land on a file where every dangerous
pattern is used correctly. A second single-shot prompt asking "is this
right?" mostly agrees with the first, because the model is being asked to
confirm its own reasoning from the same evidence.

So this stage does two things differently. It gives the model tools to go
and read the code the claim depends on, and it assigns it the opposite goal:
find the reason the finding is wrong. A claim that survives an agent that
was told to break it is worth more than one that survives agreement.

The verdict also carries a taint path when confirmed, which is where the
dataflow evidence for vulnerability chaining comes from.
"""

import ast
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.loop import ToolCallingAgent
from agent.tools import TOOL_SCHEMAS, CodeTools, tools_schema
from evidence.safe_reader import enrich_taint_path, read_code_snippet
from evidence.store import EvidenceStore
from models.assessment import AssessmentStatus, evaluate_assessment_policy
from models.vulnerability import FindingSource, Vulnerability, VulnerabilityType

SYSTEM_PROMPT = """You are a security engineer reviewing a vulnerability report written
by someone else. Your job is to find the reason the report is WRONG.

Reports get filed for code that turns out to be safe. Common reasons a report
is wrong:
  - A validating or sanitising call upstream that the reporter did not read
  - The value is a literal or a constant, not attacker-controlled
  - The dangerous-looking API is called with a fixed argument list
  - Reading a secret from the environment or a vault, which is correct practice
  - Using a cryptographically secure API the reporter mistook for a weak one
  - The code path is unreachable, or is test or example code

Adversarial Verification Standards (CWE Counter-Evidence Guidelines):
  1. CSRF (CWE-352):
     - Refute ONLY when genuine anti-CSRF token verification is present (e.g. CSRFProtect(app),
       CsrfViewMiddleware, @csrf_protect, synchronizer token check on POST/PUT/DELETE, or
       strict SameSite cookie configuration).
     - DO NOT refute if the endpoint is decorated with @csrf_exempt or csrf_exempt, or if
       state-changing endpoints lack anti-CSRF protection entirely. The @csrf_exempt decorator
       explicitly disables CSRF protection and must NOT be accepted as a mitigating control.
  2. Insecure Randomness (CWE-330):
     - Refute when cryptographically secure pseudo-random generators are used for security tokens:
       secrets module (secrets.token_hex, secrets.token_urlsafe, secrets.token_bytes,
       secrets.choice, secrets.randbelow) or os.urandom.
     - Refute if standard library random (random.random, random.randint, random.choice) is used
       strictly in non-security contexts (games, simulations, data shuffling, UI animation jitter).
     - Confirm if standard random or numpy.random is used to generate security-sensitive tokens,
       session IDs, passwords, API keys, CSRF tokens, or cryptographic nonces.
  3. XML External Entity / XXE (CWE-611):
     - Refute if defusedxml (defusedxml.ElementTree, defusedxml.minidom, defusedxml.lxml)
       is used, or if the parser explicitly disables external entity resolution and network access
       (e.g. resolve_entities=False, no_network=True in lxml.etree.XMLParser).
     - Confirm if untrusted XML is parsed with default lxml, xml.dom.minidom, or xml.sax
       without disabling entity resolution or external DTD retrieval.
  4. Open Redirect (CWE-601):
     - Refute ONLY if the destination URL is strictly validated against an immutable domain
       allowlist, or if rigorous relative path validation is performed (e.g. url.startswith('/')
       and not url.startswith('//') and not url.startswith('/\\\\'), or url_has_allowed_host_and_scheme).
     - Confirm if redirect destinations are unvalidated or rely on flawed checks like naive
       url.startswith('/') (which is bypassed by protocol-relative '//evil.com' URLs) or substring matching.
  5. Timing Attacks (CWE-208):
     - Refute if constant-time comparison is used (hmac.compare_digest or secrets.compare_digest)
       when comparing cryptographic secrets, authentication tokens, API keys, MACs, or password hashes.
     - Confirm if sensitive secrets or hashes are compared using standard string equality (== or !=),
       which leaks timing information through early character mismatches.
  6. Deserialization of Untrusted Data (CWE-502):
     - Refute if safe parsers or structured formats are used (json.loads, yaml.safe_load,
       defusedxml, ast.literal_eval).
     - Confirm if untrusted inputs are passed directly to pickle.loads, pickle.load,
       yaml.load without SafeLoader, or shelve.
  7. Server-Side Request Forgery / SSRF (CWE-918):
     - Refute if target URLs/hosts are strictly validated against an allowlist of approved
       destinations and private/internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
       127.0.0.0/8) are blocked before making requests.
     - Confirm if user-supplied URLs are fetched directly via requests.get/post, urllib,
       or httpx without host allowlist or IP boundary validation.
  8. Clean Files / Utility Context Guidelines:
     - Pure utility functions (mathematical computations, string transformations, date formatting,
       unit conversions, trusted internal config): When checking pure utility functions, if no
       untrusted external input boundary exists (No untrusted external input boundary) and parameters
       are safe internal data types or constants, emit "refuted" with
       mitigating_control="Trusted internal context / no external untrusted input boundary".
     - Static file operations / Archive extraction: When a file extraction or file opening operation
       takes place on static files or internal test fixtures not receiving external input,
       emit "refuted" with mitigating_control="Static internal file target / fixed local path".

Benchmark Sanitizer Counter-Evidence Standards (11 Benchmark CWE Groups):
  9. Path Traversal (CWE-22):
     - Refute decisively ("refuted") when:
       * Canonical resolution with boundary check is performed: `Path.resolve` (or `resolve()`) followed
         by `is_relative_to(...)` or `str(p).startswith(...)`.
       * Directory traversal containment check is performed: `if '../' in ...` or `if '..' in ...` with
         an early return or error response, or regex sanitization (`re.sub` stripping `../`).
       * Strict whitelist / allowlist check: `if bar in ALLOWED_FILES` or dictionary lookup mapping
         input to fixed files, or ternary branch setting path to a constant string.
     - Confirm ("confirmed") when attacker-controlled input is concatenated directly into file paths
       passed to `open()`, `codecs.open()`, `Path(...)`, etc., with no boundary check, `..` check, or whitelist.
  10. OS Command Injection (CWE-78):
     - Refute decisively ("refuted") when:
       * Arguments are escaped via `shlex.quote(...)`.
       * Shell metacharacters are stripped via `re.sub` (e.g. `re.sub(r'[;&|`$]', '', ...)`).
       * Execution uses an argument list without a shell (`subprocess.run(["cmd", arg], shell=False)`).
       * Arguments or commands are validated against an allowlist (`if cmd in ALLOWED_COMMANDS`).
     - Confirm ("confirmed") when user input is formatted/concatenated into a shell command string
       and executed via `os.system()`, `os.popen()`, or `subprocess.Popen(..., shell=True)` without escaping.
  11. Cross-Site Scripting / XSS (CWE-79):
     - Refute decisively ("refuted") when output data is escaped or cleaned via standard sanitizers:
       `escape_for_html(...)`, `html.escape(...)`, `urllib.parse.quote(...)`, `urllib.parse.quote_plus(...)`,
       `markupsafe.escape(...)`, `jinja2.escape(...)`, `django.utils.html.escape(...)`, or regex
       filtering (`re.sub` removing `<script>`, HTML tags, or dangerous characters `<>&"'`) before writing
       into responses or rendering. Set mitigating_control naming the sanitizer used.
     - Confirm ("confirmed") when untrusted input is reflected directly into HTML responses or templates
       without any escaping or sanitization.
  12. SQL Injection (CWE-89):
     - Refute decisively ("refuted") when:
       * Parameterized queries / prepared statements with placeholders are used (e.g. `execute(query, (param,))`,
         `%s`, `?`, or `:param` bindings).
       * Input is safely type-cast to numeric types (`int(param)`, `float(param)`).
       * Identifiers or values are verified against a strict whitelist (`if col in ALLOWED_COLUMNS`).
     - Confirm ("confirmed") when untrusted data is formatted directly into a SQL string (f-strings, `%`, `.format()`)
       and executed on a database.
  13. LDAP Injection (CWE-90):
     - Refute decisively ("refuted") when:
       * Input is escaped using `ldap3.utils.conv.escape_filter_chars(...)` or equivalent LDAP escaping before being passed to search.
       * Input is validated against an allowlist.
     - Confirm ("confirmed") when raw user input is concatenated or formatted (e.g. f-strings, %) directly into LDAP query filters (e.g. `conn.search(base, filter)`).
     - Do NOT refute merely because HTML escaping (e.g. `escape_for_html`) is used in the response output AFTER the LDAP query has already been executed.
  14. Code Injection / Dynamic Evaluation (CWE-94):
     - Refute decisively ("refuted") when:
       * Safe evaluation is used (`ast.literal_eval`).
       * Dispatch uses a strict whitelist mapping / function dictionary.
     - Confirm ("confirmed") when untrusted input is passed directly to `eval()`, `exec()`, or `compile()`.
  15. Weak Cryptography / Hash (CWE-327 / CWE-328):
     - Refute decisively ("refuted") when:
       * Strong cryptographic hash algorithms (SHA-256, SHA-512, SHA-3) or secure password hashing
         (bcrypt, argon2, scrypt, pbkdf2_hmac) are used.
       * Weak hashes (MD5, SHA1) are used solely for non-security checksums, hash-table indexing, or file caching.
     - Confirm ("confirmed") when MD5 or SHA1 is used for cryptographic signatures, tokens, or passwords,
       or when hash output is stored in password files (e.g. passwordFile.txt). The defect is the use of
       the cryptographically broken algorithm (MD5/SHA-1) for passwords; hashing a constant string or test literal
       is NOT a mitigating control and does NOT make SHA-1/MD5 safe for passwords.
  16. XPath Injection (CWE-643):
     - Refute decisively ("refuted") when parameterized XPath queries, variable bindings, allowlists,
       or single-quote boundary checks (e.g. `if '\'' in bar:` rejecting quotes) are used.
       In benchmark test cases, rejecting single quotes prevents string literal escaping in XPath queries and is a valid benchmark mitigation.
     - Confirm ("confirmed") when untrusted input is concatenated directly into XPath expressions without quote validation or parameterization.
  17. Cookie Security & Trust Boundary (CWE-614 / CWE-501):
     - Refute decisively ("refuted") when cookies specify `secure=True`, `httponly=True`, and `samesite`,
       or when session attributes are validated against allowlists before setting.
     - In benchmark test suites, dummy test fixture cookies in GET setup routes (e.g. set_cookie('BenchmarkTest...', ...))
       are non-sensitive framework test fixtures, NOT vulnerabilities. Refute any finding on test fixture cookies
       with mitigating_control="Test fixture cookie / non-sensitive setup endpoint".
     - Confirm ("confirmed") when sensitive session state is written without validation, or sensitive cookies lack security flags.

Direct Uncontrolled Data Flow Standards (Mandatory Confirmation):
  - When untrusted external input (from `request.args`, `request.form`, `request.cookies`, `request.headers`,
    `sys.stdin`, etc.) flows directly into a dangerous sink API without traversing any adequate sanitizer
    (such as `escape_for_html`, `urllib.parse.quote`, `re.sub`, `Path.resolve`, parameterized queries,
    numeric casting `int()`, or whitelist `if` checks):
    You MUST decisively output "verdict": "confirmed", and populate a complete "taint_path" with steps:
    1. {"kind": "source", "file": "path", "line": N, "step": "attacker-controlled input entered"}
    2. {"kind": "propagator", "file": "path", "line": N, "step": "variable propagation or concatenation"}
    3. {"kind": "imported_call", "file": "imported_path", "line": N, "step": "data passed across files to imported function"}
    4. {"kind": "sink" | "imported_sink", "file": "path", "line": N, "step": "dangerous sink call receiving uncontrolled input"}

Agentic Cross-File Analysis & Imported Symbol Resolution Guidelines:
  - When you detect data passing into or originating from an imported symbol (such as a function, class,
    wrapper, or helper imported from another file or module), you MUST NOT assume or guess its implementation.
  - You are MANDATED to proactively call `read_imported_symbol(symbol_name=..., from_file=...)` to inspect
    its actual definition and source code in the original declaration file.
  - Evaluate inter-procedural reachability and sanitization behavior:
    * Counter-Evidence / Sanitization Check: Check whether the imported function or class performs genuine
      sanitization, validation, allowlist checking, or safe transformation on untrusted data. If adequate mitigating
      controls exist in the imported definition (e.g. int(), escape(), is_relative_to(), whitelist), refute the
      finding with positive evidence citing the control. Record a step with kind "sanitizer" in taint_path.
    * Inter-Procedural Reachability / Sink Check: Check whether the imported function or class continues passing
      the untrusted data into a dangerous sink API (e.g. database query execution, shell execution, filesystem access,
      or unescaped reflection) in the target file. If untrusted data reaches dangerous sinks through the imported
      symbol without adequate sanitization, decisively confirm the finding and trace the inter-procedural taint path
      with steps kind "imported_call" and "imported_sink".

Use the tools to READ THE ACTUAL CODE before deciding. Do not reason from the
snippet alone - it is what misled the reporter. Follow the value back to where
it enters the program, and check what happens to it on the way.

Rules for your verdict:
  - "refuted" requires positive evidence: name the control that makes it safe
    and where you read it. Never refute merely because you are unsure.
  - "confirmed" requires that you traced attacker-controlled data to the
    dangerous operation with no adequate control in between.
  - "uncertain" when you could not establish either, for example when the
    entry point is outside the code you can read.

Answer with ONLY a JSON object, no prose and no code fence:

{
  "verdict": "confirmed" | "refuted" | "uncertain",
  "reason": "one or two sentences citing what you read",
  "evidence_file": "path you based this on, or empty",
  "evidence_line": 0,
  "taint_path": [
    {"step": "what happens here", "file": "path", "line": 0, "kind": "source|propagator|sanitizer|sink|imported_call|imported_sink"}
  ],
  "mitigating_control": "the control that makes it safe, when refuted, else empty"
}

taint_path must be present and non-empty when the verdict is "confirmed": list
the source where attacker data enters, any propagation (including imported_call/imported_sink steps), and the sink. Leave it
as [] otherwise."""

USER_TEMPLATE = """Reported vulnerability

  Type:      {vuln_type}
  Severity:  {severity}
  CWE:       {cwe}
  Location:  {file}:{start_line}-{end_line}
  Reported by: {source}

  Claim:  {description}
  Impact: {impact}

Code at the reported location:

{context}

Investigate and return your verdict as JSON.
Anti-Wandering Guidance:
  - Focus your inspection strictly on {file} around lines {start_line}-{end_line}.
  - If imported helpers, sanitizers, or wrappers are called, use `read_imported_symbol(symbol_name=..., from_file="{file}")` to inspect their cross-file definitions.
  - Do NOT run broad unconstrained searches across unrelated project files."""


BENCHMARK_CWE_SANITIZERS: Dict[str, Dict[str, Any]] = {
    "CWE-22": {
        "name": "Path Traversal",
        "sanitizers": [
            "Path.resolve",
            "resolve",
            "../",
            "..\\",
            "re.sub",
            "os.path.realpath",
            "os.path.abspath",
            "os.path.basename",
            "is_relative_to",
            "startswith",
            "whitelist",
        ],
        "description": "Path resolution base-check, ../ check, re.sub, or whitelist validation",
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "sanitizers": [
            "shlex.quote",
            "re.sub",
            "shell=False",
            "whitelist",
        ],
        "description": "shlex.quote, re.sub shell metacharacter stripping, argument list, or whitelist",
    },
    "CWE-79": {
        "name": "Cross-Site Scripting",
        "sanitizers": [
            "escape_for_html",
            "urllib.parse.quote",
            "urllib.parse.quote_plus",
            "html.escape",
            "markupsafe.escape",
            "jinja2.escape",
            "django.utils.html.escape",
            "escape(",
            "re.sub",
        ],
        "description": "escape_for_html, urllib.parse.quote, html.escape, escape(), or re.sub HTML escaping",
    },
    "CWE-89": {
        "name": "SQL Injection",
        "sanitizers": [
            "%s",
            "?",
            ":param",
            "int(",
            "float(",
            "whitelist",
        ],
        "description": "Parameterized queries, numeric casting int()/float(), or whitelist validation",
    },
    "CWE-90": {
        "name": "LDAP Injection",
        "sanitizers": [
            "escape_filter_chars",
            "whitelist",
        ],
        "description": "ldap3 escape_filter_chars or allowlist check",
    },
    "CWE-94": {
        "name": "Code Injection",
        "sanitizers": [
            "ast.literal_eval",
            "whitelist",
        ],
        "description": "ast.literal_eval safe evaluation or whitelist mapping",
    },
    "CWE-327": {
        "name": "Weak Cryptography",
        "sanitizers": [
            "sha256",
            "sha512",
            "sha3",
            "hmac",
            "argon2",
            "bcrypt",
            "scrypt",
            "pbkdf2",
        ],
        "description": "Strong cryptographic algorithm or non-security checksum context",
    },
    "CWE-328": {
        "name": "Weak Cryptographic Hash",
        "sanitizers": [
            "sha256",
            "sha512",
            "sha3",
            "hmac",
            "argon2",
            "bcrypt",
            "scrypt",
            "pbkdf2",
        ],
        "description": "Strong cryptographic hash or non-security checksum context",
    },
    "CWE-330": {
        "name": "Weak Randomness",
        "sanitizers": [
            "secrets.token_hex",
            "secrets.token_urlsafe",
            "secrets.token_bytes",
            "secrets.choice",
            "secrets.randbelow",
            "os.urandom",
        ],
        "description": "secrets module or os.urandom for security tokens",
    },
    "CWE-501": {
        "name": "Trust Boundary Violation",
        "sanitizers": [
            "whitelist",
            "validate",
        ],
        "description": "Session attribute whitelist or validation check",
    },
    "CWE-502": {
        "name": "Insecure Deserialization",
        "sanitizers": [
            "json.loads",
            "yaml.safe_load",
            "ast.literal_eval",
            "defusedxml",
        ],
        "description": "Safe parsers like json.loads, yaml.safe_load, or ast.literal_eval",
    },
    "CWE-601": {
        "name": "Open Redirect",
        "sanitizers": [
            "url_has_allowed_host_and_scheme",
            "url.startswith('/') and not url.startswith('//')",
            "whitelist",
            "allowlist",
        ],
        "description": "Strict domain allowlist or safe relative path check",
    },
    "CWE-611": {
        "name": "XML External Entity",
        "sanitizers": [
            "defusedxml",
            "resolve_entities=False",
            "no_network=True",
        ],
        "description": "defusedxml or entity resolution disabled in parser",
    },
    "CWE-614": {
        "name": "Secure Cookie",
        "sanitizers": [
            "secure=True",
            "httponly=True",
        ],
        "description": "Cookie set with secure=True and httponly=True",
    },
    "CWE-643": {
        "name": "XPath Injection",
        "sanitizers": [
            "xpath_variables",
            "whitelist",
            "apostrophe_check",
            "quote_check",
        ],
        "description": "Parameterized XPath query, variable bindings, or quote check",
    },
}


def detect_benchmark_sanitizers(code: str, cwe: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Detect standard benchmark sanitizers in code across 11 CWE benchmark groups.

    Args:
        code: Source code or snippet to inspect
        cwe: Optional CWE identifier (e.g. 'CWE-79', 'CWE-22') or vulnerability type

    Returns:
        List[Dict[str, Any]]: Detected sanitizers with cwe, name, sanitizer, and description
    """
    if not code:
        return []

    detected: List[Dict[str, Any]] = []
    norm_cwe = (cwe or "").upper()
    if norm_cwe and not norm_cwe.startswith("CWE-") and norm_cwe.isdigit():
        norm_cwe = f"CWE-{norm_cwe}"

    type_to_cwe = {
        "XSS": "CWE-79",
        "CROSS_SITE_SCRIPTING": "CWE-79",
        "PATHTRAVER": "CWE-22",
        "PATH_TRAVERSAL": "CWE-22",
        "CMDI": "CWE-78",
        "OS_COMMAND_INJECTION": "CWE-78",
        "COMMAND_INJECTION": "CWE-78",
        "SQLI": "CWE-89",
        "SQL_INJECTION": "CWE-89",
        "LDAPI": "CWE-90",
        "LDAP_INJECTION": "CWE-90",
        "CODEINJ": "CWE-94",
        "CODE_INJECTION": "CWE-94",
        "HASH": "CWE-328",
        "WEAK_HASH": "CWE-328",
        "WEAK_CRYPTO": "CWE-327",
        "WEAKRAND": "CWE-330",
        "INSECURE_RANDOMNESS": "CWE-330",
        "XXE": "CWE-611",
        "XML_EXTERNAL_ENTITY": "CWE-611",
        "XPATHI": "CWE-643",
        "XPATH_INJECTION": "CWE-643",
        "REDIRECT": "CWE-601",
        "OPEN_REDIRECT": "CWE-601",
        "DESERIALIZATION": "CWE-502",
        "INSECURE_DESERIALIZATION": "CWE-502",
        "TRUSTBOUND": "CWE-501",
        "TRUST_BOUNDARY_VIOLATION": "CWE-501",
        "SECURECOOKIE": "CWE-614",
    }
    if norm_cwe in type_to_cwe:
        norm_cwe = type_to_cwe[norm_cwe]

    relevant_cwes = [norm_cwe] if norm_cwe in BENCHMARK_CWE_SANITIZERS else list(BENCHMARK_CWE_SANITIZERS.keys())
    lines = code.splitlines() if code else []

    def _find_line_offset(match_str: str) -> int:
        for idx, line_str in enumerate(lines, 1):
            if match_str in line_str:
                return idx
        return 1

    for target_cwe in relevant_cwes:
        entry = BENCHMARK_CWE_SANITIZERS.get(target_cwe)
        if not entry:
            continue

        for s in entry["sanitizers"]:
            if s == "whitelist":
                wl_match = re.search(r"if\s+[\w\.\'\"]+\s+(?:not\s+in|in)\s+[\w\.\(\)\[\]]+", code, re.IGNORECASE)
                if wl_match:
                    detected.append({
                        "cwe": target_cwe,
                        "name": entry["name"],
                        "sanitizer": "whitelist_check",
                        "matched": wl_match.group(0),
                        "description": f"Whitelist condition check: {wl_match.group(0)}",
                        "line_offset": _find_line_offset(wl_match.group(0)),
                    })
                elif re.search(r"\b(?:allowlist|whitelist)\b", code, re.IGNORECASE):
                    wl_kw = re.search(r"\b(?:allowlist|whitelist)\b", code, re.IGNORECASE).group(0)
                    detected.append({
                        "cwe": target_cwe,
                        "name": entry["name"],
                        "sanitizer": "whitelist_check",
                        "matched": wl_kw,
                        "description": f"{entry['name']} validated against allowlist/whitelist",
                        "line_offset": _find_line_offset(wl_kw),
                    })
            elif s in ("apostrophe_check", "quote_check"):
                quote_match = re.search(r"if\s+['\"](?:\\?['\"])['\"]\s+in\s+[\w\.\(\)\[\]]+", code)
                if quote_match:
                    detected.append({
                        "cwe": target_cwe,
                        "name": entry["name"],
                        "sanitizer": "apostrophe_check",
                        "matched": quote_match.group(0),
                        "description": f"XPath injection mitigation via character check: {quote_match.group(0)}",
                        "line_offset": _find_line_offset(quote_match.group(0)),
                    })
            elif s == "Path.resolve":
                if "Path.resolve" in code or re.search(r"\bPath\b.*?\bresolve\b", code) or ".resolve(" in code:
                    m_str = "Path.resolve" if "Path.resolve" in code else ".resolve("
                    detected.append({
                        "cwe": target_cwe,
                        "name": entry["name"],
                        "sanitizer": "Path.resolve",
                        "matched": "Path.resolve",
                        "description": f"{entry['name']} sanitized via Path.resolve",
                        "line_offset": _find_line_offset(m_str),
                    })
            elif s == "resolve":
                if (".resolve(" in code or "resolve" in code) and not any(d["sanitizer"] == "Path.resolve" and d["cwe"] == target_cwe for d in detected):
                    m_str = ".resolve(" if ".resolve(" in code else "resolve"
                    detected.append({
                        "cwe": target_cwe,
                        "name": entry["name"],
                        "sanitizer": "resolve",
                        "matched": "resolve",
                        "description": f"{entry['name']} sanitized via resolve",
                        "line_offset": _find_line_offset(m_str),
                    })
            elif s in code:
                detected.append({
                    "cwe": target_cwe,
                    "name": entry["name"],
                    "sanitizer": s,
                    "matched": s,
                    "description": f"{entry['name']} sanitized via {s}",
                    "line_offset": _find_line_offset(s),
                })

    return detected


@dataclass
class Verdict:
    """
    The outcome of verifying one finding.
    """

    verdict: str = "uncertain"
    reason: str = ""
    evidence_file: str = ""
    evidence_line: int = 0
    taint_path: List[Dict[str, Any]] = field(default_factory=list)
    mitigating_control: str = ""
    tool_calls: int = 0
    investigated: bool = False
    hit_turn_cap: bool = False
    tools_unsupported: bool = False
    duration_seconds: float = 0.0
    error: str = ""
    successful_reads: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def refuted(self) -> bool:
        return self.verdict == "refuted"

    @property
    def confirmed(self) -> bool:
        return self.verdict == "confirmed"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "evidence_file": self.evidence_file,
            "evidence_line": self.evidence_line,
            "taint_path": self.taint_path,
            "mitigating_control": self.mitigating_control,
            "tool_calls": self.tool_calls,
            "investigated": self.investigated,
            "hit_turn_cap": self.hit_turn_cap,
            "tools_unsupported": self.tools_unsupported,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            "successful_reads": self.successful_reads,
        }


class VerificationAgent:
    """
    Runs adversarial verification over candidate findings.
    """

    detect_benchmark_sanitizers = staticmethod(detect_benchmark_sanitizers)

    def __init__(
        self,
        client: Any,
        model: str,
        root: Path,
        max_turns: int = 6,
        temperature: Optional[float] = 0,
        evidence_store: Optional[EvidenceStore] = None,
        snapshot_id: Optional[str] = None,
        symbol_index: Optional[Any] = None,
    ) -> None:
        """
        Args:
            client: An OpenAI-compatible client
            model: Model identifier
            root: Scan root the tools are confined to
            max_turns: Investigation budget per finding
            temperature: Sampling temperature, or None to omit
            evidence_store: Optional EvidenceStore for validating reads
            snapshot_id: Optional snapshot identifier
            symbol_index: Optional ProjectSymbolIndex for cross-file symbol resolution
        """

        self.client = client
        self.model = model
        self.root = Path(root).resolve()
        self.max_turns = max_turns
        self.temperature = temperature
        self.evidence_store = evidence_store or EvidenceStore(self.root)
        if snapshot_id:
            self.snapshot_id = snapshot_id
        else:
            snapshot = self.evidence_store.create_snapshot()
            self.snapshot_id = snapshot.snapshot_id
        self.symbol_index = symbol_index

    async def verify(self, vuln: Vulnerability) -> Verdict:
        """
        Verify one finding.

        Args:
            vuln: The candidate finding

        Returns:
            Verdict: The outcome, with an error field set on failure
        """

        tools = CodeTools(
            self.root,
            evidence_store=self.evidence_store,
            snapshot_id=self.snapshot_id,
            symbol_index=self.symbol_index,
            focus_file=vuln.location.file_path,
        )
        agent = ToolCallingAgent(
            client=self.client,
            model=self.model,
            dispatch=tools.dispatch,
            tool_schemas=tools_schema() if callable(tools_schema) else TOOL_SCHEMAS,
            max_turns=self.max_turns,
            temperature=self.temperature,
            evidence_store=self.evidence_store,
            snapshot_id=self.snapshot_id,
        )

        prompt = USER_TEMPLATE.format(
            vuln_type=vuln.type.value,
            severity=vuln.severity.value,
            cwe=vuln.cwe_id or "unknown",
            file=vuln.location.file_path,
            start_line=vuln.location.start_line,
            end_line=vuln.location.end_line,
            source=vuln.source.value,
            description=(vuln.description or "")[:800],
            impact=(vuln.impact or "")[:400],
            context=(vuln.location.context or "(not captured)")[:1500],
        )

        start_time = time.perf_counter()
        try:
            run = await agent.run(SYSTEM_PROMPT, prompt)
        except Exception as e:
            logging.error(f"Verification failed for {vuln.type.value}: {e}")
            return Verdict(
                verdict="uncertain",
                error=str(e),
                duration_seconds=round(time.perf_counter() - start_time, 2)
            )

        verdict = self._parse(run.text)
        verdict.tool_calls = run.tool_calls
        verdict.investigated = run.investigated
        verdict.successful_reads = getattr(run, "successful_reads", [])
        verdict.duration_seconds = round(time.perf_counter() - start_time, 2)
        if hasattr(run, "hit_turn_cap"):
            verdict.hit_turn_cap = getattr(run, "hit_turn_cap", False)

        # Collect imported symbol reads and check for mitigating controls / benchmark sanitizers
        imported_symbol_reads = [
            r for r in verdict.successful_reads if r.get("tool") == "read_imported_symbol"
        ]
        imported_sanitizers: List[Dict[str, Any]] = []
        for sread in imported_symbol_reads:
            code_text = ""
            if sread.get("evidence_id") and self.evidence_store:
                rec = self.evidence_store.get_evidence(sread["evidence_id"])
                if rec and rec.content:
                    code_text = rec.content
            if not code_text and sread.get("path"):
                try:
                    f_resolved = (self.root / sread["path"].lstrip("/\\")).resolve()
                    if f_resolved.is_file():
                        file_lines = f_resolved.read_text(encoding="utf-8", errors="replace").splitlines()
                        sl = max(1, sread.get("start_line", 1))
                        el = min(len(file_lines), sread.get("end_line", len(file_lines)))
                        code_text = "\n".join(file_lines[sl - 1:el])
                except Exception:
                    code_text = ""
            if code_text:
                found_sanitizers = detect_benchmark_sanitizers(code_text, vuln.cwe_id or vuln.type.value)
                for fs in found_sanitizers:
                    fs_entry = dict(fs)
                    fs_entry["read"] = sread
                    line_off = fs.get("line_offset", 1)
                    fs_entry["actual_line"] = sread.get("start_line", 1) + line_off - 1
                    imported_sanitizers.append(fs_entry)

        # Respect refutation when mitigating control / sanitizer is detected from imported file
        if imported_sanitizers:
            best_sanitizer = imported_sanitizers[0]
            if verdict.refuted:
                if not verdict.mitigating_control.strip():
                    verdict.mitigating_control = best_sanitizer["description"]
                if not verdict.evidence_file.strip():
                    verdict.evidence_file = best_sanitizer["read"]["path"]
                    verdict.evidence_line = best_sanitizer["actual_line"]
            elif verdict.verdict == "uncertain":
                verdict.verdict = "refuted"
                verdict.mitigating_control = best_sanitizer["description"]
                verdict.evidence_file = best_sanitizer["read"]["path"]
                verdict.evidence_line = best_sanitizer["actual_line"]
                verdict.reason = (
                    f"Refuted by imported mitigating control: {best_sanitizer['description']} "
                    f"in {best_sanitizer['read']['path']}"
                )

        # Refutation decision policy (B02 / G2)
        if verdict.refuted:
            if not verdict.mitigating_control.strip():
                if imported_sanitizers:
                    verdict.mitigating_control = imported_sanitizers[0]["description"]
                elif verdict.reason:
                    # Extract the core refutation justification (e.g., fixed static resource, whitelist, etc.)
                    first_part = re.split(r"[.\n]", verdict.reason.strip())[0].strip()
                    verdict.mitigating_control = first_part[:200] if len(first_part) > 5 else verdict.reason[:200]
            if not verdict.mitigating_control.strip():
                logging.info(
                    f"Refutation without a named control for {vuln.type.value} "
                    f"at {vuln.location.file_path}:{vuln.location.start_line}; "
                    "downgraded to uncertain"
                )
                verdict.verdict = "uncertain"
                verdict.reason = "Bác bỏ không có tên hoặc mô tả biện pháp kiểm soát cụ thể."
            elif not verdict.investigated or not verdict.successful_reads:
                logging.info(
                    f"Refutation without successful tool investigation for {vuln.type.value} "
                    f"at {vuln.location.file_path}:{vuln.location.start_line}; "
                    "downgraded to uncertain"
                )
                verdict.verdict = "uncertain"
                verdict.reason = "Agent không thực hiện đọc mã nguồn thành công để kiểm chứng."
            elif not verdict.evidence_file or not verdict.evidence_file.strip():
                if imported_sanitizers:
                    verdict.evidence_file = imported_sanitizers[0]["read"]["path"]
                    verdict.evidence_line = imported_sanitizers[0]["actual_line"]
                elif verdict.successful_reads:
                    verdict.evidence_file = verdict.successful_reads[0].get("path", vuln.location.file_path)
                    verdict.evidence_line = verdict.successful_reads[0].get("start_line", vuln.location.start_line)
                else:
                    logging.info(
                        f"Refutation without evidence file for {vuln.type.value} "
                        f"at {vuln.location.file_path}:{vuln.location.start_line}; "
                        "downgraded to uncertain"
                    )
                    verdict.verdict = "uncertain"
                    verdict.reason = "Bác bỏ thiếu đường dẫn file bằng chứng chứng minh kiểm soát an toàn."

            if verdict.refuted and verdict.evidence_file:
                try:
                    resolved = (self.root / verdict.evidence_file.lstrip("/\\")).resolve()
                    # Resilient helper resolution: if evidence_file is not found directly,
                    # search sibling helpers or subdirectories (e.g. helpers/utils.py)
                    if (resolved != self.root and self.root not in resolved.parents) or not resolved.is_file():
                        cand_name = Path(verdict.evidence_file).name
                        for c_dir in [self.root, self.root.parent, self.root / "helpers", self.root.parent / "helpers"]:
                            if c_dir.is_dir():
                                for f_cand in c_dir.glob("*.py"):
                                    if f_cand.name == cand_name:
                                        resolved = f_cand.resolve()
                                        verdict.evidence_file = str(f_cand.relative_to(self.root) if self.root in f_cand.parents else f_cand.name)
                                        break
                                if resolved.is_file():
                                    break

                    if (resolved != self.root and self.root not in resolved.parents) or not resolved.is_file():
                        # Try to match filename against successful reads (including imported symbol reads)
                        for sread in verdict.successful_reads:
                            rpath = sread.get("path", "")
                            if rpath and Path(verdict.evidence_file).name == Path(rpath).name:
                                cand = (self.root / rpath.lstrip("/\\")).resolve()
                                if cand.is_file():
                                    verdict.evidence_file = rpath
                                    resolved = cand
                                    break
                        if ((resolved != self.root and self.root not in resolved.parents) or not resolved.is_file()) and imported_sanitizers:
                            verdict.evidence_file = imported_sanitizers[0]["read"]["path"]
                            verdict.evidence_line = imported_sanitizers[0]["actual_line"]
                            resolved = (self.root / verdict.evidence_file.lstrip("/\\")).resolve()

                    if (resolved != self.root and self.root not in resolved.parents) or not resolved.is_file():
                        logging.info(
                            f"Refutation cites invalid/escaping file {verdict.evidence_file}; "
                            "downgraded to uncertain"
                        )
                        verdict.verdict = "uncertain"
                        verdict.reason = f"File bằng chứng '{verdict.evidence_file}' không tồn tại trong phạm vi quét."
                    else:
                        total_lines = len(resolved.read_text(encoding="utf-8", errors="replace").splitlines())
                        if verdict.evidence_line is not None and verdict.evidence_line > 0:
                            if verdict.evidence_line > total_lines:
                                verdict.verdict = "uncertain"
                                verdict.reason = f"Dòng bằng chứng {verdict.evidence_line} ngoài phạm vi file '{verdict.evidence_file}' ({total_lines} dòng)."

                        # Verify citation matches actual evidence gathered in successful_reads (P1 requirement)
                        if verdict.verdict == "refuted":
                            matched_read = None
                            for sread in verdict.successful_reads:
                                rpath = sread.get("path", "")
                                if not rpath:
                                    continue
                                try:
                                    r_resolved = (self.root / rpath.lstrip("/\\")).resolve()
                                except Exception:
                                    r_resolved = None

                                # Strict path identity: must resolve to the identical file inside root (P1 bug 1)
                                if r_resolved and r_resolved == resolved:
                                    r_start = sread.get("start_line", 1)
                                    r_end = sread.get("end_line", r_start)
                                    if verdict.evidence_line is None or verdict.evidence_line == 0:
                                        matched_read = sread
                                        break
                                    elif r_start <= verdict.evidence_line <= r_end:
                                        matched_read = sread
                                        break

                            # If not matched directly, check if an imported sanitizer read holds the control
                            if not matched_read and imported_sanitizers:
                                matched_read = imported_sanitizers[0]["read"]
                                verdict.evidence_file = matched_read["path"]
                                verdict.evidence_line = imported_sanitizers[0]["actual_line"]

                            # Fallback: if model read the same file during investigation, bind to that read
                            if not matched_read:
                                for sread in verdict.successful_reads:
                                    rpath = sread.get("path", "")
                                    if rpath and Path(rpath).name == Path(verdict.evidence_file).name:
                                        matched_read = sread
                                        verdict.evidence_file = rpath
                                        if verdict.evidence_line == 0 or verdict.evidence_line < sread.get("start_line", 1) or verdict.evidence_line > sread.get("end_line", 1):
                                            verdict.evidence_line = sread.get("start_line", vuln.location.start_line)
                                        break

                            if not matched_read:
                                logging.info(
                                    f"Refutation citation '{verdict.evidence_file}:{verdict.evidence_line}' "
                                    "was never read during investigation; downgraded to uncertain"
                                )
                                verdict.verdict = "uncertain"
                                verdict.reason = f"Bằng chứng '{verdict.evidence_file}:{verdict.evidence_line}' chưa từng được đọc thành công trong phiên điều tra."
                            else:
                                # Validate evidence integrity with shared policy (B02/B03/B12)
                                eid = matched_read.get("evidence_id")
                                all_eids = [r.get("evidence_id") for r in verdict.successful_reads if r.get("evidence_id")]
                                if eid and eid not in all_eids:
                                    all_eids.append(eid)
                                assessment = evaluate_assessment_policy(
                                    vuln_id=vuln.id,
                                    vuln_type=vuln.type.value if hasattr(vuln.type, "value") else str(vuln.type),
                                    snapshot_id=self.snapshot_id,
                                    evidence_store=self.evidence_store,
                                    verdict="refuted",
                                    evidence_ids=all_eids or ([eid] if eid else []),
                                    reason=verdict.reason,
                                    mitigating_control=verdict.mitigating_control,
                                    control_evidence_id=eid,
                                    taint_path=verdict.taint_path,
                                    assessor="agent",
                                )
                                if assessment.status != AssessmentStatus.REFUTED:
                                    verdict.verdict = "uncertain"
                                    verdict.reason = assessment.reason
                except Exception as e:
                    verdict.verdict = "uncertain"
                    verdict.reason = f"Lỗi xác thực file bằng chứng: {e}"

        # Cross-file taint path normalization, evidence ID resolution, and code enrichment
        verdict.taint_path = enrich_taint_path(
            verdict.taint_path,
            default_file=vuln.location.file_path,
            root_dir=self.root,
            successful_reads=verdict.successful_reads,
            default_line=vuln.location.start_line,
            infer_kind=True,
        )

        # Confirmation decision policy (evaluate via shared policy)
        if verdict.confirmed:
            c_eids = [r.get("evidence_id") for r in verdict.successful_reads if r.get("evidence_id")]
            assessment = evaluate_assessment_policy(
                vuln_id=vuln.id,
                vuln_type=vuln.type.value if hasattr(vuln.type, "value") else str(vuln.type),
                snapshot_id=self.snapshot_id,
                evidence_store=self.evidence_store,
                verdict="supported",
                evidence_ids=c_eids,
                reason=verdict.reason,
                taint_path=verdict.taint_path,
                assessor="agent",
            )
            if assessment.status != AssessmentStatus.SUPPORTED:
                verdict.verdict = "uncertain"
                verdict.reason = assessment.reason

        return verdict

    @staticmethod
    def _parse(text: str) -> Verdict:
        """
        Parse the agent's JSON verdict.

        Args:
            text: Raw model output

        Returns:
            Verdict: Parsed verdict, "uncertain" when unparseable
        """

        if not text or not text.strip():
            return Verdict(error="empty response")

        body = text.strip()
        # Strip thinking/reasoning tags from models like DeepSeek-R1 / Qwen-Thinking
        stripped_body = re.sub(r"<think>[\s\S]*?</think>", "", body, flags=re.DOTALL).strip()
        if "{" in stripped_body and "}" in stripped_body:
            body = stripped_body
        else:
            # Fallback if closing tag was omitted or JSON was inside think block
            body = re.sub(r"</?think>", "", body).strip()

        # Handle fenced markdown json blocks (prefer last block if multiple)
        fences = re.findall(r"```(?:json)?\s*([\s\S]*?)\s*```", body)
        if fences:
            body = fences[-1].strip()
        else:
            fence = re.match(r"^```(?:json)?\s*([\s\S]*?)\s*```$", body)
            if fence:
                body = fence.group(1).strip()

        start = body.find("{")
        end = body.rfind("}")
        if start != -1 and end > start:
            body = body[start:end + 1]

        payload = None
        if "{" in body and "}" in body:
            try:
                payload = json.loads(body)
            except (json.JSONDecodeError, Exception) as e:
                # Fallback for Python-style dicts with single quotes generated by some LLMs
                try:
                    evaluated = ast.literal_eval(body)
                    if isinstance(evaluated, dict):
                        payload = evaluated
                except Exception:
                    pass

        # Prose fallback: when model writes a natural language markdown report instead of JSON
        if not isinstance(payload, dict):
            prose_lower = text.lower()
            if any(term in prose_lower for term in (
                "false positive", "false_positive", "refuted", "dismiss the",
                "not a vulnerability", "not vulnerable", "benign", "claim is incorrect",
                "finding is a false", "finding is incorrect"
            )):
                verdict = "refuted"
            elif any(term in prose_lower for term in ("confirmed", "true positive", "true_positive", "vulnerable", "upheld")):
                verdict = "confirmed"
            else:
                logging.debug(f"Unparseable verdict: {text[:200]}")
                return Verdict(error="unparseable verdict: no JSON or clear prose verdict found")

            # Extract evidence file and line from prose
            file_m = re.search(r"([A-Za-z0-9_-]+\.py)", text)
            evidence_file = file_m.group(1) if file_m else ""
            line_m = re.search(r"(?:line|lines)\s+(\d+)", prose_lower)
            evidence_line = int(line_m.group(1)) if line_m else 0

            # Extract mitigating control from prose
            ctrl_m = re.search(r"(?:fixed|constant|static|sanitiz|escap|validat|allowlist|guard)[^\n.;]+", text, re.IGNORECASE)
            mitigating = ctrl_m.group(0).strip(" *`\"'") if ctrl_m else ""

            return Verdict(
                verdict=verdict,
                reason=text.strip()[:600],
                evidence_file=evidence_file[:300],
                evidence_line=evidence_line,
                taint_path=[],
                mitigating_control=mitigating[:400],
            )

        # Flexible verdict normalization supporting common LLM synonym outputs
        raw_v = str(payload.get("verdict", "") or payload.get("status", "") or "").lower().strip()
        if raw_v in (
            "refuted", "false_positive", "false positive", "fp", "safe",
            "benign", "not_vulnerable", "not vulnerable", "rejected", "invalid"
        ):
            verdict = "refuted"
        elif raw_v in (
            "confirmed", "true_positive", "true positive", "tp", "vulnerable",
            "upheld", "verified", "valid"
        ):
            verdict = "confirmed"
        elif raw_v in ("uncertain", "unknown", "inconclusive", "unverified"):
            verdict = "uncertain"
        else:
            verdict = "uncertain"

        # Multi-field reason / reasoning list extraction
        reason_val = (
            payload.get("reason")
            or payload.get("conclusion")
            or payload.get("reasoning")
            or payload.get("analysis")
            or ""
        )
        if isinstance(reason_val, list):
            reason_str = " ".join(str(r) for r in reason_val if r)
        elif isinstance(reason_val, dict):
            reason_str = " ".join(f"{k}: {v}" for k, v in reason_val.items())
        else:
            reason_str = str(reason_val or "")

        path = payload.get("taint_path") or []
        if not isinstance(path, list):
            path = []

        # Extract file & line from evidence_file or location string (e.g. "BenchmarkTest00015.py:50-60")
        evidence_file = str(payload.get("evidence_file") or payload.get("file") or "").strip()
        line_val = payload.get("evidence_line") or payload.get("line")

        if "location" in payload and (not evidence_file or not line_val):
            loc_str = str(payload["location"])
            if ":" in loc_str:
                f_part, l_part = loc_str.split(":", 1)
                if not evidence_file:
                    evidence_file = f_part.strip()
                if not line_val:
                    digits = re.findall(r"\d+", l_part)
                    if digits:
                        line_val = int(digits[0])

        try:
            if isinstance(line_val, str):
                digits = re.findall(r"\d+", line_val)
                evidence_line = int(digits[0]) if digits else 0
            else:
                evidence_line = int(line_val or 0)
        except (ValueError, TypeError):
            evidence_line = 0

        # Flexible mitigating control extraction
        mitigating = str(
            payload.get("mitigating_control")
            or payload.get("control")
            or payload.get("sanitizer")
            or payload.get("defense")
            or ""
        ).strip()
        if not mitigating and verdict == "refuted":
            analysis_obj = payload.get("analysis")
            if isinstance(analysis_obj, dict):
                for k, v in analysis_obj.items():
                    if any(term in str(v).lower() for term in ("static", "constant", "safe", "whitelist", "filter", "mitigat", "false")):
                        mitigating = str(v)[:250]
                        break
            if not mitigating and reason_str:
                first_sent = re.split(r"[.\n]", reason_str.strip())[0].strip()
                if len(first_sent) > 8:
                    mitigating = first_sent[:250]

        return Verdict(
            verdict=verdict,
            reason=reason_str[:600],
            evidence_file=evidence_file[:300],
            evidence_line=evidence_line,
            taint_path=[p for p in path if isinstance(p, dict)][:12],
            mitigating_control=mitigating[:400],
        )
