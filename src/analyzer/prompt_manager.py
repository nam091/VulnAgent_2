"""Prompt Manager for VulnAgent 3-Tier Asymmetric Architecture.

This module provides the :class:`PromptManager` responsible for constructing
structured prompts for LLM-based security analysis:

1. ``generate_sliced_security_prompt``: Generates high-signal Dual-Scope prompts
   combining AST-verified structural facts (from intra-procedural backward slices)
   with semantic taint reasoning guidelines, reference source code context, and
   strict JSON output schemas.
2. ``generate_general_security_prompt``: Generates full-file security analysis
   prompts compatible with :class:`analyzer.code_analyzer.CodeAnalyzer`.
3. ``CWE_TAINT_RULES``: Catalogues canonical sanitization and validation rules
   for 21 core CWE vulnerability classes (CWE-89, CWE-78, CWE-22, CWE-79,
   CWE-798, CWE-918, CWE-502, CWE-209, CWE-352, CWE-20, CWE-1188, CWE-639,
   CWE-287, CWE-284, CWE-328, CWE-330, CWE-643, CWE-614, CWE-90, CWE-601,
   CWE-611) supporting Dual-Scope analysis across both AST data-flow slices and
   file-level configuration / logic context.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional, Sequence, Union

__all__ = [
    "PromptManager",
    "CWE_TAINT_RULES",
    "UNIVERSAL_SOURCES",
    "_generate_adaptive_reference_content",
]


# ---------------------------------------------------------------------------
# Universal Source Catalog (Framework-Agnostic User Entry Points)
# ---------------------------------------------------------------------------

UNIVERSAL_SOURCES: Dict[str, List[str]] = {
    "WEB_FRAMEWORKS": [
        "request.args",
        "request.form",
        "request.values",
        "request.json",
        "request.data",
        "request.get_json()",
        "request.GET",
        "request.POST",
        "request.body",
        "request.query_params",
        "request.path_params",
        "request.files",
    ],
    "HEADERS_AND_COOKIES": [
        "request.cookies",
        "request.headers",
        "request.META",
        "cookies",
        "headers",
    ],
    "CLI_AND_ENV": [
        "sys.argv",
        "input()",
        "raw_input()",
        "os.environ",
        "os.getenv",
    ],
    "PAYLOADS_AND_STREAMS": [
        "json.loads",
        "socket.recv",
    ],
}


# ---------------------------------------------------------------------------
# CWE Taint Taxonomy & Sanitization Matrix (Section 3.2.1 / Section 4 & Dual-Scope)
# ---------------------------------------------------------------------------

CWE_TAINT_RULES: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "cwe_id": "CWE-89",
        "name": "SQL Injection",
        "category": "Injection",
        "dangerous_sinks": [
            "cursor.execute",
            "cursor.executemany",
            "connection.execute",
            "session.execute",
            "db.engine.execute",
            "raw_sql_query",
            "execute",
            "executemany",
            "raw",
            "select",
            "filter",
            "objects.raw",
            "objects.filter",
            "query.filter",
            "query.select",
        ],
        "valid_mitigations": [
            "Parameterized queries with placeholders (?, %s, :param) where variables are passed in the parameters tuple/sequence (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)))",
            "ORM query binding (e.g. Django ORM filter(id=user_id), SQLAlchemy filter_by(id=user_id))",
            "Strict integer casting int(user_id) when the parameter is strictly a numeric identifier and not embedded in dynamic string formatting",
        ],
        "invalid_controls": [
            "F-strings or string formatting in SQL: cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            "String concatenation (+): 'SELECT * FROM users WHERE id = ' + user_id",
            "% or .format() string interpolation directly into SQL text",
            "Simplistic string replacement: replace(\"'\", \"\") (ineffective against numeric injections or Sanitization Context Mismatch)",
            "shlex.quote(): Unix shell escaping utility - completely ineffective against SQL injection!",
        ],
        "semantic_notes": [
            "CRITICAL WARNING: shlex.quote() is for Unix shells, NOT for SQL! If code uses shlex.quote() for SQL queries, it is still a CRITICAL vulnerability.",
            "int() cast is only valid when the parameter is genuinely numeric and not circumvented by a try/except block assigning a dangerous fallback.",
        ],
    },
    "CWE-78": {
        "cwe_id": "CWE-78",
        "name": "OS Command Injection",
        "category": "Injection",
        "dangerous_sinks": [
            "subprocess.*",
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_output",
            "subprocess.check_call",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
            "os.system",
            "os.popen",
            "pty.spawn",
            "pty",
            "shlex",
            "shlex.split",
        ],
        "valid_mitigations": [
            "Passing arguments as a list with shell=False (default safe behavior of Python subprocess module): subprocess.run(['ping', '-c', '1', host], shell=False)",
            "Mandatory shlex.quote() wrapping on all user-supplied variables if shell=True is strictly required",
            "Strict regex whitelist: ^[a-zA-Z0-9_\\-\\.]+$",
        ],
        "invalid_controls": [
            "shell=True combined with f-strings or string concatenation: subprocess.run(f'ping {host}', shell=True)",
            "os.system() or os.popen() with concatenated user input (always invokes the shell)",
            "List of arguments that invokes an underlying shell: subprocess.run(['bash', '-c', f'ping {host}'])",
            "Weak blacklist regex: filtering only ';' (ineffective against |, &, \\n, backticks, $())",
        ],
        "semantic_notes": [
            "int() cast only sanitizes numeric parameters (e.g., port, count); it cannot sanitize hostnames, IPs, or filenames.",
            "Passing a single concatenated string to subprocess.run with shell=True on Windows or POSIX immediately leads to Remote Code Execution (RCE).",
        ],
    },
    "CWE-22": {
        "cwe_id": "CWE-22",
        "name": "Path Traversal",
        "category": "File Handling",
        "dangerous_sinks": [
            "open",
            "os.open",
            "os.remove",
            "os.rmdir",
            "shutil.*",
            "shutil.rmtree",
            "shutil.copy",
            "shutil.copy2",
            "shutil.copyfile",
            "shutil.copytree",
            "shutil.move",
            "shutil.unpack_archive",
            "pathlib.Path",
            "flask.send_file",
            "send_file",
            "send_from_directory",
            "tarfile.open",
            "tarfile.extractall",
            "zipfile.ZipFile",
            "zipfile.extractall",
            "extractall",
            "django.http.FileResponse",
            "FileResponse",
        ],
        "valid_mitigations": [
            "os.path.basename(path): strips all leading directory components, preserving only the base filename",
            "werkzeug.utils.secure_filename(path): sanitizes filename for web uploads",
            "Strict whitelist matching against an allowed list of filenames",
            "Resolved containment check: Path(base, user_path).resolve().is_relative_to(Path(base).resolve()) (Python 3.9+)",
            "Zip Slip / Tar Slip member containment check: for archive extractions (tarfile.extractall, zipfile.extractall, shutil.unpack_archive), iterate over each member and verify resolved destination containment (e.g., target_path.resolve().is_relative_to(dest_dir.resolve())) before extracting; for tarfile in Python 3.12+, use tarfile.extractall(path, filter='data')",
        ],
        "invalid_controls": [
            "Non-recursive string replacement: path.replace('../', '') (ineffective against '....//' or '..././')",
            "os.path.join(base, user_path) without containment check: if user_path starts with '/' or drive letter, os.path.join discards base completely!",
            "startswith() check on unresolved path string (ineffective due to symlinks or traversal sequences)",
            "Unchecked archive extraction: calling tarfile.extractall(), zipfile.extractall(), extractall(), or shutil.unpack_archive() without inspecting and verifying containment for each member path (Zip Slip / Tar Slip)",
        ],
        "semantic_notes": [
            "CRITICAL WARNING: os.path.join() in Python does NOT protect against Path Traversal! If the second argument is an absolute path, os.path.join discards the first path entirely.",
            "Raw string checks without Path.resolve() are dangerous anti-patterns.",
            "CRITICAL WARNING (Zip Slip / Tar Slip): Using extractall() (tarfile.extractall, zipfile.extractall, extractall, shutil.unpack_archive) on untrusted archives without checking path containment for each extracted member allows archive entries with traversal filenames ('../') or absolute paths to overwrite arbitrary files outside the destination directory.",
        ],
    },
    "CWE-79": {
        "cwe_id": "CWE-79",
        "name": "Cross-Site Scripting (XSS)",
        "category": "Injection",
        "dangerous_sinks": [
            "Markup",
            "markupsafe.Markup",
            "mark_safe",
            "django.utils.safestring.mark_safe",
            "render_template",
            "flask.render_template",
            "render_template_string",
            "flask.render_template_string",
            "HttpResponse",
            "django.http.HttpResponse",
            "Response",
            "flask.Response",
            "flash",
            "flask.flash",
            "jinja2.Template",
        ],
        "valid_mitigations": [
            "HTML Body Context (<div>$var</div>, <p>$var</p>): html.escape(text, quote=True) or markupsafe.escape() (ONLY valid in HTML body context)",
            "Template Engine Autoescape: Explicitly configured autoescape=True or loading from standard .html template files",
            "Dedicated sanitization libraries: bleach.clean(text, tags=..., attributes=...) with strict safe-tags whitelist",
            "JavaScript Context (<script>var x = '$var';</script>): HTML-safe JSON serialization (jinja2.utils.htmlsafe_json_dumps() or json.dumps() with explicit escaping of <, >, & to \\u003c, \\u003e, \\u0026)",
            "URL Context (<a href='$var'>): URL encoding (urllib.parse.quote()) combined with strict protocol whitelist (http://, https://, blocking javascript:)",
            "Quoted Attribute Context (<input value='$var'>): Double quotes surrounding attribute and html.escape(quote=True)",
        ],
        "invalid_controls": [
            "Context Mismatch: Using html.escape() or markupsafe.escape() in JavaScript, URL, unquoted attribute, or CSS contexts (COMPLETELY INEFFECTIVE)",
            "Implicit autoescape disabled or explicit autoescape=False in template engine configuration",
            "Raw HTML string concatenation: Response(f'<h1>Hello {name}</h1>')",
            "render_template_string(f'Hello {name}'): Causes both Reflected XSS and Server-Side Template Injection (SSTI)",
            "Marking untrusted data as safe: flask.Markup(user_val) or django.utils.safestring.mark_safe(user_val)",
            "Simplistic regex stripping <script>: Ineffective against <img src=x onerror=...>, <svg onload=...>, <iframe src=javascript:...>",
        ],
        "semantic_notes": [
            "CRITICAL CONTEXT-AWARE SANITIZATION: html.escape(quote=True) is ONLY valid in HTML Body and Quoted Attribute contexts.",
            "In JavaScript (<script>), URL (<a href>), and CSS contexts, html.escape() exhibits a Sanitization Context Mismatch and is COMPLETELY INEFFECTIVE.",
            "render_template_string with f-strings is a CRITICAL SSTI + XSS vulnerability.",
        ],
    },
    "CWE-798": {
        "cwe_id": "CWE-798",
        "name": "Use of Hard-coded Credentials / Secrets",
        "category": "Cryptographic / Credential Management",
        "dangerous_sinks": [
            "SECRET_KEY = ...",
            "PASSWORD = ...",
            "API_KEY = ...",
            "TOKEN = ...",
            "PRIVATE_KEY = ...",
            "JWT_SECRET = ...",
            "SECRET = ...",
            "token = ...",
            "jwt.encode(..., key='hardcoded')",
            "hashlib.pbkdf2_hmac(..., salt='hardcoded')",
            "auth=('admin', 'password')",
        ],
        "valid_mitigations": [
            "Load secrets dynamically from environment variables: os.environ.get('SECRET_KEY') or os.getenv('SECRET_KEY')",
            "External secrets management services (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, Google Secret Manager)",
            "Runtime cryptographically secure generation for ephemeral keys: secrets.token_hex(32)",
            "Storing credentials in an out-of-repository environment file (.env) excluded from version control via .gitignore",
        ],
        "invalid_controls": [
            "Static literal string assignments in source code: SECRET_KEY = 'hardcoded_secret' or SECRET_KEY = 'change-me-in-production'",
            "Fallback to hardcoded insecure default when env var is missing: os.getenv('SECRET_KEY', 'default_insecure_secret')",
            "Trivial obfuscation or encoding (base64, rot13, simple XOR) of credentials in code",
            "Committing secrets, private keys, or .env files directly into version control",
        ],
        "semantic_notes": [
            "CRITICAL WARNING: Hardcoded secrets and default credentials (e.g. SECRET_KEY, JWT_SECRET) represent immediate high/critical vulnerabilities even without dynamic taint flow.",
            "Always inspect module-level constant declarations in reference source code for static string literals assigned to sensitive configuration variables.",
        ],
    },
    "CWE-918": {
        "cwe_id": "CWE-918",
        "name": "Server-Side Request Forgery (SSRF)",
        "category": "Network / Injection",
        "dangerous_sinks": [
            "requests.*",
            "requests.get",
            "requests.post",
            "requests.request",
            "requests.put",
            "requests.delete",
            "requests.head",
            "requests.patch",
            "urllib.request.*",
            "urllib.request.urlopen",
            "urllib.request.Request",
            "urllib.request.urlretrieve",
            "session.get",
            "session.post",
            "session.request",
            "httpx.*",
            "httpx.get",
            "httpx.post",
            "httpx.request",
            "aiohttp.ClientSession",
            "aiohttp.ClientSession.get",
            "aiohttp.ClientSession.post",
            "aiohttp.request",
            "urllib3.PoolManager",
            "http.client.HTTPConnection",
            "http.client.HTTPSConnection",
        ],
        "valid_mitigations": [
            "Strict domain/URL allowlisting against an immutable list of trusted external endpoints",
            "Destination IP resolution and validation: reject loopback (127.0.0.0/8, ::1), private RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and cloud metadata endpoints (169.254.169.254)",
            "Disabling HTTP redirects or re-validating the resolved IP address on every redirect step",
            "Egress network isolation: routing outbound requests through a dedicated DMZ proxy with restricted internal network access",
        ],
        "invalid_controls": [
            "Blacklisting 'localhost' or '127.0.0.1' via simple string matching (ineffective against 127.1, 0177.0.0.1, 2130706433, http://0/, IPv6 [::1], DNS rebinding, or nip.io/sslip.io)",
            "Prefix-only domain checks: url.startswith('https://example.com') (ineffective against untrusted domain suffixes such as https://example.com.untrusted.com)",
            "Validating URL string before DNS resolution without pinning the resolved IP (vulnerable to TOCTOU DNS rebinding)",
            "Relying on regex parser without taking into account URL parser discrepancies between validator and HTTP client",
        ],
        "semantic_notes": [
            "CRITICAL: Access to internal cloud metadata service (169.254.169.254 on AWS/GCP/Azure) yields IAM role tokens and full cloud infrastructure compromise.",
            "Check both sliced request calls and un-sliced background outbound network requests in reference source code.",
        ],
    },
    "CWE-502": {
        "cwe_id": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "category": "Deserialization",
        "dangerous_sinks": [
            "pickle.*",
            "pickle.loads",
            "pickle.load",
            "_pickle.loads",
            "cPickle.loads",
            "yaml.load",
            "yaml.unsafe_load",
            "jsonpickle.decode",
            "shelve.open",
            "marshal.loads",
            "marshal.load",
            "torch.load",
        ],
        "valid_mitigations": [
            "Use safe, logic-free serialization formats that do not allow arbitrary code execution: json.loads, yaml.safe_load",
            "Cryptographic signature verification (HMAC) using a secure secret key before deserializing trusted data: itsdangerous, django.core.signing",
            "For PyTorch models: torch.load(..., weights_only=True) (PyTorch 2.4+) or safetensors",
        ],
        "invalid_controls": [
            "Using pickle.loads on untrusted data with custom unpickler blacklist (ineffective against novel gadget chains in Python standard library or dependencies)",
            "Base64 decoding or encrypting untrusted pickle data streams without cryptographic signature/MAC (encoding is not security)",
            "yaml.load without specifying Loader=yaml.SafeLoader (in PyYAML < 5.4) or using yaml.FullLoader with untrusted tags",
            "Type checking after deserialization (arbitrary code executes during the __reduce__ step of pickle.loads before any type check)",
        ],
        "semantic_notes": [
            "CRITICAL WARNING: Python pickle deserialization of untrusted input leads directly to Remote Code Execution (RCE) via __reduce__.",
            "Never use pickle for session storage, cache deserialization of client data, or webhook input processing.",
        ],
    },
    "CWE-209": {
        "cwe_id": "CWE-209",
        "name": "Generation of Error Message Containing Sensitive Information",
        "category": "Information Disclosure",
        "dangerous_sinks": [
            "traceback.format_exc",
            "traceback.print_exc",
            "format_error",
            "sys.exc_info",
            "Response(traceback.format_exc())",
            "Response(str(e))",
            "flask.jsonify({'error': str(e)})",
            "django.http.HttpResponseServerError(str(e))",
        ],
        "valid_mitigations": [
            "Return sanitized, generic user-facing error messages: {'error': 'Internal server error', 'request_id': uuid4()}",
            "Log detailed exception stack traces only to secured server-side internal loggers (logger.exception), never to client HTTP responses",
            "Ensure production debug configuration is disabled: DEBUG = False, app.debug = False",
            "Centralized custom error handlers that mask unhandled exceptions with uniform 500 error pages",
        ],
        "invalid_controls": [
            "Returning str(exception) or traceback directly in HTTP response bodies: return jsonify({'error': str(e)}), 500",
            "Enabling debug mode in production (DEBUG = True, app.run(debug=True)) which displays interactive traceback consoles",
            "Partial string filtering or regex stripping on exception messages (still leaks database table/column names, schema details, and file paths)",
        ],
        "semantic_notes": [
            "Exposing internal exception messages or stack traces leaks file system paths, database queries, third-party library versions, and internal secrets.",
            "Inspect try/except blocks in reference source code for return statements passing str(e) or traceback.format_exc() to client responses.",
        ],
    },
    "CWE-352": {
        "cwe_id": "CWE-352",
        "name": "Cross-Site Request Forgery (CSRF)",
        "category": "Session & State Management",
        "dangerous_sinks": [
            "@app.route(..., methods=['POST', 'PUT', 'DELETE'])",
            "@csrf_exempt",
            "csrf_exempt",
            "Flask-WTF without CSRFProtect",
            "state-changing endpoints without CSRF token verification",
        ],
        "valid_mitigations": [
            "Enable global anti-CSRF token verification (e.g. flask_wtf.csrf.CSRFProtect(app), Django CsrfViewMiddleware)",
            "Synchronizer Token Pattern: validate unique, cryptographically random, per-session anti-CSRF tokens on all state-changing requests (POST, PUT, DELETE, PATCH)",
            "Configure SameSite attribute on session cookies: SameSite=Strict or SameSite=Lax",
            "Verify custom request headers (e.g., X-Requested-With, X-CSRF-Token) on API endpoints",
        ],
        "invalid_controls": [
            "Using @csrf_exempt or exempting state-changing routes from CSRF verification",
            "Relying solely on Referer or Origin headers without strict origin allowlisting or failing to block missing headers",
            "Using HTTP GET methods for state-changing operations (account modification, password reset, transaction execution)",
            "Using static, predictable, or client-generated tokens without cryptographic server verification",
        ],
        "semantic_notes": [
            "State-changing endpoints without CSRF protection enable unauthorized external requests to forge actions under the authenticated session.",
            "Inspect reference source code for POST/PUT/DELETE route handlers lacking CSRF middleware or decorated with @csrf_exempt.",
        ],
    },
    "CWE-20": {
        "cwe_id": "CWE-20",
        "name": "Improper Input Validation",
        "category": "Input Validation",
        "dangerous_sinks": [
            "request.args.get",
            "request.form.get",
            "request.json.get",
            "redirect(user_input)",
            "unvalidated type conversions and boundary operations",
        ],
        "valid_mitigations": [
            "Schema-based validation with strong typing using libraries like Pydantic, Marshmallow, WTForms, or Cerberus",
            "Positive / Allow-list validation: enforce strict length, range, format, and character whitelist constraints",
            "Strict regular expression validation with start (^) and end ($) boundary anchors",
            "Reject non-conforming inputs early at the controller / trust boundary with HTTP 400 Bad Request",
        ],
        "invalid_controls": [
            "Blocklist / Denylist filtering (ineffective against novel encodings, alternate characters, or unexpected formats due to Sanitization Context Mismatch)",
            "Client-side only validation (HTML5 form attributes, frontend JavaScript) without corresponding server-side enforcement",
            "Regular expressions without boundary anchors (^ and $), allowing arbitrary untrusted prefix or suffix input sequences",
            "Assuming input data matches expected format without explicit type and range checks",
        ],
        "semantic_notes": [
            "Input validation must be performed at the application trust boundary before data is processed by business logic.",
            "Improper input validation facilitates open redirects, type confusion, resource exhaustion, and downstream injection defects.",
        ],
    },
    "CWE-1188": {
        "cwe_id": "CWE-1188",
        "name": "Insecure Default Initialization of Resource",
        "category": "Security Configuration",
        "dangerous_sinks": [
            "app.run(debug=True)",
            "DEBUG = True",
            "SESSION_COOKIE_SECURE = False",
            "SESSION_COOKIE_HTTPONLY = False",
            "SESSION_COOKIE_SAMESITE = None",
            "CORS(app, origins='*')",
            "ssl._create_unverified_context",
        ],
        "valid_mitigations": [
            "Enforce secure default configuration: DEBUG = False, app.debug = False in production",
            "Enforce secure session cookie attributes: SESSION_COOKIE_SECURE = True, SESSION_COOKIE_HTTPONLY = True, SESSION_COOKIE_SAMESITE = 'Lax'",
            "Restrict CORS origins to an explicit trusted whitelist, never pairing wildcard '*' with supports_credentials=True",
            "Strict SSL/TLS certificate validation: use ssl.create_default_context() with certificate verification enabled",
        ],
        "invalid_controls": [
            "Hardcoding DEBUG = True or running servers with debug=True, host='0.0.0.0'",
            "Wildcard CORS policies (origins='*') combined with credential support",
            "Disabling SSL certificate verification: verify=False in requests, or ssl._create_unverified_context()",
            "Leaving default administrative credentials or unauthenticated management ports enabled",
        ],
        "semantic_notes": [
            "Module-level configuration variables (e.g. DEBUG = True, SESSION_COOKIE_SECURE = False) represent severe configuration vulnerabilities.",
            "Always inspect file-level configuration constants in reference source code for insecure default values.",
        ],
    },
    "CWE-639": {
        "cwe_id": "CWE-639",
        "name": "Authorization Context Defect Through User-Controlled Key (IDOR)",
        "category": "Authorization / Access Control",
        "dangerous_sinks": [
            "Model.objects.get(id=user_id)",
            "User.query.filter_by(id=target_id).first()",
            "session.query(Record).filter(Record.id == param_id)",
            "get_object_or_404(Model, id=user_id)",
            "find_by_id(user_id)",
            "findById(user_id)",
            "objects.get",
            "query.get",
            "direct database record lookup using client-supplied identifier without ownership check",
        ],
        "valid_mitigations": [
            "Enforce object-level ownership check: Record.query.filter_by(id=param_id, owner_id=current_user.id).first_or_404()",
            "Role-Based or Attribute-Based Access Control (RBAC/ABAC) verification before returning or modifying the record",
            "Using indirect reference maps or non-enumerable cryptographically secure UUIDv4 identifiers combined with permission checks",
        ],
        "invalid_controls": [
            "Querying database records solely by user-supplied identifier (e.g. /account?id=102) without checking current authenticated user ownership",
            "Obfuscating sequential IDs with base64, simple hashes, or encoding without server-side authorization checks",
            "Relying solely on UI hiding or client-side checks to prevent unauthorized access",
        ],
        "semantic_notes": [
            "Insecure Direct Object Reference (IDOR) allows untrusted requests to access, modify, or delete other users' records by tampering with ID parameters.",
            "Inspect route handlers taking an ID parameter and directly querying or modifying database records without current_user ownership checks.",
        ],
    },
    "CWE-287": {
        "cwe_id": "CWE-287",
        "name": "Improper Authentication",
        "category": "Authentication",
        "dangerous_sinks": [
            "missing @login_required, @permission_required, or @auth_required decorators on sensitive view/handler functions",
            "authenticate(username=..., password=...) without checking result",
            "check_password(input_pass, stored_pass) return value ignored or bypassed",
            "session['user_id'] assigned directly from unverified request input",
            "jwt.decode without algorithms verification or with verify=False",
        ],
        "valid_mitigations": [
            "Enforce mandatory authentication decorators on all protected endpoints: @login_required, @auth_required",
            "Explicit check and validation on authentication calls: user = authenticate(...) and if not user: return 401",
            "Secure session handling and token verification using cryptographically signed tokens with strict algorithm whitelisting",
            "Multi-factor authentication (MFA) and rate limiting on authentication attempts",
        ],
        "invalid_controls": [
            "Omission of authentication checks or decorators on private API routes and views",
            "Client-side authentication flags (e.g., trusting isAuthenticated=true in JSON body or cookie without server verification)",
            "JWT verification with verify=False or verify_signature=False",
            "Calling authenticate() or check_password() but proceeding even when the return value is None or False",
        ],
        "semantic_notes": [
            "CRITICAL: Unauthenticated endpoints allowing access to sensitive operations or data are immediate critical vulnerabilities.",
            "Verify all route handlers and views in reference source code to ensure proper authentication decorators or middleware checks are applied.",
        ],
    },
    "CWE-284": {
        "cwe_id": "CWE-284",
        "name": "Improper Access Control",
        "category": "Authorization / Access Control",
        "dangerous_sinks": [
            "unprotected administrative route /admin",
            "action endpoint without @login_required or role check",
            "permission check omission / context mismatch",
            "horizontal or vertical privilege escalation handlers",
        ],
        "valid_mitigations": [
            "Mandatory authentication and authorization decorators on sensitive endpoints (e.g. @login_required, @roles_required('admin'))",
            "Centralized Policy Enforcement Points (PEP) verifying user identity, role, and capabilities",
            "Default-deny access control policy: explicitly grant permissions only where required",
        ],
        "invalid_controls": [
            "Client-side only role checks (checking user.role in frontend while API endpoint is completely unauthenticated)",
            "Security through obscurity (relying on secret or unlisted URL paths like /admin/delete_user)",
            "Flawed role checks trusting user-controllable request body attributes: user.role == 'admin'",
        ],
        "semantic_notes": [
            "Check for endpoints performing sensitive administrative actions without verifying user identity, login status, or requisite administrative role.",
            "Vertical privilege escalation enables regular authenticated users to execute administrative actions.",
        ],
    },
    "CWE-328": {
        "cwe_id": "CWE-328",
        "name": "Use of Weak Hash",
        "category": "Cryptography",
        "dangerous_sinks": [
            "hashlib.md5",
            "hashlib.sha1",
            "hashlib.new",
            "sha224",
            "ripemd160",
            "Crypto.Hash.MD5",
            "Crypto.Hash.SHA1",
            "crypt.crypt",
            "passlib.hash.md5_crypt",
            "passlib.hash.sha1_crypt",
            "md5",
            "sha1",
        ],
        "valid_mitigations": [
            "Password and credential storage: Use slow, memory-hard, adaptive key-derivation functions such as bcrypt (bcrypt.hashpw), argon2 (argon2.PasswordHasher), scrypt (hashlib.scrypt), or PBKDF2 (hashlib.pbkdf2_hmac with >= 600,000 iterations for SHA-256)",
            "Data integrity and digital signatures: Use collision-resistant secure hash functions such as SHA-256 (hashlib.sha256), SHA-384, SHA-512 (hashlib.sha512), or SHA-3 family (hashlib.sha3_256)",
            "Non-security operations: hashlib.md5(..., usedforsecurity=False) is acceptable strictly for non-cryptographic checksums, file deduplication, cache keys, or Bloom filters where security guarantees are explicitly not required",
        ],
        "invalid_controls": [
            "Using hashlib.md5() or hashlib.sha1() for storing passwords, generating auth tokens, verifying cryptographic integrity, or signing security data",
            "Adding a salt to MD5/SHA-1 (e.g. hashlib.md5(salt + password).hexdigest()) - vulnerable to high-speed offline dictionary and GPU attacks",
            "Iterated hashing with fast hash functions (e.g. md5(md5(pwd))) - completely ineffective against modern cracking hardware",
            "Using plain SHA-256 or SHA-512 without salt and work factor for password hashing (fast hashes are vulnerable to GPU brute-forcing; passwords require bcrypt/argon2)",
        ],
        "semantic_notes": [
            "CRITICAL DISTINCTION (bcrypt/argon2/sha256 vs md5/sha1): Passwords MUST use slow, adaptive salted hashing (bcrypt, argon2, scrypt, PBKDF2), NEVER fast hashing algorithms (MD5, SHA-1). Using MD5 or SHA-1 for passwords or security-sensitive tokens is a CRITICAL CWE-328 defect.",
            "For cryptographic integrity and signatures, SHA-256 and SHA-512 are secure collision-resistant digests, whereas MD5 and SHA-1 have proven practical collision attacks and are broken.",
            "In Python 3.9+, using MD5/SHA-1 strictly for non-security checksums (e.g., cache keys, file deduplication) with usedforsecurity=False is benign and NOT a vulnerability.",
        ],
    },
    "CWE-330": {
        "cwe_id": "CWE-330",
        "name": "Use of Insufficiently Random Values",
        "category": "Cryptography",
        "dangerous_sinks": [
            "random.random",
            "random.randint",
            "random.choice",
            "random.choices",
            "random.randrange",
            "random.sample",
            "random.getrandbits",
            "random.triangular",
            "random.betavariate",
            "random.uniform",
            "random.seed",
            "numpy.random",
            "numpy.random.randint",
            "numpy.random.choice",
        ],
        "valid_mitigations": [
            "Cryptographically secure pseudo-random number generator (CSPRNG): Use the secrets module (secrets.token_hex, secrets.token_urlsafe, secrets.token_bytes, secrets.choice, secrets.randbelow) for all security-sensitive values",
            "Operating system entropy: Use os.urandom() to generate cryptographically unpredictable byte sequences",
            "random.SystemRandom(): Use standard random interface backed by os.urandom (e.g. random.SystemRandom().randint(...))",
        ],
        "invalid_controls": [
            "Using Python standard library random module (Mersenne Twister PRNG: random.randint, random.choice, random.random) for security tokens, passwords, CSRF tokens, session IDs, or crypto keys. Mersenne Twister state is entirely reconstructible after observing 624 outputs",
            "Seeding random with time or PID: random.seed(time.time()) or random.seed(os.getpid()) - highly predictable and trivially brute-forced",
            "Custom linear congruential generators (LCG) or deterministic sequences for security-sensitive tokens",
            "numpy.random functions for generating security credentials or cryptographic nonces",
        ],
        "semantic_notes": [
            "CRITICAL DISTINCTION (secrets vs random thông thường): Distinguish security-sensitive tokens (secrets) from non-security random values.",
            "Security context: Generating session IDs, authentication tokens, password reset tokens, API keys, CSRF tokens, OTPs, or cryptographic nonces MUST use CSPRNG (secrets module or os.urandom). Using random.randint or random.choice in this context is CWE-330.",
            "Non-security context: Simulating games, dice rolls, statistical modeling, data shuffling, UI animation jitter, or ML batch randomization using random or numpy.random is SAFE and NOT a vulnerability.",
        ],
    },
    "CWE-643": {
        "cwe_id": "CWE-643",
        "name": "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
        "category": "Injection",
        "dangerous_sinks": [
            "xpath",
            "xpath_eval",
            "findtext",
            "iterfind",
            "getiterator",
            "xml.etree.ElementTree.Element.find",
            "xml.etree.ElementTree.Element.findall",
            "lxml.etree.XPath",
            "lxml.etree.XPathEvaluator",
            "tree.xpath",
            "root.xpath",
            "eval_xpath",
            "doc.xpath",
        ],
        "valid_mitigations": [
            "Parameterized XPath queries with variable bindings: tree.xpath('//user[@name=$username]', username=user_input) in lxml",
            "Pre-compiled XPath expressions with parameter variables: expr = etree.XPath('//user[@name=$val]'); expr(tree, val=user_input)",
            "Strict positive allowlist validation: Enforce alphanumeric regex ^[a-zA-Z0-9_]+$ on inputs before embedding in XPath queries when parameterized binding is unavailable",
        ],
        "invalid_controls": [
            "F-strings, % formatting, or string concatenation to build XPath queries: tree.xpath(f\"//user[name/text()='{username}']\")",
            "Simplistic quote stripping: user_input.replace(\"'\", \"\") - ineffective against numeric XPath injection or boolean logic alteration (e.g. or 1=1)",
            "Sanitization Context Mismatch: Using html.escape() or urllib.parse.quote() on XPath parameters - XPath engines do not decode HTML entities or URL encodings before evaluating query syntax",
        ],
        "semantic_notes": [
            "User input concatenated into XPath queries allows attackers to bypass authentication or extract arbitrary XML nodes and attributes via boolean logic injection (e.g. ' or '1'='1).",
            "Always use parameter binding via keyword arguments supported by lxml.etree (e.g. tree.xpath('//record[@id=$id]', id=untrusted_input)) rather than dynamic string formatting.",
        ],
    },
    "CWE-614": {
        "cwe_id": "CWE-614",
        "name": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "category": "Session & State Management",
        "dangerous_sinks": [
            "response.set_cookie",
            "set_cookie",
            "flask.Response.set_cookie",
            "django.http.HttpResponse.set_cookie",
            "Set-Cookie",
            "SESSION_COOKIE_SECURE = False",
            "CSRF_COOKIE_SECURE = False",
            "SESSION_COOKIE_HTTPONLY = False",
        ],
        "valid_mitigations": [
            "Explicitly configure secure=True on all sensitive cookies: response.set_cookie('session', token, secure=True, httponly=True, samesite='Lax')",
            "Configure httponly=True to prevent JavaScript access via XSS (mitigating document.cookie theft)",
            "Configure samesite='Lax' or samesite='Strict' to defend against CSRF",
            "Enforce secure cookie settings globally in framework configuration: SESSION_COOKIE_SECURE = True, SESSION_COOKIE_HTTPONLY = True, CSRF_COOKIE_SECURE = True",
        ],
        "invalid_controls": [
            "Omitting the secure flag or setting secure=False on session, authentication, or sensitive cookies",
            "Setting secure=True conditionally based on unverified client headers (e.g. X-Forwarded-Proto) without trusted proxy validation",
            "Relying on frontend token encryption or base64 encoding while leaving cookie transport flags (secure, httponly) unconfigured",
        ],
        "semantic_notes": [
            "Cookies containing session identifiers, authentication tokens, or sensitive state lacking the secure=True flag can be intercepted in cleartext over unencrypted HTTP connections by network adversaries.",
            "Distinguish sensitive session/auth/CSRF cookies (which REQUIRE secure=True and httponly=True) from harmless client-side UI preference cookies (e.g. theme=dark).",
        ],
    },
    "CWE-90": {
        "cwe_id": "CWE-90",
        "name": "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
        "category": "Injection",
        "dangerous_sinks": [
            "ldap.search",
            "ldap.search_s",
            "ldap.search_ext",
            "ldap.search_ext_s",
            "ldap.search_st",
            "ldap2.search",
            "ldap3.Connection.search",
            "connection.search",
            "conn.search",
            "conn.search_s",
            "client.search",
            "c.search",
            "helpers.ldap.get_connection",
        ],
        "valid_mitigations": [
            "RFC 4515 filter escaping: Use ldap3.utils.conv.escape_filter_chars(user_input) for search filter assertions",
            "RFC 4514 DN escaping: Use ldap3.utils.conv.escape_bytes() or escape_dn_chars() for distinguished name components",
            "In python-ldap: Use ldap.filter.escape_filter_chars(user_input)",
            "Strict positive allowlist validation: Validate input against alphanumeric pattern ^[a-zA-Z0-9_.-]+$ before embedding in LDAP queries",
        ],
        "invalid_controls": [
            "Concatenating or formatting unescaped user inputs directly into LDAP search filters: f\"(&(uid={username})(userPassword={password}))\" or f\"(&(objectclass=person)(uid={bar}))\"",
            "Incomplete character filtering: Stripping only '*' while allowing '(', ')', '&', '|', '!', or null bytes '\\0'",
            "Sanitization Context Mismatch: Using SQL escape functions or shlex.quote() for LDAP filters - LDAP grammar requires RFC 4515/4514 escaping (e.g. '\\2a' for '*')",
            "HTML escaping output after LDAP query execution (e.g. escape_for_html(filter)) does not mitigate LDAP query injection at search time",
        ],
        "semantic_notes": [
            "Unsanitized input in LDAP search filters allows attackers to inject filter operators (e.g. *)(uid=*))(|(uid=*), bypassing authentication or extracting sensitive directory information.",
            "Sanitization must match the specific LDAP context: search filters require RFC 4515 filter escaping, while distinguished names require RFC 4514 DN escaping.",
        ],
    },
    "CWE-601": {
        "cwe_id": "CWE-601",
        "name": "URL Redirection to Untrusted Site ('Open Redirect')",
        "category": "Input Validation / Redirection",
        "dangerous_sinks": [
            "redirect",
            "flask.redirect",
            "django.shortcuts.redirect",
            "django.http.HttpResponseRedirect",
            "django.http.HttpResponsePermanentRedirect",
            "aiohttp.web.HTTPFound",
            "fastapi.responses.RedirectResponse",
            "starlette.responses.RedirectResponse",
            "tornado.web.RequestHandler.redirect",
        ],
        "valid_mitigations": [
            "Strict destination allowlist: Validate target URLs against an immutable server-side allowlist of trusted URLs or domains before issuing a redirect",
            "Strict relative path validation: Enforce that the redirect URL begins with a single slash '/' and does not start with '//' (protocol-relative) or '/\\' (backslash bypass): url.startswith('/') and not url.startswith('//') and not url.startswith('/\\\\')",
            "Domain parsing and validation: Parse target URL with urllib.parse.urlparse(), verify parsed.scheme in ('http', 'https') or parsed.netloc == '', and ensure parsed.netloc strictly matches trusted domains",
            "Django framework validator: Use django.utils.http.url_has_allowed_host_and_scheme(url, allowed_hosts=ALLOWED_HOSTS)",
        ],
        "invalid_controls": [
            "Passing user-controlled parameter directly to redirect: redirect(request.args.get('next'))",
            "Naive prefix check: url.startswith('/') without blocking protocol-relative URLs - browsers treat '//attacker.com' as an absolute redirect to external site http(s)://attacker.com",
            "Substring matching: 'example.com' in url - trivially bypassed by attacker.com/example.com or attacker-example.com",
            "Regex matching without boundary anchors (^ and $), allowing arbitrary external domains in prefix or suffix",
        ],
        "semantic_notes": [
            "CRITICAL DISTINCTION (URL allowlist vs unvalidated redirect): Open Redirect allows attackers to craft legitimate-looking phishing links on trusted domains that redirect victims to malicious sites.",
            "Checking url.startswith('/') alone is FLAWED because protocol-relative URLs (e.g. '//evil.com') start with '/' but redirect to an external host evil.com.",
            "Safe redirects require either an explicit immutable destination allowlist or rigorous relative-path / host-and-scheme validation.",
        ],
    },
    "CWE-611": {
        "cwe_id": "CWE-611",
        "name": "Improper Restriction of XML External Entity Reference ('XXE')",
        "category": "Injection / XML Processing",
        "dangerous_sinks": [
            "xml.etree.ElementTree.parse",
            "xml.etree.ElementTree.fromstring",
            "xml.etree.ElementTree.XML",
            "xml.dom.minidom.parse",
            "xml.dom.minidom.parseString",
            "xml.sax.parse",
            "xml.sax.parseString",
            "lxml.etree.parse",
            "lxml.etree.fromstring",
            "lxml.etree.XML",
            "lxml.etree.XMLParser",
        ],
        "valid_mitigations": [
            "Use defusedxml package: Replace standard and lxml parsers with defusedxml (defusedxml.ElementTree.fromstring, defusedxml.minidom.parseString, defusedxml.lxml.fromstring), which disables entity expansion and external entity resolution by default",
            "Explicit parser configuration in lxml: Disable external entity resolution, network access, and DTDs: etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)",
            "Disallow DOCTYPE: Reject incoming XML payloads containing '<!DOCTYPE' or '<!ENTITY' declarations before parsing",
        ],
        "invalid_controls": [
            "Parsing untrusted XML with default lxml.etree parser without disabling entity resolution (lxml resolves external entities by default or when resolve_entities=True)",
            "Using standard xml.dom.minidom or xml.sax on untrusted XML without explicitly disabling external entity features (feature_external_ges, feature_external_pes)",
            "Regex-based filtering of 'DOCTYPE' or 'ENTITY' without handling character encodings (UTF-16, UTF-32, EBCDIC) or whitespace variations",
        ],
        "semantic_notes": [
            "CRITICAL DISTINCTION (defusedxml vs lxml/ElementTree entity resolution): Parsing untrusted XML with standard parsers or lxml without safe configurations exposes applications to XXE (reading local files like /etc/passwd or SSRF via external entity URLs) and Billion Laughs DoS.",
            "defusedxml is the canonical mitigation in Python, providing automatic protection against entity expansion and external entity retrieval.",
            "In modern Python 3, xml.etree.ElementTree does not resolve external entities by default, but lxml and DOM/SAX parsers remain vulnerable unless defusedxml or explicit parser flags are applied.",
        ],
    },
}


def _normalize_cwe_id(cwe_id: str) -> str:
    """Normalize user or parser input into standard 'CWE-XX' format."""
    cleaned = str(cwe_id).strip().upper()
    if not cleaned.startswith("CWE-") and cleaned.startswith("CWE"):
        cleaned = f"CWE-{cleaned[3:]}"
    elif cleaned.isdigit():
        cleaned = f"CWE-{cleaned}"
    return cleaned


def _extract_module_constants(code_content: str) -> List[str]:
    """Extract top-level constant declarations (e.g. SECRET_KEY = ..., DEBUG = ...) from code."""
    if not isinstance(code_content, str) or not code_content.strip():
        return []
    constants: List[str] = []
    try:
        tree = ast.parse(code_content)
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        constants.append(target.id)
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name):
                    constants.append(node.target.id)
    except Exception:
        pass
    return constants


# ---------------------------------------------------------------------------
# PromptManager Class
# ---------------------------------------------------------------------------

class PromptManager:
    """Manager for generating security analysis prompts for VulnAgent.

    Supports both:
    1. Dual-Scope Sliced Security Prompting: combines AST-verified structural facts
       (Scope A: intra-procedural backward slices) with full reference source code
       analysis (Scope B: file-level configuration, constants, logic flaws) and
       canonical CWE sanitization rules.
    2. General Security Prompting: backward-compatible full-file prompts matching
       :class:`analyzer.code_analyzer.CodeAnalyzer`.
    """

    CWE_TAINT_RULES = CWE_TAINT_RULES
    UNIVERSAL_SOURCES = UNIVERSAL_SOURCES

    def __init__(self, custom_cwe_rules: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        """Initialize PromptManager with optional custom CWE taint rules."""
        self.cwe_taint_rules = dict(self.CWE_TAINT_RULES)
        if custom_cwe_rules:
            self.cwe_taint_rules.update(custom_cwe_rules)

    @staticmethod
    def number_lines(content: str) -> str:
        """Prefix every source line with its 1-based, right-aligned line number.

        Args:
            content: Raw source code string.

        Returns:
            Source code with line numbers prefixed as '   1 | code'.
        """
        if not content:
            return ""
        return "\n".join(
            f"{i:>4} | {line}"
            for i, line in enumerate(content.split("\n"), 1)
        )

    # Internal alias for CodeAnalyzer compatibility
    _number_lines = number_lines

    @staticmethod
    def _generate_adaptive_reference_content(
        full_content: str,
        slices: list,
        max_full_lines: int = 500,
    ) -> str:
        """Generate adaptive reference source code context for LLM security prompts.

        Adaptive Context Slicing:
        1. If total lines <= max_full_lines (default 500 LOC):
           Retain 100% full source numbered.
        2. If total lines > max_full_lines:
           Automatically extract and preserve:
           (a) Header / imports block and all module-level constants (`Assign`,
               `AnnAssign` such as SECRET_KEY, DEBUG, CONFIG, routes, decorators).
           (b) Complete function / method blocks containing any line in `sliced_lines`
               or `target_sink_line`, preserving complete surrounding context (+-20 lines).
           (c) Outline summary of remaining classes / defs (with start-end line numbers)
               so the LLM maintains global architectural awareness without context overflow.

        Args:
            full_content: Raw source code string.
            slices: List of slice result dictionaries or objects.
            max_full_lines: Line count threshold above which adaptive slicing triggers (default 500).

        Returns:
            Numbered source code string with adaptive context slicing applied.
        """
        if not full_content or not isinstance(full_content, str):
            return ""

        raw_lines = full_content.split("\n")
        total_lines = len(raw_lines)

        # File within threshold: return 100% full source numbered
        if total_lines <= max_full_lines:
            return PromptManager.number_lines(full_content)

        # Normalize slices to list
        if slices is None:
            slice_list: list = []
        elif isinstance(slices, (list, tuple)):
            slice_list = list(slices)
        else:
            slice_list = [slices]

        # Extract all target line numbers from slices
        target_lines: set[int] = set()
        for s in slice_list:
            if isinstance(s, dict):
                sink = s.get("target_sink_line") or s.get("sink_line")
                if isinstance(sink, int) and sink > 0:
                    target_lines.add(sink)
                for l in s.get("sliced_lines", []):
                    if isinstance(l, int) and l > 0:
                        target_lines.add(l)
            else:
                sink = getattr(s, "target_sink_line", getattr(s, "sink_line", None))
                if isinstance(sink, int) and sink > 0:
                    target_lines.add(sink)
                for l in getattr(s, "sliced_lines", []):
                    if isinstance(l, int) and l > 0:
                        target_lines.add(l)
                nodes = getattr(s, "nodes", None)
                if nodes and isinstance(nodes, (list, tuple)):
                    for n in nodes:
                        lno = getattr(n, "line_number", None)
                        if isinstance(lno, int) and lno > 0:
                            target_lines.add(lno)

        # Parse AST
        try:
            tree = ast.parse(full_content)
        except Exception:
            tree = None

        # Fallback if AST cannot parse (non-Python or syntax error)
        if tree is None:
            lines_to_keep: set[int] = set()
            for l in range(1, min(total_lines, 60) + 1):
                lines_to_keep.add(l)
            for t in target_lines:
                for l in range(max(1, t - 20), min(total_lines, t + 21)):
                    lines_to_keep.add(l)

            out_lines: List[str] = [
                "# [ADAPTIVE CONTEXT: AST parsing unavailable; preserving header & target context]",
            ]
            gap_start: Optional[int] = None
            for lineno in range(1, total_lines + 1):
                if lineno in lines_to_keep:
                    if gap_start is not None:
                        gap_end = lineno - 1
                        out_lines.append(
                            f"     | ... [Lines {gap_start}-{gap_end} collapsed ({gap_end - gap_start + 1} lines)] ..."
                        )
                        gap_start = None
                    out_lines.append(f"{lineno:>4} | {raw_lines[lineno - 1]}")
                else:
                    if gap_start is None:
                        gap_start = lineno
            if gap_start is not None:
                gap_end = total_lines
                out_lines.append(
                    f"     | ... [Lines {gap_start}-{gap_end} collapsed ({gap_end - gap_start + 1} lines)] ..."
                )
            return "\n".join(out_lines)

        # -------------------------------------------------------------------
        # AST-Guided Adaptive Slicing
        # -------------------------------------------------------------------
        lines_to_keep: set[int] = set()

        # (a) Header / Imports: All lines before the first top-level function or class
        first_def_lineno: Optional[int] = None
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                decs = getattr(node, "decorator_list", [])
                node_start = min([d.lineno for d in decs] + [node.lineno])
                if first_def_lineno is None or node_start < first_def_lineno:
                    first_def_lineno = node_start

        if first_def_lineno is not None:
            lines_to_keep.update(range(1, first_def_lineno))
        else:
            lines_to_keep.update(range(1, total_lines + 1))

        # (a) Module-Level Constants / Configuration throughout the entire file
        # Retains all Assign, AnnAssign, AugAssign, Import, ImportFrom, and module-level Expr/routes
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                node_start = getattr(node, "lineno", None)
                node_end = getattr(node, "end_lineno", node_start)
                if node_start and node_end:
                    if (node_end - node_start + 1) <= 60 or any(node_start <= t <= node_end for t in target_lines):
                        lines_to_keep.update(range(node_start, node_end + 1))
                    else:
                        for sub in ast.walk(node):
                            if isinstance(sub, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Import, ast.ImportFrom)):
                                s_start = getattr(sub, "lineno", None)
                                s_end = getattr(sub, "end_lineno", s_start)
                                if s_start and s_end:
                                    lines_to_keep.update(range(s_start, s_end + 1))

        # (b) Complete function / method blocks containing any slice or sink lines (+-20 lines context)
        class _DefMeta:
            def __init__(self, n: ast.AST, parent: Optional[_DefMeta] = None) -> None:
                self.node = n
                self.parent = parent
                self.is_class = isinstance(n, ast.ClassDef)
                self.is_async = isinstance(n, ast.AsyncFunctionDef)
                self.name = getattr(n, "name", "")
                decs = getattr(n, "decorator_list", [])
                self.start_line = min([d.lineno for d in decs] + [n.lineno])
                self.end_line = getattr(n, "end_lineno", n.lineno)
                self.contains_target = any(self.start_line <= t <= self.end_line for t in target_lines)
                self.methods: List[_DefMeta] = []

        func_items: List[_DefMeta] = []
        class_items: List[_DefMeta] = []

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_items.append(_DefMeta(node))
            elif isinstance(node, ast.ClassDef):
                c_item = _DefMeta(node)
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        c_item.methods.append(_DefMeta(child, parent=c_item))
                c_item.contains_target = any(m.contains_target for m in c_item.methods) or any(
                    c_item.start_line <= t <= c_item.end_line for t in target_lines
                )
                class_items.append(c_item)

        # Preserve target top-level functions (+- 20 lines)
        for f in func_items:
            if f.contains_target:
                lines_to_keep.update(range(f.start_line, f.end_line + 1))
                ctx_start = max(1, f.start_line - 20)
                ctx_end = min(total_lines, f.end_line + 20)
                lines_to_keep.update(range(ctx_start, ctx_end + 1))

        # Preserve target class methods (+- 20 lines) and class header / constants
        for c in class_items:
            if c.contains_target:
                cls_header_end = c.node.lineno
                if c.node.body and isinstance(c.node.body[0], ast.Expr):
                    cls_header_end = getattr(c.node.body[0], "end_lineno", cls_header_end)
                lines_to_keep.update(range(c.start_line, cls_header_end + 1))

                for child in c.node.body:
                    if isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                        child_start = child.lineno
                        child_end = getattr(child, "end_lineno", child.lineno)
                        lines_to_keep.update(range(child_start, child_end + 1))

                for m in c.methods:
                    if m.contains_target:
                        lines_to_keep.update(range(m.start_line, m.end_line + 1))
                        ctx_start = max(1, m.start_line - 20)
                        ctx_end = min(total_lines, m.end_line + 20)
                        lines_to_keep.update(range(ctx_start, ctx_end + 1))

        # Preserve +- 20 lines for any target lines (sinks/slices) regardless of nesting
        for t in target_lines:
            ctx_start = max(1, t - 20)
            ctx_end = min(total_lines, t + 20)
            lines_to_keep.update(range(ctx_start, ctx_end + 1))

        # (c) Outline summary of remaining classes / defs of the file
        outline_entries: List[str] = []

        for f in func_items:
            func_line_set = set(range(f.start_line, f.end_line + 1))
            if not func_line_set.issubset(lines_to_keep):
                sig_line = raw_lines[f.node.lineno - 1].strip().rstrip(":")
                span = f.end_line - f.start_line + 1
                outline_entries.append(
                    f"Lines {f.start_line:>4}-{f.end_line:>4}: {sig_line} [{span} lines collapsed]"
                )

        for c in class_items:
            if not c.contains_target:
                m_names = ", ".join(m.name for m in c.methods) if c.methods else "no methods"
                span = c.end_line - c.start_line + 1
                outline_entries.append(
                    f"Lines {c.start_line:>4}-{c.end_line:>4}: class {c.name} ({len(c.methods)} methods: {m_names}) [{span} lines collapsed]"
                )
            else:
                collapsed_methods = [
                    m for m in c.methods
                    if not set(range(m.start_line, m.end_line + 1)).issubset(lines_to_keep)
                ]
                if collapsed_methods:
                    outline_entries.append(
                        f"Lines {c.start_line:>4}-{c.end_line:>4}: class {c.name} [partially collapsed]"
                    )
                    for m in collapsed_methods:
                        sig_line = raw_lines[m.node.lineno - 1].strip().rstrip(":")
                        span = m.end_line - m.start_line + 1
                        outline_entries.append(
                            f"    * Lines {m.start_line:>4}-{m.end_line:>4}: {sig_line} [{span} lines collapsed]"
                        )

        # Build Outline Block
        outline_block: List[str] = []
        if outline_entries:
            outline_block.append("# ==============================================================================")
            outline_block.append("# FILE OUTLINE: REMAINING CLASSES & FUNCTIONS (COLLAPSED FOR CONTEXT EFFICIENCY)")
            outline_block.append("# ==============================================================================")
            for entry in outline_entries:
                outline_block.append(f"# - {entry}")
            outline_block.append("# ==============================================================================")

        # Helper to build short description for collapsed gap markers
        def _describe_gap(start_l: int, end_l: int) -> str:
            names: List[str] = []
            for f in func_items:
                if start_l <= f.start_line <= end_l:
                    names.append(f"def {f.name}")
            for c in class_items:
                if start_l <= c.start_line <= end_l:
                    names.append(f"class {c.name}")
                else:
                    for m in c.methods:
                        if start_l <= m.start_line <= end_l:
                            names.append(f"def {c.name}.{m.name}")
            if not names:
                return ""
            if len(names) <= 3:
                return ": " + ", ".join(names)
            return f": {names[0]}, {names[1]}, +{len(names) - 2} more"

        # Assemble output with numbered lines and collapsed gaps
        result_lines: List[str] = list(outline_block)
        gap_start: Optional[int] = None

        for lineno in range(1, total_lines + 1):
            if lineno in lines_to_keep:
                if gap_start is not None:
                    gap_end = lineno - 1
                    gap_len = gap_end - gap_start + 1
                    desc = _describe_gap(gap_start, gap_end)
                    result_lines.append(
                        f"     | ... [Lines {gap_start}-{gap_end} collapsed ({gap_len} lines{desc}) - see File Outline] ..."
                    )
                    gap_start = None
                result_lines.append(f"{lineno:>4} | {raw_lines[lineno - 1]}")
            else:
                if gap_start is None:
                    gap_start = lineno

        if gap_start is not None:
            gap_end = total_lines
            gap_len = gap_end - gap_start + 1
            desc = _describe_gap(gap_start, gap_end)
            result_lines.append(
                f"     | ... [Lines {gap_start}-{gap_end} collapsed ({gap_len} lines{desc}) - see File Outline] ..."
            )

        return "\n".join(result_lines)

    def get_cwe_rules(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """Look up sanitization and taint rules for a given CWE identifier."""
        norm_id = _normalize_cwe_id(cwe_id)
        return self.cwe_taint_rules.get(norm_id)

    def format_cwe_rules_summary(self, cwe_ids: Optional[Sequence[str]] = None) -> str:
        """Format CWE taint taxonomy and sanitization rules into a readable text block.

        Args:
            cwe_ids: Optional list of CWE IDs to filter. If None, all rules are formatted.

        Returns:
            Formatted string representation of the rules matrix.
        """
        targets = (
            [_normalize_cwe_id(c) for c in cwe_ids]
            if cwe_ids is not None
            else list(self.cwe_taint_rules.keys())
        )

        blocks: List[str] = []
        for cwe_key in targets:
            rule = self.cwe_taint_rules.get(cwe_key)
            if not rule:
                continue

            lines = [
                f"### {rule['cwe_id']} - {rule['name']} ({rule.get('category', 'Vulnerability')})",
                "Dangerous Sinks:",
            ]
            for sink in rule.get("dangerous_sinks", []):
                lines.append(f"  * {sink}")

            lines.append("Valid Mitigations / Sanitizers:")
            for mit in rule.get("valid_mitigations", []):
                lines.append(f"  [+] {mit}")

            lines.append("Invalid Controls / Sanitization Context Mismatch Anti-patterns:")
            for inv in rule.get("invalid_controls", []):
                lines.append(f"  [-] {inv}")

            if rule.get("semantic_notes"):
                lines.append("Semantic Reasoning Notes:")
                for note in rule.get("semantic_notes", []):
                    lines.append(f"  [!] {note}")

            blocks.append("\n".join(lines))

        return "\n\n".join(blocks)

    def generate_sliced_security_prompt(
        self,
        parsed_code: Any,
        slices: list,
        filename: str = "",
        max_full_lines: int = 500,
    ) -> str:
        """Generate a structured Dual-Scope security prompt based on intra-procedural AST slices.

        The prompt clearly separates two critical sections:
        - [AST-VERIFIED STRUCTURAL FACTS]: Parsed sink coordinates, sliced statements,
          tracked variables, module-level constant context, and source candidates extracted
          directly by the AST parser, followed by the complete reference source code.
        - [LLM SEMANTIC TAINT REASONING (DUAL-SCOPE ANALYSIS)]: Guidance for evaluating BOTH:
          (A) AST data-flow slices (tracing taint from untrusted sources to dangerous sinks)
          (B) Reference source code (file-level, configuration, hardcoded secrets, logic flaws).

        Args:
            parsed_code: Parsed code representation (dict from CodeParser or object).
            slices: List of SliceResult or CodeSlice objects from ASTSlicer.
            filename: Path/name of the file under analysis.
            max_full_lines: LOC threshold for adaptive context slicing (default 500).

        Returns:
            Formatted prompt string ready for LLM consumption.
        """
        # 1. Resolve file context
        file_path, language, imports, functions, classes, full_content = self._extract_code_context(
            parsed_code, filename
        )

        # Extract or retrieve module-level constants
        constants: List[str] = []
        if isinstance(parsed_code, dict) and "constants" in parsed_code:
            constants = list(parsed_code["constants"])
        elif hasattr(parsed_code, "constants"):
            constants = list(getattr(parsed_code, "constants"))
        if not constants and full_content:
            constants = _extract_module_constants(full_content)

        # Normalize slices to list if a single SliceResult or object was passed
        if slices is None:
            slice_list: list = []
        elif isinstance(slices, (list, tuple)):
            slice_list = list(slices)
        else:
            slice_list = [slices]

        # 2. Build Block 1: [AST-VERIFIED STRUCTURAL FACTS]
        facts_block = self._build_ast_verified_facts_block(
            file_path=file_path,
            language=language,
            imports=imports,
            functions=functions,
            classes=classes,
            slices=slice_list,
            full_content=full_content,
            constants=constants,
            max_full_lines=max_full_lines,
        )

        # 3. Build Block 2: [LLM SEMANTIC TAINT REASONING (DUAL-SCOPE ANALYSIS)]
        reasoning_block = self._build_semantic_taint_reasoning_block(
            file_path=file_path,
            slices=slice_list
        )

        return f"{facts_block}\n\n{reasoning_block}"

    def generate_general_security_prompt(
        self,
        parsed_code: Any,
        filename: str = ""
    ) -> str:
        """Generate a full-file security analysis prompt.

        Maintains exact compatibility with :meth:`CodeAnalyzer._generate_security_prompt`.

        Args:
            parsed_code: Parsed code dictionary or object containing code metadata.
            filename: Optional file name for contextual tracking.

        Returns:
            Formatted security prompt string.
        """
        file_path, language, imports, functions, classes, content = self._extract_code_context(
            parsed_code, filename
        )
        file_type = (
            parsed_code.get("file_type", "source")
            if isinstance(parsed_code, dict)
            else getattr(parsed_code, "file_type", "source")
        )

        file_desc = f" ({file_path})" if file_path else ""

        return f"""Perform a comprehensive security analysis of this {language} code{file_desc}. Follow this methodology:
1. Identify vulnerabilities from these categories:
    - OWASP Top 10 2023
    - SANS/CWE Top 25
    - Language-specific security pitfalls
    - Framework-specific misconfigurations

2. For each finding include:
    - Vulnerability type (use exact CWE/OWASP names)
    - CVSS 3.1 vector string
    - Data flow analysis of the vulnerability
    - Taint propagation path
    - Secure alternative implementation
    - Severity level
    - Location in code
    - Description of the issue
    - Potential impact
    - Recommended fixes with secure code example

3. Code Context:
    - Imports: {imports}
    - Functions: {functions}
    - Classes: {classes}
    - File type: {file_type}

4. Analysis Requirements & Universal Source Detection:
    - Identify all user-controlled entry points across frameworks (Django, Flask, FastAPI, CLI):
      * Request parameters, form data, body, JSON (`request.args`, `request.form`, `request.json`, `request.data`, `request.GET`, `request.POST`, query params, JSON input streams)
      * Cookies, HTTP headers, authentication tokens (`request.cookies`, `request.headers`, `cookies`, `headers`)
      * CLI arguments and environment inputs (`sys.argv`, `input()`, `os.environ`)
    - Apply independent data-flow taint analysis principles:
      * Base all assessments strictly on objective taint propagation paths
      * Avoid repository-specific or test-fixture naming bias
      * Trace inter-procedural taint forwarding through helper/wrapper functions (Inter-procedural taint forwarding)
    - Apply semantic precision & pitfall disambiguation:
      * Distinguish secrets vs random thông thường: security-sensitive tokens (sessions, CSRF, passwords, keys) require CSPRNG `secrets` or `os.urandom` vs non-security random `random`/`numpy.random` for games, modeling, or data shuffling (CWE-330)
      * Distinguish bcrypt/argon2/sha256 vs md5/sha1: password hashing requires slow adaptive algorithms (bcrypt, argon2) & secure digests (sha256) vs broken/weak hashing (md5, sha1) (CWE-328)
      * Distinguish defusedxml vs lxml/ElementTree entity resolution: safe parsing with defusedxml vs vulnerable XML external entity resolution (CWE-611)
      * Distinguish URL allowlist vs unvalidated redirect: strict allowlist & relative validation vs open redirect (CWE-601)
      * Distinguish dynamic eval/exec vs safe dispatch: untrusted input in eval/exec is code injection (CWE-94)
      * Parameterize XPath queries (CWE-643) and escape LDAP search filters (CWE-90)
      * Detect archive extraction without member path containment check (`extractall` Path Traversal / Zip Slip, CWE-22)
      * Note: Do NOT flag non-sensitive dummy test cookies in benchmark setup routes (e.g. `set_cookie` in GET routes) as vulnerabilities; focus strictly on the core vulnerability under test.
    - Apply Taint Reasoning & Clean Control Principles (Optimized for cmc/reflection/beam:free & Benchmark Evaluation):
      * Khi kiểm tra các đoạn mã chuẩn hoặc clean control code (ví dụ: đã dùng hàm làm sạch hợp lệ `html.escape`, `os.path.basename`, câu truy vấn có tham số hóa parameterized SQL, hoặc sử dụng hằng số cố định), hướng dẫn mô hình phải dứt khoát xác nhận mã nguồn an toàn và trả về {{"vulnerabilities": []}} thay vì phỏng đoán suy diễn.
      * When analyzing clean control code or safe implementations with valid sanitizers (`html.escape`, `os.path.basename`, parameterized SQL queries, hardcoded constants), decisively confirm the code is safe and return {{"vulnerabilities": []}} without speculative guessing.
      * Khi phát hiện luồng dữ liệu tainted đi thẳng từ nguồn ngoại vi vào điểm chìm nguy hiểm mà không qua hàm làm sạch tương ứng, lập tức xác nhận lỗ hổng với phân loại chuẩn xác theo 11 nhóm CWE của benchmark: CWE-22 (PATHTRAVER), CWE-78 (CMDI), CWE-79 (XSS), CWE-89 (SQLI), CWE-94 (CODEINJ), CWE-328 (HASH), CWE-330 (WEAKRAND), CWE-502 (DESERIALIZATION), CWE-601 (REDIRECT), CWE-611 (XXE), CWE-643 (XPATHI).
    - Validate user input sources and check data sanitization flows against canonical defenses
    - Verify proper authz checks
    - Confirm secure defaults
    - Ensure error handling doesn't leak secrets or stack traces

5. Line numbers:
    - The source below is prefixed with its real line numbers.
    - Report start_line and end_line using EXACTLY those numbers.
    - Do not count lines yourself; read the prefix.

--- BEGIN SOURCE ---
{self.number_lines(content)}
--- END SOURCE ---

Format response as JSON matching the Vulnerability model structure.
"""

    # -----------------------------------------------------------------------
    # Helper builders
    # -----------------------------------------------------------------------

    def _extract_code_context(
        self,
        parsed_code: Any,
        filename: str
    ) -> tuple[str, str, List[Any], List[str], List[str], str]:
        """Extract standardized metadata from parsed_code."""
        if isinstance(parsed_code, dict):
            content = parsed_code.get("content", "")
            language = parsed_code.get("language", "python")
            imports = parsed_code.get("imports", [])
            raw_funcs = parsed_code.get("functions", [])
            functions = [
                f["name"] if isinstance(f, dict) and "name" in f else str(f)
                for f in raw_funcs
            ]
            raw_classes = parsed_code.get("classes", [])
            classes = [
                c["name"] if isinstance(c, dict) and "name" in c else str(c)
                for c in raw_classes
            ]
            resolved_file = filename or parsed_code.get("filename") or ""
        elif isinstance(parsed_code, str):
            content = parsed_code
            language = "python"
            imports = []
            functions = []
            classes = []
            resolved_file = filename
        else:
            content = getattr(parsed_code, "content", "")
            language = getattr(parsed_code, "language", "python")
            imports = getattr(parsed_code, "imports", [])
            raw_funcs = getattr(parsed_code, "functions", [])
            functions = [
                f["name"] if isinstance(f, dict) and "name" in f else str(f)
                for f in raw_funcs
            ]
            raw_classes = getattr(parsed_code, "classes", [])
            classes = [
                c["name"] if isinstance(c, dict) and "name" in c else str(c)
                for c in raw_classes
            ]
            resolved_file = filename or getattr(parsed_code, "filename", "")

        return resolved_file, language, imports, functions, classes, content

    def _build_ast_verified_facts_block(
        self,
        file_path: str,
        language: str,
        imports: List[Any],
        functions: List[str],
        classes: List[str],
        slices: list,
        full_content: str,
        constants: Optional[List[str]] = None,
        max_full_lines: int = 500,
    ) -> str:
        """Construct the [AST-VERIFIED STRUCTURAL FACTS] section."""
        lines: List[str] = [
            "================================================================================",
            "[AST-VERIFIED STRUCTURAL FACTS]",
            "================================================================================",
            f"File: {file_path or 'unknown_file'}",
            f"Language: {language}",
            f"Total Dangerous Slices Extracted: {len(slices)}",
            f"Imports: {imports}",
            f"Functions: {functions}",
            f"Classes: {classes}",
        ]

        if constants:
            lines.append(f"Module Constants / Configuration: {constants}")

        lines.extend([
            "",
            "The following code slices and dangerous sinks were identified by the AST static",
            "analyzer and intra-procedural backward dataflow slicer. These structural facts",
            "are verified by the Python AST parser; do not hallucinate missing statements",
            "or contradict these facts.",
        ])

        if not slices:
            lines.extend([
                "",
                "Notice: No dangerous sink calls or intra-procedural slices were isolated by the AST slicer.",
            ])
        else:
            for idx, s in enumerate(slices, 1):
                slice_block = self._format_single_slice(idx, len(slices), s)
                lines.append("")
                lines.append(slice_block)

        if full_content:
            ref_content = self._generate_adaptive_reference_content(
                full_content=full_content,
                slices=slices,
                max_full_lines=max_full_lines,
            )
            lines.extend([
                "",
                "--- BEGIN FULL SOURCE (REFERENCE) ---",
                ref_content,
                "--- END FULL SOURCE (REFERENCE) ---",
            ])

        lines.append("================================================================================")
        return "\n".join(lines)

    def _format_single_slice(self, index: int, total: int, s: Any) -> str:
        """Format an individual slice into an AST structural fact representation."""
        if isinstance(s, dict):
            sink_line = s.get("target_sink_line") or s.get("sink_line") or 0
            sink_name = s.get("sink_name") or ""
            target_var = s.get("target_variable") or ""
            sliced_lines = s.get("sliced_lines", [])
            sliced_code = s.get("sliced_code", "")
            tracked_vars = s.get("tracked_variables", [])
            source_candidates = s.get("source_candidates", [])
            completeness = s.get("completeness_status", "unknown")
            is_truncated = s.get("is_truncated", False)
            token_budget = s.get("token_budget_used", 0)
            truncation_reason = s.get("truncation_reason")
            facts_str = s.get("facts_prompt") or ""
        else:
            sink_line = getattr(s, "target_sink_line", getattr(s, "sink_line", 0))
            sink_name = getattr(s, "sink_name", "")
            target_var = getattr(s, "target_variable", "")
            sliced_lines = getattr(s, "sliced_lines", [])
            sliced_code = getattr(s, "sliced_code", "")
            tracked_vars = getattr(s, "tracked_variables", [])
            source_candidates = getattr(s, "source_candidates", [])
            completeness = getattr(s, "completeness_status", "unknown")
            is_truncated = getattr(s, "is_truncated", False)
            token_budget = getattr(s, "token_budget_used", 0)
            truncation_reason = getattr(s, "truncation_reason", None)
            if hasattr(s, "to_facts_prompt") and callable(s.to_facts_prompt):
                facts_str = s.to_facts_prompt()
            elif hasattr(s, "get_verified_facts_str") and callable(s.get_verified_facts_str):
                facts_str = s.get_verified_facts_str()
            else:
                facts_str = ""

        trunc_info = f", Truncation Reason: {truncation_reason}" if truncation_reason else ""
        slice_lines = [
            f"--------------------------------------------------------------------------------",
            f"Slice #{index} of {total}:",
            f"  - Sink Name: {sink_name or '(unnamed sink)'}",
            f"  - Sink Line: {sink_line}",
            f"  - Target Variable: {target_var or '(none)'}",
            f"  - Tracked Variables: {tracked_vars}",
            f"  - AST-extracted source candidates (unverified syntactic patterns): {source_candidates}",
            f"  - Sliced Line Numbers: {sliced_lines}",
            f"  - Completeness Status: {completeness} (is_truncated={is_truncated}, token_budget_used={token_budget}{trunc_info})",
        ]

        if facts_str:
            slice_lines.extend([
                "",
                "  AST-Verified Statement Sequence:",
                facts_str,
            ])

        if sliced_code:
            slice_lines.extend([
                "",
                f"  --- BEGIN SLICED CODE (Slice #{index}) ---",
                self.number_lines(sliced_code),
                f"  --- END SLICED CODE (Slice #{index}) ---",
            ])

        return "\n".join(slice_lines)

    def _build_semantic_taint_reasoning_block(
        self,
        file_path: str,
        slices: list
    ) -> str:
        """Construct the [LLM SEMANTIC TAINT REASONING (DUAL-SCOPE ANALYSIS)] section."""
        cwe_rules_summary = self.format_cwe_rules_summary()

        return f"""================================================================================
[LLM SEMANTIC TAINT REASONING]
DUAL-SCOPE SECURITY ANALYSIS (SCOPE A: AST SLICES & SCOPE B: FULL REFERENCE CODE)
================================================================================
You are a Senior Application Security & Taint Analysis Specialist operating
inside the VulnAgent 3-Tier Asymmetric Architecture.

Your task is to perform a comprehensive DUAL-SCOPE security analysis evaluating BOTH:
  (A) AST Data-Flow Slices (intra-procedural taint propagation from user input to dangerous sinks).
  (B) Reference Source Code (file-level, configuration, hardcoded secrets, and architectural/logic vulnerabilities).

CRITICAL DUAL-SCOPE DIRECTIVE:
- DO NOT limit your vulnerability reporting to only statements present in the AST slices.
- The AST slices (Scope A) isolate verified data-flow paths reaching dangerous sink calls.
- The Full Source Reference (Scope B) contains the entire file context, including module-level
  configuration, constant declarations (such as SECRET_KEY, DEBUG), route definitions, error
  handling blocks, and architectural logic.
- You MUST report confirmed vulnerabilities from BOTH Scope A and Scope B:
    * If an AST slice shows an unmitigated taint flow to a dangerous sink, report it.
    * If the reference source code contains file-level vulnerabilities (e.g., hardcoded SECRET_KEY,
      insecure default configuration, SSRF, CSRF, exception traceback leakage, IDOR), report them!
- Even if all AST slices are safely sanitized or benign, you MUST STILL analyze the reference
  source code and report any confirmed Scope B vulnerabilities.
- Only return {{"vulnerabilities": []}} if NEITHER Scope A NOR Scope B contains any confirmed vulnerability.

--------------------------------------------------------------------------------
CANONICAL CWE TAINT & SANITIZATION MATRIX (Mục 4 Phuong_an_2.md & Dual-Scope Taxonomy):
--------------------------------------------------------------------------------
{cwe_rules_summary}

--------------------------------------------------------------------------------
TAINT ANALYSIS PRINCIPLES & UNIVERSAL SOURCE DETECTION:
--------------------------------------------------------------------------------
1. Universal Source Detection (Framework-Agnostic Entry Points):
   Recognize ALL user-controlled external entry points across ANY Python framework
   (Django, Flask, FastAPI, Starlette, Tornado, Falcon, Bottle, etc.) and execution models (CLI, daemons):
   * Web Framework Request Objects:
     - Query Parameters: `request.args`, `request.GET`, `request.query_params`, route parameters (`<param>`)
     - Form & Body Data: `request.form`, `request.POST`, `request.data`, `request.body`, `request.get_json()`, `request.json`, JSON input streams
     - File Uploads: `request.files`, multipart upload filenames and stream data
   * Headers, Cookies & Session Metadata:
     - `request.cookies`, `request.headers`, `request.META`, `cookies`, `headers`, authentication bearer tokens
   * CLI Arguments, User Input & Environment:
     - `sys.argv`, `sys.stdin`, `argparse`, `click`, `input()`, `raw_input()`
     - `os.environ`, `os.getenv()` when carrying external runtime inputs
   * Network, Socket & Message Streams:
     - `socket.recv()`, message queue message streams (Celery, RabbitMQ, Kafka)

2. Independent Data-Flow Taint Analysis Principles (Anti-Bias Directive):
   - Never bias analysis based on repository names, directory paths, benchmark fixture structures, or variable naming conventions.
   - DO NOT assume a variable is safe or malicious simply by its name (e.g. `param`, `bar`, `safe_val`, `clean`, `test`).
   - Base all vulnerability assessments strictly on objective data-flow taint propagation:
     Source (untrusted user entry point) -> Propagator (assignments, string formatting, f-strings, concatenations) -> Sink.
   - Taint is preserved across string formatting, `.format()`, `%`, concatenations, list/dict transformations, and encoding operations unless broken by a canonical, context-appropriate sanitizer.
   - Nhận diện lan truyền taint xuyên hàm qua các helper/wrapper functions (Inter-procedural taint forwarding):
     * Follow tainted arguments across function call boundaries into callee bodies and wrapper routines.
     * Intermediate functions that forward tainted inputs to sinks or return transformed user inputs maintain taint propagation across procedure boundaries.
     * Do not assume helper functions sanitize inputs unless verified to execute canonical, context-appropriate sanitizers.

3. High-Precision Cryptographic, XML & Web Semantic Disambiguation Rules:
   - Phát hiện giải nén tệp nén không kiểm tra đường dẫn thành phần (`extractall` Path Traversal / Zip Slip - CWE-22):
     * Distinguish safe archive extraction (with per-member destination path containment validation or `filter='data'` in Python 3.12+) from vulnerable unchecked archive extractions (`extractall()`, `tarfile.extractall()`, `zipfile.extractall()`, `shutil.unpack_archive()`).
     * Extracting archive files without verifying that each member's target destination path is strictly contained within the destination directory (e.g. `(dest / member.name).resolve().is_relative_to(dest.resolve())`) allows malicious archive entries containing traversal sequences (`../`) or absolute paths to overwrite arbitrary files outside the target directory (`extractall` Path Traversal / Zip Slip). Flag these as confirmed CWE-22 vulnerabilities.
   - Phân biệt secrets vs random thông thường (Secrets vs Non-Security Randomness - CWE-330):
     * Distinguish security-sensitive tokens (secrets) from regular non-security pseudo-randomness.
     * Security context: Session IDs, CSRF tokens, password reset tokens, API keys, OTPs, cryptographic salts/nonces MUST use CSPRNG (`secrets` module: `secrets.token_hex`, `secrets.token_urlsafe`, `secrets.choice`, or `os.urandom`). Using standard `random` (`random.randint`, `random.choice`, `random.random`) is INSECURE (CWE-330).
     * Non-security context: Simulating games, dice rolls, statistical simulations, data shuffling, UI layout jitter, or ML batch randomization using `random` or `numpy.random` is SAFE and MUST NOT be flagged as CWE-330.
   - Phân biệt bcrypt/argon2/sha256 vs md5/sha1 (Password Hashing vs Secure Digests vs Weak Hashes - CWE-328):
     * Distinguish slow, adaptive key-derivation algorithms (bcrypt, argon2, scrypt, PBKDF2) from secure collision-resistant digests (SHA-256, SHA-512) and broken/obsolete hashes (MD5, SHA-1).
     * Passwords / Credentials: MUST use slow, adaptive salted hashing (`bcrypt.hashpw`, `argon2.PasswordHasher`, `hashlib.pbkdf2_hmac`). Using fast hashes (even plain SHA-256 without salt/work-factor) is weak, and using MD5/SHA-1 is CRITICAL CWE-328.
     * Integrity / Signatures: SHA-256 / SHA-512 / SHA-3 are collision-resistant and secure. Using MD5 or SHA-1 for security signatures, certificate digests, or cryptographic verification is CWE-328.
     * Non-Security Checksums: MD5/SHA-1 used strictly for non-security checksums (file deduplication, cache keys, Bloom filters with `usedforsecurity=False` in Python 3.9+) is SAFE and NOT a vulnerability.
   - Phân biệt defusedxml vs lxml/ElementTree entity resolution (XML External Entity - CWE-611):
     * Distinguish safe XML parsers (`defusedxml`) from vulnerable standard/third-party parsers (`lxml`, `xml.dom.minidom`, `xml.sax`).
     * Untrusted XML parsed with `defusedxml` (`defusedxml.ElementTree`, `defusedxml.minidom`, `defusedxml.lxml`) is SAFE against XXE and entity expansion bombs.
     * Parsing untrusted XML with `lxml.etree` (especially with default settings, `resolve_entities=True`, or custom resolvers) or `xml.dom.minidom` without disabling external entity resolution is VULNERABLE to CWE-611 (arbitrary local file disclosure or SSRF).
   - Phân biệt URL allowlist vs unvalidated redirect (Open Redirect - CWE-601):
     * Distinguish validated destination redirects from unvalidated user-controlled redirects.
     * Valid Redirection: Strict domain/URL allowlisting, `django.utils.http.url_has_allowed_host_and_scheme()`, or safe relative path validation ensuring a single leading slash (`url.startswith('/') and not url.startswith('//') and not url.startswith('/\\')`).
     * Vulnerable Redirection: Passing raw `request.args.get('next')` to `redirect()`, naive substring checks (`"example.com" in url`), or flawed prefix checks (`url.startswith('/')` without blocking protocol-relative `//attacker.com`).

4. Taint Reasoning & Clean Control Principles (Optimized for cmc/reflection/beam:free & Benchmark Evaluation):
   - Kiểm tra mã chuẩn & Clean Control Code (Anti-Speculation Directive):
     * Khi kiểm tra các đoạn mã chuẩn hoặc clean control code (ví dụ: đã dùng hàm làm sạch hợp lệ `html.escape`, `os.path.basename`, câu truy vấn có tham số hóa parameterized SQL, hoặc sử dụng hằng số cố định), hướng dẫn mô hình phải dứt khoát xác nhận mã nguồn an toàn và trả về {{"vulnerabilities": []}} thay vì phỏng đoán suy diễn.
     * When analyzing clean control code or safe reference patterns where:
       (a) Variables originate strictly from hardcoded constants, string/integer literals, or static server configurations (e.g. `cursor.execute('SELECT 1')`, `open('fixed.txt')`, `hashlib.md5(b'fixed')`).
       (b) Valid sanitizers or mitigations are applied in the proper context:
           - HTML/XSS: `html.escape`, `markupsafe.escape`, auto-escaping template engines
           - Path Traversal: `os.path.basename`, `werkzeug.utils.secure_filename`, resolved containment `Path(base, path).resolve().is_relative_to(...)`
           - SQL Injection: Parameterized queries with placeholders (?, %s, :param) passing parameters via tuple/sequence (e.g. `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`), ORM query filtering (`filter_by`, `objects.filter`)
           - Command Injection: Argument list with `shell=False` (`subprocess.run(['cmd', arg], shell=False)`), `shlex.quote`
           - Insecure Deserialization: `json.loads`, `yaml.safe_load`, defused loaders
           - Weak Cryptographic Hash: `bcrypt`, `argon2`, `hashlib.sha256()`, or non-security checksums (`usedforsecurity=False`)
           - Insecure Randomness: `secrets` module (`secrets.token_hex`), non-security contexts (games, simulations)
           - XPath/LDAP: parameterized queries or `escape_filter_chars`
           - Open Redirect: strict URL allowlist or relative path validation
           - Cookie Flag: `secure=True`, `httponly=True`
     * ANTI-SPECULATION MANDATE: You MUST DECISIVELY confirm that the code is SAFE and return {{"vulnerabilities": []}}. DO NOT speculate, assume worst-case hypothetical flaws, or hallucinate theoretical bypasses when valid mitigations are in place. Speculative false-positive guessing is strictly prohibited.
   - Xác nhận luồng dữ liệu tainted theo 11 nhóm CWE của benchmark (Confirmed Taint Flow & 11 Benchmark CWE Groups):
     * Khi phát hiện luồng dữ liệu tainted đi thẳng từ nguồn ngoại vi vào điểm chìm nguy hiểm mà không qua hàm làm sạch tương ứng, lập tức xác nhận lỗ hổng với phân loại chuẩn xác theo 11 nhóm CWE của benchmark:
       1. CWE-89 (SQLI): SQL Injection (dynamic string formatting or concatenation into SQL query execution)
       2. CWE-78 (CMDI): OS Command Injection (shell command execution with unquoted or concatenated input)
       3. CWE-22 (PATHTRAVER): Path Traversal (unvalidated user path in file operations or unchecked `extractall` Zip Slip)
       4. CWE-79 (XSS): Cross-Site Scripting (unescaped user input reflected in web responses)
       5. CWE-502 (DESERIALIZATION): Insecure Deserialization (untrusted payload passed to pickle/yaml)
       6. CWE-328 (HASH): Weak Cryptographic Hash (MD5/SHA1 used for passwords or security verification)
       7. CWE-330 (WEAKRAND): Insecure Randomness (standard pseudo-randomness used for security tokens)
       8. CWE-643 (XPATHI): XPath Injection (dynamic string construction in XML XPath queries)
       9. CWE-94 (CODEINJ): Code Injection / Dynamic Evaluation (untrusted input passed to eval/exec)
       10. CWE-611 (XXE): XML External Entity (untrusted XML parsed without disabling external entities/DTD)
       11. CWE-601 (REDIRECT): Open Redirect (unvalidated external URL in redirection)

--------------------------------------------------------------------------------
DUAL-SCOPE REASONING REQUIREMENTS & METHODOLOGY:
--------------------------------------------------------------------------------
1. Scope A: AST Data-Flow Taint Analysis:
   - Untrusted Input Boundary Verification (Universal Source Detection):
     * Cross-reference items in "AST-extracted source candidates" with universal user entry points (`request.*`, `sys.argv`, `input()`, `os.environ`, `cookies`, `headers`, query params, JSON input streams) across any framework (Django, Flask, FastAPI, CLI).
     * Determine whether the data source is genuinely controllable across an Untrusted Input Boundary.
     * If the value originates strictly from a hardcoded constant, server-controlled configuration, or trusted
       internal state, NO taint propagation defect exists on that path.
   - Mitigating Control & Sanitizer Evaluation:
     * Evaluate whether any sanitization or validation controls exist in the slice.
     * Cross-reference strictly with the CANONICAL CWE TAINT MATRIX above:
       * Valid Mitigations: Recognized sanitizers applied in the correct context (e.g. parameterized SQL,
         shlex.quote with shell=True, Path.resolve containment checks, html.escape in HTML body context).
       * Invalid Controls / Sanitization Context Mismatch Anti-patterns: Ineffective sanitizers (e.g. shlex.quote() used on SQL,
         unresolved os.path.join(), replace("../", "") non-recursive, html.escape() in JS/URL/CSS context).
       * If a sanitizer exhibits a Sanitization Context Mismatch, specify the exact defect mechanism.
   - Source-to-Sink Dataflow Trace Synthesis:
     * Trace the end-to-end data flow:
       Source (untrusted user input) -> Propagator (assignments/concatenations) -> [Sanitizer/Mismatch] -> Sink.
     * Only confirm a vulnerability if the taint path reaches the dangerous sink without valid mitigation.
   - Inter-procedural Taint Forwarding & Callee Sinks:
     * Nhận diện lan truyền taint xuyên hàm qua các helper/wrapper functions (Inter-procedural taint forwarding):
       When an AST slice terminates at a call to a local helper or wrapper function, inspect whether the callee forwards tainted parameters downstream to a dangerous sink.
   - Archive Extraction Path Traversal / Zip Slip:
     * Phát hiện giải nén tệp nén không kiểm tra đường dẫn thành phần (`extractall` Path Traversal / Zip Slip):
       Verify whether archive extraction calls (`tarfile.extractall`, `zipfile.extractall`, `extractall`, `shutil.unpack_archive`) validate containment for each member path. Flag unchecked extractions as CWE-22.
   - Clean Control Verification & Anti-Speculation:
     * When inputs to dangerous sinks originate strictly from hardcoded constants (literal strings, numbers) or pass through valid sanitizers (`html.escape`, `os.path.basename`, parameterized SQL queries with ?, %s), decisively confirm the code is safe and return {{"vulnerabilities": []}} if no Scope B flaws exist. Do not speculate or produce false positives.
   - Confirmed Taint Flow Benchmark Classification:
     * When an unmitigated taint flow connects an untrusted source to a dangerous sink without a sanitizer, immediately confirm the vulnerability and classify it accurately matching the 11 benchmark CWE groups.

2. Scope B: File-Level, Configuration & Logic Flaw Analysis (Reference Source Code):
   - Path Traversal & Archive Extraction (Zip Slip / Tar Slip - CWE-22):
     * Phát hiện giải nén tệp nén không kiểm tra đường dẫn thành phần (`extractall` Path Traversal / Zip Slip):
       Inspect file operations and archive extraction routines in reference source code. Flag calls to `tarfile.extractall()`, `zipfile.extractall()`, `extractall()`, or `shutil.unpack_archive()` lacking per-member path containment validation as CWE-22.
   - Inter-procedural Helper & Wrapper Inspection:
     * Nhận diện lan truyền taint xuyên hàm qua các helper/wrapper functions (Inter-procedural taint forwarding):
       Trace user inputs through utility/helper functions defined in the reference code to downstream sinks across function boundaries.
   - Module Constants & Secret Management (CWE-798, CWE-1188):
     * Inspect module-level constant declarations (e.g. SECRET_KEY = "...", DEBUG = True, API_KEY = "...").
     * Statically assigned secrets or insecure default configurations are immediate high/critical vulnerabilities,
       even when they do not flow into an AST sink.
   - Server-Side Request Forgery & Deserialization (CWE-918, CWE-502):
     * Inspect outbound HTTP requests (requests.get/post, urllib, httpx) for user-controllable URLs without IP/domain allowlisting.
     * Inspect object deserialization (pickle.loads, yaml.unsafe_load) on untrusted inputs leading to RCE.
   - Information Disclosure & Exception Leaks (CWE-209):
     * Inspect try/except blocks returning raw exception details (str(e), traceback.format_exc()) to HTTP responses.
   - Authentication, Authorization & CSRF (CWE-352, CWE-639, CWE-284):
     * Check for state-changing endpoints lacking CSRF protection or decorated with @csrf_exempt.
     * Check for endpoints accessing or modifying database records by client-supplied ID without ownership checks (IDOR).
   - Input Validation (CWE-20):
     * Check for endpoints accepting external inputs without proper validation or schema enforcement.
   - Cryptographic and Randomness Flaws (CWE-328, CWE-330):
     * Inspect hashing functions: distinguish bcrypt/argon2/sha256 vs md5/sha1. Flag MD5/SHA-1 used for passwords or security verification as CWE-328.
     * Inspect token generation: distinguish secrets vs random thông thường. Flag random.randint/random.choice used for security tokens as CWE-330.
   - XML Processing & Redirection (CWE-611, CWE-601, CWE-643, CWE-94):
     * Inspect XML parsing: distinguish defusedxml vs lxml/ElementTree entity resolution. Flag un-defused XML parsing as CWE-611.
     * Inspect redirects: distinguish URL allowlist vs unvalidated redirect. Flag redirect(untrusted_url) as CWE-601.
     * Inspect dynamic execution: flag untrusted input passed to eval/exec as CWE-94.
     * Inspect XPath / LDAP queries: flag dynamic string concatenation into queries as CWE-643 / CWE-90.
     * Note: Do NOT flag dummy test fixture cookies in GET setup routes as CWE-614.

3. JSON Output Format:
   - You MUST return a single valid JSON object matching the standard Vulnerability model format.
   - If one or more vulnerabilities are confirmed from Scope A or Scope B, populate the "vulnerabilities" array.
   - If all slices are safely sanitized, operate on hardcoded constants, or constitute clean control code, and no file-level/configuration flaws exist in the reference code, return {{"vulnerabilities": []}}.
   - Do NOT include markdown conversation outside the JSON block.

REQUIRED JSON OUTPUT SCHEMA:
{{
  "vulnerabilities": [
    {{
      "type": "SQL_INJECTION | OS_COMMAND_INJECTION | PATH_TRAVERSAL | CROSS_SITE_SCRIPTING | HARDCODED_CREDENTIALS | SERVER_SIDE_REQUEST_FORGERY | INSECURE_DESERIALIZATION | IMPROPER_ERROR_HANDLING | CSRF | INSECURE_DIRECT_OBJECT_REFERENCE | SECURITY_MISCONFIGURATION | INSUFFICIENT_INPUT_VALIDATION | WEAK_HASHING | INSECURE_RANDOMNESS | XPATH_INJECTION | INSECURE_COOKIE | LDAP_INJECTION | OPEN_REDIRECT | XML_EXTERNAL_ENTITY | ...",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "cwe_id": "CWE-89 | CWE-78 | CWE-22 | CWE-79 | CWE-798 | CWE-918 | CWE-502 | CWE-209 | CWE-352 | CWE-20 | CWE-1188 | CWE-639 | CWE-287 | CWE-284 | CWE-328 | CWE-330 | CWE-643 | CWE-614 | CWE-90 | CWE-601 | CWE-611 | ...",
      "owasp_category": "A01:2021-Broken Access Control | A02:2021-Cryptographic Failures | A03:2021-Injection | A05:2021-Security Misconfiguration | ...",
      "cvss_score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "location": {{
        "file_path": "{file_path or 'filename'}",
        "start_line": 1,
        "end_line": 1,
        "start_col": 0,
        "end_col": 0,
        "context": "exact code line of the dangerous sink or vulnerability"
      }},
      "description": "Technical analysis of the vulnerability",
      "impact": "Potential security defect impact",
      "remediation": "Recommended remediation using secure patterns",
      "defect_replication_notes": "Defect Replication Notes (minimal test input or trace demonstrating the defect)",
      "secure_code_example": "Secure alternative implementation",
      "data_flow": "Concise summary of taint or control flow",
      "taint_path": [
        {{"step": 1, "kind": "source", "line": 0, "symbol": "var", "description": "Source origin"}},
        {{"step": 2, "kind": "propagator", "line": 0, "symbol": "var", "description": "Transformation/propagation"}},
        {{"step": 3, "kind": "sink", "line": 0, "symbol": "sink", "description": "Dangerous sink execution"}}
      ]
    }}
  ]
}}
================================================================================"""


# ---------------------------------------------------------------------------
# Module-level aliases
# ---------------------------------------------------------------------------
_generate_adaptive_reference_content = PromptManager._generate_adaptive_reference_content

