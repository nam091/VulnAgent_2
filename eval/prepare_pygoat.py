"""Build an evaluation corpus from OWASP PyGoat.

PyGoat (https://github.com/adeyosemanputra/pygoat, MIT) is OWASP's
deliberately vulnerable Django application and the only OWASP project that
targets Python. Two other corpora are commonly suggested for this and do not
exist:

  - OWASP Benchmark is Java. There is no BenchmarkPython; the OWASP GitHub
    organisation has no such repository.
  - NIST SARD holds 426,654 test cases and none of them are Python. Filtering
    its API by language returns 45,437 for C, 32,356 for Java, 291,048 for
    PHP and 0 for Python.

PyGoat ships no ground truth, so the labels below were established by reading
each lab view and locating the sink. Line numbers are pinned to a commit; the
script checks that the line still contains what the label claims and refuses
to emit a stale corpus rather than silently scoring against the wrong lines.

    python eval/prepare_pygoat.py --source /path/to/pygoat
"""

import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Dict, List

EVAL_DIR = Path(__file__).resolve().parent
DEFAULT_OUT = EVAL_DIR / "datasets" / "pygoat"
VIEWS = "introduction/views.py"

# Each entry pins the sink line and a fragment that must still be on it.
# The fragment is what makes the corpus safe to regenerate against a newer
# checkout: if PyGoat moves the code, the build fails loudly.
LABELS: List[Dict] = [
    {
        "line": 162, "must_contain": "login.objects.raw",
        "cwe": "89", "type": "SQL_INJECTION",
        "note": "raw() on a query string concatenated from POST name/password at line 158",
    },
    {
        "line": 214, "must_contain": "pickle.loads",
        "cwe": "502", "type": "INSECURE_DESERIALIZATION",
        "note": "pickle.loads on a base64 cookie the client controls",
    },
    {
        "line": 430, "must_contain": "subprocess.Popen",
        "cwe": "78", "type": "OS_COMMAND_INJECTION",
        "note": "shell=True on 'dig {}'.format(domain) built from user input",
    },
    {
        "line": 460, "must_contain": "eval(val)",
        "cwe": "95", "type": "CODE_INJECTION",
        "note": "eval on request.POST['val']",
    },
    {
        "line": 560, "must_contain": "yaml.load",
        "cwe": "502", "type": "INSECURE_DESERIALIZATION",
        "note": "yaml.load with the unsafe Loader on an uploaded file",
    },
    {
        "line": 588, "must_contain": "ImageMath.eval",
        "cwe": "95", "type": "CODE_INJECTION",
        "note": "ImageMath.eval on a format string from request.POST",
    },
    {
        "line": 878, "must_contain": "sql_lab_table.objects.raw",
        "cwe": "89", "type": "SQL_INJECTION",
        "note": "raw() on a concatenated query in the 2021 injection lab",
    },
    {
        "line": 963, "must_contain": "requests.get(url)",
        "cwe": "918", "type": "SERVER_SIDE_REQUEST_FORGERY_(SSRF)",
        "note": "outbound fetch of a URL taken straight from request.POST",
    },
    {
        "line": 1026, "must_contain": "md5(",
        "cwe": "328", "type": "USE_OF_WEAK_HASHING_ALGORITHM",
        "note": "md5 used to hash a password, unsalted",
    },
    {
        "line": 260, "must_contain": "parseString",
        "cwe": "611", "type": "XML_EXTERNAL_ENTITY",
        "note": "external general entities enabled at line 259, then request.body parsed",
    },
]


def build(source: Path, out: Path) -> Dict:
    """
    Copy the labelled file and write its ground truth.

    Args:
        source: A PyGoat checkout
        out: Destination dataset directory

    Returns:
        Dict: Summary counts

    Raises:
        SystemExit: When the checkout is missing or the labels no longer fit
    """

    views = source / VIEWS
    if not views.is_file():
        print(f"error: {views} not found", file=sys.stderr)
        print("Clone it: git clone https://github.com/adeyosemanputra/pygoat", file=sys.stderr)
        raise SystemExit(2)

    lines = views.read_text(encoding="utf-8", errors="replace").split("\n")
    drifted = []
    for label in LABELS:
        index = label["line"] - 1
        text = lines[index] if 0 <= index < len(lines) else ""
        if label["must_contain"] not in text:
            drifted.append((label["line"], label["must_contain"], text.strip()[:70]))

    if drifted:
        print("error: the checkout has moved since these labels were written.", file=sys.stderr)
        for line, expected, found in drifted:
            print(f"  line {line}: expected {expected!r}, found {found!r}", file=sys.stderr)
        print("Re-read the views and update LABELS rather than scoring against "
              "the wrong lines.", file=sys.stderr)
        raise SystemExit(3)

    samples = out / "samples"
    if samples.exists():
        shutil.rmtree(samples)
    samples.mkdir(parents=True, exist_ok=True)

    name = "pygoat_views.py"
    shutil.copy2(views, samples / name)

    payload = {
        "schema_version": 1,
        "name": "OWASP PyGoat",
        "source": "https://github.com/adeyosemanputra/pygoat",
        "licence": "MIT",
        "match_mode": "line",
        "match_mode_note": (
            "Sinks were located by hand, so detections are matched against the "
            "line that performs the unsafe operation. This is a real "
            "application rather than a set of isolated snippets, so a miss "
            "here says more about coverage than a miss on a synthetic sample."
        ),
        "clean_files": [],
        "labels": [
            {
                "file": name,
                "line": entry["line"],
                "cwe": entry["cwe"],
                "type": entry["type"],
                "note": entry["note"],
            }
            for entry in LABELS
        ],
    }
    (out / "labels.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return {"labels": len(LABELS), "file": name}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the PyGoat corpus.")
    parser.add_argument("--source", required=True, help="Path to a PyGoat checkout")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Destination directory")
    args = parser.parse_args()

    summary = build(Path(args.source), Path(args.out))
    print(f"wrote {summary['labels']} label(s) for {summary['file']} to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
