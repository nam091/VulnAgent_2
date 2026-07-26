"""One-off test: analyze examples/vulnerable_app.py via Mimo API."""
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, "src")

from dotenv import load_dotenv

load_dotenv()

from analyzer.code_analyzer import CodeAnalyzer  # noqa: E402

ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = ROOT / "output"


async def run() -> None:
    print("BASE", os.getenv("OPENAI_BASE_URL"))
    print("MODEL", os.getenv("OPENAI_MODEL"))
    code = (ROOT / "examples" / "vulnerable_app.py").read_text(encoding="utf-8")
    analyzer = CodeAnalyzer()
    report = await analyzer.analyze_code(code, "vulnerable_app.py")
    data = report.model_dump() if hasattr(report, "model_dump") else report.dict()
    vulns = data.get("vulnerabilities") or []
    print("VULN_COUNT", len(vulns))
    for i, v in enumerate(vulns[:15], 1):
        vtype = v.get("type")
        sev = v.get("severity")
        desc = (v.get("description") or "")[:120]
        print(f"{i}. {vtype} | {sev} | {desc}")
    chained = data.get("chained_vulnerabilities") or []
    print("CHAIN_COUNT", len(chained))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = OUTPUT_DIR / f"test_report_{stamp}.json"
    latest_path = OUTPUT_DIR / "test_report_latest.json"
    payload = json.dumps(data, indent=2, default=str, ensure_ascii=False)
    report_path.write_text(payload, encoding="utf-8")
    latest_path.write_text(payload, encoding="utf-8")
    print(f"WROTE {report_path}")
    print(f"WROTE {latest_path}")


if __name__ == "__main__":
    asyncio.run(run())
