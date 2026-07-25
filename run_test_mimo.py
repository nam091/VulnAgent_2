"""One-off test: analyze examples/vulnerable_app.py via Mimo API."""
import asyncio
import json
import os
import sys

sys.path.insert(0, "src")

from dotenv import load_dotenv

load_dotenv()

from analyzer.code_analyzer import CodeAnalyzer  # noqa: E402


async def run() -> None:
    print("BASE", os.getenv("OPENAI_BASE_URL"))
    print("MODEL", os.getenv("OPENAI_MODEL"))
    code = open("examples/vulnerable_app.py", encoding="utf-8").read()
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
    with open("test_report.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)
    print("WROTE test_report.json")


if __name__ == "__main__":
    asyncio.run(run())
