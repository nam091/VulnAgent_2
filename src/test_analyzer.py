import asyncio
import json
from datetime import datetime
from pathlib import Path

from analyzer.code_analyzer import CodeAnalyzer

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "output"


async def main():
    # Initialize the analyzer
    analyzer = CodeAnalyzer()

    # Read the vulnerable application code
    vuln_app_path = ROOT / "examples" / "vulnerable_app.py"
    content = vuln_app_path.read_text(encoding="utf-8")

    print("Starting security analysis...")

    # Analyze the code
    report = await analyzer.analyze_code(content, str(vuln_app_path))

    # Calculate summary statistics
    report.calculate_summary()
    report.calculate_risk_score()

    # Print the results
    print("\nVulnerability Report:")
    print("=" * 80)
    print(f"File analyzed: {vuln_app_path}")
    print(f"Total vulnerabilities found: {report.summary['total']}")
    print(f"Risk score: {report.risk_score:.2f}")
    print("\nVulnerability distribution:")
    for severity, count in report.summary.items():
        if severity != "total":
            print(f"  {severity}: {count}")

    print("\nDetailed vulnerabilities:")
    print("=" * 80)
    for vuln in report.vulnerabilities:
        print(f"\nType: {vuln.type}")
        print(f"Severity: {vuln.severity}")
        print(f"Location: {vuln.location.file_path}:{vuln.location.start_line}")
        print(f"Description: {vuln.description}")
        print(f"Impact: {vuln.impact}")
        print(f"Remediation: {vuln.remediation}")
        print("-" * 40)

    if report.chained_vulnerabilities:
        print("\nVulnerability Chains:")
        print("=" * 80)
        for chain in report.chained_vulnerabilities:
            print(f"\nChain Severity: {chain.combined_severity}")
            print(f"Attack Path: {chain.attack_path}")
            print("Vulnerabilities in chain:")
            for vuln in chain.vulnerabilities:
                print(f"  - {vuln.type} ({vuln.severity})")
            print("-" * 40)

    # Save the report under output/
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = OUTPUT_DIR / f"vulnerability_report_{stamp}.json"
    latest_path = OUTPUT_DIR / "vulnerability_report_latest.json"
    payload = json.dumps(report.model_dump(), indent=2, default=str)
    report_path.write_text(payload, encoding="utf-8")
    latest_path.write_text(payload, encoding="utf-8")
    print(f"\nDetailed report saved to {report_path}")
    print(f"Latest copy: {latest_path}")


if __name__ == "__main__":
    asyncio.run(main())
