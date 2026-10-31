"""
Prepare Six Repos Benchmark Dataset (10 CWEs across 6 projects - No Saleor).

Repositories:
1. Django (django/django)
2. SaltStack (saltstack/salt)
3. Apache Airflow (apache/airflow)
4. WeasyPrint (Kozea/WeasyPrint)
5. Gradio (gradio-app/gradio)
6. Ansible (ansible/ansible)
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATASET_DIR = BASE_DIR / "datasets" / "six_repos"
SAMPLES_DIR = DATASET_DIR / "samples"
REPORTS_DIR = BASE_DIR.parent / "reports" / "six_repos_experiment"

# 10 Vulnerable Samples and 6 Clean Control Samples
SAMPLES_METADATA = {
    # 10 Vulnerable CVE Samples
    "django_sqli.py": {
        "repo": "django/django",
        "tag": "4.0.5",
        "url": "https://raw.githubusercontent.com/django/django/4.0.5/django/db/models/functions/datetime.py",
        "cwe": "89",
        "type": "SQL_INJECTION",
        "note": "Django CVE-2022-34265 (CWE-89): SQL Injection in Trunc() and Extract() database functions via unsanitized kind / lookup_name parameters",
    },
    "salt_cmdi.py": {
        "repo": "saltstack/salt",
        "tag": "v3002",
        "url": "https://raw.githubusercontent.com/saltstack/salt/v3002/salt/client/ssh/shell.py",
        "cwe": "78",
        "type": "COMMAND_INJECTION",
        "note": "SaltStack CVE-2020-16846 (CWE-78): OS Command Injection via shell=True in ssh-keygen command formatting",
    },
    "airflow_pathtraversal.py": {
        "repo": "apache/airflow",
        "tag": "2.6.2",
        "url": "https://raw.githubusercontent.com/apache/airflow/2.6.2/airflow/models/dagrun.py",
        "cwe": "22",
        "type": "PATH_TRAVERSAL",
        "note": "Apache Airflow CVE-2023-22887 (CWE-22): Path Traversal via unvalidated DagRun run_id parameter in directory path construction",
    },
    "salt_deserialization.py": {
        "repo": "saltstack/salt",
        "tag": "v3000.1",
        "url": "https://raw.githubusercontent.com/saltstack/salt/v3000.1/salt/transport/zeromq.py",
        "cwe": "502",
        "type": "DESERIALIZATION",
        "note": "SaltStack CVE-2020-11651 (CWE-502 / CWE-287): Insecure Deserialization of unauthenticated ZeroMQ message loads",
    },
    "weasyprint_ssrf.py": {
        "repo": "Kozea/WeasyPrint",
        "tag": "v58.1",
        "url": "https://raw.githubusercontent.com/Kozea/WeasyPrint/v58.1/weasyprint/urls.py",
        "cwe": "918",
        "type": "SSRF",
        "note": "WeasyPrint CVE-2023-24816 (CWE-918): Server-Side Request Forgery (SSRF) via arbitrary URL fetching and redirection",
    },
    "gradio_xss.py": {
        "repo": "gradio-app/gradio",
        "tag": "gradio@4.12.0",
        "url": "https://raw.githubusercontent.com/gradio-app/gradio/gradio@4.12.0/gradio/components/html.py",
        "cwe": "79",
        "type": "XSS",
        "note": "Gradio CVE-2024-1561 / CVE-2024-1729 (CWE-79): Cross-Site Scripting via unsanitized raw HTML component rendering and component injection",
    },
    "ansible_hardcoded_secret.py": {
        "repo": "ansible/ansible",
        "tag": "v2.9.12",
        "url": "https://raw.githubusercontent.com/ansible/ansible/v2.9.12/lib/ansible/parsing/vault/__init__.py",
        "cwe": "798",
        "type": "HARDCODED_CREDENTIALS",
        "note": "Ansible CVE-2020-14365 (CWE-798): Hardcoded secret and sensitive credential handling in vault encryption routines",
    },
    "salt_auth_bypass.py": {
        "repo": "saltstack/salt",
        "tag": "v3000.1",
        "url": "https://raw.githubusercontent.com/saltstack/salt/v3000.1/salt/master.py",
        "cwe": "287",
        "type": "AUTH_BYPASS",
        "note": "SaltStack ClearFuncs CVE-2020-11651 (CWE-287): Authentication Bypass in ClearFuncs exposing privileged master methods to unauthenticated callers",
    },
    "airflow_idor.py": {
        "repo": "apache/airflow",
        "tag": "2.6.2",
        "url": "https://raw.githubusercontent.com/apache/airflow/2.6.2/airflow/api_connexion/endpoints/task_instance_endpoint.py",
        "cwe": "639",
        "type": "IDOR",
        "note": "Apache Airflow DAG/Task unvalidated access (CWE-639): Insecure Direct Object Reference (IDOR) via unvalidated task instance access",
    },
    "gradio_info_disclosure.py": {
        "repo": "gradio-app/gradio",
        "tag": "gradio@4.12.0",
        "url": "https://raw.githubusercontent.com/gradio-app/gradio/gradio@4.12.0/gradio/routes.py",
        "cwe": "209",
        "type": "INFORMATION_DISCLOSURE",
        "note": "Gradio CVE-2024-1729 (CWE-209): Information Disclosure via detailed exception tracebacks in route responses",
    },

    # 6 Clean Control Samples
    "clean_django_crypto.py": {
        "repo": "django/django",
        "tag": "4.0.5",
        "url": "https://raw.githubusercontent.com/django/django/4.0.5/django/utils/crypto.py",
        "clean": True,
        "note": "Django 4.0.5 clean cryptographic utility routines",
    },
    "clean_airflow_dates.py": {
        "repo": "apache/airflow",
        "tag": "2.6.2",
        "url": "https://raw.githubusercontent.com/apache/airflow/2.6.2/airflow/utils/dates.py",
        "clean": True,
        "note": "Apache Airflow 2.6.2 clean date and timezone utility routines",
    },
    "clean_salt_units.py": {
        "repo": "saltstack/salt",
        "tag": "v3002",
        "url": "https://raw.githubusercontent.com/saltstack/salt/v3002/salt/utils/timeutil.py",
        "clean": True,
        "note": "SaltStack v3002 clean time and unit utility routines",
    },
    "clean_ansible_display.py": {
        "repo": "ansible/ansible",
        "tag": "v2.9.12",
        "url": "https://raw.githubusercontent.com/ansible/ansible/v2.9.12/lib/ansible/utils/display.py",
        "clean": True,
        "note": "Ansible v2.9.12 clean terminal display and output formatting routines",
    },
    "clean_gradio_media.py": {
        "repo": "gradio-app/gradio",
        "tag": "gradio@4.12.0",
        "url": "https://raw.githubusercontent.com/gradio-app/gradio/gradio@4.12.0/gradio/processing_utils.py",
        "clean": True,
        "note": "Gradio 4.12.0 clean media processing utilities (audio/image/video encoding)",
    },
    "clean_weasyprint_units.py": {
        "repo": "Kozea/WeasyPrint",
        "tag": "v58.1",
        "url": "https://raw.githubusercontent.com/Kozea/WeasyPrint/v58.1/weasyprint/css/utils.py",
        "clean": True,
        "note": "WeasyPrint v58.1 clean CSS dimension and unit conversion utilities",
    },
}


def download_file(url: str, dest_path: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        content = resp.read()
    dest_path.write_bytes(content)


def main():
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[+] Output directory created: {SAMPLES_DIR}")
    print(f"[+] Report directory created: {REPORTS_DIR}")

    clean_files = []
    labels = []

    for filename, meta in SAMPLES_METADATA.items():
        dest = SAMPLES_DIR / filename
        print(f"Downloading {filename} from {meta['repo']} ({meta['tag']})...")
        download_file(meta["url"], dest)
        size = dest.stat().st_size
        print(f"  -> Saved {dest} ({size:,} bytes)")

        # Verify syntax
        code = dest.read_text(encoding="utf-8", errors="replace")
        compile(code, filename, "exec")

        if meta.get("clean"):
            clean_files.append(filename)
        else:
            labels.append({
                "file": filename,
                "line": 0,
                "cwe": meta["cwe"],
                "type": meta["type"],
                "note": meta["note"],
            })

    labels_data = {
        "schema_version": 1,
        "name": "Six Repositories (10 CWE) Vulnerability Benchmark",
        "source": "Airflow, SaltStack, Gradio, Django, Ansible, WeasyPrint official release tags",
        "licence": "Various open-source licenses (Apache-2.0, BSD-3-Clause, GPL-3.0)",
        "match_mode": "file",
        "match_mode_note": "Standardized benchmark of 10 real-world CVE defect files across 10 CWE categories and 6 clean control files from 6 major Python open-source repositories.",
        "partial_labels": False,
        "clean_files": sorted(clean_files),
        "labels": sorted(labels, key=lambda x: x["file"]),
    }

    labels_path = DATASET_DIR / "labels.json"
    with open(labels_path, "w", encoding="utf-8") as f:
        json.dump(labels_data, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Successfully generated labels.json at {labels_path}")
    print(f"  Total samples: {len(SAMPLES_METADATA)} (10 vulnerable, 6 clean)")
    print(f"  Clean files:   {len(clean_files)}")
    print(f"  Labels:        {len(labels)}")


if __name__ == "__main__":
    main()
