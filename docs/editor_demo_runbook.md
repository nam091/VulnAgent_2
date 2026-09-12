# VulnAgent Editor On-Save Demo Runbook

Hướng dẫn thao tác nghiệm thu tính năng on-save trigger, diagnostic feedback, concurrency lock contention và rescan trên editor thật (VS Code, Cursor).

---

## 1. Môi trường & Điều kiện tiên quyết

- **Hệ điều hành:** Windows 10/11, Linux (Ubuntu 22.04+), hoặc macOS.
- **Python:** Python 3.10 trở lên (khuyến nghị virtualenv của dự án).
- **Editor:** Visual Studio Code hoặc Cursor cài extension `Run on Save` (`emeraldwalk.runonsave`).
- **Dependencies:**
  ```bash
  pip install -r requirements.txt
  pip install semgrep bandit
  ```
- **Thiết lập Rules Offline:**
  Để quy trình editor hook chạy hoàn toàn offline không gọi ra ngoài:
  ```bash
  # Trên Linux / macOS:
  export VULNAGENT_SEMGREP_RULES="rules/pinned_security_rules.yaml"

  # Trên Windows PowerShell:
  $env:VULNAGENT_SEMGREP_RULES = "rules/pinned_security_rules.yaml"
  ```

---

## 2. Bước 1: Khởi tạo cấu hình Editor Hook

Chạy lệnh khởi tạo tự động cho workspace (chọn host `vscode` hoặc `cursor`):

```bash
# Cấu hình tự động cho VS Code:
python src/cli.py init --host vscode

# Hoặc cho Cursor:
python src/cli.py init --host cursor
```

### Kiểm tra sức khỏe môi trường:
```bash
python src/cli.py doctor
```
Lệnh doctor sẽ xác minh Python runtime, Semgrep binary, Git, và sự hiện diện của file cấu hình `.vscode/` hoặc `.cursor/`.

### Kiểm tra cấu hình được sinh:
Mở file `.vscode/settings.json` (hoặc `.cursor/settings.json`), xác nhận entry on-save:
```json
{
  "emeraldwalk.runonsave": {
    "commands": [
      {
        "match": "\\.py$",
        "cmd": "\"<python_path>\" \"<project_root>/src/cli.py\" hook --target \"${workspaceFolder}\" --files \"${file}\" --trailing",
        "id": "vulnagent-on-save"
      }
    ]
  }
}
```
Và file `.vscode/tasks.json` chứa task `"VulnAgent On-Save Security Check"`.

*Ghi chú bảo toàn:* Lệnh `init` là idempotent, bảo tồn toàn bộ tasks và settings có sẵn của người dùng, chỉ cập nhật entry có id `vulnagent-on-save`.

---

## 3. Bước 2: Kịch bản Trigger Save trên tệp mẫu lỗi

1. Mở file mẫu: `examples/vulnerable_app.py`.
2. Kiểm tra bộ quy tắc offline `rules/pinned_security_rules.yaml` bao phủ các sink chính trong file mẫu:
   - Dòng 17: `CWE-89` (SQL Injection - `cursor.execute(f"...")`)
   - Dòng 25: `CWE-79` (XSS - `render_template_string(...)`)
   - Dòng 31: `CWE-22` (Path Traversal - `open(filename, ...)`)
   - Dòng 38: `CWE-78` (Command Injection - `subprocess.check_output(..., shell=True)`)
3. Chỉnh sửa nhẹ (thêm khoảng trắng/comment) và nhấn `Ctrl + S`.
4. **Phản hồi mong đợi (Expected Output trong Terminal):**
   ```text
   Hook status: findings_detected
     - [HIGH] SQL_INJECTION (CWE-89) at examples/vulnerable_app.py:17
     - [HIGH] CROSS_SITE_SCRIPTING (CWE-79) at examples/vulnerable_app.py:25
     - [MEDIUM] PATH_TRAVERSAL (CWE-22) at examples/vulnerable_app.py:31
     - [HIGH] OS_COMMAND_INJECTION (CWE-78) at examples/vulnerable_app.py:38
   ```
   Exit code của tiến trình: `1` (báo hiệu phát hiện lỗ hổng bảo mật).

---

## 4. Bước 3: Kiểm thử Save khi Scan đang chạy (Lock Contention & Trailing Save)

Kịch bản kiểm tra khả năng không bị nuốt sự kiện save khi scan trước chưa hoàn tất:

1. Thực hiện Save file `examples/vulnerable_app.py`.
2. Ngay khi scan đang diễn ra (tiến trình giữ file lock `.vulnagent.lock`), thực hiện tiếp chỉnh sửa thứ hai và nhấn `Ctrl + S` 2 lần liên tiếp.
3. **Hành vi xử lý:**
   - Scan đầu tiên chạy trên snapshot ban đầu.
   - Các sự kiện save tiếp theo được ghi nhận qua dirty generation tracking và trailing debounce (`--trailing`).
   - Ngay khi scan đầu tiên hoàn thành và nhả lock, tiến trình trailing tự động khởi động scan mới với nội dung tệp mới nhất.
   - Không xuất hiện xung đột race condition ghi đè trạng thái.

---

## 5. Bước 4: Khắc phục lỗ hổng & Kiểm chứng Rescan Tự động

1. Sửa đoạn mã SQL Injection tại dòng 17 trong `examples/vulnerable_app.py`:
   ```python
   # Thay bằng truy vấn parameterized binding an toàn:
   cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
   ```
2. Sửa đoạn mã Command Injection tại dòng 38:
   ```python
   # Thay bằng danh sách tham số, bỏ shell=True:
   result = subprocess.check_output(["ping", "-c", "1", host])
   ```
3. Nhấn `Ctrl + S` để lưu.
4. **Phản hồi mong đợi:**
   - Hook tự động kích hoạt lại.
   - Output cập nhật, các lỗ hổng đã sửa không còn xuất hiện trong danh sách.
   - Khi sửa sạch toàn bộ lỗ hổng:
     ```text
     Hook status: clean
     ```
     Exit code trả về: `0`.

---

## 6. Bước 5: Thu thập Log & Audit Trail

- Thư mục lưu vết kiểm toán và trạng thái:
  - Trạng thái runner: `.vulnagent-audit/runner_state.json`
  - Nhật ký sự kiện và bằng chứng: `.vulnagent-audit/audit.jsonl`
  - Cache nội dung: `.vulnagent-cache/`

- Kiểm tra audit trail qua CLI:
  ```bash
  python src/cli.py history --limit 5
  ```
  Output mẫu:
  ```text
  VulnAgent Audit Trail:
    [2026-09-13T...] SCAN             status=completed  scan_id=...
    [2026-09-13T...] ASSESSMENT       status=supported  finding_id=...
  
  Runner State (.vulnagent-audit/runner_state.json):
    Last on-save run: 2026-09-13T...
    Tracked files:    1
  ```

- Kiểm tra qua giao thức MCP stdio:
  Client kết nối `python src/mcp_server.py` có thể gọi tool `get_assessment_history(scan_id=...)` để đọc toàn bộ audit log của phiên làm việc.
