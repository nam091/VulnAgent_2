# VulnAgent Editor On-Save Demo Runbook

Hướng dẫn thao tác nghiệm thu tính năng on-save trigger, diagnostic feedback, concurrency lock contention và rescan trên editor thật (VSCode, Cursor, Neovim).

---

## 1. Môi trường & Điều kiện tiên quyết

- **Hệ điều hành:** Windows 10/11, Linux (Ubuntu 22.04+), hoặc macOS.
- **Python:** Python 3.10 trở lên (đã kiểm chứng trên Python 3.14).
- **Editor:** Visual Studio Code (hoặc Cursor) cài extension `Run on Save` / task runner, hoặc Neovim (với `autocmd BufWritePost`).
- **Dependencies:**
  ```bash
  pip install -r requirements.txt
  pip install bandit semgrep
  ```
- **Quy tắc bảo vệ môi trường:** Chạy offline/local rule mode với file `rules/pinned_security_rules.yaml` (không yêu cầu LLM API key cho rule-only mode).

---

## 2. Bước 1: Khởi tạo cấu hình Editor Hook

Chạy lệnh cấu hình tự động cho workspace:

```bash
# Cấu hình tự động cho VSCode / Cursor
python -m cli.editor_integration configure --editor vscode --workspace .
```

### Kiểm tra cấu hình được sinh:
Mở file `.vscode/settings.json` trong workspace, xác nhận cấu hình có entry định danh duy nhất:

```json
{
  "emeraldwalk.runonsave": {
    "commands": [
      {
        "match": "\\.py$",
        "cmd": "python \"F:/Projects/VulnAgent/src/cli.py\" hook --files \"${file}\"",
        "id": "vulnagent-on-save"
      }
    ]
  }
}
```

*Ghi chú bảo toàn:* Lệnh configure là idempotent, giữ nguyên toàn bộ command khác của người dùng và cập nhật đúng launcher path của VulnAgent.

---

## 3. Bước 2: Kịch bản Trigger Save trên tệp mẫu lỗi

1. Mở file mẫu: `examples/vulnerable_app.py`.
2. Thực hiện chỉnh sửa nhỏ (ví dụ thêm khoảng trắng hoặc comment) và nhấn `Ctrl + S` (Save).
3. **Phản hồi mong đợi (Expected Feedback):**
   - Hook chạy ngầm với tham số `--files examples/vulnerable_app.py`.
   - Kết quả phát hiện lỗ hổng hiển thị trong Terminal / Output tab:
     - `CWE-89`: SQL Injection tại dòng 17 (`cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")`)
     - `CWE-79`: Cross-Site Scripting (XSS) tại dòng 25 (`render_template_string(template)`)
     - `CWE-22`: Path Traversal tại dòng 31 (`open(filename, 'r').read()`)
     - `CWE-78`: Command Injection tại dòng 37 (`subprocess.check_output(f"ping -c 1 {host}", shell=True)`)
   - Exit code của hook: `1` (báo hiệu phát hiện lỗ hổng chưa được xác minh/khắc phục).

---

## 4. Bước 3: Kiểm thử Save khi Scan đang chạy (Lock Contention & Trailing Save)

Kịch bản kiểm tra khả năng không bị nuốt sự kiện save khi scan trước chưa hoàn tất:

1. Thực hiện Save file `examples/vulnerable_app.py`.
2. Ngay khi tiến trình scan đang giữ file lock (trong khoảng 1–2 giây đầu), thực hiện tiếp một chỉnh sửa và nhấn `Ctrl + S` liên tiếp 2 lần.
3. **Hành vi xử lý:**
   - Scan đầu tiên tiếp tục chạy dưới snapshot ban đầu.
   - Các sự kiện save tiếp theo được đưa vào bộ đệm debounce (trailing save).
   - Khi scan đầu tiên nhả lock, trailing save tự động kích hoạt scan mới trên nội dung mới nhất, không bỏ sót thay đổi của lập trình viên.
   - Không xuất hiện xung đột race condition ghi đè session.

---

## 5. Bước 4: Khắc phục lỗ hổng & Kiểm chứng Rescan Tự động

1. Sửa đoạn mã lỗi SQL Injection trong `examples/vulnerable_app.py` thành query an toàn dùng parameter binding:
   ```python
   # Thay dòng 17:
   cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
   ```
2. Sửa đoạn mã Command Injection tại dòng 37:
   ```python
   # Thay dòng 37:
   subprocess.check_output(["ping", "-c", "1", host])
   ```
3. Nhấn `Ctrl + S` để lưu.
4. **Phản hồi mong đợi:**
   - Hook tự động kích hoạt lại.
   - Findings của `CWE-89` và `CWE-78` được đánh dấu resolved.
   - Diagnostic cho hai lỗi này được xóa bỏ.

---

## 6. Bước 5: Thu thập Log & Audit Trail

- Toàn bộ lịch sử scan và bằng chứng được lưu tại:
  - Cache: `.vulnagent-cache/`
  - Phiên làm việc: `.vulnagent-jobs/`
- Kiểm tra log chi tiết:
  ```bash
  python src/cli.py history --limit 5
  ```
- Xác nhận các trường: `status="completed"`, `degraded=false`, danh sách `resolved_findings` chứa các finding ID đã sửa.
