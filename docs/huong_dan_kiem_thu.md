# Hướng Dẫn Kiểm Thử Toàn Diện Các Chức Năng Của VulnAgent

Tài liệu này cung cấp hướng dẫn từng bước (step-by-step) để kiểm thử thực tế toàn bộ các tính năng của VulnAgent trên máy tính của bạn, bao gồm: CLI, Tự động sửa lỗi (Fixer), Baseline, Giao thức MCP (cho AI Agent), Editor Hook (On-Save), Giao diện Web (Serve), Đo lường Benchmark và Bộ kiểm thử (Pytest).

---

## 1. Chuẩn Bị Môi Trường & Khởi Tạo

Mở terminal tại thư mục gốc của dự án `VulnAgent`:

```bash
# 1. Kích hoạt môi trường ảo (nếu dùng venv)
# Trên Linux/macOS:
source venv/bin/activate
# Trên Windows PowerShell:
venv\Scripts\Activate.ps1
# Trên Windows CMD:
venv\Scripts\activate.bat

# 2. Cài đặt package ở chế độ editable
pip install -e .

# 3. Tạo file cấu hình môi trường .env (nếu chưa có)
cp .env.example .env
# Mở file .env và điền API key nếu bạn muốn test tầng LLM (OpenAI / Anthropic / Mimo)
```

### Kiểm tra sức khỏe môi trường bằng lệnh Doctor
```bash
vulnagent doctor
```
**Kết quả mong đợi:** Lệnh sẽ kiểm tra và in ra trạng thái của Python runtime, binary của Semgrep, Git, và sự sẵn sàng của các file rules.

---

## 2. Kiểm Thử Quét Mã Nguồn Bằng CLI (`vulnagent scan`)

### 2.1. Quét nhanh bằng Rule Tier (Không gọi LLM - Siêu tốc)
```bash
vulnagent scan examples/vulnerable_app.py --no-llm
```
**Kết quả mong đợi:**
- Thời gian quét: ~3–6 giây.
- Bắt trọn vẹn 5 lỗ hổng bảo mật:
  - `CRITICAL`: SQL Injection (`CWE-89`) tại dòng 17.
  - `CRITICAL`: Command Injection (`CWE-78`) tại dòng 38.
  - `HIGH`: Cross-Site Scripting (`CWE-79`) tại dòng 21–25.
  - `HIGH`: Path Traversal (`CWE-22`) tại dòng 31.
  - `MEDIUM`: Security Misconfiguration (`CWE-16`, mở host `0.0.0.0`) tại dòng 53.
- Exit code trả về là `1` (do phát hiện lỗ hổng vượt ngưỡng mặc định).

### 2.2. Quét chi tiết hiển thị đầy đủ ngữ cảnh & đề xuất vá
```bash
vulnagent scan examples/vulnerable_app.py --no-llm --verbose
```
**Kết quả mong đợi:** Bảng kết quả in chi tiết đoạn mã có lỗi (Code Snippet), mức độ ảnh hưởng (Impact), giải thích nguyên nhân và đề xuất phương án khắc phục (Remediation).

### 2.3. Xuất báo cáo theo định dạng chuẩn SARIF (Cho GitHub / DevSecOps)
```bash
vulnagent scan examples/vulnerable_app.py --no-llm --format sarif -o output.sarif
```
**Kết quả mong đợi:** File `output.sarif` được sinh ra tại thư mục gốc, đúng chuẩn định dạng OASIS SARIF v2.1.0, có thể upload trực tiếp lên tab Security của GitHub.

### 2.4. Kiểm thử Cổng Chặn CI/CD (Gate Severity & Corroborated Only)
```bash
# Đánh fail nếu có lỗi từ mức HIGH trở lên:
vulnagent scan examples/vulnerable_app.py --no-llm --fail-on high
# Kiểm tra exit code (Windows: $LASTEXITCODE, Linux/macOS: echo $?) -> Kết quả: 1

# Chỉ đánh fail nếu lỗi ở mức CRITICAL:
vulnagent scan examples/vulnerable_app.py --no-llm --fail-on critical
# Kiểm tra exit code -> Kết quả: 1

# Thiết lập ngưỡng không bao giờ đánh rớt build:
vulnagent scan examples/vulnerable_app.py --no-llm --fail-on never
# Kiểm tra exit code -> Kết quả: 0 (sạch về mặt gate CI/CD)
```

---

## 3. Kiểm Thử Cơ Chế Baseline & Chống Nhiễu (Suppression)

### 3.1. Đóng băng lỗi cũ làm "Nợ kỹ thuật" (Baseline)
Khi đưa VulnAgent vào một codebase cũ có sẵn hàng chục lỗi, ta có thể chấp nhận các lỗi cũ và chỉ bắt các lỗi mới sinh ra:

```bash
# 1. Tạo file baseline ghi nhận toàn bộ lỗi hiện tại (chế độ rule-only offline)
vulnagent baseline examples/ --no-llm

# 2. Quét lại với cờ --fail-on-new
vulnagent scan examples/ --baseline --fail-on-new --no-llm
```
**Kết quả mong đợi:**
- Sinh ra file `.vulnagent-baseline.json`.
- Lệnh quét lần 2 sẽ thông báo các lỗi đã nằm trong baseline và trả về **Exit Code 0** (Build vẫn xanh vì không có lỗ hổng mới phát sinh).

### 3.2. Bỏ qua cảnh báo bằng Comment (Inline Suppression)
Mở file mã nguồn và thêm comment chỉ định:
```python
# vulnagent: ignore[SQL_INJECTION]
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
```
Hoặc dùng comment `# nosec` hoặc `# nosemgrep`. Khi quét lại, VulnAgent sẽ tự động bỏ qua dòng này.

---

## 4. Kiểm Thử Tự Động Sửa Lỗi An Toàn (`vulnagent fix`)

> **Lưu ý quan trọng về API Key:** Chức năng `fix` bắt buộc yêu cầu có API key của LLM trong file `.env` (OpenAI, Anthropic hoặc endpoint tương thích) vì tầng Semgrep thuần túy không sinh bản vá ngữ nghĩa. Nếu chưa cấu hình hoặc API key hết hạn, lệnh sẽ thông báo `No applicable patches` kèm cảnh báo lỗi tài khoản LLM.

### 4.1. Xem trước bản vá (Dry-run / Preview)
```bash
vulnagent fix examples/vulnerable_app.py --dry-run
```
**Kết quả mong đợi:** 
- Khi có API key LLM hợp lệ: In ra bảng các bản vá dự kiến kèm diff phân loại mức độ rủi ro (`risk="safe"` hoặc `risk="review"`), **không** can thiệp hay ghi đè vào file trên đĩa.
- Khi không có API key LLM: In thông báo `No applicable patches` (bỏ qua do thiếu secure code example từ LLM).

### 4.2. Áp dụng bản vá kèm kiểm chứng tự động (`--verify`)
```bash
vulnagent fix examples/vulnerable_app.py --verify
```
**Cơ chế hoạt động:**
1. Sinh bản vá sạch (clean substitution).
2. Kiểm tra cú pháp AST để đảm bảo code không bị lỗi cú pháp Python.
3. Chạy quét lại (rescan). Nếu bản vá làm phát sinh thêm lỗi mới hoặc không làm giảm số lượng lỗi, hệ thống sẽ **tự động hoàn tác (revert)** để bảo toàn code của bạn.

---

## 5. Kiểm Thử Giao Thức MCP Server (Dành Cho Cursor & Claude Code)

VulnAgent cung cấp MCP Server qua `stdio` để AI Agent (như Cursor Composer, Windsurf, Claude Code) tự động gọi audit code.

### 5.1. Chạy kịch bản kiểm thử MCP độc lập (Test Client Script)
Dự án đã chuẩn bị sẵn file script kiểm tra bắt tay giao thức và gọi trực tiếp các tool MCP tại `examples/test_mcp_client.py`:

```bash
python examples/test_mcp_client.py
```
**Kết quả mong đợi:** 
- In `[+] Bắt tay giao thức MCP: THÀNH CÔNG!`
- Liệt kê đầy đủ danh mục **12 công cụ MCP**.
- Bắt chính xác lỗ hổng `CRITICAL OS_COMMAND_INJECTION` (CWE-78) và in đoạn code vi phạm kèm đề xuất sửa.

### 5.2. Cấu hình tích hợp vào Cursor hoặc Claude Code
Mở file cấu hình MCP của Cursor (ví dụ: `.cursor/mcp.json` hoặc trong Settings của Cursor):

```json
{
  "mcpServers": {
    "vulnagent": {
      "command": "python",
      "args": ["<DUONG_DAN_TUYET_DOI_TOI_REPO>/src/mcp_server.py"]
    }
  }
}
```
**Cách thử nghiệm trên Cursor Composer / Chat:**
Nhập prompt:
> *"Hãy dùng tool `scan_code` của `vulnagent` kiểm tra đoạn mã sau đây xem có lỗ hổng không và đề xuất cách sửa an toàn: ..."*

---

## 6. Kiểm Thử Editor On-Save Hook (VS Code / Cursor)

Tính năng On-save Hook cho phép tự động kích hoạt quét ngầm mỗi khi bạn bấm `Ctrl + S`.

### 6.1. Khởi tạo cấu hình tự động
```bash
python src/cli.py init --host vscode --rules "rules/pinned_security_rules.yaml"
```
**Kết quả:** 
- Tự động cấu hình file `.vscode/settings.json` kết nối với extension `emeraldwalk.runonsave`.
- Tự động sinh file `.cursorrules` và `CLAUDE.md` trong workspace.

### 6.2. Kiểm chứng các chốt chặn an toàn của Hook
- **Cơ chế Debounce (1.5 giây):** Mở file Python bất kỳ, gõ và bấm `Ctrl + S` liên tục 5 lần. Hook sẽ gom lại và chỉ chạy **1 lần duy nhất** sau khi bạn ngừng lưu 1.5 giây.
- **Cơ chế Dirty Snapshotting:** Nếu bấm `Ctrl + S` nhưng nội dung file không thay đổi, hook sẽ nhận biết hash không đổi và **bỏ qua ngay lập tức**, không tốn CPU.
- **Tiến trình khóa File Lock (`.vulnagent.lock`):** Đảm bảo không bao giờ có 2 tiến trình scan chạy đè lên nhau gây corrupt dữ liệu.

---

## 7. Kiểm Thử Giao Diện Web & REST API (`vulnagent serve`)

Khởi động web server cục bộ:
```bash
vulnagent serve
```
Mở trình duyệt web và truy cập:
- **Giao diện Web:** `http://localhost:8000`  
  - Dán đoạn code cần kiểm tra hoặc upload file Python.
  - Xem kết quả trực quan dạng thẻ màu sắc và chuỗi tấn công (Attack Chains).
- **Tài liệu API tương tác (Swagger UI):** `http://localhost:8000/docs`  
  - Test trực tiếp các endpoint REST: `POST /api/scan`, `GET /api/jobs/{job_id}`, `POST /api/fix`.

---

## 8. Kiểm Thử Bộ Đo Lường Benchmark (Evaluation Harness)

Hệ thống đánh giá độ chính xác khoa học của VulnAgent trên các bộ dữ liệu gán nhãn:

```bash
# 1. Chạy đánh giá trên tập dataset mẫu nội bộ (Cold Cache):
python eval/run_eval.py --only semgrep --no-bandit --cold

# 2. Chạy đánh giá và xuất Manifest kiểm chứng tính toàn vẹn:
python eval/run_eval.py --only semgrep --no-bandit --cold --json benchmark_report.json
```
**Kết quả mong đợi:**
- In ra bảng thống kê: TP (True Positive), FP (False Positive), FN (False Negative), Precision, Recall, F1.
- Khối `integrity` trong file `benchmark_report.json` đạt `verified = true`, ghi nhận toàn vẹn hash của rules và dataset trước/sau scan.

---

## 9. Chạy Toàn Bộ Bộ Kiểm Thử (Full Pytest Suite)

Để xác nhận toàn bộ 100% tính năng hoạt động không lỗi hồi quy:

```bash
# 1. Chạy nhanh các unit test cốt lõi:
python -m pytest tests/test_core.py tests/test_workflow.py -q

# 2. Chạy toàn bộ 121 tests của dự án:
python -m pytest tests -q -ra
```
**Kết quả chuẩn mực:**
```text
121 passed in ~120s (100% PASS, 0 failures, 0 errors)
```
