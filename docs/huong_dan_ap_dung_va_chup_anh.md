# Hướng Dẫn Áp Dụng VulnAgent & Danh Sách Ảnh Chụp Báo Cáo Đồ Án

Tài liệu này tóm tắt cực kỳ ngắn gọn:
1. **Tổng quan:** VulnAgent áp dụng vào đâu?
2. **Từng bước thực hiện:** Cách áp dụng qua 3 kênh (MCP cho Cursor, CI/CD GitHub, Web UI).
3. **Checklist 5 ảnh chụp màn hình quan trọng nhất:** Chụp cái gì và chú thích ra sao để đưa vào báo cáo và slide thuyết trình.

---

## PHẦN 1: TỔNG QUAN — VULNAGENT ÁP DỤNG VÀO ĐÂU?

VulnAgent hỗ trợ 3 hình thức áp dụng thực tế:

| Hình thức | Đối tượng sử dụng | Thời điểm áp dụng | Giá trị mang lại |
| :--- | :--- | :--- | :--- |
| **1. MCP Server** *(Khuyên dùng)* | Lập trình viên dùng AI (Cursor, Windsurf, Claude Code) | Khi AI vừa sinh xong đoạn code trong bộ nhớ | AI tự động gọi quét và tự vá lỗi trước khi bàn giao cho người dùng (Vibe Coding an toàn). |
| **2. CI/CD & CLI** | Đội ngũ phát triển, kiểm thử tự động (DevSecOps) | Mỗi khi lập trình viên bấm Lưu (`Ctrl+S`) hoặc tạo Pull Request | Chặn đứng mã độc/lỗ hổng lọt vào nhánh chính, xuất báo cáo chuẩn quốc tế SARIF cho GitHub Security. |
| **3. Web UI** | Quản lý dự án, người review trực quan | Khi muốn dán code kiểm tra nhanh hoặc xem biểu đồ trực quan | Giao diện Dark/Light trực quan, xem chi tiết chuỗi khai thác (Attack Chains) mà không cần mở terminal. |

---

## PHẦN 2: CÁCH ÁP DỤNG TỪNG BƯỚC

### 1. Kênh 1: Áp dụng qua MCP trong Cursor / Claude Code
- **Mục tiêu:** Để Cursor tự động quét và sửa code Python ngay trong khung chat.
- **Bước 1:** Mở file cấu hình MCP của Cursor (ví dụ: `.cursor/mcp.json` hoặc trong Settings > MCP):
  ```json
  {
    "mcpServers": {
      "vulnagent": {
        "command": "python",
        "args": ["F:/PERSIONAL/Projects/VulnAgent/src/mcp_server.py"]
      }
    }
  }
  ```
- **Bước 2:** Chạy kiểm thử kết nối:
  ```bash
  python examples/test_mcp_client.py
  ```
- **Bước 3:** Sử dụng thực tế trong Cursor Composer / Chat:
  Nhập prompt:  
  > *"Hãy dùng công cụ `scan_code` của `vulnagent` kiểm tra đoạn mã sau xem có lỗ hổng không và đề xuất phương án sửa: ..."*

---

### 2. Kênh 2: Áp dụng qua CI/CD (GitHub Actions & Quét CLI)
- **Mục tiêu:** Tự động quét và chặn code lỗi khi tạo Pull Request, hiển thị trên tab Security của GitHub.
- **Bước 1:** Quét kiểm tra thử cục bộ và xuất file báo cáo chuẩn SARIF:
  ```bash
  vulnagent scan examples/vulnerable_app.py --no-llm -f sarif -o output/report.sarif
  ```
- **Bước 2:** Thiết lập cổng chặn rủi ro CI/CD (Chỉ đánh fail build nếu có lỗi từ HIGH trở lên):
  ```bash
  vulnagent scan examples/vulnerable_app.py --no-llm --fail-on high --confirmed-only
  ```
- **Bước 3:** Đóng băng nợ kỹ thuật cho codebase cũ (Không đánh fail lỗi cũ, chỉ bắt lỗi mới):
  ```bash
  vulnagent baseline examples/ --no-llm
  vulnagent scan examples/ --baseline --fail-on-new --no-llm --exclude "broken_syntax.py"
  ```

---

### 3. Kênh 3: Áp dụng qua Giao Diện Web (Web UI & REST API)
- **Mục tiêu:** Mở giao diện web cục bộ để dán code hoặc xem dashboard.
- **Bước 1:** Khởi động máy chủ web:
  ```bash
  vulnagent serve
  ```
- **Bước 2:** Mở trình duyệt web truy cập:
  - Giao diện người dùng: `http://localhost:8000`
  - Tài liệu Swagger REST API: `http://localhost:8000/docs`
- **Bước 3:** Vào mục **New scan**, dán đoạn code cần kiểm tra hoặc upload file để xem bảng kết quả dạng thẻ màu sắc và chuỗi tấn công Attack Chains.

---

## PHẦN 3: CHECKLIST 5 BỨC ẢNH VÀNG CẦN CHỤP CHO BÁO CÁO & SLIDE

Hãy chụp đúng 5 màn hình này để dán vào file Word báo cáo đồ án và slide bảo vệ. Đây là các bằng chứng kỹ thuật đắt giá nhất:

### 📸 Ảnh 1: Kiểm Tra Sức Khỏe Môi Trường Hệ Thống
- **Lệnh chạy trong terminal:**
  ```bash
  vulnagent doctor
  ```
- **Nội dung cần chụp:** Toàn bộ các dòng đều hiển thị `[OK]`, đặc biệt là dòng `MCP handshake smoke test passed (mode: editor, tools: 12)`.
- **Chú thích ảnh trong báo cáo:**  
  *Hình 1: Kết quả kiểm tra sức khỏe môi trường thực thi và khả năng sẵn sàng của 12 công cụ MCP trên hệ thống.*

---

### 📸 Ảnh 2: Tích Hợp AI Coding Agent Qua Giao Thức MCP
- **Lệnh chạy trong terminal:**
  ```bash
  python examples/test_mcp_client.py
  ```
- **Nội dung cần chụp:** Đoạn kết nối thành công, liệt kê 12 tool và kết quả phát hiện `CRITICAL OS_COMMAND_INJECTION (CWE-78)` tại dòng 6 kèm đề xuất sửa `shell=False`.
- **Chú thích ảnh trong báo cáo:**  
  *Hình 2: Tiến trình AI Agent kết nối qua MCP stdio tự động phát hiện lỗ hổng Command Injection trong bộ nhớ.*

---

### 📸 Ảnh 3: Bảng Thực Nghiệm Đối Sánh Khoa Học (Benchmark F1 & Precision)
- **Lệnh chạy trong terminal:**
  ```bash
  python eval/run_eval.py --only semgrep --no-bandit --cold --rules "p/python,p/security-audit"
  ```
- **Nội dung cần chụp:** Bảng kết quả in ra cột TP, FP, FN, Precision, Recall, F1.
- **Chú thích ảnh trong báo cáo:**  
  *Hình 3: Kết quả đo lường thực nghiệm khoa học chứng minh cấu hình Confirmed-Only đạt độ chính xác Precision = 1.000 (0 False Positive).*

---

### 📸 Ảnh 4: Loại Bỏ Cảnh Báo Sai Trên Mã Nguồn An Toàn (Safe Demo)
- **Lệnh chạy trong terminal:**
  ```bash
  vulnagent scan examples/safe_demo.py --no-llm
  ```
- **Nội dung cần chụp:** Màn hình trả về kết quả `No vulnerabilities found` trên file có chứa lệnh `cursor.execute` dùng Parameterized Query.
- **Chú thích ảnh trong báo cáo:**  
  *Hình 4: Cơ chế phân tích cú pháp loại bỏ hoàn toàn cảnh báo sai (False Positive) đối với câu truy vấn tham số hóa.*

---

### 📸 Ảnh 5: Cơ Chế Thất Bại Có Kiểm Soát (Controlled Degradation)
- **Lệnh chạy trong terminal:**
  ```bash
  vulnagent scan examples/broken_syntax.py --no-llm
  ```
- **Nội dung cần chụp:** Đoạn cảnh báo `WARNING: Scan completed with degraded or failed tiers` và `gate: failed` kèm mã lỗi Exit code 2.
- **Chú thích ảnh trong báo cáo:**  
  *Hình 5: Minh chứng tính trung thực học thuật: Hệ thống từ chối cấp chứng nhận an toàn giả mạo khi gặp lỗi cú pháp mã nguồn.*
