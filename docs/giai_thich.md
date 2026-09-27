# Cơ Sở Lý Thuyết & Cơ Chế Xác Định Lỗ Hổng Trong VulnAgent

Tài liệu này giải thích chi tiết bản chất học thuật và kỹ thuật của hệ thống VulnAgent:
1. **Lý thuyết thẩm định lỗ hổng:** Điều kiện nào để khẳng định một đoạn code bị lỗ hổng? Trường hợp nào không thể coi là lỗ hổng (False Positive)?
2. **Cơ chế xử lý trong code của VulnAgent:** Cách phối hợp giữa Rule Tier, LLM Tier, Fusion và Adversarial Verifier.
3. **Mức độ hoàn thiện thực tế:** Những gì repo đã làm vững chắc và những giới hạn kỹ thuật cần thừa nhận trước Hội đồng.

---

# PHẦN 1: ĐIỀU KIỆN ĐỂ KẾT LUẬN — LỖ HỔNG THẬT VS CẢNH BÁO SAI

Trong khoa học bảo mật phần mềm (Software Security), một đoạn code không thể bị coi là có lỗ hổng chỉ vì nó chứa một hàm "trông có vẻ nguy hiểm". VulnAgent áp dụng **mô hình luồng dữ liệu ô nhiễm (Taint Flow Model)** để phân định:

```
[SOURCE]              [PROPAGATOR]             [SANITIZER]             [SINK]
Dữ liệu bẩn  ───►  Gán biến, nối chuỗi  ───►  (Bị thiếu/sai)  ───►  Hàm thực thi
(Người dùng nhập)                                                  (Hệ thống bị tấn công)
```

### 1. Điều kiện để khẳng định BỊ LỖ HỔNG (True Positive / `supported`):
Để tuyên bố một đoạn mã bị lỗ hổng (ví dụ: SQLi, Command Injection, Path Traversal), đoạn code **bắt buộc phải thỏa mãn đồng thời 4 yếu tố**:
1. **Có Source (Điểm vào bẩn):** Dữ liệu bắt nguồn từ nguồn không tin cậy (người dùng nhập, HTTP request, tham số URL, cookie, biến môi trường lạ).
2. **Có Sink (Điểm thực thi nguy hiểm):** Dữ liệu đi vào hàm nhạy cảm có khả năng gây hại (ví dụ: `cursor.execute()`, `subprocess.call(..., shell=True)`, `eval()`, `open()`).
3. **Có Taint Path liên tục:** Có đường truyền dữ liệu thực tế nối từ Source đến Sink.
4. **THIẾU Sanitizer / Mitigating Control hợp lệ:** Dữ liệu trên đường truyền **không** đi qua bất kỳ hàm kiểm tra, ép kiểu hay làm sạch nào, hoặc hàm làm sạch bị viết sai logic.

---

### 2. Trường hợp nào KHÔNG THỂ coi là lỗ hổng (False Positive / `refuted`)?
Nhiều scanner truyền thống thấy dòng `cursor.execute` là báo động đỏ. Nhưng VulnAgent sẽ **bác bỏ (Refute)** nếu rơi vào các trường hợp sau:
1. **Đã có Sanitizer / Mitigating Control chuẩn:**
   - SQL: Dùng tham số hóa Parameterized Query (`cursor.execute("SELECT ... WHERE id = ?", (user_id,))`). Dữ liệu được DB driver xử lý an toàn.
   - Command: Đã dùng `shlex.quote(cmd)` hoặc truyền danh sách đối số cố định với `shell=False`.
   - Ép kiểu an toàn: Dữ liệu đã đi qua `int(user_input)` hoặc `uuid.UUID(val)` → Kẻ tấn công không thể chèn ký tự đặc biệt như dấu `'` hay `;`.
2. **Dữ liệu là Hằng số / Literal (Không bị attacker kiểm soát):**
   - Lệnh gọi `subprocess.call("ls -la", shell=True)` nhưng chuỗi lệnh là chuỗi tĩnh cố định do chính lập trình viên viết trong code, không nhận bất kỳ biến nào từ bên ngoài.
3. **Đoạn mã không thể tiếp cận (Unreachable / Dead code):**
   - Nằm trong file test (`tests/`), mock fixtures, hoặc khối code không bao giờ được gọi trong ứng dụng chính.
4. **Hiểu nhầm chuẩn mực an toàn:**
   - Regex thấy chữ `password` tưởng là lộ mật khẩu, nhưng thực tế code đang đọc an toàn từ biến môi trường `os.getenv("DB_PASSWORD")` hoặc từ HashiCorp Vault.

---

### 3. Khái niệm thứ 3 tối quan trọng: BẤT ĐỊNH (`uncertain`)
VulnAgent tuân thủ nguyên tắc **"Mặc định bi quan" (Pessimistic Default)**:
- Nếu dữ liệu đi vào hàm từ một file khác mà công cụ chưa đọc được, hoặc logic quá phức tạp: **Hệ thống TUYỆT ĐỐI KHÔNG tự tiện báo "Clean/An toàn"**, mà bắt buộc phải gắn nhãn **`uncertain`** (hoặc `degraded`) và ghi rõ: *"Chưa đủ ngữ cảnh để kết luận"*.

---

# PHẦN 2: HIỆN TẠI REPO CỦA CHÚNG TA ĐÃ XỬ LÝ NHƯ THẾ NÀO?

Hệ thống VulnAgent hiện tại hiện thực hóa các nguyên tắc trên qua **3 tầng kiểm soát nghiêm ngặt**:

### 1. Bộ lọc đồng thuận độc lập (`src/analyzer/fusion.py`)
- Nếu chỉ Semgrep báo → Gán nhãn `SEMGREP` (độ tin cậy 0.90).
- Nếu chỉ LLM báo → Gán nhãn `LLM` (độ tin cậy 0.55).
- **Nếu CẢ HAI cùng chỉ ra một vị trí lỗi** (đối chiếu theo dòng lệnh và bí danh loại `TYPE_ALIASES`) → Gán nhãn **`CONFIRMED` (độ tin cậy thiết lập 0.95)**. Sự đồng thuận này là bộ lọc tự nhiên khử bỏ phần lớn False Positive của từng bên.

### 2. Agent Xác minh đối kháng (`src/agent/verifier.py`)
- Khi cần kiểm tra nghi vấn, Verifier không hỏi xuôi ("Code này có lỗi không?").
- System prompt ra lệnh dứt khoát: *"Bạn là chuyên gia an ninh. Nhiệm vụ của bạn là tìm lý do chứng minh báo cáo này SAI"*.
- Cấp công cụ `CodeTools` + `SafeReader` cho Agent tự động đọc ngược lại mã nguồn.
- **Quy tắc bác bỏ nghiêm ngặt:** Nếu Agent muốn chọn `refuted`, prompt cấm tuyệt đối việc refute vì "không chắc", mà **bắt buộc phải nêu rõ tên hàm `mitigating_control` bảo vệ nằm ở đâu**.

### 3. Động cơ thực thi chính sách bằng chứng (`src/models/assessment.py`)
Hàm `evaluate_assessment_policy` đóng vai trò là "Tòa án kiểm tra bằng chứng":
- **Muốn tuyên bố `supported` (Có lỗi thật):**
  - Đối với các lỗi dạng Taint (SQL, Command, Traversal, XSS), bắt buộc danh sách `taint_path` phải có ít nhất một node `kind="source"` và một node `kind="sink"`.
  - Mọi bước trong Taint Path phải trích dẫn `evidence_id` có thật, nằm trong snapshot của phiên quét, đúng tên file và dòng code nằm trong phạm vi đọc được.
- **Muốn tuyên bố `refuted` (Không phải lỗi):**
  - Bắt buộc chuỗi `mitigating_control` không được rỗng.
  - Bắt buộc phải có `control_evidence_id` trỏ đúng vào dòng code chứa hàm bảo vệ trên đĩa.
  - Nếu thiếu bằng chứng → Policy engine lập tức **tước bỏ phán quyết** và ép chuyển về trạng thái **`uncertain`**.

---

# PHẦN 3: ĐÁNH GIÁ MỨC ĐỘ HOÀN THIỆN CỦA REPO (ĐIỂM MẠNH & GIỚI HẠN)

Khi bảo vệ đồ án, việc **thừa nhận đúng giới hạn kỹ thuật** sẽ giúp Hội đồng đánh giá cực kỳ cao vì tính trung thực khoa học:

### ✅ Những gì repo ĐÃ HOÀN THIỆN VỮNG CHẮC:
1. **Hợp đồng bằng chứng (Evidence Contract) khép kín:** Đã code hoàn chỉnh trong `models/assessment.py` và `agent/verifier.py`, được bảo vệ bởi **121 unit/gate tests (100% PASS)**. Không một AI hay người dùng nào có thể nộp verdict ảo nếu dòng code không tồn tại trên đĩa.
2. **Cơ chế 2-tier + Corroboration:** Đã đo đạc thực tế chứng minh lọc `--confirmed-only` loại bỏ triệt để cảnh báo sai trên file sạch `safe_handlers.py` (đưa Precision đạt 1.000).
3. **Tính trung thực khi lỗi (Controlled Degradation):** Khi gặp file lỗi cú pháp (`broken_syntax.py`), hệ thống từ chối báo Clean mà đánh cờ `DEGRADED` và Exit code 2.

### ⚠️ Những GIỚI HẠN cần nói thật trước Hội đồng:
1. **Bản chất của Taint Path:** 
   - Taint path trong VulnAgent hiện tại là do **LLM trích xuất dựa trên ngữ nghĩa**, sau đó **Policy Engine của chúng ta kiểm tra tính toàn vẹn (Validation)** trên dòng/file thật.
   - Hệ thống **chưa phải là một engine tĩnh xây dựng đồ thị luồng dữ liệu (Dataflow Graph/Points-to Analysis)** phức tạp như CodeQL hay Semgrep Pro.
2. **Phạm vi phân tích đơn file (Single-file Scope):**
   - Hiện tại hệ thống phân tích luồng dữ liệu trọn vẹn nhất bên trong 1 file (Intra-file). Nếu dữ liệu đi qua một hàm helper ở file `utils.py` khác, verifier chỉ đọc ngữ cảnh mở rộng chứ chưa thể tự động lần vết liên file đa tầng (Cross-file taint).

---

### 💡 CÂU NÓI "VÀNG" KHI TRẢ LỜI HỘI ĐỒNG:
> *"Thưa Thầy/Cô, VulnAgent không định nghĩa lỗ hổng dựa trên cảm tính của AI hay sự hiện diện của một từ khóa nguy hiểm. Hệ thống của em yêu cầu một **Hợp đồng bằng chứng (Evidence Contract)**: Một lỗi chỉ được coi là hợp lệ khi chứng minh được luồng dữ liệu đi từ Source vào Sink mà không có Sanitizer. Ngược lại, muốn bác bỏ một cảnh báo sai, hệ thống bắt buộc phải chỉ ra dòng code chứa cơ chế làm sạch (Mitigating Control) cụ thể. Nếu không đủ dữ liệu, hệ thống mặc định chọn trạng thái `uncertain` chứ kiên quyết không cấp chứng nhận an toàn giả mạo."*
