# Hướng Dẫn Thực Nghiệm & Live Demo Trên OWASP PyGoat

Tài liệu này hướng dẫn chi tiết cách tải, thiết lập và chạy kịch bản thực nghiệm đồ án tốt nghiệp trên dự án thực tế mã nguồn mở **OWASP PyGoat** bằng cả 3 hình thức: **CLI**, **Web UI**, và **MCP Server**.

---

## 1. TẠI SAO LẠI CHỌN OWASP PYGOAT?

1. **Dự án chính thức của tổ chức OWASP toàn cầu:** PyGoat là ứng dụng web Python/Django mẫu duy nhất được OWASP bảo trợ để huấn luyện và kiểm thử lỗ hổng bảo mật.
2. **Quy mô dự án thực tế (Full-stack):** Có đầy đủ cấu trúc Django hoàn chỉnh (Models, Views, Templates, URLs, Settings, SQLite/Postgres backend).
3. **Danh mục lỗ hổng đã được xác định trước (Ground Truth):** Toàn bộ các sink nguy hiểm đã được VulnAgent phân tích và neo cố định trong `eval/prepare_pygoat.py`:
   - `CWE-89`: SQL Injection (Dòng 162 & 878)
   - `CWE-78`: OS Command Injection (Dòng 430)
   - `CWE-502`: Insecure Deserialization với `pickle.loads` (Dòng 214) & `yaml.load` (Dòng 560)
   - `CWE-95`: Code Injection với `eval` (Dòng 460) & `ImageMath.eval` (Dòng 588)
   - `CWE-918`: SSRF qua `requests.get` (Dòng 963)
   - `CWE-328`: Sử dụng hàm băm yếu MD5 không salt (Dòng 1026)
   - `CWE-611`: XML External Entity (XXE) (Dòng 260)

---

## 2. CHUẨN BỊ MÔI TRƯỜNG PYGOAT

Bạn có 2 cách để chuẩn bị:

### Cách 1: Sử dụng ngay bản offline có sẵn trong repo (Khuyên dùng khi bảo vệ)
Trong VulnAgent, tệp điều phối chứa toàn bộ 10 lỗ hổng của PyGoat đã được chuẩn bị sẵn tại:
`eval/datasets/pygoat/samples/pygoat_views.py` (Kèm file nhãn chuẩn `eval/datasets/pygoat/labels.json`).
Bạn có thể quét ngay lập tức mà không cần kết nối mạng hoặc clone gì thêm!

### Cách 2: Clone từ kho GitHub chính thức
```bash
# 1. Clone repository chính thức của PyGoat
git clone https://github.com/adeyosemanputra/pygoat.git
```

---

## 3. KỊCH BẢN LIVE DEMO 3 KÊNH TRÊN PYGOAT (THEO THỨ TỰ TĂNG DẦN)

### 🎬 Kênh 1: Quét CLI & Cổng Chặn CI/CD (2 phút)
*Cho Hội đồng thấy sức mạnh phân tích thô và khả năng tích hợp DevSecOps:*

```bash
# Quét trực tiếp file chứa logic chính của PyGoat
vulnagent scan pygoat/introduction/views.py --no-llm --verbose

# Kiểm thử cổng chặn rủi ro CI/CD (đánh fail khi có lỗi CRITICAL)
vulnagent scan pygoat/introduction/views.py --no-llm --fail-on critical
```
- **Hiện tượng trên màn hình:** Bảng kết quả in ra chi tiết các lỗ hổng SQLi, Command Injection, Deserialization kèm dòng code vi phạm thực tế và trả về Exit code 1 (chặn build).

---

### 🎬 Kênh 2: Trình Diễn Web UI Trực Quan (2 phút)
*Cho Hội đồng thấy giao diện đồ họa hiện đại, dễ tiếp cận cho người dùng:*

```bash
# Khởi động máy chủ web
vulnagent serve
```
1. Mở trình duyệt truy cập: `http://localhost:8000`
2. Bấm vào **New scan** $\rightarrow$ Dán một đoạn code từ `pygoat/introduction/views.py` (ví dụ: hàm `sql_lab` ở dòng 150–170).
3. Bấm **Scan** $\rightarrow$ Chỉ cho Hội đồng thấy biểu đồ phân loại rủi ro màu đỏ/vàng và sơ đồ chuỗi tấn công liên hoàn (Attack Chains).

---

### 🎬 Kênh 3: AI Coding Agent Tự Động Quét & Vá Code Qua MCP (3 phút — Màn Highlight Đắt Giá Nhất)
*Chứng minh giải pháp cốt lõi cho xu hướng Vibe Coding:*

1. Mở file `pygoat_views.py` trong editor Cursor hoặc VS Code.
2. Tìm tới hàm thực tế `sql_lab` (khoảng dòng 155–165):
   ```python
   def sql_lab(request):
       if request.method == 'POST':
           name = request.POST.get('name')
           query = "SELECT * FROM introduction_users WHERE username = '" + name + "'"
           user = Users.objects.raw(query)
           return render(request, 'Lab_2021/A1_Injection/sql_lab.html', {'user': user})
   ```
3. Mở khung chat Cursor Composer, nhập prompt:
   > *"Dùng tool `scan_code` của `vulnagent` kiểm tra hàm `sql_lab` này và sửa lại an toàn giúp tôi."*
4. **Quan sát AI Agent tự động thực hiện chu trình khép kín:**
   - Agent gọi MCP `scan_code` → Phát hiện `CRITICAL SQL_INJECTION (CWE-89)`.
   - Agent viết lại hàm bằng **Parameterized Query**:
     ```python
     user = Users.objects.raw("SELECT * FROM introduction_users WHERE username = %s", [name])
     ```
   - Agent gọi MCP `check_fix` → Hệ thống rescan xác nhận lỗi đã sạch và code không bị lỗi cú pháp.

---

## 4. BỘ BENCHMARK BỔ TRỢ: SECURITYEVAL (115 MẪU PYTHON CWE)

Bên cạnh PyGoat (dùng cho live demo ứng dụng web), VulnAgent tích hợp sẵn tập benchmark học thuật quốc tế **SecurityEval** (từ hội nghị MSR 2022) tại `eval/datasets/securityeval/`:
- **Quy mô:** 115 bài toán bảo mật độc lập trên 70+ họ mã CWE khác nhau.
- **Lệnh chạy thực nghiệm đo lường:**
  ```bash
  python eval/run_eval.py --dataset eval/datasets/securityeval --only semgrep --no-bandit --cold
  ```
- **Ý nghĩa khoa học:** Chứng minh VulnAgent được đo lường khách quan trên tập dữ liệu chuẩn mực quốc tế, không chỉ riêng một ứng dụng mẫu nào.

---

## 5. PHƯƠNG ÁN DỰ PHÒNG (FALLBACK PLAN)
- Nếu phòng hội đồng mất mạng hoặc máy tính gặp trục trặc:
  - Sử dụng bản quét offline có sẵn: `vulnagent scan eval/datasets/pygoat/samples/pygoat_views.py --no-llm`
  - Mở trực tiếp các tệp JSON kết quả đã lưu sẵn trong `output/eval_pygoat.json` và `output/pygoat_rules.json` để trình chiếu cho Hội đồng xem.

---

## 4. BỘ CÂU HỎI PHẢN BIỆN DỰ KIẾN TRÊN PYGOAT & CÁCH TRẢ LỜI

**❓ Hội đồng: "Toàn bộ lỗ hổng của PyGoat dồn vào file `views.py`, sao gọi là codebase lớn?"**
> **Trả lời:** *"Dạ thưa Thầy/Cô, PyGoat là một ứng dụng Django full-stack hoàn chỉnh gồm nhiều tầng cấu trúc (models, templates, settings, static). Tuy nhiên, vì đây là ứng dụng giáo dục của tổ chức OWASP nên họ chủ động gom các điểm thực hành vào file điều phối `views.py`. Để bổ chứng cho tính bao quát, em đã chạy thực nghiệm bổ sung trên bộ benchmark khoa học **SecurityEval (115 mẫu Python CWE độc lập)** từ hội nghị MSR 2022 để kiểm chứng trên đa dạng cấu trúc mã nguồn thực tế."*

**❓ Hội đồng: "Nếu không có LLM, công cụ này khác gì chạy Semgrep thuần túy?"**
> **Trả lời:** *"Dạ, VulnAgent mang lại 3 giá trị vượt trội mà Semgrep thuần túy không thể có:  
> 1. **Loại bỏ False Positive:** Chế độ đồng thuận `--confirmed-only` đưa Precision lên 1.000 trên các file an toàn.  
> 2. **Chuỗi khai thác (Attack Chains):** Tự động liên kết các lỗi riêng lẻ thành chuỗi tấn công hoàn chỉnh.  
> 3. **Quy trình MCP khép kín:** Cung cấp 12 công cụ có trạng thái giúp AI Agent tự đọc bằng chứng, tự sinh bản vá và tự thẩm định lại trước khi lưu."*
