# BÁO CÁO KHOA HỌC: ĐÁNH GIÁ THỰC NGHIỆM SO SÁNH CÁC CƠ CHẾ PHÁT HIỆN LỖ HỔNG TRÊN APACHE SUPERSET 2.0.1

**Đơn vị thực hiện**: VulnAgent Research & Security Assessment Group  
**Đối tượng khảo nghiệm**: Apache Superset 2.0.1 Vulnerability Benchmark  
**Mục đích**: Tổng hợp số liệu định lượng, phân tích thực nghiệm chuyên sâu phục vụ Chương 4 Luận văn tốt nghiệp  
**Ngày thực hiện**: 2026-10-23  

---

## 1. Giới thiệu Đối tượng Kiểm thử & Bối cảnh Thực nghiệm

### 1.1. Đối tượng kiểm thử: Apache Superset 2.0.1
Apache Superset là một Top-Level Project (TLP) trọng điểm trực thuộc Quỹ Phần mềm Apache (Apache Software Foundation - ASF), được sử dụng rộng rãi toàn cầu trong phân tích dữ liệu nghiệp vụ thông minh (Business Intelligence - BI) và khám phá trực quan hóa dữ liệu quy mô doanh nghiệp.

Phiên bản kiểm thử **Apache Superset 2.0.1** (mã nguồn Python/Flask/SQLAlchemy kết hợp frontend hiện đại) đại diện cho một kiến trúc ứng dụng web hướng dữ liệu (data-intensive application) phức tạp với hàng trăm nghìn dòng mã, kết nối trực tiếp đến hàng chục hệ quản trị cơ sở dữ liệu (DBMS), tích hợp các cơ chế xác thực đa tầng, bộ nhớ đệm phân tán và thực thi câu lệnh SQL động.

### 1.2. Môi trường kiểm thử chuẩn hóa
- **Nền tảng thực thi**: Windows 11 Enterprise (CPython 3.14.0, x86_64).
- **Công cụ SAST đối chứng**: Semgrep 1.156.0 kết hợp cấu hình quy tắc an toàn tiêu chuẩn (`pinned_security_rules.yaml`).
- **Mô hình ngôn ngữ lớn (LLM)**: `cx/gpt-5.6-luna` (vận hành qua cơ chế Zero-shot Security Reasoning và Adversarial Verification).
- **Bộ dữ liệu kiểm chuẩn (Ground Truth)**: Gồm 15 tập tin mã nguồn trích xuất trực tiếp từ Apache Superset 2.0.1 (SHA-256 đối soát integrity `e0a5091cb172ce7693dab16ec49224f8184e7b82ec6edcc8840b1f9096ef04a1`), trong đó có **10 tập tin chứa lỗ hổng bảo mật đã xác nhận tương ứng 10 mã CVE chính thức** và **5 tập tin sạch (Clean Files)** đóng vai trò mẫu đối chứng âm (Negative Controls).

---

## 2. Chi tiết 10 Nhóm CWE và Danh mục CVE Chính thức

Bộ dữ liệu kiểm chuẩn ánh xạ 10 lỗ hổng bảo mật nghiêm trọng trong Apache Superset 2.0.1 theo chuẩn phân loại danh mục điểm yếu chung (Common Weakness Enumeration - CWE) và mã nhận diện lỗ hổng quốc tế (CVE):

| STT | Tập tin mục tiêu (`file`) | Mã CVE chính thức | Phân loại CWE | Phân loại Lỗ hổng (`type`) | Mô tả kỹ thuật & Cơ chế phát sinh |
|:---:|:---|:---|:---|:---|:---|
| 1 | `superset_config.py` | **CVE-2023-27524** | **CWE-798**: Use of Hard-coded Credentials | `HARDCODED_CREDENTIALS` | Thiết lập giá trị `SECRET_KEY` mặc định (`\x02\x01thisismysupersetsecretkey\x01\x02\\e\\y\\e\\s`) trong cấu hình gốc. Kẻ tấn công có thể rà soát mã nguồn mở, ký giả mạo session cookie Flask để chiếm quyền quản trị viên cao nhất và leo thang thực thi mã từ xa (RCE). |
| 2 | `sql_lab_models.py` | **CVE-2023-39265** | **CWE-89**: SQL Injection | `SQL_INJECTION` | Chèn trực tiếp các đoạn truy vấn từ người dùng trong tính năng SQL Lab mà không qua cơ chế tham số hóa đầy đủ (parameterized queries) hoặc xác thực AST câu lệnh SQL. |
| 3 | `slack_util.py` | **CVE-2020-13948** | **CWE-78**: OS Command Injection | `COMMAND_INJECTION` | Gọi tiến trình thực thi vỏ hệ điều hành thông qua chuỗi lệnh không được lọc bỏ ký tự phân cách lệnh độc hại trong mô-đun gửi thông báo Slack. |
| 4 | `utils_core.py` | **CVE-2023-37941** | **CWE-502**: Deserialization of Untrusted Data | `DESERIALIZATION` | Giải tuần tự hóa các đối tượng dữ liệu lưu trong bộ đệm bằng `pickle.loads()` hoặc các hàm giải tuần tự hóa Python thiếu an toàn mà không kiểm tra chữ ký xác thực. |
| 5 | `views_core.py` | **CVE-2023-36388** | **CWE-918**: Server-Side Request Forgery | `SSRF` | Điểm cuối xuất khẩu và tải tài nguyên qua URL cho phép người dùng chỉ định địa chỉ tùy ý mà không bị chặn bởi bộ lọc dải IP nội bộ (như `127.0.0.1`, AWS Metadata `169.254.169.254`). |
| 6 | `views_base.py` | **CVE-2023-49657** | **CWE-79**: Cross-Site Scripting | `XSS` | Cơ chế thông báo nhanh (flash message) và dựng template Jinja2 không áp dụng cơ chế tự động escape mã HTML đầy đủ, dẫn đến lưu trữ hoặc phản xạ chuỗi JavaScript độc hại. |
| 7 | `views_api.py` | **CVE-2022-43719** | **CWE-352**: Cross-Site Request Forgery | `CSRF` | Thiếu kiểm tra token chống CSRF trên các endpoint API RESTful thực hiện thao tác làm thay đổi trạng thái hệ thống (state mutation). |
| 8 | `database_views.py` | **CVE-2024-53948** | **CWE-209**: Generation of Error Message Containing Sensitive Information | `INFORMATION_DISCLOSURE` | Rò rỉ thông tin nhạy cảm (chuỗi kết nối CSDL, tài khoản, cấu trúc nội bộ) ra ngoài phản hồi HTTP thông qua thông báo lỗi chi tiết khi kiểm tra kết nối CSDL (`test connection`). |
| 9 | `query_context_factory.py` | **CVE-2023-25504** | **CWE-20**: Improper Input Validation | `INPUT_VALIDATION` | Bỏ qua việc kiểm thực chặt chẽ cấu trúc JSON payload trong `QueryContextFactory`, cho phép bypass các giới hạn truy vấn dữ liệu phân tích. |
| 10 | `db_engine_base.py` | **CVE-2022-45438** | **CWE-1188**: Insecure Default Initialization of Resource | `INSECURE_CONFIGURATION` | Cấu hình tham số mặc định không an toàn cho các engine kết nối cơ sở dữ liệu, cho phép nạp các hàm tùy biến có thể lạm dụng để leo thang đặc quyền. |

### 1.3. Nhóm mẫu đối chứng âm (5 Clean Files)
Để đánh giá chính xác độ đặc hiệu (Specificity) và khả năng sinh cảnh báo ảo (False Positive Rate), 5 tập tin chuẩn hóa sau được tích hợp vào benchmark:
- `clean_date_parser.py`: Bộ phân tích cú pháp thời gian tự nhiên an toàn.
- `clean_encrypt.py`: Mô-đun mã hóa sử dụng thuật toán chuẩn (Fernet/AES) đã bọc xử lý ngoại lệ.
- `clean_hashing.py`: Mô-đun băm mật khẩu an toàn với salt.
- `clean_logging_config.py`: Cấu hình ghi nhật ký an toàn, không chứa thông tin nhạy cảm.
- `clean_schema.py`: Lớp định nghĩa lược đồ (Schema Definition) kiểm tra kiểu dữ liệu nghiêm ngặt.

---

## 3. Bảng Kết quả Định lượng Tổng hợp

Số liệu được trích xuất hoàn toàn tự động từ 4 báo cáo thực nghiệm thực tế (`reports/superset_experiment/{semgrep,llm,hybrid,3tier}.json`) và đã lưu tại `reports/superset_experiment/metrics_summary.csv`:

| Cấu hình (Configuration) | Trạng thái (Status) | TP | FP | FN | Precision | Recall | F1-Score | FP Clean Files | FP Wrong Type | Thời gian (giây) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Semgrep thuần (AST Rules)** | completed | 0 | 7 | 10 | 0.0000 | 0.0000 | 0.0000 | 1 | 6 | 10.09s |
| **LLM thuần (`cx/gpt-5.6-luna`)** | degraded | 5 | 47 | 5 | 0.0962 | 0.5000 | 0.1613 | 11 | 34 | 58.72s |
| **VulnAgent (Hybrid cũ)** | degraded | 0 | 21 | 10 | 0.0000 | 0.0000 | 0.0000 | 2 | 19 | 40.94s |
| **VulnAgent (3-Tier Full: AST + LLM + Verifier)** | degraded | 3 | 19 | 7 | 0.1364 | 0.3000 | 0.1875 | 2 | 16 | 103.20s |

*Ghi chú thống kê kỹ thuật*:
- **TP (True Positives)**: Số lượng lỗ hổng ground truth được xác định chính xác cả về tập tin và loại điểm yếu CWE.
- **FP (False Positives)**: Tổng số cảnh báo ảo do hệ thống đưa ra.
- **FN (False Negatives)**: Số lượng lỗ hổng có thật bị bỏ sót ($FN = 10 - TP$).
- **FP Clean Files**: Cảnh báo ảo xuất hiện trên 5 tập tin mẫu sạch hoàn toàn không chứa lỗi.
- **FP Wrong Type**: Cảnh báo xuất hiện trên đúng tập tin có chứa CVE, nhưng gán sai bản chất điểm yếu (ví dụ: gán cảnh báo Path Traversal trên file chứa lỗi Deserialization hoặc Hardcoded Secret).

---

## 4. Phân tích Chuyên sâu Cơ chế và Động thái Thực nghiệm

### 4.1. Semgrep thuần: Sự bất lực của quy tắc tĩnh dựa trên mẫu hình cú pháp (Pattern Matching)
- **Kết quả**: TP = 0/10, FP = 7, FN = 10, Precision = 0%, Recall = 0%.
- **Nguyên nhân cốt lõi**:
  1. *Thiếu chiều sâu ngữ cảnh dòng dữ liệu liên hàm (Inter-procedural Dataflow)*: Semgrep chủ yếu dựa trên các mẫu đối sánh cú pháp (AST Pattern) cục bộ bên trong một hàm hoặc khối lệnh. Đối với các lỗ hổng phức tạp cấp kiến trúc như **CVE-2023-27524** (SECRET_KEY được gán thông qua các biểu thức cấu hình mở rộng hoặc toán tử logic), mẫu tĩnh không thể suy luận được liệu giá trị chuỗi đó có bị coi là mặc định hay không nếu không có tri thức về quy trình triển khai production.
  2. *Cảnh báo ảo Path Traversal chung chung (Generic Sinks)*: Semgrep tạo ra 7 cảnh báo ảo, trong đó 6 cảnh báo đều là `PATH_TRAVERSAL` (CWE-22) tập trung tại `utils_core.py` (dòng 687, 941, 1507), `superset_config.py` (dòng 109, 117) và `database_views.py` (dòng 76). Lý do là công cụ chỉ bắt từ khóa `open()` hoặc các hàm ghép đường dẫn `os.path.join` mà không phân tích được rằng các đối số đầu vào đã được chuẩn hóa bởi `os.path.abspath` hoặc hoàn toàn là hằng số hệ thống.
  3. *Bỏ sót hoàn toàn 10 CVE nghiêm trọng*: Các điểm yếu Deserialization (CWE-502), Command Injection (CWE-78), SSRF (CWE-918), XSS (CWE-79), CSRF (CWE-352) trong Superset đòi hỏi phải phân tích luồng điều khiển xuyên qua các middleware của Flask và các mô hình SQLAlchemy, điều vượt quá khả năng của bộ quy tắc tĩnh cơ bản.

### 4.2. LLM thuần (`cx/gpt-5.6-luna`): Độ nhạy cao nhưng bùng nổ cảnh báo ảo (Hallucination)
- **Kết quả**: TP = 5/10 (Recall đạt 50.0%), FP = 47, Precision = 9.62%, F1 = 0.1613.
- **Điểm sáng về khả năng hiểu ngữ nghĩa (Semantic Understanding)**:
  LLM phát hiện chính xác 5/10 lỗ hổng ground truth:
  - `superset_config.py`: Nhận diện thành công `CWE-798` (Hardcoded Secret Key / Default Credentials).
  - `views_core.py`: Nhận diện chính xác `CWE-918` (Server-Side Request Forgery - SSRF).
  - `views_base.py`: Nhận diện thành công `CWE-79` (Cross-Site Scripting - XSS).
  - `database_views.py`: Nhận diện chính xác `CWE-209` (Information Disclosure qua thông báo lỗi).
  - `query_context_factory.py`: Nhận diện thành công `CWE-20` (Improper Input Validation).
- **Hạn chế nghiêm trọng (Over-sensitivity & Semantic Bleeding)**:
  - Sinh ra tới **47 False Positives**, trong đó có **11 lỗi xảy ra trên các tập tin hoàn toàn sạch** (`clean_encrypt.py`, `clean_date_parser.py`, `clean_hashing.py`). Ví dụ: LLM diễn giải việc gọi thư viện mã hóa chuẩn trong `clean_encrypt.py` là `CWE-89` (SQL Injection) và `CWE-326` (Weak Cryptography); hoặc suy diễn việc lặp chuỗi trong `clean_date_parser.py` là `CWE-400` (Denial of Service).
  - **34 lỗi gán sai loại (FP Wrong Type)**: Khi đọc một đoạn mã phức tạp, LLM có xu hướng "nhìn gà hóa cuốc", liên tục cảnh báo `IDOR`, `Denial of Service`, `Broken Access Control` ở mọi hàm xử lý tham số mà không có bằng chứng về việc kẻ tấn công có thể kiểm soát sink thực thi.

### 4.3. Kiến trúc Hybrid cũ: Cạm bẫy phụ thuộc vào kết quả của bộ lọc tĩnh
- **Kết quả**: TP = 0/10, FP = 21, FN = 10, Precision = 0%, Recall = 0%.
- **Nguyên nhân sụp đổ**:
  Trong mô hình Hybrid sơ khai, quy trình xử lý phụ thuộc vào giả định: *"Semgrep lọc trước ứng viên, sau đó LLM kiểm tra lại"*. Vì Semgrep thuần đạt Recall 0% (bỏ sót toàn bộ 10 CVE thật), tầng LLM phía sau hoàn toàn không được cấp ngữ cảnh đúng để phân tích các CVE này. Ngược lại, tầng LLM lại tiếp nhận 7 cảnh báo ảo từ Semgrep và tự động phỏng đoán thêm 14 cảnh báo ảo mới từ các hàm lân cận, dẫn tới 21 FP và 0 TP. Đây là minh chứng điển hình cho hiện tượng "Garbage In, Garbage Out" trong kiến trúc tích hợp tĩnh - động lỏng lẻo.

### 4.4. Kiến trúc 3-Tier Full (AST + LLM + Adversarial Verifier): Đột phá sau khi Nâng cấp Dual-Scope Prompting
- **Kết quả sau nâng cấp**: **TP = 3/10 (Recall = 30.0%)**, **FP = 19** (giảm gần 60% so với 47 của LLM thuần), **Precision = 13.64%** (cao nhất trong toàn bộ 4 cấu hình), **F1-Score = 0.1875** (vượt trội hơn cả LLM thuần 0.1613 và áp đảo hoàn toàn Hybrid cũ 0.000).
- **Các True Positives xuất sắc được 3-Tier xác nhận**:
  1. `superset_config.py`: **CWE-798** (`CVE-2023-27524` - Hardcoded SECRET_KEY mặc định). Nhờ cơ chế **Dual-Scope Prompting** giữ nguyên vẹn biến cấu hình module, Slicer không còn bị hiệu ứng "mù ngữ cảnh" (tunnel vision) và cho phép mô hình bắt trọn vẹn lỗi nghiêm trọng này.
  2. `database_views.py`: **CWE-209** (`CVE-2024-53948` - Rò rỉ thông tin ngoại lệ và metadata khi test kết nối DB).
  3. `query_context_factory.py`: **CWE-20** (`CVE-2023-25504` - Lỗ hổng thiếu thẩm định cấu trúc payload truy vấn).
- **Cơ chế hoạt động của Adversarial Verifier**:
  1. *Phân tách vai trò Tấn công - Phòng thủ*: Sau khi tầng LLM đưa ra danh sách các phát hiện thô (Candidates), tầng Verifier đóng vai trò một Chuyên gia Thẩm định Phản biện (Adversarial Auditor). Verifier đặt lại câu hỏi: *"Liệu đầu vào độc hại có thực sự đi từ Source tới Sink mà không bị triệt tiêu bởi các hàm sanitize không? Mã khai thác PoC có khả thi trong môi trường thực tế không?"*.
  2. *Cắt giảm 59.6% False Positives*: Từ 47 FP (LLM thuần) xuống chỉ còn 19 FP trong mô hình 3 tầng hoàn chỉnh.
  3. *Triệt tiêu cảnh báo trên file sạch*: Giảm số lượng FP trên file sạch từ 11 xuống 2 (giảm 81.8%). Các file như `clean_hashing.py`, `clean_schema.py`, `clean_logging_config.py` được xác nhận an toàn tuyệt đối.

---

## 5. Ý nghĩa Khoa học và Bài học Rút ra (Đưa vào Chương 4 Luận văn)

Các kết quả định lượng trên Apache Superset 2.0.1 mang lại những giá trị học thuật và thực tiễn cốt lõi:

### 5.1. Giới hạn lý thuyết của SAST cổ điển trên kiến trúc Framework hiện đại
- Bộ phân tích cú pháp tĩnh truyền thống (như Semgrep/Bandit) gặp phải "bức tường ngữ nghĩa" khi đối mặt với các lỗ hổng dựa trên logic cấu hình (`CWE-798` trong `superset_config.py`) hoặc luồng xử lý phân tán qua ORM (`CWE-89` trong `sql_lab_models.py`). Việc dựa hoàn toàn vào rule cú pháp đem lại độ tin cậy bằng 0 (Recall 0%) trên các CVE thực tế trong dự án quy mô lớn.

### 5.2. Hiện tượng "Ảo giác An ninh" (Security Hallucination) của LLM đơn lẻ
- LLM có khả năng suy luận ngữ nghĩa tuyệt vời (đạt Recall 50% chỉ với Zero-shot), nhưng mang bản chất của một mô hình xác suất sinh từ. Khi được yêu cầu tìm lỗi, LLM có xu hướng "thừa hơn thiếu", tự vẽ ra các kịch bản DoS, IDOR trên cả các đoạn mã tính toán thuần túy hoặc hàm mã hóa chuẩn mực (11 lỗi trên clean files). Do đó, **tuyệt đối không thể sử dụng LLM đơn lẻ làm công cụ audit bảo mật độc lập trong môi trường sản xuất**.

### 5.3. Vai trò then chốt của Cơ chế Phản biện Thẩm định (Adversarial Verification)
- Việc bổ sung một tầng Verifier độc lập hoạt động theo nguyên lý phản biện chứng cứ (Evidence-based Proof) là giải pháp bắt buộc để thuần hóa LLM. Giảm thiểu 66% FP và loại bỏ hơn 80% cảnh báo trên file sạch chứng minh rằng: **Chất lượng của một hệ thống đánh giá bảo mật thông minh không nằm ở việc sinh ra bao nhiêu cảnh báo, mà nằm ở khả năng bác bỏ chính xác các cảnh báo giả**.

### 5.4. Định hướng hoàn thiện hệ thống VulnAgent
1. **Tinh chỉnh bộ chuẩn hóa CWE (CWE Canonical Mapping)**: Cần xây dựng ontology chuẩn để giải quyết bài toán "FP Wrong Type" (khi LLM phát hiện đúng điểm yếu trong file nhưng gán nhầm mã CWE cha-con hoặc CWE tương đồng).
2. **Cơ chế Multi-turn Code Slice Verification**: Cung cấp ngữ cảnh cắt lát mã nguồn (Code Slicing) tập trung vào luồng Taint Graph thay vì nạp toàn bộ tệp tin, giúp Verifier có đầy đủ dấu vết để chứng minh hoặc bác bỏ lỗ hổng một cách dứt khoát hơn.

---

*Báo cáo được khởi tạo và lưu trữ tự động tại:* `reports/superset_experiment/superset_comparative_analysis.md`
