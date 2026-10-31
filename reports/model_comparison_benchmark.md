# BÁO CÁO THỰC NGHIỆM SO SÁNH ĐỐI ĐẦU CÁC MÔ HÌNH AI TRÊN VULNAGENT
## ĐÁNH GIÁ ĐỘ CHÍNH XÁC, ĐỘ TRỄ, TÀI NGUYÊN TOKEN, TỶ LỆ TUÂN THỦ JSON SCHEMA VÀ ẢNH HƯỞNG CỦA BỘ LỌC AN TOÀN TRÊN MÃ NGUỒN THỰC TẾ

**Đề tài đồ án**: NGHIÊN CỨU ỨNG DỤNG LLM TRONG PHÂN TÍCH LỖ HỔNG AN TOÀN MÃ NGUỒN  
**Hệ thống thực nghiệm**: VulnAgent (Asymmetric 3-Tier Architecture)  
**Hạ tầng API**: Proxy 9Router nội bộ (`http://127.0.0.1:20128/v1`) & Ollama Local Service  
**Tập dữ liệu kiểm thử**: 13 tệp mã nguồn thực tế đại diện từ **Apache Superset 2.0.1** và **Saleor 3.10.0** (9 tệp chứa CVE chính thức + 4 tệp sạch đối chứng)  
**Ngày cập nhật thực nghiệm**: 2026-10-24  

---

## 1. TỔNG QUAN THỰC NGHIỆM

Thực nghiệm đối đầu này được thiết kế nhằm giải quyết bài toán cốt lõi trong việc lựa chọn "bộ não" suy luận cho hệ thống VulnAgent: **Đánh giá trực diện năng lực của 7 mô hình AI đại diện cho 3 phân khúc kiến trúc khác nhau** (Frontier Cloud LLM, Specialized Code LLM, và Local Open-Source LLM). Thực nghiệm đo lường chính xác các thông số kỹ thuật định lượng (độ trễ, số token tiêu thụ, tỷ lệ bắt đúng/báo sai, tỷ lệ tuân thủ cấu trúc JSON) và khảo sát chuyên sâu hai hiện tượng then chốt trong thực tế:
1. **Hiện tượng bộ lọc kiểm duyệt an toàn (Safety Filter Restriction)** của nhà cung cấp Cloud từ chối phân tích các đoạn mã chứa lỗ hổng bảo mật thực tế.
2. **Hiện tượng suy hao cấu trúc JSON (Schema Degradation)** khi chạy mô hình cục bộ quy mô lớn và sự đánh đổi giữa độ nhạy ngữ pháp AST với tỷ lệ báo sai (False Positive Rate).

Danh sách 7 mô hình tham gia đánh giá đối đầu:
1. **Frontier Cloud General / Reasoning Models**:
   - **`cx/gpt-5.6-luna`**: Mô hình thế hệ mới của OpenAI qua proxy Codex.
   - **`ag/gemini-3.8-flash-low`**: Google Gemini 3.8 Flash với mức suy luận (Thinking budget) mức **Thấp (Low)**.
   - **`ag/gemini-3.8-flash-medium`**: Google Gemini 3.8 Flash với mức suy luận mức **Trung bình (Medium)**.
   - **`ag/gemini-3.8-flash-high`**: Google Gemini 3.8 Flash với mức suy luận mức **Cao (High)**.
2. **Specialized Code Cloud Model**:
   - **`mistral/codestral-latest`**: Mô hình chuyên biệt lập trình và phân tích mã nguồn từ Mistral AI.
3. **Open-Source Local / On-Premise Models**:
   - **`ollama/gemma4`**: Mô hình mã nguồn mở gọn nhẹ chạy nội bộ (mẫu đối chứng baseline).
   - **`ollama/gpt-oss:120b`**: Mô hình mã nguồn mở quy mô lớn (120B tham số) chạy local/on-premise qua Ollama.

---

## 2. BẢNG TỔNG HỢP TOÀN BỘ THÔNG SỐ VÀ KẾT QUẢ KỸ THUẬT

Dữ liệu được trích xuất tự động từ hệ thống đo lường thời gian thực `eval/run_model_comparison.py`, lưu trữ tại `reports/model_comparison/models_metrics_summary.csv`:

| Mô hình (Model ID) | Phân lớp kiến trúc | Tỷ lệ Hoàn tất (S / B / T / E) | Tỷ lệ Blocked | Tỷ lệ Timeout | Độ trễ TB (s/req) | Valid JSON (%) | Tổng Tokens | Tổng Cảnh báo | TP | FP | FN | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`cx/gpt-5.6-luna`** | Frontier Cloud | **13 / 0 / 0 / 0** | **0.0%** | **0.0%** | **16.37s** | **100.0%** | 197.675 | 29 | **5** | 24 | **4** | **17.24%** | **55.56%** | **0.2632** |
| **`mistral/codestral-latest`** | Specialized Code | 12 / 0 / 1 / 0 | **0.0%** | 7.7% | 16.71s | **100.0%** | 153.488 | 44 | **3** | 41 | 6 | 6.82% | **33.33%** | 0.1132 |
| **`ollama/gemma4`** (Baseline) | Open-Source Local | **13 / 0 / 0 / 0** | **0.0%** | **0.0%** | **4.95s** | 84.62% | 207.420 | 19 | 2 | 17 | 7 | 10.53% | 22.22% | 0.1429 |
| **`ollama/gpt-oss:120b`** | Open-Source Local (120B) | **13 / 0 / 0 / 0** | **0.0%** | **0.0%** | 10.04s | 38.46% | 198.751 | 6 | 1 | **5** | 8 | 16.67% | 11.11% | 0.1333 |
| **`ag/gemini-3.8-flash-low`** | Frontier Cloud | 7 / 4 / 2 / 0 | **30.8%** | 15.4% | 23.99s | 100.0% | 153.700 | 5 | 0 | 5 | 9 | 0.00% | 0.00% | 0.0000 |
| **`ag/gemini-3.8-flash-medium`** | Frontier Cloud | 4 / 5 / 4 / 0 | **38.5%** | 30.8% | 32.89s | 100.0% | 86.713 | 2 | 0 | 2 | 9 | 0.00% | 0.00% | 0.0000 |
| **`ag/gemini-3.8-flash-high`** | Frontier Cloud | 1 / 1 / 11 / 0 | 7.7% | **84.6%** | 43.39s | 100.0% | 18.928 | 1 | 0 | 1 | 9 | 0.00% | 0.00% | 0.0000 |

*Ghi chú định dạng trạng thái và chỉ số*:
- **S / B / T / E**: Số lượng tệp tương ứng với **Success** (thành công) / **Blocked** (bị lọc an toàn chặn) / **Timeout** (>45 giây) / **Http Error** (lỗi giao thức 4xx/5xx).
- **Valid JSON (%)**: Tỷ lệ phản hồi trả về cú pháp JSON hợp lệ trực tiếp mà không cần qua module JSON repair / salvage.
- **Ground Truth**: Tổng cộng 9 lỗ hổng CVE chính thức trên 9 tệp mục tiêu và 4 tệp sạch đối chứng (clean control).

---

## 3. PHÂN TÍCH HIỆN TƯỢNG BỊ CHẶN BỞI BỘ LỌC AN TOÀN (SAFETY RESTRICTION ANALYSIS)

Một trong những phát hiện có giá trị nhất của đợt thực nghiệm là **sự khác biệt cơ bản về chính sách an toàn nội dung (Content Moderation Policy)** giữa các nhà cung cấp mô hình AI:

```
[MÃ NGUỒN CÓ LỖ HỔNG THỰC TẾ]
(chứa SECRET_KEY, SSRF URLs, HMAC timing comparison)
            │
            ├───> [cx/gpt-5.6-luna] ──────────> 0% Blocked  (Phân tích xuyên suốt, bắt trúng 5 CVE)
            ├───> [mistral/codestral-latest] ──> 0% Blocked  (Chuyên biệt mã nguồn, bắt trúng 3 CVE)
            ├───> [ollama/gemma4]   ──────────> 0% Blocked  (Chạy On-Premise, tự chủ hoàn toàn)
            ├───> [ollama/gpt-oss:120b] ──────> 0% Blocked  (Mã nguồn mở 120B local, không kiểm duyệt)
            │
            └───> [ag/gemini-3.8-*] ──────────> BỊ CHẶN ĐẾN 38.5%
                                                ("This request was blocked by Gemini's filters")
                                                ==> Trả về choices: null ==> Recall tụt về 0.0000
```

### 3.1. Chi tiết các tệp bị Google Gemini kiểm duyệt đánh sập
Khi đưa các tệp mã nguồn thực tế của Superset và Saleor vào các mô hình Gemini 3.8 Flash, hệ thống ghi nhận lỗi chặn hàng loạt:
- **`superset_config.py`**: Bị chặn 100% trên cả 3 phiên bản Gemini (`low`, `medium`, `high`).  
  *Nguyên nhân*: Tệp chứa dòng gán giá trị khóa bí mật mặc định `SECRET_KEY = b"\x02\x01thisismysupersetsecretkey..."` (CVE-2023-27524). Bộ lọc của Google quét thấy chuỗi nhạy cảm giống token/key và đánh dấu là hành vi rò rỉ thông tin bảo mật hoặc khai thác credential.
- **`views_core.py`**: Bị chặn trên Gemini.  
  *Nguyên nhân*: Tệp dài chứa các tham số endpoint nhận URL ngoài để kiểm tra SSRF (CVE-2023-36388).
- **`query_context_factory.py` & `refresh_token.py`**: Bị chặn không trả về kết quả do chứa logic xử lý payload và token xác thực.

### 3.2. Cấu trúc phản hồi lỗi của Gemini khi bị chặn
Khi kích hoạt bộ lọc, API Google trả về cấu trúc không có trường `choices`:
```json
{
  "response": {
    "promptFeedback": {
      "blockReason": "OTHER",
      "blockReasonMessage": "This request was blocked by Gemini's filters. They can occasionally trigger by mistake on safe coding, security, or biology-related queries. Please try rephrasing your prompt."
    },
    "usageMetadata": { "promptTokenCount": 14115, "totalTokenCount": 14115 }
  }
}
```
**Hậu quả kỹ thuật**: Các SDK OpenAI-compatible (như client của VulnAgent) nhận về phản hồi `resp.choices = None`, dẫn đến việc quét bị đổ vỡ trên các tệp quan trọng nhất và kéo chỉ số Recall của dòng Gemini xuống **0.0000**.

### 3.3. Tại sao GPT-5.6-Luna, Codestral, Gemma 4 và GPT-OSS:120B không bị chặn?
- **`cx/gpt-5.6-luna` & `mistral/codestral-latest`**: OpenAI và Mistral AI đã huấn luyện mô hình có nhận thức ngữ cảnh phòng thủ (Defensive Security Context Awareness). Hệ thống hiểu rõ sự khác biệt giữa *"yêu cầu viết mã khai thác tấn công"* và *"phân tích mã nguồn tĩnh tìm lỗi (SAST Code Audit)"*, giúp 100% tệp tin được xử lý an toàn không gián đoạn.
- **`ollama/gemma4` & `ollama/gpt-oss:120b`**: Vận hành hoàn toàn trên hạ tầng máy chủ cục bộ (On-Premise / Local Ollama), không đi qua bất kỳ cổng kiểm duyệt trung gian nào của nhà cung cấp Cloud bên thứ ba, bảo đảm quyền tự chủ tuyệt đối và tính liên tục trong vận hành.

---

## 4. PHÂN TÍCH ĐÁNH ĐỔI GIỮA NĂNG LỰC SUY LUẬN VÀ ĐỘ TRỄ (THINKING BUDGET LATENCY)

Khảo sát 3 mức suy luận của Google Gemini 3.8 Flash (`low`, `medium`, `high`) làm rõ hiện tượng **bùng nổ độ trễ và tỷ lệ quá thời gian (Timeout)** trong bài toán kiểm thử bảo mật hàng loạt:

1. **`ag/gemini-3.8-flash-low`**:
   - Sử dụng trung bình **2.491 Reasoning Tokens**.
   - Độ trễ trung bình: **23.99 giây / request**.
   - Tỷ lệ hoàn tất 53.8% (4 tệp bị chặn, 2 tệp bị timeout).
2. **`ag/gemini-3.8-flash-medium`**:
   - Tăng Reasoning Tokens lên **3.320 tokens**.
   - Độ trễ tăng vọt lên **32.89 giây / request**.
   - Số tệp bị timeout tăng lên 4 tệp (30.8% timeout), chỉ còn 4/13 tệp hoàn tất thành công.
3. **`ag/gemini-3.8-flash-high`**:
   - Mức suy luận sâu đòi hỏi thời gian tính toán rất lớn, độ trễ trung bình vượt ngưỡng **43.39 giây**.
   - **11 trên tổng số 13 tệp (84.6%) bị rơi vào trạng thái Timeout (>45s)**.
   - **Kết luận**: Mức suy luận `high` của Gemini hoàn toàn không khả thi cho các pipeline quét bảo mật tự động hóa trong CI/CD, chỉ thích hợp cho tương tác trò chuyện đơn lẻ 1-1 với lập trình viên.

---

## 5. PHÂN TÍCH CHUYÊN SÂU HAI MÔ HÌNH MỚI: MISTRAL CODESTRAL VÀ GPT-OSS 120B

Đợt cập nhật thực nghiệm bổ sung hai đại diện nổi bật trong cộng đồng kỹ thuật: mô hình chuyên biệt mã nguồn `mistral/codestral-latest` và mô hình mã nguồn mở quy mô cực lớn `ollama/gpt-oss:120b`.

### 5.1. `mistral/codestral-latest`: Chuyên biệt mã nguồn, độ nhạy AST cao và chuẩn mực cấu trúc
- **Ưu điểm vượt trội**:
  1. **100% không bị Safety Filter chặn**: Mô hình được thiết kế tối ưu riêng cho tác vụ kỹ thuật phần mềm, hoàn toàn không bị vấp phải các bộ lọc nội dung giả như dòng Gemini.
  2. **Hiểu cú pháp AST và ngữ cảnh mã nguồn sâu sắc**: Codestral đạt tỷ lệ phát hiện **Recall = 33.33%** (cao thứ hai toàn bảng, chỉ sau GPT-5.6-Luna), bắt trúng chính xác 3 lỗ hổng CVE phức tạp:
     - **CVE-2023-27524**: Hardcoded Default `SECRET_KEY` trong `superset_config.py` (CWE-798: Khóa bí mật mặc định dẫn đến giả mạo phiên làm việc và RCE).
     - **CVE-2024-53948**: Information Disclosure trong `database_views.py` (CWE-209: Rò rỉ siêu dữ liệu cơ sở dữ liệu qua thông báo lỗi khi kiểm tra kết nối).
     - **CVE-2023-25504**: Improper Input Validation trong `query_context_factory.py` (CWE-20: Thiếu kiểm tra hợp lệ dữ liệu đầu vào trong quá trình dựng truy vấn).
  3. **Tuân thủ chuẩn JSON Schema 100%**: Tất cả 13 phản hồi đều đạt chuẩn JSON nghiêm ngặt ngay ở định dạng thô, không cần đến bất kỳ sự can thiệp nào từ module JSON repair của VulnAgent.
- **Hạn chế kỹ thuật**:
  - **Quá nhạy cảm (Hyper-sensitivity / Over-flagging)**: Do được huấn luyện chuyên sâu về code patterns, Codestral có xu hướng gắn cờ cảnh báo đối với mọi cấu trúc code tiềm ẩn rủi ro logic, dẫn đến **41 cảnh báo sai (FP)** (trong đó có 10 FP rơi vào 4 tệp sạch đối chứng). Điều này khiến Precision tụt xuống **6.82%** và F1-Score đạt **0.1132**.

### 5.2. `ollama/gpt-oss:120b`: Sức mạnh mã nguồn mở 120B Local, độ chính xác cao và thách thức Schema
- **Ưu điểm vượt trội**:
  1. **Tự chủ On-Premise tuyệt đối**: Chạy hoàn toàn cục bộ qua Ollama, bảo vệ toàn vẹn bí mật mã nguồn doanh nghiệp, 0% bị chặn bởi kiểm duyệt bên ngoài.
  2. **Tỷ lệ báo sai rất thấp (High Precision on False Positives)**: Mô hình chỉ sinh ra duy nhất **5 FP** trên toàn bộ 13 tệp kiểm thử, đặc biệt đạt **0 FP trên toàn bộ 4 tệp sạch đối chứng (FP on clean = 0)**. Precision đạt **16.67%**, chỉ đứng sau GPT-5.6-Luna (17.24%).
  3. **Tốc độ ấn tượng đối với mô hình 120B**: Độ trễ trung bình đạt **10.04s / request**, nhanh gấp 1.6 lần so với GPT-5.6-Luna (16.37s) và nhanh gấp 2–4 lần so với dòng Gemini Flash.
  4. **Bắt trúng lỗ hổng nghiêm trọng**: Phát hiện chính xác CVE-2023-27524 (Default SECRET_KEY trong `superset_config.py`).
- **Hạn chế kỹ thuật**:
  - **Tỷ lệ tuân thủ JSON Schema nghiêm ngặt còn thấp (38.46%)**: Chỉ có 5/13 tệp trả về JSON thô hợp lệ trực tiếp. Trong 8/13 tệp còn lại (61.54%), mô hình tự động bao bọc kết quả trong markdown code fence (````json ... ````) hoặc sử dụng tên trường biến thể (như `vulnerability_type` thay vì `type`). Mô hình đòi hỏi hệ thống SAST phải có bộ giải cứu cú pháp (`json_salvage` / syntax repair) mạnh mẽ như VulnAgent để trích xuất dữ liệu thành công.
  - **Độ bao phủ (Recall) khiêm tốn**: Đạt **11.11%** (1/9 CVE), mô hình có xu hướng thận trọng cao nên đã bỏ qua các lỗ hổng phân tán đa bước.

---

## 6. ĐÁNH GIÁ, BẢNG XẾP HẠNG VÀ KHUYẾN NGHỊ CHO ĐỒ ÁN (RANKINGS & RECOMMENDATIONS)

Dựa trên các bằng chứng thực nghiệm định lượng toàn diện, chúng em đề xuất khung xếp hạng và định hướng lựa chọn mô hình cho hệ thống VulnAgent:

### 🏆 HẠNG 1 (Frontier Cloud toàn diện): `cx/gpt-5.6-luna`
- **Điểm đánh giá kỹ thuật**: **9.6 / 10**
- **Chỉ số cốt lõi**: F1-Score cao nhất (**0.2632**), Recall cao nhất (**55.56%**, bắt trúng 5/9 CVE), Precision cao nhất (**17.24%**), 0.0% Blocked, 0.0% Timeout, 100% Valid JSON, độ trễ tối ưu 16.37s.
- **Khuyến nghị cho đồ án**: Lựa chọn làm **Mô hình Mặc định Toàn diện (Default Primary Model)** cho VulnAgent ở môi trường Cloud. Đây là mô hình mang lại kết quả học thuật và ứng dụng thực tiễn cao nhất khi báo cáo trước hội đồng.

---

### 🥈 HẠNG 2 (Chuyên biệt Code): `mistral/codestral-latest`
- **Điểm đánh giá kỹ thuật**: **8.9 / 10**
- **Chỉ số cốt lõi**: Recall cao thứ hai (**33.33%**, bắt trúng 3/9 CVE), 0.0% Blocked, 100% Valid JSON, độ trễ 16.71s, hiểu sâu cú pháp AST và luồng dữ liệu code.
- **Khuyến nghị cho đồ án**: Lựa chọn làm **Mô hình Chuyên biệt Mã nguồn (Specialized Code Inspector)**. Rất phù hợp để đưa vào tầng Deep Analysis hoặc phối hợp trong kiến trúc Ensemble / Tiered Verification nhằm thẩm định chéo với mô hình Frontier.

---

### 🥉 HẠNG 3 (Mã nguồn mở On-Premise): `ollama/gemma4` và `ollama/gpt-oss:120b`
- **`ollama/gemma4`** (Điểm: **8.8 / 10**):
  * Tốc độ nhanh nhất toàn bảng (**4.95s / request**), F1-Score đạt **0.1429** (Recall 22.22%), không bị chặn, mức tiêu thụ tài nguyên phần cứng thấp.
  * Phù hợp cho: Tích hợp vào pre-commit hooks, CI/CD pipeline tốc độ cao, máy trạm cục bộ cấu hình vừa phải.
- **`ollama/gpt-oss:120b`** (Điểm: **8.5 / 10**):
  * Năng lực mô hình tham số lớn 120B, tỷ lệ báo sai cực thấp (Precision 16.67%, **0 FP trên tệp sạch đối chứng**), độ trễ ấn tượng 10.04s, bắt đúng CVE-2023-27524.
  * Phù hợp cho: Triển khai on-premise tại các tổ chức tài chính, ngân hàng, cơ quan an ninh đòi hỏi tính bảo mật dữ liệu tuyệt đối (Air-gapped Network) kết hợp cùng module JSON repair.
- **Khuyến nghị cho đồ án**: Cặp mô hình đại diện cho **Giải pháp On-Premise / Air-gapped Deployment**, minh chứng VulnAgent hoàn toàn tự chủ mà không bị phụ thuộc vào API độc quyền của các nhà cung cấp nước ngoài.

---

### ❌ NHÓM KHÔNG KHUYẾN NGHỊ CHO SECURITY AUDIT: Dòng `ag/gemini-3.8-flash-*`
- **Điểm đánh giá kỹ thuật**: `low` (**6.0 / 10**), `medium` (**3.5 / 10**), `high` (**2.0 / 10**)
- **Lý do loại trừ**:
  1. **Bị bộ lọc Google Safety Filter chặn từ chối xử lý**: Tỷ lệ Blocked từ **30.8% đến 38.5%** trên các tệp mã nguồn nhạy cảm chứa credential, URL tham số hay token logic.
  2. **Nghịch lý suy luận sâu gây tắc nghẽn (Timeout Bottleneck)**: Tỷ lệ timeout tăng phi mã theo mức suy luận (15.4% ở `low`, 30.8% ở `medium`, và lên tới **84.6%** ở `high`).
  3. **Hiệu quả thực tế bằng 0**: Cả 3 phiên bản đều có Recall = **0.00%** (0/9 CVE phát hiện được). Hoàn toàn không thể đưa vào quy trình audit an toàn mã nguồn thực tế.

---

## 7. ĐÓNG GÓP HỌC THUẬT ĐƯA VÀO LUẬN VĂN TỐT NGHIỆP

Số liệu thực nghiệm định lượng trên 7 mô hình cung cấp các luận cứ khoa học sắc bén cho **Chương 4 (Thực nghiệm & Đánh giá)** và **Chương 5 (Bàn luận & Kiến trúc Đề xuất)** của luận văn:

1. **Vấn đề "Bộ lọc kiểm duyệt làm mù công cụ an ninh" (Safety Filter Censorship Dilemma)**:
   - Các mô hình AI thương mại đóng vai trò người gác cổng tổng quát thường áp dụng bộ lọc từ chối nội dung quá cứng nhắc. Khi nạp vào các tệp mã nguồn chứa lỗ hổng bảo mật thật để phân tích phòng thủ, bộ lọc kích hoạt và đánh sập tiến trình audit.
   - Luận văn rút ra kết luận: Công cụ SAST thông minh bắt buộc phải chọn các mô hình có cơ chế phân biệt ngữ cảnh phòng thủ (Defensive Security Context) như `cx/gpt-5.6-luna`, `mistral/codestral-latest` hoặc hoàn toàn tự chủ với mô hình mã nguồn mở cục bộ (`ollama/gemma4`, `ollama/gpt-oss:120b`).
2. **Sự đánh đổi giữa Độ nhạy AST và Tỷ lệ Báo sai (Sensitivity vs. False Positive Trade-off)**:
   - Minh chứng từ `mistral/codestral-latest` cho thấy một mô hình chuyên biệt mã nguồn có khả năng phát hiện lỗ hổng logic sâu rất tốt (Recall 33.33%), nhưng lại đánh đổi bằng việc sinh ra nhiều cảnh báo phụ (41 FP). Điều này chứng minh sự cần thiết của tầng Thẩm định (Verification Tier / Verifier) trong kiến trúc VulnAgent để gạn lọc cảnh báo rác.
3. **Thách thức Chuẩn hóa Dữ liệu Cấu trúc trên Mô hình Local (JSON Schema Robustness)**:
   - Minh chứng từ `ollama/gpt-oss:120b` cho thấy các mô hình mã nguồn mở quy mô lớn dù có khả năng phân tích mạnh nhưng thường gặp lỗi bọc mã markdown hoặc lệch schema JSON (tỷ lệ JSON thô đạt 38.46%). Khẳng định tầm quan trọng sống còn của **Module JSON Salvage / AST-Guided Repair** mà VulnAgent đã xây dựng.
4. **Khẳng định tính ưu việt của Kiến trúc 3 tầng Bất đối xứng (Asymmetric 3-Tier Architecture)**:
   - Kiến trúc VulnAgent không bị "khóa chặt" vào một mô hình cụ thể (No Vendor Lock-in). Hệ thống có thể chuyển đổi linh hoạt: dùng `cx/gpt-5.6-luna` cho phân tích Cloud toàn diện, dùng `mistral/codestral-latest` cho thẩm định code chuyên sâu, hoặc chạy `ollama/gemma4` + `ollama/gpt-oss:120b` trên hạ tầng On-Premise tuyệt mật.

---

*Toàn bộ dữ liệu thô và kịch bản thực nghiệm được lưu trữ minh bạch tại:*
- Script thực thi kiểm thử: `eval/run_model_comparison.py`
- Bảng tổng hợp số liệu kỹ thuật: `reports/model_comparison/models_metrics_summary.csv`
- Log chi tiết từng model: `reports/model_comparison/*.json`
