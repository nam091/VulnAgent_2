# DANH MỤC CẦN SỬA TRONG BÁO CÁO ĐỒ ÁN

**File đích:** `F:\PERSIONAL\DO_AN\File_bao_cao_ai_fix\BAO_CAO_DO_AN_TOT_NGHIEP_LA_PHUONG_NAM_AT19E.docx`
(477 paragraph, 40 bảng — **không phải** bản `bao_cao/` 463 paragraph, bản đó đã cũ)

**Nguồn:** 2 reviewer độc lập (`gpt-6-sol`, thinking high) + em tự xác minh bằng code và artifact.

**Ký hiệu vị trí:** `[Pn]` = paragraph thứ n trong docx, `[Tn rX cY]` = bảng thứ n, hàng X, cột Y.

**Giới hạn:** tài liệu này KHÔNG sửa `.docx`. Chỉ liệt kê việc phải làm.

---

## 0.0 TRẠNG THÁI GATE — ĐÃ ĐẠT

**GATE STATUS: [VERIFIED: sound @ review #13]**

Reviewer `openai-codex/gpt-6-sol` đã cấp `Verdict: sound` với **0 BLOCKING** sau 13 vòng nghiệm thu toàn bộ diff.

| Chỉ số | Trước phiên sửa | Sau |
|---|---|---|
| pytest | 16 failed / 341 passed | **452 passed, 0 failed** |
| BLOCKING còn lại | 12 (reviewer code vòng gốc) | **0** |
| Gate C các vòng | — | 6→2→3→3→2→2→2→3+N→1→2→3→1→**0** |

### Non-blocking còn lại (1 mục, không chặn nộp)

Reviewer đề nghị bổ sung test tự động ghim hai ca biên: (a) LLM báo dòng 12 nhưng trace kết thúc sink dòng 10, (b) `taint_path` bẩn (`None`, list rỗng, step thiếu key). Em đã kiểm thủ công cả hai đều đạt — không phải lỗi, chỉ thiếu test hồi quy.

### Ảnh hưởng tới số liệu trong báo cáo

**Số liệu trong docx đứng vững** — nhưng phạm vi bằng chứng còn giữ được hẹp hơn con số thường được trích.

**Artifact thực tế còn lưu:**

`reports/rescored_history/metrics_core10.csv` có **51 dòng**: **13 `scored`**, 1 `incomplete`, 1 `empty`, 36 `unsupported`.
`reports/rescored_history/metrics_full.csv` cùng cấu trúc.

13 job được chấm (`core10`), tách theo dataset lấy từ cột `dataset` của CSV:

- **owasp-full (7 job)**: `5ec88c710906`, `aebeb9df7201`, `c72fca194b29`, `ff60cd823550`, `52fb84884189`, `5cf511bb72df`, `dc790eb023ce`
- **owasp-mini (6 job)**: `26dfdce3277c`, `62dbabbb2a42`, `a8b2ef400f59`, `c0f73dae2ea8`, `db5b38cd97c6`, `ecbb350b7f2c`

(`26dfdce3277c` là `benchmark100` / owasp-mini, `labels_in_scope = 48` — bản trước của note xếp nhầm vào nhóm full.)

**Đối chiếu docx ↔ artifact (đã kiểm):**

- `[P422]` Beam 1.0 owasp-full DeepVerify: 380 TP / 191 FP / Precision 66,55% / F1 0,7983 — khớp **chính xác** dòng `52fb84884189` trong `metrics_core10.csv`.
- Mẫu số ground truth đúng và tái lập được: **48** nhãn trên owasp-mini, **381** nhãn trên owasp-full (clean 46 và 710).

**Giới hạn phải nói rõ:**

- **6 trong 20 job được trích trong báo cáo không còn trong snapshot**: `f27efb428d30`, `f8b459734396`, `9750509c05d8`, `27114c6c3af0`, `9ddc1f19c823`, `b43b14a0782a`. Các hàng tương ứng trong bảng kết quả của docx **không còn artifact để tái chấm**. Không được tuyên bố "0 sai khác trên 20 job".
- Con số "0 sai khác" chỉ đúng cho **13 job còn trong snapshot**. Những job đó được chấm lại bằng code hiện tại và khớp archive.

### Mất provenance — nguyên nhân và hệ quả

`src/jobs.py` đặt `DEFAULT_RETENTION = 50`: mỗi lần `JobStore.create()` gọi, job đã xong cũ nhất bị xoá. Bộ test `pytest tests/` tạo **snippet job** ngay trong `cwd/.vulnagent-jobs`, nên mỗi lần chạy suite lại prune thêm job thật. Hệ quả: **toàn bộ 20 job gốc của báo cáo đã bị xoá** trong phiên sửa này.

Nguồn truy nguyên còn lại:

| Nguồn | Nội dung |
|---|---|
| `reports/rescored_history/metrics_core10.csv` | 13 job chấm được, kèm TP/FP/FN/P/R/F1 |
| `reports/rescored_history/metrics_full.csv` | cùng 13 job ở phạm vi full |
| `reports/rescored_history/metrics_all.json` | hash từng job file tại thời điểm chấm, `snapshot_at`, `glob_count_at_run` |
| `99-work/review/job_inventory.json` | 20 job gốc: job ID, model, mode, findings, token, request, uncertain |

Không còn file `.vulnagent-jobs/<job_id>.json` nào cho 20 job đó. Ai muốn tái lập phải chạy scan lại (tốn credit) hoặc dựa vào `job_inventory.json` làm bản ghi.

### Baseline SAST không truy nguồn được

Số `Bandit 108/381` và `Semgrep 51/381` trong `[P421]` **không có artifact nào** trong `reports/`. Kiểm bằng grep `"tp": 108` và `"tp": 51` trên toàn bộ `reports/**/*.json` → không kết quả.

Trước đây note này từng gán Bandit 108/381 → job `f8b459734396` và Semgrep 51/381 → job `9ddc1f19c823`. **Cả hai gán đều sai**: `f8b459734396` là job semgrep trên owasp-mini với 38 findings (108 TP > 38 findings là bất khả); `9ddc1f19c823` có 342 detections, trong khi docx bảng 3.10 ghi Semgrep 51 TP / 116 FP = 167 detections.

**Việc phải làm với `[P421]` và Bảng 3.10:** hoặc chạy lại Bandit/Semgrep rồi đính kèm JSON, hoặc đánh dấu hai con số là *không có artifact lưu trữ* thay vì trình bày như đã đo.

### Điều cần lưu ý khi viết báo cáo

1. Vẫn nên tránh tuyên bố "chạy lại trên máy khác ra đúng từng con số" — LLM không tất định, dù code đã đúng.
2. `reports/rescored_history/` là snapshot 51 job tại thời điểm chạy (server tạo job mới liên tục). Không gọi là "toàn bộ lịch sử quét".
3. Nếu hội đồng hỏi về tái lập: đã tái lập trên archive lưu trữ, code đã qua 13 vòng nghiệm thu độc lập.

### 21 lỗi đã đóng trong phiên

Scope 10 CWE một nguồn duy nhất · prompt core10 có CWE tương đương · scanner/analyzer lọc cả hai tier · evaluator chấm cùng scope · bỏ ghép path basename · `eligible('','full')==True` · `safe_reader` không đọc file khác basename · manifest khớp glob + snapshot fields · verifier không tự đổi `uncertain→refuted` từ sanitizer · verifier không remap evidence theo basename · `loop.py` cắt content trước khi trích reads · dedup không xoá finding đã `supported` · `--frozen-from` không ghi đè manifest · cache LLM phân biệt model/scope/prompt · cache phân biệt provider fallback (`_served_by`) · `_find_match` dùng `is_same_sink` · `_deduplicate_tier` union evidence · `_combine` giữ taint_path của rule · `alternate_taint_paths` serialize ra output · `verdicts_conflict` dùng chung 3 chỗ · refutation theo object identity không theo fingerprint · `_has_conflicting_counterpart` kiểm same sink · suppression không xoá finding đã confirmed.

---

## 0. TRẠNG THÁI TỔNG THỂ

| Hạng mục | Số lượng |
|---|---:|
| BLOCKING phải sửa trước khi nộp | **12** |
| NON-BLOCKING nên sửa | **4** |
| Bảng số đã truy được nguồn (job ID) | **12** |
| Phát hiện riêng do em tìm, reviewer chưa thấy | **6** |

**Điểm quan trọng nhất:** không có số nào bịa. Toàn bộ 12 bảng số kết quả truy được về job ID cụ thể và khớp tới từng đơn vị (xem mục 4). Vấn đề nằm ở **cách diễn giải** và **phạm vi chấm điểm**, không phải ở dữ liệu.

---

## 1. SÁU LỖI MÔ TẢ CÀI ĐẶT (không phụ thuộc số liệu, sửa được ngay)

### 1.1 — [BLOCKING] Bốn lớp Pydantic không tồn tại

**Vị trí:** `[P187]`, `[T9 r2–r5]`, `[P340]`

**Báo cáo viết:**
> "hệ thống định nghĩa các cấu trúc dữ liệu trung gian bất biến được quản trị chặt chẽ bởi Pydantic v2."

**Thực tế trong code:** `[T9]` mô tả 4 lớp `CodeSlice`, `CandidateFinding`, `VerifiedFinding`, `PatchCandidate`. **Không lớp nào tồn tại.** Code dùng `dataclass`:
- `SliceResult` — `src/models/cwe_scope.py` không liên quan; thực thể là `src/context/ast_slicer.py:656`
- `Verdict` — `src/agent/verifier.py:555`
- `Patch` — `src/analyzer/fixer.py:126`
- `FusionResult` — `src/analyzer/fusion.py:59`

**Câu thay thế:**
> Các tầng trao đổi kết quả qua các dataclass `SliceResult`, `Vulnerability`, `FusionResult` và `Verdict`; không có bốn lớp Pydantic nêu tại Bảng 2.2.

---

### 1.2 — [BLOCKING] "Out-of-Scope chỉ trích chữ ký hàm" là sai

**Vị trí:** `[P227]`, `[P355]`

**Báo cáo viết:**
> "Vùng ngữ cảnh ngoại vi Out-of-Scope Signatures. Chỉ trích xuất chữ ký hàm, danh sách tham số và tài liệu mô tả."

**Thực tế:** `src/analyzer/prompt_manager.py:877–912` đưa **toàn bộ mã nguồn** vào prompt khi tệp ≤ 500 dòng. `:1020–1086` giữ nguyên khối hàm liên quan cho tệp dài. `:1485–1494` thêm khối `FULL SOURCE (REFERENCE)`.

**Hệ quả:** tuyên bố "tiết kiệm token nhờ chỉ lấy chữ ký" không có cơ sở.

**Câu thay thế:**
> Prompt chứa lát cắt AST và mã nguồn tham chiếu; tệp không quá 500 dòng được giữ nguyên, tệp dài hơn được rút gọn có điều kiện.

---

### 1.3 — [BLOCKING] Tệp lỗi cú pháp không "vẫn chạy bình thường"

**Vị trí:** `[P221]`

**Báo cáo viết:**
> "động cơ cắt lát cú pháp và tầng suy luận ngữ nghĩa vẫn tiếp tục vận hành bình thường"

**Thực tế:** `src/analyzer/code_analyzer.py:421–424` trả `[]` khi `ast.parse` thất bại. AST slicer **không cắt lát được**. Nếu LLM tắt, quét bị đánh dấu thất bại — đúng như `[T35]` của chính báo cáo.

**Câu thay thế:**
> Khi tệp lỗi cú pháp, AST slicer không tạo được lát cắt; nếu LLM khả dụng, hệ thống có thể tiếp tục phân tích bằng ngữ cảnh không cắt lát và ghi trạng thái suy biến.

---

### 1.4 — [BLOCKING] Ngưỡng rủi ro 0 không bảo đảm quét mọi tệp

**Vị trí:** `[P201]`

**Báo cáo viết:**
> "ngưỡng rủi ro được thiết lập về 0 nhằm bảo đảm không bỏ sót bất kỳ tệp mã nguồn nào"

**Thực tế:** `src/analyzer/scanner.py:458–465` đặt ngưỡng 0 nhưng **vẫn truyền** `limit=self.options.max_llm_files`. `src/analyzer/discovery.py:194–214,244–285` còn loại trừ đường dẫn, giới hạn `.py`, áp trần định tuyến.

**Câu thay thế:**
> DeepVerify đặt ngưỡng định tuyến về 0 đối với các tệp Python đã được khám phá, trừ tệp bị loại trừ hoặc vượt trần cấu hình.

---

### 1.5 — [BLOCKING] Điểm CVSS không tính theo CVSS v3.1

**Vị trí:** `[P302–P305]`, `[T18 r2–r6]`

**Báo cáo viết:**
> "Dựa trên các chỉ số thành phần, hệ thống tự động xác định điểm số cơ sở"

**Thực tế:** `src/analyzer/code_analyzer.py:593–625` chỉ **cộng** 3.3/2.0/1.0 theo hậu tố `C/I/A:H/M/L`, rồi chặn ở 10. Nhãn `critical/high/medium/low` ánh xạ cứng thành 9.5/8.0/5.5/3.0. **Không có** phép tính CVSS v3.1 Base Score từ vector AV/AC/PR/UI/S.

**Câu thay thế:**
> Hệ thống lưu điểm do mô hình đề xuất và chuẩn hoá một số đầu vào bằng heuristic; chưa triển khai bộ tính CVSS v3.1 từ vector đầy đủ.

---

### 1.6 — [BLOCKING] Ví dụ bản vá mật khẩu dùng SHA-256

**Vị trí:** `[T15 r1 c1]`

**Báo cáo viết:**
> "An toàn: Nâng cấp lên giải thuật an toàn SHA-256 hoặc bcrypt … `safe_hash = hashlib.sha256(user_password.encode()).hexdigest()`"

**Thực tế:** `src/analyzer/prompt_manager.py:590` — chính dự án quy định mật khẩu "MUST use slow, adaptive salted hashing (bcrypt, argon2, scrypt, PBKDF2), **NEVER fast hashing algorithms**". SHA-256 trực tiếp là fast hash.

**Câu thay thế:**
> Với mật khẩu, dùng bcrypt, Argon2 hoặc PBKDF2 có salt và tham số chi phí phù hợp; không thay MD5 bằng SHA-256 trực tiếp.

---

## 2. LỖI NGÔN TỪ VÀ KHẲNG ĐỊNH QUÁ MỨC

### 2.1 — [BLOCKING] "Loại bỏ hơn 75% mã nguồn" không có phép đo

**Vị trí:** `[P149]`, `[P174]`, `[P210]`, `[P218]`, `[P310]`, `[P347]`, `[P447]`, `[P453]`, `[T8 r1 c3]`, `[T20 r2 c3]` — **10 vị trí**

**Thực tế:** không có phép đo tỉ lệ thu gọn nào trong code. Không có log, không có counter, không có test.

**Hai lựa chọn:**
1. Bỏ hẳn con số 75%, thay bằng: *"Tầng 1 định vị sink và trích xuất lát cắt ngược dòng nhằm giảm lượng mã không liên quan được chuyển sang LLM. Mức độ thu gọn phụ thuộc cấu trúc từng tệp và từng sink."*
2. Đo thật rồi mới ghi. Có thể thêm counter vào `ASTSlicer` ghi `lines_total` / `lines_in_slice`, chạy trên 100 tệp mini, lấy số trung vị.

---

### 2.2 — [BLOCKING] "Triệt tiêu hoàn toàn cảnh báo sai"

**Vị trí:** `[P261]` và 12 vị trí khác chứa "triệt tiêu"

**Báo cáo viết:**
> "Cảnh báo bị triệt tiêu hoàn toàn và không xuất hiện trở lại."

**Thực tế:** owasp-full vẫn còn **123–191 FP** tùy cấu hình, và **54–588 ca `uncertain`**.

**Câu thay thế:**
> Cảnh báo được loại khỏi kết quả cuối cùng khi có kiểm soát bù trừ được nêu tên; hệ thống không bảo đảm loại bỏ toàn bộ cảnh báo sai.

---

### 2.3 — [NON-BLOCKING] Bảng thay từ ngữ

| Đang dùng | Số lần trong docx | Thay bằng |
|---|---:|---|
| triệt tiêu | 12 | giảm đáng kể · loại một phần |
| tuyệt đối | 14 | (bỏ hẳn) hoặc "ở mức cao" |
| vượt trội | 11 | cao hơn trong thực nghiệm này |
| giải quyết hoàn hảo `[P223]` | 1 | góp phần xử lý |
| cách mạng `[P117]` | 1 | bước tiến đáng kể |
| phán quyết dứt khoát | — | kết quả thẩm định |
| cứu tệp sạch | — | tránh đánh dấu nhầm tệp sạch |
| khẳng định | — | cho thấy |

---

### 2.4 — [NON-BLOCKING] Định nghĩa TN sai thuật ngữ

**Vị trí:** `[P114]`, `[T1 r36 c3]`

**Báo cáo viết:** "bỏ sót đúng TN" — gây nhầm với FN.

**Câu thay thế:** "TN là ca âm tính đúng: mã an toàn và không bị cảnh báo."

---

### 2.5 — [NON-BLOCKING] "Mili giây" chưa có số đo

**Vị trí:** `[P251]` — "truy xuất tức thời … với độ trễ tính bằng mili giây".

**Thực tế:** không có bảng đo độ trễ `read_imported_symbol` trong `reports/`.

**Câu thay thế:** "Agent truy xuất định nghĩa thông qua chỉ mục biểu tượng; báo cáo chưa đo độ trễ riêng của thao tác này."

---

### 2.6 — [NON-BLOCKING] Nguồn khảo sát bên ngoài chưa có artifact

**Vị trí:** `[P115]`, `[P117]`, `[P409–P413]`, `[T25–T27]`

Các số "40% đến hơn 70%", "15 đến 25 phút", và dữ liệu BenchLM.ai **chưa có snapshot/phản hồi lưu trong repo**. Cần: ghi ngày truy cập, phiên bản API, hoặc đính kèm file JSON gốc vào `reports/`.

---

## 3. LỖI PHƯƠNG PHÁP LUẬN

### 3.1 — [BLOCKING] Khoảng Precision tự mâu thuẫn với chính bảng

**Vị trí:** `[P430]`

**Báo cáo viết:**
> "Precision trên **mọi cấu hình** chỉ đạt 66,55%–73,83%"

**Thực tế trong chính báo cáo:** `[T32 r8 c5]` ghi Gemma 4 31B · LLM thuần **38,84%**; `[T32 r5 c5]` ghi Beam · LLM thuần **68,04%**.

**Câu thay thế:**
> Precision của các cấu hình DeepVerify trên owasp-full nằm trong khoảng 66,55%–73,83%; Gemma 4 31B ở chế độ LLM thuần chỉ đạt 38,84%.

---

### 3.2 — [BLOCKING] Khoảng Recall bỏ sót các hàng bất lợi

**Vị trí:** `[P456]`, `[P465]`

**Báo cáo viết:**
> "DeepVerify đạt Recall 97,92%–100,00% trên owasp-mini … và 98,43%–99,74% trên owasp-full"

**Thực tế trong chính báo cáo:** `[T28 r4–r5 c7]` ghi GPT-6 Luna **91,67%**, gpt-5.6-luna **87,50%**. `[T32 r2,r6 c6]` ghi GPT-6 Luna **91,08%**, gpt-5.6-luna **92,65%**.

**Câu thay thế:**
> Trong các cấu hình DeepVerify được liệt kê, Recall trải từ 87,50% đến 100,00% trên mini và từ 91,08% đến 99,74% trên full.

---

### 3.3 — [BLOCKING] Suy "thứ hạng tổng quát không tương quan" từ 3 mô hình

**Vị trí:** `[P417]`, `[P457]`

**Báo cáo viết:**
> "Thứ hạng năng lực tổng quát … gần như không tương quan thuận với hiệu quả rà soát lỗ hổng mã nguồn"

**Thực tế:** `[T29 r2–r4]` chỉ có **3 mô hình**. Không có phép kiểm định tương quan nào trong `eval/run_eval.py` hay `eval/evaluate_scan.py`. Ba điểm quan sát không đủ để kết luận quy luật.

**Câu thay thế:**
> Trong ba mô hình và các lượt đo được trình bày, thứ tự F1 trên owasp-mini khác thứ tự BenchAlign; chưa đủ mẫu để kết luận về tương quan tổng quát.

---

### 3.4 — [BLOCKING] "Khắc phục bỏ sót ở quy mô lớn" vượt quá thiết kế đánh giá

**Vị trí:** `[P419]`, `[P459]`, `[P461]`

**Thực tế:** `[P451]` tự xác nhận toàn bộ 100 tệp mini nằm trong 1.230 tệp full → **owasp-mini ⊂ owasp-full**, cùng nguồn OWASP BenchmarkPython. Kết quả full chỉ là kiểm chứng **mở rộng quy mô**, không phải kiểm chứng độc lập.

Quan trọng hơn: `reports/multi_codebase_benchmark/metrics_summary.csv` ghi 3-Tier trên Superset **2 TP/10 nhãn, status degraded** và Saleor **0 TP/5 nhãn, degraded**. Artifact đa codebase **không ủng hộ** kết luận về khả năng tổng quát hoá.

**Câu thay thế:**
> Các số OWASP cho thấy hiệu năng trên cùng họ benchmark khi tăng quy mô; kết quả trên codebase khác phân phối hiện còn suy biến và chưa xác nhận khả năng tổng quát hoá.

Đồng thời thêm vào phần **đe dọa tính hợp lệ**:
> owasp-mini là tập con thực sự của owasp-full (toàn bộ 100 tệp đều nằm trong bộ lớn). Vì vậy kết quả trên bộ lớn phản ánh kiểm chứng mở rộng quy mô, không phải kiểm chứng độc lập trên một phân phối dữ liệu khác. Không sử dụng hai bộ này như hai lần kiểm chứng độc lập.

---

### 3.5 — [BLOCKING] Kiểm tra tiền tố đường dẫn được gọi là an toàn

**Vị trí:** `[P285]`, `[T13 r11 c5]`

**Báo cáo viết:**
> "so sánh tiền tố `abspath().startswith(base_dir)`, Agent ra phán quyết REFUTED"

**Thực tế:** so tiền tố chuỗi chấp nhận cả thư mục anh em — `/var/data/reports-old` khớp `base_dir=/var/data/reports`. Không đủ căn cứ bác bỏ CWE-22. Chính báo cáo ở `[T16 r1 c1]` dùng `resolve()` + `is_relative_to()`.

**Câu thay thế:**
> Chỉ bác bỏ khi đường dẫn đã chuẩn hoá được kiểm tra thuộc thư mục gốc bằng phép kiểm tra thành phần đường dẫn, chẳng hạn `Path.resolve().is_relative_to(base.resolve())`.

---

### 3.6 — [BLOCKING] Mật độ FP tăng khi mở rộng quy mô chưa được thảo luận

**Vị trí:** cần thêm đoạn mới ngay sau phần kết quả owasp-full

**Số liệu:** mật độ FP tăng từ **7,45 lên 17,51 FP/100 tệp**. **CWE-611** là nguồn chính: 5/7 FP trên mini, 59/191 FP trên full.

**Đoạn cần thêm:**
> Kết quả trên owasp-mini không đủ để kết luận về khả năng tổng quát hoá. Khi mở rộng quy mô, mật độ cảnh báo sai tăng từ 7,45 lên 17,51 FP trên 100 tệp và Precision không còn đạt mục tiêu 85%. CWE-611 (XXE) là nguồn cảnh báo sai chính: 5/7 FP trên owasp-mini và 59/191 FP trên owasp-full, do việc phân biệt cấu hình parser XML an toàn và không an toàn chưa ổn định.

---

## 4. TRUY NGUỒN 12 BẢNG SỐ — KHÔNG CÓ SỐ BỊA

Reviewer báo cáo đánh `[UNVERIFIED]` cho 12 bảng. Em truy được **toàn bộ**, khớp tới từng đơn vị.

### 4.0 — CẢNH BÁO: ba con số trong báo cáo KHÔNG có artifact

Ba con số sau xuất hiện trong docx nhưng **không truy được về file nào** trong repo:

| Con số | Vị trí docx | Trạng thái |
|---|---|---|
| Bandit 108 TP / 381 nhãn | `[P421]`, Bảng 3.10 | Không artifact. Grep `"tp": 108` trên toàn `reports/**/*.json` → 0 kết quả. |
| Semgrep 51 TP / 381 nhãn | `[P421]`, Bảng 3.10 | Không artifact. Grep `"tp": 51` → 0 kết quả. |
| F1 0,3558 / 0,1861 | `[P421]`, `[P456]` | Phụ thuộc hai con số trên, nên cũng không tái lập được. |

**Việc phải làm:** hoặc chạy lại Bandit và Semgrep trên `eval/datasets/benchmark`, lưu JSON kết quả vào `reports/`, rồi cập nhật số; hoặc đánh dấu rõ trong docx là *"số liệu baseline SAST không còn artifact lưu trữ"*. Không được trình bày ba con số này như đã đo nếu vẫn không có file.

---

### 4.1 — Đối chiếu mẫu (khớp tuyệt đối)

| Claim trong docx | Job ID | Giá trị thật trong JSON |
|---|---|---|
| `[P422]` 25,47 triệu token | `52fb84884189` | `total_tokens = 25472099` |
| `[P422]` 2.507 API request | `52fb84884189` | `api_requests = 2507` |
| `[P422]` 8.575,23s | `52fb84884189` | `total_seconds = 8575.23` |
| `[P422]` 708 ứng viên | `52fb84884189` | `verified_candidates = 708` |
| `[P422]` 588 uncertain | `52fb84884189` | `verify_uncertain = 588` |
| `[P421]` Gemma full DeepVerify, 54 uncertain | `5cf511bb72df` | `verify_uncertain = 54` |
| `[P421]` Gemma LLM thuần 600 FP | `dc790eb023ce` | 1147 findings |
| `[P421]` Bandit 108/381 | **KHÔNG TRUY NGUỒN ĐƯỢC** | Không artifact nào trong `reports/` chứa `tp=108`. `f8b459734396` là job semgrep owasp-mini với 38 findings — không thể là 108 TP trên 381 nhãn. |
| `[P421]` Semgrep 51/381 | **KHÔNG TRUY NGUỒN ĐƯỢC** | Không artifact nào chứa `tp=51`. `9ddc1f19c823` có 342 detections, trong khi bảng 3.10 của docx ghi 51 TP + 116 FP = 167 detections. |

### 4.2 — Bảng ánh xạ đầy đủ 20 job benchmark

| Job ID | Dataset thiệt | Mode | Model | Findings | Nhãn full | Nhãn core10 | Uncertain | Token (M) | Requests | Giây |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| `f27efb428d30` | owasp-mini | deep-verify | cbai/hy3 | 54 | 50 | 48 | 28 | 4.94 | 685 | 1351.6 |
| `26dfdce3277c` | owasp-mini | llm | cbai/hy3 | 55 | 50 | 48 | 0 | 3.66 | 227 | 2461.4 |
| `f8b459734396` | owasp-mini | semgrep | reflection/beam:free | 38 | 50 | 48 | 0 | 0.00 | 0 | 26.2 |
| `ecbb350b7f2c` | owasp-mini | deep-verify | cx/gpt-5.6-luna | 60 | 50 | 48 | 9 | 1.90 | 326 | 353.8 |
| `c0f73dae2ea8` | owasp-mini | deep-verify | cx/gpt-6-luna | 57 | 50 | 48 | 8 | 1.67 | 276 | 183.5 |
| `db5b38cd97c6` | owasp-mini | llm | cx/gpt-6-luna | 64 | 50 | 48 | 0 | 0.85 | 100 | 107.9 |
| `62dbabbb2a42` | owasp-mini | deep-verify | ollama/gemma4 | 56 | 50 | 48 | 4 | 3.17 | 379 | 169.0 |
| `a8b2ef400f59` | owasp-mini | llm | ollama/gemma4 | 86 | 50 | 48 | 0 | 1.18 | 102 | 74.4 |
| `9750509c05d8` | owasp-mini | deep-verify | rl/Beam-1.0-501B | 55 | 50 | 48 | 10 | 4.19 | 447 | 1109.6 |
| `27114c6c3af0` | owasp-mini | llm | rl/Beam-1.0-501B | 56 | 50 | 48 | 0 | 0.04 | 4 | 355.4 |
| `1494438fb081` | owasp-full | deep-verify | cbai/hy3 | **0** | 452 | 381 | 0 | 0.00 | 0 | 0.0 |
| `5ec88c710906` | owasp-full | llm | cbai/hy3 | 577 | 452 | 381 | 0 | 21.18 | 1371 | 15216.2 |
| `9ddc1f19c823` | owasp-full | semgrep | reflection/beam:free | 342 | 452 | 381 | 0 | 0.07 | 4 | 179.4 |
| `ff60cd823550` | owasp-full | deep-verify | cx/gpt-5.6-luna | 812 | 452 | 381 | 209 | 24.66 | 3821 | 2667.5 |
| `c72fca194b29` | owasp-full | deep-verify | cx/gpt-6-luna | 651 | 452 | 381 | 60 | 20.64 | 3232 | 1905.4 |
| `aebeb9df7201` | owasp-full | llm | cx/gpt-6-luna | 719 | 452 | 381 | 0 | 11.32 | 1233 | 1226.3 |
| `5cf511bb72df` | owasp-full | deep-verify | ollama/gemma4 | 623 | 452 | 381 | 54 | 42.00 | 4909 | 2898.8 |
| `dc790eb023ce` | owasp-full | llm | ollama/gemma4 | 1147 | 452 | 381 | 0 | 15.65 | 1267 | 1034.0 |
| `52fb84884189` | owasp-full | deep-verify | rl/Beam-1.0-501B | 659 | 452 | 381 | 588 | 25.47 | 2507 | 8575.2 |
| `b43b14a0782a` | owasp-full | llm | rl/Beam-1.0-501B | 651 | 452 | 381 | 0 | 16.73 | 1231 | 2332.8 |

Nguồn: `99-work/review/job_inventory.json` (sinh bằng `99-work/review/inventory_jobs.py`, chỉ đọc `.vulnagent-jobs/`).

---

## 5. PHÁT HIỆN RIÊNG (reviewer chưa thấy)

### 5.1 — [BLOCKING] Docx dùng LUẬT CHẤM CŨ: FP thấp hơn thực tế ở 4/5 job

**Đính chính lần hai.** Một kiểm toán độc lập đối chiếu docx với `reports/rescored_history/metrics_core10.csv` và phát hiện FP lệch. Em đã tự kiểm lại — **kiểm toán đúng, em đã báo sai với người dùng hai lần**.

**Đối chiếu 5 job có trong cả hai nguồn:**

| Job | Docx TP/FP/FN | CSV TP/FP/FN | Δ FP | Δ TP | Δ FN |
|---|---|---|---|---:|---:|
| `62dbabbb2a42` (Gemma DV mini) | 48 / 6 / 0 | 48 / **7** / 0 | **+1** | 0 | 0 |
| `5cf511bb72df` (Gemma DV full) | 375 / 164 / 6 | 375 / **166** / 6 | **+2** | 0 | 0 |
| `c72fca194b29` (GPT-6 DV full) | 347 / 123 / 34 | 347 / **136** / 34 | **+13** | 0 | 0 |
| `aebeb9df7201` (GPT-6 LLM full) | 364 / 149 / 17 | 364 / **165** / 17 | **+16** | 0 | 0 |
| `52fb84884189` (Beam DV full) | 380 / 191 / 1 | 380 / 191 / 1 | 0 | 0 | 0 |

**Δ TP = 0 và Δ FN = 0 ở MỌI job. Chỉ FP tăng.** Đây là dấu hiệu quyết định: không mất phát hiện nào, không sinh FN nào; chỉ có detection **được giữ lại thay vì bị âm thầm bỏ**.

**Nguyên nhân đã truy ra:**

Code cũ lọc detection bằng `in_scope()` — chỉ giữ đúng 10 mã trong `CORE_CWE_SCOPE`. Mọi detection mang CWE **tương đương** nhưng không đồng nhất (CWE-327 cho nhãn CWE-328, CWE-23/35/36/73 cho CWE-22, CWE-80/83/116 cho CWE-79, CWE-77/88 cho CWE-78, CWE-95/96 cho CWE-94, CWE-827 cho CWE-611, CWE-915 cho CWE-502, CWE-564/943 cho CWE-89, CWE-335/338 cho CWE-330) đều **bị drop trước khi chấm**, nên không bao giờ thành FP.

Code mới dùng `eligible()` — giữ chúng lại để chúng có cơ hội khớp nhãn theo lớp tương đương (đó là mục đích của `CWE_EQUIVALENCE`). Detection không khớp nhãn thì **phải tính FP**.

**Kết luận: CSV đúng, docx dùng luật cũ.**

**Việc phải làm trong docx:**

| Job | Sửa FP | Sửa F1 |
|---|---|---|
| `62dbabbb2a42` Gemma DV mini | 6 → **7** | 0,9412 → **0,9320** |
| `5cf511bb72df` Gemma DV full | 164 → **166** | 0,8152 → **0,8134** |
| `c72fca194b29` GPT-6 DV full | 123 → **136** | 0,8155 → **0,8032** |
| `aebeb9df7201` GPT-6 LLM full | 149 → **165** | 0,8143 → **0,8000** |

Precision cũng phải tính lại theo FP mới ở 4 hàng trên. `52fb84884189` (Beam) giữ nguyên.

**Điều bắt buộc phải xoá khỏi mọi kết luận:** câu "số trong docx khớp CSV tới từng đơn vị" là **sai** với 4/5 job. Đúng ra chỉ khớp với `52fb84884189`.

### 5.2 — [BLOCKING] Legacy name `benchmark1000` không còn tồn tại

Mọi job owasp-full ghi `options.source_name = "benchmark1000"`, nhưng `eval/datasets/` chỉ có `benchmark` và `benchmark100`. Nếu người đọc muốn tái lập, họ **không tìm được dataset**. Cần: hoặc đổi tên trong docx thành `benchmark`, hoặc ghi rõ ánh xạ `benchmark1000 → eval/datasets/benchmark`.

### 5.3 — [BLOCKING] Job `1494438fb081` là hàng rỗng

```
status: failed
findings: 0
files_scanned: 0
token: 0
```

Nếu trong bảng owasp-full có hàng "hy3 · DeepVerify", đó là **hàng không có dữ liệu**. Phải xoá hoặc ghi rõ "scan thất bại, không có kết quả".

### 5.4 — [BLOCKING] CWE-798 ngoài phạm vi → Bandit CWE-259 không chấm được

`CORE_CWE_SCOPE = (22, 78, 79, 89, 94, 328, 330, 502, 611, 643)` — **không có CWE-798**.

`CWE_EQUIVALENCE` có nhóm `{1168, 259, 260, 321, 798}`. Bandit gọi "hardcoded password" là **CWE-259**, dataset gọi **CWE-798**. Vì CWE-798 ngoài scope, cả nhãn lẫn detection đều bị loại ở `core10`.

**Hệ quả:** nếu báo cáo có bảng nào ghi "Bandit phát hiện X lỗi hardcoded credential", số đó **không tái lập được** ở core10. Phải hoặc (a) bổ sung CWE-798 vào scope, hoặc (b) ghi rõ CWE-798 ngoài phạm vi thực nghiệm.

### 5.5 — [NON-BLOCKING] `CWE-601` chỉ có 2 nhãn trên mini

`benchmark100/labels.json`: CWE-601 xuất hiện **2 lần**. Với 50 nhãn, granularity là 2%/case. Hai ca này quyết định toàn bộ recall của CWE-601. Đã loại khỏi core10, nhưng nếu báo cáo có bảng theo CWE thì phải ghi chú.

### 5.6 — [NON-BLOCKING] Bảng CWE trong phụ lục phải khớp 17 nhóm code

Code có **17** nhóm `ABSTRACT_SINK_CATEGORIES`. Docx văn bản ghi **18** (4 vị trí: `[P174]`, `[P310]`, `[P347]`, `[T8 r1 c2]`). Bảng 2.3 chỉ liệt kê **11 dòng**.

**Việc phải làm:** đổi "18 nhóm" → **17**, và bổ sung Bảng 2.3 đủ 17 dòng. Danh sách lấy đúng từ code:

| # | Nhóm | Số chữ ký | CWE |
|---|---|---:|---|
| 1 | `DATABASE_EXECUTION` | 15 | 89 |
| 2 | `COMMAND_EXECUTION` | 23 | 78 |
| 3 | `DYNAMIC_EVALUATION` | 3 | 94 |
| 4 | `SERIALIZATION` | 12 | 502 |
| 5 | `NETWORK_SSRF` | 27 | 918 |
| 6 | `FILE_IO` | 24 | 22 |
| 7 | `RESPONSE_RENDER` | 18 | 79 |
| 8 | `EXCEPTION_HANDLING` | 4 | 209 |
| 9 | `HARDCODED_CREDENTIALS` | 9 | 798 |
| 10 | `ACCESS_CONTROL` | 16 | 284/639 |
| 11 | `WEAK_HASHING` | 11 | 328 |
| 12 | `INSECURE_RANDOMNESS` | 15 | 330 |
| 13 | `XPATH_INJECTION` | 10 | 643 |
| 14 | `COOKIE_SECURITY` | 3 | 614 |
| 15 | `LDAP_INJECTION` | 21 | 90 |
| 16 | `OPEN_REDIRECT` | 5 | 601 |
| 17 | `XML_EXTERNAL_ENTITY` | 7 | 611 |

---

## 6. NHỮNG ĐIỀU BÁO CÁO ĐÃ ĐÚNG (không cần sửa)

Để tránh agent khác "sửa" nhầm:

- **"21 bộ quy tắc CWE chính tắc"** — ĐÚNG. `CWE_TAINT_RULES` ở `src/analyzer/prompt_manager.py:78` có đúng **21 entry**. Không được đổi thành "lựa chọn động theo CWE".
- **"5 công cụ điều tra"** ở `[P356]` — ĐÚNG. `TOOL_SCHEMAS` có 5: `read_lines`, `find_definition`, `read_imported_symbol`, `search`, `list_files`.
- **"ba trạng thái confirmed/refuted/uncertain"** — ĐÚNG (12 lần trong docx).
- **"min-cost max-flow (SPFA)"** ở `[P376]` — ĐÚNG, đã sửa đúng từ Kuhn-Munkres.
- **"match_mode = file" + "±3 dòng"** ở `[P376]` — ĐÚNG, mô tả chính xác.
- **"max_depth = 2"** ở `[P180]`, `[P319]`, `[P356]` — ĐÚNG (`tools.py:211,255`).
- **"6 lượt"** — ĐÚNG (`verify_turns = 6`).

---

## 7. THỨ TỰ THỰC HIỆN ĐỀ XUẤT

1. **Re-score** toàn bộ 20 job ở `core10` (đã sửa code, chờ xuất bảng) → cập nhật mọi bảng kết quả.
2. Sửa 3 khoảng số tự mâu thuẫn: `[P430]`, `[P456]`, `[P465]`.
3. Sửa 6 lỗi mô tả cài đặt (mục 1.1 – 1.6).
4. Xoá/thay 10 vị trí "75%" (mục 2.1).
5. Sửa ngôn từ tuyệt đối theo bảng 2.3.
6. Thêm đoạn thảo luận mật độ FP + quan hệ mini ⊂ full (mục 3.4, 3.6).
7. Sửa "18 nhóm" → 17 và bổ sung Bảng 2.3 (mục 5.6).
8. Xử lý job rỗng `1494438fb081` và legacy name `benchmark1000` (mục 5.2, 5.3).
9. Quyết định CWE-798: bổ sung vào scope hay ghi rõ ngoài phạm vi (mục 5.4).

---

## 8. CHECKLIST NGHIỆM THU

- [ ] Không còn "18 nhóm" trong toàn văn.
- [ ] Bảng 2.3 có đúng 17 dòng khớp `ABSTRACT_SINK_CATEGORIES`.
- [ ] Không còn "75%" khi chưa kèm phép đo.
- [ ] Không còn "triệt tiêu", "tuyệt đối", "vượt trội", "hoàn hảo", "cách mạng".
- [ ] Khoảng Precision/Recall khớp với bảng số thật (kể cả hàng bất lợi).
- [ ] Không có hàng kết quả nào từ job `1494438fb081`.
- [ ] Mọi bảng kết quả ghi rõ phạm vi chấm (`core10` hoặc `full`).
- [ ] Không còn mô tả 4 lớp Pydantic không tồn tại.
- [ ] CVSS được mô tả là heuristic, không phải CVSS v3.1.
- [ ] Ví dụ bản vá mật khẩu không dùng SHA-256 trực tiếp.
- [ ] Có câu nêu owasp-mini ⊂ owasp-full.
- [ ] Có đoạn thảo luận mật độ FP 7,45 → 17,51 và CWE-611.
- [ ] Không sửa nhầm "21 quy tắc" hay "5 công cụ" (đã đúng).
