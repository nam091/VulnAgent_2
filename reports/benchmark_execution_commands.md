# CẨM NANG TOÀN BỘ CÂU LỆNH THỰC THI BENCHMARK & DEMO VULNAGENT
## HƯỚNG DẪN TÁI HIỆN (REPRODUCIBILITY GUIDE) DÀNH CHO BẢO VỆ ĐỒ ÁN TỐT NGHIỆP

**Đề tài**: NGHIÊN CỨU ỨNG DỤNG LLM TRONG PHÂN TÍCH LỖ HỔNG AN TOÀN MÃ NGUỒN  
**Hệ thống thực nghiệm**: VulnAgent (Asymmetric 3-Tier Architecture)  
**Tác giả**: Nhóm nghiên cứu đồ án tốt nghiệp  
**Ngày cập nhật**: 2026-10-23  

---

## 1. THIẾT LẬP MÔI TRƯỜNG TRƯỚC KHI CHẠY (PREREQUISITES)

### 1.1. Khởi động 9Router Gateway
Đảm bảo tiến trình 9Router đang chạy ngầm trên máy cục bộ tại cổng `20128`:
```bash
# Kiểm tra cổng 20128 có phản hồi HTTP 200 hay không
curl -s http://127.0.0.1:20128/v1/models | head -c 100
```

### 1.2. Cấu hình biến môi trường `.env`
Tệp `.env` tại thư mục gốc của dự án `VulnAgent/` phải được cấu hình chuẩn:
```ini
# Cấu hình 9Router OpenAI-compatible API
OPENAI_API_KEY=sk-d8d38c4dbe7182c6-5wpch9-c84f2f0a
OPENAI_BASE_URL=http://127.0.0.1:20128/v1

# Mô hình mặc định (chọn 1 trong các mô hình khả quan đã kiểm chứng):
# 1. cmc/reflection/beam:free (Hoàn toàn miễn phí, 0% safety block, chạy mượt mà)
# 2. cx/gpt-5.6-luna (Frontier Cloud, Recall 55.6%, thông minh nhất)
# 3. mistral/codestral-latest (Chuyên gia Code châu Âu, tốc độ 2.5s)
# 4. ollama/gpt-oss:120b (Mô hình mã nguồn mở 120 tỷ tham số)
OPENAI_MODEL=cmc/reflection/beam:free
```

---

## 2. KỊCH BẢN 1: BỘ 6 REPOSITORIES THỰC TẾ (10 NHÓM CWE - RECALL 100%)
*Phạm vi: 16 tệp mã nguồn chuẩn hóa từ 6 repo lớn (`Apache Airflow`, `SaltStack Salt`, `Gradio`, `Django`, `Ansible`, `WeasyPrint`)*  
*Thư mục dữ liệu: `eval/datasets/six_repos/`*  
*Thư mục kết quả: `reports/six_repos_experiment/`*

### 2.1. Lệnh kiểm tra tính toàn vẹn bộ dữ liệu
```bash
# Xác thực 16 tệp tồn tại, đúng cú pháp AST Python và không có dữ liệu Saleor
python eval/datasets/six_repos/verify_dataset.py
```

### 2.2. Chạy Cấu hình 1: Semgrep thuần (SAST Baseline)
```bash
python eval/run_eval.py \
  --only semgrep \
  --dataset eval/datasets/six_repos \
  --json reports/six_repos_experiment/semgrep.json \
  --no-bandit \
  --cold
```
*Kết quả kỳ vọng*: TP=1/10 (10.0%), FP=7, FN=9, Thời gian: ~5.2s.

### 2.3. Chạy Cấu hình 2: LLM thuần (`cmc/reflection/beam:free`)
```bash
python eval/run_eval.py \
  --only llm \
  --dataset eval/datasets/six_repos \
  --json reports/six_repos_experiment/llm.json \
  --no-bandit \
  --cold \
  -j 8
```
*Kết quả kỳ vọng*: TP=10/10 (100.0%), FP=68, FN=0, Thời gian: ~117.5s.

### 2.4. Chạy Cấu hình 3: VulnAgent Hybrid cũ (Đồng thuận 2-Tier)
```bash
python eval/run_eval.py \
  --only hybrid \
  --dataset eval/datasets/six_repos \
  --json reports/six_repos_experiment/hybrid.json \
  --no-bandit \
  --cold \
  -j 8
```
*Kết quả kỳ vọng*: TP=6/10 (60.0%), FP=17, FN=4, Thời gian: ~214.5s.

### 2.5. Chạy Cấu hình 4: VulnAgent 3-Tier Full (Phương án 2 mới)
```bash
python eval/run_eval.py \
  --only 3tier \
  --dataset eval/datasets/six_repos \
  --json reports/six_repos_experiment/3tier.json \
  --no-bandit \
  --cold \
  -j 4
```
*Kết quả kỳ vọng*: **TP=10/10 (100.0% Recall)**, FP=52 (cắt giảm FP mạnh, FP trên file sạch giảm 76% từ 21 xuống 5), FN=0, Thời gian: ~182.4s.

---

## 3. KỊCH BẢN 2: BỘ DOANH NGHIỆP APACHE SUPERSET 2.0.1 (10 NHÓM CWE)
*Phạm vi: 15 tệp mã nguồn từ Apache Superset 2.0.1 (10 CVEs + 5 clean files)*  
*Thư mục dữ liệu: `eval/datasets/superset/`*  
*Thư mục kết quả: `reports/superset_experiment/`*

### 3.1. Chạy Semgrep thuần trên Superset
```bash
python eval/run_eval.py \
  --only semgrep \
  --dataset eval/datasets/superset \
  --json reports/superset_experiment/semgrep.json \
  --no-bandit \
  --cold
```

### 3.2. Chạy LLM thuần trên Superset
```bash
python eval/run_eval.py \
  --only llm \
  --dataset eval/datasets/superset \
  --json reports/superset_experiment/llm.json \
  --no-bandit \
  --cold \
  -j 8
```

### 3.3. Chạy VulnAgent Hybrid cũ trên Superset
```bash
python eval/run_eval.py \
  --only hybrid \
  --dataset eval/datasets/superset \
  --json reports/superset_experiment/hybrid.json \
  --no-bandit \
  --cold \
  -j 8
```

### 3.4. Chạy VulnAgent 3-Tier Full trên Superset
```bash
python eval/run_eval.py \
  --only 3tier \
  --dataset eval/datasets/superset \
  --json reports/superset_experiment/3tier.json \
  --no-bandit \
  --cold \
  -j 4
```

---

## 4. KỊCH BẢN 3: BỘ CHUẨN QUỐC TẾ OWASP BENCHMARK PYTHON (PILOT 50)
*Phạm vi: 50 tệp chuẩn hóa (25 vulnerable + 25 clean control)*  
*Thư mục dữ liệu: `eval/datasets/pilot50/`*  
*Thư mục kết quả: `reports/multi_codebase_benchmark/`*

### 4.1. Lệnh sinh tự động bộ phân tầng Pilot 50 (nếu cần tạo mới)
```bash
python eval/prepare_pilot.py
```

### 4.2. Chạy Semgrep thuần trên 50 file Pilot 50
```bash
python eval/run_eval.py \
  --only semgrep \
  --dataset eval/datasets/pilot50 \
  --json reports/multi_codebase_benchmark/pilot50_semgrep.json \
  --no-bandit \
  --cold
```

### 4.3. Chạy VulnAgent 3-Tier Full trên 50 file Pilot 50
```bash
python eval/run_eval.py \
  --only 3tier \
  --dataset eval/datasets/pilot50 \
  --json reports/multi_codebase_benchmark/pilot50_3tier.json \
  --no-bandit \
  --cold \
  -j 8
```
*Kết quả ghi nhận*: **Bắt trúng 24/25 True Positives (Recall 96.0%, F1-Score 0.7500)**.

---

## 5. KỊCH BẢN 4: SO SÁNH ĐỐI ĐẦU ĐA MÔ HÌNH AI (BENCHMARK RUNNER)
*Script đo lường chi tiết Latency, Tokens, và hiện tượng Safety Filter Block*  
*Thư mục kết quả: `reports/model_comparison/`*

### 5.1. Chạy đo đạc đồng thời các mô hình Frontier và Open-Source
```bash
# Đo đạc 4 mô hình: GPT-5.6-Luna, Codestral, GPT-OSS 120B, Gemma 4
python eval/run_model_comparison.py \
  --models cx/gpt-5.6-luna mistral/codestral-latest ollama/gpt-oss:120b ollama/gemma4 \
  --concurrency 2
```

### 5.2. Chạy đo đạc dòng Google Gemini để ghi nhận hiện tượng Safety Filter Block
```bash
python eval/run_model_comparison.py \
  --models ag/gemini-3.8-flash-low ag/gemini-3.8-flash-medium ag/gemini-3.8-flash-high \
  --concurrency 1
```

### 5.3. Tự động tổng hợp dữ liệu ra bảng CSV
```bash
python eval/run_model_comparison.py --summary-only
```
*Tệp kết quả*: `reports/model_comparison/models_metrics_summary.csv`.

---

## 6. KỊCH BẢN 5: TRÌNH DIỄN TRỰC TIẾP TỪNG TỆP QUA CLI (LIVE DEFENSE DEMO)
*Dành riêng cho lúc đứng thuyết trình trước Hội đồng, muốn chiếu terminal quét trực tiếp 1 file*

### 6.1. Quét tệp Django dính SQL Injection (CVE-2022-34265)
```bash
python -m src.cli scan \
  --file eval/datasets/six_repos/samples/django_sqli.py \
  --output reports/live_demo_django.json
```

### 6.2. Quét tệp Apache Airflow dính Path Traversal (CVE-2023-22887) kèm Verifier
```bash
python -m src.cli scan \
  --file eval/datasets/six_repos/samples/airflow_pathtraversal.py \
  --verify \
  --output reports/live_demo_airflow.json
```

### 6.3. Quét tệp SaltStack dính Command Injection (CVE-2020-16846)
```bash
python -m src.cli scan \
  --file eval/datasets/six_repos/samples/salt_cmdi.py \
  --verify \
  --output reports/live_demo_salt.json
```

### 6.4. Quét tệp demo tổng hợp `vulnerable_app.py`
```bash
python -m src.cli scan \
  --file examples/vulnerable_app.py \
  --verify
```

---

## 7. GIẢI THÍCH CHI TIẾT Ý NGHĨA CÁC THAM SỐ DÒNG LỆNH

| Tham số CLI | Ý nghĩa Kỹ thuật & Bối cảnh Nghiên cứu |
| :--- | :--- |
| **`--only <config>`** | Chỉ định duy nhất 1 cấu hình kiến trúc (`semgrep`, `llm`, `hybrid`, `ast`, `3tier`) để cô lập biến số thực nghiệm. |
| **`--dataset <path>`** | Đường dẫn tới thư mục bộ dữ liệu (bắt buộc chứa thư mục con `samples/` và tệp nhãn ground-truth `labels.json`). |
| **`--json <path>`** | Xuất kết quả thô máy đọc kèm đầy đủ mảng findings, timestamps, latency từng tệp tin và thông số coverage. |
| **`--no-bandit`** | Bỏ qua scanner phụ Bandit để giữ bảng kết quả tinh gọn, tập trung so sánh giữa Semgrep và các tầng của VulnAgent. |
| **`--cold`** | **Cờ bắt buộc trong nghiên cứu khoa học**: Vô hiệu hóa toàn bộ cache nội dung, ép hệ thống phải phân tích thật và đo lường latency thời gian thực. |
| **`-j <N>`** | Số luồng xử lý đồng thời (Concurrency). Đặt `-j 4` hoặc `-j 8` cho các mô hình nhanh (`beam:free`, `luna`, `gemma4`), đặt `-j 1` cho các mô hình suy luận sâu. |
| **`--verify`** | Bật Tầng 3 (Adversarial Verification Agent) khi quét đơn lẻ qua CLI để thẩm tra phản biện và loại bỏ False Positives. |

---

## 8. HỆ THỐNG FILE BÁO CÁO & KHO ARTIFACT LIÊN QUAN

Sau khi chạy xong các lệnh trên, toàn bộ kết quả đã được tự động lưu trữ ngăn nắp tại các đường dẫn sau:

1. **Bộ 6 Repositories Thực tế (Recall 100%)**:
   - 📊 Bảng tổng hợp số liệu CSV: `reports/six_repos_experiment/metrics_summary.csv`
   - 📊 Tiến trình vòng lặp tinh chỉnh CSV: `reports/six_repos_experiment/iteration_progress.csv`
   - 📝 Báo cáo khoa học phân tích chuyên sâu Markdown: `reports/six_repos_experiment/six_repos_comparative_analysis.md`
   - 📁 4 tệp JSON thô: `reports/six_repos_experiment/{semgrep,llm,hybrid,3tier}.json`
2. **Bộ Apache Superset 2.0.1**:
   - 📊 Bảng tổng hợp số liệu CSV: `reports/superset_experiment/metrics_summary_latest.csv`
   - 📝 Báo cáo phân tích chuyên sâu Markdown: `reports/superset_experiment/superset_comparative_analysis.md`
   - 📁 4 tệp JSON thô: `reports/superset_experiment/{semgrep,llm,hybrid,3tier}.json`
3. **Bộ So sánh Đối đầu Đa Mô hình AI**:
   - 📊 Bảng tổng hợp 7 mô hình CSV: `reports/model_comparison/models_metrics_summary.csv`
   - 📝 Báo cáo phân tích chuyên sâu Markdown: `reports/model_comparison_benchmark.md`
   - 📁 7 tệp JSON thô chi tiết: `reports/model_comparison/*.json`
