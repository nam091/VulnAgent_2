# Kịch Bản Trình Diễn (Demo), Thực Nghiệm Khoa Học & Kiểm Thử Đồ Án Tốt Nghiệp

**Đề tài:** Nghiên cứu ứng dụng LLM trong phân tích lỗ hổng an toàn mã nguồn  
**Sản phẩm:** Hệ thống phân tích lai VulnAgent (Hybrid SAST + LLM)  
**Tác giả:** Lã Phương Nam — Lớp AT19E  
**Mục tiêu tài liệu:** Cung cấp kịch bản chi tiết từng phút, câu thoại thuyết trình, các lệnh thực thi thực tế, cách bố trí màn hình và bộ câu hỏi phản biện để bảo vệ đồ án tốt nghiệp đạt kết quả xuất sắc nhất trước Hội đồng chấm thi.

---

## MỤC LỤC
1. [Chiến Lược Thuyết Trình & Phân Bổ Thời Gian](#1-chiến-lược-thuyết-trình--phân-bổ-thời-gian)
2. [Thiết Lập Môi Trường Trước Buổi Báo Cáo](#2-thiết-lập-môi-trường-trước-buổi-báo-cáo)
3. [Kịch Bản 4 Màn Trình Diễn Live Demo (Trực Quan)](#3-kịch-bản-4-màn-trình-diễn-live-demo-trực-quan)
   - [Màn 1: Vibe Coding với MCP Server (Tích hợp AI Agent)](#màn-1-vibe-coding-với-mcp-server-tích-hợp-ai-agent)
   - [Màn 2: Editor On-Save Hook & Kiểm Soát Tương Tranh](#màn-2-editor-on-save-hook--kiểm-soát-tương-tranh)
   - [Màn 3: Adversarial Verifier Đánh Bại Cảnh Báo Sai (False Positive)](#màn-3-adversarial-verifier-đánh-bại-cảnh-báo-sai-false-positive)
   - [Màn 4: Thất Bại Có Kiểm Soát (Controlled Degradation)](#màn-4-thất-bại-có-kiểm-soát-controlled-degradation)
4. [Kịch Bản Thực Nghiệm Khoa Học Lấy Số Liệu Báo Cáo (Evaluation)](#4-kịch-bản-thực-nghiệm-khoa-học-lấy-số-liệu-báo-cáo-evaluation)
   - [Thực nghiệm 1: So sánh hiệu năng 4 cấu hình detector](#thực-nghiệm-1-so-sánh-hiệu-năng-4-cấu-hình-detector)
   - [Thực nghiệm 2: Đo lường hiệu quả Content-Hash Cache](#thực-nghiệm-2-đo-lường-hiệu-quả-content-hash-cache)
   - [Thực nghiệm 3: Kiểm chứng cổng toàn vẹn Benchmark Integrity Gate](#thực-nghiệm-3-kiểm-chứng-cổng-toàn-vẹn-benchmark-integrity-gate)
5. [Kịch Bản Kiểm Thử Kỹ Thuật DevSecOps & CI/CD Gate](#5-kịch-bản-kiểm-thử-kỹ-thuật-devsecops--cicd-gate)
   - [Kỹ thuật 1: Quản lý nợ kỹ thuật bằng Baseline](#kỹ-thuật-1-quản-lý-nợ-kỹ-thuật-bằng-baseline)
   - [Kỹ thuật 2: Xuất chuẩn SARIF cho GitHub Security](#kỹ-thuật-2-xuất-chuẩn-sarif-cho-github-security)
   - [Kỹ thuật 3: Tự động hoàn tác khi vá lỗi thất bại (Verify Rollback)](#kỹ-thuật-3-tự-động-hoàn-tác-khi-vá-lỗi-thất-bại-verify-rollback)
6. [Bộ Câu Hỏi Phản Biện Của Hội Đồng & Hướng Dẫn Trả Lời](#6-bộ-câu-hỏi-phản-biện-của-hội-đồng--hướng-dẫn-trả-lời)

---

## 1. Chiến Lược Thuyết Trình & Phân Bổ Thời Gian

Thời lượng bảo vệ đồ án chuẩn thường kéo dài **15 – 20 phút** trình bày + **10 phút** hỏi đáp phản biện. Hãy phân bổ cấu trúc bài nói như sau:

| Thời lượng | Nội dung trọng tâm | Điểm nhấn cần ghi điểm với Hội đồng |
| :---: | :--- | :--- |
| **00:00 – 03:00** | **Đặt vấn đề & Thực trạng** | Làn sóng AI sinh code (Vibe Coding) bùng nổ kéo theo hàng loạt lỗ hổng bảo mật. Scanner truyền thống (SAST) quá nhiều False Positive, LLM đơn lẻ thì bị ảo giác và thiếu kiểm chứng. |
| **03:00 – 07:00** | **Đóng góp học thuật & Kiến trúc** | Không "lấy hợp" (union) hai engine mà dùng **sự đồng thuận độc lập (Corroboration)** làm tín hiệu xếp hạng. Tư duy **Adversarial Verification** bắt buộc có bằng chứng chuỗi taint path. |
| **07:00 – 14:00** | **LIVE DEMO (Trực tiếp)** | Chạy 4 màn demo trực quan: MCP Server, On-Save Hook tương tranh, Verifier loại False Positive, và Thất bại có kiểm soát. |
| **14:00 – 17:00** | **Kết quả thực nghiệm khoa học** | Trình chiếu bảng đối sánh F1, Precision 1.000 trên cấu hình `--confirmed-only`, đo đạc tốc độ Cache và chứng minh cổng Benchmark Integrity Gate. |
| **17:00 – 18:00** | **Kết luận & Hướng phát triển** | Tóm lược đóng góp thực tế, thừa nhận giới hạn (Python-only, single-file) và vạch rõ lộ trình mở rộng. |

---

## 2. Thiết Lập Môi Trường Trước Buổi Báo Cáo

Chuẩn bị sẵn môi trường trên laptop trước khi bước lên bục bảo vệ:

1. **Terminal 1 (Chính):** Mở sẵn tại thư mục gốc `F:\PERSIONAL\Projects\VulnAgent`, đã kích hoạt venv.
2. **Terminal 2 (Phụ / Monitor):** Dùng để theo dõi log hoặc chạy web UI server.
3. **Editor:** Mở VS Code hoặc Cursor với workspace trỏ vào repo `VulnAgent`.
4. **Kiểm tra nhanh trước giờ G:**
   ```bash
   vulnagent doctor
   ```
   Đảm bảo toàn bộ các mục đều báo `[OK]`, bao gồm cả `MCP handshake smoke test passed (mode: editor, tools: 12)`.

---

## 3. Kịch Bản 4 Màn Trình Diễn Live Demo (Trực Quan)

### Màn 1: Vibe Coding với MCP Server (Tích hợp AI Agent)
- **Ý nghĩa:** Trình diễn cách AI Coding Agent (Cursor / Claude Code) tự động gọi VulnAgent để tự kiểm tra và vá lỗi ngay trong bộ nhớ trước khi giao code cho người dùng.
- **Cách thức thực hiện:** Chạy client mô phỏng AI Agent giao tiếp qua chuẩn JSON-RPC stdio.

**Thao tác lệnh:**
```bash
python examples/test_mcp_client.py
```

**Lời thoại thuyết trình (Script nói):**
> *"Kính thưa Thầy/Cô, đây là trải nghiệm thực tế khi một AI Agent viết mã. Khi Agent sinh ra đoạn code có chứa lệnh `subprocess.call` với tham số người dùng nhập, thay vì lưu ngay xuống đĩa, Agent gọi công cụ `scan_code` của VulnAgent qua giao thức MCP.  
> Ngay lập tức, VulnAgent phân tích trong bộ nhớ, trả về cảnh báo `CRITICAL OS_COMMAND_INJECTION` kèm khuyến nghị sửa `shell=False`. Nhờ đó, AI Agent có thể tự phát hiện và tự sửa lỗi trước khi lập trình viên kịp nhìn thấy đoạn code bị lỗi."*

**Điểm nhấn kỹ thuật:**
- Không ghi file đè bừa bãi, dùng tempfile cô lập chống Path Traversal.
- Cung cấp trọn vẹn 12 công cụ MCP chuẩn hóa.

---

### Màn 2: Editor On-Save Hook & Kiểm Soát Tương Tranh
- **Ý nghĩa:** Chứng minh VulnAgent bảo vệ lập trình viên thao tác tay trong VS Code / Cursor mà không gây nghẽn CPU hoặc đơ máy.
- **Cách thức thực hiện:** Khởi tạo hook và kiểm tra cơ chế chống đơ máy.

**Thao tác lệnh:**
```bash
# 1. Khởi tạo cấu hình cho workspace (chuẩn lệnh CLI)
vulnagent init --host vscode --rules "rules/pinned_security_rules.yaml"

# 2. Xem cấu hình on-save tự động sinh trong .vscode/settings.json
cat .vscode/settings.json
```

**Kịch bản thao tác thực tế trên VS Code:**
1. Mở file `examples/vulnerable_app.py`.
2. Gõ vài ký tự và bấm `Ctrl + S` liên tục 4–5 lần.
3. Chỉ vào Terminal: Hệ thống **Debounce 1.5 giây**, gom toàn bộ các lần lưu lại và chỉ chạy quét đúng 1 lần duy nhất sau khi ngừng gõ.
4. Bấm `Ctrl + S` lại một lần nữa mà không sửa gì: Hệ thống kiểm tra hash qua `dirty.json` và **bỏ qua ngay lập tức trong 0.01 giây**.

**Lời thoại thuyết trình:**
> *"Các công cụ bảo mật thông thường khi tích hợp On-save thường làm đơ editor nếu người dùng lưu file liên tục. VulnAgent giải quyết triệt để vấn đề này bằng bộ điều phối `EditorHookRunner`: cơ chế Debounce 1.5s gom tiến trình, cơ chế Dirty Snapshotting bỏ qua file chưa đổi nội dung, và khóa `.vulnagent.lock` kiểm tra PID sống đảm bảo không bao giờ có 2 tiến trình scan chạy đè lên nhau."*

---

### Màn 3: Adversarial Verifier Đánh Bại Cảnh Báo Sai (False Positive)
- **Ý nghĩa:** Trình diễn sự khác biệt giữa Scanner truyền thống và VulnAgent. Scanner thông thường chỉ bắt theo keyword/regex sẽ báo động đỏ (False Positive) ngay cả khi code an toàn, trong khi VulnAgent có tầng phân tích cú pháp AST và Agent phản biện để chứng minh an toàn.
- **File mẫu đã chuẩn bị sẵn trong repo:** `examples/safe_demo.py` (sử dụng Parameterized Query chuẩn).

**Thao tác lệnh:**
```bash
vulnagent scan examples/safe_demo.py --no-llm
```

**Kết quả quan sát được:**
```text
VulnAgent  1 file(s) scanned  ·  0 sent to LLM
  No vulnerabilities found.
```

**Lời thoại thuyết trình:**
> *"Thưa Thầy/Cô, trong file `examples/safe_demo.py`, hàm `cursor.execute` được gọi để truy vấn CSDL nhưng lập trình viên đã dùng dấu `?` tham số hóa. Scanner ngây thơ chỉ dựa trên keyword `cursor.execute` sẽ ném cảnh báo sai.  
> Tầng phân tích cú pháp của VulnAgent nhận biết đây là query an toàn và báo sạch (Exit code 0).  
> Đặc biệt, khi kích hoạt chế độ đối kháng (`--verify-findings`), Agent được giao mục tiêu: 'Hãy tìm lý do chứng minh báo cáo này SAI'. Khi không tìm thấy vết bẩn (taint) nối từ input người dùng vào sink thực thi, Agent lập tức bác bỏ và gắn nhãn `refuted`, loại bỏ hoàn toàn các cảnh báo rác làm phiền lập trình viên."*

---

### Màn 4: Thất Bại Có Kiểm Soát (Controlled Degradation)
- **Ý nghĩa:** Chứng minh tính trung thực học thuật của sản phẩm. Khi hệ thống gặp sự cố (mất mạng, engine bị timeout, cú pháp code bị lỗi), VulnAgent **tuyệt đối không bao giờ báo "0 vulnerabilities found - Clean"** mà phải báo rõ `DEGRADED / INCOMPLETE SCAN` và chặn build với **Exit code 2**.
- **File mẫu đã chuẩn bị sẵn trong repo:** `examples/broken_syntax.py` (cố tình sai cú pháp Python).

**Thao tác lệnh:**
```bash
vulnagent scan examples/broken_syntax.py --no-llm
```

**Kết quả quan sát được trên màn hình:**
```text
WARNING Semgrep error: Syntax error at line examples\broken_syntax.py:1: `def calculate_tax(amount: float:` was unexpected
VulnAgent  1 file(s) scanned  ·  0 sent to LLM
  WARNING: Scan completed with degraded or failed tiers. Results may be incomplete.
  No vulnerabilities found.
  gate: failed because one or more analysis tiers degraded/failed
```
*(Exit code trả về là 2 - Báo lỗi hệ thống)*

**Lời thoại thuyết trình:**
> *"Một lỗ hổng chết người của nhiều scanner thương mại là khi gặp file lỗi cú pháp hoặc engine bị crash, nó âm thầm bỏ qua và trả về: '0 lỗ hổng - Code an toàn', khiến lập trình viên tưởng rằng code đã sạch và tự tin đẩy lên production.  
> VulnAgent tuân thủ nghiêm ngặt nguyên tắc 'Evidence-First': Khi engine không thể phân tích trọn vẹn, hệ thống lập tức gắn cờ `DEGRADED`, exit code trả về mã 2 (EXIT_ERROR) và đánh fail gate bảo vệ, từ chối cấp chứng nhận an toàn giả tạo cho bản build."*

---

## 4. Kịch Bản Thực Nghiệm Khoa Học Lấy Số Liệu Báo Cáo (Evaluation)

Để bài báo cáo đồ án có tính thuyết phục cao nhất, Thầy/Cô trong Hội đồng luôn muốn nhìn thấy **bằng chứng đo đạc định lượng (Quantitative Metrics)**.

### Thực nghiệm 1: So sánh hiệu năng các cấu hình detector

Chạy đánh giá trực tiếp trên tập dữ liệu chuẩn hóa của đồ án với 2 chế độ rule:

```bash
# Chế độ 1: Sử dụng bộ rules offline ghim sẵn (rules/pinned_security_rules.yaml)
python eval/run_eval.py --only semgrep --no-bandit --cold

# Chế độ 2: Sử dụng bộ rules đầy đủ từ Semgrep Registry (p/python, p/security-audit)
python eval/run_eval.py --only semgrep --no-bandit --cold --rules "p/python,p/security-audit"

# Chế độ 3: Chạy baseline Bandit để đối chiếu
python eval/run_eval.py --only bandit --cold
```

**Bảng số liệu đối sánh đo đạc thực tế trên tập Calibration Smoke Test (11 nhãn, có đối chứng sạch `safe_handlers.py`):**

| Cấu hình kiểm thử | Bộ Rules | TP (Bắt đúng) | FP (Bắt sai) | FN (Bỏ sót) | Precision | Recall | F1-Score |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| VulnAgent (Hợp cả 2 tier) | Registry + LLM | 11 | 9 | 0 | 0.550 | **1.000** | 0.710 |
| **VulnAgent (Confirmed Only)** | **Registry + LLM** | **8** | **0** | **3** | **1.000** | **0.727** | **0.842** |
| Semgrep (Full Registry) | p/python, p/security-audit | 7 | 3 | 4 | 0.700 | 0.636 | 0.667 |
| Semgrep (Pinned Offline) | pinned_security_rules.yaml | 4 | 0 | 7 | 1.000 | 0.364 | 0.533 |
| Bandit (Baseline truyền thống) | Bandit builtin | 7 | 6 | 4 | 0.538 | 0.636 | 0.583 |

> **Ghi chú minh bạch về nguồn gốc số liệu:**
> - Các dòng *Semgrep (Pinned)*, *Semgrep (Full Registry)*, và *Bandit (Baseline)* được đo lường và kiểm chứng trực tiếp bằng terminal trong môi trường hiện tại (`eval/run_eval.py --cold`).
> - Hai dòng *VulnAgent (Hợp cả 2 tier)* và *VulnAgent (Confirmed Only)* được kế thừa từ lượt chạy hiệu chỉnh đầy đủ khi có kết nối API LLM (đã lưu artifact tại `output/eval_results.json` và `README.md`). Khi bảo vệ trước Hội đồng, nếu có kết nối mạng và API key LLM hợp lệ, bạn có thể tái hiện toàn bộ bảng trên bằng lệnh: `python eval/run_eval.py --cold`.

**Luận điểm phân tích học thuật cần nhấn mạnh:**
1. **Tại sao không lấy phép hợp (Union)?** Vì phép hợp cộng dồn toàn bộ False Positive của cả Semgrep và LLM (FP tăng lên 9), khiến F1 tụt xuống 0.710.
2. **Sự khác biệt giữa 2 bộ Rules Semgrep:** 
   - Bộ *Pinned Offline* (`rules/pinned_security_rules.yaml`) gồm 4 rules tối giản, chạy hoàn toàn không cần internet, bắt chính xác 4 lỗi cơ bản (SQLi, Command, XSS, Path Traversal) với FP=0.
   - Bộ *Full Registry* (`p/python, p/security-audit`) quét sâu hơn (TP=7) nhưng bắt nhầm cả file sạch `safe_handlers.py` (FP=3).
3. **Giá trị cốt lõi của VulnAgent:** Khi lọc theo cấu hình đồng thuận độc lập (**`--confirmed-only`**), hệ thống loại bỏ triệt để các bắt nhầm của Semgrep trên file sạch, đưa **Precision đạt tuyệt đối 1.000 (0 False Positive)** và F1 đạt đỉnh **0.842**, vượt trội hoàn toàn so với từng engine đơn lẻ.

---

### Thực nghiệm 2: Đo lường hiệu quả Content-Hash Cache
Chứng minh khả năng tối ưu hóa chi phí token và tốc độ phản hồi:

```bash
# Lần 1: Chạy Cold (Không dùng cache)
python eval/run_eval.py --only semgrep --no-bandit --cold --json cold.json

# Lần 2: Chạy Warm (Có cache tái sử dụng)
python eval/run_eval.py --only semgrep --no-bandit --json warm.json
```
**Số liệu chứng minh:** Thời gian quét giảm từ **~9 giây** xuống còn **~1–2 giây** khi nội dung file không thay đổi, chứng minh VulnAgent hoàn toàn khả thi để chạy trong môi trường CI/CD hoặc làm linter thời gian thực.

---

### Thực nghiệm 3: Kiểm chứng cổng toàn vẹn Benchmark Integrity Gate
Chứng minh tính minh bạch của kết quả nghiên cứu khoa học:

```bash
python -m pytest tests/test_gates.py -k "test_eval_integrity_gate_detects_" -v
```
**Lời thoại thuyết trình:**
> *"Trong nghiên cứu khoa học, một rủi ro lớn là can thiệp ngầm vào file rules hoặc file nhãn của bộ benchmark để làm đẹp số liệu. VulnAgent tích hợp cơ chế Benchmark Integrity Gate: Snapshot toàn bộ SHA-256 của rules và dataset trước khi quét. Nếu có bất kỳ sự thay đổi hoặc xóa file nào trong quá trình chạy, hệ thống phát hiện ngay lập tức và tuyên bố kết quả thí nghiệm là BẤT HỢP LỆ (Run INVALID). Toàn bộ 4 kịch bản can thiệp (xóa rules, sửa rules, sửa nhãn, sửa code mẫu) đều được kiểm thử tự động đạt 100%."*

---

## 5. Kịch Bản Kiểm Thử Kỹ Thuật DevSecOps & CI/CD Gate

### Kỹ thuật 1: Quản lý nợ kỹ thuật bằng Baseline
Trình diễn kịch bản đưa VulnAgent vào một dự án thực tế đã có sẵn lỗi mà không làm gãy pipeline:

```bash
# Bước 1: Đóng băng toàn bộ lỗ hổng cũ
vulnagent baseline examples/ --no-llm

# Bước 2: Quét lại kiểm tra (loại trừ file lỗi cú pháp broken_syntax.py)
vulnagent scan examples/ --baseline --fail-on-new --no-llm --exclude "broken_syntax.py"
```
**Kết quả hiển thị thực tế:** `0 new, 5 known, 0 resolved (baseline: .vulnagent-baseline.json)`. Exit code = 0 (Build xanh hoàn toàn).

---

### Kỹ thuật 2: Xuất chuẩn SARIF cho GitHub Security
```bash
vulnagent scan examples/vulnerable_app.py --no-llm -f sarif -o output/report.sarif
```
Mở file `output/report.sarif`, chỉ cho Thầy/Cô thấy: Cấu trúc JSON tuân thủ chuẩn quốc tế OASIS SARIF v2.1.0, chứa đầy đủ vị trí dòng, thông tin CWE và đường dẫn sink, sẵn sàng tích hợp vào tab Security của GitHub Actions.

---

### Kỹ thuật 3: Tự động hoàn tác khi vá lỗi thất bại (Verify Rollback)
Trình bày cơ chế bảo vệ mã nguồn khi áp dụng tính năng tự động sửa lỗi:
- Khi chạy `vulnagent fix --verify`:
  1. Bản vá được kiểm tra cú pháp AST (`ast.parse`).
  2. Áp dụng tạm thời vào file và kích hoạt rescan ngầm.
  3. Nếu số lượng lỗi không giảm hoặc làm phát sinh lỗi mới $\rightarrow$ Hệ thống tự động **Rollback** nguyên trạng file ban đầu, bảo vệ an toàn cho hệ thống.

---

## 6. Bộ Câu Hỏi Phản Biện Của Hội Đồng & Hướng Dẫn Trả Lời

Dưới đây là 5 câu hỏi kinh điển mà các Thầy/Cô chuyên gia an toàn thông tin thường đặt ra khi phản biện đồ án ứng dụng AI/LLM:

### ❓ Câu 1: "Tại sao không dùng luôn Semgrep hay SonarQube cho nhanh, việc đưa LLM vào có thực sự cần thiết không?"
> **Trả lời:**  
> *"Dạ thưa Thầy/Cô, các công cụ SAST dựa trên rule như Semgrep hay SonarQube rất mạnh trong việc bắt các mẫu cú pháp cố định tại framework entry points (như Flask request). Tuy nhiên, chúng có 2 điểm yếu chí mạng:  
> 1. Không bắt được các lỗ hổng logic nghiệp vụ không theo mẫu (ví dụ: hardcoded credentials tự chế, logic phân quyền sai, sai lệch thuật toán mã hóa).  
> 2. Nếu một hàm độc lập không có nguồn taint rõ ràng (ví dụ: `def run_task(cmd): os.system(cmd)`), Semgrep sẽ báo sạch (Clean) nhưng LLM nhận diện được ngay đây là hàm nguy hiểm.  
> VulnAgent kết hợp cả hai: Semgrep giữ độ bao phủ và tốc độ, còn LLM phân tích ngữ nghĩa sâu. Đặc biệt, sự đồng thuận giữa 2 tier giúp loại bỏ hoàn toàn các cảnh báo sai mà Semgrep hay mắc phải."*

---

### ❓ Câu 2: "Mô hình ngôn ngữ lớn (LLM) vốn nổi tiếng là hay ảo giác (hallucination), em làm thế nào để đảm bảo kết quả quét của LLM là đáng tin cậy?"
> **Trả lời:**  
> *"Dạ thưa Thầy/Cô, VulnAgent không bao giờ tin tưởng tuyệt đối vào câu trả lời đầu tiên của LLM. Em đã thiết lập 3 chốt chặn bảo vệ:  
> 1. **Cơ chế Corroboration:** Chỉ những lỗi được cả Rule Tier và LLM Tier cùng chỉ ra mới được xếp hạng cao nhất (`CONFIRMED`).  
> 2. **Hợp đồng bằng chứng (Evidence Contract):** Mọi kết luận của LLM bắt buộc phải trích xuất được `taint_path` gồm 4 điểm: Source, Propagator, Sanitizer, Sink gắn liền với dòng code thực tế.  
> 3. **Xác minh đối kháng (Adversarial Verifier):** Agent được lập trình với mục tiêu đối lập là 'tìm lý do chứng minh báo cáo sai' và được cấp tool đọc code thực tế. Nếu không chứng minh được chuỗi dữ liệu bẩn đi vào điểm thực thi nguy hiểm, phát hiện sẽ bị hạ cấp hoặc loại bỏ."*

---

### ❓ Câu 3: "Hệ thống có quét được lỗ hổng xuyên file (Cross-file / Inter-procedural) không?"
> **Trả lời (Thẳng thắn, khoa học):**  
> *"Dạ thưa Thầy/Cô, hiện tại trong phạm vi MVP của đồ án tốt nghiệp, hệ thống tập trung phân tích luồng dữ liệu đơn file (Single-file analysis) kết hợp mở rộng ngữ cảnh hàm thông qua AST (`ast_context.py`).  
> Phân tích taint xuyên file đa tầng là bài toán phức tạp và thường là tính năng tính phí của các enterprise engine lớn (như Semgrep Pro). Đây chính là một trong các giới hạn đã được em ghi nhận rõ ràng trong báo cáo và là mục tiêu phát triển trọng tâm ở giai đoạn tiếp theo thông qua kỹ thuật Lightweight Import Chasing."*

---

### ❓ Câu 4: "Chi phí gọi API của LLM rất đắt và độ trễ cao, làm sao hệ thống đáp ứng được trong môi trường thực tế?"
> **Trả lời:**  
> *"Dạ, em đã giải quyết bài toán chi phí và thời gian bằng 3 giải pháp kiến trúc:  
> 1. **Risk Router:** Không gửi bừa bãi toàn bộ mã nguồn cho LLM. Module `discovery.py` quét nhanh regex rủi ro, chỉ những file có điểm rủi ro $\ge 3$ mới được gửi tới LLM.  
> 2. **Content-Hash Cache:** Hệ thống băm SHA-256 nội dung file. Các file không sửa đổi sẽ được lấy kết quả từ cache trong 0.01 giây mà không tốn một token nào.  
> 3. **Phân tách chế độ Fast và Deep:** Khi lập trình viên đang gõ code, hệ thống chạy chế độ `fast` (chỉ Rule tier, ~2–3 giây). Chỉ khi thực hiện review cuối hoặc chuẩn bị merge code mới kích hoạt chế độ `deep`."*

---

### ❓ Câu 5: "Cơ chế tự động sửa lỗi (Auto-fix) có làm hỏng logic phần mềm của người dùng không?"
> **Trả lời:**  
> *"Dạ, tính năng Auto-fix của VulnAgent được thiết kế theo nguyên lý phòng thủ:  
> 1. Bản vá bắt buộc phải vượt qua bước kiểm tra cú pháp AST (`ast.parse`), nếu lỗi cú pháp sẽ bị hủy ngay.  
> 2. Hệ thống phân loại bản vá: Những bản vá an toàn cục bộ (như đổi `shell=True` thành `False`) mới được gán nhãn `safe`. Các bản vá thay đổi luồng điều khiển được gán nhãn `review` để con người duyệt.  
> 3. Chế độ `--verify` tự động chạy rescan ngầm sau khi vá. Nếu phát hiện số lượng lỗi tăng lên hoặc lỗi cũ chưa hết, hệ thống sẽ tự động hoàn tác (Rollback) file về trạng thái ban đầu."*

---

### ❓ Câu 6: "Tập dữ liệu 11 nhãn có quá nhỏ không? Có ý nghĩa thống kê khoa học không?"
> **Trả lời (Thẳng thắn, chuẩn mực khoa học):**  
> *"Dạ thưa Thầy/Cô, con số 11 nhãn là tập **Calibration Smoke Test** nội bộ nhằm mục đích phát triển và hiệu chỉnh pipeline. Điểm độc đáo của tập này là nó chứa file đối chứng sạch `safe_handlers.py` — nơi toàn bộ các API nguy hiểm đều được sử dụng an toàn. Một bộ dữ liệu chỉ toàn mã độc sẽ không bao giờ đo được độ chính xác (Precision) và khả năng bắt nhầm (False Positive) của LLM.  
> Để kiểm chứng quy mô lớn hơn, đồ án đã tích hợp và xây dựng sẵn bộ chuyển đổi cho benchmark quốc tế **SecurityEval (115 mẫu Python CWE)** qua script `eval/prepare_securityeval.py` và dự án thực tế **OWASP PyGoat** qua `eval/prepare_pygoat.py`."*

---

### ❓ Câu 7: "Nếu đổi mô hình nền tảng (ví dụ: từ GPT-4o sang Claude 3.5 Sonnet hay Gemini 1.5 Pro), kết quả có bị sai lệch không?"
> **Trả lời:**  
> *"Dạ thưa Thầy/Cô, kiến trúc của VulnAgent được thiết kế **Model-Agnostic** (không phụ thuộc vào một vendor độc quyền nào) qua module `ai_client.py`:  
> 1. Toàn bộ prompt đều yêu cầu schema JSON đầu ra nghiêm ngặt.  
> 2. Tầng Rule Tier (Semgrep) luôn đóng vai trò là 'chiếc neo kiểm soát' (Anchor). Kể cả khi LLM thay đổi hành vi suy luận, những lỗ hổng đồng thuận (`CONFIRMED`) vẫn giữ nguyên tính ổn định.  
> 3. Sự khác biệt giữa các model lớn chủ yếu nằm ở số lượng gợi ý đơn nguồn (`llm-only`), và đây chính là lý do cờ `--confirmed-only` được khuyến nghị làm cổng chặn mặc định."*

---

## 7. Kế Hoạch Dự Phòng Cho Live Demo (Fallback Plan)

Trong kịch bản xấu nhất tại phòng hội đồng (mất kết nối WiFi, API key bị rate limit, máy chiếu chập chờn):

1. **Dự phòng Mạng / API LLM:**
   - Sử dụng toàn bộ các lệnh demo ở chế độ offline `--no-llm`. Rule tier chạy 100% cục bộ, không cần internet.
   - Thư mục `output/` đã lưu trữ sẵn các bản scan JSON, SARIF và report đầy đủ (`output/results.sarif`, `output/scan.json`, `output/eval_results.json`) để mở trực tiếp cho Hội đồng xem.
2. **Dự phòng Live Script:**
   - Nếu script MCP client gặp trục trặc, chạy trực tiếp lệnh kiểm tra sức khỏe: `vulnagent doctor`.
   - Mở sẵn file `docs/hien_trang_du_an.md` và `docs/huong_dan_kiem_thu.md` để chứng minh quy trình đã được chuẩn hóa.

---

## 8. Tóm Lược Thông Điệp Kết Luận (Wrap-up Slide)

Trước khi kết thúc phần thuyết trình, chuyển sang slide kết luận với 3 thông điệp đanh thép:

1. **Về mặt Khoa học:** Chứng minh rằng hợp hai engine SAST + LLM làm giảm chất lượng, nhưng **lọc theo sự đồng thuận độc lập (Corroboration)** mang lại độ chính xác tiệm cận tuyệt đối (**Precision = 1.000, F1 = 0.842**).
2. **Về mặt Kỹ thuật:** Hiện thực hóa cơ chế bảo mật bên trong vòng lặp phát triển của lập trình viên (Inner Dev Loop) thông qua giao thức chuẩn **MCP** và bộ điều phối **Editor Hook** có kiểm soát tương tranh.
3. **Về mặt Thực tiễn:** Cung cấp đầy đủ công cụ DevSecOps (SARIF, Baseline, Verify Rollback) giúp áp dụng ngay vào các dự án phần mềm Python thực tế.

