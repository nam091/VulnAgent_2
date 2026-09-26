# Tổng Quan Các Chức Năng Của Kho Mã Nguồn VulnAgent

Tài liệu này hệ thống hóa toàn bộ các chức năng, module kiến trúc, giao diện dòng lệnh (CLI), giao thức MCP, cơ chế hook và công cụ phụ trợ hiện có trong codebase `VulnAgent`.

---

## 1. Kiến Trúc Cốt Lõi (Core Pipeline)

VulnAgent hoạt động dựa trên quy trình 4 tầng liên hoàn:

```
[Input Code/Repo] 
       │
       ├────────────────────────┐
       ▼                        ▼
 [Rule Tier (Semgrep)]    [LLM Tier (AI Semantic)]
       │                        │
       └───────────┬────────────┘
                   ▼
            [Fusion Engine]
                   ▼
       [Adversarial Verifier]
                   ▼
     [Final Corroborated Findings]
```

### 1.1. Hai Tầng Phát Hiện Độc Lập (Two Independent Tiers)
- **Rule Tier (`src/analyzer/semgrep_runner.py`):** 
  - Khởi chạy engine Semgrep cục bộ với các bộ rules được ghim (`rules/pinned_security_rules.yaml`) hoặc rules từ Semgrep Registry (`p/python`, `p/security-audit`).
  - Tách biệt `stdin` bằng `subprocess.DEVNULL` để ngăn ngừa tình trạng child process chặn pipe trên Windows/MCP.
  - Tự động bắt lỗi cú pháp, timeout, phân tích lỗi chi tiết theo từng file (`last_errors`).
- **LLM Tier (`src/analyzer/code_analyzer.py` & `src/utils/ai_client.py`):**
  - Gửi mã nguồn tới LLM (hỗ trợ OpenAI, Anthropic, Xiaomi Mimo, hoặc bất kỳ endpoint tương thích).
  - Phân tích ngữ nghĩa chuyên sâu: luồng dữ liệu nghiệp vụ, hardcoded secrets, logic phân quyền, tính ngẫu nhiên không an toàn.
  - Chạy bất đồng bộ (`asyncio`) với cơ chế kiểm soát số lượng luồng đồng thời (`concurrency`).

### 1.2. Phân Luồng Rủi Ro & Bộ Nhớ Đệm (Risk Routing & Cache)
- **Risk Routing (`src/analyzer/discovery.py`):**
  - Không quét toàn bộ file bằng LLM để tiết kiệm chi phí và thời gian.
  - Phân tích regex rủi ro (`min-risk` >= 3) để chỉ chọn các file chứa điểm vào nhạy cảm (SQL, subprocess, request, auth, crypto).
  - Tự động bỏ qua các thư mục rác: `venv/`, `.git/`, `node_modules/`, `build/`, `dist/`.
- **Content-Hash Cache (`.vulnagent-cache/`):**
  - Lưu kết quả phân tích theo SHA-256 của nội dung file. File không đổi thì không tốn token LLM, giảm thời gian từ 50s xuống 10s.
  - Tắt cache dễ dàng qua cờ `--no-cache` hoặc `--cold`.

### 1.3. Động Cơ Hợp Nhất & Đồng Thuận (Fusion Engine - `src/analyzer/fusion.py`)
- Gom cụm các finding từ Semgrep và LLM dựa trên:
  - **Khoảng cách dòng:** `LINE_WINDOW = 4` dòng.
  - **Bí danh lỗ hổng (`TYPE_ALIASES`):** Nhận diện `SQL_INJECTION` tương đương `INJECTION_FLAW`, `OS_COMMAND_INJECTION` tương đương `RCE`.
  - **Tương đương CWE (`CWE_EQUIVALENCE`):** Khử độ lệch nhãn giữa các engine.
- Gán nhãn xuất xứ minh bạch (`FindingSource`):
  - `CONFIRMED` (`both-engines`): Cả 2 engine cùng đồng thuận $\rightarrow$ Độ tin cậy 0.95, hầu như không có False Positive.
  - `SEMGREP` (`rule-only`): Chỉ Semgrep phát hiện $\rightarrow$ Độ tin cậy 0.90.
  - `LLM` (`llm-only`): Chỉ LLM phát hiện $\rightarrow$ Độ tin cậy 0.55.

### 1.4. Động Cơ Xác Minh Đối Kháng (Adversarial Verifier - `src/agent/verifier.py`)
- Dành cho các finding bị nghi ngờ là False Positive hoặc chế độ `--verify-findings`.
- Ra lệnh cho Agent với tư duy đối kháng: *"Nhiệm vụ của bạn là tìm lý do chứng minh báo cáo này SAI"*.
- Cấp công cụ `CodeTools` đọc ngược file qua `SafeReader` (chống symlink escape ra ngoài thư mục dự án) để chứng minh chuỗi taint:
  - `source`: Nơi dữ liệu người dùng đi vào.
  - `propagator`: Các bước truyền dữ liệu.
  - `sanitizer`: Hàm kiểm tra / làm sạch (nếu có để kết luận `refuted`).
  - `sink`: Điểm thực thi nguy hiểm.
- Xây dựng chuỗi tấn công liên hoàn (`attack_chains` trong `src/agent/chain_judge.py`).

---

## 2. Hệ Thống 10 Lệnh Dòng Lệnh CLI (`src/cli.py`)

VulnAgent cung cấp bộ lệnh CLI đầy đủ, phục vụ mọi tác vụ từ quét thủ công đến tích hợp CI/CD:

| Lệnh | Ý nghĩa & Chức năng | Các cờ quan trọng |
| :--- | :--- | :--- |
| `scan` | Quét lỗ hổng trên file hoặc thư mục | `--no-llm`, `--no-semgrep`, `--confirmed-only`, `--fail-on {critical,high,medium,low}`, `--format {console,sarif,json}`, `--baseline`, `--fail-on-new`, `--verify-findings` |
| `fix` | Tự động sinh và áp dụng bản vá an toàn | `--dry-run`, `--verify` (tự động rollback nếu bản vá làm code tệ hơn), `--interactive` |
| `baseline` | Đóng băng toàn bộ lỗi hiện tại vào `.vulnagent-baseline.json` | `--output` |
| `serve` | Khởi chạy máy chủ Web UI và REST API | `--host`, `--port` (mặc định: `http://localhost:8000`) |
| `mcp` | Chạy máy chủ MCP Server qua giao thức `stdio` | Phục vụ kết nối trực tiếp cho Claude Code, Cursor |
| `init` | Tự động khởi tạo cấu hình hook cho workspace | `--host {vscode,cursor,claude}`, `--rules <path>` |
| `doctor` | Kiểm tra sức khỏe môi trường, dependencies và engine | Kiểm tra Python runtime, Semgrep binary, Git, rules file |
| `history` | Tra cứu lịch sử audit log và các lần chạy hook/scan | `--limit <n>`, `--scan-id <id>` |
| `check` | Quét kiểm tra nhanh các file vừa bị sửa đổi qua Git | `--changes`, `--before-release` |
| `hook` | Tiến trình ngầm xử lý sự kiện On-Save từ editor | `--target`, `--files`, `--trailing`, `--rules` |

---

## 3. Bộ 12 Công Cụ MCP Server (`src/mcp_server.py`)

Được thiết kế theo chuẩn **Model Context Protocol (MCP)**, cho phép AI Coding Agent tự động kiểm tra và vá code trong bộ nhớ hoặc trên đĩa:

1. `scan_code(code, filename, mode)`: Quét trực tiếp đoạn mã nguồn nằm trong bộ nhớ của AI Agent (chưa cần lưu xuống đĩa) qua thư mục tạm được bảo vệ.
2. `scan_file(path, mode)`: Quét một file trên đĩa với 2 chế độ `fast` (chỉ rule tier, 2–5s) hoặc `deep` (kèm LLM ngữ nghĩa).
3. `scan_directory(path, mode, concurrency)`: Quét toàn bộ thư mục kèm bộ lọc rủi ro.
4. `suggest_fix(code, filename, mode)`: Quét và chỉ trả về các lỗi có thể tự động vá kèm mã diff và mức độ rủi ro (`risk="safe"`).
5. `scan_changes(target, base_ref, include_untracked)`: Sử dụng Git diff để chỉ quét các file vừa bị sửa đổi, trả về `scan_id` và `snapshot_id`.
6. `get_finding_context(scan_id, finding_id)`: Trích xuất phạm vi hàm/block AST bao quanh vị trí lỗi để cung cấp ngữ cảnh cho Agent.
7. `read_evidence(scan_id, path, start_line, end_line)`: Cho phép Agent đọc ngược dòng code an toàn (chặn symlink traversal).
8. `submit_assessment(scan_id, finding_id, verdict, ...)`: Ghi nhận kết luận đánh giá của Agent (`supported`, `refuted`, `uncertain`) vào audit store.
9. `check_stale_assessments(scan_id)`: Kiểm tra các đánh giá cũ xem file nguồn có bị thay đổi sau khi quét hay không.
10. `get_assessment_history(scan_id, finding_id)`: Đọc toàn bộ nhật ký audit log của phiên quét.
11. `check_fix(scan_id, finding_ids)`: Nhận code đã sửa từ Agent, kiểm tra cú pháp AST và chạy rescan để xác nhận lỗi đã biến mất mà không gây lỗi mới.
12. `capabilities()`: Báo cáo năng lực hệ thống, các CWE hỗ trợ và trạng thái sẵn sàng của Semgrep/LLM.

---

## 4. Cơ Chế Điều Phối Lưu File Editor Hook (`src/integrations/host_adapter.py`)

Module `EditorHookRunner` giải quyết triệt để bài toán tích hợp mượt mà vào editor khi lưu file (`Ctrl + S`):

- **Debounce (1.5 giây):** Gom các sự kiện lưu file liên tục, chỉ chạy khi người dùng ngừng gõ 1.5s, tránh làm nghẽn CPU.
- **Dirty Snapshotting (`dirty.json`):** So sánh hash nội dung file. Nếu nội dung không đổi sau khi bấm lưu $\rightarrow$ lập tức bỏ qua.
- **Tiến trình khóa Repository (`.vulnagent.lock`):**
  - Khóa file độc quyền kèm **Token Ownership** và kiểm tra **PID sống/chết (Liveness check)**.
  - Ngăn chặn triệt để tình trạng hai tiến trình scan chạy đè lên nhau gây corrupt dữ liệu.
- **Giới hạn 2 vòng lặp (Max 2 Rounds):** Chặn cứng chu trình `Scan -> Auto-fix -> Rescan` tối đa 2 vòng lặp.
- **No-progress Termination:** Nếu sau một vòng lặp mà số lượng lỗi không giảm hoặc danh sách ID lỗi giữ nguyên $\rightarrow$ tự động dừng để chống treo vô tận.
- **Trình phân tích JSONC an toàn (`_clean_jsonc`):** Đọc và ghi `.vscode/settings.json` mà không làm hỏng comment (`//`, `/* */`) hay trailing comma có sẵn.

---

## 5. Động Cơ Vá Lỗi Tự Động (`src/analyzer/fixer.py`)

- **Unified Diff Generation:** Tự động sinh diff trực quan thể hiện rõ dòng code cũ bị thay thế và dòng code mới an toàn.
- **AST Syntax Check:** Trước khi áp dụng, bản vá được parse thử bằng `ast.parse()`. Nếu gây lỗi cú pháp (`SyntaxError`), bản vá lập tức bị hủy bỏ.
- **Phân loại rủi ro bản vá (`classify_patch`):**
  - `risk="safe"`: Thay thế cục bộ an toàn (ví dụ: chuyển `shell=True` thành `shell=False`, hoặc dùng query tham số hóa).
  - `risk="review"`: Bản vá có thể làm thay đổi luồng điều khiển (ví dụ: chèn khối `try...except`, đổi câu lệnh `return`), yêu cầu người dùng xem xét trước.
- **Tự động Rollback (`--verify`):** Áp dụng bản vá tạm thời, chạy quét lại. Nếu số lượng lỗi tăng lên hoặc không giảm $\rightarrow$ hoàn tác file về trạng thái ban đầu.

---

## 6. Động Cơ Đo Lường & Đánh Giá Benchmark (`eval/run_eval.py`)

Hệ thống đánh giá khoa học phục vụ nghiên cứu và bảo vệ đồ án tốt nghiệp:

- **Bipartite Matching:** Thuật toán ghép cặp nhãn thực tế (Ground Truth) với kết quả phát hiện của công cụ, chống trùng lặp điểm số.
- **Dung sai dòng (`LINE_TOLERANCE = 3`):** Chấp nhận khoảng cách $\pm 3$ dòng giữa vị trí gắn nhãn và vị trí phát hiện của engine.
- **Benchmark Input Integrity Gate (I01 & I02):**
  - Chụp snapshot toàn bộ file rules và dataset trước khi scan (`initial_rule_snapshots`).
  - Kiểm tra đối chiếu sau scan: Nếu file rules bị xóa, bị sửa đổi, nhãn `labels.json` bị can thiệp, hoặc sample bị sửa $\rightarrow$ lập tức đánh dấu **Run INVALID (`verified=False`)** và trả về **Exit Code 1**.
- **Provenance Manifest:** Xuất file JSON lưu lại đầy đủ Git commit, phiên bản Semgrep/Bandit, nền tảng hệ điều hành, cấu hình cache và toàn bộ hash snapshot.

---

## 7. Giao Diện Web & REST API Backend (`src/web/` & `src/jobs.py`)

- **Máy chủ FastAPI:** Cung cấp các REST endpoint bất đồng bộ:
  - `POST /api/scan`: Nhận đoạn code hoặc file upload, đưa vào hàng đợi xử lý.
  - `GET /api/jobs/{job_id}`: Kiểm tra tiến độ và nhận kết quả quét theo thời gian thực.
  - `POST /api/fix`: Sinh bản vá cho các finding được chọn.
  - `GET /docs`: Swagger UI tương tác trực quan.
- **Giao diện Web Frontend (`app.js`, `index.html`, `styles.css`):**
  - Viết bằng HTML/CSS/Vanilla JS thuần, siêu nhẹ, không cần cài đặt Node.js hay build npm.
  - Hiển thị bảng tổng hợp lỗ hổng, phân loại màu sắc theo mức độ nghiêm trọng (Critical/High/Medium/Low) và sơ đồ chuỗi khai thác (Attack Chains).

---

## 8. Tích Hợp CI/CD & DevSecOps (`action.yml`)

- Cung cấp sẵn GitHub Action để tích hợp vào pipeline kiểm tra Pull Request.
- Xuất kết quả theo chuẩn **OASIS SARIF v2.1.0** (`src/reporters/sarif.py`), hiển thị trực tiếp các cảnh báo bảo mật trên giao diện PR Review và tab Security của GitHub.
