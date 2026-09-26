# Báo Cáo Hiện Trạng Dự Án VulnAgent

**Thời điểm cập nhật:** 26/09/2025  
**Nhánh Git:** `feat/hybrid-scanner-v1`  
**Mục đích:** Đánh giá toàn diện kiến trúc, hiện trạng kỹ thuật, năng lực thực tế, các điểm nghẽn và lộ trình tối ưu hóa phục vụ đồ án tốt nghiệp và phát triển sản phẩm.

---

## 1. Bản Chất & Định Vị Dự Án (Overview & Mission)

- **Đề tài:** Nghiên cứu ứng dụng LLM trong phân tích lỗ hổng an toàn mã nguồn.
- **Bản chất kỹ thuật:** VulnAgent là hệ thống quét lỗ hổng mã nguồn tĩnh kết hợp ngữ nghĩa (**Hybrid SAST + LLM**), hoạt động trên nguyên lý **2-tier độc lập**:
  - **Rule Tier (Semgrep):** Đảm nhiệm phát hiện nhanh các mẫu cú pháp nguy hiểm, đảm bảo độ bao phủ (Recall) và vị trí chính xác của lỗ hổng.
  - **LLM Tier (AI Semantic Analysis):** Đảm nhiệm phân tích luồng dữ liệu, ngữ cảnh logic và phát hiện các khiếm khuyết nghiệp vụ mà rule cứng không thể biểu diễn.
  - **Corroboration (Đồng thuận độc lập):** Sự đồng thuận giữa hai tier được dùng làm **bộ lọc giảm nhiễu (heuristic ranking signal)**. Chế độ `--confirmed-only` loại bỏ hầu hết các cảnh báo sai (False Positives) của từng engine đơn lẻ.
- **Đối tượng & Trải nghiệm mục tiêu:** Tối ưu cho quy trình lập trình cùng AI (**Vibe Coding**), tích hợp trực tiếp khâu kiểm tra và khắc phục bảo mật vào vòng lặp viết code (Inner Development Loop) qua giao thức MCP và Editor Hook.

---

## 2. Kiến Trúc Hệ Thống (System Architecture)

```
                       [Source Code / Git Diff]
                                  │
                   ┌──────────────┴──────────────┐
                   ▼                             ▼
       [Rule Tier (Semgrep)]         [Risk Router (AST/Regex)]
                   │                             │
                   │                             ▼
                   │                     [LLM Tier (Async)]
                   │                             │
                   └──────────────┬──────────────┘
                                  ▼
                        [Fusion Engine]
                     (LINE_WINDOW, TYPE_ALIASES)
                                  │
                                  ▼
                    [Adversarial Verifier]
                 (CodeTools, SafeReader, AST)
                                  │
           ┌──────────────────────┼──────────────────────┐
           ▼                      ▼                      ▼
      [MCP Server]          [Editor Hook]            [CLI / API]
   (Cursor / Claude)    (Debounce, File Lock)    (SARIF, CI/CD Gate)
```

1. **Detection Tiers:**
   - `src/analyzer/semgrep_runner.py`: Quản lý thực thi Semgrep với timeout, detatch stdin để chống nghẽn pipe trên Windows.
   - `src/analyzer/code_analyzer.py` & `src/utils/ai_client.py`: Hỗ trợ OpenAI, Anthropic, Xiaomi Mimo, xử lý đa luồng với concurrency cap.
2. **Phân luồng & Cache:**
   - `src/analyzer/discovery.py`: Đánh giá điểm rủi ro (`min-risk`) để chỉ chuyển file nguy hiểm cho LLM Tier, tự động bỏ qua thư mục `venv`, `node_modules`, build artifacts.
   - **Content-hash cache (`.vulnagent-cache/`):** File không thay đổi hash nội dung sẽ được tái sử dụng kết quả, giảm độ trễ từ ~50s xuống ~10s.
3. **Bộ trộn Fusion (`src/analyzer/fusion.py`):**
   - So khớp finding theo khoảng cách dòng (`LINE_WINDOW = 4`), bảng bí danh loại (`TYPE_ALIASES`) và đối soát tương đương CWE (`CWE_EQUIVALENCE`).
   - Gắn nhãn provenance minh bạch: `CONFIRMED` (cả 2 cùng bắt), `SEMGREP` (rule-only), `LLM` (llm-only).
4. **Xác minh đối kháng (`src/agent/verifier.py`):**
   - Không hỏi lại mô hình để xác nhận (chống confirmation bias), mà ra lệnh cho Agent: *"Nhiệm vụ của bạn là tìm lý do chứng minh báo cáo này SAI"*.
   - Cấp công cụ `CodeTools` đọc ngược AST và file thật qua `SafeReader` (chống symlink escape) để thiết lập chuỗi `taint_path` (`source → propagator → sanitizer → sink`).
5. **Giao diện tích hợp:**
   - `src/mcp_server.py`: FastMCP server cung cấp 12 công cụ phục vụ AI coding assistant.
   - `src/integrations/host_adapter.py`: Quản lý quy trình lưu file (`EditorHookRunner`) với Debounce 1.5s, file lock `.vulnagent.lock` và dirty generation tracking.
   - `src/cli.py`: Hỗ trợ 10 lệnh (`scan`, `fix`, `baseline`, `serve`, `mcp`, `init`, `doctor`, `history`, `check`, `hook`).

---

## 3. Hiện Trạng Triển Khai & Kiểm Chứng (Current Capabilities & Verifications)

### 3.1. Kết Quả Kiểm Thử (Test Suite)
- **Toàn bộ 121/121 test cases đã PASS 100%:**
  - `tests/test_core.py`: 22/22 passed (AST parsing, baseline, detection mapping).
  - `tests/test_workflow.py`: 31/31 passed (CLI pipeline, fix verification, reporters).
  - `tests/test_gates.py`: 68/68 passed (Chốt chặn bảo mật, MCP semantics, file lock contention, debounce, và negative integrity gate tests).

### 3.2. Năng Lực Hoạt Động Của MCP Server
- Hoạt động ổn định trên kênh chuẩn `stdio`.
- Đã kiểm chứng thực nghiệm bằng kịch bản MCP Client độc lập trên mã nguồn mở (`vulnerable_app.py` và dynamic snippet):
  - `scan_code`: Quét bộ nhớ trong 6.4s, phát hiện chính xác `CRITICAL OS_COMMAND_INJECTION` (CWE-78) và đề xuất vá.
  - `scan_file`: Bắt trọn vẹn 5 lỗ hổng (CWE-89, CWE-78, CWE-79, CWE-22, CWE-16) và tự động xây dựng chuỗi tấn công liên hoàn (`attack_chains`).
  - `suggest_fix`: Sinh diff thay thế trực tiếp, đánh giá mức độ an toàn (`risk="safe"`).
  - Các công cụ ngữ cảnh: `get_finding_context`, `read_evidence`, `submit_assessment`, `check_fix`.

### 3.3. Năng Lực Hoạt Động Của Editor On-Save Hook
- Tự động cấu hình workspace cho VS Code và Cursor qua lệnh `vulnagent init --host vscode`.
- Cơ chế **Debounce 1.5s** giúp gom các lần lưu file, không gây đơ editor khi gõ nhanh.
- Cơ chế **Process-safe Repository Lock** (`.vulnagent.lock`) có kiểm tra liveness của PID sở hữu, ngăn chặn hoàn toàn tình trạng chạy chồng chéo tiến trình khi lưu liên tục.

---

## 4. Các Điểm Đã Sửa Đổi & Gia Cố Gần Nhất (Recent Hardening)

1. **Khắc phục xung đột môi trường MCP & Semgrep:**
   - Ghim phiên bản `mcp<2.0.0` trong `requirements.txt` và `setup.py` để tránh việc cài đặt đè `mcp 2.x` làm vỡ class `FastMCP` và gây crash lệnh CLI của Semgrep.
   - Thêm cơ chế **Dual-SDK import fallback** trong `src/mcp_server.py`: Thử `FastMCP` → thử `MCPServer` → dummy class, đảm bảo khả năng tương thích tiến (forward compatibility).
2. **Sửa dứt điểm lỗ hổng Benchmark Integrity Gate (I01):**
   - Trong `eval/run_eval.py`: Snapshot toàn bộ file rules cục bộ thành cấu trúc `initial_rule_snapshots` lưu loại (`file`/`directory`), đường dẫn tuyệt đối và hash trước khi chạy scan.
   - Vòng đối chiếu post-scan duyệt chính danh sách snapshot ban đầu. Nếu file bị xóa hoặc biến đổi loại, lập tức ghi nhận mismatch, đánh dấu run INVALID (`verified=False`) và trả về `exit code 1`, không bị biến thành dạng `registry`.
3. **Bổ sung bộ Negative Mutation Tests hoàn chỉnh (I02):**
   - Đã tách thành 4 bài test độc lập trong `tests/test_gates.py` với fixture `tmp_path` riêng biệt:
     - `test_eval_integrity_gate_detects_rule_file_deleted`: Bắt lỗi khi file rules bị xóa giữa chừng.
     - `test_eval_integrity_gate_detects_rule_file_mutated`: Bắt lỗi khi nội dung file rules bị can thiệp.
     - `test_eval_integrity_gate_detects_labels_mutated`: Bắt lỗi khi file nhãn `labels.json` bị sửa.
     - `test_eval_integrity_gate_detects_samples_mutated`: Bắt lỗi khi file mã nguồn mẫu trong `samples/` bị sửa.
4. **Chuẩn hóa và dọn dẹp Codebase:**
   - Di chuyển toàn bộ tài liệu đánh giá và kế hoạch (`Nhan_xet.md`, `VulnAgent_Ke_hoach_phat_trien_va_thuc_nghiem.md`) vào thư mục `docs/`.
   - Di chuyển script test thử nghiệm (`run_test_mimo.py`) vào `examples/`.
   - Bổ sung `.vulnagent-audit/` và `.vulnagent.lock` vào `.gitignore`.

---

## 5. Giới Hạn Kỹ Thuật Còn Tồn Tại (Known Limitations)

1. **Phạm vi ngôn ngữ:** Hiện chỉ hỗ trợ mã nguồn **Python** (dựa trên AST và Semgrep Python rules).
2. **Phân tích luồng dữ liệu cục bộ (Single-file Taint):** Chưa hỗ trợ theo vết dữ liệu xuyên file (Cross-file/Inter-procedural taint analysis). Nếu dữ liệu đi qua module helper ở file khác, verifier phải dựa vào heuristic đọc ngữ cảnh chứ chưa có full graph.
3. **Cơ chế xác minh bản vá (Auto-fix Verification):** 
   - `_verify_fix()` hiện tại chỉ kiểm tra tính hợp lệ về cú pháp AST và chạy lại scanner để so sánh số lượng finding.
   - Chưa tích hợp cơ chế tự động chạy bộ unit test của project (`pytest`) để phát hiện hồi quy nghiệp vụ (Functional Regression).
4. **Mức độ tích hợp UI:** Chưa có extension VS Code native (`.vsix`) dạng LSP để hiển thị trực tiếp lượn sóng đỏ/vàng trên editor; hiện vẫn sử dụng extension trung gian `emeraldwalk.runonsave` in ra terminal.

---

## 6. Khuyến Nghị Lộ Trình Nâng Cấp (Recommended Roadmap)

### Giai đoạn 1: Chuẩn bị bảo vệ đồ án tốt nghiệp
- **Chạy thực nghiệm chuẩn hóa trên tập mẫu lớn:** Sử dụng bộ dữ liệu SecurityEval (115 mẫu Python CWE) đã có script chuyển đổi `eval/prepare_securityeval.py`, lưu lại manifest toàn vẹn (`integrity.verified = true`) để đưa bảng số liệu F1/Precision/Recall vào báo cáo đồ án.
- **Kịch bản Demo chuẩn:** Chuẩn bị sẵn 3 luồng demo:
  1. Demo MCP Server kết nối trực tiếp với Cursor/Claude Code trên open code.
  2. Demo On-save hook trên VS Code bắt ngay lỗ hổng khi lưu file.
  3. Demo xử lý sự cố có kiểm soát (khi thiếu ngữ cảnh thì báo `uncertain` chứ không khẳng định bừa).

### Giai đoạn 2: Tối ưu hóa kỹ thuật sâu
- **AST Dataflow Pruning trước khi gọi LLM:** Dùng AST kiểm tra nhanh xem biến truyền vào sink có phải là hằng số hoặc literal hay không; nếu là literal thì loại ngay từ vòng gửi xe, tiết kiệm token và giảm thời gian quét.
- **Lightweight Import Chasing cho Verifier:** Mở rộng `ast_context.py` để khi verifier đọc một hàm sanitize ở file khác cùng repo, tool tự động bóc tách definition của hàm đó nhồi vào context cho LLM.
- **Test-Driven Fix Verification:** Bổ sung bước chạy test suite của repo đích sau khi apply patch. Nếu test fail → tự động rollback và gắn nhãn `fix_rejected: broken_logic`.
