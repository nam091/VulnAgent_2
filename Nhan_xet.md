# Nhận xét codebase VulnAgent so với kế hoạch

> **Cập nhật review tại `9c30986` (11/09/2026):** 78/78 test pass, nhưng chưa đóng toàn bộ R01–R07. Có regression mới ở scanner không truyền `files`; R03 còn lỗi path/schema; R07 mới bảo vệ hash chụp sau build plan. Phần cập nhật dưới đây là kết luận mới nhất. Các mục từ “1. Kết luận” trở đi giữ lại làm lịch sử review tại `5929004`.

## Cập nhật sau bản sửa R01–R07 — commit 9c30986

### Kết quả kiểm tra

- Đã đọc diff CLI, scanner, MCP và shared assessment policy; đối chiếu regression tests mới.
- `python -m pytest tests -q`: **78 passed, 1 warning**, pytest báo **8.51 giây**.
- Probe bổ sung chạy Scanner thật với hai engine disabled để kiểm tra điều phối, không cần Semgrep/API; dùng file giả trong thư mục tạm.
- Probe policy dùng EvidenceStore thật, snapshot/file/record thật; không gọi model.
- Không thay đổi mã nguồn trong lượt review này. Các phát hiện mới dưới đây đã tái hiện, trừ nhận xét thời điểm chụp hash R07 được xác minh bằng đọc luồng gọi.

### Trạng thái R01–R07

| ID | Kết luận cập nhật |
|---|---|
| R01 | Đã sửa lời gọi `get_changed_files()` và gom một Scanner với expanded scope; ca cũ có regression test pass. Chưa nghiệm thu toàn bộ Git/subdirectory/host workflow. |
| R02 | Đã chặn exit 0 ở `check`/`before-release` khi nhận result failed/degraded; test pass. Tuy nhiên scan thường hiện bị regression N01 trước khi trả result. |
| R03 | Đã chặn taint step rỗng, thiếu/ID bịa và kiểm tra range; **chưa đóng** vì path identity và enum validation vẫn lọt N02/N03. |
| R04 | Đã thêm failed report cho file yêu cầu bị thiếu, chặn resolved cho ca cũ; test pass. Chưa có toàn bộ snapshot trước/sau, rename/new helper, behavioral verification. |
| R05 | Đã dùng `id` hoặc `fingerprint()`; ca finding giống nhau qua instance mới không còn bị báo regression trong test. |
| R06 | Đã đưa error khóa `""` vào lỗi toàn run; test assembler pass. Chưa chạy Semgrep thật để kiểm tra phân loại warning/error. |
| R07 | Đã truyền expected hashes từ CLI xuống apply; **mới một phần**: hash vẫn được chụp sau scan/build_plan, chưa neo chắc vào nội dung dùng để tạo kế hoạch. Test mới chỉ gọi apply_plan trực tiếp. |

### N01 — P1: scan thông thường bị UnboundLocalError

- **Vị trí:** `src/analyzer/scanner.py:240`, `:256`, `:293`, `:367`.
- `requested_files` chỉ được gán trong `if self.options.files`, nhưng cả nhánh không có file và nhánh tổng hợp stats đều sử dụng biến đó.
- **Đã tái hiện:** `Scanner(ScanOptions(target=temp_root, use_llm=False, use_semgrep=False)).scan()` không truyền `files`. Cả thư mục rỗng và thư mục chứa `app.py` đều lỗi:

```text
UnboundLocalError: cannot access local variable 'requested_files' where it is not associated with a value
```

- **Ảnh hưởng:** scan toàn repo/file theo đường mặc định không trả ScanResult bình thường. Những CLI/MCP entrypoint không truyền `files` đều cần được kiểm tra lại; việc 78 test pass chưa bao phủ nhánh này.
- **Sửa:** khởi tạo `requested_files` cho mọi đường đi; xác định riêng `files=None` (discover theo target) và `files=[]` (scope rỗng nếu contract quy định như vậy), không dựa hoàn toàn vào truthiness.
- **Test cần có:** thư mục rỗng, một file, toàn repo và explicit files; test chạy xuyên Scanner.scan, chỉ mock engine boundary. Không mock toàn bộ Scanner.scan khi kiểm tra orchestration của nó.

### N02 — P1: taint policy vẫn đối sánh nhầm file theo hậu tố

- **Vị trí:** `src/models/assessment.py:175–177`.
- **Đã tái hiện:** evidence hợp lệ cho `app.py:1`; taint steps source và sink đều viện dẫn `b/app.py:1` với cùng evidence ID. File `b/app.py` không tồn tại. Kết quả vẫn **supported**.
- **Nguyên nhân:** điều kiện `endswith('/' + norm_rec_path)` chấp nhận `b/app.py` là cùng file với `app.py`.
- **Sửa:** resolve cả đường dẫn citation và record bằng root/policy của EvidenceStore; yêu cầu cùng resolved path và trong scope. Không dùng suffix/basename để quyết định identity.
- **Test cần có:** root `app.py` đối lập `b/app.py`; hai thư mục trùng basename; absolute/relative cùng file hợp lệ; traversal và symlink ngoài root bị từ chối.

### N03 — P1: TaintStep schema đã khai báo nhưng chưa dùng để validate

- **Vị trí:** `src/models/assessment.py:TaintStep`, `evaluate_assessment_policy`, đặc biệt dòng 195–199.
- **Đã tái hiện:** một step có evidence ID hợp lệ và `kind='not_source_not_sink'` vẫn được nhận **supported** cho SQL_INJECTION. Code tìm chuỗi con `source`/`sink`, khiến một kind không hợp lệ được tính là cả hai.
- **Đã tái hiện:** `kind=123` gây `AttributeError: 'int' object has no attribute 'strip'`, thay vì trả uncertain/schema error có cấu trúc.
- **Sửa:** validate mỗi step bằng model thực sự trước khi sử dụng; enum phải so sánh chính xác, không tìm substring; lỗi schema được thu gom thành policy failure. Dùng integer validation rõ để tránh chấp nhận bool/fractional line ngoài ý muốn. Chuẩn hóa tên kind giữa prompt (`propagator`) và schema (`propagation`) bằng migration/mapping tường minh nếu cần.
- **Test cần có:** kind số/list/object, enum lạ, chuỗi chứa cả source/sink, line sai kiểu; ca source và sink hợp lệ vẫn được chấp nhận. Thiếu bằng chứng ngữ nghĩa vẫn phải nêu limitations, không coi đúng enum là chứng minh taint.

### R07 còn lại — thời điểm chụp hash chưa gắn với scan/plan

- **Vị trí:** `src/cli.py:404`, `:411`, `:413–423`, `:478`.
- CLI quét xong, gọi build_plan, rồi mới đọc lại file để tạo expected_snapshot_hashes. Nếu nội dung đổi giữa scan/build_plan và lượt đọc lại này, hash mới có thể hợp thức hóa file mới trong khi patch được tạo từ mã cũ. Nhánh đọc hash lỗi còn `except: pass`, làm thiếu guard cho file đó.
- Đã cải thiện so với không truyền hash: edit xảy ra sau khi chụp hash mới được chặn. Chưa đủ để khẳng định tất cả stale patch đã bị chặn.
- **Sửa:** kế hoạch phải mang hash của chính nội dung gốc được dùng để xây/validate patch, đối chiếu với snapshot phân tích; không đọc lại một phiên bản mới để xác lập baseline. Không có expected hash cho patch yêu cầu ghi phải báo conflict, không bỏ qua guard.
- **Test cần có:** chạy `_run_fix` qua build_plan/apply thật với scanner giả lập; thay file giữa scan và plan, giữa plan và hash, giữa hash và apply. Test unit của apply_plan chưa bao phủ các ranh giới này.

### Hướng đi tiếp sau cập nhật

Ưu tiên **N01 → N02/N03 → R07 timing**, sau đó chạy lại suite và một smoke scan/check/fix không mock toàn Scanner. R08–R14 của review gốc vẫn cần nghiệm thu riêng. Bản mới có tiến bộ nhỏ ngoài R01–R07: doctor thiếu Semgrep đã báo lỗi, MCP serializer trả thêm assessment/corroborated, stale đồng bộ bản assessment và lưu event history; các thay đổi này chưa hoàn tất host hooks, persistent audit, cache identity, UI và thực nghiệm.

**Kết luận mới nhất:** các ca cũ R01/R02/R04/R05/R06 đã có bản sửa và test tương ứng pass; không thể ghi “đã xử lý triệt để R01–R07” khi R03/R07 còn hở và scan mặc định vừa phát sinh regression.

- Ngày review: 11/09/2026.
- Commit được kiểm tra: `5929004` — `feat: complete end-to-end workflows 1-6 according to plan`.
- Mốc đối chiếu thay đổi: `7fe1c8c`.
- Kế hoạch: [VulnAgent_Ke_hoach_phat_trien_va_thuc_nghiem.md](VulnAgent_Ke_hoach_phat_trien_va_thuc_nghiem.md), đặc biệt B01–B18 và G1–G7.
- Phạm vi đã chốt: **Python**; chưa mở rộng đa ngôn ngữ.
- Review không thay đổi mã nguồn. Chỉ bổ sung tài liệu này.

## 1. Kết luận

**Codebase đang đi đúng hướng, nhưng chưa đủ ổn để nghiệm thu toàn bộ kế hoạch hoặc tuyên bố đã hoàn thành sáu luồng đầu-cuối.** Có tiến bộ thực chất về evidence, shared assessment policy, coverage và rollback. Tuy nhiên, một số module mới chưa được nối đúng vào luồng sử dụng; còn lỗi false clean ở CLI và kiểm tra sau sửa, cùng lỗ hổng ràng buộc taint evidence.

Tên commit không phải bằng chứng nghiệm thu. Việc có class, field hoặc hàm mới cũng chưa chứng minh CLI/MCP/UI sử dụng chúng đúng. Các lỗi bên dưới cho thấy cần test xuyên qua các ranh giới module.

Không đề xuất viết lại hệ thống. Nên giữ nền hiện tại, sửa theo các PR nhỏ và bổ sung test cho từng hành vi bị lỗi. Chưa nên chạy main benchmark trước khi đóng các lỗi G1/G2/G5.

## 2. Phương pháp và giới hạn xác minh

### Đã thực hiện

- Đọc diff của commit mới và các đường gọi liên quan trong scanner, CLI, MCP, verifier, assessment policy, fixer, fusion, Semgrep runner.
- Đối chiếu adapter editor, UI, cache, dependency và cấu trúc eval với yêu cầu kế hoạch.
- Chạy `python -m pytest tests -q`: **71 passed, 1 warning**, thời gian pytest báo **3.03 giây**.
- Chạy kiểm tra bổ sung bằng Python, `tempfile`, dữ liệu giả và `unittest.mock`; không gọi provider/model thật.
- Một số probe gọi hàm trực tiếp để cô lập lỗi; các probe khác chạy scanner thật trên thư mục tạm, chỉ không đi tới Semgrep khi không còn file trong scope.
- Working tree sạch trước review. Không có `AGENTS.md` được tìm thấy trong danh sách file đã tìm ở repo.

### Chưa thực hiện

- Chưa chạy scan Semgrep thật để đo độ phủ rules hoặc hiệu quả phát hiện.
- Chưa gọi model/API thật; chưa đo token, chi phí, latency hoặc chất lượng suy luận.
- Chưa chạy MCP client qua transport stdio và chưa demo trên editor thật.
- Chưa kiểm tra UI bằng trình duyệt; nhận xét UI dựa trên mã nguồn.
- Chưa cài lại từ wheel/môi trường sạch; chưa xác minh cấu hình host theo tài liệu nhà cung cấp hiện hành.
- Chưa chạy lại benchmark/dataset bên ngoài hoặc đọc lại đề cương DOCX.

Môi trường test phát thông báo về Pydantic V1 trên Python 3.14 và cảnh báo `python_multipart`. Đây là dấu hiệu cần khóa môi trường tái lập, không phải lỗi khiến 71 test thất bại.

## 3. Những điểm đã làm tốt và nên giữ

1. **EvidenceStore và verifier đã được củng cố:** kiểm tra snapshot membership, hash, range, nội dung excerpt; các regression test cho evidence giả, stale, khác file và output bị cắt được giữ lại.
2. **Có policy dùng chung:** `evaluate_assessment_policy()` được gọi từ MCP và API verifier, giảm nguy cơ hai bên áp dụng hai luật hoàn toàn khác nhau.
3. **Scope scanner đã bỏ fallback basename:** bộ lọc file trong scanner phân biệt đường dẫn như `a/app.py` và `b/app.py`; có test mới.
4. **Semgrep runner đã trích lỗi từng file:** scanner gắn `requested`, `status`, `reason` và số findings cho engine. JSON CLI đã trả status/coverage.
5. **Có lịch sử assessment và kiểm tra stale:** MCP thêm `get_assessment_history` và `check_stale_assessments`. Đây là bước đầu hữu ích, dù chưa phải lưu trữ bền vững.
6. **Fixer có điều kiện hash trước apply/rollback:** rollback CLI đã truyền hash nội dung tool vừa ghi; phần bảo vệ trước apply còn chưa được nối vào CLI.
7. **Cache có ghi qua file tạm và bỏ qua output mang error/truncated:** tốt hơn ghi trực tiếp, nhưng identity và đồng thời vẫn cần hoàn thiện.
8. **Có thêm bảy test so với mốc trước:** tổng 71 test đều pass. Các test mới chưa bao phủ hết entrypoint và trạng thái thất bại dưới đây.

## 4. Phát hiện cần sửa, theo mức ưu tiên

P1 trong tài liệu này là lỗi chặn luồng chính hoặc có thể làm kết luận kiểm tra sai; không phải điểm CVSS. P2 là sai khác hợp đồng, tính tái lập hoặc phần thiếu cần hoàn thiện trước bàn giao.

### R01 — P1: `check --changes` gọi phương thức không tồn tại

- **Plan:** B09/B14, G4/G7.
- **Vị trí:** [src/cli.py:659](src/cli.py#L659), [src/context/diff_scope.py:21](src/context/diff_scope.py#L21).
- **Đã tái hiện:** gọi `_run_check()` với `changes=True` trên thư mục tạm tồn tại trả `AttributeError: 'DiffScopeAnalyzer' object has no attribute 'get_modified_files'`.
- **Nguyên nhân:** CLI gọi `get_modified_files()`, còn analyzer cung cấp `get_changed_files()`. Hàm hiện có trả các đường dẫn tương đối dạng chuỗi; vòng lặp CLI lại dùng `mf.exists()` như đối tượng Path. Vì vậy chỉ đổi tên phương thức là chưa đủ.
- **Cách sửa:** dùng chung logic tính changed/expanded scope với MCP; resolve các relative path trong root đã cấp; gọi một Scanner với `files=expanded_files` thay vì khởi động Semgrep riêng cho từng file. Giữ status và lỗi toàn run khi tổng hợp.
- **Nghiệm thu:** test CLI có tracked/staged/untracked files, không thay đổi, root là thư mục con và Git lỗi. Có ít nhất một smoke test gọi entrypoint CLI thực.

### R02 — P1: lệnh `check` trả thành công khi scanner thất bại

- **Plan:** B01/B14, G1.
- **Vị trí:** [src/cli.py:696](src/cli.py#L696), [src/cli.py:708](src/cli.py#L708), [src/cli.py:717](src/cli.py#L717).
- **Đã tái hiện:** mock `Scanner.scan()` trả `ScanResult([], root, {'rule_error': 'synthetic engine failure'})`. Cả `check` thường và `check --before-release` trả **exit 0** khi findings rỗng. Nhánh before-release in `Status: failed`, cảnh báo degraded, rồi vẫn in không còn unresolved findings và trả thành công.
- **Cách sửa:** xử lý `status/degraded/coverage` trước gate findings ở mọi entrypoint. Lỗi/incomplete phải có exit policy thống nhất, ví dụ exit 2; findings gate là exit 1; exit 0 chỉ theo điều kiện hoàn tất đã công bố. Không chỉ in warning rồi tiếp tục nhánh thành công.
- **Nghiệm thu:** lỗi toàn engine, parse lỗi, timeout, không provider khi yêu cầu API và partial đều có assertions trên exit code lẫn output. Phân biệt routing chủ động với thất bại ngoài dự kiến bằng policy rõ.

### R03 — P1: policy `supported` vẫn nhận taint path rỗng về nội dung hoặc evidence ID bịa

- **Plan:** B02/B03/B12, G2.
- **Vị trí:** [src/models/assessment.py:123](src/models/assessment.py#L123).
- **Đã tái hiện:** tạo file thật và một evidence hợp lệ. Gửi verdict `supported`, type `SQL_INJECTION`, kèm một trong hai taint path sau; cả hai được nhận là **supported**:

```json
[{}]
```

```json
[{"kind":"sink","file":"missing.py","line":999,"evidence_id":"invented"}]
```

- **Nguyên nhân:** policy chỉ kiểm tra danh sách taint không rỗng. Một step bị từ chối chỉ khi ID của nó có trong `invalid_eids`; ID không được khai báo trong `evidence_ids` không nằm trong tập này, nên lọt. Step thiếu ID cũng lọt.
- **Cách sửa:** schema riêng cho taint step, enum kind và phạm vi dòng. Mỗi step bắt buộc tham chiếu ID nằm trong tập evidence hợp lệ; path/range phải khớp record. Với ba CWE MVP, yêu cầu ít nhất source và sink theo policy đã định nghĩa. Tương tự, control của refutation phải có binding rõ; không dùng một chuỗi control cộng evidence bất kỳ như chứng minh ngữ nghĩa.
- **Nghiệm thu:** thiếu ID, ID không khai báo, ID không tồn tại, sai path/range, step `{}`, thiếu source/sink và stale đều thành uncertain hoặc lỗi schema rõ ràng; API và MCP cho kết quả thống nhất.
- **Giới hạn cần giữ trong báo cáo:** ràng buộc cấu trúc bằng chứng không chứng minh taint path đúng về ngữ nghĩa. Muốn kiểm tra control cụ thể cần thêm policy/mẫu đã rà và đo false refutation.

### R04 — P1: không quét được file mục tiêu vẫn báo fix resolved/clean

- **Plan:** B01/B09/B16, G1/G5.
- **Vị trí:** [src/analyzer/scanner.py:255](src/analyzer/scanner.py#L255), [src/mcp_server.py:789](src/mcp_server.py#L789).
- **Đã tái hiện:** session có finding trong `missing.py`, changed/expanded scope đều yêu cầu file đó, nhưng file không tồn tại. `check_fix()` dùng Scanner thật trả **`clean=True`, `status='completed'` và ID nằm trong `resolved_findings`**. Scanner không tìm thấy file được yêu cầu nên trả report rỗng, status vẫn completed.
- **Nguyên nhân:** coverage thiếu không chặn so sánh ID. Việc file biến mất cũng không được phân loại là deletion có chủ ý so với file không truy cập được.
- **Cách sửa:** ghi trạng thái cho mọi file được yêu cầu, kể cả missing/excluded/unreadable. `check_fix` phải tạo snapshot sau, tính lại diff/scope, kiểm tra finding IDs thuộc scan trước và khả năng so sánh. File bị xóa có chủ ý cần lifecycle riêng và kiểm tra hành vi liên quan; không dùng chung nhánh với lỗi không quét được file.
- **Nghiệm thu:** missing/excluded/rename/new helper và engine không hỗ trợ không tự thành resolved. File mới sau sửa phải được xét theo policy ảnh hưởng. Test bảo mật và chức năng trên demo Python vẫn cần bổ sung.

### R05 — P1: CLI so sánh bound method thay vì giá trị fingerprint

- **Plan:** B16, G5.
- **Vị trí:** [src/cli.py:523](src/cli.py#L523), [src/models/vulnerability.py:196](src/models/vulnerability.py#L196).
- **Đã tái hiện:** hai Vulnerability khác instance nhưng cùng dữ liệu có `old.fingerprint() == new.fingerprint()` là True; `old.fingerprint == new.fingerprint` là False. Mock rescan giữ nguyên finding khiến `_verify_fix()` báo có một regression và trả exit 2.
- **Cách sửa:** gọi `fingerprint()` hoặc dùng định danh đã chuẩn hóa `id` theo một contract thống nhất. Sau đó đối chiếu finding mục tiêu, regression và coverage, không chỉ tổng count.
- **Nghiệm thu:** finding không đổi không là regression; mục tiêu đã sửa nhưng finding cũ không liên quan vẫn tồn tại được phân loại đúng; finding mới thực sự phải bị phát hiện.

### R06 — P1: lỗi Semgrep không gắn file bị bỏ khỏi kết luận run

- **Plan:** B01, G1.
- **Vị trí:** [src/analyzer/semgrep_runner.py:359](src/analyzer/semgrep_runner.py#L359), [src/analyzer/scanner.py:728](src/analyzer/scanner.py#L728).
- **Đã tái hiện ở ranh giới assembly:** cấp `_file_rule_errors={'': [{'message': 'global rule failure'}]}` cùng một file và engine available. `_assemble()`/ScanResult trả **completed, degraded=False**. Chưa giả lập toàn subprocess Semgrep cho ca này.
- **Nguyên nhân:** runner lưu lỗi không có path dưới khóa chuỗi rỗng; assembler chỉ kiểm tra `relative in file_rule_errors`, không xử lý khóa toàn run.
- **Cách sửa:** tách global errors khỏi file errors, phân loại mức độ/ảnh hưởng và đưa vào run status/coverage. Không coi mọi warning đều fatal, nhưng error ảnh hưởng phân tích phải được phản ánh; trường hợp chưa phân loại được không được im lặng báo clean.
- **Nghiệm thu:** fixture JSON Semgrep có results rỗng và global error, rule compilation error, file parse error và warning; assertions cho cả JSON/CLI/MCP.

### R07 — P1: hash bảo vệ trước apply mới có ở hàm, chưa được CLI sử dụng

- **Plan:** B16, G5.
- **Vị trí:** [src/cli.py:466](src/cli.py#L466), `src/analyzer/fixer.py:apply_plan`.
- **Mức xác minh:** đọc call site, chưa thực hiện sửa file người dùng hoặc tái hiện concurrent write.
- CLI vẫn gọi `apply_plan(plan, dry_run=args.dry_run)` mà không truyền `expected_snapshot_hashes`. Vì vậy test unit truyền hash vào apply_plan không chứng minh luồng CLI đã được bảo vệ.
- **Cách sửa:** chụp hash đúng lúc tạo kế hoạch từ nội dung đã phân tích, truyền bắt buộc qua apply; không chụp lại ngay trước apply rồi coi đó là snapshot cũ. Khi mismatch, trả conflict có cấu trúc và không ghi file. Chỉ rollback file đã ghi thành công, còn khớp hash tool viết.
- **Nghiệm thu:** thay đổi file giữa build plan và apply qua CLI không bị ghi đè; thay đổi sau apply không bị rollback ghi đè. Hash check giảm rủi ro nhưng vẫn cần xác định chính sách concurrency/lock.

## 5. Các phần còn thiếu hoặc chưa thống nhất

### R08 — P2: editor mode/capabilities chưa nhất quán

`scan_changes` đã dùng rule-only. Tuy nhiên `capabilities()` trả cố định `backend_llm_calls=False`, trong khi tools cũ như `scan_file`/`scan_directory` mặc định deep và `_scan_target` bật LLM theo mode. Hướng dẫn MCP vẫn khuyên dùng deep để review cuối.

**Sửa:** khai báo khả năng theo tool/mode, tách editor và standalone API tường minh; editor mode chặn backend model call từ cấu hình thực thi, không chỉ mô tả trong chuỗi. Giữ tools cũ qua adapter/schema migration, không để host hiểu tất cả tool đều không gọi API. Thêm zero-provider-call test cho toàn bộ tool được phép ở editor mode.

### R09 — P2: hook editor và doctor chưa đạt B13/B14

Commit mới không thay đổi `src/integrations/host_adapter.py`. Adapter hiện chủ yếu tạo cấu hình MCP và hướng dẫn. Chưa thấy hook thực thi có debounce, dirty snapshot, repo lock, giới hạn hai vòng và no-progress. Chưa có bằng chứng demo host thật.

`doctor` chỉ kiểm tra một số executable/config tồn tại và import module; thiếu Semgrep vẫn chỉ warning và không làm `all_ok=False`. Chưa có MCP handshake/smoke hay chạy rules.

**Sửa:** chọn một editor; triển khai và xác minh config/hook theo tài liệu host khi bắt đầu. Doctor phải kiểm tra khả năng thực thi tối thiểu của mode được chọn và đưa hành động khắc phục. Test cài sạch/giữ config cũ/không lặp, rồi lưu transcript demo có thất bại có kiểm soát.

### R10 — P2: provenance và UI/report vẫn chưa theo semantics mới

- Fusion thêm `corroborated=True` nhưng vẫn gán source `CONFIRMED`, confidence 0.95.
- `_to_dict()` của MCP vẫn xuất label confirmed và confidence; chưa trả đầy đủ corroborated/assessment/evidence semantics mới.
- `src/web/app.js:48` và `:542` còn thông điệp tĩnh “Both engines came back clean”. Không có thay đổi UI trong commit mới.
- Không thể dùng việc README đã sửa từ ngữ để chứng minh UI/API đã đồng bộ.

**Sửa:** contract versioned phân biệt provenance, assessment, evidence status, ranking và user decision. Serializer dùng chung; giữ field cũ qua migration có tài liệu. UI empty phải dựa trên requested/status/coverage; hiển thị refuted/uncertain/stale và đường dẫn bằng chứng. Chưa kết luận lỗi render cụ thể trong browser vì chưa kiểm thử trực quan.

### R11 — P2: assessment history mới là in-memory và stale chưa được lưu xuyên suốt

`AssessmentStore` có dict/list trong bộ nhớ; docstring “in-memory or persistent” không làm nó trở thành persistent. Restart mất session/history/evidence. `check_stale_assessments` cập nhật assessment_status của finding nhưng bản `vuln.assessment` đã model_dump trước đó không được đồng bộ tại đây; history chứa bản copy lúc save và chưa ghi event stale.

**Sửa:** xác định rõ chính sách session-only hoặc lưu bền vững. Với mục tiêu audit của plan, lưu snapshot/evidence/assessment/event theo scan; trạng thái stale không xóa lý do gốc, lưu thành event và cập nhật view nhất quán. Hạn chế thời gian giữ/cleanup session; hỗ trợ đọc lịch sử sau restart nếu tuyên bố persistent.

### R12 — P2: cache chưa đủ identity và ghi đồng thời

Key mới gồm `CACHE_VERSION`, `AI_PROVIDER`, `OPENAI_MODEL`, chuỗi cố định `prompt_v1`, content. Đây chưa phải hash prompt thực; thiếu endpoint, cấu hình sinh đầu ra và identity provider/model thực khi fallback. Context dependency cần nằm trong key khi được dùng. File tạm chỉ thêm PID, nên hai tác vụ cùng process ghi cùng key có thể dùng cùng tên tạm.

**Sửa:** key từ cấu hình thực thi thực tế và prompt/schema hash; fallback có metadata riêng. Dùng tên tạm duy nhất cho mỗi writer và atomic replace; test concurrent writers. Chỉ cache output đã validate; cache raw analysis tách khỏi assessment theo snapshot. Chưa có số đo cold/warm mới trong review này.

### R13 — P2: safe-reader/budget cần nghiệm thu rộng hơn

Agent tools vẫn có các đường `read_text()` trực tiếp và `re.compile(pattern)` cho regex do model cung cấp. Các regression về path/evidence không thay thế kiểm thử giới hạn bytes, số file, thời gian regex, timeout/cancellation hay prompt injection. Cần audit tất cả nơi đọc nguồn, dùng policy chung và ngân sách hữu hạn; giữ nội dung repo là dữ liệu không có quyền thay policy.

### R14 — P2: thực nghiệm và đóng gói chưa đạt G6/G7

Commit mới không cập nhật harness/dataset/protocol hay thêm dữ liệu thực nghiệm. Trong cây `eval` được liệt kê vẫn có harness, script chuẩn bị dữ liệu và ba sample nội bộ; chưa thấy bộ artifact khóa protocol/split/manifest/results cho nghiên cứu mới. Không kết luận không có dữ liệu ở nơi khác; chưa được cung cấp trong review này.

`requirements.txt`/`setup.py` chưa khóa phiên bản; chưa có test extras tái lập đầy đủ. Chưa chạy clean install/wheel, nên không xác nhận bàn giao cài một lệnh hoạt động. `doctor` hiện chưa đủ thay cho clean-install test.

**Sửa:** khóa Python/dependency/rules, rà nhãn và provenance; chốt split/protocol trước main run. Lưu raw outputs, error/uncertain/refuted, usage, seed/config và code tính metrics. Chạy baseline/ablation và ba workflow theo plan. Bảng README cũ phải ghi commit/nhãn/môi trường tương ứng hoặc đánh dấu lịch sử, không dùng như kết quả cho pipeline mới.

## 6. Đánh giá bảy gate theo plan

| Gate | Kết luận tại 5929004 | Điều còn chặn |
|---|---|---|
| G1 — Status | **Chưa đạt** | R02, R04, R06: exit thành công và completed/clean trong các ca thiếu coverage/lỗi |
| G2 — Evidence | **Chưa đạt toàn gate** | Các lỗi refutation cũ đã có regression; supported taint binding vẫn lọt R03 |
| G3 — Modes | **Một phần, chưa nghiệm thu** | Có rule-only core nhưng capabilities/tools cũ chưa nhất quán; chưa zero-outbound suite toàn editor surface |
| G4 — Integration | **Chưa đạt** | CLI changes hỏng R01; hook/editor/stdio demo chưa được xác minh |
| G5 — Fix | **Chưa đạt** | R04/R05/R07; thiếu snapshot trước/sau, scope recomputation và test chức năng/security |
| G6 — Evaluation | **Chưa có đủ bằng chứng nghiệm thu** | Chưa main run/protocol/manifest/results cho pipeline mới |
| G7 — Delivery | **Chưa đạt** | UI/semantics/docs/config chưa thống nhất; chưa clean install |

Không quy đổi thành phần trăm hoàn thành: số lượng field/module/test không phản ánh độ hoàn chỉnh của từng gate.

## 7. Thứ tự sửa đề xuất

### PR-A: Status và entrypoint CLI

Đóng R01, R02, R06. Thống nhất exit semantics và global/file errors; giữ mỗi file yêu cầu trong coverage. Chạy test entrypoint có mock engine, không chỉ `_assemble`.

### PR-B: Assessment binding

Đóng R03. Schema taint/control có evidence ID bắt buộc, kiểm tra membership/path/range; API/MCP dùng chung policy và payload semantics. Bổ sung test malformed payload và các bước không gắn evidence.

### PR-C: Fix verification

Đóng R04, R05, R07. Snapshot trước/sau, scope sau sửa, kiểm tra finding IDs, chính sách deletion/rename, gọi fingerprint đúng và nối hash guard vào CLI. Bổ sung demo giữ hành vi hợp lệ, chặn input nguy hiểm.

### PR-D: MCP/editor đầu-cuối

Đóng R08/R09 và phần lưu history R11. Chọn một host, rule-only không API, MCP stdio handshake, hook hữu hạn và doctor có smoke. Không triển khai đồng thời nhiều host để kéo dài phạm vi.

### PR-E: Semantics và reporting

Đóng R10, hoàn thiện R11. Một schema/reporting contract, refuted/stale/audit có thể truy xuất; test JSON/SARIF/MCP không mất fields và UI có đầy đủ trạng thái.

### PR-F: Tái lập và đánh giá

Đóng R12–R14 theo phạm vi MVP; khóa môi trường, rules và nhãn; chạy pilot rồi khóa protocol/main run. Không dùng benchmark để bù cho lỗi false clean chưa sửa.

## 8. Ma trận test còn cần bổ sung

| Luồng | Ca tối thiểu | Kết quả kỳ vọng |
|---|---|---|
| CLI check | changes thật, engine fail, before-release fail | Không AttributeError; lỗi/incomplete không exit 0 |
| Semgrep | File parse error và error không có path | Status/coverage phản ánh đúng ảnh hưởng |
| Shared policy | `[{}]`, ID bịa, sai file/dòng, thiếu source/sink | Không supported; giải thích field thiếu |
| check_fix | File biến mất, scope rỗng, rename, helper mới, ID lạ | Không tự resolved; scope/lifecycle có căn cứ |
| CLI fix | Finding không đổi qua instance mới | Không coi là regression |
| CLI apply/rollback | User sửa giữa các bước | Không ghi đè; báo conflict |
| Editor mode | Gọi tất cả tool cho phép khi không có key | Không model request backend |
| MCP transport | scan → read → submit → sửa → check_fix | Contract đúng, stdout chỉ protocol, giữ snapshot/audit |
| Host hook | Nhiều edit, snapshot không đổi, no-progress | Debounce/lock, tối đa hai vòng, không lặp |
| Reporting | partial/failed/refuted/stale | Không static clean, không mất evidence/assessment |
| Cache | Đổi prompt/endpoint/helper, concurrent writers | Invalidate và ghi nhất quán |
| Demo Python | Input hợp lệ + payload nguy hiểm đã rà | Giữ chức năng và kiểm tra bảo mật đều pass |

Các probe bổ sung của phiên này chưa được commit thành test. Cần biến từng probe thành regression test khi sửa, kèm ca đối chứng hợp lệ để tránh giải pháp chỉ từ chối mọi kết luận.

## 9. Mốc hoàn thành nên nhắm tới

**Một project demo Python với luồng thật: sửa code → scan đúng snapshot/scope → đọc evidence → submit assessment → sửa → check_fix → xem lại audit.**

Demo phải có ít nhất ba nhánh: xử lý thành công, snapshot stale và engine failure. Bằng chứng bàn giao gồm transcript MCP/editor, JSON có coverage/snapshot/evidence, test chức năng/security và môi trường tái lập. Khi đó mới có cơ sở đóng các gate phần mềm trước khi chuyển sang kết luận nghiên cứu.

Tại commit được review, kết luận chính xác là: **nền kiến trúc đã tiến bộ và bộ regression hiện có pass; các luồng đầu-cuối vẫn cần sửa các lỗi đã tái hiện và bổ sung bằng chứng nghiệm thu.**
