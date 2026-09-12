# Nhận xét codebase VulnAgent so với kế hoạch

## Review manifest/cold-cache và runbook — cdd757c (13/09/2026)

**Có thêm artifact metadata và runbook, nhưng chưa thể nghiệm thu tính tái lập hoặc demo editor theo tài liệu mới.** Review source, chạy thử CLI eval/Semgrep thật trên dataset tạm, thử hai lệnh trong runbook và chạy suite. Các kết luận đóng G602–G604 trước đó vẫn giữ nguyên.

### Đã làm được

- --cold/--no-cache được truyền xuống ScanOptions.use_cache=False; đường cache của analyzer trả None khi tắt nên không đọc/ghi cache phân tích qua đường này. Không gọi model thật trong review để đo variance/latency.
- Output JSON bổ sung hash labels/samples, platform/Python, raw findings, cache counters, timing và protocol. Đây là bước chuẩn bị pilot có ích, nhưng metadata phải phản ánh cấu hình thực chạy.

### M01 — P1: Manifest rules không phản ánh rules thực thi

main luôn hash ROOT/rules/pinned_security_rules.yaml. Scanner lại dùng config mặc định p/python,p/security-audit hoặc VULNAGENT_SEMGREP_RULES. Probe chạy eval CLI thật với --only semgrep --cold, dataset tạm và env trỏ custom_rules.yaml (bản rules local có thêm comment): run completed/exit 0, nhưng manifest.rules.sha256 khác hash của rules thực dùng và path vẫn chỉ pinned_security_rules.yaml. Lần chạy mặc định cũng chưa được ép dùng file pinned.

Sửa: chốt config hiệu lực trước scan và truyền cùng đối tượng config cho Scanner và manifest; lưu danh sách rules thực cùng hash/version tương ứng từng engine, không gán hash file fixture chưa chạy. Nếu dùng registry phải snapshot/pin rules thực cho thí nghiệm tái lập. Ghi engine versions, model/provider/prompt/policy/config cần thiết (không ghi secrets). Hash input/config trước chạy và đối chiếu sau chạy nếu có thay đổi, tránh mô tả snapshot cuối như input đã phân tích.

Trong cùng probe gọi script tuyệt đối từ cwd tạm, environment.git trả commit=unknown vì _get_git_info chạy Git ở cwd. Sửa Git provenance để truy vấn ROOT của VulnAgent, phân biệt riêng revision dataset/target. Regression cần rules override khác hash và chạy từ cwd khác, assert manifest khớp cấu hình thực và commit công cụ.

### D01 — P1: Runbook chưa chạy được theo lệnh và expected output

- `python -m cli.editor_integration configure --editor vscode --workspace .` không có module tương ứng; probe exit 1. CLI hiện có init/doctor/hook, không có package cli.editor_integration. Cần viết đúng luồng cấu hình mà code hỗ trợ, chọn một host để nghiệm thu trước; không suy ra có VS Code configure CLI nếu chưa triển khai.
- `python src/cli.py history --limit 5` bị parser từ chối, exit 2, vì không có subcommand history. Nếu cần history dùng public MCP tool theo đúng session/scan_id và ghi rõ transport, hoặc bổ sung CLI trước khi hướng dẫn.
- Rules pinned hiện chỉ có eval và subprocess.call(shell=True). Mẫu examples/vulnerable_app.py dùng subprocess.check_output và các sink SQL/XSS/path traversal; không thể kỳ vọng bốn CWE ghi trong runbook từ bộ rules này. Runbook cũng chưa có bước nối rules env/config vào process editor. Chọn mẫu khớp rules và kiểm tra thực engine output, hoặc khóa rules đủ bao phủ mẫu rồi ghi cấu hình hiệu lực.
- _run_hook hiện in Hook status, không triển khai editor diagnostics/resolved_findings như expected output mô tả. Log/state của runner nằm .vulnagent-audit, không phải .vulnagent-jobs. Ví dụ command trong runbook thiếu --trailing và explicit target so với luồng cần thử. Không dùng trạng thái scanner thay cho bằng chứng diagnostics được cập nhật trên host.

Sửa runbook theo flow thực có: môi trường/dependency cụ thể, lệnh đã smoke, rules/mẫu phù hợp, target và trailing rõ, output/log đúng contract. Sau đó thực hiện save/fix/rescan trên editor thật và lưu bằng chứng. Review này không thao tác editor, không sửa file mẫu thật và không chạy server ứng dụng.

### M02 — P2: Nhãn warm chưa chứng minh cache đã được làm nóng

Code đặt cache_mode=warm chỉ từ use_cache=True. Lần chạy đầu trên cache rỗng cũng được ghi warm. --cold hiện là cache disabled, không phải khởi tạo cache rỗng rồi ghi cache để lần tiếp theo đo warm. Điều này có thể dùng làm protocol no-cache, nhưng phải đặt tên/diễn giải chính xác.

Sửa: phân biệt cache_enabled/disabled với trạng thái workload cold/warmed; ghi cache namespace, prewarm procedure và hit/miss thực. Nếu đo cold→warm, dùng cache trống riêng cho lượt đầu có ghi, rồi chạy cùng input/config cho lượt warm và kiểm tra hits. Nếu chỉ so no-cache với cache-enabled thì ghi đúng hai chế độ đó. Không mở rộng kết luận thành toàn bộ cache Semgrep/model/OS đều cold từ một flag analyzer.

### Kiểm thử và bước tiếp theo

- `python -m pytest tests -q -ra`: **113 passed, 1 warning, 97.82 giây**, không có skip được báo.
- Probe CLI eval với Semgrep thật, rules override và cwd tạm: completed/exit 0 nhưng manifest sai rules hash và git commit unknown như M01.
- Hai lệnh runbook không tồn tại đã được chạy để xác minh lỗi parser/module; không có thao tác configure thành công hoặc thay đổi cấu hình editor thật.

Ưu tiên M01 và D01 trước pilot/demo; hoàn thiện M02 trước so latency cold/warm. Manifest/runbook hiện là bản chuẩn bị, chưa phải bằng chứng G6/G7 đã đạt. Review chỉ cập nhật tài liệu, không sửa code và không ghi đè kết quả benchmark của người dùng.

## Review G602–G604 — e6fccae (13/09/2026)

**Bản sửa xử lý các ca G602–G604 còn mở ở lượt review 9518656.** Kết luận đóng bên dưới giới hạn ở những lỗi cụ thể đã báo; không đồng nghĩa toàn bộ G6/G7 đã nghiệm thu. Các phần dưới là lịch sử.

### Bằng chứng kiểm chứng

- **G602 — status/coverage Bandit:** đã đọc payload.errors, phân biệt failed/degraded, giữ lỗi và số file thất bại; lỗi subprocess/schema cơ bản có RunRecord failed. Probe ngoài suite chạy CLI eval với Bandit thật và xuất JSON: một file hợp lệ cho exit 0, completed, coverage 1/1; đổi file thành lỗi cú pháp cho exit 1, failed, coverage 0/1, files_failed=1, completion_rate=0, precision=null và lỗi AST được lưu. Đây là kiểm tra xuyên qua adapter → metrics → JSON → exit code.
- **G603 — relative path Bandit:** samples_dir được resolve tuyệt đối trước khi gọi engine; đường dẫn findings được chuyển về tương đối dataset. Regression mới chạy Bandit thật qua absolute và relative input, kiểm tra cùng tập project_a/app.py và project_b/app.py, không ghép prefix hai lần. Engine Bandit có mặt trong môi trường review nên nhánh kiểm tra này được thực thi.
- **G604 — metadata tái lập:** prepare_securityeval.build sinh partial_labels=True trong labels.json; test dựng source fixture, gọi build rồi load_dataset và match, assert precision/F1/FP là null. Không còn phụ thuộc bản labels ignored trên máy tác giả để nghiệm thu ca này. Nhãn XSS sink dòng 25 vẫn được kiểm tra trong suite.

### Kiểm thử

- `python -m pytest tests -q -ra`: **113 passed, 1 warning, 113.08 giây**, không có skip được báo.
- Probe CLI eval/Bandit thật ngoài suite đạt hai trường hợp completed và syntax-failed như mô tả trên.

### Kết luận và bước tiếp theo

Có thể đóng ba lỗi cụ thể: Bandit false-completed khi syntax error, relative-path doubling, và SecurityEval metadata chưa tái lập. Không phát hiện lại các lỗi này trong lượt review; không mở thêm finding từ giới hạn test đơn thuần.

Harness đã phù hợp hơn để chuyển sang pilot. Trước chạy thí nghiệm chính, vẫn cần khóa protocol/nhãn/splits, manifest hash/version/config, raw artifacts, policy degraded/uncertain và cold/warm theo plan. Demo on-save trên host thật và cài mới G7 vẫn là nghiệm thu riêng, chưa được thực hiện ở lượt này. Không dùng 113 tests để tuyên bố độ chính xác detector hoặc hoàn tất toàn bộ đồ án.

Review chỉ cập nhật Nhan_xet.md; probe CLI dùng dataset/output trong thư mục tạm, không ghi đè kết quả thí nghiệm của người dùng và không gọi model.

## Review G601–G604 — 9518656 (12/09/2026)

**G601 đã sửa ca sai TP/F1; G602–G604 có cải thiện nhưng chưa đóng hoàn toàn.** Review source mới và chạy probe Bandit thật trên thư mục tạm. Không chạy model hoặc benchmark chính. Các mục phía dưới là lịch sử.

### Đã sửa

- Matching dùng maximum-cardinality bipartite matching, xử lý ca labels 10/14 và detections 12/8; regression đảo findings/labels kiểm tra TP=2, F1=1.0. Lưu ý tie-break hiện dùng chỉ số i/j đầu vào, chưa bảo đảm cùng danh tính cặp ghép khi có nhiều phương án bằng nhau; phân biệt bất biến tổng TP với bất biến cặp ghép.
- RunRecord giữ status/errors/raw findings; bảng giữ cả baseline rỗng và failed/skipped; metrics failed bị bỏ trống thay vì chấm như completed.
- VulnAgent giữ relative path có thư mục trong ca regression hai project cùng basename. Nhãn XSS mặc định đã chuyển từ dòng 21 sang sink dòng 25. FP breakdown đã tách các nhóm trong ca line-level đầy đủ nhãn.

### G603 — P1 còn ở Bandit: đường dẫn tương đối bị ghép hai lần

`eval/run_eval.py:584` nối samples_dir vào mọi filename tương đối do Bandit trả. Khi chạy `run_bandit(Path('tmp...'))`, Bandit đã trả `tmp.../app.py` tương đối cwd; adapter biến thành đường dẫn dưới `tmp.../tmp.../app.py`, rồi detection.file còn `tmp.../app.py` thay vì `app.py`.

Probe engine thật: repo tạm tương đối có app.py dùng subprocess.call; RunRecord completed nhưng cả hai detections đều có prefix tên thư mục tạm trong file identity. Nhãn app.py sẽ không match. Nhánh `--dataset eval/dataset` cũng có thể đi qua kiểu input tương đối này; regression hiện chỉ kiểm tra conversion của VulnAgent, chưa kiểm tra output Bandit thật.

Sửa: resolve samples_dir tuyệt đối trước khi truyền vào Bandit, rồi chuẩn hóa filename theo contract/cwd của subprocess; chỉ nhận file trong dataset và trả relative path một lần. Regression chạy cùng dataset qua absolute/relative input, assert cùng detections/path/metrics, thêm hai thư mục có cùng basename.

### G602 — P1 còn ở Bandit: bỏ qua lỗi từng file và báo coverage sai

`run_bandit` kiểm tra returncode/JSON nhưng không đọc payload.errors, rồi luôn trả completed; files_scanned đếm file trên đĩa thay vì file thực sự phân tích. Probe Bandit thật với broken.py chứa `def broken(:`: harness trả **completed, errors=[], files_scanned=1**. Đây là ca lỗi cú pháp bị biến thành lượt completed rỗng.

Sửa: lưu payload.errors, file statuses và coverage thực tế; lỗi parse phải failed/degraded theo policy, không completed. Bắt cả lỗi khởi chạy subprocess và kiểm tra schema output. Regression cần Bandit thật hoặc payload chuẩn có errors + results=[]; xác minh JSON/table/exit code không thể hiện lượt đó là thành công hoàn chỉnh. Với degraded, tài liệu cần chốt rõ metrics có tính trên toàn bộ tập hay không và báo tỷ lệ hoàn tất; không dùng degraded như completed không điều kiện.

### G604 — P2: thay đổi SecurityEval chưa tái lập qua repository

eval/datasets/securityeval/labels.json bị gitignore, không có trong git ls-files của commit. eval/prepare_securityeval.py vẫn không sinh partial_labels=True. Khi sinh mới corpus, loader mặc định False; main chỉ in lời nhắc recall-only, vẫn truyền False vào match nên precision/F1 vẫn có thể được tính. Test kiểm tra file nếu tồn tại nên có thể bỏ qua kiểm tra này trên checkout sạch.

Sửa script prepare để sinh partial_labels=True đúng protocol; test tạo corpus fixture bằng script rồi load metadata và assert precision/F1=null. Không phụ thuộc dataset ignored tồn tại trên máy tác giả. Giữ test nhãn XSS tracked đã sửa. Các yêu cầu validate label nằm trong dataset/file tồn tại hiện mới cảnh báo; cần hoàn thiện trước chạy tập chính.

### Kiểm thử và kết luận

- `python -m pytest tests -q -ra`: **113 passed, 1 warning, 94.15 giây**, không có skip được báo.
- Hai probe Bandit thật ngoài suite tái hiện sai relative path và false-completed trên file syntax error như mô tả trên.

Không coi bốn regression pass là đã bao phủ các adapter engine thực tế. Ưu tiên hai nhánh Bandit và metadata generator, rồi chạy smoke có manifest/raw artifacts trước khi khóa protocol G6. Timestamp/exact_cwe trong manifest là bước đầu; các hash/version/config/cold-warm và nghiệm thu editor/G7 vẫn theo checklist trước. Review chỉ cập nhật tài liệu; probe dùng thư mục tạm và không để lại thay đổi code/dataset.

## Review demo và harness G6/G7 — HEAD f4b4aaa (12/09/2026)

**Có bộ mẫu và harness smoke, nhưng chưa đủ để nghiệm thu G6/G7 hoặc công bố kết quả đánh giá.** Workspace sạch trước review; HEAD f4b4aaa chỉ cập nhật tài liệu so với 206fe33. Không thấy commit code mới cho ba file người dùng nêu; review dựa trên eval/run_eval.py, eval/dataset/labels.json, eval/dataset/samples/vulnerable_app.py và examples/vulnerable_app.py đang có. Đã hỏi người dùng về commit/đường dẫn kịch bản mới nếu có.

### Findings cần sửa trước chạy thí nghiệm chính

**G601 — P1: Matching phụ thuộc thứ tự findings (`eval/run_eval.py:255`).** Probe cùng file/CWE, labels ở dòng 10 và 14, detections ở 12 và 8, tolerance=3: thứ tự [12,8] cho TP=1/FP=1/FN=1, F1=0.5; đảo thành [8,12] cho TP=2/FP=0/FN=0, F1=1.0. Greedy claim nhãn đầu tiên bỏ lỡ matching đầy đủ. Sửa bằng matching một-một tối đa trên tập cạnh hợp lệ; chốt tie-break theo khoảng cách/anchor và ID ổn định. Regression phải bất biến khi đảo detections/labels, gồm hai sink sát nhau. Chỉ sort đầu vào giúp lặp lại nhưng chưa giải quyết việc mất matching hợp lệ.

**G602 — P1: Mất trạng thái chạy và loại bỏ baseline rỗng.** run_vulnagent chỉ trả findings/time (`run_eval.py:354–360`), bỏ status/degraded/coverage/errors. Probe scanner trả failed=True theo status='failed', degraded=True và findings=[] vẫn được match thành bảng metric thông thường (TP=0, FN=2, F1=0), không có dấu vết failure. run_bandit trả [] cho thiếu engine/lỗi parse; main còn bỏ hẳn dòng Bandit khi detections rỗng (dòng 512), kể cả engine chạy thành công nhưng không phát hiện gì. Sửa: RunRecord có status, coverage, errors, elapsed và detections; giữ mọi configuration đã chọn trong output, phân biệt completed-empty/failed/skipped. Chốt và báo riêng tỷ lệ hoàn tất, policy xử lý failed/incomplete; exit code phản ánh lỗi thực thi. Regression cho engine failed, degraded, thiếu executable, JSON lỗi và completed-zero-finding.

**G603 — P1: Mất định danh file khi mở rộng dataset (`run_eval.py:316,394`).** Cả VulnAgent và Bandit lấy basename. Probe project_a/app.py và project_b/app.py đều thành app.py: có thể ghép nhầm nhãn hoặc bỏ lỡ nhãn dùng đường dẫn tương đối. Sửa: chuẩn hóa đường dẫn tương đối samples_dir cho cả labels/detections, giữ thư mục, kiểm tra nằm trong dataset; validate labels trỏ file tồn tại. Regression hai file cùng basename ở hai project.

**G604 — P2: Protocol/labels chưa thống nhất với phép đo.** labels.json nói nhãn là sink nhưng XSS ghi dòng 21 (tạo template), render_template_string ở dòng 25, ngoài tolerance ±3. Rà/chốt sink trước đo. SecurityEval metadata nói recall-only nhưng không đặt partial_labels; main chỉ in cảnh báo còn match vẫn tính precision/F1 khi partial_labels=False. Sửa policy vào dữ liệu và output, để precision/F1 null khi không có ground truth đủ. Không tự coi mọi file không có label là known-clean; truyền clean_files rõ ràng vào matcher. fp_wrong_type hiện còn gom cả duplicate/wrong-line cùng file và có thể âm với partial labels; cần phân nhóm theo lý do thật.

### Những gì còn thiếu để gọi là G6/G7

- Bộ mặc định có 11 nhãn, phù hợp smoke/regression theo plan. Mẫu chứa comments tiết lộ đáp án như SQL Injection vulnerability; trước chạy model chính cần input trung tính, mapping labels riêng, split theo family/project, hash/manifest và nhãn đã rà. Không dùng số lượng mẫu đơn thuần để bảo đảm ý nghĩa thống kê.
- JSON output mới có metrics tổng hợp và missed/spurious; chưa lưu đủ raw findings/assessment/status/coverage, hash dataset/rules, engine/model/prompt/config, exact-CWE mode và thông tin cache để tái lập. use_cache=True cố định cũng chưa phân biệt cold/warm. Bổ sung manifest/protocol và các chỉ số verification/uncertain/citation/budget mà mục 10 của plan yêu cầu. Đây là yêu cầu trước thí nghiệm chính, không cần gọi model thật để kiểm thử harness.
- Trong các Markdown được tìm thấy chưa có kịch bản thao tác editor mới. Có vulnerable_app.py không thay thế demo save: cần ghi host/version/dependency/đường cấu hình, bước init, save, expected feedback, save khi scan đang chạy, sửa rồi rescan và log kết quả. Chưa mở editor hoặc chạy app server trong review này.
- G7 cần tài liệu khớp hành vi, dependency/version, lệnh cài mới và artifacts chạy lại được. README eval hiện chưa thể coi là protocol G6/G7 hoàn chỉnh. Các kết luận đóng E05 trước đó vẫn giữ nguyên.

### Phạm vi kiểm chứng và bước tiếp theo

Đã đọc source/labels/plan và chạy ba probe cục bộ: order-dependent matching, failed-run scoring và basename collision. Probe failure dùng scanner giả lập để kiểm tra harness, không phải kết quả benchmark Semgrep/LLM. Không chạy lại suite 109 tests vì không sửa code và không tìm thấy tests matcher eval trong tests; không công bố lần chạy 109 mới. Không gọi model, không chạy benchmark registry hay ghi đè kết quả thí nghiệm.

Ưu tiên G601–G603, chuẩn hóa G604, rồi chạy một smoke Semgrep với rules/config được ghi rõ và xuất manifest/raw results; sau đó mới khóa protocol và chạy thí nghiệm chính. Nếu có kịch bản hoặc harness mới chưa nằm trong HEAD này, cần review đúng bản đó trước khi dùng kết luận để nghiệm thu. Lượt này chỉ cập nhật Nhan_xet.md.

## Cập nhật mới nhất — 206fe33 (12/09/2026)

**Có thể đóng E05 trong phạm vi các ca lỗi đã ghi nhận và tái hiện ở các lượt trước.** Nhánh suy đoán quyền sở hữu từ `python -m cli hook --files/--target` đã được bỏ. Các mục E05 mở ở phần lịch sử bên dưới được thay thế bởi kết luận này.

### Bằng chứng kiểm tra lại

- Probe tạo repo tạm với cli.py riêng; chạy `python -m cli hook --files app.py` từ repo đó, không có PYTHONPATH: exit 0, output OTHER_PROJECT_CLI. Sau configure, command này được giữ nguyên.
- Cùng probe giữ nguyên command launcher tuyệt đối của OtherProject và `python tools/cli.py lint`. Chạy configure hai lần: cả ba command người dùng vẫn còn nguyên, entry ID vulnagent-on-save chỉ có một, lệnh cũ có ID được thay bằng launcher hiện tại.
- Regression đã đổi kỳ vọng đúng: command module chưa xác minh được giữ, entry có ID được cập nhật. Các ca JSONC/string, tasks/settings và git-hook của E05 vẫn nằm trong suite.

### Kiểm thử

- `python -m pytest tests -q -ra`: **109 passed, 1 warning, 117.46 giây**, không có skip được báo.
- Probe E05 ngoài suite đạt các kiểm tra bảo toàn command và cập nhật idempotent như mô tả trên.

### Trạng thái so với plan

Không phát hiện lại các lỗi E05 đã báo trong phạm vi review này; không mở thêm finding chỉ từ giới hạn kiểm thử. Giữ kết luận E02 launcher độc lập và E06 ngân sách fix đã sửa. Đây là nghiệm thu các lỗi cụ thể, chưa phải khẳng định mọi trường hợp shell/migration hay toàn bộ plan đã hoàn tất.

Bước tiếp theo là demo trigger on-save trên một editor thật: save tự gọi hook, phản hồi kết quả, save liên tiếp và save trong lúc scan; kiểm tra riêng contention dài/đa file còn được ghi ở E03. Sau đó nghiệm thu G6/G7 bằng protocol, dataset, baseline, raw results và quy trình cài mới. Không cần tiếp tục mở rộng migration để chuyển sang các bước này.

Review chỉ cập nhật Nhan_xet.md; các probe dùng thư mục tạm, không sửa code/cấu hình thật và không gọi model.

## Cập nhật mới nhất — dead210 (12/09/2026)

**Ca launcher tuyệt đối khác dự án đã sửa; E05 còn mở ở fallback `python -m cli`.** Không mở rộng phạm vi review: đây vẫn là yêu cầu bảo toàn command chưa xác minh được quyền sở hữu. Các phần phía dưới là lịch sử.

### Đã xác minh

- Command `python C:/OtherProject/src/cli.py hook --check` không còn bị nhận là VulnAgent. Regression mới kiểm tra giữ command này và command echo chỉ nhắc launcher, kể cả sau configure hai lần.
- Nhánh script dùng token và đối chiếu đường dẫn với launcher hiện tại, tốt hơn regex tên file trước đó. Giữ nguyên kết luận tokenizer, launcher độc lập và fix budget ở các lượt trước.

### E05 — P1: fallback module vẫn xóa command của dự án khác

Trong `_is_vulnagent_save_command`, nhánh `-m cli hook` trả True khi thấy workspaceFolder, --target hoặc --files; nhánh này trả về trước phần kiểm tra đường dẫn launcher. Các tham số đó không chứng minh module cli thuộc VulnAgent.

Probe tái hiện đầy đủ: tạo repo tạm có cli.py riêng in `OTHER_PROJECT_CLI`, cấu hình command `python -m cli hook --files app.py`. Chạy Python hiện tại với cùng args từ repo tạm, không có PYTHONPATH: exit 0, output OTHER_PROJECT_CLI. Sau configure_editor_save_hook, command biến mất khỏi settings. Như vậy không chỉ là trường hợp giả định trùng tên: module thực thi đã được kiểm tra là module khác.

**Cách sửa gọn nhất:** bỏ tự nhận quyền sở hữu cho entry không có ID dùng `-m cli`, giữ nguyên command này. Chỉ tự thay entry có ID VulnAgent hoặc lời gọi script đã xác minh đường dẫn. Nếu muốn migrate module cũ tự động, phải có bằng chứng bổ sung về bản cài/môi trường thực thi; không thay bằng thêm heuristic tên flag. Không import/chạy module không rõ nguồn chỉ để kiểm tra trong init.

Regression hiện tại đang yêu cầu xóa command `python -m cli hook --target ...` không có ID; cần đổi kỳ vọng sang giữ entry chưa xác minh, hoặc bổ sung bằng chứng sở hữu cho fixture đó. Thêm repo có cli.py riêng như probe, assert command còn nguyên sau hai lần configure và hook ID mới không bị nhân đôi.

### Kiểm thử và kết luận

- `python -m pytest tests -q -ra`: **109 passed, 1 warning, 53.75 giây**, không có skip được báo.
- Probe ngoài suite: launcher tuyệt đối khác dự án được giữ; command module cli riêng vẫn bị xóa như mô tả trên.

Chưa đóng toàn bộ E05. Chỉ cần xử lý nhánh module còn lại trong phạm vi finding này; chưa có lý do thay tokenizer hay đổi hướng Python + Semgrep. Nghiệm thu editor thật và các gate thí nghiệm vẫn tách riêng như các review trước. Lượt này chỉ sửa Nhan_xet.md; probe dùng thư mục tạm, không sửa code/cấu hình thật hoặc gọi model.

## Cập nhật mới nhất — bfb7163 (12/09/2026)

**Tokenizer sửa được lỗi thay đổi chuỗi; E05 còn mở ở nhánh nhận diện command legacy.** Review chỉ tập trung thay đổi mới và hai ca E05 trước đó. Các phần dưới là lịch sử.

### Đã xác minh

- `_clean_jsonc` tách string literal khỏi dấu phẩy cấu trúc. Probe round-trip giữ nguyên `a,}`, `b,]`, URL, quote và backslash. Regression mới kiểm tra thêm comment markers và trailing comma trong list.
- Command `python tools/cli.py lint` và command echo nhắc chữ VulnAgent được giữ nguyên. Entry mới có ID ổn định; fixture migration và cấu hình lặp lại đã được bổ sung.
- Không thay đổi kết luận đã đóng lỗi launcher E02 và hard budget E06 của lượt trước.

### E05 — P1: legacy pattern vẫn xóa nhầm command của dự án khác

Trong `_is_vulnagent_save_command`, regex legacy khớp đường dẫn bất kỳ kết thúc `/src/cli.py` rồi tới `hook`; không xác minh đường dẫn đó thuộc VulnAgent. Probe trên settings tạm có ba commands: `python tools/cli.py lint`, `python C:/OtherProject/src/cli.py hook --check`, và `echo keep-me vulnagent`. Sau configure, command thứ hai bị xóa; hai command còn lại được giữ. Đây vẫn là lỗi mất cấu hình do suy đoán quyền sở hữu từ tên file/subcommand.

Sửa: ưu tiên ID sở hữu rõ ràng. Với entry chưa có ID, chỉ tự migrate khi executable/launcher và cấu trúc lệnh khớp bản cài VulnAgent đã biết; không coi mọi src/cli.py hook là VulnAgent. Nếu không xác minh được launcher cũ thì giữ command và báo migration chưa xác định, thay vì xóa. Nhánh current_launcher cũng nên parse lời gọi thực tế thay vì chỉ kiểm tra launcher xuất hiện ở đâu đó trong text và có chữ hook.

Nghiệm thu: giữ nguyên command ở đường dẫn dự án khác, command echo chỉ in đường dẫn launcher, và command tools/cli.py; chỉ thay entry ID của VulnAgent hoặc launcher đã xác minh. Chạy configure hai lần, assert từng command người dùng còn nguyên và không nhân đôi entry do VulnAgent sở hữu. Không cần thay tokenizer thêm để xử lý finding này.

### Kiểm thử và kết luận

- `python -m pytest tests -q -ra`: **109 passed, 1 warning, 62.41 giây**; không có skip được báo.
- Probe ngoài suite xác nhận string round-trip và hai command cũ được giữ, nhưng command của OtherProject bị xóa. Chỉ dùng thư mục tạm.

Chưa đóng toàn bộ E05 vì probe trên còn lỗi. Giữ nguyên hướng Python + Semgrep; sau khi thu hẹp migration, tiếp tục nghiệm thu trigger on-save trên editor thật và G6/G7 theo plan. Lượt này chỉ cập nhật Nhan_xet.md, không sửa code/cấu hình thật và không gọi model.

## Cập nhật mới nhất — 325ada9 (12/09/2026)

**Review E02, E05, E06: launcher đã sửa; hard budget đã có; E05 chưa đóng hoàn toàn. 108/108 tests pass.** Các phần phía dưới là lịch sử review.

### Đã xác minh và có thể đóng

- **E02, lỗi import launcher:** task và save command cùng dùng đường dẫn tuyệt đối tới src/cli.py; cli.py tự thêm thư mục src vào sys.path. Test mới chạy launcher từ cwd khác, không có PYTHONPATH. Điều này sửa lỗi No module named cli của lượt trước; không đồng nghĩa đã nghiệm thu trigger trong editor thật.
- **E06, vượt ngân sách auto-fix:** fixes_attempted nằm ngoài vòng while, chỉ tăng, bị chặn ở max(0, max_rounds - 1). Snapshot sau patch được chụp trước rescan; sửa của fixer không còn tự động cấp lại ngân sách. Regression mới kiểm tra finding không giảm, fixer đổi file, trailing=True: chỉ một lần fix với max_rounds=2 và kết thúc no_progress.
- **E05, các ca cũ:** bỏ ghi pre-commit; giữ setting editor.tabSize, tùy chọn Run On Save và command eslint trong fixture; file không parse được được giữ lại. Hai lần cấu hình không nhân đôi task/command trong ca test hiện có.

### E05 — P1 vẫn mở: hai ca làm mất hoặc thay đổi cấu hình người dùng

**1. Parser JSONC thay đổi nội dung string (`host_adapter.py:49`).** Regex bỏ trailing comma chạy trên toàn bộ text, kể cả bên trong chuỗi. Probe trực tiếp với JSON hợp lệ cho kết quả `"a,}"` thành `"a}"` và `"b,]"` thành `"b]"`. Khi init ghi lại settings/tasks, giá trị bị đổi âm thầm. Đây là lỗi bảo toàn dữ liệu, không chỉ mất định dạng.

Sửa: dùng parser JSONC hoặc tokenizer có trạng thái string/escape/comment; chỉ bỏ dấu phẩy cấu trúc ngoài string. Nghiệm thu round-trip giữ nguyên giá trị string chứa `,}`, `,]`, quote escape, URL và comment markers; kiểm tra cả tasks và settings. json.dumps hiện cũng bỏ comments: nếu chỉ cam kết giữ giá trị, sửa docstring/test description cho đúng; nếu cam kết giữ comments thì cần chỉnh sửa JSONC có bảo toàn văn bản.

**2. Nhận diện command sở hữu bằng substring quá rộng (`host_adapter.py:235–237`).** Probe settings có command người dùng `python tools/cli.py lint` và `echo keep-me`: sau configure, lệnh lint bị xóa, chỉ còn echo và hook mới. Điều kiện chứa cli.py/vulnagent/cli hook không đủ xác định command thuộc VulnAgent.

Sửa: chỉ thay command do adapter sở hữu bằng định danh ổn định được host hỗ trợ, hoặc nhận diện chính xác launcher và cấu trúc args; migration chỉ khớp mẫu lệnh VulnAgent cũ đã biết. Giữ nguyên command không xác định được chủ sở hữu. Regression cần lệnh tools/cli.py, lệnh chỉ nhắc chữ VulnAgent, lệnh VulnAgent thực, rồi chạy configure hai lần và assert các lệnh người dùng còn nguyên.

### Giới hạn nghiệm thu host

Doctor vẫn dựa trên file/key tồn tại và launcher.is_file, chưa xác minh extension đang hoạt động hoặc editor thực sự nạp trigger. Chưa demo save từ host thật trong lượt review này. Có thể đóng lỗi launcher E02, nhưng giữ nghiệm thu host/save của G4 riêng; không gọi toàn bộ E02/editor integration hoàn tất chỉ nhờ smoke launcher. Giới hạn contention dài/đa file ở E03 của lượt trước chưa được kiểm chứng thêm trong diff này.

### Kiểm thử và kết luận

- `python -m pytest tests -q -ra`: **108 passed, 1 warning, 138.12 giây**, không có skip được báo.
- Probe lệnh hook sinh từ task: thay workspaceFolder/file bằng repo tạm, chạy từ cwd repo tạm, bỏ PYTHONPATH, truyền rules cục bộ. Kết quả **exit 0, Hook status: clean**; xác minh cả hook thực thi, không chỉ --version.
- Hai probe E05 ngoài suite tái hiện thay đổi string và xóa command người dùng như mô tả trên. Chỉ thao tác thư mục tạm.

Ưu tiên sửa hai ca E05 trên, sau đó demo host thực tế và tiếp tục G6/G7 theo plan. Không cần đổi hướng Python + Semgrep. Review chỉ cập nhật tài liệu, không sửa code, không thay cấu hình thật và không gọi model.

## C?p nh?t m?i nh?t ? 595e3cd (12/09/2026)

**Review t?p trung E01?E04 v? regression trong ph?n thay ??i. ??ng h??ng Python + Semgrep; ch?a th? ??ng to?n b? editor gate.** K?t qu? suite: **105 passed, 1 warning, 112.81 gi?y** v?i `python -m pytest tests -q -ra`; kh?ng c? skip ???c b?o. C?c ph?n d??i l? l?ch s?, kh?ng ph?i m?i l?i c? ??u c?n m?.

### Tr?ng th?i b?n m?c c?

- **E01 ??ng trong ph?m vi CLI/task:** parser ?? nh?n --target, _run_hook gi?i quy?t target_opt/positional/default. Probe parse_args ch?y th?nh c?ng. Task d?ng process v? args ri?ng, c?p nh?t task c?ng label.
- **E04 ??ng ph?n n?i rules:** detector test truy?n ???ng d?n YAML tuy?t ??i v? assert configs; stdio test truy?n VULNAGENT_SEMGREP_RULES cho c? hai process. Kh?ng c?n d?ng packs registry m?c ??nh trong hai test n?y. Ch?a ki?m tra b?ng ch?n m?ng h? ?i?u h?nh; requirements.txt v?n ch?a pin phi?n b?n Semgrep n?n ch?a g?i to?n b? m?i tr??ng t?i l?p ?? kh?a.
- **E03 ?? s?a ca contention ng?n:** regression m?i d?ng hai runner, scan ??u gi? lock, save th? hai ??i v? qu?t b?n x=2. Ch?a ?? ?? kh?ng ??nh m?i ca m?t save ?? ??ng: timeout v?n 15 gi?y, dirty.files ch?a ???c ti?u th? ?? h?p nh?t ph?m vi; c?n ki?m tra scan d?i v?i save sang file kh?c. ??y l? gi?i h?n ch?a t?i hi?n trong l??t n?y, kh?ng g?n th?m P1 ch? t? suy ?o?n.
- **E02 v?n m?:** c? t?o settings cho extension Run On Save, nh?ng ???ng th?c thi ??c l?p c?a save command ch?a ch?y ???c trong m?i tr??ng target ngo?i source; xem b?n d??i.

### Findings c?n x? l?

**E02 ? P1: Save command thi?u m?i tr??ng import; khai b?o trigger th?nh c?ng qu? s?m.**

`src/integrations/host_adapter.py:191` t?o l?nh ri?ng cho emeraldwalk.runonsave; l?nh n?y kh?ng ch?y task ?? c? PYTHONPATH ? options.env. Probe ch?y ch?nh Python hi?n t?i v?i `-m cli hook --target <repo t?m> --trailing`, cwd ? repo t?m v? kh?ng c? PYTHONPATH: exit 1, `No module named cli`. V? v?y s?a task process ch?a s?a ???ng on-save ??c l?p. Code c?ng kh?ng ki?m tra extension hi?n di?n/???c b?t nh?ng tr? trigger_configured=True; doctor ch? ki?m tra tasks.json t?n t?i.

Theo [README ch?nh th?c Run On Save](https://github.com/emeraldwalk/vscode-runonsave), ??y l? ch?c n?ng c?a extension, c?u h?nh ph?i n?m trong user/workspace settings. Extension c?ng ghi r? t?o file m?i v? Save As kh?ng k?ch ho?t command. Ch?a demo host th?t trong l??t review n?y; kh?ng coi file .cursor/settings.json t? ch?ng minh editor ?? n?p c?u h?nh.

S?a: d?ng m?t launcher th?ng nh?t cho task/save, c? module path ho?c package c?i ??t ???c, ch?y ???c t? cwd b?t k?. X?c minh v? tr? workspace settings m? host th?c s? ??c; khai b?o dependency extension, doctor ki?m tra dependency/config/launcher v? ph?n bi?t configured v?i verified. Nghi?m thu l?nh sinh ra b?ng subprocess kh?ng k? th?a PYTHONPATH, r?i demo save tr?n host th?t; m? t? ho?c x? l? ri?ng new file/Save As.

**E05 ? P1: Init ghi ?? c?u h?nh/hook c? s?n (?? t?i hi?n tr?n th? m?c t?m).**

`src/integrations/host_adapter.py:189` ??t settings={} khi json.loads th?t b?i; file settings c? comment s? m?t n?i dung c?. Probe v?i editor.tabSize=8 v? comment: sau configure, key c? bi?n m?t. Ngay c? JSON chu?n, g?n to?n b? emeraldwalk.runonsave c?ng thay danh s?ch commands c?. `host_adapter.py:211` lu?n write_text v?o .git/hooks/pre-commit: probe hook c? existing-check b? thay ho?n to?n. ??y l? t?c d?ng ph? m?i ???c g?i t? init Cursor, c? th? l?m m?t b??c ki?m tra commit c?a d? ?n.

S?a: b? vi?c t? c?i pre-commit kh?i c?u h?nh on-save; n?u cung c?p t?nh n?ng Git hook th? d?ng lu?ng c?u h?nh ri?ng v? b?o to?n hook ?? c?. V?i settings/tasks, h? tr? JSONC ho?c d?ng ghi khi kh?ng parse ???c, b?o to?n n?i dung; merge ri?ng command do VulnAgent s? h?u v? gi? commands ng??i d?ng. Regression c?n settings c? comment/trailing comma, commands c? s?n, pre-commit c? s?n, v? ch?y init hai l?n kh?ng ??i ph?n ngo?i VulnAgent.

**E06 ? P1: Trailing c? th? l?p auto-fix v??t max_rounds (?? t?i hi?n).**

`src/integrations/host_adapter.py:641` so snapshot sau fix v?i snapshot tr??c fix r?i continue; ch?nh patch h?p l? c?ng l?m hai snapshot kh?c nhau. V?ng while t?i d?ng 562 ??t l?i round_num=1 ? m?i l??t. Khi fixer li?n t?c ??i file nh?ng finding v?n gi? nguy?n, nh?nh no_progress ph?a sau b? b? qua v? gi?i h?n max_rounds=2 kh?ng ch?n c?c l?n fix ti?p theo.

Probe: max_rounds=2, trailing=True; scanner lu?n tr? c?ng finding; fixer m?i l?n ??i x trong file. Fixer b? g?i t?i l?n th? 3; probe ch? ??ng raise ?? d?ng, runner tr? fix_failed v?i rounds=2. Kh?ng ph?i th? nghi?m LLM th?t v? kh?ng s?a file d? ?n. Suite hi?n t?i ch?a bao ph? k?t h?p trailing + fix thay n?i dung + finding kh?ng gi?m.

S?a: gi? ng?n s?ch fix cho to?n invocation, kh?ng reset theo v?ng qu?t pending. Ghi snapshot ngay sau patch v? tr??c rescan ?? ph?n bi?t thay ??i c?a fixer v?i edit b?n ngo?i; ??nh gi? no_progress sau rescan tr??c khi c?n nh?c th?m fix. Pending save c? th? c?n scan m?i nh?ng kh?ng t? c?p l?i ng?n s?ch s?a. Regression ph?i ch?ng minh finding kh?ng gi?m k?t th?c no_progress, patch s?ch k?t th?c clean, v? save ??ng th?i kh?ng v??t ng?n s?ch auto-fix.

### K?t lu?n theo plan

E01 v? ph?n n?i rules E04 c? th? ??ng. E02 ch?a ??t, E03 c? c?i thi?n nh?ng xu?t hi?n E06 ? nh?nh auto-fix. ?u ti?n E05 b?o to?n c?u h?nh, E06 gi?i h?n v?ng s?a, r?i ho?n thi?n E02 v? demo host. Ch?a d?ng s? tests ?? k?t lu?n to?n b? G4?G7 ho?n t?t; G6 v?n c?n b?ng ch?ng dataset/protocol/raw results ri?ng. Review n?y ch? s?a Nhan_xet.md, kh?ng thay m? ngu?n ho?c c?u h?nh th?t, kh?ng g?i model.


## C?p nh?t m?i nh?t ? fe9a17d (11/09/2026)

**?? ch?y `python -m pytest tests -q -ra`: 104 passed, 1 warning, 199.44 gi?y; kh?ng c? skip ???c b?o. ??ng h??ng Python + Semgrep, nh?ng ch?a ??ng h?t h?ng m?c editor v? t?i l?p offline.** C?c m?c ph?a d??i l? l?ch s? review; k?t lu?n m?i ? ??y thay th? nh?n x?t c? trong c?ng ph?m vi.

### ?? x?c minh

- Marker integration ?? ??ng k?; Scanner nh?n `semgrep_configs`, runner nh?n override `VULNAGENT_SEMGREP_RULES`. C? hai rules Python c?c b? cho eval/CWE-94 v? subprocess.call shell=True/CWE-78. ??y l? b? rules fixture nh?, kh?ng ph?i snapshot ??y ?? hai packs m?c ??nh.
- MCP stdio test th?t ?? ki?m tra coverage completed/non-degraded v? file status; unknown scan_id; evidence gi? b? h? xu?ng uncertain; evidence h?p l? v? assessment; stale sau s?a ??a; syntax l?i; rescan sau s?a; history; server m?i kh?i ph?c history/evidence khi cwd kh?c target repo. Test n?y pass trong suite.
- Test trailing hi?n t?i x?c minh l?n g?i th? hai sau khi l?n scan ??u ?? ho?n t?t, trong c?a s? debounce. Ch?a ki?m tra save ch?ng l?n scan ?ang ch?y.

### C?c m?c c?n m? v? c?ch s?a

**E01 ? P1: Task sinh ra kh?ng ch?y ???c CLI (?? t?i hi?n).**

`src/integrations/host_adapter.py:157` sinh `python -m cli hook --target ...`, nh?ng `src/cli.py:178` ??nh ngh?a `target` l? positional. Probe tr?c ti?p `build_parser().parse_args(['hook', '--target', '.', '--files', 'sample.py', '--trailing'])` tr? SystemExit 2: `unrecognized arguments: --target`. Test hi?n ch? ki?m tra file/label n?n v?n pass.

S?a: truy?n `hook <target> --files <file> --trailing`, ho?c th?m option v? th?ng nh?t contract. ?u ti?n task type process, command l? executable v? args t?ch ri?ng ?? x? l? ???ng d?n c? d?u c?ch. Khi c?p nh?t, thay task c?ng label thay v? gi? nguy?n l?nh l?i c?. Nghi?m thu b?ng ch?nh argv sinh t? adapter qua parser v? smoke subprocess tr?n repo t?m.

**E02 ? P2: T?o task ch?a n?i s? ki?n save.**

`configure_editor_save_hook` ch? ghi tasks.json v? tr? `hook_configured=True`; kh?ng c? ??ng k? s? ki?n save/watcher. T?m tham chi?u trong src/tests ch? th?y ??nh ngh?a v? unit test, ch?a c? ???ng init g?i n?. V? v?y ch?a c? b?ng ch?ng editor t? k?ch ho?t hook; t?n task ?On-Save? kh?ng th?c hi?n vi?c ??ng k? s? ki?n.

S?a: ch?n m?t host ?? ho?n th?nh tr??c, n?i callback save ho?c watcher th?c t? v?o runner, t?ch h?p ???ng c?u h?nh trong init v? ?? doctor ki?m tra k?t n?i. Ch? tr? hook_configured khi ?? c?u h?nh c? trigger. Nghi?m thu tr?n editor th?t: save file Python t? kh?i ch?y scan, nh?n k?t qu?; save li?n ti?p v? save trong khi scan v?n kh?ng m?t b?n cu?i.

**E03 ? P1: Trailing v?n b? m?t save khi scan ?ang gi? lock (?? t?i hi?n).**

`src/integrations/host_adapter.py:408` ch? theo th?i ?i?m scan tr??c; nh?nh PermissionError cu?i run v?n tr? skipped/locked, kh?ng x?p l?ch retry. Probe asyncio c? hai l?i g?i trailing=True: scan ??u ??c `x=1`, gi? callback ?ang ch?y; s?a file th?nh `x=2` r?i g?i hook l?n hai. K?t qu?: l?n hai skipped/locked; l?n ??u clean; callback ch? ??c `x=1`, kh?ng c? scan t? ??ng cho `x=2`. D?ng debounce=0 ?? c? l?p nh?nh lock; scan ??u ch?a c?p nh?t last_run_time n?n nh?nh n?y c?ng c? th? x?y ra v?i debounce d??ng.

S?a: l?u dirty generation/pending files d?ng chung gi?a c?c process tr??c khi th? lock. Worker gi? lock ??c generation, qu?t snapshot, r?i ??i chi?u l?i generation/hash; n?u ?? c? save m?i th? l?n l?ch qu?t b?n cu?i. Gi? gi?i h?n v?ng auto-fix ri?ng v?i l?ch qu?t pending. N?u nh??ng worker, ph?i c? b?n giao/retry r? r?ng; kh?ng b? s? ki?n ch? v? lock b?n. Nghi?m thu b?ng regression d?ng asyncio.Event ho?c hai process: s?a file khi scan b? ch?n, nh? scan v? assert b?n cu?i ???c qu?t m? kh?ng c?n save th? ba; kh?ng c?ng b? clean cho n?i dung m?i d?a tr?n snapshot c?.

**E04 ? P2: Rules offline ch?a ???c n?i v?o integration tests.**

Test Semgrep th?t v?n t?o ScanOptions kh?ng truy?n semgrep_configs; stdio test t?o StdioServerParameters v?i env=None. Kh?ng t?m th?y tham chi?u pinned_security_rules.yaml trong tests/config ch?y test; phi?n review c?ng kh?ng c? bi?n VULNAGENT_SEMGREP_RULES. V? v?y ???ng m?c ??nh v?n l? p/python v? p/security-audit. C? file rules v? override ch?a ch?ng minh suite ?ang d?ng rules offline.

S?a: test detector truy?n ???ng d?n tuy?t ??i t?i YAML; stdio test truy?n VULNAGENT_SEMGREP_RULES r? r?ng v?o m?i tr??ng server c?a c? hai l?n kh?i ??ng. Assert config hi?u l?c; pin/ghi engine version v? hash rules trong manifest. Nghi?m thu hai integration test v?i registry/network kh?ng kh? d?ng, v?n completed v? kh?ng skip. C?p nh?t m? t? trong tests/conftest.py cho ??ng ph?m vi unit/integration.

### Ph?m vi nghi?m thu theo plan

G4 c? b?ng ch?ng MCP transport t?t h?n r? r?t, nh?ng lu?ng host/save ch?a ??t v? E01?E03. Ch?a g?i to?n b? plan ho?n t?t ch? t? 104 tests. Trong test stdio, ?apply valid fix? l? test tr?c ti?p write_text r?i g?i check_fix, kh?ng ph?i build_plan/apply_plan qua transport; ?i?u n?y ch?p nh?n ???c ?? ki?m tra giao th?c nh?ng c?n m? t? ??ng. Thay eval b?ng literal_eval ch?a ch?ng minh gi? h?nh vi t?nh bi?u th?c (v? d? `1+2`); kh?ng d?ng ri?ng fixture n?y ?? nghi?m thu G5 gi? ch?c n?ng. Behavioral SQL v? fixer tests ri?ng v?n c? gi? tr? trong ph?m vi ?? ghi ? c?c review tr??c.

Sau E01?E04 v? demo host, ti?p t?c ??i chi?u G6/G7 b?ng protocol/nh?n/dataset, raw results/baselines, manifest t?i l?p v? c?i m?i theo plan. Review l?n n?y kh?ng ?o ch?t l??ng detector tr?n dataset v? kh?ng g?i model th?t. Ch? c?p nh?t t?i li?u, kh?ng s?a m? ngu?n.


## Cập nhật mới nhất — b10eea8 (11/09/2026)

**103/103 test pass (50.87 giây, 1 warning), không có test skip được báo. Đã xác nhận integration sử dụng Semgrep thật và MCP stdio client/server thật trong môi trường review.** Giữ hướng Python + Semgrep theo quyết định của người dùng. Các phần dưới đây là lịch sử, không phải mọi nhận xét cũ đều còn mở.

### Những gì đã xác minh được

- Môi trường: Semgrep **1.165.0**, MCP Python package **1.23.3**.
- `test_r14_real_semgrep_detector_and_rescan_e2e_integration`: gọi Scanner.scan với Semgrep bật, LLM tắt, không mock detector/rescan; engine phát hiện finding command injection, có report completed/non-degraded. Test gán suggestion fixture, chạy build_plan/apply_plan thật rồi rescan thật, không còn findings và status completed.
- `test_r14_mcp_transport_handshake_and_stdio_e2e`: khởi động `python src/mcp_server.py` bằng stdio client; initialize, list_tools, capabilities và scan_changes được gọi qua protocol thật. Test pass, không chỉ import hàm trực tiếp.
- Behavioral SQLite test đã đổi tên/mô tả cho đúng: finding và rescan giả lập, còn runtime valid/injection và patch pipeline thực thi thật.

### Giới hạn của bằng chứng hiện tại

1. Semgrep test xác minh detector→patch fixture→rescan trên một mẫu. Suggestion `shell=True`→`shell=False` được test gán sẵn, không phải output LLM. Test chưa chạy lệnh hợp lệ trước/sau; bỏ shell không tự chứng minh giữ nguyên chức năng hay mọi cách truyền command đều an toàn. Dùng nhãn regression fixture cho mẫu này, không tổng quát thành bộ sửa command injection đã được chứng minh an toàn.
2. MCP transport test chỉ assert scan_id/snapshot_id/coverage tồn tại sau scan_changes. Một payload có coverage failed vẫn có thể đạt các assertions này. Cần assert status/degraded/file statuses/scope thực nếu muốn nghiệm thu scan thành công qua transport.
3. Chưa chạy read_evidence→submit_assessment→sửa→check_fix→history và restart/cross-cwd restore qua cùng transport client. Những phần đó có tests nội bộ riêng; chưa coi chúng là một scenario transport hoàn chỉnh.
4. Chưa demo hook được host editor tự kích hoạt hoặc xác minh trailing debounce/feedback trên host thật. CLI hook có entrypoint không đồng nghĩa editor integration đã nghiệm thu.
5. Integration đang dùng rule packs mặc định `p/python`, `p/security-audit`, chưa thấy rules snapshot khóa trong test này. Để tái lập và tránh phụ thuộc rule registry thay đổi, cần lưu/pin rules và engine; tách integration marker/dependency hướng dẫn với unit tests offline.

### Kết luận và bước tiếp theo

**Đóng thiếu sót “chưa có test detector/rescan thật” và “chưa có test MCP stdio thật” của các lượt review trước trong phạm vi hai test mới.** Không phát hiện lỗi runtime làm hai test này thất bại trong phiên review. Không mở thêm lỗi P1 chỉ dựa trên giới hạn test nêu trên.

Tiếp theo nên tăng assertions coverage của transport test, ghép một scenario đầy đủ qua stdio (gồm failure/stale), khóa môi trường/rules và thực hiện demo một host. Sau đó chuyển sang protocol/dataset/baseline/metrics theo G6. Chưa dùng 103 test pass để công bố độ chính xác detector hoặc toàn bộ G4–G7 đã đạt.

Review chỉ cập nhật tài liệu; không sửa mã nguồn và không gọi model thật. Lượt này đã chạy Semgrep thật, MCP subprocess thật và các runtime SQLite tests trong suite.

## Cập nhật mới nhất — 918c2e8 (11/09/2026)

**101/101 test pass (24.04 giây, 1 warning). Hai ca lỗi tái hiện ở lượt trước đã được chặn. Behavioral demo đã kiểm tra input hợp lệ trước/sau và áp dụng patch thật; khâu phát hiện/rescan vẫn giả lập nên chưa gọi là full scanner/host E2E.** Các phần bên dưới là lịch sử review.

### Xác minh hai bản sửa

1. **Partial gate:** probe dùng ScanResult thật `status=partial`, `degraded=False`; runner trả failed với lý do coverage incomplete, không clean. Lượt retry cùng snapshot với callback completed đi tiếp và trả clean. Không bị khóa retry bởi snapshot của lần partial.
2. **Cross-cwd restore:** lưu snapshot/session ở repo tạm, registry ở thư mục tạm qua `VULNAGENT_REGISTRY_DIR`; bỏ session khỏi RAM trong khi cwd vẫn khác repo; gọi public `read_evidence(scan_id, 'app.py', 1, 1)` không root_hint. Kết quả read_succeeded=True, evidence valid và đúng nội dung file. Xác nhận đường registry→root→session→evidence hoạt động cho ca này. Đây là mô phỏng mất RAM, chưa phải MCP subprocess restart/transport thật.

### Behavioral demo: phần đã đạt và giới hạn cần ghi đúng

`test_r14_comprehensive_runtime_demo_with_pipeline_and_valid_input` đã chạy SQLite thật: input `1` trả Alice trước/sau; payload `999 OR 1=1` lấy hai người trước sửa và không lấy được bản ghi sau sửa. Patch đi qua build_plan/apply_plan thật trên cùng file. Phần giữ chức năng hợp lệ và vô hiệu hóa injection của mẫu này đã có bằng chứng thực thi.

Tuy nhiên, test vẫn tạo finding/suggestion bằng `make_vuln`, tự tạo `_scan_sessions`, và mock `mcp_server.Scanner.scan` trả kết quả rỗng cho check_fix. Docstring “Real scan -> finding detection” chưa đúng với phần thực thi. Test chứng minh fixer áp dụng bản sửa cho sẵn và bản sửa giữ hành vi mong muốn; chưa chứng minh detector tìm được lỗi hoặc rescan thực xác nhận resolution.

**Để nghiệm thu tiếp:** đặt tên/mô tả test là behavioral integration với finding/rescan giả lập; bổ sung một bài integration riêng dùng rules/engine thật, có coverage thực cho file và snapshot, không mock toàn Scanner.scan. Với demo editor, còn cần MCP transport/host transcript. Model/suggestion có thể là fixture trong test xác định nhưng phải ghi rõ phần đó; không coi fixture là kết quả model thật.

### Trạng thái kết luận

Đóng hai ca partial→clean và không restore được target khác cwd trong phạm vi đã tái hiện. Không phát hiện lỗi mới chặn hai bản sửa đó trong lượt kiểm tra này. Không mở lại các lỗi cũ đã đóng. Chưa đánh dấu toàn bộ R09/R14/G4/G5/G6/G7 hoàn tất: host thực, transport, detector/rescan thực, môi trường tái lập và protocol/benchmark vẫn cần bằng chứng riêng.

Review chỉ cập nhật tài liệu; không sửa mã nguồn và không gọi model/Semgrep thật. Bộ test đã thực thi các chương trình SQLite mẫu bằng subprocess như mô tả trên.

## Cập nhật mới nhất — fab6ba3 (11/09/2026)

**98/98 test pass (19.02 giây, 1 warning). H02/H03 và các ca failed/degraded của H01 đã được cải thiện có test. H01 vẫn còn partial→clean; R11 chỉ restore được khi root audit được tìm thấy qua cwd/root_hint. R09/R14 có bước triển khai thực tế nhưng chưa hoàn tất nghiệm thu host end-to-end.** Các phần bên dưới giữ làm lịch sử.

### Những điểm được xác nhận

- Runner kiểm tra initial/rescan failure và exception, không ghi last-successful snapshot ở các nhánh thất bại đã xử lý. Tests failed/retry pass.
- Lock dùng PID liveness thay vì chỉ xét mtime, cleanup kiểm token. Ca owner còn sống quá 60 giây có regression test pass; chưa kết luận mọi race/PID reuse đã được chứng minh an toàn.
- Regex chạy worker subprocess với timeout 1.5 giây. Probe bổ sung dùng `^a+a+a+a+$` trên 10.000 ký tự `a` và `!`, vượt static guard nhưng trả ToolError timeout sau **1.53 giây**. Đây là hard timeout đã thực thi, không chỉ đọc tham số trong code.
- CLI có entrypoint `vulnagent hook` gọi EditorHookRunner. Chưa xác nhận host config thực sự tự kích hoạt entrypoint này.
- Snapshot, evidence và session có lưu JSONL; test reload trong cwd trùng repo pass.
- Demo SQLite thực thi mã vulnerable và mã parameterized, xác nhận payload `999 OR 1=1` lấy được hai bản ghi trước sửa và không lấy được bản ghi sau sửa. Đây là kiểm tra hành vi thực, tốt hơn assertion trên chuỗi mã.

### H01 còn lại — P1: partial với degraded=False vẫn bị nhận clean

**Đã tái hiện:** tạo ScanResult thật chứa report `status='partial'`, tiers `semgrep='ok'`, `llm='not_routed'`, findings rỗng. Result có `status='partial'`, `degraded=False`. Runner trả `{'status':'clean','rounds':1,'findings_count':0}`.

`_is_scan_failed_or_degraded()` chỉ kiểm status failed/error và degraded. Không phải mọi incomplete đều có degraded=True; routing có thể được coi là intentional nhưng phần yêu cầu phân tích chưa hoàn tất.

**Sửa:** contract rõ cho completed/partial/failed/skipped, kiểm status và coverage ở cả initial/rescan. Nếu policy cho intentional routing là hoàn tất trong scope được yêu cầu, status phải thể hiện điều đó nhất quán từ Scanner; không cho runner tự chuyển partial thành clean. Partial chưa đủ phải giữ incomplete và cho retry; không ghi nhận như successful snapshot. Test thêm partial với degraded=False và unknown/missing status theo contract đã chọn.

### R11 còn lại — P1: public MCP tools không restore được scan_id của repo khác cwd

**Đã tái hiện:** lưu snapshot/session trong thư mục repo tạm bằng code persistence thật; xóa session khỏi RAM để mô phỏng restart; gọi `get_assessment_history(scan_id)` khi cwd vẫn ở workspace khác repo tạm. Kết quả `Unknown scan_id`. Gọi private `_get_session(scan_id, root_hint=temp_root)` thì restore được.

**Nguyên nhân:** `_get_session` chỉ tìm cwd và root_hint; public tools không nhận/truyền root_hint. `scan_changes(target=...)` cho quét repo bất kỳ nhưng scan_id không có registry để tìm root sau restart. Test hiện dùng os.chdir vào đúng repo nên bỏ sót ca này.

**Sửa:** registry scan_id→authorized repo/audit location bền vững, hoặc session handle/API có root đã cấp rõ ràng và được validate. Không dò tùy tiện toàn filesystem. Test subprocess restart với cwd khác target, rồi gọi public MCP tools để đọc snapshot/evidence/history và kiểm stale.

### R09 còn phần nghiệm thu

Có CLI hook entrypoint là tiến bộ thật, nhưng cần chứng minh adapter đã đăng ký sự kiện của một host, payload→args mapping, trailing debounce/dirty queue và output feedback. Runner hiện vẫn bỏ lượt trong debounce window; nếu không có sự kiện tiếp theo, cần bảo đảm edit cuối không bị bỏ. Doctor vẫn kiểm capabilities bằng lời gọi Python trực tiếp, chưa phải MCP transport handshake. Chưa chạy editor thật hoặc stdio client trong review này.

### R14: behavioral demo chưa hoàn tất vòng sản phẩm hoặc G6

Test mới viết riêng vulnerable script và patched script, không dùng finding/suggestion từ scanner để tạo patch rồi verify. Chỉ chạy payload injection; chưa có assertion input hợp lệ vẫn trả đúng người dùng. Do đó xác nhận cơ chế parameterized SQL của mẫu, chưa xác nhận cả pipeline sửa lỗi của VulnAgent.

**Bổ sung:** input hợp lệ trước/sau, patch đi qua build/apply/verify trên cùng demo, scanner/rules thật và transcript MCP transport/host. Giữ fault injection cho nhánh failure/stale. Runtime demo này không thay thế dataset/protocol/baseline/raw metrics của G6; không đánh dấu R14/evaluation hoàn tất chỉ vì số test tăng.

### Trạng thái hành động

Đóng các ca H02/H03 đã nêu và failed/degraded H01 đã qua tests; sửa partial gate và repo lookup sau restart trước khi tuyên bố H01/R11 triệt để. Sau đó nghiệm thu host/transport và demo hành vi đầy đủ. Không mở lại R07 trong lượt này. Review chỉ dùng dữ liệu tạm, mock/fault injection và cập nhật tài liệu; không sửa mã nguồn hoặc gọi model thật.

## Cập nhật mới nhất — 740281f (11/09/2026)

**92/92 test pass (12.46 giây, 1 warning). Có tiến bộ ở R08–R13, nhưng chưa đủ căn cứ đóng R08–R14 hoặc gọi demo là nghiệm thu editor đầu-cuối. Runner mới còn false clean và lỗi lock; bộ lọc regex chưa chống ReDoS đầy đủ.** Các kết luận ở các cập nhật trước được giữ làm lịch sử.

### Phần đã cải thiện

- MCP có EDITOR_MODE; `_scan_target` không bật LLM trong editor mode, capabilities mô tả tools/modes. Đây là thay đổi thực thi, tốt hơn chỉ khai báo không gọi API.
- AssessmentStore có JSONL audit và reload, event stale có lý do trước/sau; serializer trả provenance/assessment.
- Agent read/search/definition dùng SafeReader ở nhiều đường trước đây đọc trực tiếp.
- Cache key thêm endpoint, tên file tạm có UUID tránh đụng tên giữa writer trong cùng process.
- Có EditorHookRunner và tests cho debounce/snapshot/lock/no-progress.
- Có test ghép evidence→assessment→patch→check_fix cùng nhánh stale và failure. Những test này hữu ích cho integration nội bộ.

### H01 — P1: EditorHookRunner báo clean khi scan thất bại

**Đã tái hiện:** `scan_fn` trả `ScanResult([], root, {'rule_error': 'synthetic failure'})`; `EditorHookRunner.run()` trả:

```json
{"status":"clean","rounds":1,"findings_count":0}
```

Lượt gọi lại, debounce=0 và file không đổi, trả `{"status":"skipped","reason":"unmodified"}`. Lỗi engine bị chuyển thành sạch rồi snapshot bị đánh dấu như đã xử lý thành công.

**Nguyên nhân:** runner kiểm tra findings mà không kiểm tra status/degraded/coverage; rescan sau fix cũng có nhánh tương tự. Đồng thời callback có thể trả nhiều kiểu Any nên không có contract kết quả chắc chắn.

**Sửa:** bắt buộc result contract; gate status/degraded/coverage trước mọi clean/fix/progress decision. Failure/incomplete phải trả trạng thái riêng, không cập nhật last-successful snapshot; cho phép retry cùng snapshot khi engine phục hồi. Scan exception và cancellation phải cleanup lock, trả lỗi có kiểm soát. Không dùng số findings giảm để khẳng định không regression.

**Test cần bổ sung:** initial scan fail; rescan fail sau fix; partial/exception; fail rồi retry cùng snapshot thành công. Các ca đều không được trả clean hoặc gọi fix trên result không đủ coverage.

### H02 — P1: lock hết 60 giây bị xóa dù owner vẫn đang hoạt động

**Đã tái hiện:** giữ context `runner1.lock()`; đặt mtime file lock lùi 61 giây để mô phỏng tác vụ kéo dài; `runner2.lock()` vẫn acquire thành công khi runner1 chưa thoát. Không phải đo tác vụ thực chạy 61 giây; đây là fault injection thời gian.

**Nguyên nhân:** lock chỉ xét tuổi file >60 giây, không kiểm tra owner còn sống hoặc lease/heartbeat. Owner cũ còn có thể unlink lock thuộc owner mới khi cleanup. Budget deep review của plan có thể dài hơn ngưỡng này.

**Sửa:** dùng lock hệ điều hành hoặc lease có owner token/heartbeat và cơ chế xác nhận owner chết; release chỉ xóa lock do chính mình sở hữu. Chờ lock trong async không dùng blocking sleep trên event loop.

**Test:** long-running live owner không bị chiếm khóa; crash owner có recovery; owner cũ không xóa lock mới; concurrent processes không cùng scan/fix một repo.

### H03 — P1: regex guard có thể bị vượt qua, chưa đạt ReDoS-safe

**Đã tái hiện:** `CodeTools.search('(a|aa)+$', 'app.py')` với file tạm chứa 45 ký tự `a` rồi `!`. Pattern không bị guard từ chối. Chạy trong subprocess riêng, đặt timeout 4 giây; subprocess không hoàn tất và bị subprocess.run kết thúc khi hết timeout. Không chạy pattern này vô hạn trong tiến trình agent/server.

**Nguyên nhân:** regex kiểm tra nested quantifier chỉ chặn một số hình dạng. Ambiguous alternation cũng có thể gây backtracking rất lớn. Giới hạn pattern 200 ký tự, 100 files và bytes/file không giới hạn thời gian xử lý từng regex.

**Sửa ưu tiên:** search mặc định là literal. Nếu giữ regex, dùng engine có bảo đảm/budget phù hợp hoặc worker process bị giới hạn thời gian và có thể terminate; timeout phải được trả như tool failure/incomplete. Không chỉ thêm một blacklist pattern khác. Timeout coroutine/to_thread không tự dừng CPU regex đang chạy.

**Test:** regex guard cũ, ambiguous alternation, pattern bình thường và literal metacharacters. Giữ test độc lập bằng subprocess timeout để không treo suite.

### R09 vẫn chưa nghiệm thu host/editor

Tìm references EditorHookRunner trong src/tests chỉ thấy định nghĩa class và tests, chưa thấy CLI/host config gọi runner. HostAdapter chưa cài hook entrypoint thực thi runner này. Debounce hiện trả skipped ngay, không có lịch chạy phần edit cuối đợt; state snapshot/time chỉ trong instance nên cần thiết kế nếu host tạo process mới mỗi sự kiện.

Doctor gọi trực tiếp hàm Python `capabilities()`, không khởi động MCP server, không initialize/list_tools qua transport. Tên thông báo “MCP handshake” mạnh hơn phép kiểm thực tế.

**Cần làm:** nối một host thật tới entrypoint, trailing debounce/dirty queue, lock đúng, retry thất bại; test process lifecycle. Doctor phân biệt in-process capabilities smoke và transport handshake. Chưa kiểm tra tài liệu host trong lượt review này, nên chưa xác nhận schema cấu hình host.

### R11: persistence mới chỉ bao phủ assessment/event, chưa toàn bộ audit evidence

JSONL persistence có thật, nhưng `_scan_sessions`, snapshots và evidence records vẫn trong RAM. Các tool history vẫn yêu cầu scan_id trong `_scan_sessions`; restart làm scan_id cũ không truy xuất được trực tiếp. AssessmentStore mới ở scan tiếp theo có thể load assessment cũ, nhưng EvidenceStore mới không có evidence records cũ để validate/explain chúng.

**Cần làm:** lưu/reload scan manifest, snapshot, evidence và assessment theo scan/root identity; phân biệt record không được nạp với stale do file đổi. Có test restart MCP rồi đọc history/evidence bằng scan_id cũ. Thêm chính sách retention và xử lý JSONL hỏng/ghi thất bại, không âm thầm báo đã lưu bền vững khi persistence lỗi.

### R14: ba nhánh demo chưa chứng minh runtime/security behavior hay thực nghiệm

`test_r14_end_to_end_python_demo_three_branches` tự tạo finding và `_scan_sessions`, gọi trực tiếp hàm MCP; rescan mock `ScanResult([], root, {})`. Nó không chạy `scan_changes`, Semgrep, MCP transport hoặc editor. Mẫu SQL cũng chưa tạo kết nối/cursor/input để thực thi test hành vi; có kiểm tra chuỗi patch xuất hiện nhưng chưa kiểm tra input hợp lệ và payload nguy hiểm thực sự.

Đây là **integration test nội bộ có scanner giả lập**, chưa phải demo end-to-end trên host và không thay thế G6 evaluation. Commit này không thêm dataset/protocol/manifests/raw benchmark results hay dependency lock.

**Nghiệm thu tiếp:** demo Python chạy được với input hợp lệ/bất hợp lệ đã rà, scanner/rules thật, MCP stdio client, transcript và artifact snapshot/assessment trước-sau. Chạy nhánh failure bằng fault injection được ghi rõ; giữ main benchmark theo protocol riêng.

### R10/R12 còn giới hạn

Serializer/UI có thêm trường nhưng chưa chứng minh migration/coverage UI hoàn chỉnh qua browser. Cache vẫn dùng chuỗi prompt version cố định và identity từ biến môi trường; chưa hash prompt thực/config/fallback identity/context dependency đầy đủ. Không đánh dấu R10/R12 hoàn tất chỉ vì test field tồn tại hoặc endpoint đổi làm key đổi.

### Kết luận hành động

Ưu tiên **H01 → H02 → H03**, rồi nối runner vào một host và thực hiện transport/restart/behavioral demo. Những lỗi R07 trước đây không bị mở lại trong review này. Chưa nghiệm thu G4/G5/G6/G7; G1 có false clean mới ở runner cần chặn trước.

Review dùng dữ liệu tạm và mock/fault injection; không gọi model thật, không sửa mã nguồn. Chỉ cập nhật tài liệu này.

## Cập nhật mới nhất — 0938478 (11/09/2026)

**84/84 test pass (10.31 giây, 1 warning). Xác nhận đóng các ca R07 đã tái hiện trong chuỗi review, bao gồm fallback khi thiếu baseline.** Các cập nhật bên dưới giữ lại làm lịch sử, không phải trạng thái hiện tại của các lỗi đã đóng.

Đã xác minh code bỏ đọc đĩa tạo baseline trong ScanResult và CLI luôn dùng `require_baseline=True`. Chạy thêm ba ca qua `_run_fix`, build_plan/apply_plan thật, chỉ mock Scanner.scan và dùng file tạm:

| Ca | Kết quả |
|---|---|
| Finding cũ, thiếu baseline, file đã đổi thành `x = 999` trước khi tạo ScanResult | Exit 2, yêu cầu re-scan; giữ nguyên `x = 999` |
| Finding cũ, baseline `x = 1`, file đã đổi thành `x = 999` | Exit 2, baseline conflict; giữ nguyên `x = 999` |
| Baseline hợp lệ, file vẫn là `x = 1`, suggestion `x = 2` | Exit 0; áp dụng đúng thành `x = 2` |

Ca hợp lệ cho thấy bản sửa không chỉ từ chối mọi patch. Các regression N01–N03 và R01–R07 trong suite tiếp tục pass. Phạm vi kết luận là các đường lỗi đã nêu và kiểm tra; chưa phải chứng minh mọi race/concurrency hoặc toàn bộ G5 đã được nghiệm thu. Chưa chạy model/Semgrep thật trong lượt này, chưa kiểm tra behavioral tests hay editor end-to-end.

**Bước tiếp theo:** chuyển trọng tâm sang R08–R14 và demo Python/MCP đầu-cuối theo ma trận ở review gốc; không cần tiếp tục sửa lại fallback R07 đã đóng nếu không có bằng chứng mới. Review chỉ cập nhật tài liệu, không sửa mã nguồn.

## Cập nhật mới nhất — 8b68183 (11/09/2026)

**83/83 test pass (10.92 giây, 1 warning). R07 đã chặn ca scan→plan khi có baseline phân tích được truyền đúng. Hợp đồng thiếu baseline vẫn chưa fail-closed.** Các mục cập nhật bên dưới là lịch sử.

### Ca đã xác nhận sửa được

Probe `_run_fix` thật, chỉ mock Scanner.scan: finding từ `x = 1`, file trên đĩa đổi thành `x = 999`, ScanResult mang hash phân tích của `x = 1`. Kết quả **exit 2**, báo conflict và giữ nguyên `x = 999`. Việc gắn file_hash và truyền baseline vào build_plan đã xử lý đúng ca có baseline.

### Phần còn lại của R07: fallback tự tạo baseline từ file hiện tại

`ScanResult.__init__` khi không có file_hashes sẽ đọc lại file hiện tại để tạo hash. Hash này không có bằng chứng là hash của nội dung đã phân tích. CLI đồng thời dùng `require_baseline=bool(baseline_hashes)`, nên khi baseline hoàn toàn không có lại tắt yêu cầu baseline.

**Đã tái hiện:** cùng probe trên nhưng Scanner giả lập trả finding cũ qua `ScanResult([report], root, {})` sau khi file đổi sang `x = 999`. Constructor tự gắn hash của `x = 999`; build_plan chấp nhận suggestion cũ, CLI ghi `x = 2` và **exit 0**.

**Giới hạn bằng chứng:** đây là kiểm thử contract của ScanResult/CLI khi thiếu metadata, không phải khẳng định Scanner bình thường luôn bỏ hash. Scanner mới đã truyền hash ở đường chạy chính. Tuy nhiên, đường legacy/adapter hoặc thiếu metadata vẫn có thể bị hợp thức hóa bằng hash đọc muộn.

**Sửa cần thiết để đóng contract:** không suy ra hash phân tích bằng cách đọc file trong constructor kết quả. Thiếu hash phải giữ missing. CLI có thao tác ghi phải yêu cầu baseline bắt buộc (`require_baseline=True`); thiếu baseline là conflict/re-scan. Nếu cần compatibility cho báo cáo cũ, vẫn cho xem báo cáo nhưng không tự cho áp dụng patch. Chụp hash tại đúng nội dung đưa vào engine, hoặc kiểm tra snapshot không đổi trong quá trình scan, để không gắn findings từ nhiều phiên bản vào một baseline.

**Test cần bổ sung:** kết quả không có hash + file đã thay đổi phải giữ file, exit lỗi; kết quả có hash đúng vẫn áp dụng được; hash stale giữ conflict. Không tạo baseline muộn chỉ để test legacy pass. Review này không gọi model/Semgrep thật và không sửa mã nguồn.

## Cập nhật mới nhất — b1462d1 (11/09/2026)

**81/81 test pass (8.64 giây, 1 warning). N01–N03 đã có bản sửa và các regression test tương ứng pass. R07 đóng được khoảng thời gian từ build_plan đến apply, nhưng chưa đóng khoảng thời gian từ nội dung được phân tích đến build_plan.** Các phần cập nhật bên dưới là lịch sử ở commit cũ, không thay thế kết luận này.

- N01: kiểm tra bổ sung gọi Scanner thật, không truyền files, trên thư mục rỗng và thư mục có một file; cả hai trả completed, không còn UnboundLocalError. Hai engine disabled trong probe để không gọi API/Semgrep.
- N02/N03: code đã resolve path qua reader, validate TaintStep và so enum chính xác. Test path khác hậu tố, kind lạ và kind số pass. Chưa mở lại các lỗi này trong review hiện tại.
- R07: snapshot_hashes được tính từ đúng buffer đọc trong build_plan và CLI truyền xuống apply; không có hash thì bỏ qua patch. Test CLI thay đổi file sau build_plan đã pass. Đây là cải thiện đúng đối với plan→apply.

### R07 còn lại — P1, đã tái hiện qua CLI: thay đổi sau phân tích nhưng trước build_plan vẫn bị ghi đè

**Probe:** dùng file tạm `app.py` chứa `x = 1`. Scanner giả lập trả finding ở dòng 1, context `x = 1`, suggestion `x = 2`, nhưng trước khi trả kết quả scanner thay nội dung trên đĩa thành `x = 999`, mô phỏng user edit sau lúc mã cũ được phân tích. Chạy `_run_fix` thật với `yes=True`, `verify=False`; build_plan và apply_plan không bị mock.

**Kết quả:** CLI tạo patch từ `x = 999` sang `x = 2`, áp dụng thành công, exit 0. File cuối là `x = 2`; thay đổi mới `x = 999` bị ghi đè.

**Nguyên nhân:** build_plan vẫn tin location/suggestion từ kết quả scan cũ rồi đọc nội dung hiện tại để làm original và hash mới. Hash plan chứng minh file không đổi từ lúc lập plan; không chứng minh plan dùng cùng snapshot mà finding/suggestion dựa vào. Đây là khoảng thời gian đã được yêu cầu kiểm tra trong R07 của review trước.

**Cách sửa:** gắn file hash/snapshot thực của nội dung phân tích vào ScanResult hoặc finding, chuyển contract đó vào build_plan. So sánh hash của buffer lập plan với hash phân tích trước khi tạo patch; mismatch/thiếu baseline phải conflict và yêu cầu quét lại. Có thể kiểm tra context/anchor để phát hiện drift, nhưng không dùng context ngắn thay cho hợp đồng snapshot. Tiếp tục giữ hash plan→apply và written hash→rollback đang có.

**Test đóng lỗi:** mock scanner trả finding từ snapshot A sau khi file đã đổi sang B; `_run_fix` không ghi file B và báo stale/conflict. Ca file không đổi từ scan→plan→apply phải vẫn áp dụng bình thường. Thêm assertions cho exit code và nội dung file, không chỉ hash map.

Không gọi API/model thật hoặc sửa file project trong probe. Review chỉ cập nhật tài liệu. Các phần R08–R14 và nghiệm thu đầu-cuối vẫn giữ phạm vi như review trước.

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
