# TRẠNG THÁI — VulnAgent branch `task/cwe-scope-20261110_1314`

## KẾT LUẬN CUỐI (2026-11-11)

**GATE STATUS: [VERIFIED: sound @ review #13]**

Reviewer `openai-codex/gpt-6-sol` cấp `Verdict: sound`, **0 BLOCKING** còn lại sau 13 vòng nghiệm thu.

| Chỉ số | Trước phiên | Sau |
|---|---|---|
| pytest | 16 failed / 341 passed | **452 passed, 0 failed** |
| Reviewer code vòng gốc | 12 BLOCKING | **0** |
| Gate C các vòng | — | 6→2→3→3→2→2→2→3+N→1→2→3→1→**0** |

### Diễn biến 13 vòng

| Vòng | Reviewer | BLOCKING | Nội dung chính |
|---|---|---:|---|
| 1 | `sub-mwayfdla-e` | 6 | verifier sanitizer, dedup, safe_reader, cache provider, eligible full, manifest |
| 2 | `sub-mwb0ctpw-h` | 2 | manifest, merge gộp 2 sink thật |
| 3 | `sub-mwb1mofz-j` | 3 | fusion `_deduplicate_tier`, one-sided taint, `--frozen-from` |
| 4 | `sub-mwb2muh4-l` | 3 | fusion `_find_match` cross-tier, dedup guard, source-only sink point |
| 5 | `sub-mwb3fqdd-n` | 2 | source-only trace qua fuse, evidence_ids mất |
| 6 | `sub-mwb4f06z-p` | 2 | `_combine` mất taint_path, `_absorb_into` mất assessment_status |
| 7 | `sub-mwb5c6nb-r` | 2 | trace rule mất, status lệch verification |
| 8 | `sub-mwb63r91-t` | 3+N | alternate_taint_paths không serialize, ghi đè, post-verify guard, thứ tự |
| 9 | `sub-mwb6y9ku-v` | 1 | `_verdicts_conflict` bỏ sót khi `verification=None` |
| 10 | `sub-mwb7ygpz-x` | 2 | fuse cross-tier conflict, refutation xoá confirmed trùng fingerprint |
| 11 | `sub-mwb90yj3-z` | 3 | suppression xoá confirmed, verifier ghi đè AST path, refuted trùng lặp |
| 12 | `sub-mwba4o28-11` | 1 | `_has_conflicting_counterpart` thiếu kiểm same sink |
| 13 | `sub-mwbb9ing-13` | **0** | **VERDICT: sound** |

NON-BLOCKING còn lại (1): đề nghị thêm test ghim ca LLM báo dòng 12 nhưng trace kết thúc sink dòng 10, và `taint_path` bẩn. Em đã kiểm thủ công cả hai đều đạt, không phải lỗi.

---

## TỔNG QUAN

| Chỉ số | Trước phiên | Hiện tại |
|---|---|---|
| pytest | 16 failed / 341 passed (trên `f5886e4`) | **452 passed, 0 failed** |
| Lỗi Reviewer code vòng gốc | 12 BLOCKING | **0** |
| Lỗi Gate C qua 13 vòng | — | 6→2→3→3→2→2→2→3+N→1→2→3→1→**0** |
| File thay đổi | — | 24 modified + 6 test mới + 2 file mới |

## CÁC NHÓM ĐÃ SỬA

### 1. Scope 10 CWE — một nguồn duy nhất
`CORE_CWE_SCOPE = (22, 78, 79, 89, 94, 328, 330, 502, 611, 643)`

- `src/models/cwe_scope.py` (275 dòng) — nguồn duy nhất: `CORE_CWE_SCOPE`, `CWE_EQUIVALENCE`, `cwe_matches`, `eligible`, `normalize_cwe`, `in_scope`, `filter_labels`, `filter_clean_files`, `filter_detections`, `scope_coverage`
- `eval/cwe_scope.py` (49 dòng) — shim re-export, cùng object (`same function object: True`)
- Scope đi từ `ScanOptions` → prompt → scanner → evaluator. **Env `VULNAGENT_CWE_SCOPE` không còn ảnh hưởng.**
- Prompt core10 sinh danh sách CWE tương đương **động** từ `CWE_EQUIVALENCE` (327 cho nhãn 328, v.v.)

### 2. Bộ chấm điểm
- `eligible()`: scope `full` trả `True` **trước** khi xét CWE rỗng → Bandit detection không CWE không bị drop oan
- Bỏ ghép path bằng basename/suffix → TP giả bị chặn, có counter `rejected_paths`
- `evaluate_single_scan` tự lọc labels + clean + detections cùng scope, truyền `exact_cwe`
- `eval/run_eval.py`: `--cwe-scope core10|full`, manifest JSON `{cwe_scope, labels_full, labels_in_scope, clean_files_full, clean_files_in_scope, exact_cwe}`

### 3. Verifier (3 bug + 6 lỗi Gate C)
- BUG-1: bỏ basename remap trong `evidence_file` → không bác bỏ chéo file
- BUG-2: cắt content **trước** khi trích `successful_reads` → không ghi dòng model chưa thấy
- BUG-3 / lỗi B: `merge_duplicate_sinks()` — gộp thay vì xoá; finding đã `supported`/`uncertain` vẫn tham gia cụm và **thắng** cụm
- Lỗi A: bỏ nhánh tự đổi `uncertain → refuted` từ `imported_sanitizers`
- Lỗi C: `safe_reader` bỏ fallback `r_path / p.name` và nhánh `datasets_dir` basename guessing

### 4. Cache
- LLM cache key: `options.model` / `options.base_url` / scope / path tương đối / hash system prompt / `CACHE_VERSION=v3`. Đổi env `OPENAI_MODEL` sau khi tạo Scanner **không** đổi key.
- Benchmark cache key: hash nội dung findings + labels hash + scope + `exact_cwe` + `SCORER_VERSION`
- `_served_by` stamp provider/model thực thi → cache phân biệt fallback Anthropic vs provider chính

### 5. API & evidence
- `/api/file_context`: bắt buộc job tồn tại + có workspace (404/400); `resolve()` + `realpath()` + `is_relative_to`; `context_lines` cap 50
- `_resolve_synthetic_helper` đã xoá (−58 dòng) → verifier không nhận bằng chứng sanitizer bịa
- `safe_reader.py` import `Union`

### 6. Kiến trúc
- `src/` không còn import ngược `eval/` (trừ `src/main.py:1279` và `src/cli.py` — hợp lý vì là lớp tiện ích gọi bộ đánh giá)
- `python eval/run_eval.py` chạy được từ thư mục bất kỳ (trước đó crash `No module named 'eval'`)

## ARTIFACT ĐÃ XUẤT

`reports/rescored_history/`:
- `metrics_core10.csv` — 17 cột, **51 dòng** (13 scored / 1 incomplete / 1 empty / 36 unsupported)
- `metrics_full.csv` — cùng cấu trúc, cùng 51 dòng
- `metrics_all.json` — manifest + hash từng job
- `RESCORE_REPORT.md`

Trạng thái thật (kiểm ngày 2026-11-11): **51 dòng**, trong đó **13 scored**, 1 incomplete (`1494438fb081`), 1 empty (`d5b0e07ba35a`), **36 unsupported**.

**6 trong 20 job được trích trong báo cáo KHÔNG còn trong snapshot**: `f27efb428d30`, `f8b459734396`, `9750509c05d8`, `27114c6c3af0`, `9ddc1f19c823`, `b43b14a0782a`. Không được tuyên bố "0 sai khác trên 20 job" — chỉ đúng cho 13 job còn lại.

**Mất provenance:** `src/jobs.py` có `DEFAULT_RETENTION = 50`; mỗi `JobStore.create()` xoá job cũ nhất. `pytest tests/` tạo snippet job trong `cwd/.vulnagent-jobs` nên prune dần. Toàn bộ 20 job gốc đã bị xoá trong phiên này. Nguồn truy nguyên còn lại: `reports/rescored_history/` (đã track trong git) và `99-work/review/job_inventory.json` (**file cục bộ, KHÔNG tracked**).

`bao_cao/NOTE_CAN_SUA_BAO_CAO.md` — danh mục sửa báo cáo docx (số dòng thay đổi theo từng lần sửa; đừng ghim số):
- Mục 0.0: trạng thái gate (verdict #13 CHỈ phủ code `1b5f381`, tài liệu chưa nghiệm thu) + 13 scored + 6/20 job vắng + mất provenance
- Mục 1: 6 lỗi mô tả cài đặt (Pydantic, out-of-scope, cú pháp, ngưỡng 0, CVSS, SHA-256)
- Mục 2: ngôn từ tuyệt đối (10 chỗ "75%", 12 "triệt tiêu")
- Mục 3: 6 lỗi phương pháp luận
- Mục 4: **bảng ánh xạ 20 job** + mục 4.0 cảnh báo Bandit/Semgrep không có artifact; KHÔNG xác nhận "docx khớp core10"
- Mục 5: 6 phát hiện riêng; **5.1 nói docx dùng luật cũ, FP thấp hơn thực tế** ở 4 job
- Mục 6: **vùng cấm sửa** (21 quy tắc, 5 tool, 3 trạng thái, min-cost max-flow, max_depth=2 — đều ĐÚNG)
- Mục 7-8: thứ tự thực hiện + checklist 13 mục

## SỐ LIỆU CHUẨN

| Dataset | Nhãn full | Nhãn core10 | Clean full | Clean core10 |
|---|---:|---:|---:|---:|
| owasp-mini | 50 | 48 | 50 | 46 |
| owasp-full | 452 | 381 | 778 | 710 |

Đối chiếu docx: `[P422]` ghi Beam 1.0 owasp-full DeepVerify = 380 TP / 191 FP / 99,74% / 66,55% / F1 0,7983 → **khớp chính xác** cột `core10` (`52fb84884189`). Không phải sửa.

## BÀI HỌC PHIÊN NÀY

1. **Dùng sai model Worker.** 10 worker đầu giao `gpt-6-sol` thay vì `commandcode/deepseek/deepseek-v4.1-flash`. Hệ quả: không có kiểm chéo thật giữa người viết và người nghiệm thu. Anh đã chấn chỉnh giữa phiên.
2. **Đọc sai file docx.** Đọc `bao_cao/` (463 đoạn, bản cũ) thay vì `File_bao_cao_ai_fix/` (477 đoạn, bản mới). Khiến em khẳng định sai với anh rằng docx "không có chữ uncertain/463". Reviewer đúng, em sai.
3. **Cảnh báo sai về scope, rồi sai tiếp về độ khớp.** Lần đầu em nói "toàn bộ bảng số chấm trên nhãn full 452" — sai, docx dùng core10. Lần hai em nói "docx khớp core10 tới từng đơn vị" — cũng sai: 4/5 job đối chiếu có FP lệch (mục ĐÍNH CHÍNH bên dưới). Đã sửa mục 5.1 của note.
4. **Tự tạo lỗi mới (E, C, F) trong khi sửa lỗi cũ.** `eligible` chặn CWE rỗng trước khi xét `full`; quên `safe_reader` khi siết `main.py`; manifest không khớp glob.

## VIỆC CÒN LẠI

- [x] Reviewer Gate C cấp verdict — **sound @ review #13** (`sub-mwbb9ing-13`, 0 BLOCKING)
- [x] Commit + push nhánh — `1b5f381` (code) + `d2cd620` (docs), origin == local
- [x] Sửa note theo 3 phản đối của auditor (13 scored thay vì 19, Bandit/Semgrep không truy nguồn, công bố prune)
- [ ] **Agent khác sửa `.docx`** theo `bao_cao/NOTE_CAN_SUA_BAO_CAO.md` — ngoài phạm vi phiên này
- [ ] Cân nhắc nâng `DEFAULT_RETENTION` trong `src/jobs.py` để không prune mất job thật khi chạy pytest

## ĐÍNH CHÍNH QUAN TRỌNG (kiểm 2026-11-11)

Auditor phát hiện docx và CSV lệch FP ở 4/5 job đối chiếu. Em đã truy nguyên nhân:

| Job | docx TP/FP/FN | CSV TP/FP/FN | ΔFP |
|---|---|---|---|
| `62dbabbb2a42` | 48/6/0 | 48/7/0 | +1 |
| `5cf511bb72df` | 375/164/6 | 375/166/6 | +2 |
| `c72fca194b29` | 347/123/34 | 347/136/34 | +13 |
| `aebeb9df7201` | 364/149/17 | 364/165/17 | +16 |
| `52fb84884189` | 380/191/1 | 380/191/1 | 0 |

**ΔTP = 0 và ΔFN = 0 ở mọi job. Chỉ FP tăng.**

Nguyên nhân: code cũ lọc detection bằng `in_scope()` nên **drop** mọi CWE không nằm trong `CORE_CWE_SCOPE`, kể cả CWE tương đương (CWE-327 cho nhãn 328, CWE-23/35/36/73 cho 22, v.v.). Code mới dùng `eligible()` nên **giữ** chúng; nếu không khớp nhãn thì phải tính FP.

**Kết luận: CSV đúng, docx dùng luật cũ.** Docx phải sửa FP/F1 theo CSV cho 4 job trên. Không được viết "khớp tới từng đơn vị" như mục 5.1 cũ.
