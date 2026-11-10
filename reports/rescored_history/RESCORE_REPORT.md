# Historical job re-score: core10 vs full

## Snapshot

- Run at (UTC): `2026-11-10T18:53:42Z`
- Input glob: `.vulnagent-jobs/*.json`
- Files matched by the glob at that instant: **51**
- Jobs scored: 13; jobs skipped: 38
- Collection SHA-256 of the scored job bytes: `d20d0e58ef95bdeeca2d94564aba5ceb5944c597ffde58bfdb4bbbd9d2aeee98`
- Frozen snapshot: **false** (inputs are the files matched by the glob at run time)
- Job files present in `.vulnagent-jobs/` when this run finished: **51**
- Files added / removed / changed in `.vulnagent-jobs/` after the snapshot was read: **0** / **0** / **0** (recorded in `post_run_drift`; none of them is in the scores below)

**This artifact is a snapshot at the timestamp above, not a permanent "entire history" claim.** The dashboard server writes new job JSONs into `.vulnagent-jobs/` while it runs, so the number of files can be higher than 51 when this file is read. Re-run `python scripts/rescore_history.py` to obtain a snapshot of the then-current directory; compare `snapshot_at` and `glob_count_at_run` in `metrics_all.json` against `ls .vulnagent-jobs/*.json | wc -l` before quoting any number from this report.

*Cảnh báo: Server có thể tạo job mới sau thời điểm chạy; manifest này là snapshot tại `2026-11-10T18:53:42Z`. Chạy lại script để cập nhật.*

Matching: `exact_cwe=false`; line tolerance and path validation use `evaluate_single_scan` defaults.
Legacy `source_name=benchmark1000` maps to `eval/datasets/benchmark` (owasp-full), not `benchmark100`.
Precision/recall/F1 are rounded to 4 decimals by the evaluator; TP/FP/FN are unrounded.
No job file is modified: their SHA-256 values are recorded, never written.

## Dataset denominators

| Dataset | Labels full | Labels core10 | Removed labels | Clean full | Clean core10 |
|---|---:|---:|---:|---:|---:|
| benchmark | 452 | 381 | 71 | 778 | 710 |
| benchmark100 | 50 | 48 | 2 | 50 | 46 |

## Per-job comparison

Removed detections = parsed detections in full minus eligible parsed detections in core10 (not necessarily equal to raw findings; rejected paths stay eligible and count as FP).

| Job | Dataset | Mode | Verify | Model | Raw | Removed det. | Core10 TP/FP/FN | Core10 P/R/F1 | Full TP/FP/FN | Full P/R/F1 |
|---|---|---|---|---|---:|---:|---|---|---|---|
| 26dfdce3277c | benchmark100 | llm | False | cbai/hy3 | 55 | 4 | 45/6/3 | 0.8824/0.9375/0.9091 | 47/8/3 | 0.8545/0.94/0.8952 |
| 52fb84884189 | benchmark | deep-verify | True | rl/Beam-1.0-501B-A23B | 659 | 88 | 380/191/1 | 0.6655/0.9974/0.7983 | 451/208/1 | 0.6844/0.9978/0.8119 |
| 5cf511bb72df | benchmark | deep-verify | True | ollama/gemma4 | 623 | 82 | 375/166/6 | 0.6932/0.9843/0.8134 | 402/221/50 | 0.6453/0.8894/0.7479 |
| 5ec88c710906 | benchmark | llm | False | cbai/hy3 | 577 | 89 | 370/118/11 | 0.7582/0.9711/0.8516 | 423/154/29 | 0.7331/0.9358/0.8222 |
| 62dbabbb2a42 | benchmark100 | deep-verify | True | ollama/gemma4 | 56 | 1 | 48/7/0 | 0.8727/1.0/0.932 | 49/7/1 | 0.875/0.98/0.9245 |
| a8b2ef400f59 | benchmark100 | llm | False | ollama/gemma4 | 86 | 4 | 48/34/0 | 0.5854/1.0/0.7385 | 50/36/0 | 0.5814/1.0/0.7353 |
| aebeb9df7201 | benchmark | llm | False | cx/gpt-6-luna | 719 | 190 | 364/165/17 | 0.6881/0.9554/0.8 | 396/323/56 | 0.5508/0.8761/0.6763 |
| c0f73dae2ea8 | benchmark100 | deep-verify | True | cx/gpt-6-luna | 57 | 8 | 44/5/4 | 0.898/0.9167/0.9072 | 45/12/5 | 0.7895/0.9/0.8411 |
| c72fca194b29 | benchmark | deep-verify | True | cx/gpt-6-luna | 651 | 168 | 347/136/34 | 0.7184/0.9108/0.8032 | 377/274/75 | 0.5791/0.8341/0.6836 |
| db5b38cd97c6 | benchmark100 | llm | False | cx/gpt-6-luna | 64 | 12 | 46/6/2 | 0.8846/0.9583/0.92 | 47/17/3 | 0.7344/0.94/0.8246 |
| dc790eb023ce | benchmark | llm | False | ollama/gemma4 | 1147 | 166 | 381/600/0 | 0.3884/1.0/0.5595 | 434/713/18 | 0.3784/0.9602/0.5428 |
| ecbb350b7f2c | benchmark100 | deep-verify | True | cx/gpt-5.6-luna | 60 | 11 | 42/7/6 | 0.8571/0.875/0.866 | 43/17/7 | 0.7167/0.86/0.7818 |
| ff60cd823550 | benchmark | deep-verify | True | cx/gpt-5.6-luna | 812 | 310 | 353/149/28 | 0.7032/0.9265/0.7995 | 390/422/62 | 0.4803/0.8628/0.6171 |

## Jobs with changed precision or recall

| Job | Changed | Labels excluded | Detections excluded | Core10 P/R | Full P/R |
|---|---|---:|---:|---|---|
| 26dfdce3277c | precision, recall | 2 | 4 | 0.8824/0.9375 | 0.8545/0.94 |
| 52fb84884189 | precision, recall | 71 | 88 | 0.6655/0.9974 | 0.6844/0.9978 |
| 5cf511bb72df | precision, recall | 71 | 82 | 0.6932/0.9843 | 0.6453/0.8894 |
| 5ec88c710906 | precision, recall | 71 | 89 | 0.7582/0.9711 | 0.7331/0.9358 |
| 62dbabbb2a42 | precision, recall | 2 | 1 | 0.8727/1.0 | 0.875/0.98 |
| a8b2ef400f59 | precision | 2 | 4 | 0.5854/1.0 | 0.5814/1.0 |
| aebeb9df7201 | precision, recall | 71 | 190 | 0.6881/0.9554 | 0.5508/0.8761 |
| c0f73dae2ea8 | precision, recall | 2 | 8 | 0.898/0.9167 | 0.7895/0.9 |
| c72fca194b29 | precision, recall | 71 | 168 | 0.7184/0.9108 | 0.5791/0.8341 |
| db5b38cd97c6 | precision, recall | 2 | 12 | 0.8846/0.9583 | 0.7344/0.94 |
| dc790eb023ce | precision, recall | 71 | 166 | 0.3884/1.0 | 0.3784/0.9602 |
| ecbb350b7f2c | precision, recall | 2 | 11 | 0.8571/0.875 | 0.7167/0.86 |
| ff60cd823550 | precision, recall | 71 | 310 | 0.7032/0.9265 | 0.4803/0.8628 |

## Skipped jobs

Every job file present at the snapshot was read. A job is skipped when it cannot be scored from stored data: `incomplete` (job status not `done`), `empty` (`result.findings` empty), `unsupported` (`options.source_name` has no benchmark dataset mapping).

| Job | Status | Reason |
|---|---|---|
| 13a1e3687432 | unsupported | source_name=None has no benchmark dataset mapping |
| 1494438fb081 | incomplete | job status='failed' (not done) |
| 193db5350996 | unsupported | source_name=None has no benchmark dataset mapping |
| 1a94f93b1804 | unsupported | source_name=None has no benchmark dataset mapping |
| 2e0659b8d4fa | unsupported | source_name=None has no benchmark dataset mapping |
| 2f26ebf4ed2c | unsupported | source_name=None has no benchmark dataset mapping |
| 43751dca9e3b | unsupported | source_name=None has no benchmark dataset mapping |
| 44c26c3db675 | unsupported | source_name=None has no benchmark dataset mapping |
| 47b67ede0a2b | unsupported | source_name=None has no benchmark dataset mapping |
| 4fcd7696a079 | unsupported | source_name=None has no benchmark dataset mapping |
| 56943043dfa1 | unsupported | source_name=None has no benchmark dataset mapping |
| 583f214f5e95 | unsupported | source_name=None has no benchmark dataset mapping |
| 59b38063db54 | unsupported | source_name=None has no benchmark dataset mapping |
| 704e7b0ac167 | unsupported | source_name=None has no benchmark dataset mapping |
| 71d68f77ba62 | unsupported | source_name=None has no benchmark dataset mapping |
| 8166e908daf2 | unsupported | source_name=None has no benchmark dataset mapping |
| 8b5fa8531ac2 | unsupported | source_name=None has no benchmark dataset mapping |
| 93b4957ff2b0 | unsupported | source_name=None has no benchmark dataset mapping |
| 9991880af140 | unsupported | source_name=None has no benchmark dataset mapping |
| 9c7be50319c4 | unsupported | source_name=None has no benchmark dataset mapping |
| a13294562f3e | unsupported | source_name=None has no benchmark dataset mapping |
| a6d001586e54 | unsupported | source_name=None has no benchmark dataset mapping |
| ae0106056d26 | unsupported | source_name=None has no benchmark dataset mapping |
| b11eb270aa45 | unsupported | source_name=None has no benchmark dataset mapping |
| b1518aa3c0ed | unsupported | source_name=None has no benchmark dataset mapping |
| b154f0e5c01f | unsupported | source_name=None has no benchmark dataset mapping |
| b271d6518fbf | unsupported | source_name=None has no benchmark dataset mapping |
| bc9f26f39c94 | unsupported | source_name=None has no benchmark dataset mapping |
| be494f8b36cf | unsupported | source_name=None has no benchmark dataset mapping |
| cb93ac06275e | unsupported | source_name=None has no benchmark dataset mapping |
| cca3eb5ea320 | unsupported | source_name=None has no benchmark dataset mapping |
| d5b0e07ba35a | empty | result.findings is empty |
| dc8edd1f3b98 | unsupported | source_name=None has no benchmark dataset mapping |
| dc9963f2bac9 | unsupported | source_name=None has no benchmark dataset mapping |
| e5f45c269b67 | unsupported | source_name=None has no benchmark dataset mapping |
| e93370447a53 | unsupported | source_name=None has no benchmark dataset mapping |
| f26763588650 | unsupported | source_name=None has no benchmark dataset mapping |
| f3c68c312f6f | unsupported | source_name=None has no benchmark dataset mapping |

## How to interpret changes in a thesis report

Use the core10 columns for the 10-CWE thesis scope; earlier full-scope TP/FP/FN, precision, recall and F1 for any changed row must be replaced with the corresponding core10 values above. The full denominator includes out-of-scope labels and detections; core10 removes them before matching. A smaller label denominator does not by itself prove recall rises: TP may also change. Clean-file controls are filtered by scope as well (they classify FP; they do not add to recall's denominator). No docx was read or changed, so which numeric cells in an actual docx match historical full scores is not verified.

Hashes of each dataset's `labels.json`, of each job file, and of canonical JSON findings are in `metrics_all.json`. CSV rows without scores represent excluded jobs; their reason is in the manifest.
