# Evaluation

Measures VulnAgent against labelled ground truth, and against Semgrep and
Bandit as external baselines.

```bash
python eval/run_eval.py                                      # hand-labelled set
python eval/run_eval.py --dataset eval/datasets/securityeval # SecurityEval
python eval/run_eval.py --only hybrid --json results.json
```

## Datasets

| Dataset | Labels | Matching | Measures | Independent of |
|---|---|---|---|---|
| `eval/dataset` (hand-labelled) | 11 | line ±3 | precision **and** recall | all engines |
| `eval/datasets/securityeval` | 115 | file-level CWE | recall only | all engines |

### Hand-labelled set

Small, but the only one that can measure **precision**, because it contains
`safe_handlers.py` — a file that exercises SQL, subprocess, filesystem and
credential handling *correctly*. Any finding there is a false positive by
construction. A corpus made entirely of vulnerable code cannot measure the
axis LLM detection actually struggles on.

### SecurityEval

[SecurityEval](https://github.com/s2e-lab/SecurityEval) (Siddiq & Santos,
MSR 2022) ships 121 Python samples with the CWE encoded in each identifier.
Build the corpus from a checkout:

```bash
git clone https://github.com/s2e-lab/SecurityEval /tmp/SecurityEval
python eval/prepare_securityeval.py --source /tmp/SecurityEval
```

115 of the 121 samples fall inside the scope of single-file static analysis;
the rest need runtime context or business-logic judgement, and are skipped
with a printed reason rather than silently dropped.

Samples carry no annotated sink line, so matching is **file-level**: a
detection counts when it reports an equivalent CWE anywhere in the file.
Every sample is known-vulnerable and there are no clean counterparts, so
this corpus measures **recall**, not precision. The harness says so on every
run rather than letting the precision column be read as meaningful.

## What is deliberately not used

**OWASP Benchmark** is Java — 2,740 Java servlet test cases. WebGoat is Java,
Juice Shop and NodeGoat are JavaScript. None can evaluate a Python-only tool.
OWASP's Python project is **PyGoat**, which is a teaching application rather
than a labelled benchmark: it ships no line-level ground truth, so it is used
here for qualitative real-application testing, not for scoring.

**Bandit's `examples/` and Semgrep's rule test files** are tempting — both
carry line-level annotations and would be quick to import. Both are excluded.
Scoring an engine on the corpus its own authors wrote to test that engine
measures the corpus, not the engine, and this project's rule tier *runs
Semgrep's rules*. Importing them would inflate the rule tier's numbers and
invalidate the comparison against it.

## Configurations compared

| Configuration | What it isolates |
|---|---|
| VulnAgent (hybrid) | Both tiers, everything reported |
| VulnAgent (confirmed) | Only findings both tiers reached independently |
| Semgrep only | The rule tier alone |
| LLM only | The LLM tier alone |
| Bandit | An independent external baseline |

Running all five is the point: if the hybrid does not beat both single-tier
rows, the architecture is not earning its cost, and that is a result worth
reporting either way.

## Matching rules

A detection is a true positive when it is in the same file, carries an
equivalent CWE, and — in line mode — lands within 3 lines of the label. Each
label can be claimed by at most one detection and vice versa, so neither
duplicate findings nor one broad whole-file finding can inflate the score.

CWE comparison uses **equivalence classes**, not string equality. Engines
disagree defensibly about which CWE fits: Bandit files a literal password
under CWE-259 where this dataset says CWE-798, and Semgrep files
md5-for-passwords under CWE-327 where the dataset says CWE-328. Requiring
exact matches scored a correct detection as a false positive *and* a false
negative at once, which quietly flattered whichever engine the labels
happened to be written against.

## Adding samples

1. Drop a `.py` file into a dataset's `samples/`.
2. Add one entry to that dataset's `labels.json` per real vulnerability.
3. If the file is intentionally clean, list it under `clean_files` and add no
   labels — every finding in it then counts against precision.

```json
{
  "file": "my_sample.py",
  "line": 42,
  "cwe": "89",
  "type": "SQL_INJECTION",
  "note": "why this is a vulnerability"
}
```

`line` is the **sink** — the call that performs the unsafe operation — not the
assignment that introduced the tainted value. Detections match within ±3
lines, so the convention only has to be applied consistently.

## Dataset size

Below roughly 50 labelled vulnerabilities the scores move too much per sample
to support a conclusion; the harness prints a warning under 30. Building the
set up ten labels at a time alongside development is far less painful than
labelling a hundred in one sitting.
