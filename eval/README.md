# Evaluation

Measures VulnAgent against hand-labelled ground truth, and against Semgrep
and Bandit as external baselines.

```bash
python eval/run_eval.py                    # every configuration
python eval/run_eval.py --only hybrid      # one configuration
python eval/run_eval.py --json results.json
```

## What gets compared

| Configuration | What it isolates |
|---|---|
| VulnAgent (hybrid) | Both tiers, everything reported |
| VulnAgent (confirmed) | Only findings both tiers agreed on |
| Semgrep only | The rule tier alone |
| LLM only | The LLM tier alone |
| Bandit | An independent external baseline |

Running all five is what makes the hybrid claim checkable: if the hybrid does
not beat both single-tier rows, the architecture is not earning its cost, and
that is a result worth reporting either way.

## Adding samples

1. Drop a `.py` file into `dataset/samples/`.
2. Add one entry to `dataset/labels.json` per real vulnerability.
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
assignment that introduced the tainted value. Detections are matched within
±3 lines, so the convention only has to be applied consistently.

## Matching rules

A detection is a true positive when it is in the same file, within 3 lines of
the label, and carries the same CWE. Each label can be claimed by at most one
detection and vice versa, so neither duplicate findings nor one broad
whole-file finding can inflate the score.

## Dataset size

Below roughly 50 labelled vulnerabilities the scores move too much per sample
to support a conclusion; the harness prints a warning under 30. Building the
set up ten labels at a time alongside development is far less painful than
labelling a hundred in one sitting.

Include clean files deliberately. A dataset made only of vulnerable code
cannot measure false positives, which is the axis where LLM-based detection
actually struggles.
