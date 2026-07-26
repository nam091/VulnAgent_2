# VulnAgent 🛡️

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **VulnAgent** finds security vulnerabilities in source code by running a rule
> engine and a large language model as **two independent tiers**, then merging
> their results. Findings both tiers agree on are marked `confirmed`; findings
> only one tier reports are labelled as such and scored lower.

## Why two tiers

Measured by `eval/run_eval.py` on 11 labelled vulnerabilities across three
files, one of which is deliberately clean:

| Configuration | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| VulnAgent, everything | 11 | 9 | 0 | 0.550 | **1.000** | 0.710 |
| **VulnAgent, confirmed only** | 8 | **0** | 3 | **1.000** | 0.727 | **0.842** |
| Semgrep only | 8 | 2 | 3 | 0.800 | 0.727 | 0.762 |
| LLM only | 11 | 7 | 0 | 0.611 | **1.000** | 0.759 |
| Bandit (baseline) | 7 | 6 | 4 | 0.538 | 0.636 | 0.583 |

Read the first row carefully: **simply merging both tiers is worse than
either tier alone.** It inherits every false positive from both and scores
F1 0.710, below Semgrep's 0.762 and the LLM's 0.759. Running two engines and
reporting the union buys nothing.

What earns its keep is the second row. Because the tiers run **independently**,
agreement between them is evidence — and filtering to findings both engines
reached separately gives perfect precision on this set and the best F1 of any
configuration.

So the value is not "two engines find more". It is that **independent
agreement is a reliable confidence signal**, which is why the rule tier is
not used as a pre-filter on the LLM tier: gating one on the other would
destroy the independence the whole design rests on, and would have discarded
the hardcoded credentials the rule engine never had a pattern for.

The two rows also bracket a real trade-off you choose per context: report
everything for a human reviewing a pull request (recall 1.000), gate CI on
confirmed findings only (precision 1.000). `--confirmed-only` switches
between them.

> **On dataset size.** Eleven labels across three files is a smoke test, not
> an evaluation. The numbers move meaningfully per sample at this size. Treat
> the shape of the result as provisional until the dataset reaches 50–100
> labels.

VulnAgent also does three things a rule engine structurally cannot:

- **Chains findings into attack paths** with likelihood and prerequisites
- **Writes context-aware fixes**, validated before they are applied
- **Catches logic-level defects** that cannot be reduced to a pattern

## Install

```bash
git clone https://github.com/nam091/VulnAgent_2.git
cd VulnAgent_2
python -m venv venv && source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
cp .env.example .env      # then add your API key
```

## Use

### Command line

```bash
vulnagent scan .                          # scan a tree
vulnagent scan app.py --verbose           # one file, with impact and fixes
vulnagent scan . --no-llm                 # rule tier only, ~10s startup
vulnagent scan . --format sarif -o out.sarif
vulnagent fix . --verify                  # apply patches, revert if worse
vulnagent baseline .                      # freeze current findings as accepted
```

Exit codes: `0` clean, `1` findings breach the gate, `2` error.

Useful flags:

| Flag | Effect |
|---|---|
| `--fail-on {critical,high,medium,low,info,never}` | Gate severity (default `high`) |
| `--confirmed-only` | Only corroborated findings can fail the build |
| `--baseline [FILE] --fail-on-new` | Only new findings can fail the build |
| `--min-risk N` | How risky a file must look to reach the LLM tier |
| `--max-llm-files N` | Hard cap on LLM calls, highest risk first |
| `-j N` | Concurrent LLM calls (default 5) |

### MCP server — for AI coding agents

Lets Claude Code, Cursor or any MCP client scan the code it just wrote,
**before** handing it to the user.

```json
{
  "mcpServers": {
    "vulnagent": {
      "command": "python",
      "args": ["/absolute/path/to/VulnAgent_2/src/mcp_server.py"]
    }
  }
}
```

Tools: `scan_code`, `scan_file`, `scan_directory`, `capabilities`. Use
`mode="fast"` inside a generation loop (rule tier only, roughly ten seconds -
almost entirely fixed engine startup, so snippet size hardly matters) and
`mode="deep"` for a final review.

### Web UI

```bash
vulnagent serve      # http://localhost:8000
```

Paste code, upload a file, or point it at a public repository. API docs at
`/docs`.

### GitHub Action

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: nam091/VulnAgent_2@main
    with:
      path: src
      fail-on: high
      confirmed-only: 'true'
      openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

Results land in the repository's **Security** tab and as inline PR
annotations, via SARIF.

## Suppressing findings

```python
cursor.execute(query)  # vulnagent: ignore[SQL_INJECTION] query is a literal constant
```

Bare `# vulnagent: ignore` waives every type on the line; `# vulnagent:
ignore-file` waives the whole file. Existing `# nosec` and `# nosemgrep`
markers are honoured too.

For an existing codebase, prefer a baseline over blanket suppression:

```bash
vulnagent baseline .                                  # record today's findings
vulnagent scan . --baseline --fail-on-new             # only regressions fail
```

## Configuration

```ini
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.xiaomimimo.com/v1   # optional, any compatible provider
OPENAI_MODEL=mimo-v2.5-pro                      # optional
ANTHROPIC_API_KEY=sk-ant-...                    # optional fallback
```

## Cost and speed

A full LLM pass over every file in a repository is neither affordable nor
fast, so three mechanisms bound it:

- **Discovery** skips `venv/`, `node_modules/`, build output and anything
  `.gitignore`d. On this repository that is 10 files rather than 3,974.
- **Risk routing** sends only files whose contents suggest something worth
  reading semantically — user input, SQL, subprocess, auth, crypto — to the
  LLM. The rule tier still covers everything.
- **Content-hash caching** means an unchanged file is never paid for twice.
  A repeat scan of the example drops from 51s to 11s.

## Evaluation

```bash
python eval/run_eval.py
```

Scores the hybrid against Semgrep-only, LLM-only and Bandit on a hand-labelled
dataset. See [eval/README.md](eval/README.md) for how to add samples.

## Limitations

Stated plainly, because a scanner that overstates its coverage is worse than
one that admits its edges:

- **Python only.** Other languages are not supported.
- **Analysis is per file.** Taint that crosses module boundaries is not
  tracked; cross-file analysis is a paid Semgrep feature.
- **The rule tier needs a recognised taint source.** It reasons from framework
  entry points such as `request.args`. A standalone helper has none, so
  `os.system("echo " + cmd)` inside a plain `def run(cmd)` is reported clean
  by `--no-llm` and CRITICAL with the LLM tier enabled. A rules-only pass over
  non-framework code proves very little.
- **LLM-only findings are not reproducible run to run.** Even at temperature
  0 the marginal, low-confidence findings fluctuate. Confirmed findings are
  stable. This is why `--confirmed-only` is the recommended CI gate.
- **Generated fixes need review.** Patches are syntax-checked and classified,
  and only clean substitutions apply unattended — but a patch can parse
  correctly and still change behaviour, so `--verify` re-scans and reverts a
  change that made things worse.
- **A clean scan is not proof of security.** It means these engines found
  nothing, which is a much weaker statement.
