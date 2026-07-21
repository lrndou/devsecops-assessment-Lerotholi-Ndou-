# Multi-Scanner Orchestrator
Runs 3 security scanners against your code and gives you a single pass/fail result.

## What it does

1. Runs **semgrep** (finds code bugs), **pip-audit** (finds vulnerable dependencies), **detect-secrets** (finds hardcoded secrets)
2. Normalizes all findings into one format
3. Calculates a risk score (0-100)
4. Exits with pass (score < 50) or fail (score >= 50)

## Usage

```bash
# JSON output (default)
python orchestrator.py --target ../../country-service-main --format json

# Human-readable table
python orchestrator.py --target ../../country-service-main --format table

# SARIF (for GitHub integration)
python orchestrator.py --target ../../country-service-main --format sarif
```

## Exit Codes

- `0` — pass (score below 50)
- `1` — fail (score 50 or above)
- `2` — invalid input (bad path, etc.)

## Risk Scoring
| Severity | Weight |
|----------|--------|
| Critical | 10 |
| High | 5 |
| Medium | 2 |
| Low | 1 |

Score = sum of all weights, capped at 100.

## Why these scanners?

- **semgrep** — fast SAST, supports Java + Python, free, good rule library
- **pip-audit** — lightweight SCA, checks PyPI advisories
- **detect-secrets** — low false-positive secret detection

## If a scanner isn't installed
It gets skipped gracefully. The script won't crash — it logs a warning and continues with the others.

## Tests

```bash
python test_orchestrator.py
```

## No external Python dependencies
Uses only stdlib: `json`, `subprocess`, `argparse`, `os`, `sys`.