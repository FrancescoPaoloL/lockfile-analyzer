# lockfile-analyzer

A learning project for supply chain security. Statically analyzes npm lockfiles (`package-lock.json`, `yarn.lock`) for signs of compromise — no network calls, no external dependencies.

Inspired by two real-world incidents that happened on the same day (March 31, 2026): a malicious version of `axios` was pushed to npm containing a Remote Access Trojan, and Anthropic accidentally shipped Claude Code's internal source code inside a public npm package ([read more](https://venturebeat.com/technology/claude-codes-source-code-appears-to-have-leaked-heres-what-we-know)). Both cases showed that lockfiles are not just boring metadata — they record exactly what got installed, from where, and with what credentials. If something slipped in, the lockfile knows. This tool is my attempt to understand how to detect that programmatically.

## What it detects

| Rule | Severity | What it looks for |
|------|----------|-------------------|
| `blocklist` | HIGH | Known malicious package names |
| `secrets` | HIGH | GitHub tokens, AWS keys, URLs with embedded credentials |
| `typosquat` | HIGH / MEDIUM | Names suspiciously close to popular packages (e.g. `lodahs` vs `lodash`) |
| `transitive` | MEDIUM | Unexpected dependencies with suspicious naming patterns |
| `version` | MEDIUM / LOW | Odd pre-release suffix, git hash version, non-registry source |
| `integrity` | MEDIUM / LOW | Missing or malformed integrity hash |

## Usage

```bash
python3 -m venv .venv && source .venv/bin/activate

# run without installing
PYTHONPATH=. python -m lockfile_analyzer.main path/to/package-lock.json

# quick test
PYTHONPATH=. python -m lockfile_analyzer.main tests/fixtures/package-lock.json
```

Exit codes: `0` clean, `1` medium/low findings, `2` high findings.

## Extending

Add entries to `data/blocklist.txt` or `data/top_packages.txt`. New rules go in `lockfile_analyzer/rules/` — same contract as the existing ones: takes packages, returns findings.

## Requirements

Python 3.11+, stdlib only.

