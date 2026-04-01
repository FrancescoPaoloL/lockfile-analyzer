'''
Rule: detect secrets and credentials embedded in lockfile fields.

Scans known lockfile fields (resolved, version, integrity) for patterns
associated with authentication tokens, API keys, and URLs containing
embedded credentials.

Checked patterns:
- GitHub personal access tokens (classic, fine-grained, OAuth, Actions)
- AWS Access Key IDs
- URLs with embedded credentials (user:pass@host)
- npm registry auth tokens in resolved URLs
'''

import re

from ..models import Finding, Package, Severity


# Compiled patterns
_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "github-token-classic",
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "GitHub personal access token (classic)",
    ),
    (
        "github-token-finegrained",
        re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
        "GitHub fine-grained personal access token",
    ),
    (
        "github-token-oauth",
        re.compile(r"gho_[A-Za-z0-9]{36}"),
        "GitHub OAuth token",
    ),
    (
        "github-token-actions",
        re.compile(r"ghs_[A-Za-z0-9]{36}"),
        "GitHub Actions token",
    ),
    (
        "aws-access-key-id",
        re.compile(r"AKIA[A-Z0-9]{16}"),
        "AWS Access Key ID",
    ),
    (
        "url-embedded-credentials",
        re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@"),
        "URL with embedded credentials (user:password@host)",
    ),
    (
        "npm-auth-token",
        re.compile(r":_authToken=\S+"),
        "npm registry auth token in resolved URL",
    ),
]

# Lockfile fields to scan — no recursive scanning to keep the rule focused.
_SCANNED_FIELDS: tuple[str, ...] = ("resolved", "version", "integrity")


# Public interface
def check_secrets(packages: list[Package]) -> list[Finding]:
    """
    Scan lockfile fields for embedded secrets and credentials.

    Checks a fixed set of fields (resolved, version, integrity) against
    a list of known secret patterns. Each match produces a HIGH finding.
    """
    findings: list[Finding] = []

    for pkg in packages:
        for field in _SCANNED_FIELDS:
            value = pkg.get(field)  # type: ignore[literal-required]
            if not value:
                continue
            findings.extend(_scan_value(pkg, field, value))

    return findings


# Private helpers
def _scan_value(pkg: Package, field: str, value: str) -> list[Finding]:
    # Scan a single field value against all secret patterns.
    findings: list[Finding] = []

    for pattern_id, pattern, description in _PATTERNS:
        if pattern.search(value):
            findings.append(Finding(
                severity=Severity.HIGH,
                rule="secrets",
                package=pkg["name"],
                version=pkg["version"],
                message=(
                    f"Possible {description} found in '{field}' "
                    f"of '{pkg['name']}@{pkg['version']}'."
                ),
                suggestion=(
                    "Remove the secret immediately, rotate the credential, "
                    "and audit your git history for prior exposure."
                ),
            ))

    return findings

