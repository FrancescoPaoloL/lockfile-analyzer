'''
Rule: detect suspicious version strings and resolution sources.

Flags packages with:
- Pre-release suffixes that suggest tampering (e.g. 1.0.0-patch, 2.0.0-fix)
- Versions that look like raw git commit hashes instead of semver
- Resolution sources outside the official npm registry (file:, git+, github:, etc.)
'''

import re

from ..models import Finding, Package, Severity

# Pre-release labels that are unusual and may indicate a malicious version bump.
_SUSPICIOUS_PRERELEASE: re.Pattern[str] = re.compile(
    r"-(patch|fix|hotfix|update|urgent|critical|security|safe|clean|stable2)$",
    re.IGNORECASE,
)

# Packages resolved from non-registry sources are potentially unaudited.
_NON_REGISTRY_SOURCE: re.Pattern[str] = re.compile(
    r"^(file:|git\+|github:|bitbucket:|gitlab:)",
    re.IGNORECASE,
)

# A version that looks like a raw git hash (7 to 40 hex characters).
_GIT_HASH_VERSION: re.Pattern[str] = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


def check_version(packages: list[Package]) -> list[Finding]:
    """Flag packages with suspicious version strings or resolution sources.

    Each package may produce up to two findings: one for a suspicious version
    string, and one for a non-registry resolved URL. These are independent checks.

    """
    findings: list[Finding] = []

    for pkg in packages:
        version = pkg.get("version") or ""
        resolved = pkg.get("resolved") or ""

        version_finding = _check_version_string(pkg, version)
        if version_finding is not None:
            findings.append(version_finding)

        source_finding = _check_resolved_source(pkg, version, resolved)
        if source_finding is not None:
            findings.append(source_finding)

    return findings


def _check_version_string(pkg: Package, version: str) -> Finding | None:
    # Check the version string for suspicious patterns.

    if _SUSPICIOUS_PRERELEASE.search(version):
        return Finding(
            severity=Severity.MEDIUM,
            rule="version",
            package=pkg["name"],
            version=version,
            message=f"'{pkg['name']}@{version}' has a suspicious pre-release suffix.",
            suggestion="Verify this version was intentionally installed.",
        )

    if _GIT_HASH_VERSION.match(version):
        return Finding(
            severity=Severity.LOW,
            rule="version",
            package=pkg["name"],
            version=version,
            message=(
                f"'{pkg['name']}' has a git-hash version '{version}' instead of a semver."
            ),
            suggestion="Ensure this points to a trusted commit.",
        )

    return None


def _check_resolved_source(pkg: Package, version: str, resolved: str) -> Finding | None:
    # Check the resolved URL for non-registry sources.
    if resolved and _NON_REGISTRY_SOURCE.match(resolved):
        return Finding(
            severity=Severity.MEDIUM,
            rule="version",
            package=pkg["name"],
            version=version,
            message=(
                f"'{pkg['name']}' is resolved from a non-registry source: {resolved}"
            ),
            suggestion="Only use packages resolved from the official npm registry.",
        )
    return None
