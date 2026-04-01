'''
Rule: flag packages with missing or malformed integrity hashes.

npm lockfiles include a Subresource Integrity (SRI) hash for each package,
typically in sha512 format. A missing or malformed hash means the package
tarball cannot be verified against a known-good value.
'''

import re

from ..models import Finding, Package, Severity

# SRI format: algorithm-base64encodedHash
# Supported algorithms: sha256, sha384, sha512
_VALID_INTEGRITY: re.Pattern[str] = re.compile(
    r"^(sha512|sha384|sha256)-[A-Za-z0-9+/=]{40,}$"
)


def check_integrity(packages: list[Package]) -> list[Finding]:
    """Flag packages with missing or malformed integrity hashes.

    A missing integrity field produces a LOW finding (common in older lockfiles).
    A malformed integrity value — one that does not match the SRI format — is
    treated as MEDIUM because it may indicate tampering.

    """
    findings: list[Finding] = []

    for pkg in packages:
        finding = _check_package_integrity(pkg)
        if finding is not None:
            findings.append(finding)

    return findings


def _check_package_integrity(pkg: Package) -> Finding | None:
    # Check the integrity field of a single package.

    integrity = pkg.get("integrity")

    if not integrity:
        return Finding(
            severity=Severity.LOW,
            rule="integrity",
            package=pkg["name"],
            version=pkg["version"],
            message=f"'{pkg['name']}@{pkg['version']}' has no integrity hash.",
            suggestion=(
                "Packages without integrity hashes cannot be verified. "
                "Run 'npm install' with a modern npm version to regenerate."
            ),
        )

    if not _VALID_INTEGRITY.match(integrity):
        return Finding(
            severity=Severity.MEDIUM,
            rule="integrity",
            package=pkg["name"],
            version=pkg["version"],
            message=(
                f"'{pkg['name']}@{pkg['version']}' has a malformed integrity hash: {integrity}"
            ),
            suggestion="Verify the lockfile has not been tampered with.",
        )

    return None

