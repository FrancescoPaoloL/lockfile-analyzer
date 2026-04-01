'''
Rule: detect typosquatting via Levenshtein distance against top npm packages.
'''

from pathlib import Path

from ..models import Finding, Package, Severity

# Scoped packages (e.g. @types/node) are skipped — too many false positives
# when comparing across different scopes and unscoped names.
_SCOPED_PACKAGE_PREFIX = "@"


def check_typosquat(
    packages: list[Package],
    top_packages_path: Path,
    threshold: int = 2,
) -> list[Finding]:
    """Flag packages whose names are suspiciously close to popular packages.

    Uses Levenshtein edit distance to compare each package name against a
    reference list of popular npm packages. Exact matches are never flagged.
    Scoped packages are skipped to avoid false positives.

    """
    if not top_packages_path.exists():
        return []

    top_packages = _load_top_packages(top_packages_path)
    if not top_packages:
        return []

    top_set = set(top_packages)
    findings: list[Finding] = []

    for pkg in packages:
        name = pkg["name"].lower()

        if name in top_set:
            # Exact match — legitimate package, skip.
            continue

        if name.startswith(_SCOPED_PACKAGE_PREFIX):
            # Scoped packages produce too many false positives.
            continue

        finding = _check_single_package(pkg, name, top_packages, threshold)
        if finding is not None:
            findings.append(finding)

    return findings


def _check_single_package(
    pkg: Package,
    name: str,
    top_packages: list[str],
    threshold: int,
) -> Finding | None:
    # Check a single package name against all top packages.
    for popular in top_packages:
        distance = _levenshtein(name, popular)
        if 0 < distance <= threshold:
            severity = Severity.HIGH if distance == 1 else Severity.MEDIUM
            return Finding(
                severity=severity,
                rule="typosquat",
                package=pkg["name"],
                version=pkg["version"],
                message=(
                    f"'{pkg['name']}' looks like a typosquat of '{popular}' "
                    f"(edit distance: {distance})."
                ),
                suggestion=f"Verify you intended '{popular}', not '{pkg['name']}'.",
            )
    return None


def _load_top_packages(path: Path) -> list[str]:
    # Read the top packages reference file into a list of lowercase names.
    top: list[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                entry = line.strip()
                if entry and not entry.startswith("#"):
                    top.append(entry.lower())
    except OSError:
        pass
    return top


def _levenshtein(a: str, b: str) -> int:
    # Compute the Levenshtein edit distance between two strings.
    # Uses the standard dynamic programming approach with O(n) space.
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        curr = [i]
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            curr.append(min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr

    return prev[len(b)]

