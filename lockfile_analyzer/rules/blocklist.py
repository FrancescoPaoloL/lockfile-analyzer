'''
Rule: check packages against a known malicious blocklist.
'''

from pathlib import Path

from ..models import Finding, Package, Severity


def check_blocklist(packages: list[Package], blocklist_path: Path) -> list[Finding]:
    """Flag any package whose name appears in the local blocklist.

    The blocklist is a plain-text file with one package name per line.
    Lines starting with '#' are treated as comments and ignored.

    """
    if not blocklist_path.exists():
        return []

    blocked = _load_blocklist(blocklist_path)
    if not blocked:
        return []

    return [
        Finding(
            severity=Severity.HIGH,
            rule="blocklist",
            package=pkg["name"],
            version=pkg["version"],
            message=f"Package '{pkg['name']}' is in the known malicious blocklist.",
            suggestion="Remove this package immediately and audit your dependencies.",
        )
        for pkg in packages
        if pkg["name"].lower() in blocked
    ]


def _load_blocklist(path: Path) -> set[str]:
    # Read and parse a blocklist file into a set of lowercase package names.

    blocked: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                entry = line.strip()
                if entry and not entry.startswith("#"):
                    blocked.add(entry.lower())
    except OSError:
        # If the file cannot be read, skip silently — rule simply produces no findings.
        pass
    return blocked

