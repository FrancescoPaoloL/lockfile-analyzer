import json
import urllib.error
import urllib.request
from typing import Generator

from .models import Finding, Package, Severity

_REGISTRY_BASE = "https://registry.npmjs.org"
_TIMEOUT_SECONDS = 10


def verify_packages(packages: list[Package]) -> list[Finding]:
    findings: list[Finding] = []
    for pkg in packages:
        local_integrity = pkg.get("integrity")
        if not local_integrity:
            continue
        for finding in _check_package(pkg, local_integrity):
            findings.append(finding)
    return findings


def _check_package(
    pkg: Package,
    local_integrity: str,
) -> Generator[Finding, None, None]:
    name = pkg["name"]
    version = pkg["version"]
    url = f"{_REGISTRY_BASE}/{name}/{version}"

    try:
        remote_integrity = _fetch_integrity(url)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            yield _make_finding(
                pkg, Severity.HIGH,
                "package version not found in registry",
                f"Verify with 'npm view {name}@{version}'.",
            )
        else:
            yield _make_finding(
                pkg, Severity.LOW,
                f"registry returned HTTP {exc.code}",
                "Check https://status.npmjs.org.",
            )
        return
    except Exception as exc:
        yield _make_finding(
            pkg, Severity.LOW,
            f"registry check failed: {exc}",
            "Network issue or registry unavailable.",
        )
        return

    if remote_integrity != local_integrity:
        yield _make_finding(
            pkg, Severity.HIGH,
            f"integrity mismatch: lockfile '{local_integrity}' vs registry '{remote_integrity}'",
            "Lockfile was modified outside npm. Do not merge.",
        )


def _fetch_integrity(url: str) -> str:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
        data = json.loads(resp.read().decode())
    integrity = data.get("dist", {}).get("integrity")
    if not integrity:
        raise ValueError("missing dist.integrity")
    return integrity


def _make_finding(
    pkg: Package,
    severity: Severity,
    message: str,
    suggestion: str,
) -> Finding:
    return Finding(
        severity=severity,
        rule="registry",
        package=pkg["name"],
        version=pkg["version"],
        message=f"'{pkg['name']}@{pkg['version']}': {message}",
        suggestion=suggestion,
    )
