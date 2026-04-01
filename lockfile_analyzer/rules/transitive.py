'''
    Rule: detect unexpected transitive dependencies.

Flags packages that pull in dependencies whose names match patterns associated
with crypto, shell access, network tunnelling, or known malware naming conventions.
'''

from ..models import Finding, Package, Severity

# Substrings that are suspicious when found in a transitive dependency name.
_SUSPICIOUS_PATTERNS: frozenset[str] = frozenset({
    "crypto",
    "cipher",
    "encode",
    "exec",
    "shell",
    "spawn",
    "proxy",
    "rat",
    "payload",
    "inject",
    "exfil",
    "tunnel",
    "backdoor",
})

# Parent packages for which crypto or system dependencies are expected.
# Findings against these parents are suppressed to reduce false positives.
_WHITELISTED_PARENTS: frozenset[str] = frozenset({
    "node-forge",
    "crypto-js",
    "bcrypt",
    "bcryptjs",
    "jsonwebtoken",
    "ssh2",
    "nodemailer",
    "multer",
    "webpack",
    "esbuild",
    "vite",
    "rollup",
    "typescript",
})


def check_transitive(packages: list[Package]) -> list[Finding]:
    """Flag suspicious transitive dependencies pulled in by a package.

    A finding is raised when a package's direct dependency list contains a
    package name that matches one of the suspicious patterns, and the parent
    package is not in the whitelist.

    """
    findings: list[Finding] = []

    for pkg in packages:
        if pkg["name"].lower() in _WHITELISTED_PARENTS:
            continue

        for dep in pkg["dependencies"]:
            matched_pattern = _first_matching_pattern(dep.lower())
            if matched_pattern is not None:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    rule="transitive",
                    package=pkg["name"],
                    version=pkg["version"],
                    message=(
                        f"'{pkg['name']}' pulls in '{dep}', "
                        f"which matches suspicious pattern '{matched_pattern}'."
                    ),
                    suggestion=(
                        f"Verify that '{dep}' is a legitimate dependency of '{pkg['name']}'."
                    ),
                ))

    return findings


def _first_matching_pattern(dep_name: str) -> str | None:
    # Return the first suspicious pattern found in a dependency name, or None.
    for pattern in _SUSPICIOUS_PATTERNS:
        if pattern in dep_name:
            return pattern
    return None

