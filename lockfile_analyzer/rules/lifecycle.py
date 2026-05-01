'''
Rule: flag suspicious commands in lifecycle scripts (preinstall, install, postinstall).

These scripts run automatically during 'npm install', so a malicious body in
a published package executes on every downstream machine. This was the
delivery mechanism in the PyTorch Lightning supply chain attack of
April 30, 2026: attackers injected 'scripts.preinstall = "node .vscode/setup.mjs"'
into legitimate packages and republished.

Flagged patterns:
- IDE/tooling config dirs (.vscode/, .claude/, .cursor/, ...) as script targets
- Pipe-to-shell ('| sh', '| bash')
- GitHub releases URLs
- Network-fetch tools (curl, wget)
- Inline shell exec ('bash -c', 'sh -c')
- 'node' on a non-standard path (outside dist/, src/, lib/, build/)
'''

import re

from ..models import Finding, Package, Severity

# Lifecycle phases npm runs automatically during 'npm install'.
# 'install' is rare in modern packages but still honoured by npm.
_LIFECYCLE_PHASES: tuple[str, ...] = ("preinstall", "install", "postinstall")

# Tooling/config directories that should never contain executable entry points
# in a published npm package. Hits here are the strongest signal.
_SUSPICIOUS_PATHS: re.Pattern[str] = re.compile(
    r"(\.vscode|\.claude|\.cursor|\.idea|\.github)/",
    re.IGNORECASE,
)

# 'curl ... | sh', '... | bash', etc. — download-and-exec in one line.
_PIPE_TO_SHELL: re.Pattern[str] = re.compile(
    r"\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)

# Direct GitHub releases artifact link, used to bypass npm registry signing.
_GITHUB_RELEASES: re.Pattern[str] = re.compile(
    r"github\.com/[^/\s]+/[^/\s]+/releases/",
    re.IGNORECASE,
)

# Network-fetch tools used to pull payloads at install time.
_DOWNLOAD_TOOLS: re.Pattern[str] = re.compile(
    r"\b(curl|wget)\b",
    re.IGNORECASE,
)

# Inline shell exec via -c flag, e.g. 'bash -c "..."'.
_SHELL_DASH_C: re.Pattern[str] = re.compile(
    r"\b(bash|sh|zsh)\s+-c\b",
    re.IGNORECASE,
)

# 'node <token>' — used together with the allow-list below to flag node
# invocations on paths outside the conventional package output dirs.
_NODE_INVOCATION: re.Pattern[str] = re.compile(
    r"\bnode\s+([^\s;|&<>]+)",
    re.IGNORECASE,
)

# Conventional locations from which a published package legitimately runs JS.
# Anything else passed to 'node' is a candidate for review.
_CONVENTIONAL_NODE_TARGETS: tuple[str, ...] = (
    "dist/", "./dist/",
    "src/", "./src/",
    "lib/", "./lib/",
    "build/", "./build/",
)
_CONVENTIONAL_NODE_ENTRYPOINTS: frozenset[str] = frozenset({
    "index.js", "index.mjs", "index.cjs",
    "./index.js", "./index.mjs", "./index.cjs",
})

# Cap the script snippet shown in the message — install scripts can be large.
_SNIPPET_MAX: int = 80


def check_lifecycle(packages: list[Package]) -> list[Finding]:
    """Flag lifecycle scripts that contain commands typical of supply chain droppers.

    Each suspicious pattern matched in a phase produces an independent finding,
    so a single 'curl ... | sh' line will report both the network-fetch and
    pipe-to-shell concerns. This mirrors how rules/secrets.py handles overlap.
    """
    findings: list[Finding] = []

    for pkg in packages:
        scripts = pkg.get("scripts")
        if not scripts:
            continue

        for phase in _LIFECYCLE_PHASES:
            command = scripts.get(phase)
            if not command:
                continue
            findings.extend(_scan_command(pkg, phase, command))

    return findings


def _scan_command(pkg: Package, phase: str, command: str) -> list[Finding]:
    # Apply every pattern to a single script body and emit one finding per hit.
    findings: list[Finding] = []

    if _SUSPICIOUS_PATHS.search(command):
        findings.append(_make_finding(
            pkg, phase, command, Severity.HIGH,
            "references an IDE or tooling config directory "
            "(.vscode/, .claude/, .cursor/, .idea/, .github/) "
            "— typical hiding place for install-time droppers",
            "Open the referenced file and inspect its contents. "
            "Published packages should not execute code from IDE config dirs.",
        ))

    if _PIPE_TO_SHELL.search(command):
        findings.append(_make_finding(
            pkg, phase, command, Severity.HIGH,
            "pipes content directly into a shell — "
            "classic 'curl | sh' remote-exec pattern",
            "Reject any package that downloads and executes code at install time. "
            "Consider 'npm install --ignore-scripts' as a temporary mitigation.",
        ))

    if _GITHUB_RELEASES.search(command):
        findings.append(_make_finding(
            pkg, phase, command, Severity.HIGH,
            "downloads from a GitHub releases URL at install time",
            "GitHub releases bypass the npm registry's signing and audit trail. "
            "Pin to a registry-resolved version instead.",
        ))

    if _DOWNLOAD_TOOLS.search(command):
        findings.append(_make_finding(
            pkg, phase, command, Severity.HIGH,
            "uses a network-fetch tool (curl/wget) at install time",
            "Verify what is being downloaded. Network access during "
            "'npm install' is rarely legitimate for a library package.",
        ))

    if _SHELL_DASH_C.search(command):
        findings.append(_make_finding(
            pkg, phase, command, Severity.MEDIUM,
            "invokes a shell with -c (inline command execution)",
            "Audit the inlined command. Shell -c in install scripts "
            "is a common obfuscation vector.",
        ))

    external_path = _find_external_node_target(command)
    if external_path is not None:
        findings.append(_make_finding(
            pkg, phase, command, Severity.MEDIUM,
            f"runs 'node' on a non-standard path '{external_path}' "
            "(outside dist/, src/, lib/, build/, or a top-level index.*)",
            "Inspect the file. Legitimate packages run install-time code "
            "from conventional output directories.",
        ))

    return findings


def _find_external_node_target(command: str) -> str | None:
    # Return the first 'node <path>' argument that is not in a conventional location.
    # Returns None if no node invocation exists, or all invocations look benign.
    for match in _NODE_INVOCATION.finditer(command):
        target = match.group(1)

        # 'node -e "..."', 'node --experimental-...', etc. — skip flag forms.
        # These deserve their own dedicated check; out of scope for this rule.
        if target.startswith("-"):
            continue

        if target in _CONVENTIONAL_NODE_ENTRYPOINTS:
            continue

        if any(target.startswith(prefix) for prefix in _CONVENTIONAL_NODE_TARGETS):
            continue

        return target

    return None


def _make_finding(
    pkg: Package,
    phase: str,
    command: str,
    severity: Severity,
    what: str,
    suggestion: str,
) -> Finding:
    # Build a Finding with a truncated snippet of the offending command,
    # so the report stays readable even for multi-line install scripts.
    snippet = command if len(command) <= _SNIPPET_MAX else command[:_SNIPPET_MAX - 3] + "..."

    return Finding(
        severity=severity,
        rule="lifecycle",
        package=pkg["name"],
        version=pkg["version"],
        message=(
            f"'{pkg['name']}@{pkg['version']}' has a '{phase}' script that "
            f"{what}: '{snippet}'"
        ),
        suggestion=suggestion,
    )

