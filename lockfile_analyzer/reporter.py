'''
Reporter: format and print findings to stdout.

Output is coloured when stdout is a TTY; plain text otherwise (e.g. CI pipelines,
file redirection). Colour support is detected automatically via sys.stdout.isatty().
'''

import sys

from .models import Finding, Severity

# Severity display order: most critical first.
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
}

_SEVERITY_PREFIX: dict[Severity, str] = {
    Severity.HIGH:   "[HIGH]  ",
    Severity.MEDIUM: "[MEDIUM]",
    Severity.LOW:    "[LOW]   ",
}

# ANSI escape codes for terminal colouring.
_ANSI: dict[str, str] = {
    Severity.HIGH:   "\033[91m",  # bright red
    Severity.MEDIUM: "\033[93m",  # bright yellow
    Severity.LOW:    "\033[94m",  # bright blue
    "BOLD":          "\033[1m",
    "DIM":           "\033[2m",
    "RESET":         "\033[0m",
}

_USE_COLOR: bool = sys.stdout.isatty()


def report(findings: list[Finding], total: int) -> None:
    # Print all findings to stdout, followed by a summary line.

    if not findings:
        print(_colorize(f"\n✔ No issues found in {total} packages.\n", "BOLD"))
        return

    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))

    print()
    for finding in sorted_findings:
        _print_finding(finding)

    _print_summary(findings, total)


def _print_finding(finding: Finding) -> None:
    severity = finding["severity"]
    prefix = _colorize(_SEVERITY_PREFIX[severity], severity, "BOLD")
    package = _colorize(f"{finding['package']}@{finding['version']}", "BOLD")
    rule = _colorize(f"[{finding['rule']}]", "DIM")

    print(f"{prefix} {package} {rule}")
    print(f"         {finding['message']}")
    print(_colorize(f"         → {finding['suggestion']}", "DIM"))
    print()


def _print_summary(findings: list[Finding], total: int) -> None:
    counts: dict[Severity, int] = {sev: 0 for sev in Severity}
    for finding in findings:
        counts[finding["severity"]] += 1

    high_str   = _colorize(f"{counts[Severity.HIGH]} HIGH",     Severity.HIGH,   "BOLD")
    medium_str = _colorize(f"{counts[Severity.MEDIUM]} MEDIUM", Severity.MEDIUM, "BOLD")
    low_str    = _colorize(f"{counts[Severity.LOW]} LOW",       Severity.LOW,    "BOLD")

    print(
        f"Scanned {total} packages. "
        f"Found {len(findings)} issue(s): "
        f"{high_str}, {medium_str}, {low_str}."
    )
    print()


def _colorize(text: str, *keys: str) -> str:
    # Wrap text in ANSI colour codes if stdout is a TTY
    if not _USE_COLOR:
        return text
    codes = "".join(_ANSI.get(str(k), "") for k in keys)
    return f"{codes}{text}{_ANSI['RESET']}"

