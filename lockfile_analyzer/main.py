#!/usr/bin/env python3
'''
lockfile-analyzer: static security analyzer for npm lockfiles.

Analyses package-lock.json or yarn.lock files for signs of supply chain
compromise without making any network requests.

Exit codes:
    0 — No issues found.
    1 — One or more MEDIUM or LOW findings.
    2 — One or more HIGH findings.
'''

import argparse
import sys
from pathlib import Path

from .models import Severity
from .parser import LockfileParseError, parse_lockfile
from .reporter import report
from .rules.blocklist import check_blocklist
from .rules.integrity import check_integrity
from .rules.transitive import check_transitive
from .rules.typosquat import check_typosquat
from .rules.version import check_version
from .rules.secrets import check_secrets

# Default paths relative to the installed package's data directory.
_DATA_DIR: Path = Path(__file__).parent.parent / "data"
_DEFAULT_BLOCKLIST: Path = _DATA_DIR / "blocklist.txt"
_DEFAULT_TOP_PACKAGES: Path = _DATA_DIR / "top_packages.txt"
_DEFAULT_LEVENSHTEIN_THRESHOLD: int = 2


def build_arg_parser() -> argparse.ArgumentParser:
    # Build and return the CLI argument parser.
    parser = argparse.ArgumentParser(
        prog="lockfile-analyzer",
        description="Static security analyzer for npm lockfiles.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes:\n"
            "  0  No issues found.\n"
            "  1  MEDIUM or LOW findings only.\n"
            "  2  At least one HIGH finding.\n"
        ),
    )
    parser.add_argument(
        "lockfile",
        type=Path,
        help="Path to package-lock.json or yarn.lock.",
    )
    parser.add_argument(
        "--blocklist",
        type=Path,
        default=_DEFAULT_BLOCKLIST,
        metavar="FILE",
        help=f"Path to blocklist file (default: {_DEFAULT_BLOCKLIST}).",
    )
    parser.add_argument(
        "--top-packages",
        type=Path,
        default=_DEFAULT_TOP_PACKAGES,
        metavar="FILE",
        help=f"Path to top packages reference file (default: {_DEFAULT_TOP_PACKAGES}).",
    )
    parser.add_argument(
        "--levenshtein-threshold",
        type=int,
        default=_DEFAULT_LEVENSHTEIN_THRESHOLD,
        metavar="N",
        help=(
            f"Maximum edit distance for typosquat detection "
            f"(default: {_DEFAULT_LEVENSHTEIN_THRESHOLD})."
        ),
    )
    return parser


def main() -> None:
    # Entry point for the lockfile-analyzer CLI
    parser = build_arg_parser()
    args = parser.parse_args()

    if not args.lockfile.exists():
        print(f"[ERROR] File not found: {args.lockfile}", file=sys.stderr)
        sys.exit(1)

    try:
        packages = parse_lockfile(args.lockfile)
    except LockfileParseError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    if not packages:
        print("[ERROR] No packages found in lockfile.", file=sys.stderr)
        sys.exit(1)

    findings = []
    findings += check_blocklist(packages, args.blocklist)
    findings += check_typosquat(packages, args.top_packages, args.levenshtein_threshold)
    findings += check_transitive(packages)
    findings += check_version(packages)
    findings += check_integrity(packages)
    findings += check_secrets(packages)


    report(findings, total=len(packages))

    if any(f["severity"] == Severity.HIGH for f in findings):
        sys.exit(2)
    elif findings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

