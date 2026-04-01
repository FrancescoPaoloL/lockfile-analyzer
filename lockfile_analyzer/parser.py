'''
Parser for npm lockfile formats.

Supports:
- package-lock.json (npm lockfile v1, v2, v3)
- yarn.lock (yarn classic v1)
'''

import json
import re
from pathlib import Path

from .models import Package


class LockfileParseError(Exception):
    """Raised when a lockfile cannot be parsed."""


def parse_lockfile(path: Path) -> list[Package]:
    # Detect the lockfile format and delegate to the appropriate parser
    name = path.name.lower()

    if name == "package-lock.json":
        return _parse_package_lock(path)

    if name == "yarn.lock":
        return _parse_yarn_lock(path)


    # Unknown filename — try JSON first, then yarn format.
    try:
        return _parse_package_lock(path)
    except LockfileParseError:
        pass

    try:
        return _parse_yarn_lock(path)
    except LockfileParseError:
        pass

    raise LockfileParseError(
        f"Cannot determine lockfile format for '{path.name}'. "
        "Expected 'package-lock.json' or 'yarn.lock'."
    )


def _parse_package_lock(path: Path) -> list[Package]:
    # Parse a package-lock.json file (npm lockfile v1, v2, v3)

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise LockfileParseError(f"Invalid JSON in '{path}': {exc}") from exc
    except OSError as exc:
        raise LockfileParseError(f"Cannot read '{path}': {exc}") from exc

    if not isinstance(data, dict):
        raise LockfileParseError(f"Unexpected top-level type in '{path}': expected object.")

    # npm v2/v3 use a 'packages' key; v1 uses 'dependencies'.
    if "packages" in data:
        return _extract_packages_v2(data, path)

    if "dependencies" in data:
        return _extract_packages_v1(data, path)

    raise LockfileParseError(
        f"'{path}' does not contain 'packages' or 'dependencies'. "
        "Is this a valid package-lock.json?"
    )


def _extract_packages_v2(data: dict, path: Path) -> list[Package]:
    # Extract packages from npm lockfile v2/v3 format ('packages' key)
    packages: list[Package] = []

    for pkg_path, meta in data["packages"].items():
        if not isinstance(meta, dict):
            continue
        if pkg_path == "":
            # Root package entry — not a dependency.
            continue

        name = _extract_name_from_path(pkg_path)
        packages.append(Package(
            name=name,
            version=meta.get("version") or "unknown",
            integrity=meta.get("integrity"),
            resolved=meta.get("resolved"),
            dependencies=list((meta.get("dependencies") or {}).keys()),
            dev=bool(meta.get("dev", False)),
            path=pkg_path,
            source=path.name,
        ))

    return packages


def _extract_packages_v1(data: dict, path: Path) -> list[Package]:
    # Extract packages from npm lockfile v1 format ('dependencies' key)
    packages: list[Package] = []

    for name, meta in data["dependencies"].items():
        if not isinstance(meta, dict):
            continue

        packages.append(Package(
            name=name,
            version=meta.get("version") or "unknown",
            integrity=meta.get("integrity"),
            resolved=meta.get("resolved"),
            dependencies=list((meta.get("requires") or {}).keys()),
            dev=bool(meta.get("dev", False)),
            path=f"node_modules/{name}",
            source=path.name,
        ))

    return packages


def _parse_yarn_lock(path: Path) -> list[Package]:
    # Parse a yarn.lock file (yarn classic v1 format)

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as exc:
        raise LockfileParseError(f"Cannot read '{path}': {exc}") from exc

    packages: list[Package] = []

    # Blocks are separated by blank lines.
    for block in re.split(r"\n\n+", content.strip()):
        package = _parse_yarn_block(block, path)
        if package is not None:
            packages.append(package)

    return packages


def _parse_yarn_block(block: str, path: Path) -> Package | None:
    # Parse a single entry block from a yarn.lock file

    lines = block.strip().splitlines()
    if not lines:
        return None

    header = lines[0].rstrip(":")
    if header.startswith("#"):
        return None

    # Header may be "pkg@v1, pkg@v2" — take the first entry.
    first_entry = header.split(",")[0].strip().strip('"')
    match = re.match(r'^(@?[^@]+)@', first_entry)
    if not match:
        return None

    name = match.group(1)
    version: str = "unknown"
    integrity: str | None = None
    resolved: str | None = None
    dependencies: list[str] = []
    in_deps = False

    for line in lines[1:]:
        stripped = line.strip()

        if stripped.startswith("version"):
            version = stripped.split('"')[1] if '"' in stripped else stripped.split()[-1]
        elif stripped.startswith("integrity"):
            integrity = stripped.split()[-1]
        elif stripped.startswith("resolved"):
            resolved = stripped.split('"')[1] if '"' in stripped else stripped.split()[-1]
        elif stripped == "dependencies:":
            in_deps = True
        elif in_deps and stripped and not stripped.startswith("#"):
            dep_name = stripped.split()[0].strip('"')
            dependencies.append(dep_name)

    return Package(
        name=name,
        version=version,
        integrity=integrity,
        resolved=resolved,
        dependencies=dependencies,
        dev=False,  # yarn.lock v1 does not distinguish dev from prod.
        path=f"node_modules/{name}",
        source=path.name,
    )


def _extract_name_from_path(pkg_path: str) -> str:
    '''
    Extract the package name from a node_modules path

    Handles both regular and scoped packages, including nested paths.

    Examples:
        >>> _extract_name_from_path("node_modules/axios")
        'axios'
        >>> _extract_name_from_path("node_modules/@types/node")
        '@types/node'
        >>> _extract_name_from_path("node_modules/a/node_modules/b")
        'b'

    Args:
        pkg_path: A node_modules path string from package-lock.json.

    Returns:
        The package name, including scope if present.
    '''

    parts = pkg_path.split("node_modules/")
    return parts[-1].strip("/")

