"""
Compare two parsed lockfiles and return only the packages
that are new or have a changed integrity hash.

Used by the CLI --diff flag to focus analysis on what a PR
actually introduces, rather than re-scanning the entire lockfile.
"""

from .models import Package


def diff_packages(
    before: list[Package],
    after: list[Package],
) -> list[Package]:
    """Return packages in *after* that are absent or changed in *before*.

    A package is considered changed if its integrity hash differs —
    same name and version but different hash is a strong signal that
    the lockfile was modified without going through the registry.
    """
    before_index: dict[str, str | None] = {
        pkg["name"]: pkg.get("integrity")
        for pkg in before
    }

    changed: list[Package] = []

    for pkg in after:
        name = pkg["name"]
        integrity = pkg.get("integrity")

        if name not in before_index:
            # Package is new in this PR
            changed.append(pkg)
        elif before_index[name] != integrity:
            # Same package, different hash — high signal
            changed.append(pkg)

    return changed
