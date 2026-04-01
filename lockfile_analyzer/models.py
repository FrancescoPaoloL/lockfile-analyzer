# Shared data models for lockfile-analyzer

from enum import Enum
from typing import TypedDict


class Severity(str, Enum):
    # Finding severity levels, ordered from most to least critical.
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        return order.index(self) < order.index(other)


class Package(TypedDict):
    # A single package entry extracted from a lockfile.
    name: str
    version: str
    integrity: str | None
    resolved: str | None
    dependencies: list[str]
    dev: bool
    path: str
    source: str


class Finding(TypedDict):
    #A security finding produced by a rule.
    severity: Severity
    rule: str
    package: str
    version: str
    message: str
    suggestion: str
