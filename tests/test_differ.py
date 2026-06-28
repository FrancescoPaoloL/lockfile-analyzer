from lockfile_analyzer.differ import diff_packages
from lockfile_analyzer.models import Package


def _pkg(name: str, version: str = "1.0.0", integrity: str | None = "sha512-abc") -> Package:
    return Package(
        name=name,
        version=version,
        integrity=integrity,
        resolved=None,
        dependencies=[],
        dev=False,
        path="",
        source="npm",
        scripts=None,
    )


def test_new_package_is_flagged():
    before = [_pkg("express")]
    after = [_pkg("express"), _pkg("malicious")]
    result = diff_packages(before, after)
    assert len(result) == 1
    assert result[0]["name"] == "malicious"


def test_changed_integrity_is_flagged():
    before = [_pkg("express", integrity="sha512-aaa")]
    after = [_pkg("express", integrity="sha512-bbb")]
    result = diff_packages(before, after)
    assert len(result) == 1
    assert result[0]["name"] == "express"


def test_unchanged_package_is_not_flagged():
    before = [_pkg("express")]
    after = [_pkg("express")]
    result = diff_packages(before, after)
    assert result == []


def test_empty_after_returns_empty():
    before = [_pkg("express")]
    after = []
    result = diff_packages(before, after)
    assert result == []


def test_empty_before_returns_all():
    before = []
    after = [_pkg("express"), _pkg("lodash")]
    result = diff_packages(before, after)
    assert len(result) == 2

