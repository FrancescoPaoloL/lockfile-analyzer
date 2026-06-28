from unittest.mock import MagicMock, patch
from lockfile_analyzer.registry import verify_packages
from lockfile_analyzer.models import Package, Severity
import urllib.error


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


def _mock_response(integrity: str):
    mock = MagicMock()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = f'{{"dist": {{"integrity": "{integrity}"}}}}'.encode()
    return mock


def test_matching_integrity_produces_no_findings():
    with patch("urllib.request.urlopen", return_value=_mock_response("sha512-abc")):
        findings = verify_packages([_pkg("express", integrity="sha512-abc")])
    assert findings == []


def test_mismatched_integrity_produces_high_finding():
    with patch("urllib.request.urlopen", return_value=_mock_response("sha512-xyz")):
        findings = verify_packages([_pkg("express", integrity="sha512-abc")])
    assert len(findings) == 1
    assert findings[0]["severity"] == Severity.HIGH
    assert findings[0]["rule"] == "registry"


def test_404_produces_high_finding():
    with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
        url="", code=404, msg="Not Found", hdrs=None, fp=None
    )):
        findings = verify_packages([_pkg("express")])
    assert len(findings) == 1
    assert findings[0]["severity"] == Severity.HIGH


def test_network_error_produces_low_finding():
    with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
        findings = verify_packages([_pkg("express")])
    assert len(findings) == 1
    assert findings[0]["severity"] == Severity.LOW


def test_package_without_integrity_is_skipped():
    findings = verify_packages([_pkg("express", integrity=None)])
    assert findings == []
