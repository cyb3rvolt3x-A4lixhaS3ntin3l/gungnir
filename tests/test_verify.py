"""Unit tests for honest verification statuses (mocked HTTP only)."""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from gungnir.intelligence.correlate import Finding
from gungnir.intelligence.severity import Severity
from gungnir.intelligence import verify as verify_mod
from gungnir.intelligence.verify import (
    STATUS_CONFIRMED,
    STATUS_NOT_REPRODUCED,
    STATUS_SKIPPED,
    STATUS_UNVERIFIED,
    verify_criticals,
)
from gungnir.scope.validator import parse_brief
from gungnir.cli import _finding_to_dict


def _xss(severity=Severity.HIGH, evidence="<script>XSS_MARKER_42</script>",
         url="https://app.example.com/search?q=1", **kw) -> Finding:
    return Finding(
        title="Cross-Site Scripting (XSS)",
        severity=severity,
        asset="app.example.com",
        source="test",
        finding_type="xss",
        evidence=evidence,
        url=url,
        **kw,
    )


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test if any real network helper is reached without a mock."""
    def boom(*a, **k):
        raise AssertionError("live network attempted")
    # Default: block; individual tests patch as needed.
    monkeypatch.setattr(verify_mod, "_fetch", boom)
    monkeypatch.setattr(verify_mod, "_fetch_status", boom)
    monkeypatch.setattr(verify_mod, "_fetch_headers", boom)


def test_xss_confirmed_when_evidence_in_body(no_network, monkeypatch):
    evidence = "<script>XSS_MARKER_42</script>"
    f = _xss(evidence=evidence)
    monkeypatch.setattr(
        verify_mod, "_fetch",
        lambda url, **kw: f"<html>hi {evidence} alert(1)</html>",
    )
    out = _run(verify_criticals([f]))
    assert out[0].verification_status == STATUS_CONFIRMED
    assert out[0].verified is True


def test_xss_not_confirmed_when_only_generic_alert(no_network, monkeypatch):
    """Body has alert/onerror but NOT the finding's evidence → not confirmed."""
    evidence = "<script>XSS_MARKER_42</script>"
    f = _xss(evidence=evidence)
    fetch_calls = []

    def fake_fetch(url, **kw):
        fetch_calls.append(url)
        return "<html><body onerror=alert(1) onload=alert(1)>alert('xss')</body></html>"

    monkeypatch.setattr(verify_mod, "_fetch", fake_fetch)
    out = _run(verify_criticals([f]))
    assert len(fetch_calls) == 1
    assert out[0].verification_status == STATUS_NOT_REPRODUCED
    assert out[0].verified is False


def test_medium_skipped_no_fetch(no_network, monkeypatch):
    f = _xss(severity=Severity.MEDIUM)
    called = []

    def fake_fetch(*a, **k):
        called.append(1)
        return "x"

    monkeypatch.setattr(verify_mod, "_fetch", fake_fetch)
    out = _run(verify_criticals([f]))
    assert out[0].verification_status == STATUS_SKIPPED
    assert out[0].verified is False
    assert called == []


def test_low_skipped_no_fetch(no_network, monkeypatch):
    f = _xss(severity=Severity.LOW)
    called = []
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: called.append(1) or "x")
    out = _run(verify_criticals([f]))
    assert out[0].verification_status == STATUS_SKIPPED
    assert called == []


def test_missing_url_unverified_no_fetch(no_network, monkeypatch):
    f = _xss(url="")
    called = []
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: called.append(1) or "x")
    out = _run(verify_criticals([f]))
    assert out[0].verification_status == STATUS_UNVERIFIED
    assert out[0].verified is False
    assert called == []


def test_unknown_type_unverified_no_confirm(no_network, monkeypatch):
    f = Finding(
        title="Something odd",
        severity=Severity.HIGH,
        asset="app.example.com",
        source="test",
        finding_type="weird_thing",
        evidence="abc",
        url="https://app.example.com/x",
    )
    # unknown types never fetch in _retest — still no network
    out = _run(verify_criticals([f]))
    assert out[0].verification_status == STATUS_UNVERIFIED
    assert out[0].verified is False


def test_url_outside_scope_no_fetch(no_network, monkeypatch):
    scope = parse_brief("in_scope:\n  - *.example.com\n")
    f = _xss(url="https://evil.other.com/xss")
    called = []
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: called.append(1) or "x")
    out = _run(verify_criticals([f], scope=scope))
    assert called == []
    assert out[0].verification_status == STATUS_UNVERIFIED
    assert out[0].extra.get("verification_reason") == "out_of_scope"
    assert out[0].verified is False


def test_scope_allows_callable_gates_fetch(no_network, monkeypatch):
    f = _xss(url="https://app.example.com/x")
    called = []
    monkeypatch.setattr(verify_mod, "_fetch", lambda *a, **k: called.append(1) or "x")
    out = _run(verify_criticals([f], scope_allows=lambda u: False))
    assert called == []
    assert out[0].verification_status == STATUS_UNVERIFIED


def test_in_scope_xss_fetches_and_confirms(no_network, monkeypatch):
    scope = parse_brief("in_scope:\n  - *.example.com\n")
    evidence = "EVIDENCE_TOKEN_99"
    f = _xss(evidence=evidence, url="https://app.example.com/search")
    monkeypatch.setattr(verify_mod, "_fetch", lambda url, **kw: f"ok {evidence}")
    out = _run(verify_criticals([f], scope=scope))
    assert out[0].verification_status == STATUS_CONFIRMED
    assert out[0].verified is True


def test_finding_to_dict_includes_verification():
    f = _xss()
    f.verification_status = STATUS_CONFIRMED
    f.verified = True
    d = _finding_to_dict(f)
    assert d["verification"] == STATUS_CONFIRMED
    assert d["verified"] is True


def test_finding_to_dict_default_unverified():
    f = _xss()
    d = _finding_to_dict(f)
    assert d["verification"] == STATUS_UNVERIFIED
    assert d["verified"] is False


def test_empty_evidence_xss_unverified(no_network, monkeypatch):
    f = _xss(evidence="")
    monkeypatch.setattr(
        verify_mod, "_fetch",
        lambda url, **kw: "<html>alert(1) onerror=x</html>",
    )
    # empty evidence → can't evidence-match; _retest returns None before fetch
    # (no evidence → return None without fetch)
    out = _run(verify_criticals([f]))
    assert out[0].verification_status == STATUS_UNVERIFIED
    assert out[0].verified is False


def test_endpoint_git_confirmed(no_network, monkeypatch):
    f = Finding(
        title=".git exposed",
        severity=Severity.CRITICAL,
        asset="app.example.com",
        source="test",
        finding_type="endpoint",
        url="https://app.example.com/.git/config",
        evidence="",
    )
    monkeypatch.setattr(verify_mod, "_fetch_status", lambda url, **kw: 200)
    out = _run(verify_criticals([f]))
    assert out[0].verification_status == STATUS_CONFIRMED
    assert out[0].verified is True


def test_no_scope_allows_all_backcompat(no_network, monkeypatch):
    evidence = "TOKEN"
    f = _xss(evidence=evidence, url="https://anywhere.test/x")
    monkeypatch.setattr(verify_mod, "_fetch", lambda url, **kw: evidence)
    out = _run(verify_criticals([f]))  # no scope → allow all
    assert out[0].verification_status == STATUS_CONFIRMED
