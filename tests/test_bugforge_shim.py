"""Legacy bugforge twin must stay locked to gungnir CLI + verify (P3)."""
from __future__ import annotations

from pathlib import Path

import asyncio
import subprocess
import sys
from unittest.mock import patch

import pytest

from bugforge.intelligence.correlate import Finding as BugforgeFinding
from bugforge.intelligence.severity import Severity
from gungnir.intelligence import verify as gungnir_verify
from gungnir.intelligence.correlate import Finding as GungnirFinding
from gungnir.intelligence.verify import (
    STATUS_CONFIRMED,
    STATUS_NOT_REPRODUCED,
)


def test_bugforge_module_version_subprocess():
    """``python -m bugforge --version`` exits 0 and prints a version string."""
    root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, "-m", "bugforge", "--version"],
        capture_output=True,
        text=True,
        cwd=str(root),
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "") + (proc.stderr or "")
    assert "4.0.0" in out or "gungnir" in out.lower()
    # Must not advertise the old twin version as authoritative
    assert "bugforge 3.1.0" not in out


def test_verify_criticals_is_gungnir_function():
    from bugforge.intelligence.verify import verify_criticals as bf_vc
    from gungnir.intelligence.verify import verify_criticals as gn_vc

    assert bf_vc is gn_vc


def test_bugforge_verify_evidence_xss_confirms():
    """Import path bugforge.verify uses evidence-based XSS (P2 engine)."""
    from bugforge.intelligence.verify import verify_criticals

    evidence = "<script>XSS_MARKER_SHIM</script>"
    f = GungnirFinding(
        title="XSS",
        severity=Severity.HIGH,
        asset="app.example.com",
        source="test",
        finding_type="xss",
        evidence=evidence,
        url="https://app.example.com/q",
    )

    def fake_fetch(url, **kw):
        return f"<html>{evidence} alert(1)</html>"

    with patch.object(gungnir_verify, "_fetch", fake_fetch):
        out = asyncio.run(verify_criticals([f]))
    assert out[0].verification_status == STATUS_CONFIRMED
    assert out[0].verified is True


def test_bugforge_verify_alert_without_evidence_not_confirmed():
    from bugforge.intelligence.verify import verify_criticals

    evidence = "<script>XSS_MARKER_SHIM</script>"
    f = GungnirFinding(
        title="XSS",
        severity=Severity.HIGH,
        asset="app.example.com",
        source="test",
        finding_type="xss",
        evidence=evidence,
        url="https://app.example.com/q",
    )

    def fake_fetch(url, **kw):
        return "<html><body onerror=alert(1)>alert('xss')</body></html>"

    with patch.object(gungnir_verify, "_fetch", fake_fetch):
        out = asyncio.run(verify_criticals([f]))
    assert out[0].verification_status == STATUS_NOT_REPRODUCED
    assert out[0].verified is False


def test_bugforge_finding_has_verification_status_field():
    f = BugforgeFinding(
        title="t",
        severity=Severity.INFO,
        asset="a",
        source="s",
        finding_type="xss",
    )
    assert hasattr(f, "verification_status")
    assert f.verification_status == "unverified"
