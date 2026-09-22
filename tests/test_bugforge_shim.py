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


# --- P4: high-risk parallel modules locked to gungnir ---


def test_bugforge_cli_main_is_gungnir_main():
    from bugforge.cli import main as bf_main
    from gungnir.cli import main as gn_main

    assert bf_main is gn_main


def test_bugforge_secrets_scanner_is_gungnir():
    from bugforge.vulns.secrets import SECRET_PATTERNS as bf_pat
    from bugforge.vulns.secrets import SecretScanner as bf_cls
    from gungnir.vulns.secrets import SECRET_PATTERNS as gn_pat
    from gungnir.vulns.secrets import SecretScanner as gn_cls

    assert bf_cls is gn_cls
    assert bf_pat is gn_pat


def test_bugforge_secrets_aws_fixture_matches():
    """Same P0/P1 AWS key regex behavior via bugforge import path (no network)."""
    from bugforge.vulns.secrets import SecretScanner

    # fixture split like gungnir tests to avoid accidental secret scanners
    body = "config: AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE"
    matches = SecretScanner().scan(body)
    assert any(m.type == "aws_access_key_id" for m in matches)


def test_bugforge_ssrf_helper_is_gungnir():
    from bugforge.vulns.ssrf import SsrfHelper as bf_cls
    from bugforge.vulns.ssrf import CLOUD_METADATA as bf_meta
    from gungnir.vulns.ssrf import SsrfHelper as gn_cls
    from gungnir.vulns.ssrf import CLOUD_METADATA as gn_meta

    assert bf_cls is gn_cls
    assert bf_meta is gn_meta


def test_bugforge_ssrf_callback_uses_gungnir_creds():
    """OOB creds payload must match gungnir (not legacy bugforge@ host)."""
    from bugforge.vulns.ssrf import SsrfHelper

    payloads = SsrfHelper().callback_payloads("evil.example")
    creds = [p for p in payloads if p.technique == "oob:creds"]
    assert creds
    assert all("gungnir@" in p.payload for p in creds)
    assert all("bugforge@" not in p.payload for p in creds)


def test_bugforge_ssrf_private_ip_indicator():
    from bugforge.vulns.ssrf import SsrfHelper

    indicators = SsrfHelper().detect_internal_indicators("hit 10.0.0.5 internal")
    assert any("private_ip:10.0.0.5" in i for i in indicators)


def test_bugforge_fingerprint_is_gungnir():
    from bugforge.recon.fingerprint import TechFingerprinter as bf
    from gungnir.recon.fingerprint import TechFingerprinter as gn

    assert bf is gn


def test_bugforge_subdomains_is_gungnir():
    from bugforge.recon.subdomains import SubdomainEnum as bf
    from gungnir.recon.subdomains import SubdomainEnum as gn

    assert bf is gn


def test_bugforge_js_analyzer_is_gungnir():
    from bugforge.native.js_analyzer import SECRET_PATTERNS as bf_pat
    from bugforge.native.js_analyzer import analyze_js as bf_fn
    from gungnir.native.js_analyzer import SECRET_PATTERNS as gn_pat
    from gungnir.native.js_analyzer import analyze_js as gn_fn

    assert bf_fn is gn_fn
    assert bf_pat is gn_pat


def test_bugforge_js_secret_pattern_aws():
    """JS analyzer SECRET_PATTERNS detect AWS key via bugforge re-export."""
    from bugforge.native.js_analyzer import SECRET_PATTERNS
    import re

    sample = "const k = " + "'AKIA" + "IOSFODNN7EXAMPLE'"
    matched = False
    for pat, kind in SECRET_PATTERNS:
        if kind == "aws_key" and re.search(pat, sample):
            matched = True
            break
    assert matched
