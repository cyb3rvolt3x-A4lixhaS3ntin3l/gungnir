"""
Verification engine — re-tests critical/high findings to confirm before reporting.
Non-destructive: only re-sends the original request and checks if the finding persists.

Honest statuses (emitted as ``verification`` in JSON):
  confirmed | not_reproduced | unverified | skipped

``Finding.verified`` stays boolean for compat (True only when confirmed).
"""
from __future__ import annotations
import urllib.request
import urllib.error
from typing import Callable, List, Optional, Union

from .correlate import Finding, Severity
from ..utils.logger import get_logger

log = get_logger()

# Machine-readable verification statuses
STATUS_CONFIRMED = "confirmed"
STATUS_NOT_REPRODUCED = "not_reproduced"
STATUS_UNVERIFIED = "unverified"
STATUS_SKIPPED = "skipped"

ScopeAllows = Callable[[str], bool]


def _resolve_scope_allows(
    scope: Optional[object] = None,
    scope_allows: Optional[ScopeAllows] = None,
) -> Optional[ScopeAllows]:
    """
    Build an allow-check callable.

    - If ``scope_allows`` is given, use it.
    - Else if ``scope`` has ``is_in_scope``, fail-closed via that.
    - Else None → allow all (no scope context provided).
    """
    if scope_allows is not None:
        return scope_allows
    if scope is None:
        return None

    is_in_scope = getattr(scope, "is_in_scope", None)
    if callable(is_in_scope):
        def _allows(url: str) -> bool:
            try:
                ok, _reason = is_in_scope(url)
                return bool(ok)
            except Exception:
                return False  # fail-closed
        return _allows
    return None


def _set_status(f: Finding, status: str, verified: Optional[bool] = None) -> None:
    f.verification_status = status
    if verified is None:
        f.verified = status == STATUS_CONFIRMED
    else:
        f.verified = verified
    # Keep a short machine note in extra (status string, not prose heuristics)
    f.extra["verification"] = status


async def verify_criticals(
    findings: List[Finding],
    scope: Optional[object] = None,
    scope_allows: Optional[ScopeAllows] = None,
) -> List[Finding]:
    """
    Re-test critical and high findings. Returns updated findings.

    ``scope`` / ``scope_allows`` gate outbound retest fetches. When scope is
    provided, URLs outside scope are fail-closed (no fetch → unverified).
    When neither is provided, all URLs are allowed (back-compat).
    """
    allows = _resolve_scope_allows(scope=scope, scope_allows=scope_allows)

    for f in findings:
        if f.severity not in (Severity.CRITICAL, Severity.HIGH):
            _set_status(f, STATUS_SKIPPED)
            continue

        if not f.url:
            _set_status(f, STATUS_UNVERIFIED)
            continue

        url = f.url
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        if allows is not None and not allows(url):
            log.debug(f"Verification skipped (out of scope): {url}")
            _set_status(f, STATUS_UNVERIFIED)
            f.extra["verification_reason"] = "out_of_scope"
            continue

        try:
            result = _retest(f, url)
            if result is True:
                _set_status(f, STATUS_CONFIRMED, verified=True)
                f.confidence = min(1.0, f.confidence + 0.2)
            elif result is False:
                _set_status(f, STATUS_NOT_REPRODUCED, verified=False)
            else:
                _set_status(f, STATUS_UNVERIFIED, verified=False)
        except Exception as e:
            log.debug(f"Verification error for {f.title}: {e}")
            _set_status(f, STATUS_UNVERIFIED, verified=False)

    return findings


def _retest(f: Finding, url: str) -> Optional[bool]:
    """
    Re-test a single finding.
    Returns True (confirmed) / False (not reproduced) / None (can't verify).
    """
    # For XSS: confirm only if the finding's evidence substring appears in the body.
    # Do NOT use generic alert/onerror/onload heuristics.
    if f.finding_type == "xss":
        evidence = (f.evidence or "").strip()
        if not evidence:
            return None
        body = _fetch(url)
        if body is None or body == "":
            return None
        if evidence in body:
            return True
        return False

    # For exposed files (.git, .env, swagger): check if still accessible
    if f.finding_type == "endpoint":
        if any(p in url for p in [".git", ".env", "swagger", "openapi"]):
            result = _fetch_status(url)
            if result == 0:
                return None
            if result == 200:
                return True
            return False
        return None

    # For secrets: check if the file is still accessible
    if f.finding_type == "secret":
        result = _fetch_status(url)
        if result == 0:
            return None
        if result == 200:
            return True
        return False

    # For GraphQL: check if introspection still works
    if "graphql" in f.finding_type:
        body = _fetch(
            url,
            method="POST",
            data='{"query":"{ __schema { types { name } } }"}',
            content_type="application/json",
        )
        if body is None or body == "":
            return None
        if "__schema" in body or "types" in body:
            return True
        return False

    # For CORS: check if ACAO still reflects
    if f.finding_type == "cors":
        headers = _fetch_headers(url, origin="https://evil.com")
        if not headers:
            return None
        acao = headers.get("access-control-allow-origin", "")
        if acao and acao != "*":
            return True
        return False

    # Can't verify other types
    return None


def _fetch(url: str, method: str = "GET", data: str = None,
           content_type: str = None, timeout: int = 10) -> str:
    """Fetch URL body."""
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"}
    if content_type:
        headers["Content-Type"] = content_type

    req = urllib.request.Request(url, method=method, headers=headers,
                                  data=data.encode() if data else None)
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace")
        except Exception:
            return ""
    except Exception:
        return ""


def _fetch_status(url: str, timeout: int = 10) -> int:
    """Fetch URL status code only."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    })
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _fetch_headers(url: str, origin: str = "", timeout: int = 10) -> dict:
    """Fetch URL headers."""
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"}
    if origin:
        headers["Origin"] = origin
    req = urllib.request.Request(url, headers=headers)
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
    except Exception:
        return {}
