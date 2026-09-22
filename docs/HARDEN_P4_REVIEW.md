# gungnir harden P4 — expand bugforge shim (review before push)

## Scope (locked)

1. Re-export high-risk parallel `bugforge` modules from `gungnir` (thin wrappers, no copy-paste bodies):
   - `bugforge/cli.py` → `gungnir.cli` (`main`)
   - `bugforge/vulns/secrets.py` → `gungnir.vulns.secrets`
   - `bugforge/vulns/ssrf.py` → `gungnir.vulns.ssrf`
   - `bugforge/recon/fingerprint.py` → `gungnir.recon.fingerprint`
   - `bugforge/recon/subdomains.py` → `gungnir.recon.subdomains`
   - `bugforge/native/js_analyzer.py` → `gungnir.native.js_analyzer`
2. Extend `tests/test_bugforge_shim.py` (P3 + P4 identity/behavior)
3. README: one-line note that bugforge is a legacy shim expanding toward gungnir
4. This review doc
5. No `.github/workflows/ci.yml` edit; no Guard SDK; **no git push**

Base: `6e55113` (P3 live).

## Files changed

1. `bugforge/cli.py` — re-exports `gungnir.cli.main`
2. `bugforge/vulns/secrets.py` — re-exports SecretScanner / patterns
3. `bugforge/vulns/ssrf.py` — re-exports SsrfHelper / constants
4. `bugforge/recon/fingerprint.py` — re-exports TechFingerprinter
5. `bugforge/recon/subdomains.py` — re-exports SubdomainEnum
6. `bugforge/native/js_analyzer.py` — re-exports `analyze_js` / SECRET_PATTERNS
7. `tests/test_bugforge_shim.py` — P4 identity + fixture assertions
8. `README.md` — legacy shim expanding toward gungnir
9. `docs/HARDEN_P4_REVIEW.md` — this file

## Tests

```bash
cd /workspace/gungnir-harden
source .venv/bin/activate
pytest -q
python -m bugforge --version
python -c "from bugforge.cli import main as bm; from gungnir.cli import main as gm; assert bm is gm"
```

Acceptance additions:

- `bugforge.cli.main is gungnir.cli.main`
- secrets/ssrf callables identical; AWS fixture + gungnir@ OOB creds via bugforge path
- fingerprint / subdomains / js_analyzer same objects; JS aws_key pattern matches

## Residuals (OK for later slices)

- `bugforge/web/`, `bugforge/api/`, `bugforge/orchestrator/` (and other twins) remain parallel copies
- Remaining `bugforge/vulns/` (xss, sqli, cors, idor), `bugforge/recon/content.py`, other native modules
- No-scope hunts still allow-all retest (P2 trade-off)
- Guard SDK / CI workflow untouched

## Guard SDK

No edits to sentinelagent-guard / Guard SDK. Untouched.

## Push note

Local commit only from this workspace. Parent verifies then pushes.
