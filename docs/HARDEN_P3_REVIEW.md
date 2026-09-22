# gungnir harden P3 — bugforge thin twin shim (review before push)

## Scope (locked)

1. `python -m bugforge --version` (and `-m bugforge` help/main) succeeds and
   behaves like gungnir (delegates to `gungnir.cli.main`)
2. `from bugforge.intelligence.verify import verify_criticals` is the **same**
   implementation as gungnir (re-export) — evidence XSS + statuses + scope gate
3. Thin re-exports only — no full bugforge tree rewrite
4. `tests/test_bugforge_shim.py` covers CLI version + verify identity/behavior
5. README: short legacy note; do not advertise bugforge as primary
6. This review doc
7. No `.github/workflows/ci.yml` edit (CI OAuth HUMAN-QUEUE)

**Not touched:** Guard SDK / sentinelagent-guard. ShadowsEye, PyPI, GUI, X,
malware/exploits, requiring `--scope` on all hunts. **No git push** from this
workspace.

Base: `66d79f3` (P2 live).

## Files changed

1. `bugforge/__main__.py` — delegates to `gungnir.cli.main` (deprecation in docstring)
2. `bugforge/__init__.py` — deprecation docstring; `__version__` re-exported from gungnir
3. `bugforge/intelligence/verify.py` — re-exports gungnir verify (same `verify_criticals` object)
4. `bugforge/intelligence/correlate.py` — add `Finding.verification_status` field for P2 attrs
5. `tests/test_bugforge_shim.py` — **new**
6. `README.md` — legacy compatibility note (gungnir remains preferred entry)
7. `docs/HARDEN_P3_REVIEW.md` — this file

## How the shim works

`python -m bugforge` loads `bugforge.__main__`, which calls `gungnir.cli.main` so
version/help/subcommands cannot drift from the shipped console script. Verify and
related status helpers are imported from `gungnir.intelligence.verify`, so any
`bugforge.intelligence.verify.verify_criticals` import is the identical function
object (evidence-based XSS, honest statuses, scope gate).

## Tests

```bash
cd /workspace/gungnir-harden
source .venv/bin/activate
pytest -q
python -m bugforge --version
python -m gungnir --version
```

Acceptance in `tests/test_bugforge_shim.py`:

- `python -m bugforge --version` exit 0; version string present (gungnir 4.x)
- `bugforge…verify_criticals is gungnir…verify_criticals`
- Evidence XSS confirms; alert-without-evidence does not
- bugforge `Finding` exposes `verification_status`

## Residual risks / dissent

- **Rest of `bugforge/` tree** (cli.py body, native modules, etc.) is still a
  parallel copy and can diverge for non-verify / non-`-m` paths. Only the CI-
  relevant `-m bugforge` entry and verify import are locked in this slice.
- **`bugforge.cli` itself** is unused when entering via `__main__` (which now
  calls gungnir). Direct `from bugforge.cli import main` still hits the twin —
  out of scope unless a later slice collapses the tree.
- **No-scope hunts** still allow-all retest (P2 trade-off unchanged).
- **Tests badge** left at `150+` (still accurate after a handful of new tests).

## Guard SDK

No edits to sentinelagent-guard / Guard SDK. Untouched.

## Push note

Local commit only from this workspace. Parent verifies then pushes.
