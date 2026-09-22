# gungnir harden P2 — honest verification (review before push)

## Scope (locked)

1. Honest `verification` status on every finding in `--json` / report dicts:
   `confirmed` | `not_reproduced` | `unverified` | `skipped`
2. Keep boolean `verified` for compat (`true` only when `confirmed`)
3. XSS confirm only if the finding’s **evidence** substring is in the retest body
   (drop generic `alert` / `onerror` / `onload` heuristics)
4. Retest must not fetch URLs outside hunt scope (reuse `gungnir/scope/`)
5. No live network in tests — mock `_fetch` / `_fetch_status` / `_fetch_headers`
6. README honesty: tests badge **150+**, serve default `127.0.0.1`
7. This review doc

**Not touched:** Guard SDK / sentinelagent-guard. Web UI polish, PyPI, CI workflow
edits, greenfield, malware/exploit PoCs, X. **No git push** from this workspace.

Base: `c969ae3` (P1 live).

## Files changed

1. `gungnir/intelligence/verify.py` — status enum helpers; evidence-based XSS;
   optional `scope` / `scope_allows` (fail-closed when provided; allow-all only when
   no scope context); sets `Finding.verification_status` + `verified`
2. `gungnir/intelligence/correlate.py` — `Finding.verification_status` field
   (default `unverified`)
3. `gungnir/cli.py` — hunt path passes `scope=` into `verify_criticals`;
   `_finding_to_dict` emits `verification`
4. `gungnir/web/app.py` — same status emission; passes parsed brief into verify
   when present (no GUI expansion)
5. `tests/test_verify.py` — **new**; mocked HTTP only
6. `README.md` — 150+ badge; serve bind honesty (`127.0.0.1` default;
   `0.0.0.0` opt-in note only)
7. `docs/HARDEN_P2_REVIEW.md` — this file

## Tests

```bash
cd /workspace/gungnir-harden
source .venv/bin/activate
pytest -q
# P1 baseline: 150 passed; P2: 150 + new verify tests
```

Acceptance covered in `tests/test_verify.py`:

- Critical/high XSS + evidence in mocked body → `confirmed` / `verified=true`
- Same finding, evidence absent, body still has `alert` → **not** confirmed
- Medium/low → `skipped`, no fetch
- Missing URL / unknown type → `unverified`, no fetch
- URL outside scope → no fetch; `unverified` (+ `verification_reason=out_of_scope`)
- `_finding_to_dict` includes `verification`

## Residual risks / dissent

- **No-scope hunts still allow retest fetches to any finding URL.** Fail-closed only
  when a brief/`scope_allows` is provided. Operators who omit `--scope` still get
  the old allow-all retest behavior (documented trade-off for back-compat).
- **Empty XSS evidence** cannot be confirmed (returns `unverified`); scanners that
  omit evidence lose retest confirmation until they populate it.
- **TLS verify remains off** on retest fetches (pre-existing); out of this slice.
- **Non-XSS types** (endpoint/secret/graphql/cors) still use type-specific checks;
  only XSS evidence matching was the P2 honesty fix.
- **`bugforge/` twin** not updated (same as P1); `gungnir` console path is what
  ships.
- **Web path** threads scope when `req.scope` is set; if the UI posts an empty
  brief, retest is still allow-all.

## Guard SDK

No edits to sentinelagent-guard / Guard SDK. Untouched.

## Push note

Local commit only from this workspace. Parent verifies then pushes.
