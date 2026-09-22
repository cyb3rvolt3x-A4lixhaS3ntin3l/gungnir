# gungnir harden P0 — review before push

## Files
1. `gungnir/scope/validator.py` — brief section/bullet regexes were double-escaped; scope never parsed.
2. `gungnir/vulns/ssrf.py` — private-IP / internal-host indicator regexes same bug.
3. `tests/test_advanced_pipeline.py` — empty-state used `self.ev` instead of empty `ev`.
4. `README.md` — replace dead `pip install gungnir-security` with clone + `pip install -e .`; link gungnir-lab; authorized-scope note.
5. `.github/workflows/ci.yml` — verify `gungnir --version` (bugforge kept as soft check).
6. `docs/HARDEN_P0_REVIEW.md` — this file (optional to commit).

## Tests
```bash
cd /workspace/gungnir-harden
python3 -m venv .venv && source .venv/bin/activate
pip install -e . pytest
pytest -q
# 134 passed
```

## Out of this PR
- Broader double-escaped regex audit (secrets, js_analyzer, fingerprint, subdomains)
- PyPI publish of `gungnir-security` (Founder call — README now source-first)
- ShadowsEye harden (next after this lands)

## Guard SDK
No edits to sentinelagent-guard / Guard SDK. Untouched.
