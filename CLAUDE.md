# CLAUDE.md

Vibe Audit 0.2.1: evidence-gated multi-model security testing workbench. Python backend in `backend/vibe_audit`, React console in `frontend/`. Architecture: README "Architecture Overview" and `docs/ARCHITECTURE.md`; API and module contracts: `IMPLEMENTATION.md`.

## Commands

Run everything from the repository root; catalogs, fixtures and the built UI are not inside the Python package.

```sh
python -m pip install --require-hashes -r requirements.lock.txt   # pinned, hash-checked
PYTHONPATH=backend python -m pytest tests -q -rs                  # -rs: read every skip reason
python scripts/package-release.py --manifest-only                 # after changing any tracked file
python scripts/package-release.py --check                         # CI runs this
python scripts/redact-receipts.py --check                         # receipts in docs/ name no host or account
cd frontend && npm ci && npm run typecheck && npm run build        # dist/ is committed
git add -N frontend/dist && git diff --exit-code -- frontend/dist # CI: dist must match the sources
```

## Rules

- `source-manifest.sha256` pins every tracked file. Regenerate it with the script, never by hand.
- `.gitattributes` sets `* -text`: keep each file's existing line endings (`scripts/package-release.py` and some others are CRLF). Shell scripts stay LF.
- README.md, docs/ARCHITECTURE.md, IMPLEMENTATION.md, docs/VALIDATION.md and other docs are bilingual (Chinese and English halves). Change both halves together.
- Authoritative validation lives in `domain.py`, `contracts.py`, `policy.py` and `docs/run-input.schema.json`; keep docs consistent with them.
- A skipped test is not a pass. Do not record skips as verification in docs/VALIDATION.md.
- Run `python scripts/redact-receipts.py` before adding a JUnit receipt to docs/, then `python scripts/summarize-validation.py`.
- `.claude/` and this file are excluded from releases by `scripts/package-release.py`.

## Integration test switches

Unset means the matching tests skip with a stated reason.

| Variable | Enables |
|---|---|
| `VIBEAUDIT_TEST_DATABASE_URL`, `VIBEAUDIT_TEST_POSTGRES` | PostgreSQL store, lease and checkpoint tests |
| `VIBEAUDIT_TEST_NODE` | TypeScript Web fixture (needs Node 24) |
| `VIBEAUDIT_TEST_WORKER_IMAGE`, `VIBEAUDIT_INTEGRATION_IMAGE`, `VIBEAUDIT_FIXTURE_IMAGE`, `VIBEAUDIT_TEST_RUNTIME_CONFIG` | Docker worker, scanner, tool and fixture integrations (see docs/DOCKER_INTEGRATION_TESTING.md) |
| `VIBEAUDIT_JUNIT_XML` | `scripts/verify-linux.sh` writes a JUnit receipt |
