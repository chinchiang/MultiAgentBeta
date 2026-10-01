# Implementation contract — 0.2.0

Authoritative validation: backend/vibe_audit/domain.py, contracts.py, policy.py and docs/run-input.schema.json (schema version 2).

## API

All routes start with /api; with a session, an unknown /api path is a JSON 404. GET /session exchanges the startup token (X-VibeAudit-Token; printed as `#token=…` in the launch URL, or fixed with VIBEAUDIT_SESSION_TOKEN) for an 8-hour HttpOnly SameSite=Strict session cookie and the CSRF token; mutations require X-CSRF-Token. Host/Origin checks include workspace routes. Errors: {detail: ...}.

| Method | Route | Purpose |
|---|---|---|
| GET | /session, /capabilities | Session/CSRF and actual configured runtime availability |
| GET / PUT | /projects, /projects/{id} | List/save project settings |
| GET / PUT | /models, /models/{id} | List/save profiles; credential references only |
| GET | /catalogs?standard=... | Canonical IDs, versions and provenance |
| POST | /models/probe | Explicit endpoint contract with policy/budget |
| GET / POST | /runs | List/create immutable manifests |
| GET | /runs/{id} | State, usage, gaps and findings |
| POST | /runs/{id}/start, /cancel, /resume | Lifecycle transitions |
| GET | /runs/{id}/events | SSE progress events |
| GET | /runs/{id}/trace | Persisted entities, links and history |
| GET | /runs/{id}/evidence/{artifact_id} | Run-bound, hash-verified envelope |
| GET | /runs/{id}/report?format=json or markdown or sarif | Verified export |
| POST | /runs/{id}/retest | New run linked to original findings (trace `retests` links, Markdown and SARIF note the parent) |
| POST | /runs/{id}/reconcile | Operator attestation of worker cleanup; closes a cancelling run, which stays unresumable |
| POST | /runs/{id}/findings/{finding_id}/decision | Evidence-backed refuted/inconclusive decision |
| GET | /docs, /openapi.json | Interactive API docs and OpenAPI schema (session required) |

Stages: intake → preflight → whitebox → adjudication → threat_model → case_design → blackbox → report → complete.
Run status: created/running/cancelling/cancelled/completed/incomplete/blocked/failed.
Finding state: hypothesis/corroborated_static/validated_dynamic/refuted/inconclusive.
Execution state: pass/fail/inconclusive/blocked/execution_error/outcome_unknown. Tool completion does not imply security pass.

## Modules

- service: LangGraph orchestration, frozen manifests, sealed reviews, static evidence union, gates, journaled execution/report.
- providers: LiteLLM, explicit origins/credentials, schema/refusal/truncation validation, bounded retries, no fallback, unknown-usage latch.
- staging/snapshot: bounded raw private scanner input and separately redacted model context; repository config cannot control commands.
- worker_runtime/worker_entry: controller, independent trusted supervisor, isolated worker and Unix socket relay. Docker has no direct egress; process_test is explicitly unisolated and unavailable in production profile loading.
- lease: persistent capability binding, reservation ledger, renewal/expiry, unknown outcomes. Controller EOF or expiry revokes sockets before termination.
- tool_runners: fixed input/argv compilation → isolated execution → bounded artifact collection → normalized observations → oracle over broker evidence. No arbitrary shell/scripts.
- fixture_protocol: hashed reviewed reset/setup/cleanup, session capture, administrator-registered generic profiles; built-ins are synthetic.
- effect_collector: independent sequenced/HMAC-bound events and sink receipts; target JSON cannot confer provenance.
- store/traceability: PostgreSQL production, SQLite demo, atomic job/run commits, versioned entities/evidence links.
- catalog: pinned canonical IDs, version/source checks; category membership is not test coverage or certification.
- benchmark: seven comparative arms, common budgets/tool evidence, independent ground truth and incomplete accounting. Synthetic runs verify plumbing only.

## Roles and evidence

Live requires one commander and three distinct reviewer configurations/families. Optional dedicated architecture_mapper, challenger, threat_modeler and test_designer can use approved separate endpoints; otherwise the commander performs those roles. Reports verify existing evidence; an optional dedicated reporter may only reorder the exact existing finding IDs and cannot create claims. Models cannot add targets, run shell, change network policy or confirm findings by majority vote.

Reviewers receive the same core questions and snapshot without scanner findings or other reviewers' conclusions. Static scanners run concurrently but join only after the initial batch is sealed. Missing reviewers cannot produce a completed three-model review.

Cases bind threat model, requirement, source, fixture and case hashes. Controls and cleanup must also be in scope. Deployment change requires a new run; unknown outcomes require reconciliation/reset.

See docs/LINUX_SETUP.md, docs/VALIDATION.md and docs/DELIVERY.md.
