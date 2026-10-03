# Implementation contract — 0.2.0

Authoritative validation: backend/vibe_audit/domain.py, contracts.py, policy.py and docs/run-input.schema.json (schema version 2).

## API

All routes start with /api; with a session, an unknown /api path is a JSON 404. GET /session exchanges the startup token (X-VibeAudit-Token; printed as `#token=…` in the launch URL, or fixed with VIBEAUDIT_SESSION_TOKEN) for an 8-hour HttpOnly SameSite=Strict session cookie and the CSRF token. Every other /api request, reads included, needs both the cookie and X-CSRF-Token: cookies reach every port on the host, so the cookie alone opens nothing, and GET /session returns the token only to a caller that already presents it. Host/Origin checks include workspace routes. Errors: {detail: ...}.

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
| POST | /runs/{id}/findings/{finding_id}/decision | Evidence-backed refuted/inconclusive decision: cited black-box executions must test the finding's threats (the operator names them for a finding without threat links); refuting needs a pass and no failure of those threats in the run; a validated_dynamic finding is cleared only by a linked retest |
| GET | /openapi.json | OpenAPI schema (session and CSRF token required; no interactive docs page) |

Stages: intake → preflight → whitebox → adjudication → threat_model → case_design → blackbox → report → complete.
Run status: created/running/cancelling/cancelled/completed/incomplete/blocked/failed.
Finding state: hypothesis/corroborated_static/validated_dynamic/refuted/inconclusive.
Execution state: pass/fail/inconclusive/blocked/execution_error/outcome_unknown. Tool completion does not imply security pass. A fail whose target reset, or a later dispatch, is unconfirmed keeps its finding and carries target_state_confirmed=false; like outcome_unknown it stops the run and blocks resume. A deployment-identity change stops the run (deployment_changed=true) and blocks resume; each scheduled repetition sends the case once. Model-designed cases must match a strict case contract, and supplied cases are type-checked when the run is created. Runs with supplied or retest cases record automated threats those cases leave out as gaps; the threat model must keep every threat ID such a case tests. Worker results are rebuilt from supervisor fields and records, so extra keys a worker returns cannot set a verdict, observations or step labels; every content oracle needs a verified positive control that showed each forbidden canary, whatever executor ran the case.

## Modules

- service: LangGraph orchestration, frozen manifests, sealed reviews, static evidence union, gates, journaled execution/report.
- providers: LiteLLM, explicit origins/credentials, schema/refusal/truncation validation, bounded retries, no fallback, unknown-usage latch.
- staging/snapshot: bounded raw private scanner input and separately redacted model context; repository config cannot control commands.
- worker_runtime/worker_entry: controller, independent trusted supervisor, isolated worker and Unix socket relay. Docker has no direct egress; process_test is explicitly unisolated and unavailable in production profile loading.
- lease: persistent capability binding, reservation ledger, renewal/expiry, unknown outcomes. Controller EOF or expiry revokes sockets before termination.
- tool_runners: fixed input/argv compilation → isolated execution → bounded artifact collection → normalized observations → oracle over broker evidence. No arbitrary shell/scripts.
- fixture_protocol: hashed reviewed reset/setup/cleanup, session capture, administrator-registered generic profiles; built-ins are synthetic.
- effect_collector: independent sequenced events and sink receipts, HMAC-bound under a per-call key that exists only while the collector verifies them (stored bundles are evidence records, not re-verifiable signatures); target JSON cannot confer provenance.
- store/traceability: PostgreSQL production, SQLite demo, atomic job/run commits, versioned entities/evidence links.
- catalog: pinned canonical IDs, version/source checks; category membership is not test coverage or certification.
- benchmark: seven comparative arms, common budgets/tool evidence, independent ground truth and incomplete accounting. Synthetic runs verify plumbing only.

## Roles and evidence

Live requires one commander and three distinct reviewer configurations/families. Optional dedicated architecture_mapper, challenger, threat_modeler and test_designer can use approved separate endpoints; otherwise the commander performs those roles. Reports verify existing evidence; an optional dedicated reporter may only reorder the exact existing finding IDs and cannot create claims. Models cannot add targets, run shell, change network policy or confirm findings by majority vote.

Reviewers receive the same core questions and snapshot without scanner findings or other reviewers' conclusions. Static scanners run concurrently but join only after the initial batch is sealed. Missing reviewers cannot produce a completed three-model review.

Cases bind threat model, requirement, source, fixture and case hashes. Controls and cleanup must also be in scope. Deployment change requires a new run; unknown outcomes require reconciliation/reset.

See docs/LINUX_SETUP.md, docs/VALIDATION.md and docs/DELIVERY.md.
