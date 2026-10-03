# Architecture and methodology — 0.2.0

## Control and data planes

```mermaid
flowchart TB
  UI["Local React console"] --> API["FastAPI session / CSRF / scope"]
  API --> C["AI Commander + LangGraph"]
  C --> MG["LiteLLM gateway / per-agent profiles"]
  C --> G["Deterministic gates + job ledger"]
  G --> W["Read-only whitebox workers"]
  W --> TM["Versioned assets / flows / threats / requirements"]
  TM --> TC["Fixed case compiler / oracle / fixture hash"]
  TC --> S["Independent supervisor / persistent lease"]
  S --> B["Docker blackbox worker / network none"]
  B --> R["Unix socket relay"]
  R --> S
  S --> T["Exact approved staging interfaces"]
  T --> E["Independent effect collector / mock sink"]
  E --> A["Run-bound evidence + trace graph"]
  S --> A
  A --> UI
```

The trusted control plane includes operator configuration, the model gateway, supervisor, database and evidence writer. Repository, model, target, scanner artifacts and report text are untrusted data. JSON schema validation does not establish semantic correctness. The broker is the enforcement point; model prompts are not security boundaries.

The API listens on 127.0.0.1 only. A browser gets a session by sending the startup token, printed as the `#token=…` fragment of the launch URL or fixed with `VIBEAUDIT_SESSION_TOKEN`, to `/api/session` in `X-VibeAudit-Token`. It then holds an 8-hour HttpOnly, SameSite=Strict cookie, and every other `/api` request, reads included, must also carry `X-CSRF-Token`. Cookies are not isolated by port, so a staging service the operator opens in the same browser receives the cookie; the CSRF token lives only in the workbench tab's port-scoped sessionStorage, and `/api/session` never returns it to a cookie-only caller. The event stream and report exports are fetched with that header rather than through EventSource or plain links. Every request must carry an allowed Host, and an allowed Origin when it sends one.

## Ordered methodology

1. Freeze source staging, redacted context, deployment declaration, scope, budgets, profiles and resource versions. Record omissions.
2. Probe exact model endpoints. Each of three independent reviewers receives identical core questions and source context. Static scanners can run concurrently; initial reviewers cannot see their conclusions.
3. Seal all reviews, retain the union, preserve individual claims, inspect exact source references and run at most one challenger round. Votes cannot establish or dismiss a finding.
4. Establish assets, actors, trust boundaries, dataflows, threats and security requirements. Model-derived requirements retain derived provenance. Existing controls need evidence; unknowns remain visible.
5. Validate threat completeness and canonical standard IDs. Compile only traceable, scoped cases with positive controls, explicit oracle, allowed identities and cleanup.
6. Execute externally through a source-free worker. Every request checks capability, lease, run/case binding, method/path, identity, IP and budget. Deployment header mismatch stops the branch.
7. Evaluate actual observations. Distinguish pass/fail, inconclusive, blocked, execution_error and outcome_unknown. Preserve evidence and counter-evidence; export only run-owned verified artifacts.
8. A fix creates a new linked run with new source/deployment identification. Unknown side effects require reconciliation/reset rather than replay.

Standards classify threats and requirements; they do not create compliance automatically. The bundled registry contains ASVS 5.0.0, WSTG 4.2, LLM 2026 and Agentic 2026 canonical entries with source pins and quality notes. WSTG's duplicated source identifier retains both subitems in one canonical entry.

## Isolation and recovery

Linux Docker workers use nonroot UID 65532 for whitebox and 65533 for blackbox, dropped capabilities, read-only filesystems, resource/output limits and network none. Only whitebox receives the immutable source staging mount. Tool output goes to a size-bounded in-container tmpfs, not a host directory. The private staging copy (which keeps the repository's secret files for the scanners) is deleted when the whitebox stage completes and whenever an attempt ends, blocked, failed or cancelled; at startup any copy left on disk is removed. A resumed scan restages the source and must match the frozen intake exactly, or the run stops. Directories the intake skips (build output, dependencies, .git, links) are recorded as omissions, because neither scanners nor models see them. Each worker's host work directory is deleted after confirmed cleanup. Neither worker gets the Docker socket or target credentials. The privileged operator provisions images and offline data separately; scans never pull images or install dependencies.

The independent Python supervisor uses a Unix socket relay and owns target credentials, IP-pinned transport and dispatch ledger. It survives controller loss long enough to revoke communication and terminate the worker. Lease expiry, cancellation or controller EOF revoke sockets before process/container cleanup. It does not claim to undo an already completed remote side effect.

PostgreSQL stores job and lease records and the LangGraph checkpoints. Resume does not restore from those checkpoints. It is refused while a job is still sent, a worker awaits cleanup or an execution is outcome_unknown. Otherwise the graph restarts against the stored run record: manifest policy is checked again, stages already marked complete are skipped, an interrupted whitebox stage reuses sealed reviews whose input hash still matches the source digest, and blackbox re-runs the case gate on the stored cases before dispatching only case repetitions that have no execution yet. Jobs become sent before I/O; aggregate result and completed job are committed atomically. A crash may leave harmless orphan artifacts but cannot promote an uncertain dispatch into a fresh implicit attempt: on restart, or when an attempt stops before recording a result, every job still marked sent becomes an outcome_unknown execution with a gap, so exports show it and resume refuses the run. The supervisor separates three cases: a request that never left (connection or address failure) has no effect; a read-only request whose answer cannot be relayed (redirect, compression, size, non-UTF-8, a truncated body) is a known observation that ends only its case; a state-changing request in any of those situations stays outcome_unknown. A HEAD answer has no body whatever its Content-Length. A missing or changed deployment header stops the run, and resume refuses it. Execution and cleanup have separate fixed lifecycle identities, both replay-protected. SQLite and process_test are for explicitly synthetic/test paths, not production isolation.

## Tool and AI boundaries

ZAP executes only the reviewed requestor/passive plan. Schemathesis uses an explicit schema example. Playwright uses its API client. promptfoo uses local custom provider/eval assertions; PyRIT uses a controlled target. Tools do not independently expand targets or generate arbitrary programs. Their artifacts are auxiliary: security oracles rely on supervisor observations and independent receipts.

Built-in TS Web and Python AI targets are synthetic and deterministic. AI trials reset session/fixtures five times. Collector events distinguish proposed → denied/allowed → invoked → committed; a mock sink receipt proves only the synthetic sink effect. Generic target profiles require operator-declared lifecycle steps and a separately registered trusted collector binding. Text returned by the target cannot register a binding or forge trusted provenance.

## Limits

No complete semantic call graph or exhaustive source reading, no proven model independence, no effectiveness claim from synthetic benchmarks, no remote fleet/SaaS, no arbitrary browser automation, no production deployment/patching. Source-to-deployment matching via an operator-supplied header proves that header equality, not cryptographic correspondence to the source. Host administrators remain trusted; file hashes are not forensic immutability.
