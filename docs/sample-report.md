# 前端契約驗證 · 合成示範

Run: 9a332c1d-5e29-49f3-ad62-7c707fee767f
Mode: demo | Status: incomplete

SYNTHETIC DEMO ONLY: not real model or application validation

## Findings

- [high / hypothesis] Synthetic cross-tenant order disclosure
  Evidence: 5daea406-47b7-446f-968b-b142adbc12a3, ac940515-8fb8-46e9-bb16-c2e20b30560d, a5737f36-9cbb-498d-b5f1-cd2622896326
- [high / hypothesis] Synthetic agent export claim needs effect evidence
  Evidence: a5737f36-9cbb-498d-b5f1-cd2622896326
- [high / validated\_dynamic] Synthetic vulnerable tenant boundary
  Evidence: ba752b87-5874-4531-b696-534265cac2d7

## Coverage gaps

- C-003: inconclusive — A required trusted observation is missing.

## Executions

- C-001: fail — A forbidden test canary was observed in the response.
- C-002: pass — The specified response invariant held with verified prerequisites.
- C-003: inconclusive — A required trusted observation is missing.

## Capability limits
