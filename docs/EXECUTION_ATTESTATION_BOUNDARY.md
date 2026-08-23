# Review Authority Execution Attestation Boundary (WO-MSK-EXECUTION-EVIDENCE-ORG-01A)

## Authority Boundary

- **Review Authority**: Owns independent verification, exact digest binding (`execution_ledger_digest`, `execution_result_digest`, `candidate_sha`), review attestation, and producer/reviewer separation enforcement.
- **Verification vs. Reconstruction**: Review Authority verifies that the derived result matches the append-only ledger and fails closed if evidence is missing or corrupt. It **never** reconstructs missing command history from PR prose or agent recollection.

## Attestation Rules

1. **Digest Binding**: Verification requires matching `wo_id`, `run_id`, `attempt_id`, `ledger_sha256`, and `result_sha256`.
2. **Fail-Closed Missing Provenance**: If execution evidence is absent or corrupted, review fails closed (`REQUEST_CHANGES` or `REJECT`).
3. **Producer/Reviewer Separation**: The executor principal/provider cannot serve as the review principal for the same execution result (`EXECUTOR_REVIEWER_PRINCIPAL_COLLISION`).
