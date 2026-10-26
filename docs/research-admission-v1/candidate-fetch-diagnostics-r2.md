# Candidate acquisition diagnostics — proposed R2 repair

This is an instrumentation-only R2 security/authority change under WO-MSK-REVIEW-AUTHORITY-00B-D3-R2. It does not identify the historical root cause, activate a route, or authorize another admission run.

## Observed evidence and limits

Canonical authority `65a9b4a57ed2f84a4a75ea7e30b8ff64d2af51c8` produced CANDIDATE_FETCH_FAILED in admission job121387964069 of run40265776575 and preparation job121730319061 of run40367852203. Both recorded scoped credential issuance and revocation. The first prepare succeeded. No signed receipt, admission ledger or authenticated research-admission check followed. The first protected review used the correct User/environment but had an empty comment, which independently fails authorization schema validation; the observed Git error preceded that check.

The historical implementation mapped both fetch and checkout nonzero exits to one code and retained no operation identity or stderr. Present User-session Git ref availability does not establish the failing App-token operation. Network, authentication, permissions and checkout root causes remain undetermined. Controlled tests prove diagnostic behavior for injected failures, not a reproduction of the hosted root cause.

## Failure contract

Public Git-acquisition rejection remains CANDIDATE_FETCH_FAILED, with eligible/authorized/retry_permitted false. The existing failure_cause_code field identifies a fixed stage and cause:

| Stage prefix | Causes |
|---|---|
| CANDIDATE_GIT_INIT | IO_FAILED, UNAVAILABLE, INVOCATION_FAILED, TIMEOUT, MALFORMED_RESPONSE, NONZERO_EXIT |
| CANDIDATE_GIT_FETCH | UNAVAILABLE, INVOCATION_FAILED, TIMEOUT, MALFORMED_RESPONSE, NONZERO_EXIT |
| CANDIDATE_GIT_CHECKOUT | UNAVAILABLE, INVOCATION_FAILED, TIMEOUT, MALFORMED_RESPONSE, NONZERO_EXIT |
| CANDIDATE_GIT_OBJECT_VERIFICATION | UNAVAILABLE, INVOCATION_FAILED, TIMEOUT, MALFORMED_RESPONSE, NONZERO_EXIT, TYPE_MISMATCH, TREE_MISMATCH, HEAD_MISMATCH |
| CANDIDATE_INSTALLATION_SCOPE_MISMATCH | Existing GITHUB_APP_TOKEN_SCOPE_MISMATCH public decision remains unchanged |
| CANDIDATE_EVIDENCE_RECONCILIATION_FAILED | Existing typed evidence decision is retained; unknown exceptions remain ADMISSION_UNKNOWN_ERROR |

Only internal stage/cause constants are serialized. No stderr parsing, HTTP body, token, Authorization header, key, argv, process environment or raw exception text is published. Acquisition/evidence exception chains are suppressed at the public wrapper. Subprocesses have a300-second timeout and no automatic retry. Timeout is a typed failure, not an inferred outage or authentication diagnosis.

Both declared commits must be present and commit-typed. The candidate tree must match the policy before checkout; the resulting HEAD must match afterward. Existing target repositories also undergo these identity checks rather than bypassing validation. Hooks remain disabled during checkout and LFS smudge remains skipped. Fetch retains the same fixed repository, exact head/base and child-environment-only authentication. No target scientific code executes.

## Governance and continuation

Only research_admission_github.py's implementation-object hashes change in the proposed root manifest. Policy, schemas, workflows, App permissions, ratification principal, protected review and signing/publication gates remain unchanged. The original root bytes/digests are retained in append-only repair evidence and canonical Git history. The new root remains PROPOSED; old ratification6407727704 binds the old accepted authority tree and cannot qualify this repair.

Required future steps: independent exact-head acceptance; separate exact-head authority merge authorization; appropriate refreshed authority/root ratification binding; then separately authorized controlled diagnostic preparation. A successful future preparation still requires the actual human's complete raw approval JSON and independent signed-receipt/ledger/check reconciliation. This work order dispatches no admission run and requests no protected approval. Target PR156 stays draft/unmerged at089cec23afe6c15df9d7f085f4a0e3c298bd776a. Local Review V2.1, historical cloud status, scientific53-path custody,207 predecessor files and8 frozen outputs are preserved.
