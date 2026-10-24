# Typed rejection and partial-state semantics

Every rejected operation returns an `AdmissionDecision` with `eligible=false`, `authorized=false`, a stable `decision_code`, required follow-ups, `execution_began`, `external_side_effect`, `retry_permitted`, `retry_evidence_required`, `candidate_remains_eligible`, and credential-session issuance/revocation fields. An error never implies approval. Eligibility is conservatively false after rejection; only the fixed unchanged candidate may be reconsidered after supplying all valid evidence. Automatic retry is false. Error messages never contain raw credential or HTTP response text.

| Category | Codes | Retry evidence |
|---|---|---|
| Policy/route/risk | ADMISSION_POLICY_NOT_RATIFIED, ADMISSION_ROUTE_NOT_ALLOWED, RISK_CLASS_NOT_ELIGIBLE, HISTORICAL_AUTHORITY_MODIFIED, AUTHORIZATION_REVOKED | Reviewed, canonical, scoped and unrevoked policy; no proposal activation |
| Candidate | CANDIDATE_HEAD_STALE, CANDIDATE_BASE_MISMATCH, CANDIDATE_TREE_MISMATCH, CANDIDATE_DIGEST_MISMATCH, CANDIDATE_WORKTREE_DIRTY, CANDIDATE_FETCH_FAILED | Exact frozen identities and clean Git data; changed candidates require separate authorization |
| Review/evidence | REVIEW_REPORT_MISSING, REVIEW_REPORT_HASH_MISMATCH, REVIEW_HEAD_MISMATCH, REVIEW_VERDICT_NOT_ACCEPTED, REVIEW_PACKET_INCOMPLETE, PRIOR_VERIFICATION_FAILED, PRODUCER_BINDING_MISMATCH, TARGET_POLICY_IDENTITY_MISMATCH, ADMISSION_REQUEST_EVIDENCE_MISMATCH, EVIDENCE_GIT_OBJECT_UNAVAILABLE | Re-read exact report, complete packet, producer, prior verification and policy; fixed independence claims cannot be upgraded |
| Authorization | AUTHORIZATION_MISSING, AUTHORIZATION_PRINCIPAL_INVALID, AUTHORIZATION_EXPIRED, AUTHORIZATION_SCOPE_MISMATCH | Actual protected review by the fixed authenticated User, complete digest-bound risk acceptance and valid expiry |
| CI qualification | HOSTED_CI_EXCEPTION_NOT_ELIGIBLE, HOSTED_CI_CAUSE_UNVERIFIED, BASELINE_REGRESSION_UNMATCHED | Authenticated exact startup failure, zero steps, matched baseline and explicit compensating-control authorization |
| Schema | SCHEMA_VALIDATION_FAILED | Correct closed version/schema; unknown versions/properties never fall back |
| API/credential | AUTHENTICATED_GITHUB_READ_FAILED, GITHUB_APP_AUTHORIZATION_INSUFFICIENT, GITHUB_APP_TOKEN_SCOPE_MISMATCH, SIGNING_CREDENTIAL_UNAVAILABLE | Approved execution environment and scoped credentials; reconcile any session issued before failure |
| Publication/custody | CHECK_PUBLICATION_FAILED, CHECK_PUBLICATION_PARTIAL, ADMISSION_LEDGER_CONFLICT | Independently reconcile immutable ledger, actual check, signature and head; no blind duplicate |
| Integration | RELEASE_GATE_UNSATISFIED | Actual repository requirements and separate explicit release/merge authorization |
| Unknown | ADMISSION_UNKNOWN_ERROR | Investigate without exposing raw exception text; no inferred approval |

Execution/side-effect values describe the actual stage, rather than assuming all failures occurred before execution. Credential acquisition can begin before a later evidence rejection; the Actions wrapper reports that session and attempts revocation. A Git/Checks mutation may have reached GitHub even when its response fails. Such failures are PARTIAL, with side effects true and a sanitized `failure_cause_code` where known. Best-effort cancellation cannot erase the need to reconcile custody. A durable reservation prevents an ambiguous retry from creating another check. Unit tests model these stages explicitly with ephemeral keys and fake transports.

The same strict report, policy and request checks reject false independence or omitted limitations; they do not silently downgrade the claim into a weaker accepted review. The complete T01–T28 result matrix is retained with the actual JUnit evidence. No rejected control creates a new success check.
