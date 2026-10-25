# Work-order implementation and gate report

Terminal implementation disposition: RISK_BASED_ADMISSION_00A_IMPLEMENTED_UNRATIFIED.

Target disposition: CAUSALIS_B2_R2_RELEASE_GATES_INCOMPLETE.

This is the implementation's retained gate snapshot. The independent exact-head report and publication custody record are retained separately after the commit is frozen, avoiding a self-referential reviewed SHA. No desired future operation is represented as completed.

## A. Starting identities

Authority main a87e863173950c7f73072d1647780b3492ab0a43, tree fce694ff02ee4f3823235e936a0a9f8f13332f55; PR34 accepted 264bc27f65cbf7639f2181ee1eb2ea9d5a77fe4e. Target PR156 base d90892e3c2fdd66f2ffb13b17f7302b8689a9ced, head 089cec23afe6c15df9d7f085f4a0e3c298bd776a, tree a9d867a34ad21524a8f835774bca29ad33a8300d. Original R1 34c8c2d3a8f52a674e71e770b7a29d621fc8fb8b remains an ancestor. Live starting identities were reconciled before implementation. See [starting receipt](starting-state-reconciliation.json).

## B. Root cause

Ratified V2.1 supplies a defined protected local-review process; it does not currently supply a proportionate alternative for this nonproduction research case. Workstation service/key/model availability is an unconditional release dependency. The proposal separates scientific qualification, implementation review, canonical authority, authenticated admission, release authorization and integration. The preserved historical cloud workflow is superseded and is not activated.

## C. Ownership and contracts

Review Authority owns the new route, exact evidence reconciliation, protected authorization, App check and immutable receipt custody. Ruliology remains scientific owner. Runtime-governance contracts and control-plane integration were inspected read-only; no related repository was changed. Existing authority prior-verification, packet and RSA/App primitives are reused. See [activation and ownership](../../../docs/research-admission-v1/activation-and-custody.md).

## D. Risk classes

R0 documentary, R1 experimental research, R2 security/authority change and R3 high consequence are declared and tested. The only new-route eligibility is the exact fixed R1 CAUSALIS case. This authority patch is itself R2 and cannot qualify itself through that route. No other repository, PR, future SHA or class is enrolled. See [risk declaration](../../../docs/research-admission-v1/review-assurance-risk-classes.md).

## E. External-admission implementation

The new deterministic validator and authenticated Actions adapter enforce strict case/policy/root identities, report custody, complete packet semantics, actual GitHub principals and protected approval. Authority-only CAS custody prevents conflicting duplicate admissions; signed receipts bind the actual App key, request, evidence and check. Distinct check name: miskatonic/research-evidence-admission. Local/cloud impersonation is prohibited. Stale heads, partial writes and unknown errors fail closed. Receipt release_authorized and local_review_executed remain false. See [contract](../../../docs/research-admission-v1/external-evidence-admission-contract.md) and [failure semantics](../../../docs/research-admission-v1/failure-semantics.md).

## F. New schemas

NEW_ADMISSION_SCHEMA_VALIDATION is verified for the closed proposed root/policy and synthetic request, human authorization and signed receipt controls. Unknown properties/versions and invalid dates are rejected. LEGACY_TARGET_POLICY_SCHEMA_VALIDATION remains KNOWN_INCOMPATIBLE, not PASS. Historical V1 policy/schema bytes are preserved. A separate V2 design is proposed and tested without migration. See [schema results](new-schema-validation.json).

## G. Exact-head evidence

The actual frozen target recomputes prior PASS with candidate digest c70a9d2add189ae490ebcb7bc2ae06ee13e966827d6e6c10d7d341c67d880621. Every one of 53 paths is independently accounted for: 27 full diffs and 26 hash-bound artifacts; source diff bytes and per-path Git statuses/blobs/classifications are checked. The report digest reproduces afe7911a3f32271faf02221e34fd5ad730a1bd6dee73787c04fe65db226e9c22. See [reconciliation](exact-head-evidence-reconciliation.json) and [coverage](changed-path-coverage-verification.json).

## H. Independence

CAUSALIS exact-head ACCEPT_WITH_LIMITATIONS remains reported distinct-agent Codex review, sharing provider and filesystem. OS isolation and institutional/reviewer signature are not established. The producer's GitHub transport account overlaps the bounded human approver; runtime records that fact independently of the dispatcher's identity. Human risk acceptance is not independent scientific review. See [demarcation](../../../docs/research-admission-v1/reviewer-independence-demarcation.md).

## I. Hosted CI assessment

Authenticated Test40127087396, Lint40127087410 and Schema40127087284 runs bind the target head; all four jobs have zero steps and authenticated billing/spending startup annotations. CI remains HOSTED_CI_INFRASTRUCTURE_UNAVAILABLE_WITH_COMPENSATING_EVIDENCE; no check conclusion is rewritten. Compensating controls are eligible evidence awaiting explicit human authorization. Protection/ruleset reads returned 403 and remain an integration blocker. See [assessment](ci-infrastructure-exception-assessment.json) and [authenticated job evidence](ci-authenticated-job-evidence.json).

## J. Negative controls

All T01–T28 pass in the retained synthetic security tests. Rejections have explicit typed reasons, no new success check, conservative retry requirements and stage-aware side-effect reporting. Further controls cover partial custody, idempotency, unknown risks, missing protected environment, unedited ratification, packet bytes, producer/approver overlap and historical preservation. See [control matrix](negative-control-results.json) and [threat model](../../../docs/research-admission-v1/miskatonic-review-authority-threat-model.md).

## K. Regression results

Local authority baseline: 127 passed. Local candidate: 186 passed, including 59 added cases and the actual frozen-corpus integration test. No original test status changes or new failures. Focused new controls remain portable; hosted environments without the private corpus skip only the separate integration test. Changed Python lint, new-file formatting, compilation and action-reference audit pass. The binary dependency lock was download/hash-verified for Python3.12 without installing or executing packages. This is local verification, not hosted CI. See [regression receipt](regression-and-compatibility-results.json).

Retained target evidence was independently reconciled, not rerun as a campaign: 126 focused pass; candidate942 pass/eight failures versus original855 pass/the same eight; all87 new tests pass. The original inherited failures remain failures. Earlier development corrected a V2-schema test fixture that used an undeclared digest key; no schema constraint was weakened to make it pass.

## L. Historical preservation

All207 predecessor files match exact base/candidate Git blobs and working-tree hashes. All8 R1 JSON outputs match original R1 byte-for-byte. The historical builder's existing8/8 reproduction is retained as frozen evidence; no new experiment or Wolfram call was made. The authority test run's failing logging shims recorded zero Wolfram invocations. Historical authority roots, reviewer policies, receipts, reports and local/cloud workflow bytes are unchanged. Existing-file changes are limited to the CLI adapter/name guard and full-history authority CI fetch required for predecessor-object tests. See [preservation](historical-preservation-verification.json) and the empty invocation log in [regression evidence](regression-and-compatibility-results.json).

Scientific dispositions remain56 fixtures,48 exact/eight divergent,20,866 transitive relations and maximum depth5. Mechanism attribution remains MODEL_REPRODUCED; finite replay is not a general theorem. No new scientific claim is made.

## M. Independent review

The separate security reviewer must inspect the final frozen authority HEAD/tree and issue a report outside this immutable candidate. Provisional review informed hardening but is not final approval. Provider/filesystem sharing and lack of institutional reviewer signature must remain explicit. See [review packet](independent-review-packet.md). A final acceptance does not authorize merge or activation.

## N. Authority activation

The successor root and scoped policy are PROPOSED, not canonical or ratified. Activation requires independent R2 exact-head review, explicit trusted-starter merge authorization, verified canonical merge, and authenticated human ratification binding the separate security report and complete accepted tree. No coding agent self-ratification is permitted. See [pending authorization record](authorization-and-ratification-receipt.md).

## O. CAUSALIS admission

NOT AUTHORIZED, NOT EXECUTED. No protected environment existed at reconciliation; no new-route human approval, genuine signed admission or App check was issued. The implementation explicitly rejects unratified local execution before credentials/network activity. See [rejection evidence](unratified-execution-rejection.json). No Local Review V2.1 receipt was fabricated or reused.

## P. Target integration

PR156 remains draft/unmerged at the unchanged target head/tree above. No target merge, canonical custody receipt or CAUSALIS canonical disposition is claimed. Admission, protection qualification and target merge authorization are separate future gates.

## Q. Blockers and risks

Current gates: S7 unratified policy; S10/S19 absent exact human authorization; missing protected environment; unexercised production Actions/App signing path; target protection visibility; hosted-CI compensating acceptance and separate target merge authorization. Shared-provider/filesystem review and producer/approver account overlap are explicit accepted-risk inputs, not stronger independence. No App key is requested from the researcher or copied locally. See [security audit](security-and-credential-exposure-audit.md).

## R. Next action and follow-up

Freeze and publish one draft authority candidate, obtain the final independent exact-head report, then present that concrete result for explicit trusted-starter authorization. After authorized canonical activation and protected human approval, exercise the exact-case admission and read back its authenticated check before considering separate target integration. Broader rollout, V2 policy migration and any maintained cloud backend require a separately reviewed and authorized follow-up work order. This work order is not complete merely because the implementation exists.
