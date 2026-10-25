# Proposed activation and custody procedure

This document is a proposed procedure. No human authorization, authority ratification, App check, signed admission, or target merge has occurred under it.

## Ownership and compatibility

Review Authority owns route selection, reviewer disclosures, evidence reconciliation, authorization, receipt custody and authenticated checks. Ruliology owns scientific claims and frozen evidence. The control plane may consume an immutable released receipt; it does not decide admissions. No related repository is modified.

The existing runtime-governance decision/custody contracts were inspected. Their capability/runtime and Ed25519 receipt semantics do not represent this GitHub App RSA research-admission decision. This implementation reuses Review Authority's existing prior verifier, packet builder, RSA attestation and App authentication instead of copying an authority into another repository. Future common primitives need separate compatibility review.

Local Review V2.1 roots, reviewer policies, receipt verification and admission workflow remain unchanged. Selecting LOCAL_REVIEW_V2_1 directs callers to that implementation with its actual isolation/key/model requirements. Selecting an unknown route fails. The historical cloud workflow remains superseded; this change supplies no cloud-policy activation.

## Independent authority review and human ratification

1. Review the complete frozen authority commit and tree as an R2 security/authority change. The new external route cannot admit that authority change itself. Retain the separate agent's exact-head report and its provider/filesystem/signature limitations.
2. Obtain explicit trusted-starter authorization to merge that exact authority candidate. This work order and a draft PR are not merge authorization. Recheck the exact head, merge by the authorized method, then verify merge parents, tree and origin main.
3. Retain the security report as a separate, unedited issue comment on that authority PR. GitHub publication authenticates the publishing account; the technical review remains reported distinct-agent review. Required headers are enforced in `verify_ratification()` and must include exact accepted head/tree and R2 risk class. Do not invent a reviewer signature or institutional independence.
4. The trusted starter must personally publish an unedited JSON ratification comment conforming to `research-authority-ratification-v1.schema.json`, binding accepted head/tree, root/policy digests, external security-comment ID and SHA-256, candidate digest, all limitations and explicit bootstrap-risk acceptance. A coding agent must not publish that human attestation on the starter's behalf.
5. Runtime verifies that the PR is merged, its accepted head is an ancestor, the entire accepted tree equals current canonical main, and every implementation/policy/root object matches. Any later main-tree change requires fresh review and governance qualification; it does not inherit this ratification. A deployment from a proposal branch is denied before App credential use.

The fixed starter is GitHub User `kowen9024AI`, numeric ID `267743825`, corroborated through authenticated API reads. The policy does not allow root authors to nominate a replacement principal. There is no current ratification comment or accepted authority merge for this proposal.

## Protected, exact-request human authorization

An authorized repository administrator must configure the `research-evidence-admission` environment with exactly that required User reviewer. At starting reconciliation no environments existed. Automatically creating an environment without that rule fails runtime verification. Administrator bypass without an actual matching human review also fails.

After canonical ratification, dispatch the new workflow with the actual ratifying authority PR/comment IDs. The read-only prepare job recomputes the frozen candidate, packet, report and CI compensation, then shows the complete request and approval JSON template in its job summary. Dispatch does not authorize admission.

The human must inspect those records and approve the waiting protected job, using the typed JSON comment. It binds the request digest, canonical authority commit, root/policy/candidate/CI digests, all limitations, explicit compensating-control acceptance and an expiry within 24 hours and the case-policy expiry. Do not blindly copy the attestation without performing the review. The API supplies the real approver; request-supplied actor strings are ignored. Review history has no approval timestamp, so `recorded_at` is explicitly the authority's observation time.

The Ruliology PR's producing transport account overlaps the trusted starter. Runtime corroborates that account against the actual PR author and records the overlap even when a different account dispatches the workflow. Human risk acceptance is distinct from independent scientific review.

## Privileged execution and durable custody

The workflow installs only hash-pinned binary dependencies from the public package index. App secrets remain in authority Actions; a temporary key file is removed on exit. A short-lived installation token is independently verified to cover only the target repository, with Actions/Contents/Pull requests read and Checks write. Authority ledger writes use the authority workflow token. Target Git objects are fetched as data with candidate hooks disabled; scientific code and tests never execute under signing credentials.

The canonical request uses sorted UTF-8 JSON, compact separators, finite numbers and one trailing newline. The request digest excludes no hidden fields; the receipt digest covers all receipt fields except its own digest and signature. Existing RSA attestation serialization signs the resulting complete receipt. This is the authority's signature, never a signature by the external reviewer.

The `research-evidence-admissions-v1` authority branch stores a reservation, immutable signed receipt and terminal state. Non-forced Git reference updates act as compare-and-swap: sibling concurrent updates fail. The receipt has an immutable commit/path reference. This ledger is separate from main and never writes into Ruliology. Identical completed authorized requests return the same verified check/receipt without another check. Conflicting, reserved or partially published requests require custody reconciliation before retry.

Only `miskatonic/research-evidence-admission` may be emitted. Before success, runtime refreshes human approval, authority ratification/security report, current authority main and target PR head; then it reads back the App ID, exact head, request and receipt digest. If publication becomes ambiguous, it best-effort cancels only its own new check and returns `CHECK_PUBLICATION_PARTIAL`. It never updates historical CI checks. `release_authorized` remains false in every admission receipt.

## Release and future adoption

The exact case expires at the policy's timestamp and is single-use. A separately governed canonical revocation disables the route; any authority-main movement invalidates an in-flight workflow. Receipt history remains immutable. Rollback leaves Local Review V2.1 available under its unchanged contract.

Target merge still requires actual GitHub requirements, qualification of any infrastructure exception, and separate trusted-starter authorization. Starting branch-protection/ruleset reads returned plan-related 403; integration requirements remain unresolved. No administrative bypass or fabricated CI success is authorized.

Future work should review a general assurance-class adoption contract, an explicit V2 target-policy migration, and a maintained external-cloud backend. This proposal enrolls no other repository, PR or future head.

GitHub contracts used: [workflow approval history](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run), [protected environments](https://docs.github.com/en/rest/deployments/environments), [non-forced Git reference updates](https://docs.github.com/en/rest/git/refs#update-a-reference), and [App check runs](https://docs.github.com/en/rest/checks/runs).
