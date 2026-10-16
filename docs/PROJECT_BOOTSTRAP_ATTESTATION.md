# Review Authority Boundary for `project-bootstrap-v1`

**Protocol owner:** `Miskatonic-System/miskatonic-control-plane`  
**External trust anchor:** `Miskatonic-System/miskatonic-review-authority`

Review Authority certifies a completed bootstrap candidate; it does not perform project bootstrapping.

## Review Authority may attest

A bootstrap attestation may bind:

```text
protocol_id
profile_id
repository
base_sha
candidate_sha
bootstrap_manifest_digest
source-verification receipt digest(s)
local-validation receipt digest
independent-evaluator receipt digest
human acceptance ref
policy version
verdict
```

The attestation should preserve the existing authority properties: exact candidate identity, immutable evidence references, external reviewer identity, fail-closed behavior, and signed/authenticated verdict provenance.

## Review Authority SHALL NOT own

- repository scaffolding;
- source discovery;
- DOI/bibliographic lookup;
- source canonicality inference;
- semantic claim extraction;
- source/evidence verification performed on behalf of the producer;
- local project validator generation;
- project profile generation;
- atlas registration;
- candidate mutation while reviewing it.

Moving these responsibilities into Review Authority would collapse the separation between candidate production and independent authorization.

## Preconditions for a positive bootstrap verdict

A `project-bootstrap-v1` positive verdict SHOULD require, where the selected profile requires them:

1. candidate SHA resolves and descends from the declared base;
2. bootstrap manifest validates against the pinned protocol schema;
3. required input identities/digests are bound;
4. source-verification receipts are present and do not identify the producer as its own verifier;
5. project-local validation passed against the exact candidate;
6. independent evaluator passed against the exact candidate and manifest;
7. human acceptance includes an immutable/versioned review reference;
8. no artifact being reviewed can modify Review Authority or its trusted policy while requesting approval.

## Non-substitution rule

Review Authority SHALL NOT reconstruct missing provenance or treat its own semantic review as a substitute for missing required bootstrap receipts. Missing evidence is a bootstrap failure and should fail closed.

## Atlas registration

Review Authority attestation may be a prerequisite for atlas registration under a profile, but the attestation itself does not mutate the organization graph or create architecture edges.
