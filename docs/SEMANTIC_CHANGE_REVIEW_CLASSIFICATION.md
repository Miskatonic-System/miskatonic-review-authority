# Semantic Change Review Classification v0.1

**Status:** PROPOSED REVIEW DIRECTION / NOT POLICY  
**Repository:** `Miskatonic-System/miskatonic-review-authority`  
**Canonical starting main:** `17192b40f08d25e596f6ad43fa71e4c27ae83385`  
**Motivating architecture:** Miskatonic agentic source-control and workspace fabric  
**Authority delta:** NONE  
**Trusted reviewer, signer, policy, schema, or service change:** NONE

## 1. Purpose

Preserve a future review-routing model for high-throughput agent-generated changes.

Agentic development can increase the number of candidate changes far faster than human review capacity. Review therefore needs a semantic risk model that is independent of diff size, agent confidence, or the source-control substrate used to produce the candidate.

```text
SMALL DIFF
        !=
LOW-RISK CHANGE

LARGE DIFF
        !=
HIGH-RISK CHANGE

AGENT-GENERATED
        !=
UNREVIEWABLE

AUTOMATED CLASSIFICATION
        !=
ACCEPTANCE VERDICT
```

This document is a non-operative direction note. It does not modify Review Authority policy, trusted principals, signing requirements, schemas, or deployed behavior.

## 2. Candidate semantic classes

| Class | Typical content | Primary review focus |
| --- | --- | --- |
| `DOCUMENTATION_ONLY` | Prose, pointers, diagrams, non-normative notes | Scope, accuracy, claim ceiling, source quality |
| `EVIDENCE_ONLY` | Receipts, reports, manifests, frozen observations | Custody, derivation, immutability, chronology |
| `TEST_OR_HARNESS` | Tests, fixtures, validators, launchers, benchmark code | Behavioral coverage, anti-gaming, hidden authority |
| `SCIENTIFIC_LOGIC` | Models, algorithms, inference, analysis, formal claims | Independent scientific or mathematical review |
| `AUTHORITY_OR_GOVERNANCE` | Policies, trust roots, grants, ratification, constitutional rules | Human authority, supersession, constitutional consistency |
| `RUNTIME_OR_DEPLOYMENT` | Services, schedulers, packages, system configuration, host effects | Operational safety, rollback, current-state verification |
| `SECRETS_OR_IAM` | Credentials, principals, access controls, token or key paths | Least authority, secret custody, audience and currentness |
| `CROSS_REPOSITORY_CONTRACT` | Schemas, APIs, provider-consumer contracts, supersession | Provider-consumer compatibility and complete ancestry |
| `MIXED_OR_UNKNOWN` | Multiple classes or unresolved semantics | Fail closed to the strongest applicable review path |

A candidate may carry multiple classes. The strongest applicable requirements remain in force.

## 3. Classification is not authority

Semantic classification answers:

```text
WHAT KIND OF CHANGE IS THIS?
WHICH REVIEW QUESTIONS APPLY?
WHICH REVIEWERS OR AUTHORITIES ARE REQUIRED?
```

It does not answer:

```text
IS THE CHANGE CORRECT?
IS THE EVIDENCE ACCEPTABLE?
MAY THE CHANGE MERGE?
MAY AN EXTERNAL EFFECT OCCUR?
```

```text
CLASSIFICATION
        !=
REVIEW
        !=
RATIFICATION
        !=
MERGE AUTHORITY
        !=
RUNTIME AUTHORITY
```

## 4. Producer self-classification boundary

A producer may propose a semantic class, but it may not unilaterally lower review requirements.

Required future behavior:

- classification is computed or checked from changed paths, object identities, schemas, ownership metadata, and repository policy;
- a producer-provided class is treated as an assertion;
- conflicts resolve to `MIXED_OR_UNKNOWN` or the strongest plausible class;
- classification evidence is bound to the exact candidate commit and tree;
- classification is recomputed after any candidate change;
- a reviewer can inspect why each class was assigned;
- unknown files or semantic owners fail closed.

```text
PRODUCER SAYS DOCUMENTATION_ONLY
        !=
DOCUMENTATION_ONLY ESTABLISHED
```

## 5. Exact candidate binding

Every future classification record should bind:

```text
repository identity
candidate commit
candidate tree
base commit
complete candidate parent vector
changed path set
per-path blob identity and mode
classification rule version
proposed classes
resolved classes
reasons and evidence references
unknowns and conflicts
observed_at
authority = NONE
```

For merge candidates, complete parent vectors matter. First-parent-only views may hide imported authority, evidence, repair, or supersession ancestry.

```text
FIRST-PARENT DIFF
        !=
COMPLETE MERGE SEMANTICS
```

## 6. Proposed routing matrix

The following is direction only, not active policy.

| Class | Candidate future review route |
| --- | --- |
| `DOCUMENTATION_ONLY` | Focused accuracy, scope, and source-boundary review |
| `EVIDENCE_ONLY` | Custody and derivation review separate from the evidence producer |
| `TEST_OR_HARNESS` | Implementation review plus hostile anti-gaming controls |
| `SCIENTIFIC_LOGIC` | Domain-independent scientific or mathematical review |
| `AUTHORITY_OR_GOVERNANCE` | Independent policy review plus explicit human ratification where required |
| `RUNTIME_OR_DEPLOYMENT` | Source review plus host/runtime qualification and rollback evidence |
| `SECRETS_OR_IAM` | Security review and human authority for any access expansion |
| `CROSS_REPOSITORY_CONTRACT` | Provider and consumer review with exact version and ancestry binding |
| `MIXED_OR_UNKNOWN` | Review for every plausible class; no automatic downgrade |

A candidate classified into a lighter route may still receive a stronger review at the repository owner's discretion.

## 7. Agentic source-control integration

A future workspace fabric may produce a machine-readable changeset before creating a remote branch or pull request. Review classification may begin from that frozen changeset, but the final review must bind the published Git candidate.

Candidate flow:

```text
workspace changeset sealed against exact base
        ->
provisional semantic classification
        ->
trusted host publication as Git commit
        ->
classification replay against published commit and tree
        ->
review routing
```

```text
LOCAL CHANGESET CLASSIFICATION
        !=
PUBLISHED CANDIDATE CLASSIFICATION
```

If publication changes bytes, paths, file modes, parents, or metadata relevant to classification, the earlier record is stale.

## 8. Source-control substrate neutrality

Review Authority should not depend on whether the candidate was produced through:

- ordinary Git;
- a linked worktree;
- sparse or partial materialization;
- a future workspace broker;
- Oak or Jujutsu comparator tooling;
- Cursor Origin, Diversion, or another forge.

The review input remains the exact admitted Git candidate and its evidence.

```text
SUBSTRATE UX
        !=
REVIEW SEMANTICS
```

Any substrate that cannot export complete, ordinary Git candidate identity and ancestry is not eligible for this routing model without separate policy work.

## 9. Candidate hostile controls

A later qualification should include:

- prose file that changes executable configuration through embedded metadata;
- evidence file that also modifies a trust root;
- test change that weakens an assertion while adding passing cases;
- runtime code hidden under a documentation-like path;
- generated file whose producer changed;
- schema change with unchanged filename;
- cross-repository contract change labeled local-only;
- secret or credential path introduced by indirection;
- merge commit whose second parent contains governance changes;
- producer-declared `DOCUMENTATION_ONLY` contradicted by changed file modes or content;
- unknown binary file;
- candidate rewritten after classification.

Each must route to the strongest applicable class or fail closed.

## 10. Evidence versus acceptance

Review records should continue to separate:

```text
CLASSIFICATION EVIDENCE
INDEPENDENT REVIEW EVIDENCE
HUMAN RATIFICATION
MERGE RECEIPT
RUNTIME EFFECT RECEIPT
```

No object substitutes for another.

A passing documentation review does not accept a scientific claim. A passing scientific review does not authorize deployment. A trusted reviewer identity does not become a human signer or ratifier.

## 11. Future implementation boundary

A future implementation should be separately proposed only after:

- the Systems architecture is accepted;
- Org Automation qualifies the changeset and ancestry inputs;
- repository owners agree on class mappings;
- Review Authority schemas and policy impacts are explicitly scoped;
- negative controls demonstrate that self-downgrade fails closed;
- the human ratifier boundary remains unchanged.

No policy JSON, trusted-principal list, schema, or runtime source should be modified merely to preserve this direction note.

## 12. Nonclaims

This document does not:

- classify any existing pull request;
- change the acceptance level of any candidate;
- add or remove a trusted producer, reviewer, or signer;
- create automatic review or merge authority;
- alter human ratification requirements;
- authorize a service, model call, workflow, or deployment;
- issue the proposed Org Automation source-control exploration work order.

```text
AUTHORITY_DELTA = NONE
POLICY_DELTA = NONE
IMPLEMENTATION_DELTA = NONE
```