# Discrepancy-Balanced Review Assignment

**Status:** Research candidate only  
**Priority:** P4 among current discrepancy-theory transfer candidates  
**Authority impact:** None

## Motivation

Independent review can be distorted by workload composition even when review rules are correct. One reviewer or review pool may accidentally receive a disproportionate concentration of speculative, high-risk, low-evidence, cross-project, or specialty-heavy items.

A future assignment layer may use discrepancy-aware balancing to distribute review tasks across declared dimensions while preserving existing eligibility and authority rules.

## Candidate balancing dimensions

Potential dimensions include:

- repository / program;
- task type;
- risk class;
- novelty class;
- evidence maturity;
- source family;
- implementation vs research;
- cross-repository relevance;
- required specialty;
- expected review complexity;
- authority tier already required by policy.

Dimensions must be explicit and auditable. No hidden weighted review score should be introduced.

## Non-negotiable authority boundary

Balancing is subordinate to eligibility.

Correct order:

```text
review task
   -> resolve eligible reviewers / pools under canonical policy
   -> apply workload-composition balancing among eligible choices
   -> record assignment provenance
```

Forbidden order:

```text
balance first
   -> assign otherwise-ineligible reviewer because the matrix looks nicer
```

The partition/assignment mechanism must not:

- create review authority;
- bypass role or credential requirements;
- weaken independence requirements;
- change acceptance thresholds;
- convert balanced workload into evidence of correctness;
- silently alter adjudication semantics.

## Candidate experiment

Before any production use, compare:

1. random eligible assignment;
2. round-robin assignment;
3. ordinary stratification;
4. discrepancy-aware assignment;
5. affine-spectral-independence-inspired assignment if justified.

Measure:

- maximum per-dimension workload imbalance;
- reviewer/pool workload variance;
- concentration of high-risk or low-evidence cases;
- assignment stability;
- operational complexity;
- whether assignment affects review outcomes in undesirable ways.

If simple stratification or round-robin performs adequately, do not deploy more complicated machinery.

## Provenance requirement

Any future automated assignment should emit an immutable assignment manifest containing at least:

```text
assignment_id
review_task_ids
eligible_reviewer_set_digest
feature_schema_version
assignment_policy
algorithm_version
per-dimension imbalance diagnostics
assigned reviewer/pool
created_at
```

This is a research sketch, not an accepted schema.

## Dependency discipline

Do not implement this in `miskatonic-review-authority` yet.

Preferred sequence:

1. `msk-clio` tests discrepancy-balanced independent evidence witnessing.
2. `msk-gridiron` tests discrepancy-balanced validation cohorts once enough prospective evidence exists.
3. `msk-epistemic-engine` considers a domain-neutral partition contract only if application results justify extraction.
4. Review Authority may consume a proven contract only after its own assignment policy and independence constraints are explicitly modeled.

No canonical architecture edge should be added merely because this note exists.

## Source inspiration

- Nikhil Bansal and Haotian Jiang, *Decoupling via Affine Spectral-Independence: Beck-Fiala and Komlós Bounds Beyond Banaszczyk*, arXiv:2508.03961.
- Quanta Magazine coverage, 2026-08-21.

The relevant hypothesis is high-dimensional assignment balance. The discrepancy result is not being treated as a generic measure of reviewer quality, epistemic certainty, or correctness.