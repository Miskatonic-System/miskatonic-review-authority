# Independent exact-head review: CAUSALIS B2 R2 provenance repair

Repository: `Miskatonic-System/msk-ruliology`, draft PR #156.

Accepted candidate HEAD: `089cec23afe6c15df9d7f085f4a0e3c298bd776a`.

Accepted candidate tree: `a9d867a34ad21524a8f835774bca29ad33a8300d`.

Canonical base: `d90892e3c2fdd66f2ffb13b17f7302b8689a9ced`.

Original R1 ancestor: `34c8c2d3a8f52a674e71e770b7a29d621fc8fb8b`.

Implementation ancestor: `b53b787d73ebcee22acbd11069170c71ff96b46c`.

Reviewer: separately delegated Codex agent `r2_independent_review`, OpenAI GPT-6 family as identified in this session. The reviewer did not author or modify the candidate. This is a distinct implementation/evidence review by an agent sharing the producer's provider and filesystem. It is not the OS-isolated Local Review V2.1 service identity, a signed receipt, or release authorization.

## Scope and exact-head custody

This report binds the complete canonical-base-to-final-head diff, including the original R1 patch, forward implementation repair, and R2 evidence/report commit. I independently checked that the actual 53 changed paths exactly equal `artifacts/causalis-b2-exact-edge-reconciliation-00a-r2/r2_changed_file_inventory.json`. The final evidence commit adds 34 artifact/report files only; all five implementation/test/builder blobs are identical to the reviewed implementation ancestor. The original R1 remains an ancestor. The candidate worktree was clean during the final checks. No candidate file was edited by this reviewer.

The candidate's internal gate records are preparation snapshots: they truthfully leave final external review, policy and release gates pending and avoid embedding their enclosing commit hash. This external report supplies final HEAD/tree qualification without a recursive self-reference. It does not qualify any later HEAD.

## Method and independent evidence

I read the five-file repair diff, traced every exact-emitting entry point, reviewed current R2 contracts and receipts, compared precise source Git objects, and examined the initial stopped execution separately from the resumed execution. I wrote independent probe and scientific-calculation scripts outside the candidate repository.

The source-boundary probes exercise the public implementation under test. The independent scientific calculation does not use the author's tree, producer, correspondence or quotient-model functions: it reconstructs B1 token lineage and history metrics, establishes event correspondence from the frozen structured Wolfram state-instance fields, and propagates quotient token provenance forward by generation and string. It reads all 56 frozen records, including both large R004/R047 records. It is not a second independently implemented InputForm parser; the preserved parser's raw/structured integrity controls were separately rerun in the focused suite. Earlier independent-review retrieval limits remain historical limits, not rewritten assertions.

The reviewer independently reran 112 provenance/control probes at the final accepted HEAD. Results include real frozen M1/M8 positives and metadata-only attacks, direct audit and correspondence paths, missing/malformed metadata, unbound surface wrappers, exposed-label mutation, legacy caller mismatch instrumentation, corpus mislabeling under a valid filename, and duplicate-edge rejection. All probes passed. Reviewer instrumentation recorded zero attempted subprocess calls for legacy mismatches.

## Source-boundary implementation findings

There is one assignment of EVENT_LINEAGE_EDGE_PARITY_EXACT in the reviewed implementation. It follows audit_fixture's source-binding guard, guarded establish_correspondence, complete event correspondence and directed-edge equality with duplicate-edge exclusion. audit_fixture returns PARITY_NOT_AVAILABLE before any count/isomorphism fallback when binding fails. audit_corpus uses the same guard and handles source metadata errors. r1_parity_from_records handles B1 and raw metadata errors explicitly.

parse_raw_wolfram_record retains an immutable SourceIdentity. surface_from_vertex_edge_strings carries explicit strict source_metadata or leaves the surface unbound; unbound surfaces cannot obtain exact authority through audit or correspondence. The exposed tree/surface identity fields are rechecked against their immutable declarations. establish_correspondence validates identity before its empty-event COMPLETE return.

Fixture ID and seed use exact string types and equality. Depth and any declared max_events require exact nonnegative integers, excluding bool and float. Explicit null is malformed; absence is handled separately. Declared B1 max_depth is compared with declared Wolfram evolution depth rather than completed_depth, preserving M8's fixed-point interpretation. A max_events budget may be absent on both sides; if either side declares it, the other must declare it and agree. No coercion or normalization makes inconsistent inputs equal.

The legacy helper checks fixture_id, ordered pattern/replacement rules, initial_state and max_depth against B1 before constructing a request or invoking subprocess.run. It does not select a convenient caller value after a failed binding. The boolean-depth negative control remains present, fails closed and reports the actual malformed input field max_depth. Only the erroneous diagnostic assertion was changed.

The count-only helper remains an arithmetic classification without a reference fixture identity argument. It cannot emit exact parity and supplies no provenance acceptance. No source-mismatched audit path reaches count-only or isomorphism acceptance.

This contract validates declarations against the supplied B1 reference; it does not independently authenticate the external truth of arbitrarily forged matching declarations. The frozen Wolfram raw format has no separate complete rules manifest. That documented boundary is distinct from the demonstrated mismatch defect, which is closed.

## Required eight answers

| Question | Independent answer |
|---|---|
| Can a foreign fixture ID still produce EXACT? | No on the reviewed entry points and tested real M1/M8 records. Fixture declarations and exposed labels must agree. |
| Can a wrong seed still produce EXACT? | No. Wrong seeds reject before correspondence, including empty M8. |
| Can an empty graph bypass source identity? | No. The guard precedes the empty-event return. Correct M8 is explicitly marked vacuous and has no invented event/configuration witness. |
| Can legacy helper arguments disagree with B1? | They can be supplied, but all four required independent mismatches are rejected with unavailable/false. |
| Can any tested mismatch invoke Wolfram unnecessarily? | No. Instrumentation recorded zero attempted subprocess calls for mismatches. |
| Can malformed/missing source metadata fail open? | No in the reviewed contract and probes. Relevant values produce explicit malformed/missing dispositions, unavailable/false, without a probe parser crash. |
| Are original scientific results preserved? | Yes. Independent calculations reproduce all required metrics, the original 48/8 split and quotient-model results; the frozen builder reproduces all eight JSON files. |
| Are all historical predecessor files unchanged? | Yes, 207/207 were directly compared with canonical-base Git bytes and their historical SHA-256 values. |

## Scientific preservation

The independent calculation reproduces:

- 56 systems; 1,597 nonempty maximal histories; 9,392 history-event occurrences.
- 10,160 per-history direct-edge occurrences; 20,866 strict transitive causal relations; 2,486 incomparable pairs.
- 2,102 distinct event nodes and 2,832 unique direct edges.
- Depth distribution 0..5: 1,597 / 1,668 / 2,002 / 2,035 / 1,535 / 555; maximum causal depth 5.
- 48 exact fixtures and the same eight divergent fixtures: R004, R014, R018, R020, R021, R022, R030 and R047. No Python edge is missing from Wolfram.

R014 independently gives 8 Python edges, 12 Wolfram edges, and precisely four extras: e_2→e_5, e_4→e_5, e_1→e_6 and e_3→e_6. Its e_5/e_6 source-instance distinction is retained. R004 and R047 each independently give 1,256 Python edges, 72,918 Wolfram edges, and 71,662 extras: 70,186 cross-history plus 1,476 same-history non-lineage. The independently propagated generation/string quotient model reproduces all observed edges on the 56-fixture corpus.

These findings remain bounded model reproduction, not proof of Wolfram internals or actual state-ID reuse. The finite replay remains finite evidence, not a serializability theorem. No physical, causal-invariance, branchial, quantum or universal-parity claim is added. The previous R1 F6 assurance that a mismatched record cannot pass is falsified by the retained original reproductions; this report does not reuse that assurance or the old ACCEPT as qualification.

## Historical builder and source identities

The reviewer verified that

`34c8c2d3a8f52a674e71e770b7a29d621fc8fb8b:src/msk_ruliology/causalis_b2_resource_causality.py`

has SHA-256

`3f5e9e1b5f9dbae14e32364bb5963e350d66ba60509b2c631b0ec122888ca3b3`.

The S11 builder branch computes this value from the exact local Git object with checked failure semantics. It does not insert an unexplained digest constant, retrieve source over the network, or fall back to working-tree source. The comment and R2 source receipt explain that S11's historical source_sha256_at_canonical_base field denotes frozen R1 source despite its name. All eight original R1 JSON files remain byte-identical to their R1 Git objects; no historical value was overwritten.

I independently resolved all ten original/repaired source references in r2_source_identities.json, checked each Git blob and SHA-256, and confirmed each repaired blob is also present unchanged at the final accepted HEAD. This fulfills separate historical-versus-repaired source custody without a recursive candidate hash.

The execution_01_stopped archive retains the prior 125-pass/one-assertion-failure run and seven-of-eight builder result. Current receipts correctly distinguish the approved continuation, 126 focused passes and eight-of-eight reproduction. Archived failures are not misrepresented as current results or silently erased.

## Regression and no-Wolfram evidence

Independent focused rerun: 126 passed, zero failed/skipped. Existing parser-integrity, duplicate-edge and R014 controls pass. Independent builder checks at the implementation and final accepted heads both return `{"regenerated": 8, "differs": []}`.

The producer's full-suite XML was independently compared, rather than unnecessarily rerunning that suite again: original R1 has 855 passes/eight LPO failures; the candidate has 942 passes/the same eight failures. All 863 original test statuses are unchanged; all 87 added cases pass. This comparison establishes matched baseline debt, not a blanket CI waiver. The reported static/lint/format checks pass. The inherited C414 expression was matched against original R1 and replaced with equivalent sorted-edge iteration.

The failing logging shim remained first on PATH for reviewer runs. The log has zero entries; its SHA-256 is `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. No new Wolfram primary call or campaign execution occurred.

For reproducible commands, CANDIDATE_REPO denotes an exact checkout of the accepted HEAD, PYTHON the documented repository interpreter, WOLFRAM_SHIM_DIR the failing logging shim directory, and REVIEW_OUTPUT_DIR an independent review-output directory. These are symbolic paths, not host identity disclosures:

```sh
cd "$CANDIDATE_REPO"
export PATH="$WOLFRAM_SHIM_DIR:$PATH"
export PYTHONPATH="$CANDIDATE_REPO/src"
"$PYTHON" "$REVIEW_OUTPUT_DIR/reviewer_probes.py"
"$PYTHON" -m pytest tests/test_causalis_b2_r1_edge_reconciliation.py tests/test_causalis_b2_resource_causality.py --junitxml="$REVIEW_OUTPUT_DIR/focused.xml"
"$PYTHON" experiments/causalis-b2-exact-edge-reconciliation-00a-r1/build_r1_evidence.py --check
"$PYTHON" "$REVIEW_OUTPUT_DIR/final_head_checks.py"
git diff --exit-code b53b787d73ebcee22acbd11069170c71ff96b46c 089cec23afe6c15df9d7f085f4a0e3c298bd776a -- src tests experiments
```

The review output retains independent_results.json, final_head_checks.json, probe scripts, focused log/XML and builder logs outside the candidate. No private signing material was accessed.

## Verdict and remaining gates

No material or blocking implementation/evidence finding was identified. The demonstrated source-provenance false positives, zero-event bypass and unbound legacy arguments are closed on the accepted exact HEAD.

Limitations: the scientific claims remain bounded to the frozen cohort and trusted supplied B1 declarations; the independent scientific reimplementation uses structured Wolfram records rather than a second raw InputForm parser; this is a separate agent review sharing the producer's provider/filesystem. It must not be represented as OS-isolated local approval or an institutional signed receipt.

External authority-policy acceptance, exact-head prior verification, Local Review V2.1 APPROVE, a genuine signature and receipt admission, the authenticated exact-head GitHub App check, hosted CI qualification and trusted-starter merge authorization remain separate requirements. Neither the eight inherited local failures nor hosted runner-startup failures constitute passing CI. This review does not authorize merging an otherwise unqualified candidate and does not claim canonical integration.

VERDICT: ACCEPT_WITH_LIMITATIONS
