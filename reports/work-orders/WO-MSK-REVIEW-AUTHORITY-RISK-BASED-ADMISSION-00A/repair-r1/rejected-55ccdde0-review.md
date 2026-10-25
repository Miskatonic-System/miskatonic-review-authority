AUTHORITY_REVIEW_REPOSITORY: Miskatonic-System/miskatonic-review-authority
AUTHORITY_REVIEW_HEAD: 55ccdde031957e6fa68cdab97327f056a2ac50fa
AUTHORITY_REVIEW_TREE: 319f37649b1de9a7c533105582ee50c662796fff
REVIEWER_IDENTITY: reported-agent:risk_admission_security_review:openai-codex
REVIEWER_DISTINCT_FROM_IMPLEMENTER: REPORTED
REVIEWER_PROVIDER_DISTINCT: NO
REVIEWER_FILESYSTEM_ISOLATED: NO
INSTITUTIONAL_REVIEWER_SIGNATURE: NOT_ESTABLISHED
AUTHORITY_CHANGE_RISK_CLASS: R2_SECURITY_OR_AUTHORITY_CHANGE
VERDICT: REVISE

# Independent exact-head security and governance review

The frozen authority candidate cannot be accepted. Its new security-test snapshot fixture fails on a clean committed checkout, preventing 45 required tests from running. Its new production workflow also contains two YAML syntax errors. These are verification and operational blockers under work-order S15. The implementation remains unratified and must remain draft and unmerged. This report grants no admission, ratification, release or merge authorization.

Review base: `a87e863173950c7f73072d1647780b3492ab0a43`. The reviewed HEAD/tree above were independently resolved from Git; the candidate worktree was clean before and after review. The complete inventory contains 61 changed paths and is retained separately as `exact-changed-path-inventory.json`, including each path's status, Git blob, SHA-256 and byte length. Existing authority-file modifications are limited to `src/miskatonic_review_authority/cli.py` and `.github/workflows/authority-ci.yml`; all 93 other predecessor authority files were independently checked byte-for-byte.

## F1 — Blocking: security tests assume uncommitted source changes

Severity: MEDIUM. Acceptance impact: BLOCKING.

At [tests/test_research_admission.py, lines 61–70](https://github.com/Miskatonic-System/miskatonic-review-authority/blob/55ccdde031957e6fa68cdab97327f056a2ac50fa/tests/test_research_admission.py#L61), `snapshot()` clones the repository, copies the source/policy/schema/report directories into that clone, stages them, and unconditionally runs an ordinary `git commit`. On the frozen committed candidate those copied bytes already equal HEAD. The synthetic clone is clean, so Git returns exit status 1 because there is nothing to commit. Pytest reports setup errors for every test depending on this session fixture.

Independent full run: **141 passed, 45 setup errors, zero test failures, zero skips; 186 collected**. All 127 original baseline tests passed. Of the 59 new tests, 14 passed and 45 errored during setup. The affected tests include the complete-route positive control, most T01–T28 controls, actual frozen-corpus integration, signed receipt, idempotency, partial publication, stale-head publication and ledger controls. Setup errors cannot be counted as successful adversarial controls.

The independently retained temporary snapshot was clean and resolved to the same `55ccdde031957e6fa68cdab97327f056a2ac50fa` HEAD. This establishes the failure cause without relying on a model interpretation of the test traceback. A pre-freeze passing run against a dirty working tree does not qualify the committed candidate.

A bounded correction could make the synthetic commit explicitly permit an unchanged tree or reuse the already committed snapshot while preserving its required ancestry. No correction was applied by this reviewer. Repair requires authorization, a new frozen commit/tree, rerun validation on that clean commit, and fresh exact-head independent review. The recorded 186-pass and T01–T28 qualification must not be asserted for this rejected HEAD.

## F2 — Blocking: proposed production workflow is invalid YAML

Severity: MEDIUM. Acceptance impact: BLOCKING.

At [.github/workflows/admit-research-evidence.yml, line 38](https://github.com/Miskatonic-System/miskatonic-review-authority/blob/55ccdde031957e6fa68cdab97327f056a2ac50fa/.github/workflows/admit-research-evidence.yml#L38), the dependency command is a plain, unquoted YAML scalar containing `--only-binary=:all: --require-hashes`. The final colon in `:all:` is followed by a space, so it is interpreted as a YAML mapping separator. Independent parsing of the frozen file with the already-installed PyYAML 6.0.3 raises `ScannerError: mapping values are not allowed here` at line 38, column 83.

An in-memory-only probe that quotes the first command exposes the same error at line 84, column 83, in the admit job. Quoting both command scalars in memory makes parsing succeed. The actual workflow file was never changed. The original frozen workflow SHA-256 is `adfbcb2474f836151367d2f3375fb3c343360149aac04cd9e4d60ececc958eda`.

This is a static production-feasibility failure, not a missing credential or protected-environment configuration. The proposed workflow cannot be qualified as executable YAML. The retained immutable-action audit does not detect this syntax error. A bounded future correction could use quoted scalars or block scalars for both commands while retaining the hash-pinned binary-only dependency constraints, then add an actual workflow-syntax check. No correction was applied. New commit/tree, clean validation and independent review are required.

## Independent checks completed

The following checks succeeded independently and do not override F1:

- Direct Git/worktree comparison confirmed the full 61-path authority inventory, all 93 preserved predecessor authority files, and all 43 root-manifest objects. Root SHA-256: `1759f4a44745e68748e5144ad14c75492856ca051f3e3d5bd44b6279a81f227e`; scoped-policy SHA-256: `9854428efe571e6e5ae47c8e2145d1c93c0993aa101222725bd8f45e5e317556`.
- Frozen target identity reproduced: repository `Miskatonic-System/msk-ruliology`, PR156, base `d90892e3c2fdd66f2ffb13b17f7302b8689a9ced`, HEAD `089cec23afe6c15df9d7f085f4a0e3c298bd776a`, tree `a9d867a34ad21524a8f835774bca29ad33a8300d`.
- Offline data-only reconciliation reproduced prior `PASS` and candidate digest `c70a9d2add189ae490ebcb7bc2ae06ee13e966827d6e6c10d7d341c67d880621`. Recomputed prior evidence equals the retained prior evidence. The complete 53-path packet reconciles 27 `FULL_DIFF_REVIEWED` and 26 `HASH_BOUND_GENERATED_ARTIFACT` paths, with exact per-path status/blob/classification and full source-diff bytes.
- Retained CAUSALIS review digest reproduced `afe7911a3f32271faf02221e34fd5ad730a1bd6dee73787c04fe65db226e9c22`. Its exact-head/tree custody and limitations remain distinct from a signed Local Review V2.1 receipt.
- All 207 original target predecessor files and all eight frozen R1 JSON outputs were independently compared using both Git contents and working-tree bytes. Every file was identical. Original R1 remains an ancestor. No scientific campaign or historical builder was rerun by this reviewer.
- The target's retained normalized JUnit and compensating evidence were reconciled by the offline validator: original 855 passed/eight failures, candidate 942 passed/the same eight failures, focused 126 passed, 87 added passing cases. These are reconciled historical results, not new executions of the scientific suite.
- The independent authority test run used failing Wolfram shims; its invocation log is empty. Offline target reconciliation denied network access and allowed only data-reading Git subprocesses. No candidate scientific code executed.

No additional runtime fail-open was established in the source examination. This is not a statement that all security controls passed: F1 prevented their exact-head execution.

## Source and governance examination

The review examined the complete changed-path inventory; new core/adaptor/workflow/root/policy/schema code; CLI and CI changes; threat model, contracts, operational documents and retained evidence. Provisional examination informed bounded hardening before freeze, but the reviewer did not author or mutate the implementation.

The inspected design binds the sole exact CAUSALIS R1 case, preserves Local Review V2.1 and historical cloud semantics, requires independently fetched merged-authority and protected-review facts, pins the trusted starter, binds the exact external security report and full accepted authority tree, and rechecks approval and HEAD before success. It uses a distinct research-admission check, an authority-only CAS ledger, signed receipt custody, conflicting-request rejection and explicit partial publication handling. These observations justify completing a repaired review cycle; they do not qualify this rejected candidate.

The route provides authenticated GitHub-account risk acceptance with disclosed producer/approver transport overlap. It does not prove physical human presence or independent institutional review. This reviewer is a distinct agent as reported, sharing the implementation provider and filesystem. No OS isolation or institutional reviewer signature is established. This report is not a Local Review V2.1 receipt.

Hosted target Test/Lint/Schema runs remain failed infrastructure-startup runs with compensating evidence; no hosted CI pass is claimed. The protected environment was absent at starting reconciliation. Actual workflow execution, protected human approval, App signing/check publication and ledger admission were not exercised by this reviewer. No genuine credentials or service signing keys were accessed. Synthetic test keys and fake transports used by the authority tests are not real admissions. The historical V1 target-policy schema remains incompatible; only the new strict admission contracts have their own formal validation mechanism.

## Execution and evidence

Independent test environment: Python 3.13.11, pytest 9.1.1, jsonschema 4.26.0. The retained implementation run used pytest 8.4.2, so the reviewer environment differs. F1 is the direct ordinary-Git no-change commit failure and does not depend on pytest's version. The implementer subsequently retained a focused T01 reproduction under the original Python 3.13.11/pytest 8.4.2 environment. The reviewer re-read its log/XML and confirmed the same Git setup error; this corroboration is separately labeled implementer-produced evidence, not the reviewer's independent full run. YAML validation used the already-installed Python 3.14.7/PyYAML 6.0.3 parser; it did not install dependencies or execute the workflow.

Reproducible command, with role names substituted for private local paths:

```sh
PATH=REVIEW_WOLFRAM_FAILING_SHIM:$PATH \
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
MSK_CAUSALIS_FROZEN_REPO=FROZEN_TARGET_CHECKOUT \
python3.13 -m pytest -p no:cacheprovider \
  --basetemp=REVIEW_TMP/pytest --junitxml=REVIEW_TMP/full-tests.xml
```

Retained independent evidence: `full-tests.log`, `full-tests.xml`, `final-review-validation.json`, `exact-changed-path-inventory.json`, `independent-custody-verification.json`, `independent-target-reconciliation.json`, `workflow-yaml-validation.json`, `original-environment-reproduction-reference.json`, and the empty `wolfram-invocations.log`. Review-only scripts are retained alongside them. The machine validation receipt binds evidence hashes and enumerates all 45 error case IDs. Raw local diagnostics remain in reviewer custody; publication should preserve digest-bound normalized evidence without disclosing unrelated host paths.

Next action: retain the draft/unmerged candidate and this negative finding; obtain direction for the bounded fixture and YAML repairs, then validate and review the new clean exact HEAD. Authority activation, human authorization, authenticated admission, branch-protection qualification and target integration remain separate unmet gates.
