# Bounded repair R1 — execution authorized, release authority absent

Rejected authority HEAD: 55ccdde031957e6fa68cdab97327f056a2ac50fa. Its exact-head verdict remains REVISE. The original report is copied byte-for-byte as rejected-55ccdde0-review.md, SHA-256 eb724f437e1b23ebab1f421b41f3265d922948509c99ac9a8c1a15ee5ec059cd. Original source, evidence and negative findings remain in Git history.

The user authorized only the two known blockers and directly necessary regression tests. This execution authorization is not root ratification, human admission approval, release authority or merge authorization.

## F1: committed snapshot identity

The former fixture cloned HEAD, copied working-tree source over it, then always committed. Before freeze the overlay changed tracked files, so that commit succeeded. On a clean committed candidate the same overlay made no changes and ordinary Git correctly failed. The retained 186-pass pre-freeze result therefore did not qualify rejected HEAD55ccdde0.

The authority fixture needs the committed candidate's identity; its synthetic review facts already bind whichever existing HEAD/tree is checked out. A new identity is unnecessary. It now captures HEAD, clones without checkout, and explicitly checks out that commit with hooks disabled. It copies no working-tree files and performs no authority-snapshot commit. Git errors continue to propagate through check=True/check_output. A new regression asserts source/snapshot HEAD and tree equality and clean snapshot status. All pre-existing admission assertions and all 45 previously errored cases remain present. The separate existing synthetic53-path inventory graph remains unchanged.

## F2: complete workflow parsing

The two dependency-install commands contained `:all:` followed by a space in a plain YAML scalar. Quoting each entire scalar preserves the decoded shell command byte-for-byte and repairs YAML tokenization. Both jobs, all steps, protected environment, canonical-main guards, permissions, hash requirements and binary-only constraints remain present.

A test-only pinned PyYAML6.0.3 dependency supports full-file parsing of every authority workflow, using BaseLoader to preserve GitHub's `on` key rather than YAML1.1 boolean coercion. Regressions retain the rejected workflow as an invalid negative control, compare both decoded install commands to the rejected source, and enforce the admission job/guard/environment relationships. A dependency test permits only this test-extra addition; production requirements are unchanged. Independent Actions syntax/expression validation uses official checksum-verified actionlint1.7.12. Its optional shellcheck/pyflakes integrations are outside that grammar check.

## Root and preservation

The offline root builder updates only the workflow object's Git blob/SHA-256. No route, scope, principal, approval field, policy, runtime source, signing rule or ratification state changes. The historical-authority preservation test explicitly permits the new test-only pyproject dependency; a separate exact comparison constrains that change. The target PR156 remains immutable at089cec23afe6c15df9d7f085f4a0e3c298bd776a; no scientific files, historical outputs or Local Review V2.1 artifacts change.

## Qualification sequence

Commit the repair, clone its committed identity freshly without local object sharing, and run the complete suite plus workflow/schema, static, adversarial, preservation and zero-Wolfram checks. Compare every collected original/rejected test ID and every formerly errored case. Evidence from that committed revision may be appended in a later evidence-only commit, but the final published HEAD must then be validated again from another genuinely fresh checkout and receive its own independent exact-head review. No result is transferred merely because source appears unchanged. Final receipts/review are retained separately from their immutable reviewed commit and in the draft PR custody record to avoid a self-referential SHA.

No root ratification, genuine signed admission, authenticated release check, production activation, branch-protection bypass, target merge, paid model call or Wolfram execution is authorized. A new substantive failure requires another stop with evidence.
