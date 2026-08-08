# Local-Test Evidence Boundary

Local-test evidence produced by a candidate workspace or Agent OS execution is **supporting evidence**, not review or release authority.

The Review Authority may consume such evidence only when it is bound to an exact repository, commit SHA, profile identity, environment digest, and evaluator run. It must not treat candidate-controlled profile declarations as independent evidence.

The intended chain is:

```text
repository profile
  -> Runtime Governance authorization receipt
  -> Agent OS execution/resource evidence
  -> Agent Evaluator acceptance verdict + hidden tests
  -> Review Authority independent semantic/release review
```

Required distinctions:

- requested network denial is not proof of network isolation;
- requested memory/GPU limits are not proof of enforcement;
- a passing local profile is not proof that hidden acceptance passed;
- local evidence does not replace previous-release verification or independent cloud review;
- any later candidate commit invalidates evidence bound to the prior head.

The Review Authority should eventually include local-test/evaluator evidence digests in the exact-work review bundle, but this document grants no new release authority and changes no existing trust anchor.
