# Miskatonic Review Authority

This repository is the external trust anchor for Miskatonic Systems code review and release authorization.

It exists to keep three roles separate:

```text
coding agent -> candidate patch
previous trusted verifier -> inherited-policy evidence
independent cloud reviewer -> semantic review
GitHub App -> authenticated check and signed attestation
```

The authority repository does **not** contain deployment credentials, runtime service credentials, or consumer source code. Its GitHub App private key and cloud-review API key exist only as GitHub Actions secrets.

## Security properties

- Candidate repositories cannot modify this authority while asking it to approve their changes.
- GitHub App checks authenticate the authority principal.
- Signed attestations bind the repository, base SHA, head SHA, canonical candidate digest, producer binding, reviewer execution, verdict, and policy version.
- The prior-release verifier executes code from the pinned previous control-plane release.
- Candidate code is inspected as data and is never executed by privileged authority workflows.
- Missing credentials, ambiguous provenance, stale heads, model failures, and malformed evidence fail closed.
- Every external action and reusable workflow reference must use a full 40-character commit SHA.

## Genesis root

`roots/control-plane-v0.1.0.json` designates control-plane commit
`98161a4a9f66420fd293f37cd88473a427585093` as the previous trusted verifier for the first governed control-plane upgrade.

## Required repository configuration

Actions variables:

- `MSK_REVIEW_APP_ID`
- `MSK_CLOUD_REVIEW_MODEL` when cloud review is enabled

Actions secrets:

- `MSK_REVIEW_APP_PRIVATE_KEY`
- `MSK_CLOUD_REVIEW_API_KEY` when cloud review is enabled

The GitHub App should have only Actions read, Checks write, Contents read, Pull requests read, and implicit Metadata read permissions on explicitly selected repositories.

## Bootstrap status

The authority bootstrap pull request is a one-time constitutional ratification. After it is merged by the trusted starter, routine release decisions belong to authenticated independent cloud review rather than the coding agent or repository owner.
