# Bootstrap and Operations

## One-time bootstrap

1. The trusted starter creates the repository and GitHub App.
2. This bootstrap candidate establishes the genesis root and authority workflows.
3. Candidate CI proves the code behaves as designed.
4. The App-authentication workflow proves the GitHub App can issue authenticated checks and reveals only the derived public key.
5. The trusted starter ratifies and merges the authority bootstrap.
6. The merged authority runs prior-release verification and independent cloud review against control-plane PR #3.

The trusted starter is not the routine reviewer. This one-time merge establishes the reviewer institution.

## Required checks

After the authority has emitted them at least once, configure the control-plane ruleset to require checks from the **Miskatonic Review Authority** GitHub App:

- `miskatonic/prior-release-verify`
- `miskatonic/independent-cloud-review`

Candidate CI remains useful but non-authoritative.

## Full-SHA policy

Enable GitHub's repository policy requiring actions to use full commit SHAs after every existing workflow has been migrated. The authority also audits reusable-workflow references, which GitHub's built-in setting does not force to immutable SHAs.

Rollout order for each repository:

1. Inventory every `uses:` reference.
2. Resolve each trusted release tag to its exact upstream commit.
3. Replace tags and branches with 40-character SHAs.
4. Add a human-readable comment containing the release tag.
5. Run CI.
6. Enable the repository-level enforcement switch.
7. Add Dependabot or a governed update process for future action upgrades.

Do not enable the enforcement switch first on a repository whose workflows still contain tags. GitHub will reject those workflow jobs immediately.

## Cloud reviewer configuration

Set:

- secret `MSK_CLOUD_REVIEW_API_KEY`
- variable `MSK_CLOUD_REVIEW_MODEL`

The current provider adapter uses the OpenAI Responses API with Structured Outputs and `store: false`. The authority records the provider request ID, response ID, requested model, and returned model. Missing or failed provider configuration publishes a failing review check.

## Key rotation

1. Generate a new GitHub App private key.
2. Update the Actions secret.
3. Derive and commit the new public key in a separately reviewed authority change.
4. Add the new key ID to consumer trust configuration.
5. Permit overlap during migration.
6. Revoke the old private key only after all consumers recognize the replacement.
