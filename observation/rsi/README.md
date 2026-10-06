# Passive RSI owner export v0.2

Run separately after the native action has completed:

```sh
python -B -m observation.rsi.owner_export /path/to/completed-native.json --owner-release EXACT_OWNER_COMMIT
```

Install the observation-only requirements in `observation/rsi/requirements.txt`.
The exporter checks duplicate keys and nonfinite numbers, resolves an exact
owner-schema snapshot, validates the parsed native object with JSON Schema,
and projects only its fixed metadata allowlist. Source digests cover original
bytes. No native workflow calls this component; it emits stdout and makes no
network calls or writes. Export failures cannot change a completed owner outcome.

The immutable schema binding includes repository, canonical commit, path, raw
schema SHA-256 and content-addressed artifact identity. It participates in the
exporter implementation digest. Formats use a deterministic RFC3339 date-time
subset (no leap seconds), explicitly named in provenance. A schema-valid native
payload field does not become exportable. Missing fields permitted by the native
contract stay UNKNOWN. Runtime Governance has no native candidate binding;
Review Authority maps authority_workflow_run_id to owner_native_event_id.

Schema conformance establishes contract shape, not issuer authentication, signature
validity, acceptance or occurrence. Authentication stays NOT_PERFORMED_BY_EXPORTER.
Owner-release input remains OWNER_SUPPLIED_METADATA_UNAUTHENTICATED.

`fixtures/native_artifact.v0.2.json` and the per-version fixtures are complete,
schema-valid synthetic, non-authenticated, non-occurred and non-authoritative
controls. Review's fictional signature is not cryptographically authenticated.
The original v0.1 schema, incomplete metadata fixture and 00D evidence are retained
as historical candidate evidence. v0.2 explicitly versions the repaired contract.

Adoption remains CANDIDATE_NOT_CANONICAL, standing epoch participation remains
NOT_ESTABLISHED, and lane activation is prohibited by 00D-R1. No independent
review, owner acceptance, authentication or runtime separation is self-issued.
