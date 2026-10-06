# Passive RSI owner export v0.1

This owner-local source component projects an already completed native artifact.
It adds no call to the native propose/evaluate/review/authorize/execute path and
does not interpret an export as an owner receipt or decision. Invoke separately:

```sh
python -B -m observation.rsi.owner_export /path/to/completed-native.json --owner-release EXACT_OWNER_COMMIT
```

The exporter emits stdout only, without network or writes. Run it from a pinned
source release. No background transport, hook, scheduler, or standing adoption
is enabled by this patch. Export failure is OBSERVATION_EXPORT_FAILED and has no
connection to the already-completed owner outcome. Caller orchestration must
never make this command a native gate, prerequisite, or retry trigger.

Exports are deterministic derivations and bind original raw bytes by digest,
native schema/event/candidate identities, pointer mapping, transformation and
implementation digests. No raw native payload, signing material, private
reasoning, or holdout contents is copied. The exporter does not authenticate
reviews or authorize effects. Missing native fields remain UNKNOWN; Runtime
Governance has no native candidate binding and Review Authority has no event ID.
UNIX timestamp conversion retains the original scalar and transformation version.

The small fixture is synthetic metadata for projection tests, not a complete
qualified native receipt, owner attestation, occurred transition, or real canary.
Failure tests demonstrate the disconnected post-completion API and unchanged
input bytes; they do not claim deployed asynchronous transport or runtime access
isolation. Canonical integration, owner acceptance and standing epoch/write
boundary evidence are still required. No independent review is self-issued.

`--owner-release` is caller-supplied metadata, explicitly labeled unauthenticated;
it is not promoted into a native owner assertion. An omitted release stays UNKNOWN.
The source component is excluded from the observation lane it implements.
