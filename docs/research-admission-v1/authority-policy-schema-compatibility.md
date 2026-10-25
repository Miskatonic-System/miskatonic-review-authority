# New and legacy schema validation

NEW_ADMISSION_SCHEMA_VALIDATION is strict and required for each new request, policy, authority-root declaration, human authorization and signed receipt. Unknown properties/versions are rejected.

LEGACY_TARGET_POLICY_SCHEMA_VALIDATION is KNOWN_INCOMPATIBLE: canonical V1 includes verification_profile, key_evidence_diff_files and independent_r2_review absent from its schema, and omits pinned_evidence_digests. Preserve both historical bytes. The new route admits only an explicitly digest-pinned exact legacy target policy under its own strict case policy. It does not advertise V1 schema PASS or permit arbitrary V1 data. A scientific-target-policy-v2 schema is proposed separately with required exact evidence identities; no target migration is needed for this vertical slice.
