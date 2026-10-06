"""Synthetic post-completion export witnesses; never a live owner transition."""

import json
from pathlib import Path

import pytest

from observation.rsi import owner_export as owner
from observation.rsi import projection as p

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "observation/rsi/fixtures/native_metadata.json"
)


def native():
    return json.loads(FIXTURE.read_text())


class MemoryCustody:
    def __init__(self, writable=True):
        self.writable = writable
        self.artifacts = {}

    def store(self, raw):
        if not self.writable:
            raise OSError("synthetic-storage-unavailable")
        value = json.loads(raw)
        identity = p.digest(
            p.canonical({k: v for k, v in value.items() if k != "export_id"})
        )
        if identity in self.artifacts:
            assert self.artifacts[identity] == raw
        self.artifacts[identity] = raw
        return identity


def test_deterministic_identity_and_unknown_preservation():
    raw = FIXTURE.read_bytes()
    one = owner.attempt_export(raw)
    assert p.canonical(one) == p.canonical(owner.attempt_export(raw))
    assert one["status"] == "OBSERVATION_EXPORT_EMITTED"
    export = one["export"]
    assert export["owner_component_version"] == "UNKNOWN"
    assert export["trust_epoch_ref_if_known"] == "UNKNOWN"
    assert export["native_artifact_refs"][0]["raw_native_digest"] == p.digest(raw)
    assert export["export_provenance"]["authentication"] == "NOT_PERFORMED_BY_EXPORTER"
    for field, path in owner.CONFIG["schemas"][native()["schema_version"]].items():
        expected = p.pointer(native(), path)
        if field != "occurred_at":
            actual = export.get(field, export["owner_metadata"].get(field))
            assert actual == expected
    assert "signature" not in export and "content" not in export


@pytest.mark.parametrize(
    "failure",
    [
        "observer_unavailable",
        "custody_unavailable",
        "malformed_export",
        "schema_mismatch",
        "candidate_mismatch",
        "stale_observer_release",
        "unknown_field",
        "duplicate_export",
        "storage_failure",
        "trust_epoch_unavailable",
    ],
)
def test_post_completion_failures_leave_native_outcome_bytes_unchanged(failure):
    # The owner action is already complete. No owner module invokes this exporter.
    completed = FIXTURE.read_bytes()
    outcome_digest = p.digest(completed)
    value = native()
    if failure == "schema_mismatch":
        value["schema_version"] = "wrong-version"
    elif failure == "unknown_field":
        path = owner.CONFIG["schemas"][value["schema_version"]].get("candidate_sha")
        if path and "." not in path:
            value.pop(path, None)
    projected = owner.attempt_export(p.canonical(value))
    store = MemoryCustody(writable=failure != "storage_failure")
    expected, candidate = owner.IMPLEMENTATION_DIGEST, "UNKNOWN"
    if failure == "observer_unavailable":
        projected = None
    elif failure == "custody_unavailable":
        store = None
    elif failure == "malformed_export":
        projected["export"]["export_id"] = "sha256:" + "0" * 64
    elif failure == "candidate_mismatch":
        candidate = "f" * 40
    elif failure == "stale_observer_release":
        expected = "sha256:" + "f" * 64
    elif failure == "duplicate_export":
        p.deliver_observation(projected, store, expected)
    observation = p.deliver_observation(projected, store, expected, candidate)
    if failure in {
        "observer_unavailable",
        "custody_unavailable",
        "malformed_export",
        "schema_mismatch",
        "candidate_mismatch",
        "stale_observer_release",
        "storage_failure",
    }:
        assert observation["status"] == "OBSERVATION_EXPORT_FAILED"
    else:
        assert observation["status"] == "OBSERVATION_EXPORT_STORED"
        assert observation["trust_epoch"] == "UNKNOWN"
        if failure == "duplicate_export":
            assert len(store.artifacts) == 1
    assert observation["status"] in {
        "OBSERVATION_EXPORT_STORED",
        "OBSERVATION_EXPORT_FAILED",
    }
    assert FIXTURE.read_bytes() == completed
    assert p.digest(completed) == outcome_digest
    assert "owner_outcome" not in observation


@pytest.mark.parametrize("key", sorted(p.SECRET_KEYS))
def test_secret_or_hidden_content_is_not_exported(key):
    value = native()
    value[key] = "synthetic-private-material"
    result = owner.attempt_export(p.canonical(value))
    assert result == {
        "status": "OBSERVATION_EXPORT_FAILED",
        "reason": "SECRET_OR_HIDDEN_EVIDENCE_BOUNDARY",
        "authority": "NONE",
    }


def test_unsigned_review_reference_fails_and_private_key_values_fail():
    value = native()
    if owner.CONFIG["component"] == "review":
        value.pop("signature")
        assert (
            owner.attempt_export(p.canonical(value))["status"]
            == "OBSERVATION_EXPORT_FAILED"
        )
    value = native()
    value["extra"] = "-----BEGIN PRIVATE KEY-----synthetic"
    assert (
        owner.attempt_export(p.canonical(value))["status"]
        == "OBSERVATION_EXPORT_FAILED"
    )


def test_duplicate_keys_nonfinite_and_unknown_native_fields():
    for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":1e999}'):
        assert owner.attempt_export(raw)["status"] == "OBSERVATION_EXPORT_FAILED"
    value = native()
    for path in owner.CONFIG["schemas"][value["schema_version"]].values():
        if "." not in path:
            value.pop(path, None)
    if owner.CONFIG["component"] == "review":
        value["signature"] = native()["signature"]
    export = owner.attempt_export(p.canonical(value))["export"]
    assert export["candidate_sha"] == "UNKNOWN"
    assert export["occurred_at"] == "UNKNOWN"
