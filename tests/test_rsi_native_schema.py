"""Canonical native-schema falsifiers; synthetic bytes never authenticate an owner."""

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from observation.rsi import native_schema as ns
from observation.rsi import owner_export as owner
from observation.rsi import projection as p

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = tuple(owner.CONFIG["schemas"])
FOREIGN_NATIVE = {
    "allowed": False,
    "capability_name": "synthetic:capability_name",
    "decided_at": "2026-02-01T00:00:00Z",
    "decision_id": "synthetic:decision_id",
    "policy_version": "synthetic:policy_version",
    "reason": "synthetic:reason",
    "reason_code": "synthetic:reason_code",
    "schema_version": "miskatonic.authorization-decision.v1",
}


def fixture(version):
    binding = ns.SCHEMA_BINDINGS[owner.CONFIG["owner_repository"]][version]
    name = "native-" + binding["source_path"].split("/")[-1].replace(
        ".schema.json", ".v0.2.json"
    )
    return json.loads((ROOT / "observation/rsi/fixtures" / name).read_text())


def schema(version):
    return ns.resolve_schema(
        owner.CONFIG["owner_repository"],
        version,
        owner.CONFIG["schemas"][version]["native_schema_ref"],
    )[0]


@pytest.mark.parametrize("version", VERSIONS)
def test_full_native_fixture_conforms_and_keeps_exact_raw_digest(version):
    value = fixture(version)
    raw = json.dumps(value, indent=3, sort_keys=False).encode() + b"\n"
    result = owner.attempt_export(raw, "a" * 40)
    assert result["status"] == "OBSERVATION_EXPORT_EMITTED"
    assert p.canonical(result) == p.canonical(owner.attempt_export(raw, "a" * 40))
    export = result["export"]
    assert export["schema_version"] == "miskatonic.rsi-owner-observation-export.v0.2"
    provenance = export["export_provenance"]
    assert provenance["authentication"] == "NOT_PERFORMED_BY_EXPORTER"
    assert (
        provenance["release_identity_provenance"]
        == "OWNER_SUPPLIED_METADATA_UNAUTHENTICATED"
    )
    assert (
        provenance["source_digest"]
        == provenance["native_source_raw_sha256"]
        == p.digest(raw)
    )
    assert export["native_artifact_refs"][0]["raw_native_digest"] == p.digest(raw)
    assert (
        provenance["native_schema_identity"]
        == owner.CONFIG["schemas"][version]["native_schema_ref"]
    )
    assert "signature" not in export and "summary" not in export.get(
        "owner_metadata", {}
    )
    if owner.CONFIG["component"] == "review":
        assert export["owner_native_event_id"] == value["authority_workflow_run_id"]
    if owner.CONFIG["component"] == "authorization":
        assert export["candidate_repository"] == export["candidate_sha"] == "UNKNOWN"


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize(
    "attack",
    [
        "missing_required",
        "invalid_enum",
        "invalid_type",
        "additional_property",
        "wrong_native_owner",
    ],
)
def test_invalid_native_contract_fails_before_projection_and_preserves_outcome(
    version, attack
):
    original = fixture(version)
    completed = p.canonical(original)
    value = copy.deepcopy(original)
    contract = schema(version)
    mappings = owner.CONFIG["schemas"][version]["field_mappings"].values()
    if attack == "missing_required":
        key = next(
            k
            for k in contract["required"]
            if k != "schema_version" and k not in mappings
        )
        del value[key]  # This unmapped field was accepted by the previous exporter.
    elif attack == "invalid_enum":
        keys = [k for k, v in contract["properties"].items() if "enum" in v]
        if not keys:
            pytest.skip("Canonical native schema has no non-version enum")
        value[keys[0]] = "OUTSIDE_CANONICAL_DOMAIN"
    elif attack == "invalid_type":
        key = next(
            k
            for k in contract["required"]
            if k != "schema_version"
            and contract["properties"][k].get("type")
            in ("string", "boolean", "number", "integer")
        )
        value[key] = {"incompatible": "type"}
    elif attack == "additional_property":
        if contract.get("additionalProperties") is not False:
            pytest.skip("Canonical native schema permits additional properties")
        value["undeclared_fixture_property"] = "not in native contract"
    else:
        value = copy.deepcopy(FOREIGN_NATIVE)
        value["schema_version"] = version
    result = owner.attempt_export(p.canonical(value))
    assert result["status"] == "OBSERVATION_EXPORT_FAILED"
    assert result["reason"] == "NATIVE_OWNER_SCHEMA_INVALID"
    assert "export" not in result
    assert p.canonical(original) == completed
    delivery = p.deliver_observation(result, None, owner.IMPLEMENTATION_DIGEST)
    assert delivery["status"] == "OBSERVATION_EXPORT_FAILED"
    assert "owner_outcome" not in delivery


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize(
    "attack",
    [
        "wrong_digest",
        "other_owner_schema",
        "mutable_reference",
        "field_mapping_expansion",
    ],
)
def test_schema_and_projection_config_substitution_fails_closed(version, attack):
    config = copy.deepcopy(owner.CONFIG)
    entry = config["schemas"][version]
    if attack == "wrong_digest":
        entry["native_schema_ref"]["artifact_id"] = "sha256:" + "0" * 64
    elif attack == "other_owner_schema":
        other = next(
            key for key in ns.SCHEMA_BINDINGS if key != config["owner_repository"]
        )
        entry["native_schema_ref"] = next(iter(ns.SCHEMA_BINDINGS[other].values()))[
            "native_schema_ref"
        ]
    elif attack == "mutable_reference":
        entry["native_schema_ref"]["artifact_id"] = (
            "https://example.invalid/main/schema.json"
        )
    else:
        entry["field_mappings"]["disposition"] = "summary"
    result = p.attempt(
        p.canonical(fixture(version)), config, owner.IMPLEMENTATION_DIGEST
    )
    assert result["status"] == "OBSERVATION_EXPORT_FAILED"
    assert result["reason"] in {
        "NATIVE_SCHEMA_BINDING_INVALID",
        "PROJECTION_CONFIG_INVALID",
    }
    assert "export" not in result


@pytest.mark.parametrize("version", VERSIONS)
def test_changed_pinned_schema_artifact_fails_in_separate_export_invocation(
    version, tmp_path
):
    # Corrupt an isolated source copy, never the real owner or its completed outcome.
    target = tmp_path / "observation/rsi"
    shutil.copytree(ROOT / "observation/rsi", target)
    ref = owner.CONFIG["schemas"][version]["native_schema_ref"]
    snapshot_path = target / "native_schemas" / (ref["artifact_id"][7:] + ".json")
    artifact = json.loads(snapshot_path.read_text())
    contract = json.loads(artifact["content"])
    contract["required"] = ["schema_version"]
    artifact["content"] = json.dumps(contract)
    artifact["raw_sha256"] = p.digest(artifact["content"].encode())
    snapshot_path.write_text(json.dumps(artifact))
    raw = p.canonical(fixture(version))
    native_path = tmp_path / "completed.json"
    native_path.write_bytes(raw)
    result = subprocess.run(
        [sys.executable, "-B", "-m", "observation.rsi.owner_export", str(native_path)],
        cwd=tmp_path,
        env=dict(os.environ, PYTHONPATH=str(tmp_path), PYTHONDONTWRITEBYTECODE="1"),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    observation = json.loads(result.stdout)
    assert observation["status"] == "OBSERVATION_EXPORT_FAILED"
    assert observation["reason"] == "NATIVE_SCHEMA_ARTIFACT_DIGEST_MISMATCH"
    assert native_path.read_bytes() == raw


def test_schema_valid_native_payload_stays_outside_export_allowlist():
    version = VERSIONS[0]
    value = fixture(version)
    if owner.CONFIG["component"] == "authorization":
        value["reason"] = "fictional-native-explanation-not-exportable"
    elif owner.CONFIG["component"] == "review":
        value["summary"] = "fictional-native-summary-not-exportable"
    elif owner.CONFIG["component"] == "evaluation":
        value["gate_evidence"] = {"detail": "fictional-native-detail-not-exportable"}
    elif owner.CONFIG["component"] == "execution":
        value["containment_result"] = {
            "detail": "fictional-native-detail-not-exportable"
        }
    else:
        value["publisher_identity"] = "fictional-native-publisher-not-exportable"
    result = owner.attempt_export(p.canonical(value))
    assert result["status"] == "OBSERVATION_EXPORT_EMITTED"
    serialized = p.canonical(result["export"])
    assert b"not-exportable" not in serialized
