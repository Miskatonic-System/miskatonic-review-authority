"""Post-completion projection only. No native-owner calls, writes, or network."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, datetime

UNKNOWN = "UNKNOWN"
VERSION = "miskatonic.rsi-owner-observation-export.v0.1"
SECRET_KEYS = {
    "secret",
    "password",
    "api_key",
    "private_key",
    "signing_key",
    "signing_material",
    "credentials",
    "hidden_holdout_contents",
    "hidden_taskpack_contents",
    "private_reasoning",
    "chain_of_thought",
}


class ObservationError(ValueError):
    pass


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ObservationError("DUPLICATE_NATIVE_KEY")
            result[key] = value
        return result

    def nonfinite(value):
        raise ObservationError("NONFINITE_NATIVE_NUMBER")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)

    def walk(node):
        if isinstance(node, dict):
            if any(k.casefold() in SECRET_KEYS for k in node):
                raise ObservationError("SECRET_OR_HIDDEN_EVIDENCE_BOUNDARY")
            for item in node.values():
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, float) and not math.isfinite(node):
            raise ObservationError("NONFINITE_NATIVE_NUMBER")
        elif isinstance(node, str) and (
            "PRIVATE KEY-----" in node or node.startswith("Bearer ")
        ):
            raise ObservationError("SECRET_OR_HIDDEN_EVIDENCE_BOUNDARY")

    walk(value)
    if not isinstance(value, dict):
        raise ObservationError("NATIVE_OBJECT_REQUIRED")
    return value


def pointer(value, path):
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            return UNKNOWN
        value = value[key]
    return UNKNOWN if value is None else value


def project(raw, config, implementation_digest, owner_release=UNKNOWN):
    if not isinstance(raw, bytes) or len(raw) > 1048576:
        raise ObservationError("NATIVE_ARTIFACT_NOT_BOUNDED")
    native = parse(raw)
    version = native.get("schema_version")
    if version not in config["schemas"]:
        raise ObservationError("OWNER_SCHEMA_MISMATCH")
    if owner_release != UNKNOWN and not re.fullmatch("[0-9a-f]{40}", owner_release):
        raise ObservationError("IMMUTABLE_OWNER_RELEASE_REQUIRED")
    if config["component"] == "review":
        signature = native.get("signature")
        if (
            not isinstance(signature, dict)
            or signature.get("algorithm") != "RSASSA-PKCS1-v1_5-SHA256"
            or not signature.get("key_id")
            or not signature.get("value_base64")
        ):
            raise ObservationError("UNSIGNED_ARTIFACT_NOT_ATTESTATION_REFERENCE")
    mapping = config["schemas"][version]
    fields = {key: pointer(native, path) for key, path in mapping.items()}
    for key in (
        "owner_native_event_id",
        "candidate_repository",
        "candidate_sha",
        "occurred_at",
    ):
        fields.setdefault(key, UNKNOWN)
    for key, value in fields.items():
        if isinstance(value, (dict, list)) or value is None:
            raise ObservationError("NATIVE_METADATA_TYPE_INVALID")
        if isinstance(value, str) and (
            len(value) > 256 or any(c in value for c in ("\n", "\r", "\x00"))
        ):
            raise ObservationError("NATIVE_METADATA_NOT_BOUNDED")
    for field in config.get("unavailable_metadata_fields", ()):
        fields[field] = UNKNOWN
    candidate = fields["candidate_sha"]
    if candidate != UNKNOWN and (
        not isinstance(candidate, str) or not re.fullmatch("[0-9a-f]{40}", candidate)
    ):
        raise ObservationError("EXACT_CANDIDATE_SHA_REQUIRED")
    occurred = fields["occurred_at"]
    transformation = "DIRECT_NATIVE_POINTERS_V0_1"
    if occurred != UNKNOWN:
        if isinstance(occurred, (int, float)) and not isinstance(occurred, bool):
            occurred = (
                datetime.fromtimestamp(occurred, UTC).isoformat().replace("+00:00", "Z")
            )
            transformation = "DIRECT_NATIVE_POINTERS_AND_UNIX_UTC_V0_1"
        if (
            not isinstance(occurred, str)
            or datetime.fromisoformat(occurred).tzinfo is None
        ):
            raise ObservationError("NATIVE_TIME_NOT_EXACT")
    metadata = {
        k: v
        for k, v in fields.items()
        if k
        not in (
            "owner_native_event_id",
            "candidate_repository",
            "candidate_sha",
            "occurred_at",
        )
    }
    export = {
        "schema_version": VERSION,
        "owner_repository": config["owner_repository"],
        "owner_component": config["component"],
        "owner_component_version": owner_release,
        "owner_native_event_type": version,
        "owner_native_event_id": fields["owner_native_event_id"],
        "candidate_repository": fields["candidate_repository"],
        "candidate_sha": candidate,
        "occurred_at": occurred,
        "trust_epoch_ref_if_known": UNKNOWN,
        "owner_metadata": metadata,
        "authority": "NONE",
        "native_artifact_refs": [
            {
                "raw_native_digest": digest(raw),
                "native_schema_version": version,
                "owner_repository": config["owner_repository"],
                "owner_release_identity": owner_release,
                "native_event_id": fields["owner_native_event_id"],
                "native_candidate_identity": candidate,
            }
        ],
        "export_provenance": {
            "class": "DETERMINISTIC_DERIVATION",
            "source_fields": {
                **mapping,
                **{
                    field: "@UNAVAILABLE_NATIVE_FIELD"
                    for field in config.get("unavailable_metadata_fields", ())
                },
                "owner_component_version": "@owner_release_input",
            },
            "release_identity_input": owner_release,
            "release_identity_provenance": "UNKNOWN"
            if owner_release == UNKNOWN
            else "OWNER_SUPPLIED_METADATA_UNAUTHENTICATED",
            "transformation_version": transformation,
            "transformation_digest": implementation_digest,
            "projection_identity": "miskatonic.rsi-owner-projection.v0.1",
            "export_digest_domain": "JSON_SORTED_UTF8_V1",
            "source_digest": digest(raw),
            "authentication": "NOT_PERFORMED_BY_EXPORTER",
            "timestamp_native_value": fields["occurred_at"],
            "unknown_fields": sorted(k for k, v in fields.items() if v == UNKNOWN)
            + ["trust_epoch_ref_if_known"],
        },
    }
    export["export_id"] = digest(canonical(export))
    return export


def attempt(raw, config, implementation_digest, owner_release=UNKNOWN):
    try:
        return {
            "status": "OBSERVATION_EXPORT_EMITTED",
            "export": project(raw, config, implementation_digest, owner_release),
            "authority": "NONE",
        }
    except Exception as error:  # noqa: BLE001 - observation failure cannot affect native completion.
        reason = (
            str(error)
            if isinstance(error, ObservationError)
            else "INVALID_NATIVE_ARTIFACT"
        )
        return {
            "status": "OBSERVATION_EXPORT_FAILED",
            "reason": reason,
            "authority": "NONE",
        }


def deliver_observation(
    result, storage, expected_projection, expected_candidate=UNKNOWN
):
    """Separate post-completion delivery. This API never calls a native owner."""
    try:
        if result is None or result.get("status") != "OBSERVATION_EXPORT_EMITTED":
            raise ObservationError("OBSERVER_UNAVAILABLE_OR_EXPORT_FAILED")
        export = result["export"]
        if export["export_id"] != digest(
            canonical({k: v for k, v in export.items() if k != "export_id"})
        ):
            raise ObservationError("MALFORMED_EXPORT_DIGEST")
        if export["export_provenance"]["transformation_digest"] != expected_projection:
            raise ObservationError("STALE_OBSERVER_RELEASE")
        if (
            expected_candidate != UNKNOWN
            and export["candidate_sha"] != expected_candidate
        ):
            raise ObservationError("CANDIDATE_IDENTITY_MISMATCH")
        if storage is None:
            raise ObservationError("CUSTODY_STORE_UNAVAILABLE")
        stored = storage.store(canonical(export))
        if stored != export["export_id"]:
            raise ObservationError("CUSTODY_IDENTITY_MISMATCH")
        return {
            "status": "OBSERVATION_EXPORT_STORED",
            "export_id": stored,
            "authority": "NONE",
            "trust_epoch": export["trust_epoch_ref_if_known"],
            "candidate_sha": export["candidate_sha"],
        }
    except Exception as error:  # noqa: BLE001 - observation failure cannot affect native completion.
        reason = (
            str(error)
            if isinstance(error, ObservationError)
            else "OBSERVATION_STORAGE_FAILED"
        )
        return {
            "status": "OBSERVATION_EXPORT_FAILED",
            "reason": reason,
            "authority": "NONE",
        }
