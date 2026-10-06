"""Pinned, offline native JSON Schema validation. Conformance is not authentication."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime
from pathlib import Path

SCHEMA_BINDINGS = {
    "Miskatonic-System/miskatonic-control-plane": {
        "miskatonic.candidate-publication-receipt.v1": {
            "owner_repository": "Miskatonic-System/miskatonic-control-plane",
            "native_schema_version": "miskatonic.candidate-publication-receipt.v1",
            "source_path": "schemas/candidate-publication-receipt-v1.schema.json",
            "source_commit": "55164feee6d6d1f228b81000d7abb8780650ca74",
            "raw_sha256": "sha256:e09094b550e1b1f659b5ebd91ce2ec9dfbd20958ec360c8ba13652c9d39da51d",
            "native_schema_ref": {
                "artifact_id": "sha256:1338e881625f1dc750acf8130dd26858366d8da58858b56dd2183c895d647c08",
                "kind": "canonical_native_owner_schema",
                "version": "1",
            },
        },
        "miskatonic.candidate-publication-receipt.v2": {
            "owner_repository": "Miskatonic-System/miskatonic-control-plane",
            "native_schema_version": "miskatonic.candidate-publication-receipt.v2",
            "source_path": "schemas/candidate-publication-receipt-v2.schema.json",
            "source_commit": "55164feee6d6d1f228b81000d7abb8780650ca74",
            "raw_sha256": "sha256:9bccee68a7ba62c2ecf22a22f27ef7e4d70b57415507933cadd98460d91a9bc1",
            "native_schema_ref": {
                "artifact_id": "sha256:8d19aa462107157fa916269f8e6b3bc755efb3e1288d0860d65218bbb9a298da",
                "kind": "canonical_native_owner_schema",
                "version": "1",
            },
        },
    },
    "Miskatonic-System/miskatonic-agent-os": {
        "miskatonic.agent-execution-receipt.v1": {
            "owner_repository": "Miskatonic-System/miskatonic-agent-os",
            "native_schema_version": "miskatonic.agent-execution-receipt.v1",
            "source_path": "schemas/agent-execution-receipt-v1.schema.json",
            "source_commit": "185f9717c0e6133a55f8b20ad0ecd8b387f4ded1",
            "raw_sha256": "sha256:37f6db555686b54abcd85f77689816dc43cb5c7ff4783ea6030c9870ec8096bc",
            "native_schema_ref": {
                "artifact_id": "sha256:daeb81fd83a8216bb9072888252eaf1bb08120730bfebcc27c34cfc58716c3ad",
                "kind": "canonical_native_owner_schema",
                "version": "1",
            },
        }
    },
    "Miskatonic-System/miskatonic-agent-evaluator": {
        "miskatonic.evaluation.v2": {
            "owner_repository": "Miskatonic-System/miskatonic-agent-evaluator",
            "native_schema_version": "miskatonic.evaluation.v2",
            "source_path": "schemas/evaluation-result-v2.schema.json",
            "source_commit": "545c018285bd0e77248157c8a7cc7206cf416bcb",
            "raw_sha256": "sha256:5091affee5a7281cea41a480d94bc31fddeb2eed1605e06fdf55f0c0c8e7a658",
            "native_schema_ref": {
                "artifact_id": "sha256:5fc379fd075f0bd5aeec7b6b1e4a0904b32c281cb7eb43d94a73db2b62181da3",
                "kind": "canonical_native_owner_schema",
                "version": "1",
            },
        }
    },
    "Miskatonic-System/miskatonic-review-authority": {
        "review-attestation-v1": {
            "owner_repository": "Miskatonic-System/miskatonic-review-authority",
            "native_schema_version": "review-attestation-v1",
            "source_path": "schemas/review-attestation-v1.schema.json",
            "source_commit": "83ff809b185497978b74fb98a40e8d07c245d607",
            "raw_sha256": "sha256:133f5b8c255227f8bb59b93b0e59963dfdb791849c547cf02001d0553f5191a6",
            "native_schema_ref": {
                "artifact_id": "sha256:d4ae8b008b14f8b52b9376691aae6a57ac0fbd575fdb52f7d89b6f9edb90c4ce",
                "kind": "canonical_native_owner_schema",
                "version": "1",
            },
        }
    },
    "Miskatonic-System/miskatonic-runtime-governance": {
        "miskatonic.authorization-decision.v1": {
            "owner_repository": "Miskatonic-System/miskatonic-runtime-governance",
            "native_schema_version": "miskatonic.authorization-decision.v1",
            "source_path": "schemas/authorization-decision-v1.schema.json",
            "source_commit": "025f9199c4c51a1548d7716ecf80e92000e0c542",
            "raw_sha256": "sha256:6f3daefac0b5ff73cbbe685e29b180bf03eceb5a3b240430818f05557f42643b",
            "native_schema_ref": {
                "artifact_id": "sha256:11e9e0f61b54df3f78f3d2386390bde9b36555075c750536533c79489e39fd94",
                "kind": "canonical_native_owner_schema",
                "version": "1",
            },
        }
    },
}
PROJECTION_CONFIGS = {
    "Miskatonic-System/miskatonic-control-plane": {
        "component": "publication",
        "owner_repository": "Miskatonic-System/miskatonic-control-plane",
        "schemas": {
            "miskatonic.candidate-publication-receipt.v1": {
                "native_schema_ref": {
                    "artifact_id": "sha256:1338e881625f1dc750acf8130dd26858366d8da58858b56dd2183c895d647c08",
                    "kind": "canonical_native_owner_schema",
                    "version": "1",
                },
                "field_mappings": {
                    "candidate_repository": "repository",
                    "candidate_sha": "candidate_sha",
                    "occurred_at": "published_at",
                    "owner_native_event_id": "receipt_sha256",
                    "task_identity": "task_id",
                },
            },
            "miskatonic.candidate-publication-receipt.v2": {
                "native_schema_ref": {
                    "artifact_id": "sha256:8d19aa462107157fa916269f8e6b3bc755efb3e1288d0860d65218bbb9a298da",
                    "kind": "canonical_native_owner_schema",
                    "version": "1",
                },
                "field_mappings": {
                    "candidate_repository": "repository",
                    "candidate_sha": "roles.semantic_candidate_sha",
                    "occurred_at": "provider.observed_at",
                    "owner_native_event_id": "receipt_sha256",
                    "work_order_identity": "work_order_id",
                },
            },
        },
        "unavailable_metadata_fields": ["handoff_identity"],
    },
    "Miskatonic-System/miskatonic-agent-os": {
        "component": "execution",
        "owner_repository": "Miskatonic-System/miskatonic-agent-os",
        "schemas": {
            "miskatonic.agent-execution-receipt.v1": {
                "native_schema_ref": {
                    "artifact_id": "sha256:daeb81fd83a8216bb9072888252eaf1bb08120730bfebcc27c34cfc58716c3ad",
                    "kind": "canonical_native_owner_schema",
                    "version": "1",
                },
                "field_mappings": {
                    "agent_os_version": "agent_os_sha",
                    "candidate_repository": "destination_repository",
                    "candidate_sha": "candidate_commit",
                    "disposition": "execution_result",
                    "occurred_at": "completed_at",
                    "owner_native_event_id": "execution_id",
                    "task_manifest_identity": "task_manifest_sha256",
                },
            }
        },
        "unavailable_metadata_fields": ["execution_envelope_identity"],
    },
    "Miskatonic-System/miskatonic-agent-evaluator": {
        "component": "evaluation",
        "owner_repository": "Miskatonic-System/miskatonic-agent-evaluator",
        "schemas": {
            "miskatonic.evaluation.v2": {
                "native_schema_ref": {
                    "artifact_id": "sha256:5fc379fd075f0bd5aeec7b6b1e4a0904b32c281cb7eb43d94a73db2b62181da3",
                    "kind": "canonical_native_owner_schema",
                    "version": "1",
                },
                "field_mappings": {
                    "candidate_repository": "candidate_repository",
                    "candidate_sha": "candidate_sha",
                    "disposition": "recommendation",
                    "evaluator_identity": "evaluator_repository",
                    "evaluator_version": "evaluator_sha",
                    "occurred_at": "created_at",
                    "owner_native_event_id": "evaluation_id",
                    "taskpack_identity": "task_pack_sha256",
                },
            }
        },
        "unavailable_metadata_fields": [],
    },
    "Miskatonic-System/miskatonic-review-authority": {
        "component": "review",
        "owner_repository": "Miskatonic-System/miskatonic-review-authority",
        "schemas": {
            "review-attestation-v1": {
                "native_schema_ref": {
                    "artifact_id": "sha256:d4ae8b008b14f8b52b9376691aae6a57ac0fbd575fdb52f7d89b6f9edb90c4ce",
                    "kind": "canonical_native_owner_schema",
                    "version": "1",
                },
                "field_mappings": {
                    "candidate_repository": "repository",
                    "candidate_sha": "head_sha",
                    "disposition": "verdict",
                    "occurred_at": "issued_at",
                    "policy_version": "reviewer_policy_version",
                    "review_principal": "reviewer_principal",
                    "owner_native_event_id": "authority_workflow_run_id",
                },
            }
        },
        "unavailable_metadata_fields": ["attestation_identity"],
    },
    "Miskatonic-System/miskatonic-runtime-governance": {
        "component": "authorization",
        "owner_repository": "Miskatonic-System/miskatonic-runtime-governance",
        "schemas": {
            "miskatonic.authorization-decision.v1": {
                "native_schema_ref": {
                    "artifact_id": "sha256:11e9e0f61b54df3f78f3d2386390bde9b36555075c750536533c79489e39fd94",
                    "kind": "canonical_native_owner_schema",
                    "version": "1",
                },
                "field_mappings": {
                    "disposition": "allowed",
                    "occurred_at": "decided_at",
                    "owner_native_event_id": "decision_id",
                    "policy_version": "policy_version",
                },
            }
        },
        "unavailable_metadata_fields": ["authority_domain", "policy_identity"],
    },
}


class NativeSchemaError(ValueError):
    """Only fixed error codes may leave the observation boundary."""


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


def parse_schema_artifact(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise NativeSchemaError("NATIVE_SCHEMA_ARTIFACT_INVALID")
            value[key] = item
        return value

    def finite(value):
        raise NativeSchemaError("NATIVE_SCHEMA_ARTIFACT_INVALID")

    def walk(value):
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, float) and not math.isfinite(value):
            raise NativeSchemaError("NATIVE_SCHEMA_ARTIFACT_INVALID")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=finite)
    walk(value)
    return value


def check_projection_config(config):
    owner = config.get("owner_repository")
    expected = PROJECTION_CONFIGS.get(owner)
    if expected is None or set(config) != set(expected):
        raise NativeSchemaError("PROJECTION_CONFIG_INVALID")
    if (
        config["component"] != expected["component"]
        or config["unavailable_metadata_fields"]
        != expected["unavailable_metadata_fields"]
    ):
        raise NativeSchemaError("PROJECTION_CONFIG_INVALID")
    if set(config["schemas"]) != set(expected["schemas"]):
        raise NativeSchemaError("NATIVE_SCHEMA_BINDING_INVALID")
    for version, entry in config["schemas"].items():
        if (
            set(entry) != {"native_schema_ref", "field_mappings"}
            or entry["native_schema_ref"]
            != expected["schemas"][version]["native_schema_ref"]
        ):
            raise NativeSchemaError("NATIVE_SCHEMA_BINDING_INVALID")
        if entry["field_mappings"] != expected["schemas"][version]["field_mappings"]:
            raise NativeSchemaError("PROJECTION_CONFIG_INVALID")


def resolve_schema(owner, version, ref, artifact_raw=None):
    binding = SCHEMA_BINDINGS.get(owner, {}).get(version)
    if binding is None or ref != binding["native_schema_ref"]:
        raise NativeSchemaError("NATIVE_SCHEMA_BINDING_INVALID")
    if not re.fullmatch("[0-9a-f]{40}", binding["source_commit"]):
        raise NativeSchemaError("NATIVE_SCHEMA_BINDING_INVALID")
    try:
        if artifact_raw is None:
            artifact_raw = (
                Path(__file__).parent
                / "native_schemas"
                / (ref["artifact_id"][7:] + ".json")
            ).read_bytes()
        artifact = parse_schema_artifact(artifact_raw)
        if digest(canonical(artifact)) != ref["artifact_id"]:
            raise NativeSchemaError("NATIVE_SCHEMA_ARTIFACT_DIGEST_MISMATCH")
        metadata = {k: v for k, v in binding.items() if k != "native_schema_ref"}
        if artifact != {
            "kind": ref["kind"],
            "version": ref["version"],
            **metadata,
            "content": artifact.get("content"),
        }:
            raise NativeSchemaError("NATIVE_SCHEMA_BINDING_INVALID")
        raw_schema = artifact["content"].encode()
        if digest(raw_schema) != binding["raw_sha256"]:
            raise NativeSchemaError("NATIVE_SCHEMA_RAW_DIGEST_MISMATCH")
        schema = parse_schema_artifact(raw_schema)
        if (
            schema.get("properties", {}).get("schema_version", {}).get("const")
            != version
        ):
            raise NativeSchemaError("NATIVE_SCHEMA_VERSION_BINDING_INVALID")
        return schema, binding
    except NativeSchemaError:
        raise
    except Exception:  # noqa: BLE001 - never echo source contents across the export boundary.
        raise NativeSchemaError(
            "NATIVE_SCHEMA_ARTIFACT_UNAVAILABLE_OR_INVALID"
        ) from None


def validate_native(native, owner, version, ref, artifact_raw=None):
    schema, binding = resolve_schema(owner, version, ref, artifact_raw)
    if native.get("schema_version") != version:
        raise NativeSchemaError("NATIVE_SCHEMA_VERSION_BINDING_INVALID")
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from jsonschema.validators import validator_for
        from referencing import Registry
    except ImportError:
        raise NativeSchemaError("NATIVE_SCHEMA_VALIDATOR_UNAVAILABLE") from None

    checker = FormatChecker()

    @checker.checks("date-time", raises=(ValueError, TypeError))
    def exact_datetime(value):
        # Deterministic RFC3339 subset; never silently skip a declared date-time.
        if not isinstance(value, str):
            return True  # JSON Schema type keywords remain authoritative.
        if not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})",
            value,
        ):
            return False
        return datetime.fromisoformat(value.replace("z", "Z")).tzinfo is not None

    try:
        cls = validator_for(schema, default=Draft202012Validator)
        cls.check_schema(schema)
        # Registry has no retrieval callback: a native $ref cannot cause network IO.
        if not cls(schema, registry=Registry(), format_checker=checker).is_valid(
            native
        ):
            raise NativeSchemaError("NATIVE_OWNER_SCHEMA_INVALID")
    except NativeSchemaError:
        raise
    except Exception:  # noqa: BLE001 - never echo source contents across the export boundary.
        raise NativeSchemaError("NATIVE_OWNER_SCHEMA_INVALID") from None
    return binding
