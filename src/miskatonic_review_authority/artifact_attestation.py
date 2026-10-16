from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .attestation import sign_attestation, verify_attestation
from .util import AuthorityError


_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_VERDICTS = {"APPROVE", "REQUEST_CHANGES", "REJECT"}


def require_artifact_digest(value: str) -> str:
    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        raise AuthorityError("ARTIFACT_DIGEST_INVALID")
    return value


def _require_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuthorityError("ARTIFACT_ATTESTATION_FIELD_MISSING", field)
    return value


def _validate_verdict(verdict: str, release_authorized: bool) -> None:
    if verdict not in _ALLOWED_VERDICTS:
        raise AuthorityError("ARTIFACT_ATTESTATION_VERDICT_INVALID")
    if bool(release_authorized) != (verdict == "APPROVE"):
        raise AuthorityError("ARTIFACT_ATTESTATION_RELEASE_INCONSISTENT")


def build_artifact_attestation(
    *,
    authority_principal: str,
    workflow_run_id: str,
    artifact_type: str,
    artifact_id: str,
    artifact_schema_version: str,
    artifact_digest: str,
    scope: dict[str, Any],
    producer_binding: dict[str, Any],
    reviewer_principal: str,
    review_provider: str,
    review_execution: dict[str, Any],
    verdict: str,
    release_authorized: bool,
    summary: str,
    findings: list[Any],
    confidence: float,
    reviewer_policy_version: str,
    review_model_requested: str = "",
    issued_at: str | None = None,
) -> dict[str, Any]:
    """Build an unsigned attestation for an exact typed artifact digest."""
    _validate_verdict(verdict, release_authorized)
    if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise AuthorityError("ARTIFACT_ATTESTATION_CONFIDENCE_INVALID")
    if not isinstance(scope, dict):
        raise AuthorityError("ARTIFACT_ATTESTATION_SCOPE_INVALID")
    if not isinstance(producer_binding, dict):
        raise AuthorityError("ARTIFACT_ATTESTATION_PRODUCER_BINDING_INVALID")
    if not isinstance(review_execution, dict):
        raise AuthorityError("ARTIFACT_ATTESTATION_REVIEW_EXECUTION_INVALID")
    if not isinstance(findings, list):
        raise AuthorityError("ARTIFACT_ATTESTATION_FINDINGS_INVALID")

    producer_principal = producer_binding.get("producer_principal")
    if producer_principal and producer_principal == reviewer_principal:
        raise AuthorityError("REVIEWER_PRODUCER_PRINCIPAL_COLLISION")

    return {
        "schema_version": "artifact-attestation-v1",
        "authority_principal": _require_text(authority_principal, "authority_principal"),
        "authority_workflow_run_id": _require_text(workflow_run_id, "workflow_run_id"),
        "artifact_type": _require_text(artifact_type, "artifact_type"),
        "artifact_id": _require_text(artifact_id, "artifact_id"),
        "artifact_schema_version": _require_text(
            artifact_schema_version, "artifact_schema_version"
        ),
        "artifact_digest": require_artifact_digest(artifact_digest),
        "scope": scope,
        "producer_binding": producer_binding,
        "reviewer_principal": _require_text(reviewer_principal, "reviewer_principal"),
        "review_provider": _require_text(review_provider, "review_provider"),
        "review_model_requested": str(review_model_requested),
        "review_execution": review_execution,
        "verdict": verdict,
        "release_authorized": bool(release_authorized),
        "summary": str(summary),
        "findings": findings,
        "confidence": float(confidence),
        "reviewer_policy_version": _require_text(
            reviewer_policy_version, "reviewer_policy_version"
        ),
        "issued_at": issued_at or datetime.now(timezone.utc).isoformat(),
    }


def sign_artifact_attestation(
    attestation: dict[str, Any], private_key_path: str, *, key_id: str
) -> dict[str, Any]:
    if attestation.get("schema_version") != "artifact-attestation-v1":
        raise AuthorityError("ARTIFACT_ATTESTATION_SCHEMA_UNSUPPORTED")
    return sign_attestation(attestation, private_key_path, key_id=key_id)


def verify_artifact_attestation(
    attestation: dict[str, Any],
    public_key_path: str,
    *,
    expected_key_id: str | None = None,
    expected_artifact_type: str | None = None,
    expected_artifact_id: str | None = None,
    expected_artifact_schema_version: str | None = None,
    expected_artifact_digest: str | None = None,
) -> None:
    if attestation.get("schema_version") != "artifact-attestation-v1":
        raise AuthorityError("ARTIFACT_ATTESTATION_SCHEMA_UNSUPPORTED")
    _validate_verdict(
        str(attestation.get("verdict", "")),
        bool(attestation.get("release_authorized")),
    )
    require_artifact_digest(str(attestation.get("artifact_digest", "")))

    expected = {
        "artifact_type": expected_artifact_type,
        "artifact_id": expected_artifact_id,
        "artifact_schema_version": expected_artifact_schema_version,
        "artifact_digest": expected_artifact_digest,
    }
    for field, value in expected.items():
        if value is not None and attestation.get(field) != value:
            raise AuthorityError("ARTIFACT_ATTESTATION_BINDING_MISMATCH", field)

    producer_principal = attestation.get("producer_binding", {}).get(
        "producer_principal"
    )
    if producer_principal and producer_principal == attestation.get("reviewer_principal"):
        raise AuthorityError("REVIEWER_PRODUCER_PRINCIPAL_COLLISION")

    verify_attestation(
        attestation, public_key_path, expected_key_id=expected_key_id
    )
