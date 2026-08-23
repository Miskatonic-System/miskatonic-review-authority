"""Review Attestation V2 with Evaluator Evidence Binding.

Implements WO-RA-EVALUATOR-ATTESTATION-BINDING-01A.
Cryptographically binds independently verified EvaluatorEvidenceIngress v1 evidence
into signed review-attestation-v2 artifacts without modifying historical v1 semantics.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import jsonschema

from .attestation import sign_attestation, verify_attestation
from .util import (
    AuthorityError,
    canonical_json_bytes,
    read_json,
    require_full_sha,
    sha256_bytes,
)

SCHEMA_VERSION_V2 = "review-attestation-v2"
RELEASE_GATE_POLICY_VERSION = "evaluator-gated-review-v1"


def derive_release_gate(
    verdict: str,
    evaluator_recommendation: str,
    attestation_mode: str,
) -> Tuple[Dict[str, Any], bool]:
    """Mechanically derives the release_gate object and final release_authorized boolean.
    
    Canonical rule (WO-RA-EVALUATOR-ATTESTATION-BINDING-01A Section 2 & 23):
    release_authorized =
        attestation_mode == "PRODUCTION_REVIEW"
        AND verdict == "APPROVE"
        AND evaluator_evidence.recommendation == "approve_candidate"
    """
    review_verdict_allows_release = (verdict == "APPROVE")
    evaluator_recommendation_allows_release = (evaluator_recommendation == "approve_candidate")
    attestation_mode_allows_release = (attestation_mode == "PRODUCTION_REVIEW")

    release_gate = {
        "policy_version": RELEASE_GATE_POLICY_VERSION,
        "review_verdict_allows_release": review_verdict_allows_release,
        "evaluator_recommendation_allows_release": evaluator_recommendation_allows_release,
        "attestation_mode_allows_release": attestation_mode_allows_release,
    }

    release_authorized = (
        review_verdict_allows_release
        and evaluator_recommendation_allows_release
        and attestation_mode_allows_release
    )

    return release_gate, release_authorized


def build_review_attestation_v2(
    *,
    authority_principal: str,
    authority_workflow_run_id: str,
    review_authority_sha: str,
    attestation_mode: str,
    repository: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    candidate_digest: str,
    producer_binding: Dict[str, Any],
    reviewer_principal: str,
    review_provider: str,
    review_model_requested: str,
    review_execution: Dict[str, Any],
    verdict: str,
    summary: str,
    findings: List[Dict[str, Any]],
    confidence: float,
    reviewer_policy_version: str,
    evaluator_evidence: Dict[str, Any],
    issued_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Builds an unsigned review-attestation-v2 artifact with mechanically derived release authority."""
    require_full_sha(review_authority_sha, field="review_authority_sha")
    require_full_sha(base_sha, field="base_sha")
    require_full_sha(head_sha, field="head_sha")

    if attestation_mode not in {"PRODUCTION_REVIEW", "CONTROLLED_INTEGRATION"}:
        raise AuthorityError("ATTESTATION_MODE_INVALID", f"unsupported attestation_mode '{attestation_mode}'")

    if verdict not in {"APPROVE", "REQUEST_CHANGES", "REJECT"}:
        raise AuthorityError("REVIEW_VERDICT_INVALID", f"unsupported verdict '{verdict}'")

    rec = evaluator_evidence.get("recommendation")
    if rec not in {"approve_candidate", "reject"}:
        raise AuthorityError("EVALUATOR_RECOMMENDATION_INVALID", f"unsupported evaluator recommendation '{rec}'")

    # Mechanically derive release gate
    release_gate, release_authorized = derive_release_gate(
        verdict=verdict,
        evaluator_recommendation=rec,
        attestation_mode=attestation_mode,
    )

    # Sanitize evaluator_evidence to only exact schema fields
    cleaned_evaluator_evidence = {
        "schema_version": "evaluator-evidence-ingress-v1",
        "ingress_id": evaluator_evidence["ingress_id"],
        "ingress_sha256": evaluator_evidence["ingress_sha256"],
        "ingress_review_authority_sha": evaluator_evidence.get("ingress_review_authority_sha") or evaluator_evidence.get("review_authority_sha"),
        "evaluator_repository": evaluator_evidence["evaluator_repository"],
        "evaluator_sha": evaluator_evidence["evaluator_sha"],
        "control_plane_repository": evaluator_evidence["control_plane_repository"],
        "control_plane_sha": evaluator_evidence["control_plane_sha"],
        "evaluation_id": evaluator_evidence["evaluation_id"],
        "evaluation_result_sha256": evaluator_evidence["evaluation_result_sha256"],
        "recommendation": evaluator_evidence["recommendation"],
        "task_pack_id": evaluator_evidence["task_pack_id"],
        "task_pack_sha256": evaluator_evidence["task_pack_sha256"],
        "authority_effect": "EVIDENCE_ONLY",
    }

    now_iso = issued_at or datetime.now(timezone.utc).isoformat()

    return {
        "schema_version": SCHEMA_VERSION_V2,
        "authority_principal": authority_principal,
        "authority_workflow_run_id": authority_workflow_run_id,
        "review_authority_sha": review_authority_sha,
        "attestation_mode": attestation_mode,
        "repository": repository.lower(),
        "pr_number": pr_number,
        "base_sha": base_sha.lower(),
        "head_sha": head_sha.lower(),
        "candidate_digest": candidate_digest.lower(),
        "producer_binding": copy.deepcopy(producer_binding),
        "reviewer_principal": reviewer_principal,
        "review_provider": review_provider,
        "review_model_requested": review_model_requested,
        "review_execution": copy.deepcopy(review_execution),
        "verdict": verdict,
        "release_authorized": release_authorized,
        "summary": summary,
        "findings": copy.deepcopy(findings),
        "confidence": confidence,
        "reviewer_policy_version": reviewer_policy_version,
        "evaluator_evidence": cleaned_evaluator_evidence,
        "release_gate": release_gate,
        "issued_at": now_iso,
    }


def validate_review_attestation_v2(
    attestation: Dict[str, Any],
    *,
    schema: Optional[Dict[str, Any]] = None,
    schema_path: Optional[Path] = None,
    expected_evaluator_evidence: Optional[Dict[str, Any]] = None,
) -> None:
    """Validates schema and semantic invariants of a review-attestation-v2 artifact."""
    if schema is None:
        if schema_path is None:
            schema_path = Path(__file__).resolve().parent.parent.parent / "schemas" / "review-attestation-v2.schema.json"
        if not schema_path.exists():
            raise AuthorityError("REVIEW_ATTESTATION_V2_SCHEMA_MISSING", str(schema_path))
        schema = read_json(schema_path)

    # 1. Schema Validation
    schema_to_use = copy.deepcopy(schema)
    if "signature" not in attestation:
        if "signature" in schema_to_use.get("required", []):
            schema_to_use["required"] = [r for r in schema_to_use["required"] if r != "signature"]
    try:
        jsonschema.validate(instance=attestation, schema=schema_to_use)
    except Exception as err:
        raise AuthorityError("REVIEW_ATTESTATION_V2_SCHEMA_VIOLATION", str(err)) from err

    # 2. Review Authority Source SHA
    require_full_sha(attestation.get("review_authority_sha", ""), field="review_authority_sha")

    # 3. Release Gate Consistency
    mode = attestation.get("attestation_mode")
    verdict = attestation.get("verdict")
    eval_ev = attestation.get("evaluator_evidence", {})
    rec = eval_ev.get("recommendation")

    expected_gate, expected_rel_auth = derive_release_gate(
        verdict=verdict,
        evaluator_recommendation=rec,
        attestation_mode=mode,
    )

    actual_gate = attestation.get("release_gate")
    if actual_gate != expected_gate:
        raise AuthorityError(
            "RELEASE_GATE_DERIVATION_MISMATCH",
            f"actual gate {actual_gate} != expected {expected_gate}",
        )

    if attestation.get("release_authorized") != expected_rel_auth:
        raise AuthorityError(
            "RELEASE_AUTHORIZED_INCONSISTENT",
            f"actual {attestation.get('release_authorized')} != expected {expected_rel_auth}",
        )

    if mode == "CONTROLLED_INTEGRATION" and attestation.get("release_authorized") is not False:
        raise AuthorityError("CONTROLLED_MODE_CANNOT_AUTHORIZE_RELEASE")

    # 4. Ingress Binding Cross-Check (if provided)
    if expected_evaluator_evidence is not None:
        if eval_ev.get("ingress_sha256", "").lower() != expected_evaluator_evidence.get("ingress_sha256", "").lower():
            raise AuthorityError("ATTESTATION_INGRESS_DIGEST_MISMATCH")
        if eval_ev.get("ingress_id") != expected_evaluator_evidence.get("ingress_id"):
            raise AuthorityError("ATTESTATION_INGRESS_ID_MISMATCH")
        if eval_ev.get("evaluator_repository", "").lower() != expected_evaluator_evidence.get("evaluator_repository", "").lower():
            raise AuthorityError("ATTESTATION_EVALUATOR_REPO_MISMATCH")
        if eval_ev.get("evaluator_sha", "").lower() != expected_evaluator_evidence.get("evaluator_sha", "").lower():
            raise AuthorityError("ATTESTATION_EVALUATOR_SHA_MISMATCH")
        if eval_ev.get("control_plane_repository", "").lower() != expected_evaluator_evidence.get("control_plane_repository", "").lower():
            raise AuthorityError("ATTESTATION_CONTROL_PLANE_REPO_MISMATCH")
        if eval_ev.get("control_plane_sha", "").lower() != expected_evaluator_evidence.get("control_plane_sha", "").lower():
            raise AuthorityError("ATTESTATION_CONTROL_PLANE_SHA_MISMATCH")
        if eval_ev.get("evaluation_id") != expected_evaluator_evidence.get("evaluation_id"):
            raise AuthorityError("ATTESTATION_EVALUATION_ID_MISMATCH")
        if eval_ev.get("evaluation_result_sha256", "").lower() != expected_evaluator_evidence.get("evaluation_result_sha256", "").lower():
            raise AuthorityError("ATTESTATION_EVALUATION_RESULT_SHA_MISMATCH")
        if eval_ev.get("recommendation") != expected_evaluator_evidence.get("recommendation"):
            raise AuthorityError("ATTESTATION_RECOMMENDATION_MISMATCH")
        if eval_ev.get("task_pack_id") != expected_evaluator_evidence.get("task_pack_id"):
            raise AuthorityError("ATTESTATION_TASK_PACK_ID_MISMATCH")
        if eval_ev.get("task_pack_sha256", "").lower() != expected_evaluator_evidence.get("task_pack_sha256", "").lower():
            raise AuthorityError("ATTESTATION_TASK_PACK_SHA_MISMATCH")

        # Candidate binding check
        cand_repo = expected_evaluator_evidence.get("candidate_repository")
        if cand_repo and attestation.get("repository", "").lower() != cand_repo.lower():
            raise AuthorityError("ATTESTATION_CANDIDATE_REPO_MISMATCH")
        base_sha = expected_evaluator_evidence.get("baseline_sha")
        if base_sha and attestation.get("base_sha", "").lower() != base_sha.lower():
            raise AuthorityError("ATTESTATION_BASELINE_SHA_MISMATCH")
        head_sha = expected_evaluator_evidence.get("candidate_sha")
        if head_sha and attestation.get("head_sha", "").lower() != head_sha.lower():
            raise AuthorityError("ATTESTATION_CANDIDATE_SHA_MISMATCH")


def sign_review_attestation_v2(
    attestation: Dict[str, Any],
    private_key_path: str,
    *,
    key_id: str,
    schema_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Signs a review-attestation-v2 artifact using the standard Review Authority signer."""
    validate_review_attestation_v2(attestation, schema_path=schema_path)
    return sign_attestation(attestation, private_key_path, key_id=key_id)


def verify_review_attestation_v2(
    attestation: Dict[str, Any],
    public_key_path: str,
    evaluator_ingress: Dict[str, Any],
    *,
    expected_key_id: Optional[str] = None,
    schema_path: Optional[Path] = None,
) -> None:
    """Verifies RSA signature, schema, release-gate semantics, and ingress binding for review-attestation-v2."""
    # 1. Validate Schema and Internal Attestation Invariants
    validate_review_attestation_v2(
        attestation,
        schema_path=schema_path,
    )

    # 2. Verify RSA Signature (Section 38: signature covers all unsigned fields including ingress_sha256)
    verify_attestation(attestation, public_key_path, expected_key_id=expected_key_id)

    # 3. Recompute Evaluator Ingress Digest (Section 37, 39)
    env_for_digest = {k: v for k, v in evaluator_ingress.items() if k != "ingress_sha256"}
    recomputed_ingress_sha = sha256_bytes(canonical_json_bytes(env_for_digest))
    declared_ingress_sha = evaluator_ingress.get("ingress_sha256", "").lower()
    if declared_ingress_sha != recomputed_ingress_sha.lower():
        raise AuthorityError(
            "INGRESS_ENVELOPE_DIGEST_MISMATCH",
            f"declared '{declared_ingress_sha}' != computed '{recomputed_ingress_sha}'",
        )

    # 4. Cross-validate Attestation Evaluator Evidence Against Evaluator Ingress Artifact
    validate_review_attestation_v2(
        attestation,
        schema_path=schema_path,
        expected_evaluator_evidence=evaluator_ingress,
    )
