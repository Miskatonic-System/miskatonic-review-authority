"""Independent Review Authority V2 Runner.

Implements WO-RA-EVALUATOR-ATTESTATION-BINDING-01A and 01A-R1.
Runs production cloud-review or controlled-integration reviews against candidates
bound to independently verified EvaluatorEvidenceIngress v1 evidence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .attestation import sign_attestation
from .attestation_v2 import (
    build_review_attestation_v2,
    validate_review_attestation_v2,
    verify_review_attestation_v2,
)
from .canonical_digest import candidate_digest
from .evaluator_ingress import (
    verify_evaluator_ingress_for_attestation,
    verify_review_authority_source,
    write_ingress_json_atomically,
)
from .review_runner import _call_openai, _trusted_producer
from .util import AuthorityError, read_json

CONTROLLED_FIXTURE_ALLOWED_KEYS = {
    "verdict",
    "summary",
    "findings",
    "confidence",
    "release_authorized",  # inert / compatibility only
}


def run_review_v2(
    *,
    repository: str,
    pr_number: int,
    head_branch: str,
    repo_path: str,
    base_sha: str,
    head_sha: str,
    prior_evidence_path: str,
    producer_bindings_path: str,
    reviewer_policy_path: str,
    private_key_path: str | Path,
    public_key_path: str | Path,
    key_id: str,
    diff_path: str,
    output_path: str,
    api_key: str,
    model: str,
    authority_principal: str,
    workflow_run_id: str,
    review_authority_root: str | Path,
    evaluator_root: str | Path,
    control_plane_root: str | Path,
    evaluator_python: str | Path,
    evaluator_ingress_path: str | Path,
    evaluation_request_path: str | Path,
    evaluation_result_path: str | Path,
    custody_receipt_path: str | Path,
    dispatch_state_path: str | Path,
    attestation_mode: str = "PRODUCTION_REVIEW",
    review_fixture: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Runs a Review Authority V2 review binding independently verified evaluator evidence.
    
    Production order (WO-RA-EVALUATOR-ATTESTATION-BINDING-01A / 01A-R1):
    1. verify exact clean RA source;
    2. verify accepted evaluator ingress and underlying foreign evidence;
    3. verify candidate / base / head binding;
    4. verify prior evidence;
    5. compute candidate digest;
    6. resolve trusted producer;
    7. load reviewer policy;
    8. enforce reviewer/producer independence;
    9. load bounded diff;
    10. invoke independent cloud review (or controlled integration fixture);
    11. derive release gate mechanically;
    12. construct review-attestation-v2;
    13. validate unsigned v2 schema and cross-field invariants;
    14. sign using existing Review Authority signer;
    15. verify signed v2 schema;
    16. verify RSA signature with provided public_key_path;
    17. verify expected key_id;
    18. verify evaluator-ingress digest/binding;
    19. verify release gate;
    20. atomically materialize output only after full post-sign verification.
    """
    ra_root = Path(review_authority_root).resolve()
    eval_root = Path(evaluator_root).resolve()
    cp_root = Path(control_plane_root).resolve()
    eval_py = Path(evaluator_python).resolve()
    ingr_path = Path(evaluator_ingress_path).resolve()
    req_path = Path(evaluation_request_path).resolve()
    res_path = Path(evaluation_result_path).resolve()
    cust_path = Path(custody_receipt_path).resolve()
    disp_path = Path(dispatch_state_path).resolve()
    out_path = Path(output_path).resolve()
    priv_path = Path(private_key_path).resolve()
    pub_path = Path(public_key_path).resolve()

    if not pub_path.exists() or not pub_path.is_file():
        raise AuthorityError("PUBLIC_KEY_NOT_FOUND", str(pub_path))
    if not priv_path.exists() or not priv_path.is_file():
        raise AuthorityError("PRIVATE_KEY_NOT_FOUND", str(priv_path))

    # 1. Verify exact clean Review Authority source
    ra_sha = verify_review_authority_source(ra_root)

    # 2. Verify accepted evaluator ingress and underlying foreign evidence
    eval_evidence = verify_evaluator_ingress_for_attestation(
        evaluator_ingress_path=ingr_path,
        review_authority_root=ra_root,
        evaluator_root=eval_root,
        control_plane_root=cp_root,
        evaluator_python=eval_py,
        evaluation_request_path=req_path,
        evaluation_result_path=res_path,
        custody_receipt_path=cust_path,
        dispatch_state_path=disp_path,
    )

    # 3. Verify candidate / base / head binding against ingress
    if repository.lower() != eval_evidence["candidate_repository"].lower():
        raise AuthorityError("CANDIDATE_REPOSITORY_BINDING_MISMATCH")
    if base_sha.lower() != eval_evidence["baseline_sha"].lower():
        raise AuthorityError("BASELINE_SHA_BINDING_MISMATCH")
    if head_sha.lower() != eval_evidence["candidate_sha"].lower():
        raise AuthorityError("CANDIDATE_SHA_BINDING_MISMATCH")

    # 4. Verify prior evidence
    prior = read_json(prior_evidence_path)
    if prior.get("verdict") != "PASS" or prior.get("head_sha") != head_sha or prior.get("base_sha") != base_sha:
        raise AuthorityError("PRIOR_VERIFICATION_EVIDENCE_INVALID")
    digest, _ = candidate_digest(repository, repo_path, base_sha, head_sha)
    if prior.get("candidate_digest") != digest:
        raise AuthorityError("PRIOR_VERIFICATION_DIGEST_STALE")

    # 5. Resolve trusted producer
    producer = _trusted_producer(producer_bindings_path, repository, pr_number, head_branch)

    # 6. Load reviewer policy
    reviewer_policy = read_json(reviewer_policy_path)
    if reviewer_policy.get("schema_version") != "reviewer-policy-v1":
        raise AuthorityError("REVIEWER_POLICY_SCHEMA_UNSUPPORTED")
    reviewer_principal = str(reviewer_policy.get("reviewer_principal", ""))
    if not reviewer_principal:
        raise AuthorityError("REVIEWER_PRINCIPAL_MISSING")
    if reviewer_principal == producer.get("producer_principal"):
        raise AuthorityError("REVIEWER_PRODUCER_PRINCIPAL_COLLISION")

    # 7. Load bounded diff
    diff_text = Path(diff_path).read_text(encoding="utf-8", errors="replace")
    max_chars = int(reviewer_policy.get("max_diff_characters", 500000))
    if len(diff_text) > max_chars:
        raise AuthorityError("REVIEW_DIFF_BUDGET_EXCEEDED")

    # 8. Cloud review or controlled integration execution
    if attestation_mode == "CONTROLLED_INTEGRATION":
        review_provider = "controlled-integration"
        review_model_requested = "none"
        review_execution = {
            "client_request_id": "controlled-integration",
            "provider_request_id": "controlled-integration",
            "response_id": "controlled-integration",
            "returned_model": "none",
        }

        if review_fixture is not None:
            # Validate controlled fixture key set (Section P)
            unknown_keys = set(review_fixture.keys()) - CONTROLLED_FIXTURE_ALLOWED_KEYS
            if unknown_keys:
                raise AuthorityError(
                    "CONTROLLED_FIXTURE_INVALID_KEY",
                    f"unknown keys in controlled fixture: {sorted(unknown_keys)}",
                )
            verdict = review_fixture.get("verdict", "REQUEST_CHANGES")
            summary = review_fixture.get("summary", "Controlled integration fixture; no production review executed.")
            findings = review_fixture.get("findings", [])
            confidence = float(review_fixture.get("confidence", 1.0))
        else:
            verdict = "REQUEST_CHANGES"
            summary = "Controlled integration fixture; no production review executed."
            findings = []
            confidence = 1.0

    elif attestation_mode == "PRODUCTION_REVIEW":
        if reviewer_policy.get("provider") != "openai-responses":
            raise AuthorityError("REVIEW_PROVIDER_UNSUPPORTED")
        review_provider = "openai-responses"
        review_model_requested = model

        prompt = json.dumps(
            {
                "task": "Review candidate for release authorization",
                "repository": repository,
                "pr_number": pr_number,
                "base_sha": base_sha,
                "head_sha": head_sha,
                "candidate_digest": digest,
                "producer": producer,
                "prior_verification": prior,
                "evaluator_evidence": {
                    "ingress_id": eval_evidence["ingress_id"],
                    "ingress_sha256": eval_evidence["ingress_sha256"],
                    "evaluator_repository": eval_evidence["evaluator_repository"],
                    "evaluator_sha": eval_evidence["evaluator_sha"],
                    "evaluation_id": eval_evidence["evaluation_id"],
                    "evaluation_result_sha256": eval_evidence["evaluation_result_sha256"],
                    "recommendation": eval_evidence["recommendation"],
                    "task_pack_id": eval_evidence["task_pack_id"],
                    "task_pack_sha256": eval_evidence["task_pack_sha256"],
                },
                "unified_diff": diff_text,
            },
            ensure_ascii=False,
        )
        review, review_execution = _call_openai(api_key=api_key, model=model, prompt=prompt)
        verdict = review["verdict"]
        summary = review["summary"]
        findings = review["findings"]
        confidence = float(review["confidence"])
    else:
        raise AuthorityError("ATTESTATION_MODE_INVALID", f"unsupported mode '{attestation_mode}'")

    # 9. Build Review Attestation V2
    attestation = build_review_attestation_v2(
        authority_principal=authority_principal,
        authority_workflow_run_id=workflow_run_id,
        review_authority_sha=ra_sha,
        attestation_mode=attestation_mode,
        repository=repository,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        candidate_digest=digest,
        producer_binding=producer,
        reviewer_principal=reviewer_principal,
        review_provider=review_provider,
        review_model_requested=review_model_requested,
        review_execution=review_execution,
        verdict=verdict,
        summary=summary,
        findings=findings,
        confidence=confidence,
        reviewer_policy_version=reviewer_policy["policy_version"],
        evaluator_evidence=eval_evidence,
    )

    # 10. Validate before signing (fail before signing)
    validate_review_attestation_v2(
        attestation,
        expected_evaluator_evidence=eval_evidence,
    )

    # 11. Sign with standard RSA signer
    signed = sign_attestation(attestation, str(priv_path), key_id=key_id)

    # 12. Post-sign verification (Sections E, F, G)
    # Must verify signed artifact before writing to disk
    ingress_for_verify = eval_evidence.get("envelope", eval_evidence)
    try:
        verify_review_attestation_v2(
            signed,
            str(pub_path),
            ingress_for_verify,
            expected_key_id=key_id,
        )
    except Exception as err:
        if isinstance(err, AuthorityError):
            raise
        raise AuthorityError("SIGNED_ATTESTATION_POSTVERIFY_FAILED", str(err)) from err

    # 13. Atomically materialize output only after full post-sign verification
    write_ingress_json_atomically(out_path, signed)

    return signed
