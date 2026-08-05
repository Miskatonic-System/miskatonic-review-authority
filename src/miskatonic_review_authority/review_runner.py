from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .attestation import sign_attestation
from .canonical_digest import candidate_digest
from .util import AuthorityError, read_json, write_json


_REVIEW_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "release_authorized", "summary", "findings", "confidence"],
    "properties": {
        "verdict": {"type": "string", "enum": ["APPROVE", "REQUEST_CHANGES", "REJECT"]},
        "release_authorized": {"type": "boolean"},
        "summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["severity", "title", "details", "path"],
                "properties": {
                    "severity": {"type": "string", "enum": ["P0", "P1", "P2", "P3", "INFO"]},
                    "title": {"type": "string"},
                    "details": {"type": "string"},
                    "path": {"type": "string"},
                },
            },
        },
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
}


def _extract_output_text(response: dict[str, Any]) -> str:
    for item in response.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                return content["text"]
    raise AuthorityError("CLOUD_REVIEW_OUTPUT_MISSING")


def _validate_review(value: dict[str, Any]) -> None:
    required = {"verdict", "release_authorized", "summary", "findings", "confidence"}
    if not isinstance(value, dict) or set(value) != required:
        raise AuthorityError("CLOUD_REVIEW_SCHEMA_INVALID")
    if value["verdict"] not in {"APPROVE", "REQUEST_CHANGES", "REJECT"}:
        raise AuthorityError("CLOUD_REVIEW_VERDICT_INVALID")
    if bool(value["release_authorized"]) != (value["verdict"] == "APPROVE"):
        raise AuthorityError("CLOUD_REVIEW_RELEASE_INCONSISTENT")
    if not isinstance(value["findings"], list):
        raise AuthorityError("CLOUD_REVIEW_FINDINGS_INVALID")
    if not isinstance(value["confidence"], (int, float)) or not 0 <= value["confidence"] <= 1:
        raise AuthorityError("CLOUD_REVIEW_CONFIDENCE_INVALID")


def _call_openai(*, api_key: str, model: str, prompt: str) -> tuple[dict[str, Any], dict[str, str]]:
    if not api_key:
        raise AuthorityError("CLOUD_REVIEW_API_KEY_MISSING")
    if not model:
        raise AuthorityError("CLOUD_REVIEW_MODEL_MISSING")
    request_id = str(uuid.uuid4())
    payload = {
        "model": model,
        "store": False,
        "instructions": (
            "You are an independent cloud code reviewer. Review the exact candidate evidence. "
            "Do not approve unless inherited policy, architecture, security, tests, and release boundaries are sound. "
            "Return only the requested structured verdict."
        ),
        "input": prompt,
        "text": {
            "format": {
                "type": "json_schema",
                "name": "miskatonic_review_verdict",
                "strict": True,
                "schema": _REVIEW_SCHEMA,
            }
        },
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "miskatonic-review-authority/0.1",
            "X-Client-Request-Id": request_id,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=600) as response:
            response_json = json.loads(response.read().decode("utf-8"))
            server_request_id = response.headers.get("x-request-id", "")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[-4000:]
        raise AuthorityError("CLOUD_REVIEW_REQUEST_FAILED", f"HTTP {error.code}: {detail}") from error
    if response_json.get("status") not in {None, "completed"}:
        raise AuthorityError("CLOUD_REVIEW_NOT_COMPLETED", str(response_json.get("status")))
    review = json.loads(_extract_output_text(response_json))
    _validate_review(review)
    return review, {
        "client_request_id": request_id,
        "provider_request_id": server_request_id,
        "response_id": str(response_json.get("id", "")),
        "returned_model": str(response_json.get("model", model)),
    }


def _trusted_producer(bindings_path: str, repository: str, pr_number: int, head_branch: str) -> dict[str, Any]:
    bindings = read_json(bindings_path)
    for binding in bindings.get("bindings", []):
        if (
            binding.get("repository", "").lower() == repository.lower()
            and binding.get("pr_number") == pr_number
            and binding.get("head_branch") == head_branch
        ):
            return binding
    raise AuthorityError("TRUSTED_PRODUCER_BINDING_MISSING")


def run_review(
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
    private_key_path: str,
    key_id: str,
    diff_path: str,
    output_path: str,
    api_key: str,
    model: str,
    authority_principal: str,
    workflow_run_id: str,
) -> dict[str, Any]:
    prior = read_json(prior_evidence_path)
    if prior.get("verdict") != "PASS" or prior.get("head_sha") != head_sha or prior.get("base_sha") != base_sha:
        raise AuthorityError("PRIOR_VERIFICATION_EVIDENCE_INVALID")
    digest, _ = candidate_digest(repository, repo_path, base_sha, head_sha)
    if prior.get("candidate_digest") != digest:
        raise AuthorityError("PRIOR_VERIFICATION_DIGEST_STALE")
    producer = _trusted_producer(producer_bindings_path, repository, pr_number, head_branch)
    reviewer_policy = read_json(reviewer_policy_path)
    if reviewer_policy.get("schema_version") != "reviewer-policy-v1":
        raise AuthorityError("REVIEWER_POLICY_SCHEMA_UNSUPPORTED")
    if reviewer_policy.get("provider") != "openai-responses":
        raise AuthorityError("REVIEW_PROVIDER_UNSUPPORTED")
    reviewer_principal = str(reviewer_policy.get("reviewer_principal", ""))
    if not reviewer_principal:
        raise AuthorityError("REVIEWER_PRINCIPAL_MISSING")
    if reviewer_principal == producer.get("producer_principal"):
        raise AuthorityError("REVIEWER_PRODUCER_PRINCIPAL_COLLISION")
    diff_text = Path(diff_path).read_text(encoding="utf-8", errors="replace")
    max_chars = int(reviewer_policy.get("max_diff_characters", 500000))
    if len(diff_text) > max_chars:
        raise AuthorityError("REVIEW_DIFF_BUDGET_EXCEEDED")
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
            "unified_diff": diff_text,
        },
        ensure_ascii=False,
    )
    review, provider_evidence = _call_openai(api_key=api_key, model=model, prompt=prompt)
    issued_at = datetime.now(timezone.utc).isoformat()
    attestation: dict[str, Any] = {
        "schema_version": "review-attestation-v1",
        "authority_principal": authority_principal,
        "authority_workflow_run_id": workflow_run_id,
        "repository": repository.lower(),
        "pr_number": pr_number,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "candidate_digest": digest,
        "producer_binding": producer,
        "reviewer_principal": reviewer_principal,
        "review_provider": "openai-responses",
        "review_model_requested": model,
        "review_execution": provider_evidence,
        "verdict": review["verdict"],
        "release_authorized": review["release_authorized"],
        "summary": review["summary"],
        "findings": review["findings"],
        "confidence": review["confidence"],
        "reviewer_policy_version": reviewer_policy["policy_version"],
        "issued_at": issued_at,
    }
    signed = sign_attestation(attestation, private_key_path, key_id=key_id)
    write_json(output_path, signed)
    return signed
