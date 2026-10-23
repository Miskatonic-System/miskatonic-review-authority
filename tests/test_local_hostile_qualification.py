"""Hostile qualification test suite for Local Review Authority V2 (WO-MSK-REVIEW-AUTHORITY-LOCAL-INDEPENDENCE-00A Section 8).

Verifies 11 adversarial controls on synthetic cases. All controls must fail closed.
No live scientific PR is approved during this qualification.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pwd
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from miskatonic_review_authority.local_review import (
    run_local_independent_review,
    sign_local_receipt,
    unsigned_receipt,
    verify_and_admit_local_review_receipt,
    verify_detached_signature,
    verify_execution_isolation,
)
from miskatonic_review_authority.review_backends import (
    PROMPT_TEMPLATE_SHA256,
    PROMPT_VERSION,
    SLICE_SCHEMA_SHA256,
    SLICE_SCHEMA_VERSION,
    VERDICT_SCHEMA_SHA256,
    VERDICT_SCHEMA_VERSION,
    LocalLlamaCppBackend,
)
from miskatonic_review_authority.util import AuthorityError, canonical_json_bytes, sha256_bytes, sha256_file, write_json


@pytest.fixture
def test_setup(tmp_path: Path):
    """Sets up synthetic repository, keys, and policies for hostile controls."""
    # 1. Synthetic git repo
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(repo), check=True)
    (repo / ".gitattributes").write_text("*.json text\n")
    (repo / "code.py").write_text("print('base')\n")
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "base"], cwd=str(repo), check=True)
    base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo), text=True).strip()

    (repo / "code.py").write_text("print('candidate v2')\n")
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "candidate"], cwd=str(repo), check=True)
    head_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo), text=True).strip()

    # 2. Keypairs
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    rev_priv = keys_dir / "reviewer.pem"
    rev_pub = keys_dir / "reviewer.pub.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(rev_priv), "2048"], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(rev_priv), "-pubout", "-out", str(rev_pub)], check=True, capture_output=True)
    rev_der = keys_dir / "rev.der"
    subprocess.run(["openssl", "pkey", "-in", str(rev_priv), "-pubout", "-outform", "DER", "-out", str(rev_der)], check=True, capture_output=True)
    rev_fp = f"sha256:{sha256_file(rev_der)}"

    other_priv = keys_dir / "other.pem"
    other_pub = keys_dir / "other.pub.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(other_priv), "2048"], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(other_priv), "-pubout", "-out", str(other_pub)], check=True, capture_output=True)

    # 3. Model dummy file
    model_file = tmp_path / "model.gguf"
    model_file.write_text("dummy model weights")
    model_sha = sha256_file(model_file)
    bin_file = tmp_path / "server"
    bin_file.write_text("dummy server binary")
    bin_sha = sha256_file(bin_file)

    # 4. Reviewer Policy V2
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    reviewer_policy = {
        "schema_version": "reviewer-policy-v2",
        "policy_version": "2.0.0",
        "provider": "LOCAL_LLAMA_CPP",
        "reviewer_principal": "local-review-service:msk-local-reviewer",
        "authority_principal": "github-app:miskatonic-review-authority",
        "lifecycle_state": "ACTIVE",
        "require_prior_verification": True,
        "require_signed_receipt": True,
        "release_requires": "APPROVE",
        "allowed_verdicts": ["APPROVE", "REQUEST_CHANGES", "REJECT"],
        "max_slice_characters": 24000,
        "max_slice_tokens": 12000,
        "model_identity": {
            "backend": "LOCAL_LLAMA_CPP",
            "endpoint_url": "http://127.0.0.1:11434/v1",
            "model_name": "Qwen3-14B-NVFP4.gguf",
            "model_path": str(model_file),
            "model_size_bytes": model_file.stat().st_size,
            "model_weights_sha256": model_sha,
            "runtime_binary_path": str(bin_file),
            "runtime_binary_sha256": bin_sha,
        },
        "prompt_and_schema": {
            "prompt_template_sha256": PROMPT_TEMPLATE_SHA256,
            "prompt_version": PROMPT_VERSION,
            "slice_schema_sha256": SLICE_SCHEMA_SHA256,
            "slice_schema_version": SLICE_SCHEMA_VERSION,
            "verdict_schema_sha256": VERDICT_SCHEMA_SHA256,
            "verdict_schema_version": VERDICT_SCHEMA_VERSION,
        },
        "isolation_requirements": {
            "prohibit_candidate_code_execution": True,
            "prohibit_github_app_key_on_host": True,
            "prohibit_loopback_leakage": True,
            "prohibited_agent_workspace_substring": "/home/kowen9024",
            "prohibited_service_users": ["kowen9024"],
            "require_readonly_checkout": True,
            "required_service_user": "msk-local-reviewer",
        },
        "signing": {
            "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
            "key_id": "test-reviewer-key",
            "public_key_fingerprint": rev_fp,
            "public_key_path": str(rev_pub),
        },
    }
    reviewer_policy_path = policy_dir / "trusted-reviewers-v2.json"
    write_json(reviewer_policy_path, reviewer_policy)

    signers_policy = {
        "schema_version": "miskatonic.review-trusted-signer.v1",
        "authority_id": "miskatonic-review-authority",
        "reviewer_principal": "local-review-service:msk-local-reviewer",
        "key_id": "test-reviewer-key",
        "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
        "public_key_path": str(rev_pub),
        "public_key_fingerprint": rev_fp,
        "trust_root_version": "2.0.0",
        "lifecycle_state": "ACTIVE",
    }
    signers_policy_path = policy_dir / "trusted-signers.json"
    write_json(signers_policy_path, signers_policy)

    producers_policy = {
        "schema_version": "trusted-producer-bindings-v1",
        "bindings": [
            {
                "repository": "Miskatonic-System/msk-ruliology",
                "pr_number": 999,
                "head_branch": "agent/synthetic-test",
                "producer_principal": "cloud-authoring-service:openai-chatgpt-connected-github",
                "producer_key_id": "producer-test-key",
            }
        ],
    }
    producers_policy_path = policy_dir / "trusted-producers.json"
    write_json(producers_policy_path, producers_policy)

    # 5. Prior evidence and review packet
    from miskatonic_review_authority.canonical_digest import candidate_digest

    cand_digest, _ = candidate_digest("Miskatonic-System/msk-ruliology", str(repo), base_sha, head_sha)

    prior_evidence = {
        "base_sha": base_sha,
        "candidate_digest": cand_digest,
        "head_sha": head_sha,
        "policy_version": "2.0.0",
        "repository": "miskatonic-system/msk-ruliology",
        "schema_version": "prior-verification-evidence-v1",
        "scientific_evidence_verifications": {
            "all_passed": True,
            "hostile_controls_passed": 38,
        },
        "target_policy_schema": "scientific-target-policy-v1",
        "verdict": "PASS",
    }
    prior_path = tmp_path / "prior.json"
    write_json(prior_path, prior_evidence)

    diff_str = subprocess.check_output(["git", "diff", base_sha, head_sha], cwd=str(repo), text=True)
    review_packet = {
        "base_sha": base_sha,
        "candidate_digest": cand_digest,
        "changed_file_manifest": [
            {
                "classification": "FULL_DIFF_REVIEWED",
                "git_blob_sha": "dummy",
                "path": "code.py",
                "size_bytes": 20,
                "status": "M",
            }
        ],
        "classification_counts": {"FULL_DIFF_REVIEWED": 1},
        "head_sha": head_sha,
        "repository": "Miskatonic-System/msk-ruliology",
        "schema_version": "scientific-review-packet-v1",
        "source_diff": diff_str,
        "total_changed_files": 1,
    }
    packet_path = tmp_path / "packet.json"
    write_json(packet_path, review_packet)

    return {
        "base_sha": base_sha,
        "cand_digest": cand_digest,
        "diff_str": diff_str,
        "head_sha": head_sha,
        "model_file": model_file,
        "model_sha": model_sha,
        "other_priv": other_priv,
        "other_pub": other_pub,
        "packet_path": packet_path,
        "policy_dir": policy_dir,
        "prior_path": prior_path,
        "producers_policy_path": producers_policy_path,
        "repo": repo,
        "rev_fp": rev_fp,
        "rev_priv": rev_priv,
        "rev_pub": rev_pub,
        "reviewer_policy": reviewer_policy,
        "reviewer_policy_path": reviewer_policy_path,
        "signers_policy_path": signers_policy_path,
        "tmp_path": tmp_path,
    }


def _make_valid_synthetic_receipt(setup: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    diff_bytes = len(setup["diff_str"].encode("utf-8"))
    receipt = {
        "abstention": {"abstained": False, "reason": ""},
        "base_sha": setup["base_sha"],
        "candidate_digest": setup["cand_digest"],
        "confidence": 1.0,
        "deterministic_verification_outcomes": {
            "prior_verification_digest": "a" * 64,
            "prior_verification_verdict": "PASS",
            "scientific_evidence_verifications": {"status": "QUALIFIED"},
            "target_policy_path": "policy/targets/msk-ruliology-cra-05y-v2.json",
            "target_policy_sha256": "b" * 64,
        },
        "findings": [],
        "head_branch": "agent/synthetic-test",
        "head_sha": setup["head_sha"],
        "issued_at": "2026-10-23T10:00:00Z",
        "model_identity": {
            "backend": "LOCAL_LLAMA_CPP",
            "endpoint_url": "http://127.0.0.1:11434/v1",
            "loopback_only_verified": True,
            "model_name": "Qwen3-14B-NVFP4.gguf",
            "model_path": str(setup["model_file"]),
            "model_size_bytes": setup["model_file"].stat().st_size,
            "model_weights_sha256": setup["model_sha"],
            "runtime_binary_path": "/opt/miskatonic/local-reviewer/bin/llama-server",
            "runtime_binary_sha256": setup["reviewer_policy"]["model_identity"]["runtime_binary_sha256"],
        },
        "pr_number": 999,
        "producer_binding": {
            "producer_principal": "cloud-authoring-service:openai-chatgpt-connected-github",
            "producer_key_id": "producer-test-key",
        },
        "prompt_and_schema": {
            "prompt_template_sha256": PROMPT_TEMPLATE_SHA256,
            "prompt_version": PROMPT_VERSION,
            "slice_schema_sha256": SLICE_SCHEMA_SHA256,
            "slice_schema_version": SLICE_SCHEMA_VERSION,
            "verdict_schema_sha256": VERDICT_SCHEMA_SHA256,
            "verdict_schema_version": VERDICT_SCHEMA_VERSION,
        },
        "receipt_id": "receipt-test-01",
        "release_authorized": True,
        "repository": "Miskatonic-System/msk-ruliology",
        "review_coverage_manifest": {
            "all_changed_files_accounted_for": True,
            "classification_counts": {"FULL_DIFF_REVIEWED": 1},
            "full_diff_aggregate_sha256": sha256_bytes(setup["diff_str"].encode("utf-8")),
            "full_diff_bytes_reviewed": diff_bytes,
            "full_diff_bytes_total": diff_bytes,
            "full_diff_files_reviewed": 1,
            "full_diff_files_total": 1,
            "max_slice_characters_budget": 24000,
            "max_slice_tokens_observed": 100,
            "slice_count": 1,
            "slices": [
                {
                    "abstained": False,
                    "diff_bytes": diff_bytes,
                    "diff_sha256": sha256_bytes(setup["diff_str"].encode("utf-8")),
                    "findings_count": 0,
                    "finish_reason": "stop",
                    "paths": ["code.py"],
                    "slice_id": "slice_0001",
                    "slice_status": "PASS",
                    "uncertainty_level": "LOW",
                }
            ],
            "total_changed_files": 1,
        },
        "review_packet_digest": "c" * 64,
        "review_packet_manifest_digest": "c" * 64,
        "reviewer_implementation_digest": "d" * 64,
        "reviewer_policy_version": "2.0.0",
        "reviewer_service_identity": {
            "candidate_checkout_path": "/var/lib/miskatonic/local-reviewer/checkouts/test",
            "candidate_checkout_readonly_verified": True,
            "candidate_code_executed": False,
            "github_app_private_key_present_locally": False,
            "os_gid": 994,
            "os_uid": 994,
            "os_user": "msk-local-reviewer",
            "reviewer_principal": "local-review-service:msk-local-reviewer",
            "signing_key_id": "test-reviewer-key",
            "signing_public_key_fingerprint": setup["rev_fp"],
            "working_directory": "/var/lib/miskatonic/local-reviewer",
        },
        "schema_version": "local-review-receipt-v2",
        "summary": "Synthesized APPROVE verdict for candidate.",
        "uncertainty": {"explicit_uncertainties": [], "level": "LOW", "residual_risks": []},
        "verdict": "APPROVE",
    }
    receipt.update(overrides)
    signed, _ = sign_local_receipt(
        receipt,
        str(setup["rev_priv"]),
        key_id="test-reviewer-key",
        public_key_fingerprint_val=setup["rev_fp"],
    )
    return signed


# =============================================================================
# 11 HOSTILE QUALIFICATION CONTROLS (SECTION 8)
# =============================================================================


def test_control_01_stale_head(test_setup):
    """Control 1: Stale HEAD SHA must fail closed."""
    receipt = _make_valid_synthetic_receipt(test_setup, head_sha="1" * 40)
    receipt_file = test_setup["tmp_path"] / "r1.json"
    write_json(receipt_file, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=receipt_file,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup["head_sha"],  # Different from receipt's 1111...
            expected_base_sha=test_setup["base_sha"],
            target_repo_path=str(test_setup["repo"]),
            target_policy_path="dummy",
            trusted_reviewers_policy_path=str(test_setup["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup["producers_policy_path"]),
        )
    assert exc_info.value.code == "STALE_REVIEW_HEAD"


def test_control_02_forged_model_identity(test_setup):
    """Control 2: Forged model weights digest must fail closed."""
    # Alter model weights digest in receipt
    model_override = copy.deepcopy(test_setup["reviewer_policy"]["model_identity"])
    model_override["model_weights_sha256"] = "f" * 64
    receipt = _make_valid_synthetic_receipt(test_setup, model_identity=model_override)
    receipt_file = test_setup["tmp_path"] / "r2.json"
    write_json(receipt_file, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=receipt_file,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup["head_sha"],
            expected_base_sha=test_setup["base_sha"],
            target_repo_path=str(test_setup["repo"]),
            target_policy_path="dummy",
            trusted_reviewers_policy_path=str(test_setup["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup["producers_policy_path"]),
        )
    assert exc_info.value.code == "FORGED_MODEL_IDENTITY"


def test_control_03_forged_reviewer_identity(test_setup):
    """Control 3: Forged reviewer principal or untrusted key ID must fail closed."""
    rev_id_override = copy.deepcopy(test_setup["reviewer_policy"]["signing"])
    receipt = _make_valid_synthetic_receipt(
        test_setup,
        reviewer_service_identity={
            "candidate_checkout_path": "/var/lib/test",
            "candidate_checkout_readonly_verified": True,
            "candidate_code_executed": False,
            "github_app_private_key_present_locally": False,
            "os_gid": 994,
            "os_uid": 994,
            "os_user": "msk-local-reviewer",
            "reviewer_principal": "imposter-reviewer-service",
            "signing_key_id": "test-reviewer-key",
            "signing_public_key_fingerprint": test_setup["rev_fp"],
            "working_directory": "/var/lib/test",
        },
    )
    receipt_file = test_setup["tmp_path"] / "r3.json"
    write_json(receipt_file, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=receipt_file,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup["head_sha"],
            expected_base_sha=test_setup["base_sha"],
            target_repo_path=str(test_setup["repo"]),
            target_policy_path="dummy",
            trusted_reviewers_policy_path=str(test_setup["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup["producers_policy_path"]),
        )
    assert exc_info.value.code == "FORGED_REVIEWER_IDENTITY"


def test_control_04_tampered_receipt(test_setup):
    """Control 4: Tampered receipt payload after signing must fail closed."""
    receipt = _make_valid_synthetic_receipt(test_setup)
    # Tamper with verdict or confidence after signing
    receipt["confidence"] = 0.5
    receipt_file = test_setup["tmp_path"] / "r4.json"
    write_json(receipt_file, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=receipt_file,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup["head_sha"],
            expected_base_sha=test_setup["base_sha"],
            target_repo_path=str(test_setup["repo"]),
            target_policy_path="dummy",
            trusted_reviewers_policy_path=str(test_setup["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup["producers_policy_path"]),
        )
    assert exc_info.value.code in ("RECEIPT_PAYLOAD_TAMPERED", "RECEIPT_SIGNATURE_INVALID")


def test_control_05_invalid_signature(test_setup):
    """Control 5: Corrupted cryptographic signature must fail closed."""
    receipt = _make_valid_synthetic_receipt(test_setup)
    # Corrupt signature string
    corrupt_sig = "A" + receipt["detached_signature"]["value_base64"][1:]
    receipt["detached_signature"]["value_base64"] = corrupt_sig
    receipt_file = test_setup["tmp_path"] / "r5.json"
    write_json(receipt_file, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=receipt_file,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup["head_sha"],
            expected_base_sha=test_setup["base_sha"],
            target_repo_path=str(test_setup["repo"]),
            target_policy_path="dummy",
            trusted_reviewers_policy_path=str(test_setup["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup["producers_policy_path"]),
        )
    assert exc_info.value.code == "RECEIPT_SIGNATURE_INVALID"


def test_control_06_producer_reviewer_key_collision(test_setup):
    """Control 6: Collision between producer key/principal and reviewer key/principal must fail closed."""
    # Modify producers policy so producer key matches reviewer key
    colliding_producers = {
        "schema_version": "trusted-producer-bindings-v1",
        "bindings": [
            {
                "repository": "Miskatonic-System/msk-ruliology",
                "pr_number": 999,
                "head_branch": "agent/synthetic-test",
                "producer_principal": "local-review-service:msk-local-reviewer",  # Colliding principal!
                "producer_key_id": "test-reviewer-key",  # Colliding key!
            }
        ],
    }
    col_path = test_setup["tmp_path"] / "col_producers.json"
    write_json(col_path, colliding_producers)

    receipt = _make_valid_synthetic_receipt(test_setup)
    receipt_file = test_setup["tmp_path"] / "r6.json"
    write_json(receipt_file, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=receipt_file,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup["head_sha"],
            expected_base_sha=test_setup["base_sha"],
            target_repo_path=str(test_setup["repo"]),
            target_policy_path="dummy",
            trusted_reviewers_policy_path=str(test_setup["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup["signers_policy_path"]),
            trusted_producers_policy_path=str(col_path),
        )
    assert exc_info.value.code in (
        "REVIEWER_PRODUCER_PRINCIPAL_COLLISION",
        "PRODUCER_REVIEWER_KEY_COLLISION",
    )


def test_control_07_truncated_evidence(test_setup):
    """Control 7: Truncated evidence or incomplete file review coverage must fail closed."""
    receipt = _make_valid_synthetic_receipt(test_setup)
    # Set full_diff_files_reviewed to 0
    receipt["review_coverage_manifest"]["full_diff_files_reviewed"] = 0
    signed, _ = sign_local_receipt(
        unsigned_receipt(receipt),
        str(test_setup["rev_priv"]),
        key_id="test-reviewer-key",
        public_key_fingerprint_val=test_setup["rev_fp"],
    )
    receipt_file = test_setup["tmp_path"] / "r7.json"
    write_json(receipt_file, signed)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=receipt_file,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup["head_sha"],
            expected_base_sha=test_setup["base_sha"],
            target_repo_path=str(test_setup["repo"]),
            target_policy_path="dummy",
            trusted_reviewers_policy_path=str(test_setup["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup["producers_policy_path"]),
        )
    assert exc_info.value.code == "TRUNCATED_EVIDENCE"


def test_control_08_incorrect_prior_verification(test_setup):
    """Control 8: Prior verification failure or mismatch must fail closed."""
    receipt = _make_valid_synthetic_receipt(test_setup)
    receipt["deterministic_verification_outcomes"]["prior_verification_verdict"] = "FAIL"
    signed, _ = sign_local_receipt(
        unsigned_receipt(receipt),
        str(test_setup["rev_priv"]),
        key_id="test-reviewer-key",
        public_key_fingerprint_val=test_setup["rev_fp"],
    )
    receipt_file = test_setup["tmp_path"] / "r8.json"
    write_json(receipt_file, signed)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=receipt_file,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup["head_sha"],
            expected_base_sha=test_setup["base_sha"],
            target_repo_path=str(test_setup["repo"]),
            target_policy_path="dummy",
            trusted_reviewers_policy_path=str(test_setup["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup["producers_policy_path"]),
        )
    assert exc_info.value.code == "INCORRECT_PRIOR_VERIFICATION"


def test_control_09_fabricated_approve(test_setup):
    """Control 9: Fabricated APPROVE with abstention or slice failures must fail closed."""
    # Fabricated approval where model actually abstained
    receipt = _make_valid_synthetic_receipt(
        test_setup,
        abstention={"abstained": True, "reason": "insufficient evidence"},
        verdict="APPROVE",
        release_authorized=True,
    )
    receipt_file = test_setup["tmp_path"] / "r9.json"
    write_json(receipt_file, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=receipt_file,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup["head_sha"],
            expected_base_sha=test_setup["base_sha"],
            target_repo_path=str(test_setup["repo"]),
            target_policy_path="dummy",
            trusted_reviewers_policy_path=str(test_setup["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup["producers_policy_path"]),
        )
    assert exc_info.value.code == "LOCAL_REVIEW_ABSTENTION_BLOCKS_APPROVAL"


def test_control_10_model_nonresponse(test_setup):
    """Control 10: Model nonresponse or server outage must fail closed."""
    backend = LocalLlamaCppBackend(endpoint_url="http://127.0.0.1:9999/v1")  # Dead port

    with pytest.raises(AuthorityError) as exc_info:
        backend.review(
            repository="Miskatonic-System/msk-ruliology",
            pr_number=999,
            base_sha=test_setup["base_sha"],
            head_sha=test_setup["head_sha"],
            candidate_digest=test_setup["cand_digest"],
            review_packet=json.loads(test_setup["packet_path"].read_text()),
            prior_evidence=json.loads(test_setup["prior_path"].read_text()),
            producer_binding={},
            reviewer_policy=test_setup["reviewer_policy"],
        )
    assert exc_info.value.code in ("MODEL_ENDPOINT_UNAVAILABLE", "LOCAL_REVIEW_MODEL_NONRESPONSE")


def test_control_11_explicit_request_changes(test_setup):
    """Control 11: Explicit REQUEST_CHANGES verdict must fail closed during admission."""
    receipt = _make_valid_synthetic_receipt(
        test_setup,
        verdict="REQUEST_CHANGES",
        release_authorized=False,
        findings=[{"details": "missing test", "path": "code.py", "severity": "P2", "title": "Coverage gap"}],
    )
    receipt_file = test_setup["tmp_path"] / "r11.json"
    write_json(receipt_file, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=receipt_file,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup["head_sha"],
            expected_base_sha=test_setup["base_sha"],
            target_repo_path=str(test_setup["repo"]),
            target_policy_path="dummy",
            trusted_reviewers_policy_path=str(test_setup["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup["producers_policy_path"]),
        )
    assert exc_info.value.code == "LOCAL_REVIEW_VERDICT_NOT_APPROVED"


def test_control_12_isolation_prohibits_authoring_agent_user(test_setup):
    """Extra isolation control: Reviewer running as candidate authoring user must fail closed."""
    with pytest.raises(AuthorityError) as exc_info:
        verify_execution_isolation(
            candidate_repo_path=str(test_setup["repo"]),
            prohibited_users=[pwd.getpwuid(os.getuid()).pw_name],  # Current user prohibited
            enforce_strict_os_user=True,
        )
    assert exc_info.value.code == "REVIEWER_SERVICE_IDENTITY_PROHIBITED"
