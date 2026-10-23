"""Hostile qualification test suite for Local Review Authority V2.1 Admission Repair
(WO-MSK-REVIEW-AUTHORITY-LOCAL-V2-ADMISSION-REPAIR-00A Section 11).

Verifies failing adversarial controls for all 19 required attack vectors:
1. Confidence = 100
2. Missing target policy
3. Forged target-policy digest
4. Wrong PR target
5. Incorrect prior-verification claim
6. Missing required scientific evidence
7. Omitted diff file
8. Skipped diff slice
9. Fabricated reviewed-byte count
10. Invalid diff aggregate digest
11. P1 suppressed during synthesis
12. Arbitrary authoritative check name
13. Local review impersonating cloud review
14. Wrong reviewer identity
15. Wrong model weights digest
16. Invalid detached signature
17. Stale candidate HEAD
18. Unauthorized authoring-user review
19. Tampered signed receipt

All controls must fail closed.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from miskatonic_review_authority.cli import _admit_local_review, _local_review
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
from miskatonic_review_authority.util import (
    AuthorityError,
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    write_json,
)


@pytest.fixture
def test_setup_v2_1(tmp_path: Path):
    """Sets up synthetic repository, keys, target policy, and policies for V2.1 controls."""
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

    (repo / "code.py").write_text("print('candidate v2.1')\n")
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "candidate"], cwd=str(repo), check=True)
    head_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo), text=True).strip()

    # 2. Keypair
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    rev_priv = keys_dir / "reviewer.pem"
    rev_pub = keys_dir / "reviewer.pub.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(rev_priv), "2048"], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(rev_priv), "-pubout", "-out", str(rev_pub)], check=True, capture_output=True)
    rev_der = keys_dir / "rev.der"
    subprocess.run(["openssl", "pkey", "-in", str(rev_priv), "-pubout", "-outform", "DER", "-out", str(rev_der)], check=True, capture_output=True)
    rev_fp = f"sha256:{sha256_file(rev_der)}"

    # 3. Model dummy file
    model_file = tmp_path / "model.gguf"
    model_file.write_text("dummy model weights")
    model_sha = sha256_file(model_file)
    bin_file = tmp_path / "server"
    bin_file.write_text("dummy server binary")
    bin_sha = sha256_file(bin_file)

    # 4. Reviewer Policy V2.1
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    reviewer_policy = {
        "schema_version": "reviewer-policy-v2",
        "policy_version": "2.1.0",
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
    reviewer_policy_path = policy_dir / "trusted-reviewers-v2.1.json"
    write_json(reviewer_policy_path, reviewer_policy)

    signers_policy = {
        "schema_version": "miskatonic.review-trusted-signer.v1",
        "authority_id": "miskatonic-review-authority",
        "reviewer_principal": "local-review-service:msk-local-reviewer",
        "key_id": "test-reviewer-key",
        "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
        "public_key_path": str(rev_pub),
        "public_key_fingerprint": rev_fp,
        "trust_root_version": "2.1.0",
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

    # 5. Target Scientific Policy
    target_policy = {
        "schema_version": "scientific-target-policy-v1",
        "policy_version": "2.1.0",
        "repository": "Miskatonic-System/msk-ruliology",
        "expected_pr_number": 999,
        "expected_head_branch": "agent/synthetic-test",
        "expected_head_sha": head_sha,
        "expected_base_sha": base_sha,
        "allowed_modify_patterns": [r"^\.gitattributes$", r"^code\.py$"],
        "forbidden_modify_patterns": [r"credentials/.*"],
        "evidence_base_path": "",
        "required_evidence_files": [],
        "pinned_evidence_digests": {},
        "lfs_expected_payloads": {},
        "verification_profile": "custom",
    }
    target_policy_path = policy_dir / "synthetic-target-policy.json"
    write_json(target_policy_path, target_policy)
    target_policy_sha = sha256_bytes(canonical_json_bytes(target_policy))

    # 6. Prior evidence and review packet
    from miskatonic_review_authority.canonical_digest import candidate_digest
    cand_digest, _ = candidate_digest("Miskatonic-System/msk-ruliology", str(repo), base_sha, head_sha)

    diff_str = subprocess.check_output(["git", "diff", base_sha, head_sha], cwd=str(repo), text=True)
    diff_bytes = len(diff_str.encode("utf-8"))
    diff_sha = sha256_bytes(diff_str.encode("utf-8"))

    prior_evidence = {
        "base_sha": base_sha,
        "candidate_digest": cand_digest,
        "head_sha": head_sha,
        "policy_version": "2.1.0",
        "repository": "miskatonic-system/msk-ruliology",
        "schema_version": "prior-verification-evidence-v1",
        "scientific_evidence_verifications": {
            "all_passed": True,
            "status": "QUALIFIED",
        },
        "target_policy_schema": "scientific-target-policy-v1",
        "verdict": "PASS",
    }
    prior_path = tmp_path / "prior.json"
    write_json(prior_path, prior_evidence)
    prior_digest = sha256_bytes(canonical_json_bytes(prior_evidence))

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
        "diff_bytes": diff_bytes,
        "diff_sha": diff_sha,
        "diff_str": diff_str,
        "head_sha": head_sha,
        "model_file": model_file,
        "model_sha": model_sha,
        "packet_path": packet_path,
        "policy_dir": policy_dir,
        "prior_digest": prior_digest,
        "prior_path": prior_path,
        "producers_policy_path": producers_policy_path,
        "repo": repo,
        "rev_fp": rev_fp,
        "rev_priv": rev_priv,
        "rev_pub": rev_pub,
        "reviewer_policy": reviewer_policy,
        "reviewer_policy_path": reviewer_policy_path,
        "signers_policy_path": signers_policy_path,
        "target_policy": target_policy,
        "target_policy_path": target_policy_path,
        "target_policy_sha": target_policy_sha,
        "tmp_path": tmp_path,
    }


def _make_valid_receipt_v2_1(setup: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    diff_bytes = setup["diff_bytes"]
    diff_sha = setup["diff_sha"]
    receipt = {
        "abstention": {"abstained": False, "reason": ""},
        "base_sha": setup["base_sha"],
        "candidate_digest": setup["cand_digest"],
        "confidence": 1.0,
        "deterministic_verification_outcomes": {
            "prior_verification_digest": setup["prior_digest"],
            "prior_verification_verdict": "PASS",
            "scientific_evidence_verifications": {"status": "QUALIFIED"},
            "target_policy_path": "synthetic-target-policy.json",
            "target_policy_sha256": setup["target_policy_sha"],
        },
        "findings": [],
        "head_branch": "agent/synthetic-test",
        "head_sha": setup["head_sha"],
        "issued_at": "2026-10-23T12:00:00Z",
        "model_identity": {
            "backend": "LOCAL_LLAMA_CPP",
            "endpoint_url": "http://127.0.0.1:11434/v1",
            "loopback_only_verified": True,
            "model_name": "Qwen3-14B-NVFP4.gguf",
            "model_path": str(setup["model_file"]),
            "model_size_bytes": setup["model_file"].stat().st_size,
            "model_weights_sha256": setup["model_sha"],
            "runtime_binary_path": setup["reviewer_policy"]["model_identity"]["runtime_binary_path"],
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
        "receipt_id": "receipt-v2-1-valid",
        "release_authorized": True,
        "repository": "Miskatonic-System/msk-ruliology",
        "review_coverage_manifest": {
            "all_changed_files_accounted_for": True,
            "classification_counts": {"FULL_DIFF_REVIEWED": 1},
            "full_diff_aggregate_sha256": diff_sha,
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
                    "diff_sha256": diff_sha,
                    "findings_count": 0,
                    "finish_reason": "stop",
                    "paths": ["code.py"],
                    "slice_id": "slice_0001",
                    "slice_start_byte": 0,
                    "slice_end_byte": diff_bytes,
                    "slice_status": "PASS",
                    "uncertainty_level": "LOW",
                }
            ],
            "total_changed_files": 1,
        },
        "review_packet_digest": "c" * 64,
        "review_packet_manifest_digest": "c" * 64,
        "reviewer_implementation_digest": "d" * 64,
        "reviewer_policy_version": "2.1.0",
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
# 19 HOSTILE ADVERSARIAL CONTROLS (§11)
# =============================================================================

def test_control_01_confidence_100_rejected(test_setup_v2_1):
    """Control 1: Confidence = 100 must fail closed (schema interval [0,1])."""
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1, confidence=100)
    rf = test_setup_v2_1["tmp_path"] / "r_conf100.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(test_setup_v2_1["target_policy_path"]),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "LOCAL_REVIEW_SCHEMA_INVALID"


def test_control_02_missing_target_policy(test_setup_v2_1):
    """Control 2: Missing target policy file must fail closed."""
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1)
    rf = test_setup_v2_1["tmp_path"] / "r_missing_tp.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(test_setup_v2_1["tmp_path"] / "nonexistent-target-policy.json"),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "TARGET_POLICY_FILE_MISSING"


def test_control_03_forged_target_policy_digest(test_setup_v2_1):
    """Control 3: Forged target-policy digest in receipt must fail closed."""
    outcomes = copy.deepcopy(_make_valid_receipt_v2_1(test_setup_v2_1)["deterministic_verification_outcomes"])
    outcomes["target_policy_sha256"] = "f" * 64
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1, deterministic_verification_outcomes=outcomes)
    rf = test_setup_v2_1["tmp_path"] / "r_forged_tp_sha.json"
    write_json(rf, receipt)

    with patch("miskatonic_review_authority.local_review.run_scientific_prior_verification") as mock_prior:
        mock_prior.return_value = {"verdict": "PASS"}
        with pytest.raises(AuthorityError) as exc_info:
            verify_and_admit_local_review_receipt(
                receipt_path=rf,
                repository="Miskatonic-System/msk-ruliology",
                expected_pr_number=999,
                expected_head_sha=test_setup_v2_1["head_sha"],
                expected_base_sha=test_setup_v2_1["base_sha"],
                target_repo_path=str(test_setup_v2_1["repo"]),
                target_policy_path=str(test_setup_v2_1["target_policy_path"]),
                trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
                trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
                trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
            )
    assert exc_info.value.code == "FORGED_TARGET_POLICY_DIGEST"


def test_control_04_wrong_pr_target(test_setup_v2_1):
    """Control 4: Wrong PR target in target policy must fail closed."""
    wrong_tp = copy.deepcopy(test_setup_v2_1["target_policy"])
    wrong_tp["expected_pr_number"] = 123  # Candidate is 999
    wrong_tp_path = test_setup_v2_1["tmp_path"] / "wrong_tp.json"
    write_json(wrong_tp_path, wrong_tp)

    receipt = _make_valid_receipt_v2_1(test_setup_v2_1)
    rf = test_setup_v2_1["tmp_path"] / "r_wrong_pr.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(wrong_tp_path),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "TARGET_POLICY_PR_MISMATCH"


def test_control_05_incorrect_prior_verification_claim(test_setup_v2_1):
    """Control 5: Incorrect prior-verification claim in receipt must fail closed."""
    outcomes = copy.deepcopy(_make_valid_receipt_v2_1(test_setup_v2_1)["deterministic_verification_outcomes"])
    outcomes["prior_verification_digest"] = "e" * 64
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1, deterministic_verification_outcomes=outcomes)
    rf = test_setup_v2_1["tmp_path"] / "r_bad_prior.json"
    write_json(rf, receipt)

    with patch("miskatonic_review_authority.local_review.run_scientific_prior_verification") as mock_prior:
        mock_prior.return_value = {"verdict": "PASS", "reproduced": True}
        with pytest.raises(AuthorityError) as exc_info:
            verify_and_admit_local_review_receipt(
                receipt_path=rf,
                repository="Miskatonic-System/msk-ruliology",
                expected_pr_number=999,
                expected_head_sha=test_setup_v2_1["head_sha"],
                expected_base_sha=test_setup_v2_1["base_sha"],
                target_repo_path=str(test_setup_v2_1["repo"]),
                target_policy_path=str(test_setup_v2_1["target_policy_path"]),
                trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
                trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
                trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
            )
    assert exc_info.value.code == "INCORRECT_PRIOR_VERIFICATION"


def test_control_06_missing_required_scientific_evidence(test_setup_v2_1):
    """Control 6: Missing required scientific evidence in candidate repo must fail closed."""
    strict_tp = copy.deepcopy(test_setup_v2_1["target_policy"])
    strict_tp["required_evidence_files"] = ["nonexistent_results.json"]
    strict_tp_path = test_setup_v2_1["tmp_path"] / "strict_tp.json"
    write_json(strict_tp_path, strict_tp)

    outcomes = copy.deepcopy(_make_valid_receipt_v2_1(test_setup_v2_1)["deterministic_verification_outcomes"])
    outcomes["target_policy_sha256"] = sha256_bytes(canonical_json_bytes(strict_tp))
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1, deterministic_verification_outcomes=outcomes)
    rf = test_setup_v2_1["tmp_path"] / "r_missing_ev.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(strict_tp_path),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "REQUIRED_EVIDENCE_FILE_MISSING"


def test_control_07_omitted_diff_file(test_setup_v2_1):
    """Control 7: Omitted diff file in review coverage must fail closed."""
    cov = copy.deepcopy(_make_valid_receipt_v2_1(test_setup_v2_1)["review_coverage_manifest"])
    cov["full_diff_files_reviewed"] = 0
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1, review_coverage_manifest=cov)
    rf = test_setup_v2_1["tmp_path"] / "r_omitted_file.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(test_setup_v2_1["target_policy_path"]),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "TRUNCATED_EVIDENCE"


def test_control_08_skipped_diff_slice(test_setup_v2_1):
    """Control 8: Skipped diff slice in coverage manifest must fail closed."""
    cov = copy.deepcopy(_make_valid_receipt_v2_1(test_setup_v2_1)["review_coverage_manifest"])
    cov["slices"] = []  # Empty slices list
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1, review_coverage_manifest=cov)
    rf = test_setup_v2_1["tmp_path"] / "r_skipped_slice.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(test_setup_v2_1["target_policy_path"]),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "DIFF_COVERAGE_INCOMPLETE"


def test_control_09_fabricated_reviewed_byte_count(test_setup_v2_1):
    """Control 9: Fabricated reviewed-byte count in manifest must fail closed."""
    cov = copy.deepcopy(_make_valid_receipt_v2_1(test_setup_v2_1)["review_coverage_manifest"])
    cov["full_diff_bytes_reviewed"] = cov["full_diff_bytes_total"] + 500  # Fabricated
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1, review_coverage_manifest=cov)
    rf = test_setup_v2_1["tmp_path"] / "r_fab_bytes.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(test_setup_v2_1["target_policy_path"]),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "TRUNCATED_EVIDENCE"


def test_control_10_invalid_diff_aggregate_digest(test_setup_v2_1):
    """Control 10: Invalid diff aggregate digest in coverage manifest must fail closed."""
    cov = copy.deepcopy(_make_valid_receipt_v2_1(test_setup_v2_1)["review_coverage_manifest"])
    cov["full_diff_aggregate_sha256"] = "9" * 64  # Corrupted
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1, review_coverage_manifest=cov)
    rf = test_setup_v2_1["tmp_path"] / "r_bad_diff_sha.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(test_setup_v2_1["target_policy_path"]),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "INVALID_DIFF_AGGREGATE_DIGEST"


def test_control_11_p1_suppressed_during_synthesis(test_setup_v2_1):
    """Control 11: P1 finding present in review slice but omitted from synthesis must fail closed."""
    backend = LocalLlamaCppBackend()
    backend._verify_model_identity = MagicMock()

    # Mock call_llama to simulate slice returning P1, and synthesis omitting it with APPROVE
    slice_resp = {
        "slice_id": "slice_0001",
        "reviewed_paths": ["code.py"],
        "slice_status": "CONCERN",
        "findings": [
            {
                "severity": "P1",
                "title": "Critical custody leak",
                "details": "Mutable custody leak in candidate",
                "path": "code.py",
            }
        ],
        "uncertainty_level": "LOW",
        "uncertainty_notes": "",
        "abstained": False,
        "abstention_reason": "",
        "summary": "Slice identified P1 issue",
    }
    synth_resp = {
        "verdict": "APPROVE",
        "release_authorized": True,
        "summary": "Synthesized APPROVE ignoring P1",
        "findings": [],  # Omitted P1!
        "confidence": 1.0,
        "uncertainty": {"level": "LOW", "explicit_uncertainties": [], "residual_risks": []},
        "abstention": {"abstained": False, "reason": ""},
        "scientific_verification_assessment": {
            "prior_verification_accepted": True,
            "negative_findings_preserved": True,
            "notes": "",
        },
    }

    call_count = 0
    def mock_call(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        metrics = {
            "prompt_tokens": 10,
            "completion_tokens": 10,
            "total_tokens": 20,
            "finish_reason": "stop",
            "prompt_sha256": "0" * 64,
            "response_sha256": "1" * 64,
        }
        if call_count == 1:
            return slice_resp, metrics
        return synth_resp, metrics

    backend._call_llama_json_schema = mock_call

    packet = json.load(open(test_setup_v2_1["packet_path"]))
    prior = json.load(open(test_setup_v2_1["prior_path"]))
    prod = json.load(open(test_setup_v2_1["producers_policy_path"]))["bindings"][0]

    with pytest.raises(AuthorityError) as exc_info:
        backend.review(
            repository="Miskatonic-System/msk-ruliology",
            pr_number=999,
            base_sha=test_setup_v2_1["base_sha"],
            head_sha=test_setup_v2_1["head_sha"],
            candidate_digest=test_setup_v2_1["cand_digest"],
            review_packet=packet,
            prior_evidence=prior,
            producer_binding=prod,
            reviewer_policy=test_setup_v2_1["reviewer_policy"],
        )
    assert exc_info.value.code in ("LOCAL_REVIEW_FINDINGS_CONTRADICT_APPROVAL", "HIGH_SEVERITY_FINDING_SUPPRESSED")


def test_control_12_arbitrary_authoritative_check_name(test_setup_v2_1):
    """Control 12: Caller specifying arbitrary authoritative check name must fail closed."""
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1)
    rf = test_setup_v2_1["tmp_path"] / "r_arb_check.json"
    write_json(rf, receipt)

    args = argparse.Namespace(
        receipt=str(rf),
        detached_sig=None,
        repository="Miskatonic-System/msk-ruliology",
        pr_number=999,
        expected_head_sha=test_setup_v2_1["head_sha"],
        expected_base_sha=test_setup_v2_1["base_sha"],
        target_repo_path=str(test_setup_v2_1["repo"]),
        target_policy=str(test_setup_v2_1["target_policy_path"]),
        trusted_reviewers_policy=str(test_setup_v2_1["reviewer_policy_path"]),
        trusted_signers_policy=str(test_setup_v2_1["signers_policy_path"]),
        trusted_producers_policy=str(test_setup_v2_1["producers_policy_path"]),
        github_app_private_key=None,
        output_attestation=None,
        publish_check=True,
        also_publish_cloud_review=False,
        check_name="miskatonic/arbitrary-unauthorized-check",
        token_env="DUMMY_TOKEN_ENV",
        details_url=None,
    )
    os.environ["DUMMY_TOKEN_ENV"] = "fake-token"

    with patch("miskatonic_review_authority.local_review.run_scientific_prior_verification") as mock_prior:
        mock_prior.return_value = {"verdict": "PASS"}
        with pytest.raises(AuthorityError) as exc_info:
            _admit_local_review(args)
    assert exc_info.value.code == "ARBITRARY_CHECK_NAME_PROHIBITED"


def test_control_13_local_review_impersonating_cloud_review(test_setup_v2_1):
    """Control 13: Local review attempting to publish cloud review check must fail closed."""
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1)
    rf = test_setup_v2_1["tmp_path"] / "r_cloud_impersonation.json"
    write_json(rf, receipt)

    args = argparse.Namespace(
        receipt=str(rf),
        detached_sig=None,
        repository="Miskatonic-System/msk-ruliology",
        pr_number=999,
        expected_head_sha=test_setup_v2_1["head_sha"],
        expected_base_sha=test_setup_v2_1["base_sha"],
        target_repo_path=str(test_setup_v2_1["repo"]),
        target_policy=str(test_setup_v2_1["target_policy_path"]),
        trusted_reviewers_policy=str(test_setup_v2_1["reviewer_policy_path"]),
        trusted_signers_policy=str(test_setup_v2_1["signers_policy_path"]),
        trusted_producers_policy=str(test_setup_v2_1["producers_policy_path"]),
        github_app_private_key=None,
        output_attestation=None,
        publish_check=True,
        also_publish_cloud_review=False,
        check_name="miskatonic/independent-cloud-review",
        token_env="DUMMY_TOKEN_ENV",
        details_url=None,
    )
    os.environ["DUMMY_TOKEN_ENV"] = "fake-token"

    with patch("miskatonic_review_authority.local_review.run_scientific_prior_verification") as mock_prior:
        mock_prior.return_value = {"verdict": "PASS"}
        with pytest.raises(AuthorityError) as exc_info:
            _admit_local_review(args)
    assert exc_info.value.code == "LOCAL_REVIEW_IMPERSONATING_CLOUD_REVIEW"


def test_control_14_wrong_reviewer_identity(test_setup_v2_1):
    """Control 14: Wrong reviewer identity in receipt must fail closed."""
    id_info = copy.deepcopy(_make_valid_receipt_v2_1(test_setup_v2_1)["reviewer_service_identity"])
    id_info["reviewer_principal"] = "imposter-reviewer"
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1, reviewer_service_identity=id_info)
    rf = test_setup_v2_1["tmp_path"] / "r_bad_rev_id.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(test_setup_v2_1["target_policy_path"]),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "FORGED_REVIEWER_IDENTITY"


def test_control_15_wrong_model_weights_digest(test_setup_v2_1):
    """Control 15: Wrong model weights digest in receipt must fail closed."""
    model_override = copy.deepcopy(_make_valid_receipt_v2_1(test_setup_v2_1)["model_identity"])
    model_override["model_weights_sha256"] = "0" * 64
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1, model_identity=model_override)
    rf = test_setup_v2_1["tmp_path"] / "r_bad_model_weights.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(test_setup_v2_1["target_policy_path"]),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "FORGED_MODEL_IDENTITY"


def test_control_16_invalid_detached_signature(test_setup_v2_1):
    """Control 16: Invalid detached signature must fail closed."""
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1)
    rf = test_setup_v2_1["tmp_path"] / "r_bad_sig.json"
    write_json(rf, receipt)
    sig_f = rf.with_suffix(".sig")
    sig_f.write_bytes(b"\x00" * 256)  # Corrupted signature bytes

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            detached_sig_path=sig_f,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(test_setup_v2_1["target_policy_path"]),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "RECEIPT_SIGNATURE_INVALID"


def test_control_17_stale_candidate_head(test_setup_v2_1):
    """Control 17: Stale candidate HEAD in receipt must fail closed."""
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1, head_sha="1" * 40)
    rf = test_setup_v2_1["tmp_path"] / "r_stale_head.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(test_setup_v2_1["target_policy_path"]),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "STALE_REVIEW_HEAD"


def test_control_18_unauthorized_authoring_user_review(test_setup_v2_1):
    """Control 18: Review issued by unauthorized authoring user (kowen9024) must fail closed."""
    id_info = copy.deepcopy(_make_valid_receipt_v2_1(test_setup_v2_1)["reviewer_service_identity"])
    id_info["os_user"] = "kowen9024"
    id_info["os_uid"] = 1001
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1, reviewer_service_identity=id_info)
    rf = test_setup_v2_1["tmp_path"] / "r_unauth_user.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(test_setup_v2_1["target_policy_path"]),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "UNAUTHORIZED_AUTHORING_USER_REVIEW"


def test_control_19_tampered_signed_receipt(test_setup_v2_1):
    """Control 19: Tampered signed receipt bytes must fail closed."""
    receipt = _make_valid_receipt_v2_1(test_setup_v2_1)
    receipt["summary"] = "Tampered summary after signing"
    rf = test_setup_v2_1["tmp_path"] / "r_tampered.json"
    write_json(rf, receipt)

    with pytest.raises(AuthorityError) as exc_info:
        verify_and_admit_local_review_receipt(
            receipt_path=rf,
            repository="Miskatonic-System/msk-ruliology",
            expected_pr_number=999,
            expected_head_sha=test_setup_v2_1["head_sha"],
            expected_base_sha=test_setup_v2_1["base_sha"],
            target_repo_path=str(test_setup_v2_1["repo"]),
            target_policy_path=str(test_setup_v2_1["target_policy_path"]),
            trusted_reviewers_policy_path=str(test_setup_v2_1["reviewer_policy_path"]),
            trusted_signers_policy_path=str(test_setup_v2_1["signers_policy_path"]),
            trusted_producers_policy_path=str(test_setup_v2_1["producers_policy_path"]),
        )
    assert exc_info.value.code == "RECEIPT_PAYLOAD_TAMPERED"
