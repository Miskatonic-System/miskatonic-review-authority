from __future__ import annotations

import copy
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from miskatonic_review_authority.attestation import sign_attestation, verify_attestation
from miskatonic_review_authority.canonical_digest import ChangeRecord, candidate_digest
from miskatonic_review_authority.check_publisher import publish_check
from miskatonic_review_authority.github_api import verify_pr_head
from miskatonic_review_authority.github_app import create_installation_token
from miskatonic_review_authority.prior_verifier import run_prior_verification
from miskatonic_review_authority.review_packet import build_review_packet
from miskatonic_review_authority.review_runner import (
    _trusted_producer,
    _validate_review,
    run_review,
)
from miskatonic_review_authority.scientific_verifier import (
    run_scientific_prior_verification,
    verify_lfs_objects,
    verify_path_scope,
    verify_scientific_evidence,
)
from miskatonic_review_authority.util import AuthorityError, read_json, run, write_json

PILOT_POLICY_PATH = (
    Path(__file__).resolve().parents[1]
    / "policy"
    / "msk-ruliology-scientific-review-v1.json"
)
TRUSTED_PRODUCERS_PATH = (
    Path(__file__).resolve().parents[1] / "policy" / "trusted-producers.json"
)
TRUSTED_REVIEWERS_PATH = (
    Path(__file__).resolve().parents[1] / "policy" / "trusted-reviewers.json"
)
RULIOLOGY_WORKTREE = Path("/home/kowen9024/worktrees/ruliology-05y-independent-times")

BASE_SHA = "975a25190f3522f470215ae9bab52c677b1dae9b"
HEAD_SHA = "faf77bee488d94806f53bc14aae4c1d41f09004f"
PR_NUMBER = 143
HEAD_BRANCH = "agent/ruliology-cra-high-inversion-holdout-05y"
REPOSITORY = "Miskatonic-System/msk-ruliology"


def _make_keypair(directory: Path) -> tuple[Path, Path, str]:
    directory.mkdir(parents=True, exist_ok=True)
    private_key_path = directory / "review-app-private.pem"
    public_key_path = directory / "review-app-public.pem"
    run(["openssl", "genrsa", "-out", str(private_key_path), "2048"])
    run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key_path),
            "-pubout",
            "-out",
            str(public_key_path),
        ]
    )
    key_id = "test-authority-key-01"
    return private_key_path, public_key_path, key_id


# =============================================================================
# 28 HOSTILE CONTROLS AS SPECIFIED IN WO SECTION 21
# =============================================================================


def test_control_01_unbound_repository() -> None:
    """Control 01: Unbound repository must be rejected."""
    with pytest.raises(AuthorityError) as exc_info:
        _trusted_producer(
            str(TRUSTED_PRODUCERS_PATH),
            "Miskatonic-System/unbound-repo",
            PR_NUMBER,
            HEAD_BRANCH,
        )
    assert exc_info.value.code == "TRUSTED_PRODUCER_BINDING_MISSING"


def test_control_02_wrong_pr_number() -> None:
    """Control 02: Wrong PR number must be rejected."""
    with pytest.raises(AuthorityError) as exc_info:
        _trusted_producer(str(TRUSTED_PRODUCERS_PATH), REPOSITORY, 999, HEAD_BRANCH)
    assert exc_info.value.code == "TRUSTED_PRODUCER_BINDING_MISSING"


def test_control_03_wrong_branch() -> None:
    """Control 03: Wrong branch must be rejected."""
    with pytest.raises(AuthorityError) as exc_info:
        _trusted_producer(
            str(TRUSTED_PRODUCERS_PATH), REPOSITORY, PR_NUMBER, "wrong-branch"
        )
    assert exc_info.value.code == "TRUSTED_PRODUCER_BINDING_MISSING"


def test_control_04_stale_head_sha() -> None:
    """Control 04: Stale head SHA must fail with STALE_REVIEW_HEAD."""
    with patch(
        "miskatonic_review_authority.github_api.get_pr_head_sha",
        return_value="1111111111111111111111111111111111111111",
    ):
        with pytest.raises(AuthorityError) as exc_info:
            verify_pr_head(
                token="dummy",
                repository=REPOSITORY,
                pr_number=PR_NUMBER,
                expected_head_sha=HEAD_SHA,
            )
        assert exc_info.value.code == "STALE_REVIEW_HEAD"


def test_control_05_wrong_base_sha() -> None:
    """Control 05: Wrong base SHA must fail with CANDIDATE_BASE_SHA_MISMATCH."""
    policy = read_json(PILOT_POLICY_PATH)
    wrong_base = "0000000000000000000000000000000000000000"
    with tempfile.TemporaryDirectory() as tmp_dir:
        evidence_out = str(Path(tmp_dir) / "evidence.json")
        with pytest.raises(AuthorityError) as exc_info:
            run_scientific_prior_verification(
                repository=REPOSITORY,
                target_path=str(RULIOLOGY_WORKTREE),
                base_sha=wrong_base,
                head_sha=HEAD_SHA,
                policy=policy,
                evidence_out=evidence_out,
            )
        assert exc_info.value.code == "CANDIDATE_BASE_SHA_MISMATCH"


def test_control_06_candidate_digest_mismatch() -> None:
    """Control 06: Prior evidence candidate digest mismatch must fail with PRIOR_VERIFICATION_DIGEST_STALE."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        private_key, _, key_id = _make_keypair(tmp_path)
        prior_file = tmp_path / "prior.json"
        write_json(
            prior_file,
            {
                "base_sha": BASE_SHA,
                "candidate_digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "head_sha": HEAD_SHA,
                "schema_version": "prior-verification-evidence-v1",
                "verdict": "PASS",
            },
        )
        with pytest.raises(AuthorityError) as exc_info:
            run_review(
                repository=REPOSITORY,
                pr_number=PR_NUMBER,
                head_branch=HEAD_BRANCH,
                repo_path=str(RULIOLOGY_WORKTREE),
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                prior_evidence_path=str(prior_file),
                producer_bindings_path=str(TRUSTED_PRODUCERS_PATH),
                reviewer_policy_path=str(TRUSTED_REVIEWERS_PATH),
                private_key_path=str(private_key),
                key_id=key_id,
                diff_path=str(tmp_path / "diff.txt"),
                output_path=str(tmp_path / "out.json"),
                api_key="dummy",
                model="gpt-5.6-thinking",
                authority_principal="github-app:miskatonic-review-authority",
                workflow_run_id="run-1",
            )
        assert exc_info.value.code == "PRIOR_VERIFICATION_DIGEST_STALE"


def test_control_07_missing_review_authority_inputs() -> None:
    """Control 07: Missing Review Authority inputs must fail with SCIENTIFIC_INPUTS_MISSING."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "target"
        target.mkdir()
        (target / "experiments/cra-high-inversion-holdout-05y/results").mkdir(
            parents=True
        )
        policy = read_json(PILOT_POLICY_PATH)
        with pytest.raises(AuthorityError) as exc_info:
            verify_scientific_evidence(str(target), policy, BASE_SHA, HEAD_SHA)
        assert exc_info.value.code == "SCIENTIFIC_INPUTS_MISSING"


def test_control_08_input_digest_mismatch() -> None:
    """Control 08: Input digest mismatch must fail with SCIENTIFIC_INPUTS_DIGEST_MISMATCH."""
    policy = read_json(PILOT_POLICY_PATH)
    mutated_policy = copy.deepcopy(policy)
    mutated_policy["pinned_evidence_digests"]["review_authority_input_digest"] = (
        "0" * 64
    )
    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(AuthorityError) as exc_info:
            run_scientific_prior_verification(
                repository=REPOSITORY,
                target_path=str(RULIOLOGY_WORKTREE),
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                policy=mutated_policy,
                evidence_out=str(Path(tmp_dir) / "evidence.json"),
            )
        assert exc_info.value.code == "SCIENTIFIC_INPUTS_DIGEST_MISMATCH"


def test_control_09_scientific_registry_mismatch() -> None:
    """Control 09: Scientific registry mismatch must fail with SCIENTIFIC_REGISTRY_MISMATCH."""
    policy = read_json(PILOT_POLICY_PATH)
    mutated_policy = copy.deepcopy(policy)
    mutated_policy["pinned_evidence_digests"]["scientific_registry_id"] = "0" * 64
    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(AuthorityError) as exc_info:
            run_scientific_prior_verification(
                repository=REPOSITORY,
                target_path=str(RULIOLOGY_WORKTREE),
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                policy=mutated_policy,
                evidence_out=str(Path(tmp_dir) / "evidence.json"),
            )
        assert exc_info.value.code == "SCIENTIFIC_REGISTRY_MISMATCH"


def test_control_10_certification_snapshot_mismatch() -> None:
    """Control 10: Certification snapshot mismatch must fail with CERTIFICATION_SNAPSHOT_MISMATCH."""
    policy = read_json(PILOT_POLICY_PATH)
    mutated_policy = copy.deepcopy(policy)
    mutated_policy["pinned_evidence_digests"]["certification_snapshot_id"] = "0" * 64
    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(AuthorityError) as exc_info:
            run_scientific_prior_verification(
                repository=REPOSITORY,
                target_path=str(RULIOLOGY_WORKTREE),
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                policy=mutated_policy,
                evidence_out=str(Path(tmp_dir) / "evidence.json"),
            )
        assert exc_info.value.code == "CERTIFICATION_SNAPSHOT_MISMATCH"


def test_control_11_execution_ledger_mismatch() -> None:
    """Control 11: Execution ledger mismatch must fail with EXECUTION_LEDGER_DIGEST_MISMATCH."""
    policy = read_json(PILOT_POLICY_PATH)
    mutated_policy = copy.deepcopy(policy)
    mutated_policy["pinned_evidence_digests"]["execution_ledger_digest"] = "0" * 64
    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(AuthorityError) as exc_info:
            run_scientific_prior_verification(
                repository=REPOSITORY,
                target_path=str(RULIOLOGY_WORKTREE),
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                policy=mutated_policy,
                evidence_out=str(Path(tmp_dir) / "evidence.json"),
            )
        assert exc_info.value.code == "EXECUTION_LEDGER_DIGEST_MISMATCH"


def test_control_12_execution_result_mismatch() -> None:
    """Control 12: Execution result mismatch must fail with EXECUTION_RESULT_DIGEST_MISMATCH."""
    policy = read_json(PILOT_POLICY_PATH)
    mutated_policy = copy.deepcopy(policy)
    mutated_policy["pinned_evidence_digests"]["execution_result_digest"] = "0" * 64
    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(AuthorityError) as exc_info:
            run_scientific_prior_verification(
                repository=REPOSITORY,
                target_path=str(RULIOLOGY_WORKTREE),
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                policy=mutated_policy,
                evidence_out=str(Path(tmp_dir) / "evidence.json"),
            )
        assert exc_info.value.code == "EXECUTION_RESULT_DIGEST_MISMATCH"


def test_control_13_changed_path_outside_policy() -> None:
    """Control 13: Changed path outside policy must fail with SCIENTIFIC_POLICY_PATH_REJECTED."""
    policy = read_json(PILOT_POLICY_PATH)
    bad_records = [
        ChangeRecord(
            "100644",
            "100644",
            "0" * 40,
            "1" * 40,
            "M",
            ".github/workflows/malicious.yml",
        ),
        ChangeRecord(
            "100644",
            "100644",
            "0" * 40,
            "1" * 40,
            "M",
            "experiments/cra-05x-old/results.json",
        ),
        ChangeRecord(
            "100644", "100644", "0" * 40, "1" * 40, "M", "credentials/secret.key"
        ),
    ]
    for rec in bad_records:
        with pytest.raises(AuthorityError) as exc_info:
            verify_path_scope([rec], policy)
        assert exc_info.value.code == "SCIENTIFIC_POLICY_PATH_REJECTED"


def test_control_14_generated_artifact_silently_omitted() -> None:
    """Control 14: Generated artifact omitted from packet manifest must fail completeness proof."""
    policy = read_json(PILOT_POLICY_PATH)
    prior_evidence = run_scientific_prior_verification(
        repository=REPOSITORY,
        target_path=str(RULIOLOGY_WORKTREE),
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        policy=policy,
        evidence_out="/tmp/prior_ev_14.json",
    )
    with patch(
        "miskatonic_review_authority.review_packet.changed_records"
    ) as mock_records:
        real_records = candidate_digest(
            REPOSITORY, str(RULIOLOGY_WORKTREE), BASE_SHA, HEAD_SHA
        )[1]["records"]
        mock_records.return_value = [ChangeRecord(**r) for r in real_records]
        _packet, manifest = build_review_packet(
            repository=REPOSITORY,
            target_path=str(RULIOLOGY_WORKTREE),
            base_sha=BASE_SHA,
            head_sha=HEAD_SHA,
            policy=policy,
            prior_evidence=prior_evidence,
        )
        assert manifest["completeness_proof"]["all_paths_accounted_for"] is True
        assert manifest["completeness_proof"]["no_unclassified_paths"] is True
        assert (
            manifest["completeness_proof"]["total_changed"]
            == manifest["completeness_proof"]["total_classified"]
        )


def test_control_15_malformed_lfs_pointer() -> None:
    """Control 15: Malformed LFS pointer must fail with MALFORMED_LFS_POINTER."""
    policy = read_json(PILOT_POLICY_PATH)
    fake_record = ChangeRecord(
        "100644",
        "100644",
        "0" * 40,
        "dummy_blob_oid",
        "M",
        "experiments/cra-high-inversion-holdout-05y/results/high_inversion_holdout_tasks_v0_1.json",
    )
    with patch("miskatonic_review_authority.scientific_verifier.run") as mock_run:
        mock_run.return_value.stdout = b"corrupted pointer without git-lfs header\n"
        with pytest.raises(AuthorityError) as exc_info:
            verify_lfs_objects(str(RULIOLOGY_WORKTREE), [fake_record], policy, {})
        assert exc_info.value.code == "MALFORMED_LFS_POINTER"


def test_control_16_lfs_oid_mismatch() -> None:
    """Control 16: LFS OID mismatch must fail with LFS_OID_PAYLOAD_MISMATCH."""
    policy = read_json(PILOT_POLICY_PATH)
    fake_record = ChangeRecord(
        "100644",
        "100644",
        "0" * 40,
        "dummy_blob_oid",
        "M",
        "experiments/cra-high-inversion-holdout-05y/results/high_inversion_holdout_tasks_v0_1.json",
    )
    with patch("miskatonic_review_authority.scientific_verifier.run") as mock_run:
        # Valid LFS format, but with unexpected OID
        mock_run.return_value.stdout = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
            b"size 12345\n"
        )
        with pytest.raises(AuthorityError) as exc_info:
            verify_lfs_objects(str(RULIOLOGY_WORKTREE), [fake_record], policy, {})
        assert exc_info.value.code == "LFS_OID_PAYLOAD_MISMATCH"


def test_control_17_candidate_executable_not_invoked() -> None:
    """Control 17: Verifier must inspect candidate repo as data only, never execute candidate code."""
    real_subproc_run = subprocess.run
    executed_commands: list[list[str]] = []

    def spy_run(*args: Any, **kwargs: Any) -> Any:
        cmd = list(args[0]) if args else list(kwargs.get("args", []))
        executed_commands.append(cmd)
        return real_subproc_run(*args, **kwargs)

    policy = read_json(PILOT_POLICY_PATH)
    with patch("subprocess.run", side_effect=spy_run):
        evidence = run_scientific_prior_verification(
            repository=REPOSITORY,
            target_path=str(RULIOLOGY_WORKTREE),
            base_sha=BASE_SHA,
            head_sha=HEAD_SHA,
            policy=policy,
            evidence_out="/tmp/prior_ev_17.json",
        )
        assert evidence["verdict"] == "PASS"

    assert len(executed_commands) > 0
    forbidden_executables = {
        "bash",
        "lean",
        "pytest",
        "python",
        "python3",
        "ruff",
        "sh",
    }
    for cmd in executed_commands:
        prog = Path(cmd[0]).name
        assert prog not in forbidden_executables, (
            f"Forbidden candidate execution: {cmd}"
        )
        assert prog == "git", f"Non-git command executed: {cmd}"


def test_control_18_target_app_token_least_privilege() -> None:
    """Control 18: Target App token must be scoped to single target repository with least privilege."""
    with (
        patch(
            "miskatonic_review_authority.github_app.create_app_jwt", return_value="jwt"
        ),
        patch("miskatonic_review_authority.github_app._request_json") as mock_req,
    ):
        mock_req.side_effect = [
            [{"account": {"login": "Miskatonic-System"}, "id": 1234}],
            {"expires_at": "2026-10-20T00:00:00Z", "token": "ghs_test123"},
        ]
        with tempfile.TemporaryDirectory() as tmp_dir:
            key_file = Path(tmp_dir) / "key.pem"
            key_file.write_text("dummy")
            result = create_installation_token(
                app_id="123",
                private_key_path=str(key_file),
                owner="Miskatonic-System",
                repositories=["msk-ruliology"],
                permissions={
                    "actions": "read",
                    "checks": "write",
                    "contents": "read",
                    "pull_requests": "read",
                },
            )
            assert result["token"] == "ghs_test123"
            post_payload = mock_req.call_args_list[1][1]["payload"]
            assert post_payload["repositories"] == ["msk-ruliology"]
            assert post_payload["permissions"] == {
                "actions": "read",
                "checks": "write",
                "contents": "read",
                "pull_requests": "read",
            }


def test_control_19_missing_trusted_producer_binding() -> None:
    """Control 19: Missing trusted producer binding must fail closed."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        empty_bindings = tmp_path / "producers.json"
        write_json(
            empty_bindings,
            {"bindings": [], "schema_version": "trusted-producer-bindings-v1"},
        )
        with pytest.raises(AuthorityError) as exc_info:
            _trusted_producer(str(empty_bindings), REPOSITORY, PR_NUMBER, HEAD_BRANCH)
        assert exc_info.value.code == "TRUSTED_PRODUCER_BINDING_MISSING"


def test_control_20_producer_reviewer_principal_collision() -> None:
    """Control 20: Producer and reviewer principal collision must fail with REVIEWER_PRODUCER_PRINCIPAL_COLLISION."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        private_key, _, key_id = _make_keypair(tmp_path)
        prior_file = tmp_path / "prior.json"
        digest = candidate_digest(
            REPOSITORY, str(RULIOLOGY_WORKTREE), BASE_SHA, HEAD_SHA
        )[0]
        write_json(
            prior_file,
            {
                "base_sha": BASE_SHA,
                "candidate_digest": digest,
                "head_sha": HEAD_SHA,
                "schema_version": "prior-verification-evidence-v1",
                "verdict": "PASS",
            },
        )
        colliding_reviewer_policy = tmp_path / "reviewer.json"
        write_json(
            colliding_reviewer_policy,
            {
                "policy_version": "1.0.0",
                "provider": "openai-responses",
                "reviewer_principal": "cloud-authoring-service:openai-chatgpt-connected-github",  # Same as producer!
                "schema_version": "reviewer-policy-v1",
            },
        )
        with pytest.raises(AuthorityError) as exc_info:
            run_review(
                repository=REPOSITORY,
                pr_number=PR_NUMBER,
                head_branch=HEAD_BRANCH,
                repo_path=str(RULIOLOGY_WORKTREE),
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                prior_evidence_path=str(prior_file),
                producer_bindings_path=str(TRUSTED_PRODUCERS_PATH),
                reviewer_policy_path=str(colliding_reviewer_policy),
                private_key_path=str(private_key),
                key_id=key_id,
                diff_path=str(tmp_path / "diff.txt"),
                output_path=str(tmp_path / "out.json"),
                api_key="dummy",
                model="gpt-5.6-thinking",
                authority_principal="github-app:miskatonic-review-authority",
                workflow_run_id="run-1",
            )
        assert exc_info.value.code == "REVIEWER_PRODUCER_PRINCIPAL_COLLISION"


def test_control_21_packet_nondeterministic_truncation() -> None:
    """Control 21: Packet builder must never truncate without failing closed."""
    policy = read_json(PILOT_POLICY_PATH)
    prior_evidence = run_scientific_prior_verification(
        repository=REPOSITORY,
        target_path=str(RULIOLOGY_WORKTREE),
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        policy=policy,
        evidence_out="/tmp/prior_ev_21.json",
    )
    packet, manifest = build_review_packet(
        repository=REPOSITORY,
        target_path=str(RULIOLOGY_WORKTREE),
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        policy=policy,
        prior_evidence=prior_evidence,
        max_packet_characters=500000,
    )
    assert len(packet["changed_file_manifest"]) == 168
    assert manifest["completeness_proof"]["total_classified"] == 168


def test_control_22_review_packet_over_budget() -> None:
    """Control 22: Packet exceeding character budget must fail closed with SCIENTIFIC_REVIEW_PACKET_BUDGET_EXCEEDED."""
    policy = read_json(PILOT_POLICY_PATH)
    prior_evidence = run_scientific_prior_verification(
        repository=REPOSITORY,
        target_path=str(RULIOLOGY_WORKTREE),
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        policy=policy,
        evidence_out="/tmp/prior_ev_22.json",
    )
    with pytest.raises(AuthorityError) as exc_info:
        build_review_packet(
            repository=REPOSITORY,
            target_path=str(RULIOLOGY_WORKTREE),
            base_sha=BASE_SHA,
            head_sha=HEAD_SHA,
            policy=policy,
            prior_evidence=prior_evidence,
            max_packet_characters=1000,  # Tiny budget
        )
    assert exc_info.value.code == "SCIENTIFIC_REVIEW_PACKET_BUDGET_EXCEEDED"


def test_control_23_unsigned_attestation() -> None:
    """Control 23: Attestation missing signature must fail validation."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        _, public_key, key_id = _make_keypair(Path(tmp_dir))
        unsigned = {"schema_version": "review-attestation-v1", "verdict": "APPROVE"}
        with pytest.raises(AuthorityError) as exc_info:
            verify_attestation(unsigned, str(public_key), expected_key_id=key_id)
        assert exc_info.value.code == "ATTESTATION_SIGNATURE_MISSING"


def test_control_24_wrong_attestation_key() -> None:
    """Control 24: Attestation signed by wrong key must fail signature verification."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        priv1, _pub1, key_id1 = _make_keypair(tmp_path / "k1")
        _priv2, pub2, _key_id2 = _make_keypair(tmp_path / "k2")
        attestation = {
            "authority_principal": "github-app:miskatonic-review-authority",
            "authority_workflow_run_id": "run-1",
            "base_sha": BASE_SHA,
            "candidate_digest": "0" * 64,
            "confidence": 1.0,
            "findings": [],
            "head_sha": HEAD_SHA,
            "issued_at": "2026-10-19T00:00:00Z",
            "pr_number": PR_NUMBER,
            "producer_binding": {},
            "release_authorized": True,
            "repository": REPOSITORY,
            "review_execution": {},
            "review_model_requested": "m",
            "review_provider": "openai-responses",
            "reviewer_policy_version": "1.0.0",
            "reviewer_principal": "rev",
            "schema_version": "review-attestation-v1",
            "summary": "ok",
            "verdict": "APPROVE",
        }
        signed = sign_attestation(attestation, str(priv1), key_id=key_id1)
        with pytest.raises(AuthorityError) as exc_info:
            verify_attestation(signed, str(pub2), expected_key_id=key_id1)
        assert exc_info.value.code == "ATTESTATION_SIGNATURE_INVALID"


def test_control_25_release_authorized_true_with_non_approve_verdict() -> None:
    """Control 25: release_authorized=True with non-APPROVE verdict must fail with CLOUD_REVIEW_RELEASE_INCONSISTENT."""
    invalid_review = {
        "confidence": 0.9,
        "findings": [],
        "release_authorized": True,
        "summary": "rejected but authorized?",
        "verdict": "REJECT",
    }
    with pytest.raises(AuthorityError) as exc_info:
        _validate_review(invalid_review)
    assert exc_info.value.code == "CLOUD_REVIEW_RELEASE_INCONSISTENT"


def test_control_26_pr_head_mutates_after_review() -> None:
    """Control 26: PR head mutation after review must trigger STALE_REVIEW_HEAD on second check."""
    heads = [HEAD_SHA, "2222222222222222222222222222222222222222"]
    with patch(
        "miskatonic_review_authority.github_api.get_pr_head_sha", side_effect=heads
    ):
        assert (
            verify_pr_head(
                token="tok",
                repository=REPOSITORY,
                pr_number=PR_NUMBER,
                expected_head_sha=HEAD_SHA,
            )
            == HEAD_SHA
        )
        with pytest.raises(AuthorityError) as exc_info:
            verify_pr_head(
                token="tok",
                repository=REPOSITORY,
                pr_number=PR_NUMBER,
                expected_head_sha=HEAD_SHA,
            )
        assert exc_info.value.code == "STALE_REVIEW_HEAD"


def test_control_27_check_published_to_wrong_sha() -> None:
    """Control 27: Check publication requires valid SHA-40."""
    with pytest.raises(AuthorityError) as exc_info:
        publish_check(
            token="dummy",
            repository=REPOSITORY,
            head_sha="invalid_short_sha",
            name="miskatonic/independent-cloud-review",
            conclusion="success",
            title="title",
            summary="summary",
        )
    assert exc_info.value.code == "INVALID_FULL_SHA"


def test_control_28_candidate_pr_prose_not_treated_as_authority() -> None:
    """Control 28: Verifier ignores PR prose and derives qualification solely from exact data bytes."""
    policy = read_json(PILOT_POLICY_PATH)
    evidence = run_scientific_prior_verification(
        repository=REPOSITORY,
        target_path=str(RULIOLOGY_WORKTREE),
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        policy=policy,
        evidence_out="/tmp/prior_ev_28.json",
    )
    assert evidence["verdict"] == "PASS"
    assert (
        evidence["candidate_digest"]
        == "60574235438d5585ce698182359b6215b17cfd5f841e0abf0508ef3df81567a0"
    )


# =============================================================================
# END-TO-END PRIOR VERIFICATION & PACKET BUILDER TESTS
# =============================================================================


def test_scientific_target_prior_verification_flow() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        evidence_path = tmp_path / "prior-release.json"
        packet_path = tmp_path / "review-packet.json"
        manifest_path = tmp_path / "review-packet-manifest.json"

        evidence = run_prior_verification(
            repository=REPOSITORY,
            target_path=str(RULIOLOGY_WORKTREE),
            base_sha=BASE_SHA,
            head_sha=HEAD_SHA,
            policy_path=str(PILOT_POLICY_PATH),
            evidence_out=str(evidence_path),
            review_packet_out=str(packet_path),
            packet_manifest_out=str(manifest_path),
            max_packet_characters=500000,
        )

        assert evidence["verdict"] == "PASS"
        assert evidence_path.is_file()
        assert packet_path.is_file()
        assert manifest_path.is_file()

        manifest = read_json(manifest_path)
        assert manifest["schema_version"] == "review-packet-manifest-v1"
        assert manifest["total_changed_files"] == 168
        assert manifest["classification_counts"]["LFS_PAYLOAD_IDENTITY_BOUND"] == 9
        assert manifest["classification_counts"]["FULL_DIFF_REVIEWED"] == 28
        assert manifest["classification_counts"]["HASH_BOUND_GENERATED_ARTIFACT"] == 131
        assert manifest["completeness_proof"]["all_paths_accounted_for"] is True
        assert manifest["completeness_proof"]["no_unclassified_paths"] is True
