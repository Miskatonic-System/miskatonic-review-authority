from __future__ import annotations

import copy
import hashlib
import json
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
    _self_excluding_sha256,
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
REAL_RULIOLOGY_WORKTREE = Path(
    "/home/kowen9024/worktrees/ruliology-05y-independent-times"
)

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


def _build_synthetic_scientific_repo(
    root: Path,
) -> tuple[str, str, str, dict[str, Any]]:
    repo = root / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(repo),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(repo),
        check=True,
        capture_output=True,
    )
    (repo / ".gitattributes").write_text("*.json text\n")
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "base"], cwd=str(repo), check=True, capture_output=True
    )
    base_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=str(repo), text=True
    ).strip()

    exp = repo / "experiments/cra-high-inversion-holdout-05y"
    results = exp / "results"
    results.mkdir(parents=True, exist_ok=True)
    (exp / "common_05y.py").write_text("# code\n")
    (repo / ".gitattributes").write_text(
        "experiments/**/tasks*.json filter=lfs diff=lfs merge=lfs -text\n"
    )

    # LFS file
    lfs_payload = "a" * 64
    (results / "high_inversion_holdout_tasks_v0_1.json").write_text(
        f"version https://git-lfs.github.com/spec/v1\noid sha256:{lfs_payload}\nsize 100\n"
    )

    # Ledger
    ledger = results / "execution_ledger.jsonl"
    ledger.write_text(json.dumps({"attempt": 1}) + "\n")
    ledger_sha = hashlib.sha256(ledger.read_bytes()).hexdigest()

    # Result
    res = {
        "execution_ledger_digest": ledger_sha,
        "schema": "CRA05Y_EXECUTION_RESULT_V1",
    }
    res_digest = _self_excluding_sha256(res, "execution_result_digest")
    res["execution_result_digest"] = res_digest
    (results / "execution_result.json").write_text(json.dumps(res, indent=1) + "\n")

    # Manifest
    man = {
        "definition_id": "def1",
        "frozen_sources": 312,
        "frozen_tasks": 67603,
        "member_occurrences": 307137,
        "observed_member_languages": 30,
        "permutation_classification": "HIGH_INVERSION_OBSERVED_BLOCK_PERMUTATION_INVARIANCE_SUPPORTED",
        "primary_generalization_classification": "X3_HIGH_INVERSION_HOLDOUT_GENERALIZATION_REFUTED",
        "residual_carrier_classification": "CANONICAL_45_STATE_RESIDUAL_CARRIER_CONTAINS_HOLDOUT_LANGUAGES",
        "scientific_artifact_payload_sha256": {
            "high_inversion_holdout_tasks_v0_1.json": lfs_payload
        },
    }
    man_id = _self_excluding_sha256(man, "manifest_id")
    man["manifest_id"] = man_id
    (results / "scientific_measurement_manifest_r1_v0_1.json").write_text(
        json.dumps(man, indent=1) + "\n"
    )

    # Registry
    reg = {
        "canonical_scientific_authorities": {"canonical_05X_merge": base_commit},
        "definition_id": "def1",
        "scientific_artifact_payload_sha256": {
            "high_inversion_holdout_tasks_v0_1.json": lfs_payload
        },
        "scientific_measurement_manifest_id": man_id,
    }
    reg_id = _self_excluding_sha256(reg, "scientific_registry_id")
    reg["scientific_registry_id"] = reg_id
    (results / "scientific_result_registry_r1_v0_1.json").write_text(
        json.dumps(reg, indent=1) + "\n"
    )

    # Parity & controls & regression
    (results / "independent_member_parity_r1_v0_1.json").write_text(
        json.dumps({"member_count": 50113, "passed": True, "task_count": 67603}) + "\n"
    )
    (results / "independent_science_parity_r1_v0_1.json").write_text(
        json.dumps({"checks": {"c1": True}, "passed": True}) + "\n"
    )
    (results / "hostile_controls_v0_1.json").write_text(
        json.dumps(
            {"all_controls_passed": True, "controls_passed": 38, "total_controls": 38}
        )
        + "\n"
    )
    (results / "regression_v0_1.json").write_text(json.dumps({"passed": True}) + "\n")

    # Envelope
    env = {
        "custody": {
            "execution_ledger_digest": ledger_sha,
            "execution_result_digest": res_digest,
            "global_status": "QUALIFIED",
            "pull_request": PR_NUMBER,
        },
        "scientific_registry_id": reg_id,
        "verification_receipt_sha256": {
            "execution_result.json": hashlib.sha256(
                (results / "execution_result.json").read_bytes()
            ).hexdigest(),
        },
    }
    env_id = _self_excluding_sha256(env, "certification_envelope_id")
    env["certification_envelope_id"] = env_id
    (results / "certification_envelope_r1_v0_1.json").write_text(
        json.dumps(env, indent=1) + "\n"
    )

    # Inputs
    inp = {
        "canonical_base_sha": base_commit,
        "certification_snapshot_id": env_id,
        "execution_ledger_digest": ledger_sha,
        "execution_result_digest": res_digest,
        "repository": REPOSITORY,
        "scientific_registry_id": reg_id,
    }
    inp_digest = _self_excluding_sha256(inp, "inputs_digest")
    inp["inputs_digest"] = inp_digest
    (results / "review_authority_inputs_v0_2.json").write_text(
        json.dumps(inp, indent=1) + "\n"
    )

    subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "head"], cwd=str(repo), check=True, capture_output=True
    )
    head_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=str(repo), text=True
    ).strip()

    policy = {
        "allowed_modify_patterns": [
            "^(\\.gitattributes|experiments/cra-high-inversion-holdout-05y/.*)$"
        ],
        "allowed_paths": [
            ".gitattributes",
            "experiments/cra-high-inversion-holdout-05y/**",
        ],
        "evidence_base_path": "experiments/cra-high-inversion-holdout-05y/results",
        "expected_base_sha": base_commit,
        "expected_head_branch": HEAD_BRANCH,
        "expected_head_sha": head_commit,
        "expected_pr_number": PR_NUMBER,
        "forbidden_modify_patterns": [
            "(^|/)(credential|credentials|secret|secrets)(/|$)",
            "\\.(pem|key)$",
            "^\\.github/",
        ],
        "forbidden_paths": [".github/**", "credentials/**"],
        "lfs_expected_payloads": {
            "experiments/cra-high-inversion-holdout-05y/results/high_inversion_holdout_tasks_v0_1.json": lfs_payload
        },
        "pinned_evidence_digests": {
            "certification_snapshot_id": env_id,
            "execution_ledger_digest": ledger_sha,
            "execution_result_digest": res_digest,
            "review_authority_input_digest": inp_digest,
            "scientific_registry_id": reg_id,
        },
        "policy_version": "1.0.0",
        "repository": REPOSITORY,
        "required_evidence_files": [
            "review_authority_inputs_v0_2.json",
            "scientific_result_registry_r1_v0_1.json",
            "scientific_measurement_manifest_r1_v0_1.json",
            "certification_envelope_r1_v0_1.json",
            "execution_ledger.jsonl",
            "execution_result.json",
            "independent_member_parity_r1_v0_1.json",
            "independent_science_parity_r1_v0_1.json",
            "hostile_controls_v0_1.json",
            "regression_v0_1.json",
        ],
        "schema_version": "scientific-target-policy-v1",
    }
    return str(repo), base_commit, head_commit, policy


@pytest.fixture
def candidate_repo(tmp_path: Path) -> tuple[str, str, str, dict[str, Any]]:
    if REAL_RULIOLOGY_WORKTREE.is_dir():
        return (
            str(REAL_RULIOLOGY_WORKTREE),
            BASE_SHA,
            HEAD_SHA,
            read_json(PILOT_POLICY_PATH),
        )
    return _build_synthetic_scientific_repo(tmp_path)


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


def test_control_05_wrong_base_sha(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 05: Wrong base SHA must fail with CANDIDATE_BASE_SHA_MISMATCH."""
    repo_path, _, head_commit, policy = candidate_repo
    wrong_base = "0000000000000000000000000000000000000000"
    with tempfile.TemporaryDirectory() as tmp_dir:
        evidence_out = str(Path(tmp_dir) / "evidence.json")
        with pytest.raises(AuthorityError) as exc_info:
            run_scientific_prior_verification(
                repository=REPOSITORY,
                target_path=repo_path,
                base_sha=wrong_base,
                head_sha=head_commit,
                policy=policy,
                evidence_out=evidence_out,
            )
        assert exc_info.value.code == "CANDIDATE_BASE_SHA_MISMATCH"


def test_control_06_candidate_digest_mismatch(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 06: Prior evidence candidate digest mismatch must fail with PRIOR_VERIFICATION_DIGEST_STALE."""
    repo_path, base_commit, head_commit, _ = candidate_repo
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        private_key, _, key_id = _make_keypair(tmp_path)
        prior_file = tmp_path / "prior.json"
        write_json(
            prior_file,
            {
                "base_sha": base_commit,
                "candidate_digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "head_sha": head_commit,
                "schema_version": "prior-verification-evidence-v1",
                "verdict": "PASS",
            },
        )
        with pytest.raises(AuthorityError) as exc_info:
            run_review(
                repository=REPOSITORY,
                pr_number=PR_NUMBER,
                head_branch=HEAD_BRANCH,
                repo_path=repo_path,
                base_sha=base_commit,
                head_sha=head_commit,
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


def test_control_08_input_digest_mismatch(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 08: Input digest mismatch must fail with SCIENTIFIC_INPUTS_DIGEST_MISMATCH."""
    repo_path, base_commit, head_commit, policy = candidate_repo
    mutated_policy = copy.deepcopy(policy)
    mutated_policy["pinned_evidence_digests"]["review_authority_input_digest"] = (
        "0" * 64
    )
    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(AuthorityError) as exc_info:
            run_scientific_prior_verification(
                repository=REPOSITORY,
                target_path=repo_path,
                base_sha=base_commit,
                head_sha=head_commit,
                policy=mutated_policy,
                evidence_out=str(Path(tmp_dir) / "evidence.json"),
            )
        assert exc_info.value.code == "SCIENTIFIC_INPUTS_DIGEST_MISMATCH"


def test_control_09_scientific_registry_mismatch(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 09: Scientific registry mismatch must fail with SCIENTIFIC_REGISTRY_MISMATCH."""
    repo_path, base_commit, head_commit, policy = candidate_repo
    mutated_policy = copy.deepcopy(policy)
    mutated_policy["pinned_evidence_digests"]["scientific_registry_id"] = "0" * 64
    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(AuthorityError) as exc_info:
            run_scientific_prior_verification(
                repository=REPOSITORY,
                target_path=repo_path,
                base_sha=base_commit,
                head_sha=head_commit,
                policy=mutated_policy,
                evidence_out=str(Path(tmp_dir) / "evidence.json"),
            )
        assert exc_info.value.code == "SCIENTIFIC_REGISTRY_MISMATCH"


def test_control_10_certification_snapshot_mismatch(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 10: Certification snapshot mismatch must fail with CERTIFICATION_SNAPSHOT_MISMATCH."""
    repo_path, base_commit, head_commit, policy = candidate_repo
    mutated_policy = copy.deepcopy(policy)
    mutated_policy["pinned_evidence_digests"]["certification_snapshot_id"] = "0" * 64
    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(AuthorityError) as exc_info:
            run_scientific_prior_verification(
                repository=REPOSITORY,
                target_path=repo_path,
                base_sha=base_commit,
                head_sha=head_commit,
                policy=mutated_policy,
                evidence_out=str(Path(tmp_dir) / "evidence.json"),
            )
        assert exc_info.value.code == "CERTIFICATION_SNAPSHOT_MISMATCH"


def test_control_11_execution_ledger_mismatch(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 11: Execution ledger mismatch must fail with EXECUTION_LEDGER_DIGEST_MISMATCH."""
    repo_path, base_commit, head_commit, policy = candidate_repo
    mutated_policy = copy.deepcopy(policy)
    mutated_policy["pinned_evidence_digests"]["execution_ledger_digest"] = "0" * 64
    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(AuthorityError) as exc_info:
            run_scientific_prior_verification(
                repository=REPOSITORY,
                target_path=repo_path,
                base_sha=base_commit,
                head_sha=head_commit,
                policy=mutated_policy,
                evidence_out=str(Path(tmp_dir) / "evidence.json"),
            )
        assert exc_info.value.code == "EXECUTION_LEDGER_DIGEST_MISMATCH"


def test_control_12_execution_result_mismatch(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 12: Execution result mismatch must fail with EXECUTION_RESULT_DIGEST_MISMATCH."""
    repo_path, base_commit, head_commit, policy = candidate_repo
    mutated_policy = copy.deepcopy(policy)
    mutated_policy["pinned_evidence_digests"]["execution_result_digest"] = "0" * 64
    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(AuthorityError) as exc_info:
            run_scientific_prior_verification(
                repository=REPOSITORY,
                target_path=repo_path,
                base_sha=base_commit,
                head_sha=head_commit,
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


def test_control_14_generated_artifact_silently_omitted(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 14: Generated artifact omitted from packet manifest must fail completeness proof."""
    repo_path, base_commit, head_commit, policy = candidate_repo
    prior_evidence = run_scientific_prior_verification(
        repository=REPOSITORY,
        target_path=repo_path,
        base_sha=base_commit,
        head_sha=head_commit,
        policy=policy,
        evidence_out="/tmp/prior_ev_14.json",
    )
    with patch(
        "miskatonic_review_authority.review_packet.changed_records"
    ) as mock_records:
        real_records = candidate_digest(
            REPOSITORY, repo_path, base_commit, head_commit
        )[1]["records"]
        mock_records.return_value = [ChangeRecord(**r) for r in real_records]
        _packet, manifest = build_review_packet(
            repository=REPOSITORY,
            target_path=repo_path,
            base_sha=base_commit,
            head_sha=head_commit,
            policy=policy,
            prior_evidence=prior_evidence,
        )
        assert manifest["completeness_proof"]["all_paths_accounted_for"] is True
        assert manifest["completeness_proof"]["no_unclassified_paths"] is True
        assert (
            manifest["completeness_proof"]["total_changed"]
            == manifest["completeness_proof"]["total_classified"]
        )


def test_control_15_malformed_lfs_pointer(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 15: Malformed LFS pointer must fail with MALFORMED_LFS_POINTER."""
    repo_path, _, _, policy = candidate_repo
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
            verify_lfs_objects(repo_path, [fake_record], policy, {})
        assert exc_info.value.code == "MALFORMED_LFS_POINTER"


def test_control_16_lfs_oid_mismatch(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 16: LFS OID mismatch must fail with LFS_OID_PAYLOAD_MISMATCH."""
    repo_path, _, _, policy = candidate_repo
    fake_record = ChangeRecord(
        "100644",
        "100644",
        "0" * 40,
        "dummy_blob_oid",
        "M",
        "experiments/cra-high-inversion-holdout-05y/results/high_inversion_holdout_tasks_v0_1.json",
    )
    with patch("miskatonic_review_authority.scientific_verifier.run") as mock_run:
        mock_run.return_value.stdout = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
            b"size 12345\n"
        )
        with pytest.raises(AuthorityError) as exc_info:
            verify_lfs_objects(repo_path, [fake_record], policy, {})
        assert exc_info.value.code == "LFS_OID_PAYLOAD_MISMATCH"


def test_control_17_candidate_executable_not_invoked(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 17: Verifier must inspect candidate repo as data only, never execute candidate code."""
    repo_path, base_commit, head_commit, policy = candidate_repo
    real_subproc_run = subprocess.run
    executed_commands: list[list[str]] = []

    def spy_run(*args: Any, **kwargs: Any) -> Any:
        cmd = list(args[0]) if args else list(kwargs.get("args", []))
        executed_commands.append(cmd)
        return real_subproc_run(*args, **kwargs)

    with patch("subprocess.run", side_effect=spy_run):
        evidence = run_scientific_prior_verification(
            repository=REPOSITORY,
            target_path=repo_path,
            base_sha=base_commit,
            head_sha=head_commit,
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


def test_control_20_producer_reviewer_principal_collision(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 20: Producer and reviewer principal collision must fail with REVIEWER_PRODUCER_PRINCIPAL_COLLISION."""
    repo_path, base_commit, head_commit, _ = candidate_repo
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        private_key, _, key_id = _make_keypair(tmp_path)
        prior_file = tmp_path / "prior.json"
        digest = candidate_digest(REPOSITORY, repo_path, base_commit, head_commit)[0]
        write_json(
            prior_file,
            {
                "base_sha": base_commit,
                "candidate_digest": digest,
                "head_sha": head_commit,
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
                "reviewer_principal": "cloud-authoring-service:openai-chatgpt-connected-github",
                "schema_version": "reviewer-policy-v1",
            },
        )
        with pytest.raises(AuthorityError) as exc_info:
            run_review(
                repository=REPOSITORY,
                pr_number=PR_NUMBER,
                head_branch=HEAD_BRANCH,
                repo_path=repo_path,
                base_sha=base_commit,
                head_sha=head_commit,
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


def test_control_21_packet_nondeterministic_truncation(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 21: Packet builder must never truncate without failing closed."""
    repo_path, base_commit, head_commit, policy = candidate_repo
    prior_evidence = run_scientific_prior_verification(
        repository=REPOSITORY,
        target_path=repo_path,
        base_sha=base_commit,
        head_sha=head_commit,
        policy=policy,
        evidence_out="/tmp/prior_ev_21.json",
    )
    packet, manifest = build_review_packet(
        repository=REPOSITORY,
        target_path=repo_path,
        base_sha=base_commit,
        head_sha=head_commit,
        policy=policy,
        prior_evidence=prior_evidence,
        max_packet_characters=500000,
    )
    assert len(packet["changed_file_manifest"]) == manifest["total_changed_files"]
    assert (
        manifest["completeness_proof"]["total_classified"]
        == manifest["total_changed_files"]
    )


def test_control_22_review_packet_over_budget(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 22: Packet exceeding character budget must fail closed with SCIENTIFIC_REVIEW_PACKET_BUDGET_EXCEEDED."""
    repo_path, base_commit, head_commit, policy = candidate_repo
    prior_evidence = run_scientific_prior_verification(
        repository=REPOSITORY,
        target_path=repo_path,
        base_sha=base_commit,
        head_sha=head_commit,
        policy=policy,
        evidence_out="/tmp/prior_ev_22.json",
    )
    with pytest.raises(AuthorityError) as exc_info:
        build_review_packet(
            repository=REPOSITORY,
            target_path=repo_path,
            base_sha=base_commit,
            head_sha=head_commit,
            policy=policy,
            prior_evidence=prior_evidence,
            max_packet_characters=100,  # Tiny budget
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


def test_control_28_candidate_pr_prose_not_treated_as_authority(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    """Control 28: Verifier ignores PR prose and derives qualification solely from exact data bytes."""
    repo_path, base_commit, head_commit, policy = candidate_repo
    evidence = run_scientific_prior_verification(
        repository=REPOSITORY,
        target_path=repo_path,
        base_sha=base_commit,
        head_sha=head_commit,
        policy=policy,
        evidence_out="/tmp/prior_ev_28.json",
    )
    assert evidence["verdict"] == "PASS"
    assert len(evidence["candidate_digest"]) == 64


# =============================================================================
# END-TO-END PRIOR VERIFICATION & PACKET BUILDER TESTS
# =============================================================================


def test_scientific_target_prior_verification_flow(
    candidate_repo: tuple[str, str, str, dict[str, Any]],
) -> None:
    repo_path, base_commit, head_commit, policy = candidate_repo
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        evidence_path = tmp_path / "prior-release.json"
        packet_path = tmp_path / "review-packet.json"
        manifest_path = tmp_path / "review-packet-manifest.json"
        policy_file = tmp_path / "policy.json"
        write_json(policy_file, policy)

        evidence = run_prior_verification(
            repository=REPOSITORY,
            target_path=repo_path,
            base_sha=base_commit,
            head_sha=head_commit,
            policy_path=str(policy_file),
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
        assert manifest["total_changed_files"] > 0
        assert manifest["completeness_proof"]["all_paths_accounted_for"] is True
        assert manifest["completeness_proof"]["no_unclassified_paths"] is True


def test_envelope_receipt_lfs_pointer_matching(tmp_path: Path) -> None:
    """Envelope receipts that point to LFS pointers must be verified via their payload OID."""
    repo_path, base_commit, head_commit, policy = _build_synthetic_scientific_repo(
        tmp_path
    )
    results_dir = Path(repo_path) / "experiments/cra-high-inversion-holdout-05y/results"
    env_path = results_dir / "certification_envelope_r1_v0_1.json"
    env = read_json(env_path)

    # Write a simulated LFS pointer file for independent_member_reconstruction_r1_v0_1.json
    dummy_oid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    lfs_file = results_dir / "independent_member_reconstruction_r1_v0_1.json"
    lfs_file.write_text(
        f"version https://git-lfs.github.com/spec/v1\noid sha256:{dummy_oid}\nsize 1234\n"
    )

    # Set the expected receipt hash to the dummy_oid
    env["verification_receipt_sha256"]["independent_member_reconstruction_r1_v0_1.json"] = dummy_oid
    env["certification_envelope_id"] = _self_excluding_sha256(env, "certification_envelope_id")
    write_json(env_path, env)

    # Update inputs and policy with new env_id
    inputs_path = results_dir / "review_authority_inputs_v0_2.json"
    inputs = read_json(inputs_path)
    inputs["certification_snapshot_id"] = env["certification_envelope_id"]
    inputs["inputs_digest"] = _self_excluding_sha256(inputs, "inputs_digest")
    write_json(inputs_path, inputs)

    updated_policy = dict(policy)
    updated_policy["pinned_evidence_digests"] = dict(policy["pinned_evidence_digests"])
    updated_policy["pinned_evidence_digests"]["certification_snapshot_id"] = env["certification_envelope_id"]
    updated_policy["pinned_evidence_digests"]["review_authority_input_digest"] = inputs["inputs_digest"]

    # Should pass when OID matches
    verify_scientific_evidence(repo_path, updated_policy, base_commit, head_commit)

    # Should fail when OID mismatches
    env["verification_receipt_sha256"]["independent_member_reconstruction_r1_v0_1.json"] = "wrong" + "0" * 59
    env["certification_envelope_id"] = _self_excluding_sha256(env, "certification_envelope_id")
    write_json(env_path, env)
    inputs["certification_snapshot_id"] = env["certification_envelope_id"]
    inputs["inputs_digest"] = _self_excluding_sha256(inputs, "inputs_digest")
    write_json(inputs_path, inputs)
    updated_policy["pinned_evidence_digests"]["certification_snapshot_id"] = env["certification_envelope_id"]
    updated_policy["pinned_evidence_digests"]["review_authority_input_digest"] = inputs["inputs_digest"]

    with pytest.raises(AuthorityError) as exc_info:
        verify_scientific_evidence(repo_path, updated_policy, base_commit, head_commit)
    assert exc_info.value.code == "VERIFICATION_RECEIPT_MISMATCH"

