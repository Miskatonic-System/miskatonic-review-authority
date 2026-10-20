from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .canonical_digest import ChangeRecord, candidate_digest, changed_records
from .util import (
    AuthorityError,
    read_json,
    require_full_sha,
    run,
    sha256_bytes,
    sha256_file,
    validate_repository_name,
    write_json,
)

LFS_POINTER_REGEX = re.compile(
    r"^version https://git-lfs\.github\.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize (\d+)\n?$"
)


def _scientific_exact_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _self_excluding_sha256(data: dict[str, Any], id_key: str) -> str:
    body = {k: v for k, v in data.items() if k != id_key}
    return sha256_bytes(_scientific_exact_json_bytes(body))


def verify_path_scope(
    records: list[ChangeRecord], policy: dict[str, Any]
) -> list[dict[str, Any]]:
    allowed_patterns = [
        re.compile(p) for p in policy.get("allowed_modify_patterns", [])
    ]
    forbidden_patterns = [
        re.compile(p) for p in policy.get("forbidden_modify_patterns", [])
    ]

    path_results: list[dict[str, Any]] = []
    for record in records:
        path = record.path
        is_forbidden = any(pattern.search(path) for pattern in forbidden_patterns)
        is_allowed = any(pattern.search(path) for pattern in allowed_patterns)

        if is_forbidden or not is_allowed:
            reason = (
                "matched forbidden pattern"
                if is_forbidden
                else "did not match allowed patterns"
            )
            path_results.append({"allowed": False, "path": path, "reason": reason})
            raise AuthorityError("SCIENTIFIC_POLICY_PATH_REJECTED", f"{path}: {reason}")

        path_results.append(
            {"allowed": True, "path": path, "reason": "admitted by scientific policy"}
        )

    return path_results


def verify_lfs_objects(
    target_path: str,
    records: list[ChangeRecord],
    policy: dict[str, Any],
    payload_hashes: dict[str, str],
) -> list[dict[str, Any]]:
    lfs_expected = dict(policy.get("lfs_expected_payloads", {}))
    lfs_results: list[dict[str, Any]] = []

    for record in records:
        if record.new_oid == "0" * 40 or not record.new_oid:
            continue

        is_declared_lfs = record.path in lfs_expected

        # Read git object content directly from git repository
        try:
            blob_bytes = run(
                ["git", "-C", target_path, "cat-file", "-p", record.new_oid]
            ).stdout
        except (OSError, AuthorityError):
            blob_bytes = b""

        looks_like_lfs = blob_bytes.startswith(
            b"version https://git-lfs.github.com/spec/v1"
        )

        if is_declared_lfs or looks_like_lfs:
            file_content = blob_bytes.decode("utf-8", errors="replace")
            match = LFS_POINTER_REGEX.match(file_content)
            if not match:
                raise AuthorityError("MALFORMED_LFS_POINTER", record.path)

            oid = match.group(1)
            declared_size = int(match.group(2))

            expected_payload = (
                lfs_expected.get(record.path)
                or payload_hashes.get(record.path)
                or payload_hashes.get(Path(record.path).name)
            )

            if not expected_payload or oid != expected_payload:
                raise AuthorityError(
                    "LFS_OID_PAYLOAD_MISMATCH",
                    f"{record.path}: LFS oid {oid} != expected payload {expected_payload}",
                )

            lfs_results.append(
                {
                    "declared_size": declared_size,
                    "git_blob_sha": record.new_oid,
                    "lfs_oid": oid,
                    "parity_result": True,
                    "path": record.path,
                    "scientific_payload_digest": expected_payload,
                }
            )

    return lfs_results


def verify_scientific_evidence(
    target_path: str,
    policy: dict[str, Any],
    base_sha: str,
    head_sha: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    base_results = Path(
        target_path,
        policy.get(
            "evidence_base_path", "experiments/cra-high-inversion-holdout-05y/results"
        ),
    )
    if not base_results.is_dir():
        raise AuthorityError("SCIENTIFIC_EVIDENCE_DIRECTORY_MISSING", str(base_results))

    required_files = policy.get("required_evidence_files", [])
    for rf in required_files:
        if not (base_results / rf).is_file():
            raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", rf)

    pinned = policy.get("pinned_evidence_digests", {})
    expected_inp_digest = pinned.get("review_authority_input_digest")
    expected_reg_id = pinned.get("scientific_registry_id")
    expected_env_id = pinned.get("certification_snapshot_id")
    expected_ledger_digest = pinned.get("execution_ledger_digest")
    expected_result_digest = pinned.get("execution_result_digest")

    # 1. review_authority_inputs_v0_2.json
    inputs_file = base_results / "review_authority_inputs_v0_2.json"
    inputs = read_json(inputs_file)
    actual_inp_digest = _self_excluding_sha256(inputs, "inputs_digest")
    if (
        inputs.get("inputs_digest") != actual_inp_digest
        or actual_inp_digest != expected_inp_digest
    ):
        raise AuthorityError(
            "SCIENTIFIC_INPUTS_DIGEST_MISMATCH",
            f"expected {expected_inp_digest}, got {actual_inp_digest}",
        )

    if inputs.get("canonical_base_sha") != base_sha:
        raise AuthorityError(
            "CANDIDATE_BASE_SHA_MISMATCH",
            f"inputs base {inputs.get('canonical_base_sha')} != {base_sha}",
        )
    if inputs.get("scientific_registry_id") != expected_reg_id:
        raise AuthorityError(
            "SCIENTIFIC_REGISTRY_MISMATCH", "inputs registry id mismatch"
        )
    if inputs.get("certification_snapshot_id") != expected_env_id:
        raise AuthorityError(
            "CERTIFICATION_SNAPSHOT_MISMATCH", "inputs certification snapshot mismatch"
        )
    if inputs.get("execution_ledger_digest") != expected_ledger_digest:
        raise AuthorityError(
            "EXECUTION_LEDGER_DIGEST_MISMATCH", "inputs ledger digest mismatch"
        )
    if inputs.get("execution_result_digest") != expected_result_digest:
        raise AuthorityError(
            "EXECUTION_RESULT_DIGEST_MISMATCH", "inputs result digest mismatch"
        )

    # 2. scientific_result_registry_r1_v0_1.json
    reg_file = base_results / "scientific_result_registry_r1_v0_1.json"
    registry = read_json(reg_file)
    actual_reg_id = _self_excluding_sha256(registry, "scientific_registry_id")
    if (
        registry.get("scientific_registry_id") != actual_reg_id
        or actual_reg_id != expected_reg_id
    ):
        raise AuthorityError(
            "SCIENTIFIC_REGISTRY_MISMATCH",
            f"expected {expected_reg_id}, got {actual_reg_id}",
        )
    if (
        registry.get("canonical_scientific_authorities", {}).get("canonical_05X_merge")
        != base_sha
    ):
        raise AuthorityError(
            "CANDIDATE_BASE_SHA_MISMATCH", "registry canonical base mismatch"
        )

    # 3. execution_ledger.jsonl
    ledger_file = base_results / "execution_ledger.jsonl"
    actual_ledger_sha = sha256_file(ledger_file)
    if actual_ledger_sha != expected_ledger_digest:
        raise AuthorityError(
            "EXECUTION_LEDGER_DIGEST_MISMATCH",
            f"expected {expected_ledger_digest}, got {actual_ledger_sha}",
        )
    with open(ledger_file, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            if line.strip():
                try:
                    json.loads(line)
                except Exception as error:
                    raise AuthorityError(
                        "EXECUTION_LEDGER_MALFORMED", f"line {line_num}"
                    ) from error

    # 4. execution_result.json
    result_file = base_results / "execution_result.json"
    result = read_json(result_file)
    actual_result_digest = _self_excluding_sha256(result, "execution_result_digest")
    if (
        result.get("execution_result_digest") != actual_result_digest
        or actual_result_digest != expected_result_digest
    ):
        raise AuthorityError(
            "EXECUTION_RESULT_DIGEST_MISMATCH",
            f"expected {expected_result_digest}, got {actual_result_digest}",
        )
    if result.get("execution_ledger_digest") != actual_ledger_sha:
        raise AuthorityError(
            "EXECUTION_LEDGER_DIGEST_MISMATCH",
            "execution result ledger digest mismatch",
        )

    # 5. certification_envelope_r1_v0_1.json
    env_file = base_results / "certification_envelope_r1_v0_1.json"
    envelope = read_json(env_file)
    actual_env_id = _self_excluding_sha256(envelope, "certification_envelope_id")
    if (
        envelope.get("certification_envelope_id") != actual_env_id
        or actual_env_id != expected_env_id
    ):
        raise AuthorityError(
            "CERTIFICATION_SNAPSHOT_MISMATCH",
            f"expected {expected_env_id}, got {actual_env_id}",
        )
    if envelope.get("scientific_registry_id") != expected_reg_id:
        raise AuthorityError(
            "SCIENTIFIC_REGISTRY_MISMATCH", "envelope registry id mismatch"
        )
    custody = envelope.get("custody", {})
    if custody.get("execution_ledger_digest") != expected_ledger_digest:
        raise AuthorityError(
            "EXECUTION_LEDGER_DIGEST_MISMATCH",
            "envelope custody ledger digest mismatch",
        )
    if custody.get("execution_result_digest") != expected_result_digest:
        raise AuthorityError(
            "EXECUTION_RESULT_DIGEST_MISMATCH",
            "envelope custody result digest mismatch",
        )
    if custody.get("global_status") != "QUALIFIED":
        raise AuthorityError(
            "CERTIFICATION_STATUS_NOT_QUALIFIED", str(custody.get("global_status"))
        )

    expected_pr = policy.get("expected_pr_number")
    if expected_pr is not None and custody.get("pull_request") != expected_pr:
        raise AuthorityError(
            "PR_NUMBER_MISMATCH",
            f"expected {expected_pr}, got {custody.get('pull_request')}",
        )

    # Verify receipts in envelope
    for receipt_fn, exp_h in envelope.get("verification_receipt_sha256", {}).items():
        receipt_path = base_results / receipt_fn
        if receipt_path.is_file():
            actual_receipt_h = sha256_file(receipt_path)
            if actual_receipt_h != exp_h:
                raise AuthorityError(
                    "VERIFICATION_RECEIPT_MISMATCH",
                    f"{receipt_fn}: expected {exp_h}, got {actual_receipt_h}",
                )

    # 6. scientific_measurement_manifest_r1_v0_1.json
    manifest_file = base_results / "scientific_measurement_manifest_r1_v0_1.json"
    manifest = read_json(manifest_file)
    actual_manifest_id = _self_excluding_sha256(manifest, "manifest_id")
    if manifest.get("manifest_id") != actual_manifest_id:
        raise AuthorityError(
            "MEASUREMENT_MANIFEST_ID_MISMATCH",
            f"expected {actual_manifest_id}, got {manifest.get('manifest_id')}",
        )
    if registry.get("scientific_measurement_manifest_id") != manifest.get(
        "manifest_id"
    ):
        raise AuthorityError(
            "MEASUREMENT_MANIFEST_ID_MISMATCH", "registry manifest id mismatch"
        )
    if registry.get("definition_id") != manifest.get("definition_id"):
        raise AuthorityError(
            "SCIENTIFIC_DEFINITION_MISMATCH", "registry definition id mismatch"
        )

    if manifest.get("frozen_sources") != 312:
        raise AuthorityError(
            "FROZEN_SOURCE_COUNT_MISMATCH", str(manifest.get("frozen_sources"))
        )
    if manifest.get("frozen_tasks") != 67603:
        raise AuthorityError(
            "FROZEN_TASK_COUNT_MISMATCH", str(manifest.get("frozen_tasks"))
        )
    if manifest.get("member_occurrences") != 307137:
        raise AuthorityError(
            "MEMBER_OCCURRENCE_COUNT_MISMATCH", str(manifest.get("member_occurrences"))
        )
    if manifest.get("observed_member_languages") != 30:
        raise AuthorityError(
            "MEMBER_LANGUAGE_COUNT_MISMATCH",
            str(manifest.get("observed_member_languages")),
        )

    if (
        manifest.get("primary_generalization_classification")
        != "X3_HIGH_INVERSION_HOLDOUT_GENERALIZATION_REFUTED"
    ):
        raise AuthorityError(
            "CLASSIFICATION_MISMATCH",
            "primary generalization classification unexpected",
        )
    if (
        manifest.get("residual_carrier_classification")
        != "CANONICAL_45_STATE_RESIDUAL_CARRIER_CONTAINS_HOLDOUT_LANGUAGES"
    ):
        raise AuthorityError(
            "CLASSIFICATION_MISMATCH", "residual carrier classification unexpected"
        )
    if (
        manifest.get("permutation_classification")
        != "HIGH_INVERSION_OBSERVED_BLOCK_PERMUTATION_INVARIANCE_SUPPORTED"
    ):
        raise AuthorityError(
            "CLASSIFICATION_MISMATCH", "permutation classification unexpected"
        )

    # 7. independent parity files
    mem_parity_file = base_results / "independent_member_parity_r1_v0_1.json"
    mem_parity = read_json(mem_parity_file)
    if (
        mem_parity.get("passed") is not True
        or mem_parity.get("task_count") != 67603
        or mem_parity.get("member_count") != 50113
    ):
        raise AuthorityError("INDEPENDENT_MEMBER_PARITY_FAILED")

    sci_parity_file = base_results / "independent_science_parity_r1_v0_1.json"
    sci_parity = read_json(sci_parity_file)
    if sci_parity.get("passed") is not True or not all(
        sci_parity.get("checks", {}).values()
    ):
        raise AuthorityError("INDEPENDENT_SCIENCE_PARITY_FAILED")

    # 8. hostile controls and regression
    controls_file = base_results / "hostile_controls_v0_1.json"
    controls = read_json(controls_file)
    if (
        controls.get("all_controls_passed") is not True
        or controls.get("controls_passed") != 38
    ):
        raise AuthorityError("HOSTILE_CONTROLS_FAILED")

    regression_file = base_results / "regression_v0_1.json"
    regression = read_json(regression_file)
    if regression.get("passed") is not True:
        raise AuthorityError("REGRESSION_FAILED")

    # Combine all artifact payload sha256 mappings
    payload_hashes: dict[str, str] = {}
    payload_hashes.update(manifest.get("scientific_artifact_payload_sha256", {}))
    payload_hashes.update(registry.get("scientific_artifact_payload_sha256", {}))
    payload_hashes.update(envelope.get("verification_receipt_sha256", {}))

    verified_summary = {
        "certification_snapshot_id": expected_env_id,
        "execution_ledger_digest": expected_ledger_digest,
        "execution_result_digest": expected_result_digest,
        "frozen_sources": 312,
        "frozen_tasks": 67603,
        "hostile_controls_passed": 38,
        "independent_member_parity": "PASSED",
        "independent_science_parity": "PASSED",
        "member_occurrences": 307137,
        "observed_member_languages": 30,
        "permutation_classification": "HIGH_INVERSION_OBSERVED_BLOCK_PERMUTATION_INVARIANCE_SUPPORTED",
        "primary_generalization_classification": "X3_HIGH_INVERSION_HOLDOUT_GENERALIZATION_REFUTED",
        "regression_passed": True,
        "residual_carrier_classification": "CANONICAL_45_STATE_RESIDUAL_CARRIER_CONTAINS_HOLDOUT_LANGUAGES",
        "review_authority_input_digest": expected_inp_digest,
        "scientific_registry_id": expected_reg_id,
    }

    return verified_summary, payload_hashes


def run_scientific_prior_verification(
    *,
    repository: str,
    target_path: str,
    base_sha: str,
    head_sha: str,
    policy: dict[str, Any],
    evidence_out: str,
) -> dict[str, Any]:
    repository = validate_repository_name(repository)
    require_full_sha(base_sha, field="base_sha")
    require_full_sha(head_sha, field="head_sha")

    if policy.get("repository", "").lower() != repository.lower():
        raise AuthorityError(
            "PRIOR_POLICY_REPOSITORY_MISMATCH",
            f"{policy.get('repository')} != {repository}",
        )

    expected_base = policy.get("expected_base_sha")
    if expected_base and expected_base != base_sha:
        raise AuthorityError(
            "CANDIDATE_BASE_SHA_MISMATCH", f"expected {expected_base}, got {base_sha}"
        )

    expected_head = policy.get("expected_head_sha")
    if expected_head and expected_head != head_sha:
        raise AuthorityError(
            "CANDIDATE_HEAD_SHA_MISMATCH", f"expected {expected_head}, got {head_sha}"
        )

    digest, digest_record = candidate_digest(
        repository, target_path, base_sha, head_sha
    )
    records = changed_records(target_path, base_sha, head_sha)
    if not records:
        raise AuthorityError("EMPTY_CANDIDATE_PATCH")

    path_results = verify_path_scope(records, policy)
    verified_summary, payload_hashes = verify_scientific_evidence(
        target_path, policy, base_sha, head_sha
    )
    lfs_results = verify_lfs_objects(target_path, records, policy, payload_hashes)

    evidence = {
        "base_sha": base_sha,
        "candidate_digest": digest,
        "candidate_record": digest_record,
        "head_sha": head_sha,
        "lfs_verifications": lfs_results,
        "path_results": path_results,
        "policy_version": policy["policy_version"],
        "repository": repository.lower(),
        "schema_version": "prior-verification-evidence-v1",
        "scientific_evidence_verifications": verified_summary,
        "target_policy_schema": policy.get("schema_version"),
        "verdict": "PASS",
    }

    write_json(evidence_out, evidence)
    return evidence
