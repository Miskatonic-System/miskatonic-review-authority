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
    profile = policy.get("verification_profile", "cra_05y")
    if profile == "causalis_b1_01a":
        return _verify_causalis_b1_evidence(target_path, policy, base_sha, head_sha)
    if profile == "causalis_b2":
        return _verify_causalis_b2_evidence(target_path, policy, base_sha, head_sha)
    if profile == "atlas_01a":
        return _verify_atlas_01a_evidence(target_path, policy, base_sha, head_sha)
    if profile == "cdl_00a":
        return _verify_cdl_00a_evidence(target_path, policy, base_sha, head_sha)

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
        if not receipt_path.is_file():
            raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", receipt_fn)
        content = receipt_path.read_text(encoding="utf-8", errors="replace")
        lfs_match = LFS_POINTER_REGEX.match(content)
        if lfs_match:
            actual_receipt_h = lfs_match.group(1)
        else:
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

    # Section 4: If extended CRA 05Y artifacts are present or explicitly requested, verify all 8 items
    x3_file = base_results / "x3_generalization_and_collision_cells_v0_1.json"
    if policy.get("require_extended_cra_05y_checks") or x3_file.is_file():
        sec4_results = _verify_cra_05y_section4_checks(
            base_results=base_results,
            target_path=target_path,
            base_sha=base_sha,
            head_sha=head_sha,
            manifest=manifest,
            registry=registry,
            envelope=envelope,
            inputs=inputs,
            ledger_file=ledger_file,
            result=result,
        )
        verified_summary["cra_05y_section4_verifications"] = sec4_results

    return verified_summary, payload_hashes


def _verify_cra_05y_section4_checks(
    *,
    base_results: Path,
    target_path: str,
    base_sha: str,
    head_sha: str,
    manifest: dict[str, Any],
    registry: dict[str, Any],
    envelope: dict[str, Any],
    inputs: dict[str, Any],
    ledger_file: Path,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Deterministically verifies the 8 explicit scientific items for CRA 05Y (Work Order Section 4)."""
    # 1. Exact frozen scientific population
    sources_file = base_results / "high_inversion_holdout_sources_v0_1.json"
    if not sources_file.is_file():
        raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", "high_inversion_holdout_sources_v0_1.json")
    sources_data = read_json(sources_file)
    if len(sources_data.get("sources", [])) != 312:
        raise AuthorityError("FROZEN_SOURCE_COUNT_MISMATCH", f"sources length {len(sources_data.get('sources', []))} != 312")
    if sources_data.get("source_manifest_id") != "52961ab0d8e98c1fa91773de5103a268c84067f332557e74633815ff4cd50106":
        raise AuthorityError("SOURCE_MANIFEST_ID_MISMATCH", str(sources_data.get("source_manifest_id")))

    manifest_recon_file = base_results / "independent_manifest_reconstruction_v0_1.json"
    if not manifest_recon_file.is_file():
        raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", "independent_manifest_reconstruction_v0_1.json")
    manifest_recon = read_json(manifest_recon_file)
    if (
        manifest_recon.get("passed") is not True
        or manifest_recon.get("source_manifest_id") != "52961ab0d8e98c1fa91773de5103a268c84067f332557e74633815ff4cd50106"
        or manifest_recon.get("task_manifest_id") != "a783466f56cdeb7b3dff57b8eb6b17f718ba7106428177910970c67283b06bad"
    ):
        raise AuthorityError("MANIFEST_RECONSTRUCTION_FAILED")

    # 2. Source and evidence identities
    def_file = base_results / "high_inversion_holdout_definition_v0_1.json"
    if not def_file.is_file():
        raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", "high_inversion_holdout_definition_v0_1.json")
    definition = read_json(def_file)
    if definition.get("definition_id") != "36a16f6456af41357e5bf598c5dcb2f94268d0ac463e95a758f36bedf1bfe78f":
        raise AuthorityError("SCIENTIFIC_DEFINITION_MISMATCH", "definition id mismatch")

    id_check_file = base_results / "identity_check_v0_1.json"
    if not id_check_file.is_file():
        raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", "identity_check_v0_1.json")
    id_check = read_json(id_check_file)
    if (
        id_check.get("passed") is not True
        or id_check.get("scientific_implementation_parity") is not True
        or id_check.get("verification_implementation_parity") is not True
    ):
        raise AuthorityError("IDENTITY_CHECK_FAILED")

    # Verify implementation file maps
    for rel_p, exp_hash in registry.get("primary_scientific_implementation", {}).get("file_map", {}).items():
        fp = Path(target_path, rel_p)
        if not fp.is_file() or sha256_file(fp) != exp_hash:
            raise AuthorityError("SCIENTIFIC_IMPLEMENTATION_HASH_MISMATCH", rel_p)

    for rel_p, exp_hash in registry.get("verification_implementation", {}).get("file_map", {}).items():
        fp = Path(target_path, rel_p)
        if not fp.is_file() or sha256_file(fp) != exp_hash:
            raise AuthorityError("VERIFICATION_IMPLEMENTATION_HASH_MISMATCH", rel_p)

    # 3. Chronological custody
    ledger_lines = [line.strip() for line in ledger_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(ledger_lines) != 20:
        raise AuthorityError("EXECUTION_LEDGER_SEQUENCE_INVALID", f"ledger line count {len(ledger_lines)} != 20")
    prev_end = ""
    member_idx = -1
    science_idx = -1
    for idx, raw_line in enumerate(ledger_lines, 1):
        row = json.loads(raw_line)
        exp_attempt = f"attempt_{idx:04d}"
        if row.get("attempt_id") != exp_attempt:
            raise AuthorityError("EXECUTION_LEDGER_SEQUENCE_INVALID", f"row {idx}: {row.get('attempt_id')} != {exp_attempt}")
        st = row.get("start_timestamp", "")
        et = row.get("end_timestamp", "")
        if not st or not et or st > et:
            raise AuthorityError("EXECUTION_LEDGER_CHRONOLOGY_INVALID", f"row {idx} timestamps: {st} > {et}")
        if prev_end and st < prev_end:
            raise AuthorityError("EXECUTION_LEDGER_CHRONOLOGY_INVALID", f"row {idx} overlapped previous attempt: {st} < {prev_end}")
        prev_end = et
        cmd = row.get("command", "")
        if "member_05y.py" in cmd:
            member_idx = idx
        if "science_05y.py" in cmd:
            science_idx = idx

    if definition.get("member_authority_sealed_before_languages") is not True:
        raise AuthorityError("MEMBER_AUTHORITY_SEAL_INVALID", "member authority was not sealed before languages")
    if member_idx < 0 or science_idx < 0 or member_idx >= science_idx:
        raise AuthorityError("CHRONOLOGICAL_CUSTODY_ORDER_VIOLATED", f"member_05y ({member_idx}) must precede science_05y ({science_idx})")

    # 4. Canonical membership reconstruction
    mem_parity = read_json(base_results / "independent_member_parity_r1_v0_1.json")
    if (
        mem_parity.get("passed") is not True
        or mem_parity.get("task_count") != 67603
        or mem_parity.get("member_count") != 50113
        or mem_parity.get("primary_member_authority_id") != "69e91561d64d086e98f2bf2e84d73e59463312c83cdb5f91c35749ad1ef9476e"
        or mem_parity.get("independent_member_authority_id") != "69e91561d64d086e98f2bf2e84d73e59463312c83cdb5f91c35749ad1ef9476e"
    ):
        raise AuthorityError("INDEPENDENT_MEMBER_RECONSTRUCTION_FAILED")

    # 5. X3 falsification witnesses
    x3_file = base_results / "x3_generalization_and_collision_cells_v0_1.json"
    if not x3_file.is_file():
        raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", "x3_generalization_and_collision_cells_v0_1.json")
    x3_data = read_json(x3_file)
    if (
        x3_data.get("classification") != "X3_HIGH_INVERSION_HOLDOUT_GENERALIZATION_REFUTED"
        or x3_data.get("complete_collision_cell_coverage") is not True
        or x3_data.get("x3_exact_heterogeneous_group_count") != 118
        or x3_data.get("hypothesis_updated") is not False
    ):
        raise AuthorityError("X3_FALSIFICATION_WITNESS_INVALID")

    # 6. G2 measured sufficiency
    suff_file = base_results / "holdout_statistic_sufficiency_v0_1.json"
    if not suff_file.is_file():
        raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", "holdout_statistic_sufficiency_v0_1.json")
    suff_data = read_json(suff_file)
    g2 = suff_data.get("G2", {})
    if (
        g2.get("classification") != "HOLDOUT_STATISTIC_LANGUAGE_SUFFICIENT"
        or g2.get("heterogeneous_groups") != 0
        or g2.get("contextual_groups") != 66872
        or g2.get("homogeneous_groups") != 66872
        or g2.get("maximum_languages_per_group") != 1
        or g2.get("partition_identity") != "b2e355ccf5c5830039726ea81fce16b147fbabbab78044b243337446e5339c8e"
    ):
        raise AuthorityError("G2_SUFFICIENCY_VERIFICATION_FAILED")
    g3 = suff_data.get("G3", {})
    if (
        g3.get("classification") != "HOLDOUT_STATISTIC_LANGUAGE_INSUFFICIENT"
        or g3.get("heterogeneous_groups") != 118
    ):
        raise AuthorityError("G3_INSUFFICIENCY_WITNESS_MISMATCH")

    # 7. Residual-language conservation
    res_carrier_file = base_results / "holdout_residual_carrier_relation_v0_1.json"
    if not res_carrier_file.is_file():
        raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", "holdout_residual_carrier_relation_v0_1.json")
    res_carrier = read_json(res_carrier_file)
    if (
        res_carrier.get("classification") != "CANONICAL_45_STATE_RESIDUAL_CARRIER_CONTAINS_HOLDOUT_LANGUAGES"
        or res_carrier.get("canonical_05V_mutated") is not False
        or res_carrier.get("canonical_carrier_states") != 45
        or res_carrier.get("canonical_root_reachable_states") != 43
        or res_carrier.get("holdout_language_count") != 30
        or res_carrier.get("new_observed_languages_count") != 0
        or res_carrier.get("union_derivative_closure_state_count") != 45
    ):
        raise AuthorityError("RESIDUAL_LANGUAGE_CONSERVATION_FAILED")

    # 8. Preservation of negative findings
    if definition.get("no_adaptation") is not True:
        raise AuthorityError("NEGATIVE_FINDINGS_NOT_PRESERVED", "no_adaptation is not True")
    if registry.get("implementation_separation", {}).get("primary_scientific_measurements_changed") is not False:
        raise AuthorityError("NEGATIVE_FINDINGS_NOT_PRESERVED", "primary measurements were modified")
    nonclaims = definition.get("nonclaims", [])
    if "DIAGNOSTIC_STATISTIC_SUCCESS != POST_HOC_CANONICAL_REPLACEMENT" not in nonclaims:
        raise AuthorityError("NEGATIVE_FINDINGS_NOT_PRESERVED", "nonclaims missing diagnostic replacement guard")
    if "HOLDOUT_REFUTATION != FAILURE_OF_CANONICAL_05X_RESULT" not in nonclaims:
        raise AuthorityError("NEGATIVE_FINDINGS_NOT_PRESERVED", "nonclaims missing holdout refutation guard")

    return {
        "canonical_membership_reconstruction": "QUALIFIED_EXACT",
        "chronological_custody": "QUALIFIED_STRICT_20_ATTEMPTS",
        "exact_frozen_scientific_population": "QUALIFIED_312_SOURCES_67603_TASKS",
        "g2_measured_sufficiency": "HOLDOUT_STATISTIC_LANGUAGE_SUFFICIENT_66872_GROUPS",
        "preservation_of_negative_findings": "QUALIFIED_X3_REFUTED_NO_ADAPTATION",
        "residual_language_conservation": "CANONICAL_45_STATE_CARRIER_CONSERVED",
        "source_and_evidence_identities": "QUALIFIED_EXACT_DIGESTS",
        "x3_falsification_witnesses": "118_EXACT_HETEROGENEOUS_WITNESSES",
    }


def _verify_causalis_b1_evidence(
    target_path: str,
    policy: dict[str, Any],
    base_sha: str,
    head_sha: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Deterministically verifies CAUSALIS B1 PR #144 evidence artifacts."""
    base_results = Path(target_path, policy.get("evidence_base_path", "artifacts/causalis-event-instance-parity-01a"))
    if not base_results.is_dir():
        raise AuthorityError("SCIENTIFIC_EVIDENCE_DIRECTORY_MISSING", str(base_results))

    r1_dir = base_results / "r1"
    manifest_file = r1_dir / "manifest.json"
    if not manifest_file.is_file():
        raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", "r1/manifest.json")
    manifest = read_json(manifest_file)
    for fname, finfo in manifest.get("files", {}).items():
        fp = r1_dir / fname
        if not fp.is_file():
            raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", f"r1/{fname}")
        if sha256_file(fp) != finfo.get("sha256"):
            raise AuthorityError("SCIENTIFIC_EVIDENCE_DIGEST_MISMATCH", f"r1/{fname}")

    receipt_file = r1_dir / "verification_receipt.json"
    receipt = read_json(receipt_file)
    if (
        receipt.get("parity_disposition") != "CAUSALIS_B1_EVENT_INSTANCE_PARITY_EXACT"
        or receipt.get("scientific_disposition") != "CAUSALIS_B1_INDEPENDENT_RAW_RECONSTRUCTION_QUALIFIED"
        or receipt.get("hostile_controls_passed") != "30/30"
        or receipt.get("primary_independent_parity") != "EXACT (56/56)"
    ):
        raise AuthorityError("CAUSALIS_PARITY_RECEIPT_INVALID")

    controls_file = r1_dir / "hostile_controls.json"
    controls = read_json(controls_file)
    if (
        controls.get("disposition") != "HOSTILE_CONTROLS_ALL_PASS"
        or controls.get("passed_count") != 30
        or controls.get("total_count") != 30
    ):
        raise AuthorityError("HOSTILE_CONTROLS_FAILED")

    recon_file = base_results / "cross_runtime_reconciliation.json"
    recon = read_json(recon_file)
    if (
        recon.get("canonical_starting_main") != base_sha
        or recon.get("scientific_disposition") != "CAUSALIS_B1_EVENT_INSTANCE_PARITY_EXACT"
        or recon.get("gates", {}).get("G13_hostile_controls") != "20/20"
    ):
        raise AuthorityError("RECONCILIATION_VERIFICATION_FAILED")

    payload_hashes: dict[str, str] = {
        fname: finfo["sha256"] for fname, finfo in manifest.get("files", {}).items()
    }
    verified_summary = {
        "arborescence_audits_passed": receipt.get("arborescence_audits_passed"),
        "hostile_controls_passed": 30,
        "parity_disposition": receipt.get("parity_disposition"),
        "primary_independent_parity": receipt.get("primary_independent_parity"),
        "scientific_disposition": receipt.get("scientific_disposition"),
        "total_evaluations": receipt.get("total_evaluations"),
    }
    return verified_summary, payload_hashes


def _verify_atlas_01a_evidence(
    target_path: str,
    policy: dict[str, Any],
    base_sha: str,
    head_sha: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Deterministically verifies ATLAS Rule-Disjoint Prediction PR #145 evidence artifacts."""
    base_results = Path(target_path, policy.get("evidence_base_path", "artifacts/atlas-rule-disjoint-prediction-01a"))
    if not base_results.is_dir():
        raise AuthorityError("SCIENTIFIC_EVIDENCE_DIRECTORY_MISSING", str(base_results))

    r1_dir = base_results / "r1"
    manifest_file = r1_dir / "manifest.json"
    if not manifest_file.is_file():
        raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", "r1/manifest.json")
    manifest = read_json(manifest_file)
    for art in manifest.get("artifacts", []):
        fp = r1_dir / art.get("file", "")
        if not fp.is_file():
            raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", f"r1/{art.get('file')}")
        if sha256_file(fp) != art.get("sha256"):
            raise AuthorityError("SCIENTIFIC_EVIDENCE_DIGEST_MISMATCH", f"r1/{art.get('file')}")

    primary_file = r1_dir / "primary_result.json"
    primary = read_json(primary_file)
    if (
        primary.get("disposition") != "R1_RULE_DISJOINT_ATLAS_PREDICTIVE_ASSOCIATION_NOT_SUPPORTED"
        or primary.get("association_test", {}).get("supported") is not False
        or primary.get("confusion_matrix", {}).get("total") != 86
    ):
        raise AuthorityError("ATLAS_PRIMARY_RESULT_INVALID")

    recon_file = r1_dir / "independent_reconstruction.json"
    recon = read_json(recon_file)
    if (
        recon.get("disposition") != "INDEPENDENT_RECONSTRUCTION_QUALIFIED"
        or recon.get("primary_correspondence_exact") is not True
        or recon.get("primary_evidence_divergence") != 0
    ):
        raise AuthorityError("ATLAS_RECONSTRUCTION_FAILED")

    controls_file = r1_dir / "hostile_controls.json"
    controls = read_json(controls_file)
    if (
        controls.get("disposition") != "ALL_HOSTILE_CONTROLS_PASS"
        or controls.get("passed_controls") != 40
        or controls.get("failed_controls") != 0
    ):
        raise AuthorityError("HOSTILE_CONTROLS_FAILED")

    parity_file = r1_dir / "cross_runtime_parity.json"
    parity = read_json(parity_file)
    if parity.get("disposition") != "CROSS_RUNTIME_PARITY_EXACT" or parity.get("parity_exact") is not True:
        raise AuthorityError("CROSS_RUNTIME_PARITY_FAILED")

    payload_hashes: dict[str, str] = {
        art["file"]: art["sha256"] for art in manifest.get("artifacts", [])
    }
    verified_summary = {
        "confusion_matrix": primary.get("confusion_matrix"),
        "cross_runtime_parity": "CROSS_RUNTIME_PARITY_EXACT",
        "disposition": primary.get("disposition"),
        "hostile_controls_passed": 40,
        "independent_reconstruction": "INDEPENDENT_RECONSTRUCTION_QUALIFIED",
        "p_value_rational": primary.get("association_test", {}).get("p_value_rational"),
    }
    return verified_summary, payload_hashes


def _verify_cdl_00a_evidence(
    target_path: str,
    policy: dict[str, Any],
    base_sha: str,
    head_sha: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Deterministically verifies CDL Finite Group Foundation PR #146 evidence artifacts."""
    base_results = Path(target_path, policy.get("evidence_base_path", "artifacts/cdl-finite-group-foundation-00a"))
    if not base_results.is_dir():
        raise AuthorityError("SCIENTIFIC_EVIDENCE_DIRECTORY_MISSING", str(base_results))

    manifest_file = base_results / "manifest.json"
    if not manifest_file.is_file():
        raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", "manifest.json")
    manifest = read_json(manifest_file)
    for art_name, art_info in manifest.get("artifacts", {}).items():
        fp = base_results / art_name
        if not fp.is_file():
            raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", art_name)
        if sha256_file(fp) != art_info.get("sha256"):
            raise AuthorityError("SCIENTIFIC_EVIDENCE_DIGEST_MISMATCH", art_name)

    receipt_file = base_results / "execution_receipt.json"
    receipt = read_json(receipt_file)
    if (
        receipt.get("canonical_base") != base_sha
        or "CDL_FINITE_GROUP_FOUNDATION_V0_1_R1_QUALIFIED" not in receipt.get("dispositions", [])
        or receipt.get("qualification_matrix", {}).get("R1-G12") != "34/34"
    ):
        raise AuthorityError("CDL_EXECUTION_RECEIPT_INVALID")

    recon_file = base_results / "independent_reconstruction.json"
    recon = read_json(recon_file)
    if (
        recon.get("status") != "EXACT_RECONSTRUCTION_VERIFIED"
        or recon.get("divergence_count") != 0
        or recon.get("v4_normality", {}).get("normal_in_s4") is not True
    ):
        raise AuthorityError("CDL_RECONSTRUCTION_FAILED")

    controls_file = base_results / "hostile_controls.json"
    controls = read_json(controls_file)
    if (
        controls.get("status") != "ALL_HOSTILE_CONTROLS_PASSED"
        or controls.get("count") != 34
        or len(controls.get("controls", {})) != 34
    ):
        raise AuthorityError("HOSTILE_CONTROLS_FAILED")

    payload_hashes: dict[str, str] = {
        name: info["sha256"] for name, info in manifest.get("artifacts", {}).items()
    }
    verified_summary = {
        "dispositions": receipt.get("dispositions"),
        "hostile_controls_passed": 34,
        "independent_reconstruction": "EXACT_RECONSTRUCTION_VERIFIED",
        "qualification_matrix_r1_g12": receipt.get("qualification_matrix", {}).get("R1-G12"),
    }
    return verified_summary, payload_hashes


def _verify_causalis_b2_evidence(
    target_path: str,
    policy: dict[str, Any],
    base_sha: str,
    head_sha: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Deterministically verifies CAUSALIS B2 Resource Causality PR #155 evidence artifacts."""
    base_results = Path(
        target_path,
        policy.get(
            "evidence_base_path", "artifacts/causalis-b2-resource-causality-00a"
        ),
    )
    if not base_results.is_dir():
        raise AuthorityError("SCIENTIFIC_EVIDENCE_DIRECTORY_MISSING", str(base_results))

    required_files = policy.get(
        "required_evidence_files",
        [
            "b2_scientific_definition.json",
            "b2_resource_lineage_semantics.md",
            "b2_commutation_theorem.md",
            "b2_direct_dependency_relations.json",
            "b2_causal_poset_results.json",
            "b2_overlap_conflict_witnesses.json",
            "b2_independent_reconstruction.json",
            "b2_wolfram_causal_surface_assessment.json",
            "b2_scientific_claim_authority.json",
            "b1_scientific_preservation.json",
        ],
    )
    for rf in required_files:
        fp = base_results / rf
        if not fp.is_file():
            raise AuthorityError("SCIENTIFIC_INPUTS_MISSING", rf)

    # 1. Scientific Definition & Base Alignment
    def_file = base_results / "b2_scientific_definition.json"
    definition = read_json(def_file)
    if definition.get("canonical_predecessor") != base_sha:
        raise AuthorityError(
            "CANDIDATE_BASE_SHA_MISMATCH",
            f"definition base {definition.get('canonical_predecessor')} != {base_sha}",
        )
    if (
        definition.get("retained_b1_authorities", {})
        .get("qualified_population", {})
        .get("total_evaluations")
        != 56
    ):
        raise AuthorityError("B1_QUALIFIED_POPULATION_MISMATCH")

    nonclaims = definition.get("permanent_nonclaims", [])
    if "EVENT ANCESTRY != CAUSAL DEPENDENCY" not in nonclaims:
        raise AuthorityError("PERMANENT_NONCLAIMS_MISSING_EVENT_ANCESTRY_GUARD")
    if "STATE RECONVERGENCE != CAUSAL INVARIANCE" not in nonclaims:
        raise AuthorityError("PERMANENT_NONCLAIMS_MISSING_STATE_RECONVERGENCE_GUARD")

    # 2. Scientific Claim Authority
    claim_file = base_results / "b2_scientific_claim_authority.json"
    claim_auth = read_json(claim_file)
    if (
        claim_auth.get("disposition")
        != "CAUSALIS_B2_RESOURCE_CAUSALITY_QUALIFIED"
        or claim_auth.get("total_fixtures_evaluated") != 56
    ):
        raise AuthorityError("CAUSALIS_B2_CLAIM_AUTHORITY_INVALID")

    measurements = claim_auth.get("aggregate_measurements", {})
    if (
        measurements.get("total_events_measured") != 9392
        or measurements.get("total_direct_edges_measured") != 10160
        or measurements.get("total_incomparable_pairs_measured") != 2486
        or measurements.get("total_conflict_witnesses") != 1443
    ):
        raise AuthorityError("CAUSALIS_B2_AGGREGATE_MEASUREMENTS_INVALID")

    # 3. Independent Reconstruction
    recon_file = base_results / "b2_independent_reconstruction.json"
    recon = read_json(recon_file)
    agg_recon = recon.get("aggregate_verification", {})
    if (
        recon.get("imports_b2_module") is not False
        or agg_recon.get("status") != "EXACT_INDEPENDENT_RECONSTRUCTION_VERIFIED"
        or agg_recon.get("verified_fixtures_count") != 56
        or agg_recon.get("total_histories_verified") != 1597
        or agg_recon.get("all_acyclic") is not True
        or agg_recon.get("all_edges_match") is not True
        or agg_recon.get("all_incomparables_match") is not True
    ):
        raise AuthorityError("CAUSALIS_B2_INDEPENDENT_RECONSTRUCTION_FAILED")

    # 4. B1 Preservation
    b1_file = base_results / "b1_scientific_preservation.json"
    b1_pres = read_json(b1_file)
    if (
        b1_pres.get("total_fixtures_verified") != 56
        or b1_pres.get("b1_records_immutable") is not True
    ):
        raise AuthorityError("B1_SCIENTIFIC_PRESERVATION_FAILED")

    # 5. Build payload hashes
    payload_hashes: dict[str, str] = {
        rf: sha256_file(base_results / rf) for rf in required_files
    }

    verified_summary = {
        "b1_preservation_verified": b1_pres.get("total_fixtures_verified"),
        "disposition": claim_auth.get("disposition"),
        "independent_reconstruction_status": agg_recon.get("status"),
        "total_conflict_witnesses": measurements.get("total_conflict_witnesses"),
        "total_direct_edges_measured": measurements.get("total_direct_edges_measured"),
        "total_events_measured": measurements.get("total_events_measured"),
        "total_fixtures_evaluated": claim_auth.get("total_fixtures_evaluated"),
        "total_incomparable_pairs_measured": measurements.get(
            "total_incomparable_pairs_measured"
        ),
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
