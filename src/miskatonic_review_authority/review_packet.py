from __future__ import annotations

import json
from typing import Any

from .canonical_digest import changed_records
from .util import (
    AuthorityError,
    require_full_sha,
    run,
    validate_repository_name,
    write_json,
)


def _get_git_blob_size(target_path: str, blob_sha: str) -> int:
    if not blob_sha or blob_sha == "0" * 40:
        return 0
    try:
        output = (
            run(["git", "-C", target_path, "cat-file", "-s", blob_sha])
            .stdout.decode()
            .strip()
        )
        return int(output)
    except (ValueError, OSError, AuthorityError):
        return 0


def build_review_packet(
    *,
    repository: str,
    target_path: str,
    base_sha: str,
    head_sha: str,
    policy: dict[str, Any],
    prior_evidence: dict[str, Any],
    max_packet_characters: int = 500000,
    packet_out: str | None = None,
    manifest_out: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    repository = validate_repository_name(repository)
    require_full_sha(base_sha, field="base_sha")
    require_full_sha(head_sha, field="head_sha")

    records = changed_records(target_path, base_sha, head_sha)
    if not records:
        raise AuthorityError("EMPTY_CANDIDATE_PATCH")

    lfs_expected = dict(policy.get("lfs_expected_payloads", {}))
    lfs_lookup = {
        item["path"]: item for item in prior_evidence.get("lfs_verifications", [])
    }

    # Identify categories
    full_diff_paths: list[str] = []
    full_content_paths: list[str] = []
    hash_bound_paths: list[str] = []
    lfs_paths: list[str] = []

    # Manifest files list
    manifest_files: list[dict[str, Any]] = []

    # Priority rules for classification
    key_evidence_diff_files = set(
        policy.get(
            "key_evidence_diff_files",
            [
                "experiments/cra-high-inversion-holdout-05y/results/certification_envelope_r1_v0_1.json",
                "experiments/cra-high-inversion-holdout-05y/results/execution_result.json",
                "experiments/cra-high-inversion-holdout-05y/results/high_inversion_holdout_definition_v0_1.json",
                "experiments/cra-high-inversion-holdout-05y/results/hostile_controls_v0_1.json",
                "experiments/cra-high-inversion-holdout-05y/results/independent_member_parity_r1_v0_1.json",
                "experiments/cra-high-inversion-holdout-05y/results/independent_science_parity_r1_v0_1.json",
                "experiments/cra-high-inversion-holdout-05y/results/regression_v0_1.json",
                "experiments/cra-high-inversion-holdout-05y/results/review_authority_inputs_v0_2.json",
                "experiments/cra-high-inversion-holdout-05y/results/scientific_result_registry_r1_v0_1.json",
            ],
        )
    )

    for record in records:
        p = record.path
        classification: str

        if p in lfs_expected or p in lfs_lookup:
            classification = "LFS_PAYLOAD_IDENTITY_BOUND"
            lfs_paths.append(p)
        elif (
            p.endswith((".py", ".lean", ".md", ".wl", ".wls", ".wlt"))
            or p == ".gitattributes"
            or p.startswith("schemas/")
            or p in key_evidence_diff_files
        ):
            classification = "FULL_DIFF_REVIEWED"
            full_diff_paths.append(p)
        else:
            classification = "HASH_BOUND_GENERATED_ARTIFACT"
            hash_bound_paths.append(p)

        lfs_info = lfs_lookup.get(p)
        lfs_oid = lfs_info["lfs_oid"] if lfs_info else None
        scientific_payload = lfs_info["scientific_payload_digest"] if lfs_info else None
        size_bytes = (
            lfs_info["declared_size"]
            if lfs_info
            else _get_git_blob_size(target_path, record.new_oid)
        )

        manifest_files.append(
            {
                "classification": classification,
                "git_blob_sha": record.new_oid,
                "lfs_oid": lfs_oid,
                "path": p,
                "scientific_payload_digest": scientific_payload,
                "size_bytes": size_bytes,
                "status": record.status,
            }
        )

    # Completeness proof
    total_changed = len(records)
    total_classified = (
        len(full_diff_paths)
        + len(full_content_paths)
        + len(hash_bound_paths)
        + len(lfs_paths)
    )
    if total_classified != total_changed:
        raise AuthorityError(
            "REVIEW_PACKET_COMPLETENESS_FAILED",
            f"classified {total_classified} files != changed {total_changed} files",
        )

    # Build source code unified diff
    source_diff = ""
    if full_diff_paths:
        diff_cmd = [
            "git",
            "-C",
            target_path,
            "diff",
            "--no-ext-diff",
            "--binary",
            "--full-index",
            "--find-renames=0",
            base_sha,
            head_sha,
            "--",
        ] + full_diff_paths
        source_diff = run(diff_cmd).stdout.decode("utf-8", errors="replace")

    classification_counts = {
        "FULL_CONTENT_REVIEWED": len(full_content_paths),
        "FULL_DIFF_REVIEWED": len(full_diff_paths),
        "HASH_BOUND_GENERATED_ARTIFACT": len(hash_bound_paths),
        "LFS_PAYLOAD_IDENTITY_BOUND": len(lfs_paths),
    }

    completeness_proof = {
        "all_paths_accounted_for": True,
        "no_unclassified_paths": True,
        "total_changed": total_changed,
        "total_classified": total_classified,
    }

    manifest_record = {
        "base_sha": base_sha,
        "candidate_digest": prior_evidence["candidate_digest"],
        "classification_counts": classification_counts,
        "completeness_proof": completeness_proof,
        "files": manifest_files,
        "head_sha": head_sha,
        "repository": repository,
        "schema_version": "review-packet-manifest-v1",
        "total_changed_files": total_changed,
    }

    scientific_verifs = prior_evidence.get("scientific_evidence_verifications", {})
    scientific_summary = {
        "authorities": {
            "certification_snapshot_id": scientific_verifs.get(
                "certification_snapshot_id"
            ),
            "execution_ledger_digest": scientific_verifs.get("execution_ledger_digest"),
            "execution_result_digest": scientific_verifs.get("execution_result_digest"),
            "review_authority_input_digest": scientific_verifs.get(
                "review_authority_input_digest"
            ),
            "scientific_registry_id": scientific_verifs.get("scientific_registry_id"),
        },
        "classifications": {
            "permutation_invariance": scientific_verifs.get(
                "permutation_classification"
            ),
            "primary_generalization": scientific_verifs.get(
                "primary_generalization_classification"
            ),
            "residual_carrier": scientific_verifs.get(
                "residual_carrier_classification"
            ),
        },
        "frozen_corpus": {
            "frozen_sources": scientific_verifs.get("frozen_sources"),
            "frozen_tasks": scientific_verifs.get("frozen_tasks"),
            "member_occurrences": scientific_verifs.get("member_occurrences"),
            "observed_languages": scientific_verifs.get("observed_member_languages"),
        },
        "hostile_controls": {
            "passed": scientific_verifs.get("hostile_controls_passed"),
        },
        "parity_status": {
            "independent_member_parity": scientific_verifs.get(
                "independent_member_parity"
            ),
            "independent_science_parity": scientific_verifs.get(
                "independent_science_parity"
            ),
        },
        "regression": {
            "passed": scientific_verifs.get("regression_passed"),
        },
    }

    review_packet = {
        "base_sha": base_sha,
        "candidate_digest": prior_evidence["candidate_digest"],
        "changed_file_manifest": manifest_files,
        "classification_counts": classification_counts,
        "completeness_proof": completeness_proof,
        "head_sha": head_sha,
        "repository": repository,
        "schema_version": "scientific-review-packet-v1",
        "scientific_summary": scientific_summary,
        "source_diff": source_diff,
        "total_changed_files": total_changed,
    }

    packet_json_str = json.dumps(review_packet, sort_keys=True, ensure_ascii=False)
    total_characters = len(packet_json_str)

    if total_characters > max_packet_characters:
        raise AuthorityError(
            "SCIENTIFIC_REVIEW_PACKET_BUDGET_EXCEEDED",
            f"packet characters {total_characters} exceeds budget {max_packet_characters}",
        )

    if packet_out:
        write_json(packet_out, review_packet)
    if manifest_out:
        write_json(manifest_out, manifest_record)

    return review_packet, manifest_record
