from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType

from .canonical_digest import candidate_digest, changed_records
from .root import verify_root_record
from .util import AuthorityError, read_json, run, sha256_file, write_json


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AuthorityError("PRIOR_VERIFIER_MODULE_LOAD_FAILED", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verify_candidate_manifest(target_path: str, policy: dict[str, object]) -> dict[str, object]:
    manifest_relative = str(policy.get("candidate_release_manifest", "provenance/release-manifest-v0.1.json"))
    manifest_path = Path(target_path, manifest_relative)
    if not manifest_path.is_file():
        raise AuthorityError("CANDIDATE_RELEASE_MANIFEST_MISSING")
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or not manifest:
        raise AuthorityError("CANDIDATE_RELEASE_MANIFEST_INVALID")
    excluded_fragments = tuple(policy.get("manifest_excluded_path_fragments", ["__pycache__", ".egg-info/"]))
    expected_paths: set[str] = set()
    for include_dir in policy.get("manifest_include_dirs", []):
        directory = Path(target_path, include_dir)
        if not directory.exists():
            continue
        for candidate in directory.rglob("*"):
            if not candidate.is_file():
                continue
            relative_path = candidate.relative_to(target_path).as_posix()
            if any(fragment in relative_path for fragment in excluded_fragments):
                continue
            expected_paths.add(relative_path)
    for include_file in policy.get("manifest_include_files", []):
        candidate = Path(target_path, include_file)
        if candidate.is_file():
            expected_paths.add(Path(include_file).as_posix())

    manifest_paths = set(manifest)
    missing_from_manifest = sorted(expected_paths - manifest_paths)
    unexpected_in_manifest = sorted(manifest_paths - expected_paths)
    if missing_from_manifest:
        raise AuthorityError("CANDIDATE_MANIFEST_ENTRY_MISSING", ",".join(missing_from_manifest))
    if unexpected_in_manifest:
        raise AuthorityError("CANDIDATE_MANIFEST_UNEXPECTED_ENTRY", ",".join(unexpected_in_manifest))

    verified = 0
    for relative_path, expected_hash in sorted(manifest.items()):
        if any(fragment in relative_path for fragment in excluded_fragments):
            raise AuthorityError("CANDIDATE_MANIFEST_CONTAINS_VOLATILE_PATH", relative_path)
        candidate = Path(target_path, relative_path)
        if not candidate.is_file() or sha256_file(candidate) != expected_hash:
            raise AuthorityError("CANDIDATE_RELEASE_FILE_HASH_MISMATCH", relative_path)
        verified += 1
    required_manifest_entries = set(policy.get("required_manifest_entries", []))
    missing = sorted(required_manifest_entries - set(manifest))
    if missing:
        raise AuthorityError("CANDIDATE_MANIFEST_REQUIRED_ENTRY_MISSING", ",".join(missing))
    return {
        "candidate_manifest_path": manifest_relative,
        "candidate_manifest_sha256": sha256_file(manifest_path),
        "candidate_manifest_verified_files": verified,
    }


def _verify_unchanged_paths(target_path: str, base_sha: str, head_sha: str, patterns: list[str]) -> None:
    records = changed_records(target_path, base_sha, head_sha)
    for record in records:
        for pattern in patterns:
            if re.search(pattern, record.path):
                raise AuthorityError("SEALED_PATH_CHANGED", record.path)


def run_prior_verification(
    *,
    repository: str,
    target_path: str,
    base_sha: str,
    head_sha: str,
    prior_control_path: str,
    root_record_path: str,
    policy_path: str,
    evidence_out: str,
) -> dict[str, object]:
    root_evidence = verify_root_record(root_record_path, prior_control_path)
    policy = read_json(policy_path)
    if policy.get("schema_version") != "prior-verification-policy-v1":
        raise AuthorityError("PRIOR_POLICY_SCHEMA_UNSUPPORTED")
    if policy.get("repository", "").lower() != repository.lower():
        raise AuthorityError("PRIOR_POLICY_REPOSITORY_MISMATCH")

    digest, digest_record = candidate_digest(repository, target_path, base_sha, head_sha)
    records = changed_records(target_path, base_sha, head_sha)
    if not records:
        raise AuthorityError("EMPTY_CANDIDATE_PATCH")

    prior_policy = _load_module(
        "miskatonic_prior_policy",
        Path(prior_control_path, "src/miskatonic_control/policy.py"),
    )
    prior_git_patch = _load_module(
        "miskatonic_prior_git_patch",
        Path(prior_control_path, "src/miskatonic_control/git_patch.py"),
    )

    manifest_policy = {
        "allowed_paths": policy["allowed_paths"],
        "forbidden_paths": policy.get("forbidden_paths", []),
        "sealed_paths": policy.get("sealed_paths", []),
    }
    role_policy = {
        "allowed_modify_patterns": policy["allowed_modify_patterns"],
        "forbidden_modify_patterns": policy.get("forbidden_modify_patterns", []),
    }
    baseline_policy = {
        "forbidden_modify_patterns": policy.get("baseline_forbidden_modify_patterns", []),
    }
    profile = {
        "project_specific_control_files": policy.get("project_specific_control_files", []),
        "sealed_namespaces": policy.get("sealed_namespaces", []),
    }

    path_results: list[dict[str, object]] = []
    for record in records:
        allowed, reason = prior_policy.verify_path_against_policies(
            record.path,
            manifest_policy,
            role_policy,
            baseline_policy,
            profile,
        )
        path_results.append({"allowed": bool(allowed), "path": record.path, "reason": reason})
        if not allowed:
            raise AuthorityError("PRIOR_POLICY_PATH_REJECTED", f"{record.path}: {reason}")

    prior_git_patch.check_modes_and_gitlinks(target_path, commit_ref=base_sha, cached=False)
    _verify_unchanged_paths(target_path, base_sha, head_sha, list(policy.get("required_unchanged_patterns", [])))
    manifest_evidence = _verify_candidate_manifest(target_path, policy)

    evidence = {
        "base_sha": base_sha,
        "candidate_digest": digest,
        "candidate_record": digest_record,
        "head_sha": head_sha,
        "path_results": path_results,
        "policy_version": policy["policy_version"],
        "prior_release": root_evidence,
        "repository": repository.lower(),
        "schema_version": "prior-verification-evidence-v1",
        "verdict": "PASS",
        **manifest_evidence,
    }
    write_json(evidence_out, evidence)
    return evidence
