from __future__ import annotations

from pathlib import Path

from .util import AuthorityError, read_json, require_full_sha, run, sha256_file, validate_repository_name


def verify_release_manifest(checkout: str, manifest_relative_path: str, expected_manifest_sha256: str) -> dict[str, object]:
    manifest_path = Path(checkout, manifest_relative_path)
    if not manifest_path.is_file():
        raise AuthorityError("PRIOR_RELEASE_MANIFEST_MISSING")
    actual_manifest_hash = sha256_file(manifest_path)
    if actual_manifest_hash != expected_manifest_sha256:
        raise AuthorityError("PRIOR_RELEASE_MANIFEST_HASH_MISMATCH")
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or not manifest:
        raise AuthorityError("PRIOR_RELEASE_MANIFEST_INVALID")
    verified_files = 0
    for relative_path, expected_hash in sorted(manifest.items()):
        candidate = Path(checkout, relative_path)
        if not candidate.is_file() or sha256_file(candidate) != expected_hash:
            raise AuthorityError("PRIOR_RELEASE_FILE_HASH_MISMATCH", relative_path)
        verified_files += 1
    return {
        "manifest_path": manifest_relative_path,
        "manifest_sha256": actual_manifest_hash,
        "verified_file_count": verified_files,
    }


def verify_root_record(root_record_path: str, prior_checkout: str) -> dict[str, object]:
    root = read_json(root_record_path)
    required = {
        "schema_version",
        "repository",
        "commit_sha",
        "release_manifest_path",
        "release_manifest_sha256",
        "designation",
        "ratified_by",
        "authority_repository",
    }
    if not isinstance(root, dict) or set(root) < required:
        raise AuthorityError("AUTHORITY_ROOT_INVALID")
    if root["schema_version"] != "authority-root-v1":
        raise AuthorityError("AUTHORITY_ROOT_SCHEMA_UNSUPPORTED")
    validate_repository_name(root["repository"])
    require_full_sha(root["commit_sha"], field="root.commit_sha")
    actual_head = run(["git", "-C", prior_checkout, "rev-parse", "HEAD"]).stdout.decode().strip()
    if actual_head != root["commit_sha"]:
        raise AuthorityError("PRIOR_RELEASE_COMMIT_MISMATCH")
    tree_sha = run(["git", "-C", prior_checkout, "rev-parse", "HEAD^{tree}"]).stdout.decode().strip()
    status = run(["git", "-C", prior_checkout, "status", "--porcelain=v1", "-z"]).stdout
    if status:
        raise AuthorityError("PRIOR_RELEASE_CHECKOUT_DIRTY")
    manifest_evidence = verify_release_manifest(
        prior_checkout,
        root["release_manifest_path"],
        root["release_manifest_sha256"],
    )
    return {
        "authority_root": root,
        "commit_sha": actual_head,
        "tree_sha": tree_sha,
        **manifest_evidence,
    }
