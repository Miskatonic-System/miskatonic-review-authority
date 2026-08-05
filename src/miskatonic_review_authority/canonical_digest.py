from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .util import AuthorityError, canonical_json_bytes, require_full_sha, run, sha256_bytes, validate_repository_name


@dataclass(frozen=True)
class ChangeRecord:
    old_mode: str
    new_mode: str
    old_oid: str
    new_oid: str
    status: str
    path: str

    def as_dict(self) -> dict[str, str]:
        return {
            "new_mode": self.new_mode,
            "new_oid": self.new_oid,
            "old_mode": self.old_mode,
            "old_oid": self.old_oid,
            "path": self.path,
            "status": self.status,
        }


def _validate_path(path: str) -> str:
    if not path or path.startswith("/") or "\x00" in path:
        raise AuthorityError("INVALID_CHANGED_PATH", path)
    parts = Path(path).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise AuthorityError("INVALID_CHANGED_PATH", path)
    return path


def changed_records(repo_path: str, base_sha: str, head_sha: str) -> list[ChangeRecord]:
    require_full_sha(base_sha, field="base_sha")
    require_full_sha(head_sha, field="head_sha")
    result = run(
        [
            "git",
            "-C",
            repo_path,
            "diff",
            "--raw",
            "-z",
            "--no-abbrev",
            "--no-renames",
            base_sha,
            head_sha,
            "--",
        ]
    )
    tokens = result.stdout.decode("utf-8", errors="strict").split("\x00")
    records: list[ChangeRecord] = []
    index = 0
    while index < len(tokens):
        header = tokens[index]
        index += 1
        if not header:
            continue
        if not header.startswith(":"):
            raise AuthorityError("MALFORMED_GIT_RAW_DIFF", header[:120])
        fields = header[1:].split()
        if len(fields) != 5:
            raise AuthorityError("MALFORMED_GIT_RAW_DIFF", header[:120])
        if index >= len(tokens):
            raise AuthorityError("MALFORMED_GIT_RAW_DIFF", "missing path")
        path = _validate_path(tokens[index])
        index += 1
        old_mode, new_mode, old_oid, new_oid, status = fields
        if status.startswith(("R", "C")):
            raise AuthorityError("RENAME_DETECTION_MUST_BE_DISABLED")
        records.append(ChangeRecord(old_mode, new_mode, old_oid, new_oid, status, path))
    records.sort(key=lambda record: (record.path, record.status, record.old_oid, record.new_oid))
    return records


def candidate_record(repository: str, repo_path: str, base_sha: str, head_sha: str) -> dict[str, object]:
    repository = validate_repository_name(repository)
    records = changed_records(repo_path, base_sha, head_sha)
    return {
        "base_sha": require_full_sha(base_sha, field="base_sha"),
        "head_sha": require_full_sha(head_sha, field="head_sha"),
        "records": [record.as_dict() for record in records],
        "repository": repository,
        "schema_version": "candidate-digest-v1",
    }


def candidate_digest(repository: str, repo_path: str, base_sha: str, head_sha: str) -> tuple[str, dict[str, object]]:
    record = candidate_record(repository, repo_path, base_sha, head_sha)
    return sha256_bytes(canonical_json_bytes(record)), record
