from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Iterable


class AuthorityError(RuntimeError):
    """Fail-closed authority error with a stable public code."""

    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: str | os.PathLike[str]) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: str | os.PathLike[str], value: Any) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical_json_bytes(value))


def run(
    argv: Iterable[str],
    *,
    cwd: str | os.PathLike[str] | None = None,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        list(argv),
        cwd=cwd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")[-4000:]
        raise AuthorityError("COMMAND_FAILED", f"{list(argv)!r}: {stderr}")
    return result


def require_full_sha(value: str, *, field: str) -> str:
    import re

    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise AuthorityError("INVALID_FULL_SHA", field)
    return value


def validate_repository_name(value: str) -> str:
    import re

    normalized = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+", normalized):
        raise AuthorityError("INVALID_REPOSITORY", value)
    return normalized
