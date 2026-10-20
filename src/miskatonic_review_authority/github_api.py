from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .util import AuthorityError, require_full_sha, validate_repository_name


def _request_json(
    url: str, *, token: str, method: str = "GET", payload: dict[str, Any] | None = None
) -> Any:
    request = urllib.request.Request(
        url,
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "miskatonic-review-authority/0.1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[-4000:]
        raise AuthorityError(
            "GITHUB_API_FAILED", f"HTTP {error.code}: {detail}"
        ) from error


def get_pr_head_sha(*, token: str, repository: str, pr_number: int) -> str:
    repository = validate_repository_name(repository)
    if not token:
        raise AuthorityError("GITHUB_APP_TOKEN_MISSING")
    if pr_number < 1:
        raise AuthorityError("INVALID_PR_NUMBER", str(pr_number))
    url = f"https://api.github.com/repos/{repository}/pulls/{pr_number}"
    data = _request_json(url, token=token)
    head_sha = data.get("head", {}).get("sha")
    if not head_sha:
        raise AuthorityError("GITHUB_PR_HEAD_NOT_FOUND", f"{repository}#{pr_number}")
    return require_full_sha(str(head_sha), field="pr_head_sha")


def verify_pr_head(
    *, token: str, repository: str, pr_number: int, expected_head_sha: str
) -> str:
    expected_head_sha = require_full_sha(expected_head_sha, field="expected_head_sha")
    actual_head_sha = get_pr_head_sha(
        token=token, repository=repository, pr_number=pr_number
    )
    if actual_head_sha != expected_head_sha:
        raise AuthorityError(
            "STALE_REVIEW_HEAD",
            f"PR #{pr_number} head {actual_head_sha} != expected {expected_head_sha}",
        )
    return actual_head_sha
