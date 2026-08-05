from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .util import AuthorityError, require_full_sha, validate_repository_name


_ALLOWED_CONCLUSIONS = {"success", "failure", "neutral", "cancelled", "timed_out", "action_required"}


def publish_check(
    *,
    token: str,
    repository: str,
    head_sha: str,
    name: str,
    conclusion: str,
    title: str,
    summary: str,
    details_url: str | None = None,
) -> dict[str, Any]:
    repository = validate_repository_name(repository)
    require_full_sha(head_sha, field="head_sha")
    if conclusion not in _ALLOWED_CONCLUSIONS:
        raise AuthorityError("INVALID_CHECK_CONCLUSION", conclusion)
    if not token:
        raise AuthorityError("GITHUB_APP_TOKEN_MISSING")
    payload: dict[str, Any] = {
        "name": name,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {"title": title[:255], "summary": summary[:65000]},
    }
    if details_url:
        payload["details_url"] = details_url
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/check-runs",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
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
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[-4000:]
        raise AuthorityError("CHECK_PUBLISH_FAILED", f"HTTP {error.code}: {detail}") from error
    return body
