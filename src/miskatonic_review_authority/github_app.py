from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .util import AuthorityError, canonical_json_bytes, run


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def create_app_jwt(app_id: str, private_key_path: str, *, now: int | None = None) -> str:
    if not str(app_id).strip():
        raise AuthorityError("GITHUB_APP_ID_MISSING")
    if not Path(private_key_path).is_file():
        raise AuthorityError("GITHUB_APP_PRIVATE_KEY_MISSING")
    issued = int(time.time() if now is None else now)
    header = _b64url(canonical_json_bytes({"alg": "RS256", "typ": "JWT"}).rstrip(b"\n"))
    payload = _b64url(
        canonical_json_bytes({"exp": issued + 540, "iat": issued - 60, "iss": str(app_id)}).rstrip(b"\n")
    )
    unsigned = f"{header}.{payload}".encode("ascii")
    signature = run(
        ["openssl", "dgst", "-sha256", "-sign", private_key_path],
        input_bytes=unsigned,
    ).stdout
    return f"{header}.{payload}.{_b64url(signature)}"


def _request_json(url: str, *, token: str, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
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
        raise AuthorityError("GITHUB_APP_API_FAILED", f"HTTP {error.code}: {detail}") from error


def create_installation_token(
    *,
    app_id: str,
    private_key_path: str,
    owner: str,
    repositories: list[str],
    permissions: dict[str, str],
) -> dict[str, Any]:
    jwt = create_app_jwt(app_id, private_key_path)
    installations = _request_json("https://api.github.com/app/installations?per_page=100", token=jwt)
    installation_id = None
    for installation in installations:
        account = installation.get("account", {})
        if str(account.get("login", "")).lower() == owner.lower():
            installation_id = installation.get("id")
            break
    if installation_id is None:
        raise AuthorityError("GITHUB_APP_INSTALLATION_NOT_FOUND", owner)
    result = _request_json(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        token=jwt,
        method="POST",
        payload={"repositories": repositories, "permissions": permissions},
    )
    if not result.get("token"):
        raise AuthorityError("GITHUB_APP_INSTALLATION_TOKEN_MISSING")
    return {
        "expires_at": result.get("expires_at", ""),
        "installation_id": installation_id,
        "token": result["token"],
    }
