"""Authenticated Actions adapter and authority-controlled receipt custody.

Only canonical authority workflow code may use the Actions-held App key. Tests
inject a fake transport and temporary test key; those are never real admissions.
"""

from __future__ import annotations

import base64
import copy
import os
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .attestation import public_key_fingerprint, sign_attestation, verify_attestation
from .github_app import create_app_jwt, create_installation_token
from .research_admission import (
    AUTHORITY,
    CHECK_NAME,
    ENVIRONMENT,
    ROUTE,
    TARGET,
    AdmissionError,
    assess_ci,
    build_request,
    canonical,
    decide,
    digest,
    git,
    load_contract,
    reconcile_candidate,
    require,
    strict_json,
    validate_schema,
    verify_authorization,
    verify_pr,
    verify_ratification,
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHub:
    def __init__(self, token: str):
        require(bool(token), "GITHUB_APP_AUTHORIZATION_INSUFFICIENT")
        self._token = token

    def api(
        self, method: str, path: str, payload: Any = None, *, missing_ok: bool = False
    ) -> Any:
        require(
            path.startswith("/") and not path.startswith("//") and "://" not in path,
            "AUTHORIZATION_SCOPE_MISMATCH",
        )
        request = urllib.request.Request(
            "https://api.github.com" + path,
            data=None if payload is None else canonical(payload),
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self._token,
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "miskatonic-research-admission/1",
            },
        )
        try:
            with urllib.request.build_opener(_NoRedirect()).open(
                request, timeout=30
            ) as response:
                data = response.read()
                return None if response.status == 204 else strict_json(data)
        except urllib.error.HTTPError as exc:
            if missing_ok and exc.code == 404:
                return None
            # Never echo headers, tokens, response bodies or untrusted API text.
            raise AdmissionError(
                "AUTHENTICATED_GITHUB_READ_FAILED"
                if method == "GET"
                else "CHECK_PUBLICATION_FAILED"
            ) from exc
        except (OSError, ValueError) as exc:
            raise AdmissionError(
                "AUTHENTICATED_GITHUB_READ_FAILED"
                if method == "GET"
                else "CHECK_PUBLICATION_FAILED"
            ) from exc

    def pages(self, path: str, key: str | None = None) -> list:
        result = []
        separator = "&" if "?" in path else "?"
        for page in range(1, 101):
            value = self.api("GET", f"{path}{separator}per_page=100&page={page}")
            items = value[key] if key else value
            require(type(items) is list, "AUTHENTICATED_GITHUB_READ_FAILED")
            result.extend(items)
            if len(items) < 100:
                return result
        raise AdmissionError("AUTHENTICATED_GITHUB_READ_FAILED")


def target_token(
    private_key: str, app_id: int, *, effects: dict | None = None
) -> GitHub:
    effects = effects if effects is not None else {}
    effects["credential_use_started"] = True
    require(Path(private_key).is_file(), "SIGNING_CREDENTIAL_UNAVAILABLE")
    try:
        jwt = create_app_jwt(str(app_id), private_key)
        app = GitHub(jwt).api("GET", "/app")
        require(app.get("id") == app_id, "GITHUB_APP_AUTHORIZATION_INSUFFICIENT")
        effects["credential_session_attempted"] = True
        result = create_installation_token(
            app_id=str(app_id),
            private_key_path=private_key,
            owner="Miskatonic-System",
            repositories=["msk-ruliology"],
            permissions={
                "actions": "read",
                "checks": "write",
                "contents": "read",
                "pull_requests": "read",
            },
        )
        client = GitHub(result["token"])
        effects["credential_session_issued"] = True
        effects["target_client"] = client
        repos = client.api("GET", "/installation/repositories?per_page=100")
        require(
            repos.get("total_count") == 1
            and [r.get("full_name") for r in repos.get("repositories", [])] == [TARGET],
            "GITHUB_APP_TOKEN_SCOPE_MISMATCH",
        )
        return client
    except AdmissionError:
        raise
    except Exception as exc:
        raise AdmissionError("GITHUB_APP_AUTHORIZATION_INSUFFICIENT") from exc


def collect_facts(
    authority: Path,
    root: dict,
    policy: dict,
    authority_api: GitHub,
    target_api: GitHub,
    run_id: int,
    ratification_pr: int,
    ratification_comment: int,
    *,
    approval: bool,
) -> tuple[dict, list]:
    head = authority_api.api("GET", f"/repos/{AUTHORITY}/git/ref/heads/main")["object"][
        "sha"
    ]
    require(
        git(authority, "rev-parse", "HEAD").decode().strip() == head,
        "ADMISSION_POLICY_NOT_RATIFIED",
    )
    workflow = authority_api.api("GET", f"/repos/{AUTHORITY}/actions/runs/{run_id}")
    require(workflow.get("id") == run_id, "AUTHORIZATION_SCOPE_MISMATCH")
    pr = target_api.api("GET", f"/repos/{TARGET}/pulls/156")
    verify_pr(pr, policy)
    commit = target_api.api(
        "GET", f"/repos/{TARGET}/git/commits/{policy['candidate']['head_sha']}"
    )
    require(
        commit.get("sha") == policy["candidate"]["head_sha"], "CANDIDATE_HEAD_STALE"
    )
    facts = {
        "canonical_authority_sha": head,
        "workflow": workflow,
        "target_pr": pr,
        "candidate_tree_sha": commit["tree"]["sha"],
        "ratification_pr": authority_api.api(
            "GET", f"/repos/{AUTHORITY}/pulls/{ratification_pr}"
        ),
        "ratification_comment": authority_api.api(
            "GET", f"/repos/{AUTHORITY}/issues/comments/{ratification_comment}"
        ),
    }
    ratification_body = strict_json(facts["ratification_comment"].get("body", ""))
    validate_schema(ratification_body, "research-authority-ratification-v1", authority)
    facts["authority_security_review"] = authority_api.api(
        "GET",
        f"/repos/{AUTHORITY}/issues/comments/{ratification_body['security_review_comment_id']}",
    )
    facts["ratification_identity"] = verify_ratification(authority, root, policy, facts)
    runs = []
    for expected in policy["ci_runs"]:
        run = target_api.api("GET", f"/repos/{TARGET}/actions/runs/{expected['id']}")
        jobs = target_api.pages(
            f"/repos/{TARGET}/actions/runs/{expected['id']}/jobs", "jobs"
        )
        pairs = []
        for job in jobs:
            # Construct the URL from independently bound numeric IDs, never follow request-provided URLs.
            annotations = target_api.pages(
                f"/repos/{TARGET}/check-runs/{job['id']}/annotations"
            )
            pairs.append({"job": job, "annotations": annotations})
        runs.append({"run": run, "jobs": pairs})
    if approval:
        facts["environment"] = authority_api.api(
            "GET", f"/repos/{AUTHORITY}/environments/{ENVIRONMENT}"
        )
        facts["approval_history"] = authority_api.api(
            "GET", f"/repos/{AUTHORITY}/actions/runs/{run_id}/approvals"
        )
        facts["resolved_principal"] = authority_api.api(
            "GET", f"/users/{policy['authorization_principal']['github_login']}"
        )
    return facts, runs


class AuthorityLedger:
    """CAS-backed authority Git ledger. Never writes candidate files or canonical main."""

    REF = "heads/research-evidence-admissions-v1"

    def __init__(self, api: GitHub, canonical_head: str, scope: str):
        self.api = api
        self.canonical_head = canonical_head
        self.state_path = f"admissions/research-evidence-v1/{scope}/state.json"
        self.receipt_path = f"admissions/research-evidence-v1/{scope}/receipt.json"
        self.head = None

    def read_file(self, commit: str, path: str) -> bytes | None:
        value = self.api.api(
            "GET", f"/repos/{AUTHORITY}/contents/{path}?ref={commit}", missing_ok=True
        )
        if value is None:
            return None
        require(
            value.get("type") == "file" and value.get("encoding") == "base64",
            "ADMISSION_LEDGER_CONFLICT",
        )
        try:
            return base64.b64decode(value["content"], validate=False)
        except (ValueError, KeyError) as exc:
            raise AdmissionError("ADMISSION_LEDGER_CONFLICT") from exc

    def read(self) -> dict | None:
        ref = self.api.api(
            "GET", f"/repos/{AUTHORITY}/git/ref/{self.REF}", missing_ok=True
        )
        self.head = ref["object"]["sha"] if ref else None
        data = self.read_file(self.head, self.state_path) if self.head else None
        return strict_json(data) if data is not None else None

    def write(self, state: dict, receipt: dict | None = None) -> str:
        parent = self.head or self.canonical_head
        tree = self.api.api("GET", f"/repos/{AUTHORITY}/git/commits/{parent}")["tree"][
            "sha"
        ]
        files = {self.state_path: state}
        if receipt is not None:
            files[self.receipt_path] = receipt
        entries = []
        for path, value in files.items():
            blob = self.api.api(
                "POST",
                f"/repos/{AUTHORITY}/git/blobs",
                {
                    "content": base64.b64encode(canonical(value)).decode(),
                    "encoding": "base64",
                },
            )
            entries.append(
                {"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]}
            )
        new_tree = self.api.api(
            "POST",
            f"/repos/{AUTHORITY}/git/trees",
            {"base_tree": tree, "tree": entries},
        )
        commit = self.api.api(
            "POST",
            f"/repos/{AUTHORITY}/git/commits",
            {
                "message": "Record scoped research admission custody",
                "tree": new_tree["sha"],
                "parents": [parent],
            },
        )
        if self.head is None:
            self.api.api(
                "POST",
                f"/repos/{AUTHORITY}/git/refs",
                {"ref": "refs/" + self.REF, "sha": commit["sha"]},
            )
        else:
            self.api.api(
                "PATCH",
                f"/repos/{AUTHORITY}/git/refs/{self.REF}",
                {"sha": commit["sha"], "force": False},
            )
        observed = self.api.api("GET", f"/repos/{AUTHORITY}/git/ref/{self.REF}")[
            "object"
        ]["sha"]
        require(observed == commit["sha"], "ADMISSION_LEDGER_CONFLICT")
        self.head = commit["sha"]
        return self.head


def key_identity(private_key: str, app_id: int) -> tuple[str, bytes]:
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "public.pem"
        proc = subprocess.run(
            ["openssl", "pkey", "-in", private_key, "-pubout", "-out", str(path)],
            capture_output=True,
            check=False,
        )
        require(proc.returncode == 0, "SIGNING_CREDENTIAL_UNAVAILABLE")
        public = path.read_bytes()
        return f"github-app:{app_id}:sha256:{public_key_fingerprint(str(path))}", public


def verify_signed_receipt(
    receipt: dict, authority: Path, public: bytes, key_id: str
) -> None:
    validate_schema(receipt, "research-admission-receipt-v1", authority)
    unsigned = copy.deepcopy(receipt)
    unsigned.pop("signature")
    supplied = unsigned.pop("receipt_digest")
    require(digest(unsigned) == supplied, "ADMISSION_LEDGER_CONFLICT")
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "public.pem"
        path.write_bytes(public)
        try:
            verify_attestation(receipt, str(path), expected_key_id=key_id)
        except Exception as exc:
            raise AdmissionError("ADMISSION_LEDGER_CONFLICT") from exc


def check_matches(
    check: dict, policy: dict, request_digest: str, receipt_digest: str | None = None
) -> None:
    require(
        check.get("head_sha") == policy["candidate"]["head_sha"]
        and check.get("name") == CHECK_NAME
        and check.get("external_id") == request_digest
        and check.get("app", {}).get("id") == policy["expected_app_id"],
        "CHECK_PUBLICATION_FAILED",
    )
    if receipt_digest is not None:
        require(
            check.get("conclusion") == "success"
            and receipt_digest in check.get("output", {}).get("summary", ""),
            "CHECK_PUBLICATION_FAILED",
        )


def publish_admission(
    authority: Path,
    policy: dict,
    root: dict,
    request: dict,
    evidence: dict,
    facts: dict,
    ci: dict,
    authority_api: GitHub,
    target_api: GitHub,
    private_key: str,
    now: datetime,
    *,
    ledger=None,
) -> dict:
    # A supplied request or PASS flag is never sufficient. Revalidate the complete route first.
    decision = decide(authority, root, policy, request, evidence, facts, ci, now)
    req_digest = digest(request)
    evidence_digest = digest(
        {
            "request": req_digest,
            "prior": digest(evidence["prior"]),
            "manifest": digest(evidence["manifest"]),
            "report": evidence["report_sha256"],
            "ci": digest(ci),
            "ratification": facts["ratification_identity"],
            "authorization": decision.authorization_identity["evidence_digest"],
        }
    )
    key_id, public = key_identity(private_key, policy["expected_app_id"])
    scope = digest(policy["candidate"])
    ledger = ledger or AuthorityLedger(
        authority_api, facts["canonical_authority_sha"], scope
    )
    state = ledger.read()
    if state is not None:
        require(
            state.get("request_digest") == req_digest
            and state.get("evidence_digest") == evidence_digest,
            "ADMISSION_LEDGER_CONFLICT",
        )
        if state.get("status") != "ADMITTED":
            raise AdmissionError("CHECK_PUBLICATION_PARTIAL", side_effect=True)
        raw = ledger.read_file(state["receipt_commit"], ledger.receipt_path)
        require(raw is not None, "ADMISSION_LEDGER_CONFLICT")
        receipt = strict_json(raw)
        verify_signed_receipt(receipt, authority, public, key_id)
        require(
            receipt["request_digest"] == req_digest
            and receipt["evidence_digest"] == evidence_digest
            and receipt["receipt_digest"] == state["receipt_digest"],
            "ADMISSION_LEDGER_CONFLICT",
        )
        verify_pr(target_api.api("GET", f"/repos/{TARGET}/pulls/156"), policy)
        check = target_api.api(
            "GET", f"/repos/{TARGET}/check-runs/{receipt['check_run_id']}"
        )
        check_matches(check, policy, req_digest, receipt["receipt_digest"])
        return {
            "status": "ALREADY_ADMITTED_IDENTICAL_REQUEST",
            "receipt": receipt,
            "receipt_commit": state["receipt_commit"],
            "check_run_id": receipt["check_run_id"],
            "release_authorized": False,
        }
    state = {
        "status": "RESERVED",
        "request_digest": req_digest,
        "evidence_digest": evidence_digest,
        "workflow_run_id": facts["workflow"]["id"],
    }
    side_effect = False
    check_id = None
    try:
        side_effect = True
        ledger.write(state)
        verify_pr(target_api.api("GET", f"/repos/{TARGET}/pulls/156"), policy)
        check = target_api.api(
            "POST",
            f"/repos/{TARGET}/check-runs",
            {
                "name": CHECK_NAME,
                "head_sha": request["head_sha"],
                "external_id": req_digest,
                "status": "in_progress",
                "output": {
                    "title": "Research admission validation; not release authorization",
                    "summary": "No success or local/cloud review is claimed while receipt custody is pending.",
                },
            },
        )
        check_matches(check, policy, req_digest)
        check_id = check["id"]
        receipt = {
            "schema_version": "research-admission-receipt-v1",
            "receipt_id": "research-admission-" + req_digest,
            "admission_route": ROUTE,
            "risk_class": policy["risk_class"],
            **policy["candidate"],
            "authority_root_identity": request["authority_root_reference"],
            "authority_policy_identity": request["authority_policy_reference"],
            "target_policy_identity": request["target_policy_reference"],
            "review_report_sha256": request["review_report_sha256"],
            "reviewer_identity": request["reviewer_identity"],
            "reviewer_independence_class": request["reviewer_independence_class"],
            "prior_verification_digest": digest(evidence["prior"]),
            "review_packet_manifest_digest": digest(evidence["manifest"]),
            "authorization_principal": decision.authorization_identity["principal"],
            "authorization_evidence_digest": decision.authorization_identity[
                "evidence_digest"
            ],
            "authorization_decision": "EXPLICIT_BOUNDED_RESEARCH_RISK_ACCEPTED",
            "ci_qualification_state": ci["state"],
            "limitations": policy["limitations"],
            "decision": "ADMITTED_RESEARCH_CONTRACT_ONLY",
            "release_authorized": False,
            "local_review_executed": False,
            "created_at": now.astimezone(UTC).isoformat(),
            "workflow_run_id": facts["workflow"]["id"],
            "check_run_id": check_id,
            "signature_algorithm": "RSASSA-PKCS1-v1_5-SHA256",
            "signing_key_identity": key_id,
            "request_digest": req_digest,
            "evidence_digest": evidence_digest,
            "producer_approver_account_overlap": decision.authorization_identity[
                "producer_approver_account_overlap"
            ],
        }
        receipt["receipt_digest"] = digest(receipt)
        receipt = sign_attestation(receipt, private_key, key_id=key_id)
        verify_signed_receipt(receipt, authority, public, key_id)
        state.update(
            status="RECEIPT_PERSISTED",
            check_run_id=check_id,
            receipt_digest=receipt["receipt_digest"],
        )
        receipt_commit = ledger.write(state, receipt)
        reference = f"https://github.com/{AUTHORITY}/blob/{receipt_commit}/{ledger.receipt_path}"
        # Refresh actual approval and ratification immediately before the only success transition.
        fresh = dict(facts)
        fresh["environment"] = authority_api.api(
            "GET", f"/repos/{AUTHORITY}/environments/{ENVIRONMENT}"
        )
        fresh["approval_history"] = authority_api.api(
            "GET",
            f"/repos/{AUTHORITY}/actions/runs/{facts['workflow']['id']}/approvals",
        )
        fresh["ratification_comment"] = authority_api.api(
            "GET",
            f"/repos/{AUTHORITY}/issues/comments/{facts['ratification_comment']['id']}",
        )
        ratification_body = strict_json(fresh["ratification_comment"].get("body", ""))
        validate_schema(
            ratification_body, "research-authority-ratification-v1", authority
        )
        fresh["authority_security_review"] = authority_api.api(
            "GET",
            f"/repos/{AUTHORITY}/issues/comments/{ratification_body['security_review_comment_id']}",
        )
        verify_ratification(authority, root, policy, fresh)
        renewed = verify_authorization(
            authority, policy, request, fresh, datetime.now(UTC)
        )
        require(
            renewed["evidence_digest"]
            == decision.authorization_identity["evidence_digest"],
            "AUTHORIZATION_SCOPE_MISMATCH",
        )
        # Fresh authoritative head/main reads immediately precede the only success transition.
        verify_pr(target_api.api("GET", f"/repos/{TARGET}/pulls/156"), policy)
        require(
            authority_api.api("GET", f"/repos/{AUTHORITY}/git/ref/heads/main")[
                "object"
            ]["sha"]
            == facts["canonical_authority_sha"],
            "ADMISSION_POLICY_NOT_RATIFIED",
        )
        summary = canonical(
            {
                "admission_route": ROUTE,
                "head_sha": request["head_sha"],
                "candidate_digest": request["candidate_digest"],
                "authority_policy_commit": facts["canonical_authority_sha"],
                "review_report_sha256": request["review_report_sha256"],
                "authorization_principal": policy["authorization_principal"],
                "receipt_digest": receipt["receipt_digest"],
                "receipt_reference": reference,
                "ci_qualification_state": ci["state"],
                "limitations": policy["limitations"],
                "disposition": "RESEARCH_ADMISSION_CONTRACT_PASSED",
                "local_review_executed": False,
                "release_authorized": False,
            }
        ).decode()
        target_api.api(
            "PATCH",
            f"/repos/{TARGET}/check-runs/{check_id}",
            {
                "status": "completed",
                "conclusion": "success",
                "details_url": reference,
                "output": {
                    "title": "Bounded external research-admission contract passed",
                    "summary": summary,
                },
            },
        )
        observed = target_api.api("GET", f"/repos/{TARGET}/check-runs/{check_id}")
        check_matches(observed, policy, req_digest, receipt["receipt_digest"])
        verify_pr(target_api.api("GET", f"/repos/{TARGET}/pulls/156"), policy)
        state.update(status="ADMITTED", receipt_commit=receipt_commit)
        ledger.write(state)
        return {
            "status": "ADMISSION_AUTHENTICATED",
            "receipt": receipt,
            "receipt_commit": receipt_commit,
            "receipt_reference": reference,
            "check_run_id": check_id,
            "release_authorized": False,
        }
    except Exception as exc:
        # Preserve a durable reservation. Never create another check on an ambiguous retry.
        # Withdraw only this new route's own check; historical CI conclusions are untouched.
        cancellation_unconfirmed = False
        if check_id is not None:
            try:
                target_api.api(
                    "PATCH",
                    f"/repos/{TARGET}/check-runs/{check_id}",
                    {
                        "status": "completed",
                        "conclusion": "cancelled",
                        "output": {
                            "title": "Research admission publication incomplete",
                            "summary": "No release authorization. Reconcile authority custody before retry.",
                        },
                    },
                )
            except Exception:  # noqa: BLE001 - preserve a typed partial result
                cancellation_unconfirmed = True
        error = AdmissionError(
            "CHECK_PUBLICATION_PARTIAL" if side_effect else "CHECK_PUBLICATION_FAILED",
            side_effect=side_effect,
        )
        error.decision = replace(
            error.decision,
            failure_cause_code=(
                exc.code
                if isinstance(exc, AdmissionError)
                else "ADMISSION_UNKNOWN_ERROR"
            ),
        )
        if cancellation_unconfirmed:
            error.decision.required_followups.append(
                "Automatic cancellation was not confirmed; reconcile the authenticated check before retry."
            )
        raise error from exc


def _run_actions_phase(
    authority: Path,
    target: Path,
    *,
    phase: str,
    private_key: str,
    ratification_pr: int,
    ratification_comment: int,
    run_id: int,
    authority_token: str,
    output: Path,
    effects: dict,
) -> dict:
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_REPOSITORY") == AUTHORITY
        and os.environ.get("GITHUB_REF") == "refs/heads/main",
        "ADMISSION_POLICY_NOT_RATIFIED",
    )
    require(phase in ("plan", "admit"), "ADMISSION_ROUTE_NOT_ALLOWED")
    root, policy = load_contract(authority)
    authority_api = GitHub(authority_token)
    # Verify canonical workflow identity before using any App credential.
    canonical_head = authority_api.api("GET", f"/repos/{AUTHORITY}/git/ref/heads/main")[
        "object"
    ]["sha"]
    require(
        git(authority, "rev-parse", "HEAD").decode().strip() == canonical_head,
        "ADMISSION_POLICY_NOT_RATIFIED",
    )
    workflow = authority_api.api("GET", f"/repos/{AUTHORITY}/actions/runs/{run_id}")
    require(
        workflow.get("head_sha") == canonical_head
        and workflow.get("path") == ".github/workflows/admit-research-evidence.yml"
        and workflow.get("head_branch") == "main"
        and workflow.get("event") == "workflow_dispatch",
        "ADMISSION_POLICY_NOT_RATIFIED",
    )
    # Re-read the actual merged ratification and security-review custody before
    # using the App key; canonical branch/workflow checks alone are insufficient.
    preliminary = {
        "canonical_authority_sha": canonical_head,
        "workflow": workflow,
        "ratification_pr": authority_api.api(
            "GET", f"/repos/{AUTHORITY}/pulls/{ratification_pr}"
        ),
        "ratification_comment": authority_api.api(
            "GET", f"/repos/{AUTHORITY}/issues/comments/{ratification_comment}"
        ),
    }
    ratification_body = strict_json(preliminary["ratification_comment"].get("body", ""))
    validate_schema(ratification_body, "research-authority-ratification-v1", authority)
    preliminary["authority_security_review"] = authority_api.api(
        "GET",
        f"/repos/{AUTHORITY}/issues/comments/{ratification_body['security_review_comment_id']}",
    )
    verify_ratification(authority, root, policy, preliminary)
    target_api = target_token(private_key, policy["expected_app_id"], effects=effects)
    target.mkdir(parents=True, exist_ok=True)
    if not (target / ".git").exists():
        # Fetch only frozen data; no candidate scripts, hooks, tests, imports or filters execute.
        subprocess.run(["git", "init", str(target)], check=True, capture_output=True)
        # Token remains in the child environment rather than process arguments or logs.
        env = dict(os.environ)
        env.update(
            GIT_CONFIG_COUNT="1",
            GIT_CONFIG_KEY_0="http.extraheader",
            GIT_CONFIG_VALUE_0="Authorization: Basic "
            + base64.b64encode(
                ("x-access-token:" + target_api._token).encode()
            ).decode(),
            GIT_LFS_SKIP_SMUDGE="1",
        )
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(target),
                "fetch",
                "https://github.com/" + TARGET + ".git",
                policy["candidate"]["head_sha"],
                policy["candidate"]["base_sha"],
            ],
            env=env,
            capture_output=True,
            check=False,
        )
        require(proc.returncode == 0, "CANDIDATE_FETCH_FAILED")
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(target),
                "-c",
                "core.hooksPath=/dev/null",
                "checkout",
                "--detach",
                policy["candidate"]["head_sha"],
            ],
            env={**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"},
            capture_output=True,
            check=False,
        )
        require(proc.returncode == 0, "CANDIDATE_FETCH_FAILED")
    evidence = reconcile_candidate(authority, target, policy)
    facts, runs = collect_facts(
        authority,
        root,
        policy,
        authority_api,
        target_api,
        run_id,
        ratification_pr,
        ratification_comment,
        approval=phase == "admit",
    )
    ci = assess_ci(policy, runs, evidence["compensating"])
    request = build_request(
        authority, policy, evidence, ci, facts["canonical_authority_sha"], run_id
    )
    if phase == "plan":
        now = datetime.now(UTC)
        template = {
            "schema_version": "research-human-authorization-v1",
            "purpose": "ADMIT_EXACT_CAUSALIS_RESEARCH",
            "authority_head_sha": facts["canonical_authority_sha"],
            "authority_root_sha256": request["authority_root_reference"]["sha256"],
            "authority_policy_sha256": request["authority_policy_reference"]["sha256"],
            "candidate_digest": request["candidate_digest"],
            "request_digest": digest(request),
            "ci_assessment_digest": digest(ci),
            "expires_at": (now + timedelta(hours=12)).isoformat(),
            "human_review_attestation": "I personally reviewed and authorize this exact bounded research risk decision.",
            "accept_independence_limitations": True,
            "accept_ci_compensating_controls": True,
            "limitations": policy["limitations"],
        }
        result = {
            "state": "PREPARED_AWAITING_PROTECTED_HUMAN_AUTHORIZATION",
            "authorized": False,
            "request": request,
            "authorization_comment_template": template,
            "ci_assessment": ci,
        }
    else:
        result = publish_admission(
            authority,
            policy,
            root,
            request,
            evidence,
            facts,
            ci,
            authority_api,
            target_api,
            private_key,
            datetime.now(UTC),
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(result))
    return {
        k: v
        for k, v in result.items()
        if k not in ("receipt", "request", "authorization_comment_template")
    }


def run_actions_phase(*args, **kwargs) -> dict:
    """Record credential preparation effects honestly and revoke scoped sessions."""
    effects = {}
    try:
        return _run_actions_phase(*args, **kwargs, effects=effects)
    except Exception as exc:
        client = effects.get("target_client")
        if client is not None:
            try:
                client.api("DELETE", "/installation/token")
                effects["credential_session_revoked"] = True
            except Exception:  # noqa: BLE001 - cleanup cannot replace the fail-closed result
                effects["credential_revocation_unconfirmed"] = True
        error = (
            exc
            if isinstance(exc, AdmissionError)
            else AdmissionError("ADMISSION_UNKNOWN_ERROR")
        )
        error.decision = replace(
            error.decision,
            execution_began=error.decision.execution_began
            or effects.get("credential_use_started", False),
            external_side_effect=error.decision.external_side_effect
            or effects.get("credential_session_attempted", False),
            credential_session_issued=effects.get("credential_session_issued", False),
            credential_session_revoked=effects.get("credential_session_revoked", False),
        )
        raise error from exc
    finally:
        client = effects.get("target_client")
        if client is not None and not effects.get("credential_session_revoked", False):
            try:
                client.api("DELETE", "/installation/token")
                effects["credential_session_revoked"] = True
            except Exception:  # noqa: BLE001 - cleanup cannot replace the fail-closed result
                effects["credential_revocation_unconfirmed"] = True
