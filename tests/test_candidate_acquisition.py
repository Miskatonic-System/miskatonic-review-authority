"""Controlled Git/credential probes only; no live API, authority key or admission."""

from __future__ import annotations

import copy
import json
import subprocess
import traceback
from pathlib import Path

import pytest

from miskatonic_review_authority import research_admission as ra
from miskatonic_review_authority import research_admission_github as gh

REPO = Path(__file__).resolve().parents[1]
SECRET = "TEST_ONLY_SECRET_SENTINEL_NOT_A_REAL_TOKEN"
HEAD, BASE, TREE = "1" * 40, "2" * 40, "3" * 40
AUTH_HEAD = "6" * 40
POLICY = json.loads((REPO / ra.POLICY_PATH).read_text())


def operation(args):
    return next(
        x for x in ("init", "fetch", "cat-file", "checkout", "rev-parse") if x in args
    )


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    policy = copy.deepcopy(POLICY)
    policy["candidate"].update(head_sha=HEAD, base_sha=BASE, tree_sha=TREE)
    calls, later, revoked = [], [], []
    mode = {"failure": None}
    key = tmp_path / "TEST_ONLY_FAKE_KEY_NOT_SIGNING_MATERIAL"
    key.write_text("TEST ONLY; JWT and token creation are stubbed, never signed")
    ratification = {
        "schema_version": "research-authority-ratification-v1",
        "purpose": "RATIFY_EXTERNAL_EVIDENCE_ADMISSION_V1",
        "authority_accepted_head_sha": AUTH_HEAD,
        "authority_accepted_tree_sha": TREE,
        "authority_change_risk_class": "R2_SECURITY_OR_AUTHORITY_CHANGE",
        "authority_root_sha256": "0" * 64,
        "authority_policy_sha256": "0" * 64,
        "candidate_digest": policy["candidate"]["candidate_digest"],
        "security_review_comment_id": 8,
        "security_review_sha256": "0" * 64,
        "limitations": policy["limitations"],
        "accept_bootstrap_independence_limits": True,
        "human_review_attestation": "I personally reviewed and authorize this exact bounded research risk decision.",
    }

    class FakeAPI:
        def __init__(self, token):
            self._token = token

        def api(self, method, path, *args, **kwargs):
            if method == "DELETE" and path == "/installation/token":
                revoked.append(True)
                return None
            if path == "/app":
                return {"id": policy["expected_app_id"]}
            if path.startswith("/installation/repositories"):
                names = [ra.TARGET]
                if mode["failure"] == "scope":
                    names.append("TEST_ONLY/unrelated")
                return {
                    "total_count": len(names),
                    "repositories": [{"full_name": n} for n in names],
                }
            if path.endswith("/git/ref/heads/main"):
                return {"object": {"sha": AUTH_HEAD}}
            if "/actions/runs/" in path:
                return {
                    "head_sha": AUTH_HEAD,
                    "path": ra.WORKFLOW_PATH,
                    "head_branch": "main",
                    "event": "workflow_dispatch",
                }
            if "/pulls/" in path:
                return {"merged": True}
            if path.endswith("/issues/comments/7"):
                return {"body": json.dumps(ratification)}
            if path.endswith("/issues/comments/8"):
                return {}
            raise AssertionError("Unexpected TEST ONLY API endpoint")

    def fake_git(args, **kwargs):
        op = operation(args)
        calls.append(op)
        assert kwargs["capture_output"] is True and kwargs["check"] is False
        assert kwargs["timeout"] == 300
        assert not any(SECRET in x for x in args)
        failure = mode["failure"]
        if failure == "git_unavailable" and op == "init":
            raise FileNotFoundError(SECRET)
        if failure == "timeout" and op == "fetch":
            raise subprocess.TimeoutExpired(
                ["git", SECRET], 300, output=SECRET, stderr=SECRET
            )
        if failure == "invocation" and op == "checkout":
            raise OSError(SECRET)
        failed = (
            (failure == "init" and op == "init")
            or (failure in ("fetch", "auth_rejected") and op == "fetch")
            or (failure == "checkout" and op == "checkout")
            or (failure == "missing_commit" and op == "cat-file")
        )
        if failed:
            return subprocess.CompletedProcess(
                args, 128, SECRET.encode(), ("Authorization: " + SECRET).encode()
            )
        output = b""
        if op == "cat-file":
            output = b"tree\n" if failure == "object_type" else b"commit\n"
        if op == "rev-parse":
            value = TREE if args[-1].endswith("^{tree}") else HEAD
            if failure == "wrong_tree" and args[-1].endswith("^{tree}"):
                value = "4" * 40
            if failure == "wrong_head" and args[-1] == "HEAD":
                value = "4" * 40
            output = (value + "\n").encode()
            if failure == "malformed":
                output = SECRET.encode()
        if op == "fetch":
            assert kwargs["env"]["GIT_CONFIG_KEY_0"] == "http.extraheader"
            assert kwargs["env"]["GIT_LFS_SKIP_SMUDGE"] == "1"
            if failure == "malformed_return":
                return subprocess.CompletedProcess(args, True, b"", SECRET.encode())
        if op == "checkout":
            assert "core.hooksPath=/dev/null" in args
            assert kwargs["env"]["GIT_LFS_SKIP_SMUDGE"] == "1"
        return subprocess.CompletedProcess(args, 0, output, SECRET.encode())

    def reconcile(*args):
        later.append("reconcile")
        if mode["failure"] == "evidence":
            raise ra.AdmissionError("PRIOR_VERIFICATION_FAILED")
        if mode["failure"] == "unknown_evidence":
            raise ValueError(SECRET)
        raise AssertionError("Tests stop before successful evidence publication")

    def forbidden(*args, **kwargs):
        later.append("SUCCESS_EVIDENCE_OR_PUBLICATION")
        raise AssertionError("Failed operation cannot advance")

    for env_name, value in {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": ra.AUTHORITY,
        "GITHUB_REF": "refs/heads/main",
    }.items():
        monkeypatch.setenv(env_name, value)
    monkeypatch.setattr(gh, "load_contract", lambda *a: ({}, policy))
    monkeypatch.setattr(gh, "git", lambda *a: (AUTH_HEAD + "\n").encode())
    # Authentication/ratification preconditions are synthetic here; the existing
    # admission suite independently exercises their real fail-closed validators.
    monkeypatch.setattr(gh, "verify_ratification", lambda *a: {})
    monkeypatch.setattr(gh, "GitHub", FakeAPI)
    monkeypatch.setattr(gh, "create_app_jwt", lambda *a: "TEST_ONLY_FAKE_JWT")

    def installation(**kwargs):
        assert kwargs["repositories"] == ["msk-ruliology"]
        assert kwargs["permissions"] == {
            "actions": "read",
            "checks": "write",
            "contents": "read",
            "pull_requests": "read",
        }
        return {"token": SECRET}

    monkeypatch.setattr(gh, "create_installation_token", installation)
    monkeypatch.setattr(gh.subprocess, "run", fake_git)
    monkeypatch.setattr(gh, "reconcile_candidate", reconcile)
    for name in [
        "collect_facts",
        "build_request",
        "publish_admission",
        "sign_attestation",
    ]:
        monkeypatch.setattr(gh, name, forbidden)
    return {
        "mode": mode,
        "calls": calls,
        "later": later,
        "revoked": revoked,
        "key": key,
        "policy": policy,
        "target": tmp_path / "target",
        "output": tmp_path / "never-created.json",
    }


CASES = [
    ("init", "CANDIDATE_GIT_INIT_NONZERO_EXIT"),
    ("fetch", "CANDIDATE_GIT_FETCH_NONZERO_EXIT"),
    ("auth_rejected", "CANDIDATE_GIT_FETCH_NONZERO_EXIT"),
    ("checkout", "CANDIDATE_GIT_CHECKOUT_NONZERO_EXIT"),
    ("missing_commit", "CANDIDATE_GIT_OBJECT_VERIFICATION_NONZERO_EXIT"),
    ("git_unavailable", "CANDIDATE_GIT_INIT_UNAVAILABLE"),
    ("timeout", "CANDIDATE_GIT_FETCH_TIMEOUT"),
    ("invocation", "CANDIDATE_GIT_CHECKOUT_INVOCATION_FAILED"),
    ("malformed", "CANDIDATE_GIT_OBJECT_VERIFICATION_MALFORMED_RESPONSE"),
    ("malformed_return", "CANDIDATE_GIT_FETCH_MALFORMED_RESPONSE"),
    ("object_type", "CANDIDATE_GIT_OBJECT_VERIFICATION_TYPE_MISMATCH"),
    ("wrong_tree", "CANDIDATE_GIT_OBJECT_VERIFICATION_TREE_MISMATCH"),
    ("wrong_head", "CANDIDATE_GIT_OBJECT_VERIFICATION_HEAD_MISMATCH"),
    ("scope", "CANDIDATE_INSTALLATION_SCOPE_MISMATCH"),
    ("evidence", "CANDIDATE_EVIDENCE_RECONCILIATION_FAILED"),
    ("unknown_evidence", "CANDIDATE_EVIDENCE_RECONCILIATION_FAILED"),
]


@pytest.mark.parametrize("failure,cause", CASES, ids=[c[0] for c in CASES])
def test_pipeline_failure_is_stage_bound_revoked_and_credential_free(
    pipeline, failure, cause, capsys
):
    p = pipeline
    p["mode"]["failure"] = failure
    with pytest.raises(ra.AdmissionError) as caught:
        gh.run_actions_phase(
            REPO,
            p["target"],
            phase="admit",
            private_key=str(p["key"]),
            ratification_pr=35,
            ratification_comment=7,
            run_id=123,
            authority_token="TEST_ONLY_AUTHORITY",
            output=p["output"],
        )
    decision = caught.value.decision
    expected = (
        "GITHUB_APP_TOKEN_SCOPE_MISMATCH"
        if failure == "scope"
        else "PRIOR_VERIFICATION_FAILED"
        if failure == "evidence"
        else "ADMISSION_UNKNOWN_ERROR"
        if failure == "unknown_evidence"
        else "CANDIDATE_FETCH_FAILED"
    )
    assert decision.decision_code == expected
    assert decision.failure_cause_code == cause
    assert decision.credential_session_issued and decision.credential_session_revoked
    assert p["revoked"] == [True]
    assert (
        not decision.authorized
        and not decision.eligible
        and not decision.retry_permitted
    )
    assert not p["output"].exists()
    assert "SUCCESS_EVIDENCE_OR_PUBLICATION" not in p["later"]
    assert p["later"] == (
        ["reconcile"] if failure in ("evidence", "unknown_evidence") else []
    )
    if failure in ("fetch", "auth_rejected", "timeout", "scope"):
        assert "checkout" not in p["calls"]
    if failure == "scope":
        assert p["calls"] == []
    visible = (
        ra.canonical(ra.decision_json(decision)).decode()
        + str(caught.value)
        + repr(caught.value)
        + "".join(traceback.format_exception(caught.type, caught.value, caught.tb))
    )
    captured = capsys.readouterr()
    visible += captured.out + captured.err
    assert SECRET not in visible
    assert "Authorization:" not in visible
    assert "TEST_ONLY_FAKE_KEY_NOT_SIGNING_MATERIAL" not in visible


def test_fake_git_success_checks_objects_and_checkout(pipeline):
    p = pipeline
    gh._acquire_candidate(p["target"], p["policy"], SECRET)
    assert p["calls"] == [
        "init",
        "fetch",
        "cat-file",
        "cat-file",
        "rev-parse",
        "checkout",
        "rev-parse",
    ]
    assert p["later"] == []


def test_controlled_real_git_repository_and_local_only_transport(tmp_path, monkeypatch):
    real_run = subprocess.run
    source = tmp_path / "inert-source"
    source.mkdir()

    def git(*args, cwd=source):
        return (
            real_run(
                ["git", "-c", "core.hooksPath=/dev/null", *args],
                cwd=cwd,
                capture_output=True,
                check=True,
            )
            .stdout.decode()
            .strip()
        )

    git("init")
    git("config", "user.name", "TEST ONLY")
    git("config", "user.email", "test@example.invalid")
    (source / "fixture.txt").write_text("inert base\n")
    git("add", ".")
    git("-c", "commit.gpgsign=false", "commit", "-m", "TEST ONLY base")
    base = git("rev-parse", "HEAD")
    (source / "fixture.txt").write_text("inert candidate\n")
    git("add", ".")
    git("-c", "commit.gpgsign=false", "commit", "-m", "TEST ONLY candidate")
    head, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
    policy = {"candidate": {"head_sha": head, "base_sha": base, "tree_sha": tree}}
    fetched = []

    def local_transport(args, **kwargs):
        args = list(args)
        if "fetch" in args:
            assert (
                args[args.index("fetch") + 1]
                == "https://github.com/" + ra.TARGET + ".git"
            )
            args[args.index("fetch") + 1] = str(source)
            fetched.append(True)
        return real_run(args, **kwargs)

    monkeypatch.setattr(gh.subprocess, "run", local_transport)
    target = tmp_path / "frozen"
    gh._acquire_candidate(target, policy, SECRET)
    assert fetched == [True]
    assert (target / "fixture.txt").read_text() == "inert candidate\n"
    gh._acquire_candidate(target, policy, SECRET)
    assert fetched == [
        True
    ]  # Existing data are still verified; never refetched blindly.
    git("checkout", "--detach", base, cwd=target)
    with pytest.raises(ra.AdmissionError) as caught:
        gh._acquire_candidate(target, policy, SECRET)
    assert (
        caught.value.decision.failure_cause_code
        == "CANDIDATE_GIT_OBJECT_VERIFICATION_HEAD_MISMATCH"
    )
