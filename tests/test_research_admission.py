"""Synthetic admission controls: no real authorization, network, App key or receipt.

The Git snapshot and frozen scientific inputs are real; API approval facts and
signing keys below are TEST ONLY and cannot publish an authenticated check.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jsonschema
import pytest

from miskatonic_review_authority import research_admission as ra
from miskatonic_review_authority import research_admission_github as gh

REPO = Path(__file__).resolve().parents[1]
TARGET_REPO = Path(
    os.environ.get("MSK_CAUSALIS_FROZEN_REPO", "/nonexistent-private-causalis-corpus")
)
NOW = datetime(2026, 10, 24, 21, 0, tzinfo=UTC)


def cmd(*args, cwd=None):
    return subprocess.check_output(list(args), cwd=cwd).decode().strip()


@pytest.fixture(scope="session")
def snapshot(tmp_path_factory):
    path = tmp_path_factory.mktemp("TEST_ONLY_auth") / "authority"
    subprocess.run(
        ["git", "clone", "--shared", str(REPO), str(path)],
        check=True,
        capture_output=True,
    )
    for name in (
        "src",
        "schemas",
        "roots",
        "policy",
        "reviews",
        "reports",
        ".github",
        "scripts",
    ):
        shutil.copytree(
            REPO / name,
            path / name,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
    cmd("git", "config", "user.name", "TEST ONLY synthetic authority", cwd=path)
    cmd("git", "config", "user.email", "test@example.invalid", cwd=path)
    cmd("git", "add", ".", cwd=path)
    cmd(
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-m",
        "TEST ONLY unratified snapshot",
        cwd=path,
    )
    root, policy = ra.load_contract(path)
    # Portable authority unit tests use a real synthetic53-path Git graph.
    # Only the separately marked integration check reads the private frozen corpus.
    packet_target = tmp_path_factory.mktemp("TEST_ONLY_packet_git")
    cmd("git", "init", str(packet_target))
    cmd("git", "config", "user.name", "TEST ONLY", cwd=packet_target)
    cmd("git", "config", "user.email", "test@example.invalid", cwd=packet_target)
    cmd(
        "git",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--allow-empty",
        "-m",
        "TEST ONLY base",
        cwd=packet_target,
    )
    base = cmd("git", "rev-parse", "HEAD", cwd=packet_target)
    for i in range(53):
        suffix = ".py" if i < 27 else ".json"
        (packet_target / (f"test_only_{i:02}" + suffix)).write_text(
            '"TEST ONLY inert data"\n'
        )
    cmd("git", "add", ".", cwd=packet_target)
    cmd(
        "git",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-m",
        "TEST ONLY candidate",
        cwd=packet_target,
    )
    packet_head = cmd("git", "rev-parse", "HEAD", cwd=packet_target)
    target_policy = json.loads((path / policy["target_policy_path"]).read_text())
    from miskatonic_review_authority.review_packet import build_review_packet

    prior = {
        "verdict": "PASS",
        "head_sha": policy["candidate"]["head_sha"],
        "base_sha": policy["candidate"]["base_sha"],
        "candidate_digest": policy["candidate"]["candidate_digest"],
        "test_only_synthetic": True,
    }
    packet, manifest = build_review_packet(
        repository=ra.TARGET,
        target_path=str(packet_target),
        base_sha=base,
        head_sha=packet_head,
        policy=target_policy,
        prior_evidence=prior,
    )
    bindings = json.loads((path / policy["producer_bindings_path"]).read_text())[
        "bindings"
    ]
    producer = next(
        b for b in bindings if b["repository"] == ra.TARGET and b["pr_number"] == 156
    )
    evidence = {
        "prior": prior,
        "packet": packet,
        "manifest": manifest,
        "producer": producer,
        "report_sha256": policy["review_report_sha256"],
        "target_policy": target_policy,
        "compensating": json.loads(
            (path / policy["compensating_evidence_path"]).read_text()
        ),
    }
    packet_policy = copy.deepcopy(policy)
    packet_policy["candidate"].update(base_sha=base, head_sha=packet_head)
    return path, root, policy, evidence, packet_target, packet_policy


@pytest.fixture
def case(snapshot):
    authority, root, policy, evidence, packet_target, packet_policy = snapshot
    root, policy, evidence = copy.deepcopy((root, policy, evidence))
    head = cmd("git", "rev-parse", "HEAD", cwd=authority)
    tree = cmd("git", "rev-parse", "HEAD^{tree}", cwd=authority)
    user = {"id": 267743825, "login": "kowen9024AI", "type": "User"}
    pr = {
        "number": 156,
        "state": "open",
        "merged": False,
        "user": user,
        "head": {
            "sha": policy["candidate"]["head_sha"],
            "repo": {"full_name": ra.TARGET},
        },
        "base": {
            "sha": policy["candidate"]["base_sha"],
            "repo": {"full_name": ra.TARGET},
        },
    }
    authority_pr = {
        "number": 9001,
        "merged": True,
        "merge_commit_sha": head,
        "head": {"sha": head, "repo": {"full_name": ra.AUTHORITY}},
        "base": {"repo": {"full_name": ra.AUTHORITY}},
    }
    issue = f"https://api.github.com/repos/{ra.AUTHORITY}/issues/9001"
    headers = {
        "AUTHORITY_REVIEW_REPOSITORY": ra.AUTHORITY,
        "AUTHORITY_REVIEW_HEAD": head,
        "AUTHORITY_REVIEW_TREE": tree,
        "REVIEWER_IDENTITY": "reported-agent:risk_admission_security_review:openai-codex",
        "REVIEWER_DISTINCT_FROM_IMPLEMENTER": "REPORTED",
        "REVIEWER_PROVIDER_DISTINCT": "NO",
        "REVIEWER_FILESYSTEM_ISOLATED": "NO",
        "INSTITUTIONAL_REVIEWER_SIGNATURE": "NOT_ESTABLISHED",
        "AUTHORITY_CHANGE_RISK_CLASS": "R2_SECURITY_OR_AUTHORITY_CHANGE",
        "VERDICT": "ACCEPT_WITH_LIMITATIONS",
    }
    security_text = (
        "\n".join(f"{k}: {v}" for k, v in headers.items())
        + "\nTEST ONLY. No production review/admission is asserted.\n"
    )
    security = {
        "id": 8,
        "body": security_text,
        "issue_url": issue,
        "user": user,
        "created_at": "2026-10-24T20:00:00Z",
        "updated_at": "2026-10-24T20:00:00Z",
    }
    ratification = {
        "schema_version": "research-authority-ratification-v1",
        "purpose": "RATIFY_EXTERNAL_EVIDENCE_ADMISSION_V1",
        "authority_accepted_head_sha": head,
        "authority_accepted_tree_sha": tree,
        "authority_root_sha256": ra.byte_digest(
            (authority / ra.ROOT_PATH).read_bytes()
        ),
        "authority_policy_sha256": ra.byte_digest(
            (authority / ra.POLICY_PATH).read_bytes()
        ),
        "candidate_digest": policy["candidate"]["candidate_digest"],
        "human_review_attestation": "I personally reviewed and authorize this exact bounded research risk decision.",
        "limitations": policy["limitations"],
        "authority_change_risk_class": "R2_SECURITY_OR_AUTHORITY_CHANGE",
        "accept_bootstrap_independence_limits": True,
        "security_review_comment_id": 8,
        "security_review_sha256": ra.byte_digest(security_text.encode()),
    }
    comment = {
        "id": 7,
        "body": json.dumps(ratification),
        "user": user,
        "issue_url": issue,
        "created_at": "2026-10-24T20:00:00Z",
        "updated_at": "2026-10-24T20:00:00Z",
        "performed_via_github_app": None,
    }
    workflow = {
        "id": 123,
        "head_sha": head,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": ra.WORKFLOW_PATH,
        "repository": {"full_name": ra.AUTHORITY},
        "actor": user,
    }
    environment = {
        "id": 4,
        "name": ra.ENVIRONMENT,
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": False,
                "reviewers": [{"type": "User", "reviewer": user}],
            }
        ],
    }
    facts = {
        "canonical_authority_sha": head,
        "workflow": workflow,
        "target_pr": pr,
        "candidate_tree_sha": policy["candidate"]["tree_sha"],
        "ratification_pr": authority_pr,
        "ratification_comment": comment,
        "authority_security_review": security,
        "resolved_principal": user,
        "environment": environment,
        "approval_history": [],
    }
    facts["ratification_identity"] = ra.verify_ratification(
        authority, root, policy, facts
    )
    runs = []
    for i, expected in enumerate(policy["ci_runs"]):
        run = {
            **expected,
            "status": "completed",
            "conclusion": "failure",
            "head_sha": policy["candidate"]["head_sha"],
        }
        job = {
            "id": 100 + i,
            "run_id": run["id"],
            "head_sha": run["head_sha"],
            "steps": [],
            "conclusion": "failure",
        }
        runs.append(
            {
                "run": run,
                "jobs": [
                    {
                        "job": job,
                        "annotations": [
                            {
                                "annotation_level": "failure",
                                "message": ra.STARTUP_FAILURE + " TEST ONLY",
                            }
                        ],
                    }
                ],
            }
        )
    ci = ra.assess_ci(policy, runs, evidence["compensating"])
    request = ra.build_request(authority, policy, evidence, ci, head, 123)
    approval = {
        "schema_version": "research-human-authorization-v1",
        "purpose": "ADMIT_EXACT_CAUSALIS_RESEARCH",
        "authority_head_sha": head,
        "authority_root_sha256": request["authority_root_reference"]["sha256"],
        "authority_policy_sha256": request["authority_policy_reference"]["sha256"],
        "candidate_digest": request["candidate_digest"],
        "request_digest": ra.digest(request),
        "ci_assessment_digest": ra.digest(ci),
        "expires_at": (NOW + timedelta(hours=12)).isoformat(),
        "human_review_attestation": "I personally reviewed and authorize this exact bounded research risk decision.",
        "accept_independence_limitations": True,
        "accept_ci_compensating_controls": True,
        "limitations": policy["limitations"],
    }
    facts["approval_history"] = [
        {
            "state": "approved",
            "comment": json.dumps(approval),
            "user": user,
            "environments": [{"id": 4, "name": ra.ENVIRONMENT}],
        }
    ]
    return {
        "authority": authority,
        "root": root,
        "policy": policy,
        "evidence": evidence,
        "facts": facts,
        "request": request,
        "ci": ci,
        "runs": runs,
        "approval": approval,
        "packet_target": packet_target,
        "packet_policy": packet_policy,
    }


def decision(c):
    return ra.decide(
        c["authority"],
        c["root"],
        c["policy"],
        c["request"],
        c["evidence"],
        c["facts"],
        c["ci"],
        NOW,
    )


def reject(c, code=None):
    with pytest.raises(ra.AdmissionError) as caught:
        decision(c)
    if code:
        assert caught.value.code == code
    assert not caught.value.decision.authorized
    assert not caught.value.decision.external_side_effect
    return caught.value.code


def test_synthetic_complete_route_requires_all_evidence(case):
    result = decision(case)
    assert result.eligible and result.authorized
    assert not result.external_side_effect
    assert result.authorization_identity["producer_approver_account_overlap"] is True
    assert "This admission is not release authorization." in result.required_followups


def test_T01_head_changed(case):
    case["facts"]["target_pr"]["head"]["sha"] = "1" * 40
    reject(case, "CANDIDATE_HEAD_STALE")


def test_T02_base_changed(case):
    case["facts"]["target_pr"]["base"]["sha"] = "1" * 40
    reject(case, "CANDIDATE_BASE_MISMATCH")


def test_T03_foreign_repository_or_pr(case):
    case["facts"]["target_pr"]["number"] = 155
    reject(case, "AUTHORIZATION_SCOPE_MISMATCH")
    case["facts"]["target_pr"]["number"] = 156
    case["facts"]["target_pr"]["head"]["repo"]["full_name"] = "foreign/repository"
    reject(case, "AUTHORIZATION_SCOPE_MISMATCH")


def test_T04_report_digest_substitution(case):
    case["request"]["review_report_sha256"] = "1" * 64
    reject(case, "ADMISSION_REQUEST_EVIDENCE_MISMATCH")


def test_T05_historical_R1_report_reuse(case):
    case["request"]["review_report_reference"]["path"] = (
        "artifacts/causalis-b2-exact-edge-reconciliation-00a-r1/independent_b2_r1_review.md"
    )
    reject(case, "ADMISSION_REQUEST_EVIDENCE_MISMATCH")


def test_T06_wrong_review_head(case):
    case["facts"]["authority_security_review"]["body"] = case["facts"][
        "authority_security_review"
    ]["body"].replace(case["facts"]["canonical_authority_sha"], "1" * 40)
    reject(case, "REVIEW_REPORT_HASH_MISMATCH")


def test_T07_omitted_material_limitation(case):
    case["request"]["review_limitations"].remove("SHARED_FILESYSTEM")
    reject(case, "ADMISSION_REQUEST_EVIDENCE_MISMATCH")


def test_T08_generated_promoted_to_full_review(case):
    packet, manifest = copy.deepcopy(
        (case["evidence"]["packet"], case["evidence"]["manifest"])
    )
    row = next(
        r
        for r in manifest["files"]
        if r["classification"] == "HASH_BOUND_GENERATED_ARTIFACT"
    )
    path = row["path"]
    row["classification"] = "FULL_DIFF_REVIEWED"
    next(r for r in packet["changed_file_manifest"] if r["path"] == path)[
        "classification"
    ] = "FULL_DIFF_REVIEWED"
    with pytest.raises(ra.AdmissionError, match="REVIEW_PACKET_INCOMPLETE"):
        ra.verify_packet(
            case["packet_target"],
            case["packet_policy"],
            case["evidence"]["target_policy"],
            packet,
            manifest,
        )


def test_T09_missing_path(case):
    packet, manifest = copy.deepcopy(
        (case["evidence"]["packet"], case["evidence"]["manifest"])
    )
    packet["changed_file_manifest"].pop()
    manifest["files"].pop()
    with pytest.raises(ra.AdmissionError, match="REVIEW_PACKET_INCOMPLETE"):
        ra.verify_packet(
            case["packet_target"],
            case["packet_policy"],
            case["evidence"]["target_policy"],
            packet,
            manifest,
        )


def test_T10_allowlist_expansion_cannot_replace_pinned_policy(case):
    case["request"]["target_policy_reference"]["sha256"] = "1" * 64
    reject(case, "ADMISSION_REQUEST_EVIDENCE_MISMATCH")


def test_T11_producer_claims_reviewer(case):
    case["request"]["reviewer_identity"] = case["evidence"]["producer"][
        "producer_principal"
    ]
    reject(case, "ADMISSION_REQUEST_EVIDENCE_MISMATCH")


def test_T12_shared_review_claimed_isolated(case):
    case["request"]["reviewer_independence_class"] = "OS_ISOLATED_REVIEW"
    reject(case, "ADMISSION_REQUEST_EVIDENCE_MISMATCH")


def test_T13_local_check_impersonation_rejected_by_schema(case):
    case["request"]["check_name"] = "miskatonic/independent-local-review"
    with pytest.raises(ra.AdmissionError, match="SCHEMA_VALIDATION_FAILED"):
        ra.validate_schema(
            case["request"], "research-admission-request-v1", case["authority"]
        )
    assert gh.CHECK_NAME == "miskatonic/research-evidence-admission"


def test_T14_untrusted_ratification(case):
    case["facts"]["ratification_comment"]["user"] = {
        "id": 1,
        "login": "attacker",
        "type": "User",
    }
    reject(case, "AUTHORIZATION_PRINCIPAL_INVALID")


def test_T15_forged_supplied_github_actor(case):
    case["facts"]["approval_history"][0]["user"] = {
        "id": 1,
        "login": "kowen9024AI",
        "type": "User",
    }
    reject(case, "AUTHORIZATION_PRINCIPAL_INVALID")


def test_T18_hosted_failure_never_pass(case):
    assert case["ci"]["hosted_ci_pass"] is False
    assert (
        case["ci"]["state"]
        == "HOSTED_CI_INFRASTRUCTURE_UNAVAILABLE_WITH_COMPENSATING_EVIDENCE"
    )
    case["approval"]["accept_ci_compensating_controls"] = False
    case["facts"]["approval_history"][0]["comment"] = json.dumps(case["approval"])
    reject(case, "SCHEMA_VALIDATION_FAILED")


def test_T19_executed_test_failure_not_startup(case):
    case["runs"][0]["jobs"][0]["job"]["steps"] = [
        {"name": "pytest", "conclusion": "failure"}
    ]
    with pytest.raises(ra.AdmissionError, match="HOSTED_CI_EXCEPTION_NOT_ELIGIBLE"):
        ra.assess_ci(case["policy"], case["runs"], case["evidence"]["compensating"])


def test_T20_foreign_PR_scope(case):
    case["request"]["pr_number"] = 157
    reject(case, "ADMISSION_REQUEST_EVIDENCE_MISMATCH")


def test_T21_future_head_scope(case):
    case["request"]["head_sha"] = "2" * 40
    reject(case, "ADMISSION_REQUEST_EVIDENCE_MISMATCH")


def test_T22_expired_and_revoked(case):
    case["approval"]["expires_at"] = (NOW - timedelta(seconds=1)).isoformat()
    case["facts"]["approval_history"][0]["comment"] = json.dumps(case["approval"])
    reject(case, "AUTHORIZATION_EXPIRED")
    case["policy"]["revoked"] = True
    reject(case, "AUTHORIZATION_REVOKED")


def test_T24_unknown_version(case):
    case["request"]["schema_version"] = "research-admission-request-v999"
    reject(case, "ADMISSION_REQUEST_EVIDENCE_MISMATCH")
    with pytest.raises(ra.AdmissionError, match="SCHEMA_VALIDATION_FAILED"):
        ra.validate_schema(
            case["request"], "research-admission-request-v1", case["authority"]
        )


def test_T25_unreviewed_authority_commit(case):
    case["facts"]["workflow"]["head_sha"] = "1" * 40
    reject(case, "ADMISSION_POLICY_NOT_RATIFIED")


def test_T26_schema_error_fails_closed(case):
    case["approval"]["ignore_required_checks"] = True
    case["facts"]["approval_history"][0]["comment"] = json.dumps(case["approval"])
    reject(case, "SCHEMA_VALIDATION_FAILED")


def test_T27_dispatch_is_not_authorization(case):
    case["facts"]["approval_history"] = []
    reject(case, "AUTHORIZATION_MISSING")


def test_T28_compromised_review_despite_prior_PASS(case):
    assert case["evidence"]["prior"]["verdict"] == "PASS"
    case["facts"]["authority_security_review"]["body"] += "tampered"
    reject(case, "REVIEW_REPORT_HASH_MISMATCH")


@pytest.mark.parametrize(
    "route,risk,expected",
    [
        (
            ra.LOCAL_ROUTE,
            "R3_HIGH_CONSEQUENCE_OPERATION",
            "EXISTING_LOCAL_REVIEW_V2_1_IMPLEMENTATION",
        ),
        (ra.ROUTE, "R1_EXPERIMENTAL_RESEARCH", ra.ROUTE),
    ],
)
def test_explicit_route_selection_preserves_local(route, risk, expected):
    assert ra.select_route(route, risk) == expected


@pytest.mark.parametrize(
    "risk",
    [
        "R0_DOCUMENTARY",
        "R2_SECURITY_OR_AUTHORITY_CHANGE",
        "R3_HIGH_CONSEQUENCE_OPERATION",
    ],
)
def test_external_does_not_enroll_other_risks(risk):
    with pytest.raises(ra.AdmissionError, match="RISK_CLASS_NOT_ELIGIBLE"):
        ra.select_route(ra.ROUTE, risk)


def test_unknown_route_never_falls_back():
    with pytest.raises(ra.AdmissionError, match="ADMISSION_ROUTE_NOT_ALLOWED"):
        ra.select_route("skip_local_review", "R1_EXPERIMENTAL_RESEARCH")


def test_dispatcher_is_not_producer_identity(case):
    case["facts"]["workflow"]["actor"] = {"id": 999, "login": "TEST-bot", "type": "Bot"}
    assert (
        decision(case).authorization_identity["producer_approver_account_overlap"]
        is True
    )


def test_unprotected_auto_created_environment_is_rejected(case):
    case["facts"]["environment"]["protection_rules"] = []
    reject(case, "AUTHORIZATION_MISSING")


def test_approval_edit_and_authority_review_binding(case):
    case["facts"]["ratification_comment"]["updated_at"] = "2026-10-24T20:01:00Z"
    reject(case, "AUTHORIZATION_SCOPE_MISMATCH")


def test_strict_json_rejects_duplicate_nan_and_unknown(case):
    for data in ('{"a":1,"a":2}', '{"a":NaN}'):
        with pytest.raises(ra.AdmissionError, match="SCHEMA_VALIDATION_FAILED"):
            ra.strict_json(data)
    case["request"]["prior_verification"] = "PASS"
    with pytest.raises(ra.AdmissionError, match="SCHEMA_VALIDATION_FAILED"):
        ra.validate_schema(
            case["request"], "research-admission-request-v1", case["authority"]
        )


def test_schema_contracts_are_closed_and_well_formed(case):
    for path in (case["authority"] / "schemas").glob("research-*.schema.json"):
        schema = json.loads(path.read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False
    for value, name in [
        (case["root"], "research-admission-authority-root-v1"),
        (case["policy"], "research-admission-policy-v1"),
        (case["request"], "research-admission-request-v1"),
    ]:
        ra.validate_schema(value, name, case["authority"])


def test_legacy_target_schema_is_preserved_and_not_passing():
    path = "schemas/scientific-target-policy-v1.schema.json"
    assert (REPO / path).read_bytes() == ra.git_bytes(
        REPO, "a87e863173950c7f73072d1647780b3492ab0a43", path
    )
    policy = json.loads(
        (REPO / "policy/targets/msk-ruliology-causalis-b2-r1-v2.json").read_text()
    )
    schema = json.loads((REPO / path).read_text())
    assert list(jsonschema.Draft202012Validator(schema).iter_errors(policy))
    assert policy["schema_version"] == "scientific-target-policy-v1"


@pytest.mark.skipif(
    not (TARGET_REPO / ".git").exists(),
    reason="Private frozen corpus not provisioned; all portable T01-T28 controls still run",
)
def test_frozen_causalis_integration_reconciles_actual53_paths(snapshot):
    authority, _root, policy, _, _, _ = snapshot
    evidence = ra.reconcile_candidate(authority, TARGET_REPO, policy)
    assert evidence["prior"]["verdict"] == "PASS"
    assert evidence["manifest"]["total_changed_files"] == 53


class FakeGitHub:
    """TEST ONLY in-memory API; cannot perform network or publish a real check."""

    def __init__(self, case):
        self.case = case
        self.checks = {}
        self.mutations = []
        self.pr_reads = 0
        self.head_moves_on = None
        self.fail_readback = False

    def api(self, method, path, payload=None, **kwargs):
        c = self.case
        if method == "GET" and path.endswith("/pulls/156"):
            self.pr_reads += 1
            result = copy.deepcopy(c["facts"]["target_pr"])
            if self.head_moves_on and self.pr_reads >= self.head_moves_on:
                result["head"]["sha"] = "1" * 40
            return result
        if method == "GET" and path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": c["facts"]["canonical_authority_sha"]}}
        if method == "GET" and "/environments/" in path:
            return copy.deepcopy(c["facts"]["environment"])
        if method == "GET" and path.endswith("/approvals"):
            return copy.deepcopy(c["facts"]["approval_history"])
        if method == "GET" and path.endswith("/issues/comments/7"):
            return copy.deepcopy(c["facts"]["ratification_comment"])
        if method == "GET" and path.endswith("/issues/comments/8"):
            return copy.deepcopy(c["facts"]["authority_security_review"])
        if method == "POST" and path.endswith("/check-runs"):
            self.mutations.append((method, path, copy.deepcopy(payload)))
            number = len(self.checks) + 1
            self.checks[number] = {
                "id": number,
                "app": {"id": c["policy"]["expected_app_id"]},
                **copy.deepcopy(payload),
            }
            return copy.deepcopy(self.checks[number])
        if "/check-runs/" in path:
            number = int(path.rsplit("/", 1)[1])
            if method == "GET":
                if self.fail_readback:
                    self.fail_readback = False
                    raise OSError("TEST ONLY ambiguous network response")
                return copy.deepcopy(self.checks[number])
            if method == "PATCH":
                self.mutations.append((method, path, copy.deepcopy(payload)))
                self.checks[number].update(copy.deepcopy(payload))
                return copy.deepcopy(self.checks[number])
        if method == "DELETE" and path == "/installation/token":
            return None
        raise AssertionError(f"Unexpected TEST ONLY API operation: {method} {path}")


class MemoryLedger:
    """TEST ONLY authority-custody simulation; never creates production receipts."""

    receipt_path = "admissions/TEST_ONLY/receipt.json"

    def __init__(self):
        self.state = None
        self.objects = {}
        self.writes = []

    def read(self):
        return copy.deepcopy(self.state)

    def write(self, state, receipt=None):
        self.writes.append(copy.deepcopy(state))
        self.state = copy.deepcopy(state)
        commit = ra.digest({"state": state, "receipt": receipt})[:40]
        if receipt is not None:
            self.objects[commit] = ra.canonical(receipt)
        return commit

    def read_file(self, commit, path):
        return self.objects.get(commit)


@pytest.fixture(scope="session")
def test_key(tmp_path_factory):
    path = tmp_path_factory.mktemp("TEST_ONLY_key") / "never-a-production-key.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(path),
        ],
        capture_output=True,
        check=True,
    )
    return path


@pytest.fixture
def publication(case, test_key, monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(gh, "datetime", Clock)
    api = FakeGitHub(case)
    ledger = MemoryLedger()

    def run():
        return gh.publish_admission(
            case["authority"],
            case["policy"],
            case["root"],
            case["request"],
            case["evidence"],
            case["facts"],
            case["ci"],
            api,
            api,
            str(test_key),
            NOW,
            ledger=ledger,
        )

    return case, api, ledger, run


def test_signed_synthetic_receipt_and_distinct_check_only(publication):
    c, api, ledger, run = publication
    result = run()
    receipt = result["receipt"]
    assert result["status"] == "ADMISSION_AUTHENTICATED"
    assert receipt["decision"] == "ADMITTED_RESEARCH_CONTRACT_ONLY"
    assert (
        receipt["release_authorized"] is False
        and receipt["local_review_executed"] is False
    )
    assert receipt["producer_approver_account_overlap"] is True
    assert ledger.state["status"] == "ADMITTED"
    assert all(
        p["name"] == ra.CHECK_NAME for method, _, p in api.mutations if method == "POST"
    )
    assert receipt["receipt_digest"] in api.checks[1]["output"]["summary"]
    assert (
        "HOSTED_CI_INFRASTRUCTURE_UNAVAILABLE_WITH_COMPENSATING_EVIDENCE"
        in api.checks[1]["output"]["summary"]
    )
    ra.validate_schema(receipt, "research-admission-receipt-v1", c["authority"])


def test_T16_wrong_target_app_token_scope(case, test_key, monkeypatch):
    class WrongScope:
        def __init__(self, token):
            pass

        def api(self, method, path, *args, **kwargs):
            if path == "/app":
                return {"id": 4497300}
            if path.startswith("/installation/repositories"):
                return {
                    "total_count": 2,
                    "repositories": [
                        {"full_name": ra.TARGET},
                        {"full_name": "unrelated/repo"},
                    ],
                }
            raise AssertionError(path)

    effects = {}
    monkeypatch.setattr(gh, "GitHub", WrongScope)
    monkeypatch.setattr(gh, "create_app_jwt", lambda *a, **k: "TEST_ONLY_NOT_REAL")
    monkeypatch.setattr(
        gh, "create_installation_token", lambda **k: {"token": "TEST_ONLY_NOT_REAL"}
    )
    with pytest.raises(ra.AdmissionError, match="GITHUB_APP_TOKEN_SCOPE_MISMATCH"):
        gh.target_token(str(test_key), 4497300, effects=effects)
    assert effects["credential_session_issued"] is True


def test_T17_unknown_error_does_not_expose_credentials(monkeypatch, capsys, tmp_path):
    import argparse

    from miskatonic_review_authority import cli

    def fail(*a, **k):
        raise RuntimeError("TEST_ONLY_SECRET_SENTINEL_MUST_NEVER_BE_LOGGED")

    monkeypatch.setattr(gh, "run_actions_phase", fail)
    args = argparse.Namespace(
        authority_path=".",
        target_path=".",
        phase="admit",
        private_key="TEST_ONLY",
        ratification_pr=1,
        ratification_comment=1,
        run_id=1,
        authority_token_env="NONEXISTENT_TEST_TOKEN",
        output=str(tmp_path / "unused.json"),
    )
    assert cli._research_admission_run(args) == 1
    output = capsys.readouterr().err
    assert "TEST_ONLY_SECRET_SENTINEL" not in output
    assert json.loads(output)["authorized"] is False
    assert json.loads(output)["decision_code"] == "ADMISSION_UNKNOWN_ERROR"


def test_T23_conflicting_duplicate_fails_without_second_check(publication):
    _c, api, ledger, run = publication
    run()
    before = len(api.mutations)
    ledger.state["evidence_digest"] = "1" * 64
    with pytest.raises(ra.AdmissionError, match="ADMISSION_LEDGER_CONFLICT"):
        run()
    assert len(api.mutations) == before


def test_identical_completed_request_is_idempotent(publication):
    _c, api, _ledger, run = publication
    first = run()
    before = len(api.mutations)
    second = run()
    assert second["status"] == "ALREADY_ADMITTED_IDENTICAL_REQUEST"
    assert second["receipt"] == first["receipt"] and len(api.mutations) == before
    assert second["release_authorized"] is False


def test_partial_publication_is_recorded_and_never_blindly_retried(publication):
    _c, api, ledger, run = publication
    api.fail_readback = True
    with pytest.raises(ra.AdmissionError, match="CHECK_PUBLICATION_PARTIAL") as result:
        run()
    assert result.value.decision.external_side_effect is True
    assert result.value.decision.retry_permitted is False
    assert result.value.decision.failure_cause_code == "ADMISSION_UNKNOWN_ERROR"
    assert ledger.state["status"] == "RECEIPT_PERSISTED"
    assert api.checks[1]["conclusion"] == "cancelled"
    before = len(api.mutations)
    with pytest.raises(ra.AdmissionError, match="CHECK_PUBLICATION_PARTIAL"):
        run()
    assert len(api.mutations) == before


def test_head_movement_before_success_never_publishes_success(publication):
    _c, api, _ledger, run = publication
    api.head_moves_on = 2
    with pytest.raises(ra.AdmissionError, match="CHECK_PUBLICATION_PARTIAL") as result:
        run()
    assert result.value.decision.failure_cause_code == "CANDIDATE_HEAD_STALE"
    assert not any(
        payload.get("conclusion") == "success" for _, _, payload in api.mutations
    )
    assert api.checks[1]["conclusion"] == "cancelled"


def test_invalid_request_has_no_signing_or_check_side_effect(publication, monkeypatch):
    c, api, ledger, run = publication
    c["request"]["head_sha"] = "1" * 40

    def forbidden(*args, **kwargs):
        raise AssertionError("No signing on rejected request")

    monkeypatch.setattr(gh, "key_identity", forbidden)
    with pytest.raises(ra.AdmissionError, match="ADMISSION_REQUEST_EVIDENCE_MISMATCH"):
        run()
    assert not api.mutations and not ledger.writes


def test_token_failure_effects_are_recorded_and_revoked(monkeypatch):
    effects_seen = {}

    class Token:
        def api(self, method, path):
            assert method == "DELETE" and path == "/installation/token"
            effects_seen["revoked"] = True

    def fail(*args, effects, **kwargs):
        effects.update(
            credential_use_started=True,
            credential_session_attempted=True,
            credential_session_issued=True,
            target_client=Token(),
        )
        raise ra.AdmissionError("GITHUB_APP_TOKEN_SCOPE_MISMATCH")

    monkeypatch.setattr(gh, "_run_actions_phase", fail)
    with pytest.raises(ra.AdmissionError) as result:
        gh.run_actions_phase()
    assert (
        result.value.decision.execution_began
        and result.value.decision.external_side_effect
    )
    assert (
        result.value.decision.credential_session_issued
        and result.value.decision.credential_session_revoked
    )
    assert effects_seen["revoked"]


def test_generic_publisher_cannot_impersonate_new_route():
    import argparse

    from miskatonic_review_authority import cli

    with pytest.raises(ra.AuthorityError, match="ADMISSION_ROUTE_REQUIRED"):
        cli._publish_check(argparse.Namespace(name=ra.CHECK_NAME))


def test_branch_execution_rejected_before_key_or_network(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", ra.AUTHORITY)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/UNRATIFIED_TEST_BRANCH")
    with pytest.raises(ra.AdmissionError, match="ADMISSION_POLICY_NOT_RATIFIED"):
        gh.run_actions_phase(
            tmp_path,
            tmp_path / "target",
            phase="admit",
            private_key="NEVER_READ_TEST_PATH",
            ratification_pr=1,
            ratification_comment=1,
            run_id=1,
            authority_token="TEST_ONLY",
            output=tmp_path / "unused.json",
        )
    assert not (tmp_path / "target").exists()


def test_both_policy_and_root_cannot_nominate_an_attacker(case):
    attacker = {"github_id": 1, "github_login": "attacker", "github_type": "User"}
    case["root"]["ratifying_principal"] = attacker
    case["policy"]["authorization_principal"] = attacker
    reject(case, "AUTHORIZATION_PRINCIPAL_INVALID")


def test_security_report_requires_exact_tree_and_disclosures(case):
    text = case["facts"]["authority_security_review"]["body"].replace(
        "REVIEWER_FILESYSTEM_ISOLATED: NO", "REVIEWER_FILESYSTEM_ISOLATED: YES"
    )
    case["facts"]["authority_security_review"]["body"] = text
    body = json.loads(case["facts"]["ratification_comment"]["body"])
    body["security_review_sha256"] = ra.byte_digest(text.encode())
    case["facts"]["ratification_comment"]["body"] = json.dumps(body)
    reject(case, "REVIEW_HEAD_MISMATCH")


def test_unrecognized_risk_never_falls_back_to_local():
    with pytest.raises(ra.AdmissionError, match="RISK_CLASS_NOT_ELIGIBLE"):
        ra.select_route(ra.LOCAL_ROUTE, "UNKNOWN_RISK")


def test_packet_blob_substitution_and_diff_truncation(case):
    packet, manifest = copy.deepcopy(
        (case["evidence"]["packet"], case["evidence"]["manifest"])
    )
    packet["changed_file_manifest"][0]["git_blob_sha"] = "1" * 40
    manifest["files"][0]["git_blob_sha"] = "1" * 40
    with pytest.raises(ra.AdmissionError, match="REVIEW_PACKET_INCOMPLETE"):
        ra.verify_packet(
            case["packet_target"],
            case["packet_policy"],
            case["evidence"]["target_policy"],
            packet,
            manifest,
        )
    packet, manifest = copy.deepcopy(
        (case["evidence"]["packet"], case["evidence"]["manifest"])
    )
    packet["source_diff"] = packet["source_diff"][:-1]
    with pytest.raises(ra.AdmissionError, match="REVIEW_PACKET_INCOMPLETE"):
        ra.verify_packet(
            case["packet_target"],
            case["packet_policy"],
            case["evidence"]["target_policy"],
            packet,
            manifest,
        )


def test_ci_cause_unknown_and_baseline_unmatched(case):
    case["runs"][0]["jobs"][0]["annotations"] = []
    with pytest.raises(ra.AdmissionError, match="HOSTED_CI_CAUSE_UNVERIFIED"):
        ra.assess_ci(case["policy"], case["runs"], case["evidence"]["compensating"])


def test_strict_dates_and_policy_versions(case):
    policy = copy.deepcopy(case["policy"])
    policy["expires_at"] = "tomorrow"
    with pytest.raises(ra.AdmissionError, match="SCHEMA_VALIDATION_FAILED"):
        ra.validate_schema(policy, "research-admission-policy-v1", case["authority"])
    policy = copy.deepcopy(case["policy"])
    policy["policy_version"] = "999.0.0"
    with pytest.raises(ra.AdmissionError, match="SCHEMA_VALIDATION_FAILED"):
        ra.validate_schema(policy, "research-admission-policy-v1", case["authority"])


def test_v2_schema_design_requires_digest_manifest_and_rejects_unknown_fields():
    schema = json.loads(
        (REPO / "schemas/scientific-target-policy-v2.schema.json").read_text()
    )
    policy = json.loads(
        (REPO / "policy/targets/msk-ruliology-causalis-b2-r1-v2.json").read_text()
    )
    policy["schema_version"] = "scientific-target-policy-v2"
    policy["pinned_evidence_digests"] = dict.fromkeys(
        schema["properties"]["pinned_evidence_digests"]["required"], "a" * 64
    )
    jsonschema.Draft202012Validator(schema).validate(policy)
    policy["pinned_evidence_digests"] = {}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(policy)
    policy["pinned_evidence_digests"] = dict.fromkeys(
        schema["properties"]["pinned_evidence_digests"]["required"], "a" * 64
    )
    policy["allow_unsigned"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(policy)


def test_all_historical_authority_bytes_preserved_except_reviewed_cli_ci_changes():
    base = "a87e863173950c7f73072d1647780b3492ab0a43"
    paths = ra.git(REPO, "ls-tree", "-r", "--name-only", base).decode().splitlines()
    allowed = {
        "src/miskatonic_review_authority/cli.py",
        ".github/workflows/authority-ci.yml",
    }
    for path in paths:
        if path not in allowed:
            assert (REPO / path).read_bytes() == ra.git_bytes(REPO, base, path), path


def test_ledger_uses_authority_only_nonforced_updates(case):
    class Storage:
        def __init__(self):
            self.ref = None
            self.mutations = []
            self.n = 0

        def api(self, method, path, payload=None, **kwargs):
            assert path.startswith("/repos/" + ra.AUTHORITY + "/")
            if method == "GET" and "/git/ref/" in path:
                return {"object": {"sha": self.ref}} if self.ref else None
            if method == "GET" and "/git/commits/" in path:
                return {"tree": {"sha": "a" * 40}}
            if method == "GET" and "/contents/" in path:
                return None
            self.mutations.append((method, path, copy.deepcopy(payload)))
            self.n += 1
            if path.endswith("/git/refs"):
                assert payload["ref"] == "refs/" + gh.AuthorityLedger.REF
                self.ref = payload["sha"]
                return {"object": {"sha": self.ref}}
            if method == "PATCH" and "/git/refs/" in path:
                assert payload["force"] is False
                self.ref = payload["sha"]
                return {"object": {"sha": self.ref}}
            return {"sha": f"{self.n:040x}"}

    api = Storage()
    ledger = gh.AuthorityLedger(api, case["facts"]["canonical_authority_sha"], "0" * 64)
    assert ledger.read() is None
    ledger.write({"status": "TEST_ONLY_RESERVED"})
    ledger.write({"status": "TEST_ONLY_RECONCILED"})
    assert any(
        method == "PATCH" and payload.get("force") is False
        for method, _, payload in api.mutations
    )
    assert not any("/heads/main" in path for _, path, _ in api.mutations)
