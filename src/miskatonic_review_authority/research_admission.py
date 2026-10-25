"""Scoped external research admission. Evidence qualification never authorizes release.

Production callers must obtain authenticated facts through research_admission_github.
No model, candidate code, local reviewer identity, or private-key fallback is used here.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jsonschema

from .canonical_digest import changed_records
from .prior_verifier import run_prior_verification
from .util import AuthorityError

AUTHORITY = "Miskatonic-System/miskatonic-review-authority"
TARGET = "Miskatonic-System/msk-ruliology"
ROUTE = "EXTERNAL_EVIDENCE_ADMISSION_V1"
LOCAL_ROUTE = "LOCAL_REVIEW_V2_1"
CHECK_NAME = "miskatonic/research-evidence-admission"
POLICY_PATH = "policy/research-admission/causalis-b2-r2-v1.json"
ROOT_PATH = "roots/research-admission-authority-v1.json"
WORKFLOW_PATH = ".github/workflows/admit-research-evidence.yml"
EXACT_CASE = {
    "repository": TARGET,
    "pr_number": 156,
    "base_sha": "d90892e3c2fdd66f2ffb13b17f7302b8689a9ced",
    "head_sha": "089cec23afe6c15df9d7f085f4a0e3c298bd776a",
    "tree_sha": "a9d867a34ad21524a8f835774bca29ad33a8300d",
    "candidate_digest": "c70a9d2add189ae490ebcb7bc2ae06ee13e966827d6e6c10d7d341c67d880621",
}
ENVIRONMENT = "research-evidence-admission"
STARTUP_FAILURE = "The job was not started because recent account payments have failed or your spending limit needs to be increased."


def canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def byte_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def strict_json(data: str | bytes) -> Any:
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out

    def bad_constant(_):
        raise ValueError("nonfinite JSON value")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=bad_constant)
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise AdmissionError("SCHEMA_VALIDATION_FAILED") from exc


@dataclass(frozen=True)
class AdmissionDecision:
    eligible: bool
    authorized: bool
    decision_code: str
    policy_identity: dict
    candidate_identity: dict
    evidence_identity: dict
    authorization_identity: dict
    limitations: list[str]
    required_followups: list[str]
    execution_began: bool = False
    external_side_effect: bool = False
    retry_permitted: bool = False
    retry_evidence_required: str = (
        "Correct the named evidence or obtain new bounded authorization."
    )
    candidate_remains_eligible: bool = False
    credential_session_issued: bool = False
    credential_session_revoked: bool = False
    failure_cause_code: str | None = None


class AdmissionError(AuthorityError):
    def __init__(self, code: str, *, side_effect: bool = False):
        super().__init__(code)
        self.decision = AdmissionDecision(
            False,
            False,
            code,
            {},
            {},
            {},
            {},
            [],
            ["No success check or release authorization may be inferred."],
            execution_began=side_effect,
            external_side_effect=side_effect,
            retry_permitted=False,
            retry_evidence_required=(
                "Reconcile credential sessions, authority ledger, and GitHub check state before retry."
                if side_effect
                else "Supply valid evidence under a ratified scoped policy."
            ),
        )


def require(condition: bool, code: str) -> None:
    if not condition:
        raise AdmissionError(code)


def validate_schema(value: Any, schema_name: str, authority: Path) -> None:
    try:
        schema = strict_json(
            (authority / "schemas" / (schema_name + ".schema.json")).read_bytes()
        )
        jsonschema.Draft202012Validator.check_schema(schema)
        checker = jsonschema.FormatChecker()

        @checker.checks("date-time", raises=(ValueError, TypeError))
        def date_time(text):
            if type(text) is not str or not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})",
                text,
            ):
                return False
            return datetime.fromisoformat(text).tzinfo is not None

        jsonschema.Draft202012Validator(schema, format_checker=checker).validate(value)
    except (
        OSError,
        jsonschema.exceptions.SchemaError,
        jsonschema.ValidationError,
    ) as exc:
        raise AdmissionError("SCHEMA_VALIDATION_FAILED") from exc


def git(root: Path, *args: str) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, check=False
    )
    if proc.returncode:
        raise AdmissionError("EVIDENCE_GIT_OBJECT_UNAVAILABLE")
    return proc.stdout


def safe_path(path: str) -> str:
    require(
        type(path) is str
        and bool(re.fullmatch(r"[A-Za-z0-9_./-]+", path))
        and not path.startswith("/")
        and all(p not in ("", ".", "..") for p in path.split("/")),
        "AUTHORIZATION_SCOPE_MISMATCH",
    )
    return path


def git_bytes(root: Path, commit: str, path: str) -> bytes:
    require(
        type(commit) is str and bool(re.fullmatch(r"[0-9a-f]{40}", commit)),
        "AUTHORIZATION_SCOPE_MISMATCH",
    )
    return git(root, "show", f"{commit}:{safe_path(path)}")


def utc(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value)
        require(result.tzinfo is not None, "AUTHORIZATION_EXPIRED")
        return result.astimezone(UTC)
    except (ValueError, TypeError, AttributeError) as exc:
        raise AdmissionError("AUTHORIZATION_EXPIRED") from exc


def select_route(route: str, risk_class: str) -> str:
    require(
        risk_class
        in {
            "R0_DOCUMENTARY",
            "R1_EXPERIMENTAL_RESEARCH",
            "R2_SECURITY_OR_AUTHORITY_CHANGE",
            "R3_HIGH_CONSEQUENCE_OPERATION",
        },
        "RISK_CLASS_NOT_ELIGIBLE",
    )
    require(route in (LOCAL_ROUTE, ROUTE), "ADMISSION_ROUTE_NOT_ALLOWED")
    if route == LOCAL_ROUTE:
        return "EXISTING_LOCAL_REVIEW_V2_1_IMPLEMENTATION"
    require(risk_class == "R1_EXPERIMENTAL_RESEARCH", "RISK_CLASS_NOT_ELIGIBLE")
    return ROUTE


def load_contract(authority: Path) -> tuple[dict, dict]:
    root = strict_json((authority / ROOT_PATH).read_bytes())
    policy = strict_json((authority / POLICY_PATH).read_bytes())
    validate_schema(root, "research-admission-authority-root-v1", authority)
    validate_schema(policy, "research-admission-policy-v1", authority)
    require(policy["candidate"] == EXACT_CASE, "AUTHORIZATION_SCOPE_MISMATCH")
    require(
        root["ratifying_principal"]
        == policy["authorization_principal"]
        == {
            "github_id": 267743825,
            "github_login": "kowen9024AI",
            "github_type": "User",
        },
        "AUTHORIZATION_PRINCIPAL_INVALID",
    )
    require(
        root["predecessor_commit"]
        == policy["predecessor_authority_commit"]
        == "a87e863173950c7f73072d1647780b3492ab0a43",
        "ADMISSION_POLICY_NOT_RATIFIED",
    )
    require(
        policy["review_report_path"]
        == "reviews/msk-ruliology-causalis-b2-r2-089cec23.md"
        and policy["review_report_sha256"]
        == "afe7911a3f32271faf02221e34fd5ad730a1bd6dee73787c04fe65db226e9c22",
        "REVIEW_REPORT_HASH_MISMATCH",
    )
    for path_key, hash_key in (
        ("target_policy_path", "target_policy_sha256"),
        ("producer_bindings_path", "producer_binding_sha256"),
    ):
        predecessor = git_bytes(authority, root["predecessor_commit"], policy[path_key])
        require(
            byte_digest(predecessor) == policy[hash_key],
            "TARGET_POLICY_IDENTITY_MISMATCH",
        )
    require(
        root["policy_path"] == POLICY_PATH
        and root["policy_sha256"]
        == byte_digest((authority / POLICY_PATH).read_bytes()),
        "ADMISSION_POLICY_NOT_RATIFIED",
    )
    require(not root["revoked"] and not policy["revoked"], "AUTHORIZATION_REVOKED")
    select_route(policy["admission_route"], policy["risk_class"])
    for key in ("predecessor_root", "preserved_local_review_policy"):
        item = root[key]
        require(
            byte_digest((authority / safe_path(item["path"])).read_bytes())
            == item["sha256"],
            "HISTORICAL_AUTHORITY_MODIFIED",
        )
    for item in root["implementation_objects"]:
        data = (authority / safe_path(item["path"])).read_bytes()
        oid = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
        require(
            byte_digest(data) == item["sha256"] and oid == item["git_blob_sha"],
            "ADMISSION_POLICY_NOT_RATIFIED",
        )
    return root, policy


def assess_ci(policy: dict, runs: list[dict], compensating: dict) -> dict:
    expected = {(r["id"], r["name"]) for r in policy["ci_runs"]}
    require(
        len(runs) == len(expected)
        and {(r["run"]["id"], r["run"]["name"]) for r in runs} == expected,
        "HOSTED_CI_CAUSE_UNVERIFIED",
    )
    jobs = []
    for item in runs:
        run = item["run"]
        require(
            run["head_sha"] == policy["candidate"]["head_sha"]
            and run["conclusion"] == "failure"
            and run["status"] == "completed",
            "HOSTED_CI_CAUSE_UNVERIFIED",
        )
        require(bool(item["jobs"]), "HOSTED_CI_CAUSE_UNVERIFIED")
        for pair in item["jobs"]:
            job = pair["job"]
            require(
                job["run_id"] == run["id"] and job["head_sha"] == run["head_sha"],
                "HOSTED_CI_CAUSE_UNVERIFIED",
            )
            require(job.get("steps") == [], "HOSTED_CI_EXCEPTION_NOT_ELIGIBLE")
            require(
                job["conclusion"] == "failure"
                and any(
                    a.get("annotation_level") == "failure"
                    and a.get("message", "").startswith(STARTUP_FAILURE)
                    for a in pair["annotations"]
                ),
                "HOSTED_CI_CAUSE_UNVERIFIED",
            )
            jobs.append(
                {
                    "run_id": run["id"],
                    "job_id": job["id"],
                    "head_sha": job["head_sha"],
                    "conclusion": job["conclusion"],
                    "executed_steps": 0,
                    "cause": "AUTHENTICATED_GITHUB_BILLING_STARTUP_FAILURE",
                }
            )
    baseline, candidate, focused = (
        compensating[k] for k in ("baseline", "candidate", "focused")
    )
    require(
        baseline["failed"] == candidate["failed"] == 8
        and baseline["failure_ids"] == candidate["failure_ids"]
        and baseline["passed"] == 855
        and candidate["passed"] == 942
        and focused["passed"] == 126
        and focused["failed"] == 0
        and compensating["all_original_statuses_unchanged"] is True
        and compensating["added_passing_cases"] == 87
        and compensating["new_failures"] == []
        and all(compensating[k] == "PASS" for k in ("lint", "format", "compilation")),
        "BASELINE_REGRESSION_UNMATCHED",
    )
    return {
        "state": policy["ci_qualification_state"],
        "jobs": sorted(jobs, key=lambda j: j["job_id"]),
        "compensating_evidence_digest": digest(compensating),
        "hosted_ci_pass": False,
        "explicit_human_risk_acceptance_required": True,
    }


def verify_compensating(
    authority: Path, target: Path, policy: dict, data: dict
) -> None:
    require(
        data["candidate_head"] == policy["candidate"]["head_sha"],
        "BASELINE_REGRESSION_UNMATCHED",
    )
    fixed_path = "artifacts/causalis-b2-exact-edge-reconciliation-00a-r2/r2_regression_receipt.json"
    native_bytes = git_bytes(target, policy["candidate"]["head_sha"], fixed_path)
    require(
        byte_digest(native_bytes) == data["target_receipt_sha256"],
        "BASELINE_REGRESSION_UNMATCHED",
    )
    native = strict_json(native_bytes)
    results = {}
    for label, item in data["junit_reports"].items():
        path = authority / safe_path(item["path"])
        raw = path.read_bytes()
        require(
            len(raw) < 4_000_000
            and b"<!DOCTYPE" not in raw
            and b"<!ENTITY" not in raw
            and byte_digest(raw) == item["sha256"],
            "BASELINE_REGRESSION_UNMATCHED",
        )
        require(
            item["original_raw_sha256"] == native["retained_logs"][path.name]["sha256"],
            "BASELINE_REGRESSION_UNMATCHED",
        )
        try:
            cases = list(ET.fromstring(raw).iter("testcase"))
            states = {
                c.attrib["classname"] + "::" + c.attrib["name"]: (
                    "FAIL"
                    if c.find("failure") is not None or c.find("error") is not None
                    else "SKIP"
                    if c.find("skipped") is not None
                    else "PASS"
                )
                for c in cases
            }
        except (ET.ParseError, KeyError) as exc:
            raise AdmissionError("BASELINE_REGRESSION_UNMATCHED") from exc
        require(len(cases) == len(states), "BASELINE_REGRESSION_UNMATCHED")
        expected = {
            "passed": sum(v == "PASS" for v in states.values()),
            "failed": sum(v == "FAIL" for v in states.values()),
            "skipped": sum(v == "SKIP" for v in states.values()),
            "failure_ids": sorted(k for k, v in states.items() if v == "FAIL"),
        }
        require(expected == data[label], "BASELINE_REGRESSION_UNMATCHED")
        results[label] = states
    require(
        set(results) == {"baseline", "candidate", "focused"},
        "BASELINE_REGRESSION_UNMATCHED",
    )
    require(
        all(results["candidate"].get(k) == v for k, v in results["baseline"].items())
        and len(set(results["candidate"]) - set(results["baseline"])) == 87,
        "BASELINE_REGRESSION_UNMATCHED",
    )
    for label, item in data["static_checks"].items():
        require(
            item["source_head"] == policy["candidate"]["head_sha"]
            and item["exit_code"] == 0
            and byte_digest((authority / safe_path(item["path"])).read_bytes())
            == item["sha256"],
            "BASELINE_REGRESSION_UNMATCHED",
        )
    require(
        set(data["static_checks"]) == {"lint", "format", "compilation"},
        "BASELINE_REGRESSION_UNMATCHED",
    )


def verify_packet(
    target: Path, policy: dict, target_policy: dict, packet: dict, manifest: dict
) -> None:
    candidate = policy["candidate"]
    records = changed_records(str(target), candidate["base_sha"], candidate["head_sha"])
    actual = {record.path: record for record in records}
    require(len(records) == len(actual) == 53, "REVIEW_PACKET_INCOMPLETE")
    require(
        packet.get("changed_file_manifest") == manifest.get("files"),
        "REVIEW_PACKET_INCOMPLETE",
    )
    rows = manifest.get("files", [])
    require(
        len(rows) == 53 and len({row.get("path") for row in rows}) == 53,
        "REVIEW_PACKET_INCOMPLETE",
    )
    require(
        {row.get("path") for row in rows} == set(actual), "REVIEW_PACKET_INCOMPLETE"
    )
    expected_counts = Counter()
    full_paths = []
    for row in rows:
        path = row["path"]
        full = (
            path.endswith((".py", ".lean", ".md", ".wl", ".wls", ".wlt"))
            or path == ".gitattributes"
            or path.startswith("schemas/")
            or path in target_policy.get("key_evidence_diff_files", [])
        )
        expected = "FULL_DIFF_REVIEWED" if full else "HASH_BOUND_GENERATED_ARTIFACT"
        require(
            row.get("classification") == expected
            and row.get("git_blob_sha") == actual[path].new_oid
            and row.get("status") == actual[path].status,
            "REVIEW_PACKET_INCOMPLETE",
        )
        expected_counts[expected] += 1
        if full:
            full_paths.append(path)
    counts = {name: expected_counts[name] for name in policy["expected_packet_counts"]}
    proof = {
        "all_paths_accounted_for": True,
        "no_unclassified_paths": True,
        "total_changed": 53,
        "total_classified": 53,
    }
    for payload in (packet, manifest):
        require(
            payload.get("classification_counts")
            == counts
            == policy["expected_packet_counts"]
            and payload.get("completeness_proof") == proof,
            "REVIEW_PACKET_INCOMPLETE",
        )
    raw_diff = git(
        target,
        "diff",
        "--no-ext-diff",
        "--binary",
        "--full-index",
        "--find-renames=0",
        candidate["base_sha"],
        candidate["head_sha"],
        "--",
        *full_paths,
    ).decode("utf-8", errors="replace")
    require(packet.get("source_diff") == raw_diff, "REVIEW_PACKET_INCOMPLETE")


def reconcile_candidate(authority: Path, target: Path, policy: dict) -> dict:
    """Read the frozen checkout as data and recompute trusted existing verification."""
    candidate = policy["candidate"]
    require(
        git(target, "rev-parse", "HEAD").decode().strip() == candidate["head_sha"],
        "CANDIDATE_HEAD_STALE",
    )
    require(
        git(target, "rev-parse", "HEAD^{tree}").decode().strip()
        == candidate["tree_sha"],
        "CANDIDATE_TREE_MISMATCH",
    )
    require(not git(target, "status", "--porcelain"), "CANDIDATE_WORKTREE_DIRTY")
    for path in (
        policy["target_policy_path"],
        policy["review_report_path"],
        policy["producer_bindings_path"],
        policy["compensating_evidence_path"],
    ):
        safe_path(path)
    target_policy_bytes = (authority / policy["target_policy_path"]).read_bytes()
    require(
        byte_digest(target_policy_bytes) == policy["target_policy_sha256"],
        "TARGET_POLICY_IDENTITY_MISMATCH",
    )
    target_policy = strict_json(target_policy_bytes)
    require(
        target_policy["expected_base_sha"] == candidate["base_sha"],
        "CANDIDATE_BASE_MISMATCH",
    )
    require(
        target_policy["expected_head_sha"] == candidate["head_sha"]
        and target_policy["expected_pr_number"] == candidate["pr_number"]
        and target_policy["repository"] == candidate["repository"],
        "AUTHORIZATION_SCOPE_MISMATCH",
    )
    require(
        (authority / policy["review_report_path"]).is_file(), "REVIEW_REPORT_MISSING"
    )
    report_bytes = (authority / policy["review_report_path"]).read_bytes()
    require(
        byte_digest(report_bytes) == policy["review_report_sha256"],
        "REVIEW_REPORT_HASH_MISMATCH",
    )
    report = report_bytes.decode("utf-8")
    require(f"Repository: `{TARGET}`, draft PR #156." in report, "REVIEW_HEAD_MISMATCH")
    require(
        re.findall(r"Accepted candidate HEAD: `([0-9a-f]{40})`", report)
        == [candidate["head_sha"]]
        and re.findall(r"Accepted candidate tree: `([0-9a-f]{40})`", report)
        == [candidate["tree_sha"]],
        "REVIEW_HEAD_MISMATCH",
    )
    require(
        re.findall(r"^VERDICT: ([A-Z_]+)\s*$", report, re.MULTILINE)
        == [policy["review_verdict"]],
        "REVIEW_VERDICT_NOT_ACCEPTED",
    )
    # The old report predates this route and binds HEAD/tree, not a claimed signature.
    # Its exact byte digest plus the recomputed HEAD/tree/digest forms a new custody binding.
    for mentioned in re.findall(
        r"candidate digest[:\s`]+([0-9a-f]{64})", report, re.IGNORECASE
    ):
        require(mentioned == candidate["candidate_digest"], "CANDIDATE_DIGEST_MISMATCH")
    bindings_bytes = (authority / policy["producer_bindings_path"]).read_bytes()
    require(
        byte_digest(bindings_bytes) == policy["producer_binding_sha256"],
        "PRODUCER_BINDING_MISMATCH",
    )
    bindings = strict_json(bindings_bytes)["bindings"]
    matches = [
        b
        for b in bindings
        if b["repository"] == candidate["repository"]
        and b["pr_number"] == candidate["pr_number"]
    ]
    require(
        len(matches) == 1
        and matches[0]["producer_principal"] == "cloud-authoring-service:openai-codex"
        and matches[0]["head_branch"] == target_policy["expected_head_branch"],
        "PRODUCER_BINDING_MISMATCH",
    )
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        try:
            prior = run_prior_verification(
                repository=candidate["repository"],
                target_path=str(target),
                base_sha=candidate["base_sha"],
                head_sha=candidate["head_sha"],
                policy_path=str(authority / policy["target_policy_path"]),
                evidence_out=str(temp / "prior.json"),
                review_packet_out=str(temp / "packet.json"),
                packet_manifest_out=str(temp / "manifest.json"),
                max_packet_characters=2_000_000,
            )
        except AuthorityError as exc:
            raise AdmissionError("PRIOR_VERIFICATION_FAILED") from exc
        packet = strict_json((temp / "packet.json").read_bytes())
        manifest = strict_json((temp / "manifest.json").read_bytes())
    require(prior["verdict"] == "PASS", "PRIOR_VERIFICATION_FAILED")
    require(
        prior["candidate_digest"] == candidate["candidate_digest"],
        "CANDIDATE_DIGEST_MISMATCH",
    )
    verify_packet(target, policy, target_policy, packet, manifest)
    require(
        packet["candidate_digest"]
        == manifest["candidate_digest"]
        == prior["candidate_digest"],
        "CANDIDATE_DIGEST_MISMATCH",
    )
    compensating_bytes = (authority / policy["compensating_evidence_path"]).read_bytes()
    require(
        byte_digest(compensating_bytes) == policy["compensating_evidence_sha256"],
        "BASELINE_REGRESSION_UNMATCHED",
    )
    compensating = strict_json(compensating_bytes)
    verify_compensating(authority, target, policy, compensating)
    return {
        "candidate": candidate,
        "prior": prior,
        "packet": packet,
        "manifest": manifest,
        "producer": matches[0],
        "report_sha256": byte_digest(report_bytes),
        "target_policy": target_policy,
        "compensating": compensating,
    }


def verify_pr(pr: dict, policy: dict) -> None:
    c = policy["candidate"]
    require(
        pr.get("number") == c["pr_number"]
        and pr.get("base", {}).get("repo", {}).get("full_name") == c["repository"]
        and pr.get("head", {}).get("repo", {}).get("full_name") == c["repository"],
        "AUTHORIZATION_SCOPE_MISMATCH",
    )
    require(pr.get("head", {}).get("sha") == c["head_sha"], "CANDIDATE_HEAD_STALE")
    require(pr.get("base", {}).get("sha") == c["base_sha"], "CANDIDATE_BASE_MISMATCH")
    require(
        pr.get("state") == "open" and pr.get("merged") is False,
        "RELEASE_GATE_UNSATISFIED",
    )


def verify_ratification(authority: Path, root: dict, policy: dict, facts: dict) -> dict:
    """Facts must come from authenticated canonical-main and merged-PR API reads."""
    run, pr, comment = (
        facts["workflow"],
        facts["ratification_pr"],
        facts["ratification_comment"],
    )
    commit = facts["canonical_authority_sha"]
    require(
        run.get("head_sha") == commit
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("path") == WORKFLOW_PATH
        and run.get("repository", {}).get("full_name") == AUTHORITY,
        "ADMISSION_POLICY_NOT_RATIFIED",
    )
    require(
        pr.get("merged") is True
        and pr.get("base", {}).get("repo", {}).get("full_name") == AUTHORITY
        and pr.get("head", {}).get("repo", {}).get("full_name") == AUTHORITY,
        "ADMISSION_POLICY_NOT_RATIFIED",
    )
    # Inspect the actual merged/accepted objects, not a client-supplied PASS flag.
    accepted = pr.get("head", {}).get("sha", "")
    try:
        git(
            authority,
            "merge-base",
            "--is-ancestor",
            root["predecessor_commit"],
            accepted,
        )
        git(authority, "merge-base", "--is-ancestor", pr["merge_commit_sha"], commit)
        git(authority, "merge-base", "--is-ancestor", accepted, pr["merge_commit_sha"])
        require(
            git(authority, "rev-parse", accepted + "^{tree}")
            == git(authority, "rev-parse", commit + "^{tree}"),
            "ADMISSION_POLICY_NOT_RATIFIED",
        )
        for path in (
            ROOT_PATH,
            POLICY_PATH,
            *[item["path"] for item in root["implementation_objects"]],
        ):
            require(
                git_bytes(authority, accepted, path) == (authority / path).read_bytes(),
                "ADMISSION_POLICY_NOT_RATIFIED",
            )
    except (KeyError, AdmissionError) as exc:
        raise AdmissionError("ADMISSION_POLICY_NOT_RATIFIED") from exc
    principal = policy["authorization_principal"]
    require(
        principal
        == {
            "github_id": 267743825,
            "github_login": "kowen9024AI",
            "github_type": "User",
        },
        "AUTHORIZATION_PRINCIPAL_INVALID",
    )
    user = comment.get("user", {})
    require(
        user.get("id") == principal["github_id"]
        and user.get("login") == principal["github_login"]
        and user.get("type") == "User"
        and not comment.get("performed_via_github_app"),
        "AUTHORIZATION_PRINCIPAL_INVALID",
    )
    require(
        comment.get("issue_url")
        == f"https://api.github.com/repos/{AUTHORITY}/issues/{pr['number']}"
        and comment.get("created_at") == comment.get("updated_at"),
        "AUTHORIZATION_SCOPE_MISMATCH",
    )
    body = strict_json(comment.get("body", ""))
    validate_schema(body, "research-authority-ratification-v1", authority)
    require(
        body["authority_accepted_head_sha"] == accepted
        and body["authority_root_sha256"]
        == byte_digest((authority / ROOT_PATH).read_bytes())
        and body["authority_policy_sha256"]
        == byte_digest((authority / POLICY_PATH).read_bytes())
        and body["candidate_digest"] == policy["candidate"]["candidate_digest"]
        and sorted(body["limitations"]) == sorted(policy["limitations"]),
        "AUTHORIZATION_SCOPE_MISMATCH",
    )
    security = facts.get("authority_security_review", {})
    require(
        security.get("id") == body["security_review_comment_id"]
        and security.get("issue_url") == comment["issue_url"]
        and security.get("created_at") == security.get("updated_at"),
        "REVIEW_REPORT_MISSING",
    )
    text = security.get("body", "")
    require(
        type(text) is str
        and len(text) <= 512_000
        and byte_digest(text.encode()) == body["security_review_sha256"],
        "REVIEW_REPORT_HASH_MISMATCH",
    )
    require(
        body["authority_accepted_tree_sha"]
        == git(authority, "rev-parse", accepted + "^{tree}").decode().strip(),
        "REVIEW_HEAD_MISMATCH",
    )
    headers = {
        "AUTHORITY_REVIEW_REPOSITORY": AUTHORITY,
        "AUTHORITY_REVIEW_HEAD": accepted,
        "AUTHORITY_REVIEW_TREE": body["authority_accepted_tree_sha"],
        "REVIEWER_IDENTITY": "reported-agent:risk_admission_security_review:openai-codex",
        "REVIEWER_DISTINCT_FROM_IMPLEMENTER": "REPORTED",
        "REVIEWER_PROVIDER_DISTINCT": "NO",
        "REVIEWER_FILESYSTEM_ISOLATED": "NO",
        "INSTITUTIONAL_REVIEWER_SIGNATURE": "NOT_ESTABLISHED",
        "AUTHORITY_CHANGE_RISK_CLASS": "R2_SECURITY_OR_AUTHORITY_CHANGE",
    }
    for key, expected_value in headers.items():
        require(
            re.findall(r"^" + key + r": ([^\n]+)$", text, re.MULTILINE)
            == [expected_value],
            "REVIEW_HEAD_MISMATCH",
        )
    require(
        re.findall(r"^VERDICT: ([A-Z_]+)\s*$", text, re.MULTILINE)
        in (["ACCEPT"], ["ACCEPT_WITH_LIMITATIONS"]),
        "REVIEW_VERDICT_NOT_ACCEPTED",
    )
    return {
        "principal": principal,
        "comment_id": comment["id"],
        "authority_security_review_comment_id": security["id"],
        "authority_security_review_sha256": body["security_review_sha256"],
        "review_publisher_account": {
            k: security.get("user", {}).get(k) for k in ("id", "login", "type")
        },
        "comment_created_at": comment["created_at"],
        "merged_authority_pr": pr["number"],
        "accepted_head": accepted,
        "canonical_head": commit,
        "body_digest": digest(body),
    }


def build_request(
    authority: Path,
    policy: dict,
    evidence: dict,
    ci: dict,
    authority_sha: str,
    run_id: int,
) -> dict:
    def ref(path):
        return {
            "repository": AUTHORITY,
            "commit_sha": authority_sha,
            "path": path,
            "sha256": byte_digest((authority / path).read_bytes()),
        }

    def evidence_ref(value):
        return {"kind": "RECOMPUTED_AUTHORITY_EVIDENCE", "sha256": digest(value)}

    request = {
        "schema_version": "research-admission-request-v1",
        **policy["candidate"],
        "target_policy_reference": ref(policy["target_policy_path"]),
        "authority_policy_reference": ref(POLICY_PATH),
        "authority_root_reference": ref(ROOT_PATH),
        "risk_class": policy["risk_class"],
        "admission_route": policy["admission_route"],
        "review_report_reference": ref(policy["review_report_path"]),
        "review_report_sha256": policy["review_report_sha256"],
        "reviewer_identity": policy["reviewer_identity"],
        "reviewer_independence_class": policy["reviewer_independence"],
        "review_verdict": policy["review_verdict"],
        "review_limitations": list(policy["limitations"]),
        "prior_verification_reference": evidence_ref(evidence["prior"]),
        "review_packet_manifest_reference": evidence_ref(evidence["manifest"]),
        "changed_path_count": 53,
        "ci_evidence_reference": evidence_ref(ci),
        "human_authorization_reference": {
            "kind": "GITHUB_PROTECTED_ENVIRONMENT_REVIEW",
            "environment": ENVIRONMENT,
            "run_id": run_id,
        },
    }
    request["request_id"] = "research-" + digest(request)
    validate_schema(request, "research-admission-request-v1", authority)
    return request


def verify_authorization(
    authority: Path, policy: dict, request: dict, facts: dict, now: datetime
) -> dict:
    require(now < utc(policy["expires_at"]), "AUTHORIZATION_EXPIRED")
    validate_schema(request, "research-admission-request-v1", authority)
    require(
        type(request["pr_number"]) is int
        and type(request["human_authorization_reference"]["run_id"]) is int,
        "SCHEMA_VALIDATION_FAILED",
    )
    env = facts["environment"]
    require(env.get("name") == ENVIRONMENT, "AUTHORIZATION_MISSING")
    principal = policy["authorization_principal"]
    require(
        principal
        == {
            "github_id": 267743825,
            "github_login": "kowen9024AI",
            "github_type": "User",
        },
        "AUTHORIZATION_PRINCIPAL_INVALID",
    )
    rules = [
        r
        for r in env.get("protection_rules", [])
        if r.get("type") == "required_reviewers"
    ]
    require(len(rules) == 1, "AUTHORIZATION_MISSING")
    reviewers = rules[0].get("reviewers", [])
    require(
        len(reviewers) == 1
        and reviewers[0].get("type") == "User"
        and reviewers[0].get("reviewer", {}).get("id") == principal["github_id"]
        and reviewers[0].get("reviewer", {}).get("login") == principal["github_login"]
        and reviewers[0].get("reviewer", {}).get("type") == "User",
        "AUTHORIZATION_PRINCIPAL_INVALID",
    )
    transport = policy["producer_transport_identity"]
    require(
        facts["target_pr"].get("user", {}).get("id") == transport["github_id"]
        and facts["target_pr"].get("user", {}).get("login")
        == transport["github_login"],
        "PRODUCER_BINDING_MISMATCH",
    )
    resolved = facts["resolved_principal"]
    require(
        resolved.get("id") == principal["github_id"]
        and resolved.get("login") == principal["github_login"]
        and resolved.get("type") == "User",
        "AUTHORIZATION_PRINCIPAL_INVALID",
    )
    reviews = [
        r
        for r in facts["approval_history"]
        if any(
            e.get("id") == env.get("id") and e.get("name") == ENVIRONMENT
            for e in r.get("environments", [])
        )
    ]
    require(
        len(reviews) == 1 and reviews[0].get("state") == "approved",
        "AUTHORIZATION_MISSING",
    )
    review = reviews[0]
    require(
        review.get("user", {}).get("id") == principal["github_id"]
        and review.get("user", {}).get("login") == principal["github_login"]
        and review.get("user", {}).get("type") == "User",
        "AUTHORIZATION_PRINCIPAL_INVALID",
    )
    body = strict_json(review.get("comment", ""))
    validate_schema(body, "research-human-authorization-v1", authority)
    require(
        body["purpose"] == "ADMIT_EXACT_CAUSALIS_RESEARCH"
        and body["authority_head_sha"] == facts["canonical_authority_sha"]
        and body["request_digest"] == digest(request)
        and body["authority_root_sha256"]
        == request["authority_root_reference"]["sha256"]
        and body["authority_policy_sha256"]
        == request["authority_policy_reference"]["sha256"]
        and body["candidate_digest"] == request["candidate_digest"]
        and body["ci_assessment_digest"] == request["ci_evidence_reference"]["sha256"]
        and sorted(body["limitations"]) == sorted(policy["limitations"]),
        "AUTHORIZATION_SCOPE_MISMATCH",
    )
    expires = utc(body["expires_at"])
    require(
        now < expires <= now + timedelta(hours=24)
        and expires <= utc(policy["expires_at"]),
        "AUTHORIZATION_EXPIRED",
    )
    require(
        request["human_authorization_reference"]["run_id"] == facts["workflow"]["id"],
        "AUTHORIZATION_SCOPE_MISMATCH",
    )
    approval_identity = {
        "user": {k: review["user"][k] for k in ("id", "login", "type")},
        "state": "approved",
        "comment": body,
        "environment_id": env["id"],
        "workflow_run_id": facts["workflow"]["id"],
    }
    return {
        "principal": principal,
        "evidence_digest": digest(approval_identity),
        "body_digest": digest(body),
        "expires_at": body["expires_at"],
        "recorded_at": now.astimezone(UTC).isoformat(),
        "approval_timestamp_source": "GitHub review history has no approval timestamp; recorded_at is authority observation time.",
        "producer_approver_account_overlap": policy["producer_transport_identity"][
            "github_id"
        ]
        == principal["github_id"],
    }


def decide(
    authority: Path,
    root: dict,
    policy: dict,
    request: dict,
    evidence: dict,
    facts: dict,
    ci: dict,
    now: datetime,
) -> AdmissionDecision:
    select_route(request.get("admission_route"), request.get("risk_class"))
    require(not policy["revoked"] and not root["revoked"], "AUTHORIZATION_REVOKED")
    verify_pr(facts["target_pr"], policy)
    require(
        facts["candidate_tree_sha"] == policy["candidate"]["tree_sha"],
        "CANDIDATE_TREE_MISMATCH",
    )
    verify_ratification(authority, root, policy, facts)
    expected = build_request(
        authority,
        policy,
        evidence,
        ci,
        facts["canonical_authority_sha"],
        facts["workflow"]["id"],
    )
    require(request == expected, "ADMISSION_REQUEST_EVIDENCE_MISMATCH")
    auth = verify_authorization(authority, policy, request, facts, now)
    return AdmissionDecision(
        True,
        True,
        "BOUNDED_RESEARCH_ADMISSION_AUTHORIZED",
        request["authority_policy_reference"],
        policy["candidate"],
        {
            "prior": digest(evidence["prior"]),
            "manifest": digest(evidence["manifest"]),
            "review": evidence["report_sha256"],
            "ci": digest(ci),
        },
        auth,
        policy["limitations"],
        [
            "This admission is not release authorization.",
            "Resolve target protection/CI requirements and obtain separate target merge authorization.",
        ],
        candidate_remains_eligible=True,
    )


def decision_json(decision: AdmissionDecision) -> dict:
    return asdict(decision)
