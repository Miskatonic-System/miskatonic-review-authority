"""Independent Evaluator Evidence Ingress for Review Authority.

Implements WO-RA-EVALUATOR-EVIDENCE-INGRESS-01A, 01A-R1, and WO-RA-EVALUATOR-ATTESTATION-BINDING-01A.
Independently verifies EvaluationRequest v1, EvaluationResult v2,
Control Plane result custody receipt v1, and dispatch state v1,
producing a verified EvaluatorEvidenceIngress envelope as sidecar evidence
without acquiring release, merge, activation, or runtime authority.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import jsonschema

from .util import (
    AuthorityError,
    canonical_json_bytes,
    read_json,
    require_full_sha,
    sha256_bytes,
    sha256_file,
    write_json,
)

EXPECTED_REVIEW_AUTHORITY_REPO = "miskatonic-system/miskatonic-review-authority"
EXPECTED_EVALUATOR_REPO = "miskatonic-system/miskatonic-agent-evaluator"
EXPECTED_CONTROL_PLANE_REPO = "miskatonic-system/miskatonic-control-plane"
HEX_40_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
HEX_64_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def parse_and_validate_github_origin(remote_url: str) -> str:
    """Parses and validates a GitHub remote URL.
    
    Supported forms:
    - https://github.com/OWNER/REPO.git
    - http://github.com/OWNER/REPO.git
    - git@github.com:OWNER/REPO.git
    - ssh://git@github.com/OWNER/REPO.git
    - https://github.com/OWNER/REPO
    - http://github.com/OWNER/REPO
    - git@github.com:OWNER/REPO
    - ssh://git@github.com/OWNER/REPO
    
    Requirements:
    - Trusted host must be exactly 'github.com' (case-insensitive).
    - Returns normalized lowercase 'owner/repo'.
    - Raises AuthorityError on untrusted host, invalid format, or missing origin.
    """
    if not remote_url or not remote_url.strip():
        raise AuthorityError("REMOTE_ORIGIN_INVALID", "remote origin URL is empty or missing")

    url = remote_url.strip()

    # 1. SCP-like git syntax: git@github.com:owner/repo(.git)
    scp_match = re.match(r"^git@([^:]+):([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?$", url)
    if scp_match:
        host, owner, repo = scp_match.groups()
        if host.lower() != "github.com":
            raise AuthorityError("UNTRUSTED_GIT_HOST", f"untrusted git host '{host}' in origin '{url}' (expected 'github.com')")
        return f"{owner.lower()}/{repo.lower()}"

    # 2. URI syntax: (https|http|ssh)://(user@)?host(:port)?/owner/repo(.git)
    uri_match = re.match(r"^(?:https?|ssh)://(?:[^@/]+@)?([^:/]+)(?::\d+)?/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?/?$", url)
    if uri_match:
        host, owner, repo = uri_match.groups()
        if host.lower() != "github.com":
            raise AuthorityError("UNTRUSTED_GIT_HOST", f"untrusted git host '{host}' in origin '{url}' (expected 'github.com')")
        return f"{owner.lower()}/{repo.lower()}"

    raise AuthorityError("REMOTE_ORIGIN_INVALID", f"unrecognized git remote origin URL '{url}'")


def load_upstream_evidence_lock(review_authority_root: Path) -> Dict[str, Any]:
    """Loads and validates contracts/evaluator-evidence.lock.json."""
    root = Path(review_authority_root).resolve()
    lock_path = root / "contracts" / "evaluator-evidence.lock.json"
    if not lock_path.exists():
        raise AuthorityError("UPSTREAM_EVIDENCE_LOCK_NOT_FOUND", str(lock_path))

    try:
        lock_data = read_json(lock_path)
    except Exception as err:
        raise AuthorityError("UPSTREAM_EVIDENCE_LOCK_MALFORMED", str(err)) from err

    if lock_data.get("schema_version") != "miskatonic.upstream-evidence-lock.v1":
        raise AuthorityError("UPSTREAM_EVIDENCE_LOCK_INVALID_VERSION", lock_data.get("schema_version"))

    for field in [
        "evaluator_repository",
        "evaluator_sha",
        "request_schema_path",
        "request_schema_id",
        "request_schema_sha256",
        "result_schema_path",
        "result_schema_id",
        "result_schema_sha256",
        "control_plane_repository",
        "control_plane_sha",
        "custody_schema_path",
        "custody_schema_id",
        "custody_schema_sha256",
    ]:
        if field not in lock_data or not lock_data[field]:
            raise AuthorityError("UPSTREAM_EVIDENCE_LOCK_FIELD_MISSING", field)

    require_full_sha(lock_data["evaluator_sha"], field="evaluator_sha")
    require_full_sha(lock_data["control_plane_sha"], field="control_plane_sha")

    return lock_data


def load_evaluator_ingress_attestation_lock(review_authority_root: Path) -> Dict[str, Any]:
    """Loads and validates contracts/evaluator-ingress-attestation.lock.json."""
    root = Path(review_authority_root).resolve()
    lock_path = root / "contracts" / "evaluator-ingress-attestation.lock.json"
    if not lock_path.exists():
        raise AuthorityError("EVALUATOR_INGRESS_ATTESTATION_LOCK_NOT_FOUND", str(lock_path))

    try:
        lock_data = read_json(lock_path)
    except Exception as err:
        raise AuthorityError("EVALUATOR_INGRESS_ATTESTATION_LOCK_MALFORMED", str(err)) from err

    if lock_data.get("schema_version") != "miskatonic.evaluator-ingress-attestation-lock.v1":
        raise AuthorityError("EVALUATOR_INGRESS_ATTESTATION_LOCK_INVALID_VERSION", lock_data.get("schema_version"))

    for field in [
        "ingress_repository",
        "ingress_source_sha",
        "ingress_schema_path",
        "ingress_schema_version",
        "ingress_schema_sha256",
        "evaluator_repository",
        "evaluator_sha",
        "control_plane_repository",
        "control_plane_sha",
    ]:
        if field not in lock_data or not lock_data[field]:
            raise AuthorityError("EVALUATOR_INGRESS_ATTESTATION_LOCK_FIELD_MISSING", field)

    require_full_sha(lock_data["ingress_source_sha"], field="ingress_source_sha")
    require_full_sha(lock_data["evaluator_sha"], field="evaluator_sha")
    require_full_sha(lock_data["control_plane_sha"], field="control_plane_sha")

    return lock_data


def verify_evaluator_python(evaluator_python: Path, evaluator_root: Path) -> Dict[str, str]:
    """Verifies that evaluator_python is an explicit executable with Python >=3.12 and can import miskatonic_evaluator.schemas."""
    py_path = Path(evaluator_python).resolve()
    if not py_path.exists() or not os.access(py_path, os.X_OK):
        raise AuthorityError("EVALUATOR_PYTHON_UNAVAILABLE", str(py_path))

    # Version check >= 3.12
    cmd_ver = [str(py_path), "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}'); sys.exit(0 if sys.version_info >= (3, 12) else 1)"]
    res_ver = subprocess.run(cmd_ver, capture_output=True, text=True)
    if res_ver.returncode != 0:
        raise AuthorityError("EVALUATOR_PYTHON_VERSION_INCOMPATIBLE", f"expected >=3.12, got {res_ver.stdout.strip()}")

    py_version = res_ver.stdout.strip()

    # Import check
    env = os.environ.copy()
    env["PYTHONPATH"] = str(evaluator_root / "src")
    cmd_imp = [str(py_path), "-c", "from miskatonic_evaluator.schemas import load_evaluation_request, load_evaluation_result; print('IMPORT_OK')"]
    res_imp = subprocess.run(cmd_imp, cwd=evaluator_root, capture_output=True, text=True, env=env)
    if res_imp.returncode != 0 or "IMPORT_OK" not in res_imp.stdout:
        raise AuthorityError("EVALUATOR_IMPORT_FAILED", res_imp.stderr.strip() or res_imp.stdout.strip())

    return {
        "python_path": str(py_path),
        "python_version": py_version,
    }


def verify_evaluator_checkout(
    evaluator_root: Path,
    lock: Dict[str, Any],
    evaluator_python: Path,
) -> Dict[str, Any]:
    """Verifies the evaluator git checkout, schemas, and runtime environment."""
    eval_path = Path(evaluator_root).resolve()
    if not eval_path.exists() or not eval_path.is_dir():
        raise AuthorityError("EVALUATOR_CHECKOUT_UNAVAILABLE", str(eval_path))

    # 1. Git repository check
    res = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=eval_path, capture_output=True, text=True)
    if res.returncode != 0 or res.stdout.strip() != "true":
        raise AuthorityError("EVALUATOR_CHECKOUT_INVALID", f"{eval_path} is not a git repository")

    # 2. Remote check
    res = subprocess.run(["git", "remote", "get-url", "origin"], cwd=eval_path, capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorityError("EVALUATOR_CHECKOUT_INVALID", "failed to get remote origin")
    remote_origin = parse_and_validate_github_origin(res.stdout.strip())
    expected_origin = lock["evaluator_repository"].lower().strip()
    if remote_origin != expected_origin:
        raise AuthorityError(
            "EVALUATOR_ORIGIN_MISMATCH",
            f"detected '{remote_origin}' != expected '{expected_origin}'",
        )

    # 3. HEAD SHA check
    res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=eval_path, capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorityError("EVALUATOR_CHECKOUT_INVALID", "failed to resolve HEAD commit")
    head_sha = res.stdout.strip().lower()
    if head_sha != lock["evaluator_sha"].lower():
        raise AuthorityError(
            "EVALUATOR_SHA_MISMATCH",
            f"checkout HEAD '{head_sha}' != locked SHA '{lock['evaluator_sha']}'",
        )

    # 4. Clean worktree check
    res = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=eval_path, capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorityError("EVALUATOR_CHECKOUT_INVALID", "failed to check git status")
    if res.stdout.strip():
        raise AuthorityError("EVALUATOR_CHECKOUT_DIRTY", f"evaluator checkout at {eval_path} is dirty")

    # 5. Schema files and digests
    req_schema_path = eval_path / lock["request_schema_path"]
    if not req_schema_path.exists() or not req_schema_path.is_file():
        raise AuthorityError("EVALUATOR_SCHEMA_MISSING", str(req_schema_path))
    actual_req_sha = sha256_file(req_schema_path).lower()
    expected_req_sha = lock["request_schema_sha256"].lower().removeprefix("sha256:")
    if actual_req_sha != expected_req_sha:
        raise AuthorityError(
            "EVALUATOR_REQUEST_SCHEMA_DIGEST_MISMATCH",
            f"actual '{actual_req_sha}' != locked '{expected_req_sha}'",
        )

    res_schema_path = eval_path / lock["result_schema_path"]
    if not res_schema_path.exists() or not res_schema_path.is_file():
        raise AuthorityError("EVALUATOR_SCHEMA_MISSING", str(res_schema_path))
    actual_res_sha = sha256_file(res_schema_path).lower()
    expected_res_sha = lock["result_schema_sha256"].lower().removeprefix("sha256:")
    if actual_res_sha != expected_res_sha:
        raise AuthorityError(
            "EVALUATOR_RESULT_SCHEMA_DIGEST_MISMATCH",
            f"actual '{actual_res_sha}' != locked '{expected_res_sha}'",
        )

    # 6. Python runtime verification
    py_info = verify_evaluator_python(evaluator_python, eval_path)

    return {
        "evaluator_root": str(eval_path),
        "head_sha": head_sha,
        "python_info": py_info,
    }


def verify_control_plane_checkout(
    control_plane_root: Path,
    lock: Dict[str, Any],
) -> Dict[str, Any]:
    """Verifies the control plane git checkout and custody schema."""
    cp_path = Path(control_plane_root).resolve()
    if not cp_path.exists() or not cp_path.is_dir():
        raise AuthorityError("CONTROL_PLANE_CHECKOUT_UNAVAILABLE", str(cp_path))

    # 1. Git repository check
    res = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=cp_path, capture_output=True, text=True)
    if res.returncode != 0 or res.stdout.strip() != "true":
        raise AuthorityError("CONTROL_PLANE_CHECKOUT_INVALID", f"{cp_path} is not a git repository")

    # 2. Remote check
    res = subprocess.run(["git", "remote", "get-url", "origin"], cwd=cp_path, capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorityError("CONTROL_PLANE_CHECKOUT_INVALID", "failed to get remote origin")
    remote_origin = parse_and_validate_github_origin(res.stdout.strip())
    expected_origin = lock["control_plane_repository"].lower().strip()
    if remote_origin != expected_origin:
        raise AuthorityError(
            "CONTROL_PLANE_ORIGIN_MISMATCH",
            f"detected '{remote_origin}' != expected '{expected_origin}'",
        )

    # 3. HEAD SHA check
    res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=cp_path, capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorityError("CONTROL_PLANE_CHECKOUT_INVALID", "failed to resolve HEAD commit")
    head_sha = res.stdout.strip().lower()
    if head_sha != lock["control_plane_sha"].lower():
        raise AuthorityError(
            "CONTROL_PLANE_SHA_MISMATCH",
            f"checkout HEAD '{head_sha}' != locked SHA '{lock['control_plane_sha']}'",
        )

    # 4. Clean worktree check
    res = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=cp_path, capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorityError("CONTROL_PLANE_CHECKOUT_INVALID", "failed to check git status")
    if res.stdout.strip():
        raise AuthorityError("CONTROL_PLANE_CHECKOUT_DIRTY", f"control plane checkout at {cp_path} is dirty")

    # 5. Custody schema file and digest
    custody_schema_path = cp_path / lock["custody_schema_path"]
    if not custody_schema_path.exists() or not custody_schema_path.is_file():
        raise AuthorityError("CONTROL_PLANE_SCHEMA_MISSING", str(custody_schema_path))
    actual_custody_sha = sha256_file(custody_schema_path).lower()
    expected_custody_sha = lock["custody_schema_sha256"].lower().removeprefix("sha256:")
    if actual_custody_sha != expected_custody_sha:
        raise AuthorityError(
            "CONTROL_PLANE_CUSTODY_SCHEMA_DIGEST_MISMATCH",
            f"actual '{actual_custody_sha}' != locked '{expected_custody_sha}'",
        )

    custody_schema = read_json(custody_schema_path)

    return {
        "control_plane_root": str(cp_path),
        "head_sha": head_sha,
        "custody_schema_path": custody_schema_path,
        "custody_schema": custody_schema,
    }


def verify_review_authority_source(review_authority_root: Path) -> str:
    """Verifies that Review Authority checkout is a valid git repo with canonical origin and clean status."""
    ra_path = Path(review_authority_root).resolve()
    if not ra_path.exists() or not ra_path.is_dir():
        raise AuthorityError("REVIEW_AUTHORITY_SOURCE_UNAVAILABLE", str(ra_path))

    # 1. Git repository check
    res = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=ra_path, capture_output=True, text=True)
    if res.returncode != 0 or res.stdout.strip() != "true":
        raise AuthorityError("REVIEW_AUTHORITY_SOURCE_INVALID", f"{ra_path} is not a git repository")

    # 2. Remote check
    res = subprocess.run(["git", "remote", "get-url", "origin"], cwd=ra_path, capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorityError("REVIEW_AUTHORITY_SOURCE_INVALID", "failed to get remote origin")
    remote_origin = parse_and_validate_github_origin(res.stdout.strip())
    expected_origin = EXPECTED_REVIEW_AUTHORITY_REPO
    if remote_origin != expected_origin:
        raise AuthorityError(
            "REVIEW_AUTHORITY_ORIGIN_MISMATCH",
            f"detected '{remote_origin}' != expected '{expected_origin}'",
        )

    # 3. HEAD SHA check
    res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ra_path, capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorityError("REVIEW_AUTHORITY_SOURCE_INVALID", "failed to resolve HEAD commit")
    head_sha = res.stdout.strip().lower()
    require_full_sha(head_sha, field="review_authority_head")

    # 4. Clean worktree check
    res = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=ra_path, capture_output=True, text=True)
    if res.returncode != 0:
        raise AuthorityError("REVIEW_AUTHORITY_SOURCE_INVALID", "failed to check git status")
    if res.stdout.strip():
        raise AuthorityError("REVIEW_AUTHORITY_SOURCE_DIRTY", f"review authority checkout at {ra_path} is dirty")

    return head_sha


def validate_evaluator_artifacts(
    evaluator_root: Path,
    evaluator_python: Path,
    req_data: Dict[str, Any],
    res_data: Dict[str, Any],
    lock: Dict[str, Any],
) -> Dict[str, Any]:
    """Independently invokes upstream evaluator schemas to validate EvaluationResult v2 against EvaluationRequest v1."""
    eval_root = Path(evaluator_root).resolve()
    eval_py = Path(evaluator_python).resolve()

    code = """
import json
import sys
from miskatonic_evaluator.schemas import load_evaluation_request, load_evaluation_result

req_data = json.loads(sys.argv[1])
res_data = json.loads(sys.argv[2])

try:
    req = load_evaluation_request(req_data)
except Exception as e:
    print(json.dumps({"error": f"REQUEST_VALIDATION_ERROR: {e}"}))
    sys.exit(1)

try:
    res = load_evaluation_result(res_data)
except Exception as e:
    print(json.dumps({"error": f"RESULT_VALIDATION_ERROR: {e}"}))
    sys.exit(1)

try:
    res.validate_against_request(req)
except Exception as e:
    print(json.dumps({"error": f"REQUEST_RESULT_BINDING_ERROR: {e}"}))
    sys.exit(1)

facts = {
    "schema_version": res.schema_version,
    "evaluation_id": res.evaluation_id,
    "result_sha256": res.result_sha256,
    "request_id": res.request_id,
    "request_sha256": res.request_sha256,
    "candidate_repository": res.candidate_repository,
    "baseline_sha": res.baseline_sha,
    "candidate_sha": res.candidate_sha,
    "evaluator_repository": res.evaluator_repository,
    "evaluator_sha": res.evaluator_sha,
    "task_pack_id": res.task_pack_id,
    "task_pack_sha256": res.task_pack_sha256,
    "recommendation": res.recommendation,
    "hard_gates": res.hard_gates,
}
print(json.dumps({"success": True, "facts": facts}))
sys.exit(0)
"""

    env = os.environ.copy()
    env["PYTHONPATH"] = str(eval_root / "src")
    res = subprocess.run(
        [str(eval_py), "-c", code, json.dumps(req_data), json.dumps(res_data)],
        cwd=eval_root,
        capture_output=True,
        text=True,
        env=env,
    )

    if res.returncode != 0:
        error_msg = res.stderr.strip() or res.stdout.strip()
        try:
            parsed = json.loads(res.stdout.strip())
            if "error" in parsed:
                error_msg = parsed["error"]
        except Exception:
            pass
        raise AuthorityError("EVALUATOR_ARTIFACT_VALIDATION_FAILED", error_msg)

    try:
        data = json.loads(res.stdout.strip())
        facts = data.get("facts", {})
    except Exception as err:
        raise AuthorityError("EVALUATOR_FACTS_PARSE_FAILED", str(err)) from err

    # Verify evaluator self-identity
    if facts.get("evaluator_repository", "").lower() != lock["evaluator_repository"].lower():
        raise AuthorityError(
            "EVALUATOR_EVIDENCE_IDENTITY_MISMATCH",
            f"evaluator_repository '{facts.get('evaluator_repository')}' != locked '{lock['evaluator_repository']}'",
        )
    if facts.get("evaluator_sha", "").lower() != lock["evaluator_sha"].lower():
        raise AuthorityError(
            "EVALUATOR_EVIDENCE_IDENTITY_MISMATCH",
            f"evaluator_sha '{facts.get('evaluator_sha')}' != locked '{lock['evaluator_sha']}'",
        )

    return facts


def recompute_control_plane_custody_receipt_sha256(receipt: Dict[str, Any]) -> str:
    """Recomputes the canonical Control Plane receipt SHA-256 over receipt excluding receipt_sha256."""
    rec_for_digest = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
    canon = json.dumps(rec_for_digest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def compute_ingress_envelope_id(
    request_sha256: str,
    result_sha256: str,
    raw_result_sha256: str,
    custody_receipt_sha256: str,
    raw_dispatch_state_sha256: str,
    evaluator_sha: str,
    control_plane_sha: str,
    review_authority_sha: str,
) -> str:
    """Computes deterministic ingress_id from stable evidence seed."""
    seed_payload = {
        "control_plane_sha": control_plane_sha.lower(),
        "custody_receipt_sha256": custody_receipt_sha256.lower(),
        "dispatch_state_raw_sha256": raw_dispatch_state_sha256.lower(),
        "evaluator_sha": evaluator_sha.lower(),
        "raw_result_sha256": raw_result_sha256.lower(),
        "request_sha256": request_sha256.lower(),
        "result_sha256": result_sha256.lower(),
        "review_authority_sha": review_authority_sha.lower(),
    }
    digest = hashlib.sha256(json.dumps(seed_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f"evalingress-{digest}"


def validate_evaluator_evidence_ingress_envelope(
    envelope: Dict[str, Any],
    *,
    ingress_schema: Dict[str, Any],
    expected_ingress_id: str,
    expected_review_authority_sha: str,
    expected_evaluator_repository: str,
    expected_evaluator_sha: str,
    expected_control_plane_repository: str,
    expected_control_plane_sha: str,
    expected_request_facts: Dict[str, Any],
    expected_result_facts: Dict[str, Any],
    expected_custody: Dict[str, Any],
    expected_dispatch: Dict[str, Any],
    raw_request_sha256: str,
    raw_result_sha256: str,
    raw_custody_sha256: str,
    raw_dispatch_sha256: str,
) -> None:
    """Canonical validator for EvaluatorEvidenceIngress envelopes.
    
    Fails closed if any property, schema rule, digest, binding, identity,
    assertion, or exit consistency check fails.
    """
    # 1. Schema validation (Section D)
    try:
        jsonschema.validate(instance=envelope, schema=ingress_schema)
    except Exception as err:
        raise AuthorityError("INGRESS_ENVELOPE_SCHEMA_VIOLATION", str(err)) from err

    # 2. Ingress digest validation (Section E)
    env_for_digest = {k: v for k, v in envelope.items() if k != "ingress_sha256"}
    recomputed_ingress_sha256 = sha256_bytes(canonical_json_bytes(env_for_digest))
    if envelope.get("ingress_sha256", "").lower() != recomputed_ingress_sha256.lower():
        raise AuthorityError(
            "INGRESS_ENVELOPE_DIGEST_MISMATCH",
            f"declared '{envelope.get('ingress_sha256')}' != computed '{recomputed_ingress_sha256}'",
        )

    # 3. Identity validation (Section F)
    if envelope.get("ingress_id") != expected_ingress_id:
        raise AuthorityError(
            "INGRESS_ID_MISMATCH",
            f"envelope ingress_id '{envelope.get('ingress_id')}' != expected '{expected_ingress_id}'",
        )
    if envelope.get("review_authority_repository") != EXPECTED_REVIEW_AUTHORITY_REPO:
        raise AuthorityError("REVIEW_AUTHORITY_REPOSITORY_MISMATCH")
    if envelope.get("review_authority_sha", "").lower() != expected_review_authority_sha.lower():
        raise AuthorityError("REVIEW_AUTHORITY_SHA_MISMATCH")
    if envelope.get("evaluator_repository", "").lower() != expected_evaluator_repository.lower():
        raise AuthorityError("EVALUATOR_REPOSITORY_MISMATCH")
    if envelope.get("evaluator_sha", "").lower() != expected_evaluator_sha.lower():
        raise AuthorityError("EVALUATOR_SHA_MISMATCH")
    if envelope.get("control_plane_repository", "").lower() != expected_control_plane_repository.lower():
        raise AuthorityError("CONTROL_PLANE_REPOSITORY_MISMATCH")
    if envelope.get("control_plane_sha", "").lower() != expected_control_plane_sha.lower():
        raise AuthorityError("CONTROL_PLANE_SHA_MISMATCH")

    # 4. Raw artifact digest revalidation (Section G)
    if envelope.get("evaluation_request_raw_sha256", "").lower() != raw_request_sha256.lower():
        raise AuthorityError("EVALUATION_REQUEST_RAW_DIGEST_MISMATCH")
    if envelope.get("evaluation_result_raw_sha256", "").lower() != raw_result_sha256.lower():
        raise AuthorityError("EVALUATION_RESULT_RAW_DIGEST_MISMATCH")
    if envelope.get("custody_receipt_raw_sha256", "").lower() != raw_custody_sha256.lower():
        raise AuthorityError("CUSTODY_RECEIPT_RAW_DIGEST_MISMATCH")
    if envelope.get("dispatch_state_raw_sha256", "").lower() != raw_dispatch_sha256.lower():
        raise AuthorityError("DISPATCH_STATE_RAW_DIGEST_MISMATCH")

    # 5. Request / Result binding revalidation (Section H)
    if envelope.get("evaluation_request_id") != expected_request_facts.get("request_id"):
        raise AuthorityError("EVALUATION_REQUEST_ID_MISMATCH")
    if envelope.get("evaluation_request_sha256", "").lower() != expected_request_facts.get("request_sha256", "").lower():
        raise AuthorityError("EVALUATION_REQUEST_DIGEST_MISMATCH")
    if envelope.get("evaluation_id") != expected_result_facts.get("evaluation_id"):
        raise AuthorityError("EVALUATION_ID_MISMATCH")
    if envelope.get("evaluation_result_sha256", "").lower() != expected_result_facts.get("result_sha256", "").lower():
        raise AuthorityError("EVALUATION_RESULT_DIGEST_MISMATCH")
    if envelope.get("evaluation_result_schema") != expected_result_facts.get("schema_version", "miskatonic.evaluation.v2"):
        raise AuthorityError("EVALUATION_RESULT_SCHEMA_MISMATCH")
    if envelope.get("recommendation") != expected_result_facts.get("recommendation"):
        raise AuthorityError("RECOMMENDATION_MISMATCH")

    # 6. Candidate / Task pack binding (Section I)
    if envelope.get("candidate_repository") != expected_result_facts.get("candidate_repository"):
        raise AuthorityError("CANDIDATE_REPOSITORY_MISMATCH")
    if envelope.get("baseline_sha", "").lower() != expected_result_facts.get("baseline_sha", "").lower():
        raise AuthorityError("BASELINE_SHA_MISMATCH")
    if envelope.get("candidate_sha", "").lower() != expected_result_facts.get("candidate_sha", "").lower():
        raise AuthorityError("CANDIDATE_SHA_MISMATCH")
    if envelope.get("task_pack_id") != expected_result_facts.get("task_pack_id"):
        raise AuthorityError("TASK_PACK_ID_MISMATCH")
    if envelope.get("task_pack_sha256", "").lower() != expected_result_facts.get("task_pack_sha256", "").lower():
        raise AuthorityError("TASK_PACK_DIGEST_MISMATCH")

    # 7. Custody / Dispatch binding (Section J)
    if envelope.get("custody_receipt_sha256", "").lower() != expected_custody.get("receipt_sha256", "").lower():
        raise AuthorityError("CUSTODY_RECEIPT_DIGEST_MISMATCH")
    if envelope.get("dispatch_id") != expected_custody.get("dispatch_id"):
        raise AuthorityError("DISPATCH_ID_MISMATCH")

    # 8. Validation assertions (Section K)
    if envelope.get("request_contract_validation") != "PASS":
        raise AuthorityError("INVALID_VALIDATION_ASSERTION", "request_contract_validation must be PASS")
    if envelope.get("result_contract_validation") != "PASS":
        raise AuthorityError("INVALID_VALIDATION_ASSERTION", "result_contract_validation must be PASS")
    if envelope.get("request_result_binding") != "PASS":
        raise AuthorityError("INVALID_VALIDATION_ASSERTION", "request_result_binding must be PASS")
    if envelope.get("control_plane_custody_validation") != "PASS":
        raise AuthorityError("INVALID_VALIDATION_ASSERTION", "control_plane_custody_validation must be PASS")
    if envelope.get("dispatch_state_validation") != "PASS":
        raise AuthorityError("INVALID_VALIDATION_ASSERTION", "dispatch_state_validation must be PASS")
    if envelope.get("evaluator_identity_validation") != "PASS":
        raise AuthorityError("INVALID_VALIDATION_ASSERTION", "evaluator_identity_validation must be PASS")
    if envelope.get("authority_effect") != "EVIDENCE_ONLY":
        raise AuthorityError("INVALID_AUTHORITY_EFFECT", "authority_effect must be EVIDENCE_ONLY")

    # 9. Exit / Recommendation consistency (Section L)
    rec = envelope.get("recommendation")
    proc_rc = envelope.get("evaluator_process_exit_code")
    if rec == "approve_candidate" and proc_rc != 0:
        raise AuthorityError("EVALUATOR_EXIT_RECOMMENDATION_INCONSISTENT", f"approve_candidate requires exit 0, got {proc_rc}")
    elif rec == "reject" and proc_rc != 1:
        raise AuthorityError("EVALUATOR_EXIT_RECOMMENDATION_INCONSISTENT", f"reject requires exit 1, got {proc_rc}")


def write_ingress_json_atomically(destination: Path, envelope: Dict[str, Any]) -> None:
    """Atomically writes an EvaluatorEvidenceIngress envelope to destination.
    
    Required sequence (WO-RA-EVALUATOR-EVIDENCE-INGRESS-01A-R1):
    1. ensure destination parent exists;
    2. canonical serialize envelope once;
    3. create temporary file in SAME directory;
    4. write complete bytes;
    5. flush;
    6. os.fsync(file descriptor);
    7. os.replace(temp, destination);
    8. fsync parent directory where supported;
    9. clean temporary file on failure.
    """
    dest = Path(destination).resolve()
    dest_dir = dest.parent
    dest_dir.mkdir(parents=True, exist_ok=True)

    content_bytes = canonical_json_bytes(envelope)
    tmp_path: Optional[Path] = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=dest_dir,
            prefix=f".{dest.name}.tmp-",
            delete=False,
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(content_bytes)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())

        os.replace(tmp_path, dest)
        tmp_path = None

        # Fsync parent directory where supported
        try:
            dir_fd = os.open(dest_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception:
            pass

    except Exception:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass
        raise


def verify_evaluator_evidence_source_set(
    *,
    review_authority_root: Path,
    evaluator_root: Path,
    control_plane_root: Path,
    evaluator_python: Path,
    evaluation_request_path: Path,
    evaluation_result_path: Path,
    custody_receipt_path: Path,
    dispatch_state_path: Path,
    lock: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Independently verifies the foreign evaluator and control plane evidence chain.
    
    Returns immutable dictionary of verified facts, raw digests, and decoded structures.
    """
    ra_root = Path(review_authority_root).resolve()
    eval_root = Path(evaluator_root).resolve()
    cp_root = Path(control_plane_root).resolve()
    eval_py = Path(evaluator_python).resolve()

    req_path = Path(evaluation_request_path).resolve()
    res_path = Path(evaluation_result_path).resolve()
    cust_path = Path(custody_receipt_path).resolve()
    disp_path = Path(dispatch_state_path).resolve()

    # 1. Upstream Evidence Lock Validation
    if lock is None:
        lock = load_upstream_evidence_lock(ra_root)

    # 2. Checkouts and Runtime Verification
    eval_info = verify_evaluator_checkout(eval_root, lock, eval_py)
    cp_info = verify_control_plane_checkout(cp_root, lock)

    # 3. Read Foreign Artifacts (Strictly Read-Only)
    if not req_path.exists() or not req_path.is_file():
        raise AuthorityError("EVALUATION_REQUEST_NOT_FOUND", str(req_path))
    if not res_path.exists() or not res_path.is_file():
        raise AuthorityError("EVALUATION_RESULT_NOT_FOUND", str(res_path))
    if not cust_path.exists() or not cust_path.is_file():
        raise AuthorityError("CUSTODY_RECEIPT_NOT_FOUND", str(cust_path))
    if not disp_path.exists() or not disp_path.is_file():
        raise AuthorityError("DISPATCH_STATE_NOT_FOUND", str(disp_path))

    req_bytes = req_path.read_bytes()
    res_bytes = res_path.read_bytes()
    cust_bytes = cust_path.read_bytes()
    disp_bytes = disp_path.read_bytes()

    raw_req_sha256 = sha256_bytes(req_bytes)
    raw_res_sha256 = sha256_bytes(res_bytes)
    raw_cust_sha256 = sha256_bytes(cust_bytes)
    raw_disp_sha256 = sha256_bytes(disp_bytes)

    try:
        req_data = json.loads(req_bytes.decode("utf-8"))
    except Exception as err:
        raise AuthorityError("EVALUATION_REQUEST_MALFORMED", str(err)) from err

    try:
        res_data = json.loads(res_bytes.decode("utf-8"))
    except Exception as err:
        raise AuthorityError("EVALUATION_RESULT_MALFORMED", str(err)) from err

    try:
        cust_data = json.loads(cust_bytes.decode("utf-8"))
    except Exception as err:
        raise AuthorityError("CUSTODY_RECEIPT_MALFORMED", str(err)) from err

    try:
        disp_data = json.loads(disp_bytes.decode("utf-8"))
    except Exception as err:
        raise AuthorityError("DISPATCH_STATE_MALFORMED", str(err)) from err

    # 4. External Evaluator Validation
    facts = validate_evaluator_artifacts(eval_root, eval_py, req_data, res_data, lock)

    # 5. Control Plane Custody Schema Validation
    try:
        jsonschema.validate(instance=cust_data, schema=cp_info["custody_schema"])
    except Exception as err:
        raise AuthorityError("CONTROL_PLANE_CUSTODY_SCHEMA_VIOLATION", str(err)) from err

    # 6. Control Plane Custody Digest Recomputation
    computed_cust_digest = recompute_control_plane_custody_receipt_sha256(cust_data)
    declared_cust_digest = cust_data.get("receipt_sha256", "").lower()
    if declared_cust_digest != computed_cust_digest.lower():
        raise AuthorityError(
            "CONTROL_PLANE_CUSTODY_DIGEST_MISMATCH",
            f"declared '{declared_cust_digest}' != computed '{computed_cust_digest}'",
        )

    # 7. Raw Result Custody Binding
    if cust_data.get("evaluation_result_raw_sha256", "").lower() != raw_res_sha256.lower():
        raise AuthorityError(
            "CONTROL_PLANE_RAW_RESULT_BINDING_MISMATCH",
            f"custody raw '{cust_data.get('evaluation_result_raw_sha256')}' != computed raw '{raw_res_sha256}'",
        )

    # 8. Semantic Result Custody Binding
    if cust_data.get("evaluation_result_sha256", "").lower() != facts["result_sha256"].lower():
        raise AuthorityError("CONTROL_PLANE_RESULT_DIGEST_BINDING_MISMATCH")
    if cust_data.get("evaluation_id") != facts["evaluation_id"]:
        raise AuthorityError("CONTROL_PLANE_EVALUATION_ID_BINDING_MISMATCH")
    if cust_data.get("recommendation") != facts["recommendation"]:
        raise AuthorityError("CONTROL_PLANE_RECOMMENDATION_BINDING_MISMATCH")

    # 9. Request Custody Binding
    if cust_data.get("evaluation_request_id") != facts["request_id"]:
        raise AuthorityError("CONTROL_PLANE_REQUEST_ID_BINDING_MISMATCH")
    if cust_data.get("evaluation_request_sha256", "").lower() != facts["request_sha256"].lower():
        raise AuthorityError("CONTROL_PLANE_REQUEST_DIGEST_BINDING_MISMATCH")

    # 10. Candidate Binding
    if cust_data.get("candidate_repository") != facts["candidate_repository"]:
        raise AuthorityError("CANDIDATE_REPOSITORY_BINDING_MISMATCH")
    if cust_data.get("baseline_sha", "").lower() != facts["baseline_sha"].lower():
        raise AuthorityError("BASELINE_SHA_BINDING_MISMATCH")
    if cust_data.get("candidate_sha", "").lower() != facts["candidate_sha"].lower():
        raise AuthorityError("CANDIDATE_SHA_BINDING_MISMATCH")

    # 11. Task-Pack Binding
    if cust_data.get("task_pack_id") != facts["task_pack_id"]:
        raise AuthorityError("TASK_PACK_ID_BINDING_MISMATCH")
    if cust_data.get("task_pack_sha256", "").lower() != facts["task_pack_sha256"].lower():
        raise AuthorityError("TASK_PACK_DIGEST_BINDING_MISMATCH")

    # 12. Control Plane Source Binding
    if cust_data.get("control_plane_repository", "").lower() != lock["control_plane_repository"].lower():
        raise AuthorityError("CONTROL_PLANE_PROVENANCE_MISMATCH", "repository mismatch")
    if cust_data.get("control_plane_sha", "").lower() != lock["control_plane_sha"].lower():
        raise AuthorityError("CONTROL_PLANE_PROVENANCE_MISMATCH", "sha mismatch")

    # 13. Dispatch State Validation
    if disp_data.get("state") != "COMPLETE":
        raise AuthorityError("DISPATCH_STATE_NOT_COMPLETE", f"expected 'COMPLETE', got '{disp_data.get('state')}'")
    if disp_data.get("dispatch_id") != cust_data.get("dispatch_id"):
        raise AuthorityError("DISPATCH_ID_BINDING_MISMATCH")
    if disp_data.get("request_id") != facts["request_id"]:
        raise AuthorityError("DISPATCH_REQUEST_ID_BINDING_MISMATCH")
    if disp_data.get("request_sha256", "").lower() != facts["request_sha256"].lower():
        raise AuthorityError("DISPATCH_REQUEST_DIGEST_BINDING_MISMATCH")
    if disp_data.get("evaluator_sha", "").lower() != lock["evaluator_sha"].lower():
        raise AuthorityError("DISPATCH_EVALUATOR_SHA_BINDING_MISMATCH")
    if disp_data.get("candidate_sha", "").lower() != facts["candidate_sha"].lower():
        raise AuthorityError("DISPATCH_CANDIDATE_SHA_BINDING_MISMATCH")
    if disp_data.get("dispatch_source_sha", "").lower() != lock["control_plane_sha"].lower():
        raise AuthorityError("DISPATCH_SOURCE_SHA_BINDING_MISMATCH")

    # 14. Exit Code / Recommendation Consistency
    rec = facts["recommendation"]
    proc_rc = cust_data.get("evaluator_process_exit_code")
    if rec == "approve_candidate" and proc_rc != 0:
        raise AuthorityError("EVALUATOR_EXIT_RECOMMENDATION_INCONSISTENT", f"approve_candidate requires exit 0, got {proc_rc}")
    elif rec == "reject" and proc_rc != 1:
        raise AuthorityError("EVALUATOR_EXIT_RECOMMENDATION_INCONSISTENT", f"reject requires exit 1, got {proc_rc}")

    # 15. Source Authority Effect Verification
    if cust_data.get("authority_effect") != "NONE":
        raise AuthorityError("INVALID_SOURCE_AUTHORITY_EFFECT", f"expected 'NONE', got '{cust_data.get('authority_effect')}'")

    return {
        "lock": lock,
        "eval_info": eval_info,
        "cp_info": cp_info,
        "req_data": req_data,
        "res_data": res_data,
        "cust_data": cust_data,
        "disp_data": disp_data,
        "raw_req_sha256": raw_req_sha256,
        "raw_res_sha256": raw_res_sha256,
        "raw_cust_sha256": raw_cust_sha256,
        "raw_disp_sha256": raw_disp_sha256,
        "facts": facts,
        "proc_rc": proc_rc,
    }


def verify_evaluator_ingress_for_attestation(
    *,
    evaluator_ingress_path: Path,
    review_authority_root: Path,
    evaluator_root: Path,
    control_plane_root: Path,
    evaluator_python: Path,
    evaluation_request_path: Path,
    evaluation_result_path: Path,
    custody_receipt_path: Path,
    dispatch_state_path: Path,
) -> Dict[str, Any]:
    """Independently verifies accepted evaluator ingress envelope against raw foreign evidence and locks."""
    ra_root = Path(review_authority_root).resolve()
    ingr_path = Path(evaluator_ingress_path).resolve()

    if not ingr_path.exists() or not ingr_path.is_file():
        raise AuthorityError("EVALUATOR_INGRESS_NOT_FOUND", str(ingr_path))

    # 1. Load Attestation Ingress Lock
    att_lock = load_evaluator_ingress_attestation_lock(ra_root)

    # 2. Check Ingress Schema File and Digest
    ingr_schema_path = ra_root / att_lock["ingress_schema_path"]
    if not ingr_schema_path.exists() or not ingr_schema_path.is_file():
        raise AuthorityError("INGRESS_SCHEMA_MISSING", str(ingr_schema_path))
    actual_ingr_schema_sha = sha256_file(ingr_schema_path).lower()
    expected_ingr_schema_sha = att_lock["ingress_schema_sha256"].lower().removeprefix("sha256:")
    if actual_ingr_schema_sha != expected_ingr_schema_sha:
        raise AuthorityError(
            "INGRESS_SCHEMA_DIGEST_MISMATCH",
            f"actual '{actual_ingr_schema_sha}' != locked '{expected_ingr_schema_sha}'",
        )
    ingress_schema = read_json(ingr_schema_path)

    # 3. Verify Foreign Evidence Chain
    verified_foreign = verify_evaluator_evidence_source_set(
        review_authority_root=ra_root,
        evaluator_root=evaluator_root,
        control_plane_root=control_plane_root,
        evaluator_python=evaluator_python,
        evaluation_request_path=evaluation_request_path,
        evaluation_result_path=evaluation_result_path,
        custody_receipt_path=custody_receipt_path,
        dispatch_state_path=dispatch_state_path,
    )

    facts = verified_foreign["facts"]
    cust_data = verified_foreign["cust_data"]
    disp_data = verified_foreign["disp_data"]
    raw_req_sha256 = verified_foreign["raw_req_sha256"]
    raw_res_sha256 = verified_foreign["raw_res_sha256"]
    raw_cust_sha256 = verified_foreign["raw_cust_sha256"]
    raw_disp_sha256 = verified_foreign["raw_disp_sha256"]

    # 4. Load Ingress Envelope
    try:
        envelope = read_json(ingr_path)
    except Exception as err:
        raise AuthorityError("EVALUATOR_INGRESS_MALFORMED", str(err)) from err

    # 5. Compute Expected Ingress ID using Accepted Ingress Source SHA
    expected_ingr_id = compute_ingress_envelope_id(
        request_sha256=facts["request_sha256"],
        result_sha256=facts["result_sha256"],
        raw_result_sha256=raw_res_sha256,
        custody_receipt_sha256=cust_data["receipt_sha256"],
        raw_dispatch_state_sha256=raw_disp_sha256,
        evaluator_sha=att_lock["evaluator_sha"],
        control_plane_sha=att_lock["control_plane_sha"],
        review_authority_sha=att_lock["ingress_source_sha"],
    )

    # 6. Validate Persisted Envelope
    validate_evaluator_evidence_ingress_envelope(
        envelope,
        ingress_schema=ingress_schema,
        expected_ingress_id=expected_ingr_id,
        expected_review_authority_sha=att_lock["ingress_source_sha"],
        expected_evaluator_repository=att_lock["evaluator_repository"],
        expected_evaluator_sha=att_lock["evaluator_sha"],
        expected_control_plane_repository=att_lock["control_plane_repository"],
        expected_control_plane_sha=att_lock["control_plane_sha"],
        expected_request_facts=facts,
        expected_result_facts=facts,
        expected_custody=cust_data,
        expected_dispatch=disp_data,
        raw_request_sha256=raw_req_sha256,
        raw_result_sha256=raw_res_sha256,
        raw_custody_sha256=raw_cust_sha256,
        raw_dispatch_sha256=raw_disp_sha256,
    )

    return {
        "schema_version": "evaluator-evidence-ingress-v1",
        "ingress_id": envelope["ingress_id"],
        "ingress_sha256": envelope["ingress_sha256"],
        "ingress_review_authority_sha": envelope["review_authority_sha"],
        "evaluator_repository": envelope["evaluator_repository"],
        "evaluator_sha": envelope["evaluator_sha"],
        "control_plane_repository": envelope["control_plane_repository"],
        "control_plane_sha": envelope["control_plane_sha"],
        "evaluation_id": envelope["evaluation_id"],
        "evaluation_result_sha256": envelope["evaluation_result_sha256"],
        "recommendation": envelope["recommendation"],
        "task_pack_id": envelope["task_pack_id"],
        "task_pack_sha256": envelope["task_pack_sha256"],
        "authority_effect": "EVIDENCE_ONLY",
        "candidate_repository": envelope["candidate_repository"],
        "baseline_sha": envelope["baseline_sha"],
        "candidate_sha": envelope["candidate_sha"],
        "evaluator_process_exit_code": envelope["evaluator_process_exit_code"],
        "envelope": envelope,
    }


def ingest_evaluator_evidence(
    review_authority_root: Path,
    evaluator_root: Path,
    control_plane_root: Path,
    evaluator_python: Path,
    evaluation_request_path: Path,
    evaluation_result_path: Path,
    custody_receipt_path: Path,
    dispatch_state_path: Path,
    output_path: Path,
) -> Dict[str, Any]:
    """Principal evidence ingestion function for Review Authority."""
    ra_root = Path(review_authority_root).resolve()
    out_path = Path(output_path).resolve()

    # 1. Independently verify foreign evidence chain
    foreign = verify_evaluator_evidence_source_set(
        review_authority_root=ra_root,
        evaluator_root=evaluator_root,
        control_plane_root=control_plane_root,
        evaluator_python=evaluator_python,
        evaluation_request_path=evaluation_request_path,
        evaluation_result_path=evaluation_result_path,
        custody_receipt_path=custody_receipt_path,
        dispatch_state_path=dispatch_state_path,
    )

    lock = foreign["lock"]
    facts = foreign["facts"]
    cust_data = foreign["cust_data"]
    disp_data = foreign["disp_data"]
    raw_req_sha256 = foreign["raw_req_sha256"]
    raw_res_sha256 = foreign["raw_res_sha256"]
    raw_cust_sha256 = foreign["raw_cust_sha256"]
    raw_disp_sha256 = foreign["raw_disp_sha256"]
    proc_rc = foreign["proc_rc"]

    # 2. Verify Review Authority source
    ra_sha = verify_review_authority_source(ra_root)

    # 3. Ingress ID Computation
    ingress_id = compute_ingress_envelope_id(
        request_sha256=facts["request_sha256"],
        result_sha256=facts["result_sha256"],
        raw_result_sha256=raw_res_sha256,
        custody_receipt_sha256=cust_data["receipt_sha256"],
        raw_dispatch_state_sha256=raw_disp_sha256,
        evaluator_sha=lock["evaluator_sha"],
        control_plane_sha=lock["control_plane_sha"],
        review_authority_sha=ra_sha,
    )

    # 4. Load Ingress Schema
    ingress_schema_path = ra_root / "schemas" / "evaluator-evidence-ingress-v1.schema.json"
    if not ingress_schema_path.exists():
        raise AuthorityError("INGRESS_SCHEMA_MISSING", str(ingress_schema_path))
    ingress_schema = read_json(ingress_schema_path)

    # 5. Check Existing Output for Full Idempotent Revalidation (Section M)
    if out_path.exists():
        try:
            existing = read_json(out_path)
        except Exception as err:
            raise AuthorityError("EXISTING_INGRESS_ENVELOPE_MALFORMED", str(err)) from err

        # Perform strict canonical revalidation across all envelope fields
        validate_evaluator_evidence_ingress_envelope(
            existing,
            ingress_schema=ingress_schema,
            expected_ingress_id=ingress_id,
            expected_review_authority_sha=ra_sha,
            expected_evaluator_repository=lock["evaluator_repository"],
            expected_evaluator_sha=lock["evaluator_sha"],
            expected_control_plane_repository=lock["control_plane_repository"],
            expected_control_plane_sha=lock["control_plane_sha"],
            expected_request_facts=facts,
            expected_result_facts=facts,
            expected_custody=cust_data,
            expected_dispatch=disp_data,
            raw_request_sha256=raw_req_sha256,
            raw_result_sha256=raw_res_sha256,
            raw_custody_sha256=raw_cust_sha256,
            raw_dispatch_sha256=raw_disp_sha256,
        )

        return {
            "status": "IDEMPOTENT",
            "ingress_id": existing["ingress_id"],
            "ingress_sha256": existing["ingress_sha256"],
            "recommendation": existing["recommendation"],
            "authority_effect": existing["authority_effect"],
            "envelope": existing,
        }

    # 6. Assemble New Ingress Envelope
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    envelope = {
        "schema_version": "evaluator-evidence-ingress-v1",
        "ingress_id": ingress_id,
        "review_authority_repository": EXPECTED_REVIEW_AUTHORITY_REPO,
        "review_authority_sha": ra_sha,
        "evaluator_repository": lock["evaluator_repository"],
        "evaluator_sha": lock["evaluator_sha"],
        "control_plane_repository": lock["control_plane_repository"],
        "control_plane_sha": lock["control_plane_sha"],
        "evaluation_request_id": facts["request_id"],
        "evaluation_request_sha256": facts["request_sha256"],
        "evaluation_request_raw_sha256": raw_req_sha256,
        "evaluation_id": facts["evaluation_id"],
        "evaluation_result_sha256": facts["result_sha256"],
        "evaluation_result_raw_sha256": raw_res_sha256,
        "evaluation_result_schema": facts.get("schema_version", "miskatonic.evaluation.v2"),
        "custody_receipt_sha256": cust_data["receipt_sha256"],
        "custody_receipt_raw_sha256": raw_cust_sha256,
        "dispatch_id": cust_data["dispatch_id"],
        "dispatch_state_raw_sha256": raw_disp_sha256,
        "candidate_repository": facts["candidate_repository"],
        "baseline_sha": facts["baseline_sha"],
        "candidate_sha": facts["candidate_sha"],
        "task_pack_id": facts["task_pack_id"],
        "task_pack_sha256": facts["task_pack_sha256"],
        "recommendation": facts["recommendation"],
        "evaluator_process_exit_code": proc_rc,
        "request_contract_validation": "PASS",
        "result_contract_validation": "PASS",
        "request_result_binding": "PASS",
        "control_plane_custody_validation": "PASS",
        "dispatch_state_validation": "PASS",
        "evaluator_identity_validation": "PASS",
        "authority_effect": "EVIDENCE_ONLY",
        "ingested_at": now_iso,
    }

    env_for_digest = {k: v for k, v in envelope.items() if k != "ingress_sha256"}
    envelope["ingress_sha256"] = sha256_bytes(canonical_json_bytes(env_for_digest))

    # 7. Pre-write Validation (Section T)
    validate_evaluator_evidence_ingress_envelope(
        envelope,
        ingress_schema=ingress_schema,
        expected_ingress_id=ingress_id,
        expected_review_authority_sha=ra_sha,
        expected_evaluator_repository=lock["evaluator_repository"],
        expected_evaluator_sha=lock["evaluator_sha"],
        expected_control_plane_repository=lock["control_plane_repository"],
        expected_control_plane_sha=lock["control_plane_sha"],
        expected_request_facts=facts,
        expected_result_facts=facts,
        expected_custody=cust_data,
        expected_dispatch=disp_data,
        raw_request_sha256=raw_req_sha256,
        raw_result_sha256=raw_res_sha256,
        raw_custody_sha256=raw_cust_sha256,
        raw_dispatch_sha256=raw_disp_sha256,
    )

    # 8. Atomic Output Materialization (Section P, Q, R)
    write_ingress_json_atomically(out_path, envelope)

    return {
        "status": "INGRESS_READY",
        "ingress_id": ingress_id,
        "ingress_sha256": envelope["ingress_sha256"],
        "recommendation": envelope["recommendation"],
        "authority_effect": envelope["authority_effect"],
        "envelope": envelope,
    }
