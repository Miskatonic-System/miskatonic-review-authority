"""Review Authority Execution Evidence Attestation Verifier (WO-MSK-EXECUTION-EVIDENCE-ORG-01A Section 18, 19, 20)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .util import AuthorityError, read_json


def verify_execution_evidence_attestation(
    *,
    work_order_id: str,
    run_id: str,
    attempt_id: str,
    ledger_path: str | Path,
    result_path: str | Path,
    candidate_sha: str,
    executor_principal: str,
    reviewer_principal: str,
) -> dict[str, Any]:
    """Verifies work-order execution evidence ledger & derived result digests and attests validity (Section 18, 19, 20).
    
    Fails closed if:
    - ledger or result file absent
    - digest mismatch
    - missing provenance
    - executor_principal == reviewer_principal (Section 20 self-attestation prohibition)
    """
    # Rule 1: Producer/Reviewer Separation (Section 20)
    if executor_principal.lower() == reviewer_principal.lower():
        raise AuthorityError("EXECUTOR_REVIEWER_PRINCIPAL_COLLISION", f"Executor principal '{executor_principal}' cannot be review principal.")

    ledger_file = Path(ledger_path)
    result_file = Path(result_path)

    if not ledger_file.exists():
        raise AuthorityError("EXECUTION_LEDGER_ABSENT", f"Execution ledger missing at {ledger_path}")
    if not result_file.exists():
        raise AuthorityError("EXECUTION_RESULT_ABSENT", f"Execution result missing at {result_path}")

    # Compute actual ledger sha256
    ledger_bytes = ledger_file.read_bytes()
    ledger_digest = f"sha256:{hashlib.sha256(ledger_bytes).hexdigest()}"

    result_data = read_json(str(result_file))

    # Verify ledger digest binding
    if result_data.get("ledger_sha256") != ledger_digest:
        raise AuthorityError(
            "EXECUTION_LEDGER_DIGEST_MISMATCH",
            f"Result ledger_sha256 {result_data.get('ledger_sha256')} != computed {ledger_digest}"
        )

    # Verify work_order_id & attempt_id binding
    if result_data.get("wo_id") != work_order_id:
        raise AuthorityError("WORK_ORDER_ID_MISMATCH", f"Result wo_id {result_data.get('wo_id')} != {work_order_id}")
    if result_data.get("attempt_id") != attempt_id:
        raise AuthorityError("ATTEMPT_ID_MISMATCH", f"Result attempt_id {result_data.get('attempt_id')} != {attempt_id}")

    # Check git candidate SHA if present in fields
    git_val = result_data.get("fields", {}).get("git", {}).get("value")
    if git_val and isinstance(git_val, dict):
        observed_sha = git_val.get("candidate_sha")
        if observed_sha and observed_sha.lower() != candidate_sha.lower():
            raise AuthorityError(
                "CANDIDATE_SHA_MISMATCH",
                f"Result candidate_sha {observed_sha} != expected {candidate_sha}"
            )

    return {
        "verified": True,
        "work_order_id": work_order_id,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "ledger_sha256": ledger_digest,
        "result_sha256": f"sha256:{hashlib.sha256(result_file.read_bytes()).hexdigest()}",
        "terminal_verdict": result_data.get("terminal_verdict"),
        "executor_principal": executor_principal,
        "reviewer_principal": reviewer_principal,
    }
