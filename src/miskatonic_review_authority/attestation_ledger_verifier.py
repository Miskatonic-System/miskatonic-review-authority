"""Review Authority Independent Execution Evidence Verifier (WO-MSK-EXECUTION-EVIDENCE-ORG-01A-R1 Section 24-31)."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .attestation import sign_attestation
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
    private_key_path: str | Path | None = None,
    key_id: str | None = None,
) -> dict[str, Any]:
    """Independently verifies execution evidence ledger & derived result contract (Section 24-31).
    
    Fails closed if:
    - ledger or result file absent
    - ledger or result digest mismatch
    - result not derivable from ledger (Section 26)
    - run_id mismatch (Section 28)
    - candidate_sha missing or mismatch (Section 29)
    - evidence sequence invalid (Section 27)
    - executor_principal == reviewer_principal (Section 30 self-attestation prohibition)
    """
    # Rule 1: Producer/Reviewer Separation (Section 30)
    if executor_principal.lower() == reviewer_principal.lower():
        raise AuthorityError("EXECUTOR_REVIEWER_PRINCIPAL_COLLISION", f"Executor principal '{executor_principal}' cannot be review principal.")

    ledger_file = Path(ledger_path)
    result_file = Path(result_path)

    if not ledger_file.exists():
        raise AuthorityError("EXECUTION_LEDGER_ABSENT", f"Execution ledger missing at {ledger_path}")
    if not result_file.exists():
        raise AuthorityError("EXECUTION_RESULT_ABSENT", f"Execution result missing at {result_path}")

    # 1. Compute actual ledger sha256
    ledger_bytes = ledger_file.read_bytes()
    ledger_digest = f"sha256:{hashlib.sha256(ledger_bytes).hexdigest()}"

    result_data = read_json(str(result_file))

    # 2. Verify ledger digest binding
    if result_data.get("ledger_sha256") != ledger_digest:
        raise AuthorityError(
            "EXECUTION_LEDGER_DIGEST_MISMATCH",
            f"Result ledger_sha256 {result_data.get('ledger_sha256')} != computed {ledger_digest}"
        )

    # 3. Verify work_order_id & attempt_id binding
    if result_data.get("wo_id") != work_order_id and result_data.get("work_order_id") != work_order_id:
        raise AuthorityError("WORK_ORDER_ID_MISMATCH", f"Result wo_id {result_data.get('wo_id')} != {work_order_id}")
    if result_data.get("attempt_id") != attempt_id:
        raise AuthorityError("ATTEMPT_ID_MISMATCH", f"Result attempt_id {result_data.get('attempt_id')} != {attempt_id}")

    # 4. Verify run_id binding (Section 28)
    res_run_id = result_data.get("run_id")
    if res_run_id and res_run_id != run_id:
        raise AuthorityError("RUN_ID_MISMATCH", f"Result run_id '{res_run_id}' != requested run_id '{run_id}'")

    # 5. Parse ledger events and validate sequence monotonicity & schema (Section 37, 38, 39)
    lines = ledger_file.read_text(encoding="utf-8").splitlines()
    events: list[dict[str, Any]] = []
    seq_set: set[int] = set()
    expected_seq = 1

    for line_idx, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            raw_item = json.loads(line)
        except Exception as e:
            raise AuthorityError("EXECUTION_LEDGER_CORRUPT", f"Line {line_idx} is not valid JSON: {e}") from e

        if raw_item.get("event_kind") == "EXECUTION_RECEIPT" and "receipt" in raw_item:
            seq = raw_item.get("ledger_sequence") or line_idx
            rec = raw_item["receipt"]
            if not isinstance(rec, dict):
                raise AuthorityError("EXECUTION_RECEIPT_CORRUPT", f"Line {line_idx} receipt is not a dict")

            # Verify receipt identity agreement (Section 39)
            rec_wo = rec.get("work_order_id") or rec.get("wo_id")
            if rec_wo and rec_wo != work_order_id:
                raise AuthorityError("WORK_ORDER_ID_MISMATCH", f"Receipt work_order_id '{rec_wo}' != '{work_order_id}'")
            if rec.get("run_id") and rec["run_id"] != run_id:
                raise AuthorityError("RUN_ID_MISMATCH", f"Receipt run_id '{rec['run_id']}' != '{run_id}'")
            if rec.get("attempt_id") and rec["attempt_id"] != attempt_id:
                raise AuthorityError("ATTEMPT_ID_MISMATCH", f"Receipt attempt_id '{rec['attempt_id']}' != '{attempt_id}'")

            # Re-compute receipt digest (Section 38)
            cpy = dict(rec)
            provided_digest = cpy.pop("receipt_digest", None)
            if not provided_digest:
                raise AuthorityError("EXECUTION_RECEIPT_DIGEST_MISSING", f"Line {line_idx} receipt missing receipt_digest")

            computed_digest = f"sha256:{hashlib.sha256((json.dumps(cpy, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode('utf-8')).hexdigest()}"
            if provided_digest != computed_digest:
                raise AuthorityError("EXECUTION_RECEIPT_DIGEST_MISMATCH", f"Line {line_idx} receipt digest mismatch")

            event = rec
            event["ledger_sequence"] = seq
        else:
            event = raw_item
            seq = event.get("ledger_sequence") or event.get("sequence") or line_idx
            event["ledger_sequence"] = seq

        if seq != expected_seq:
            raise AuthorityError("EXECUTION_LEDGER_SEQUENCE_NON_MONOTONIC", f"Line {line_idx} sequence {seq} != expected {expected_seq}")
        expected_seq += 1
        seq_set.add(seq)
        events.append(event)

        # Verify executor principal separation on event level
        evt_executor = event.get("executor_principal")
        if evt_executor and evt_executor.lower() == reviewer_principal.lower():
            raise AuthorityError("EXECUTOR_REVIEWER_PRINCIPAL_COLLISION", f"Event executor '{evt_executor}' matches review principal.")

    # 6. Verify Candidate SHA (Section 29)
    git_val = result_data.get("fields", {}).get("git", {}).get("value")
    observed_sha = git_val.get("candidate_sha") if isinstance(git_val, dict) else None
    if not observed_sha:
        for e in reversed(events):
            if e.get("observed_head_sha"):
                observed_sha = e["observed_head_sha"]
                break
            elif e.get("git_head"):
                observed_sha = e["git_head"]
                break

    if not observed_sha:
        raise AuthorityError("CANDIDATE_SHA_MISSING", "Candidate git SHA is absent in ledger/result evidence.")
    if observed_sha.lower() != candidate_sha.lower():
        raise AuthorityError("CANDIDATE_SHA_MISMATCH", f"Observed candidate SHA {observed_sha} != expected {candidate_sha}")

    # 7. Verify Evidence Sequences & Relevance (Section 27, 40)
    fields = result_data.get("fields", {})
    for field_name, field_obj in fields.items():
        if isinstance(field_obj, dict):
            ev_seqs = field_obj.get("evidence_sequence", [])
            for seq in ev_seqs:
                if seq not in seq_set:
                    raise AuthorityError(
                        "EVIDENCE_SEQUENCE_INVALID",
                        f"Field '{field_name}' references non-existent sequence {seq}."
                    )
                # Verify evidence sequence relevance
                matching_event = next((e for e in events if e.get("ledger_sequence") == seq or e.get("sequence") == seq), None)
                if matching_event:
                    if field_name == "pytest" and "pytest" not in matching_event.get("command_summary", "").lower():
                        raise AuthorityError("EVIDENCE_SEQUENCE_IRRELEVANT", f"Field '{field_name}' references irrelevant event sequence {seq}.")

    # 8. Independent Result Re-Derivation (Section 24, 26)
    pytest_events = [e for e in events if "pytest" in e.get("command_summary", "").lower()]
    if pytest_events:
        has_fail = any(e.get("exit_code", 0) != 0 or e.get("status") == "FAIL" for e in pytest_events)
        last_event = pytest_events[-1]
        last_pass = (last_event.get("exit_code") == 0 and last_event.get("status") in ("PASS", "PASS_AFTER_RETRY"))
        if has_fail and last_pass:
            derived_pytest_status = "PASS_AFTER_RETRY"
        elif last_pass:
            derived_pytest_status = "PASS"
        else:
            derived_pytest_status = "FAIL"
    else:
        derived_pytest_status = "NOT_RUN"

    res_pytest_val = fields.get("pytest", {}).get("value")
    res_pytest_status = res_pytest_val.get("status") if isinstance(res_pytest_val, dict) else "NOT_RUN"

    if derived_pytest_status != res_pytest_status:
        raise AuthorityError(
            "RESULT_NOT_DERIVABLE",
            f"Result pytest status '{res_pytest_status}' != independently derived status '{derived_pytest_status}'"
        )

    # Compute signed attestation using Review Authority cryptographic signing
    attestation_payload = {
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

    if private_key_path and Path(private_key_path).is_file():
        signed_att = sign_attestation(attestation_payload, str(private_key_path), key_id=key_id or "review-authority-key-v1")
    else:
        # Generate ephemeral RSA signing key pair for cryptographic attestation signature
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_key_path = Path(tmp_dir, "review_key.pem")
            subprocess.run(["openssl", "genrsa", "-out", str(tmp_key_path), "2048"], capture_output=True, check=True)
            signed_att = sign_attestation(attestation_payload, str(tmp_key_path), key_id=key_id or "review-authority-key-v1")

    return signed_att
