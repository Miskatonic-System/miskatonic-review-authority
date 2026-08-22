"""Acceptance test suite for Review Authority Execution Evidence Verifier (WO-MSK-EXECUTION-EVIDENCE-ORG-01A Section 18, 19, 20)."""

import json
import pathlib
import pytest

from miskatonic_review_authority import verify_execution_evidence_attestation
from miskatonic_review_authority.util import AuthorityError


@pytest.fixture
def tmp_evidence(tmp_path):
    ledger_file = tmp_path / "execution.jsonl"
    result_file = tmp_path / "result.json"

    ledger_line = json.dumps({
        "schema_version": "miskatonic.execution-event.v1",
        "sequence": 1,
        "timestamp": "2026-08-22T00:00:00Z",
        "wo_id": "WO-ORG-TEST-01A",
        "attempt_id": "attempt_01",
        "phase": "VALIDATION",
        "event_type": "COMMAND_EXECUTION",
        "cwd": "/tmp",
        "command_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "command_summary": "pytest -q",
        "started_at": "2026-08-22T00:00:00Z",
        "completed_at": "2026-08-22T00:00:01Z",
        "duration_ms": 1000,
        "exit_code": 0,
        "stdout_sha256": None,
        "stderr_sha256": None,
        "status": "PASS",
    }) + "\n"
    ledger_file.write_text(ledger_line, encoding="utf-8")

    import hashlib
    ledger_digest = f"sha256:{hashlib.sha256(ledger_line.encode('utf-8')).hexdigest()}"

    result_data = {
        "schema_version": "miskatonic.execution-result.v1",
        "wo_id": "WO-ORG-TEST-01A",
        "attempt_id": "attempt_01",
        "derived_at": "2026-08-22T00:00:01Z",
        "ledger_sha256": ledger_digest,
        "terminal_verdict": "EXECUTION_EVIDENCE_LEDGER_READY",
        "fields": {
            "git": {
                "value": {"candidate_sha": "1288045a7c805d6d19c657f7f28addcaf76d7283"},
                "evidence_sequence": [1]
            }
        },
        "contradictions": [],
    }
    result_file.write_text(json.dumps(result_data, indent=2) + "\n", encoding="utf-8")

    return ledger_file, result_file, ledger_digest


def test_verify_execution_evidence_attestation_success(tmp_evidence):
    ledger_file, result_file, _ = tmp_evidence

    res = verify_execution_evidence_attestation(
        work_order_id="WO-ORG-TEST-01A",
        run_id="run_01",
        attempt_id="attempt_01",
        ledger_path=ledger_file,
        result_path=result_file,
        candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
        executor_principal="agent-os-executor",
        reviewer_principal="review-authority-checker",
    )

    assert res["verified"] is True
    assert res["work_order_id"] == "WO-ORG-TEST-01A"
    assert res["attempt_id"] == "attempt_01"


def test_executor_reviewer_principal_collision_fails_closed(tmp_evidence):
    """Test Section 20: executor principal cannot be reviewer principal for same result."""
    ledger_file, result_file, _ = tmp_evidence

    with pytest.raises(AuthorityError) as exc_info:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            executor_principal="same-principal",
            reviewer_principal="same-principal",
        )
    assert "EXECUTOR_REVIEWER_PRINCIPAL_COLLISION" in str(exc_info.value)


def test_ledger_digest_mismatch_fails_closed(tmp_evidence):
    """Test Section 18: digest mismatch fails closed."""
    ledger_file, result_file, _ = tmp_evidence
    ledger_file.write_text("modified ledger content\n", encoding="utf-8")

    with pytest.raises(AuthorityError) as exc_info:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            executor_principal="agent-os-executor",
            reviewer_principal="review-authority-checker",
        )
    assert "EXECUTION_LEDGER_DIGEST_MISMATCH" in str(exc_info.value)
