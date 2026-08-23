"""Acceptance test suite for Review Authority Execution Evidence Verifier (WO-MSK-PROGRAM-EXECUTION-TRUTH-01E-R4A Section 28)."""

import json
import hashlib
import pathlib
import pytest
import subprocess
import tempfile

from miskatonic_review_authority import verify_execution_evidence_attestation
import miskatonic_review_authority.attestation_ledger_verifier as verifier_mod
from miskatonic_review_authority.util import AuthorityError


def compute_auth_decision_digest(dec: dict) -> str:
    dec_at = dec.get("decided_at", "")
    dec_str = str(dec_at).replace("+00:00", "Z") if dec_at else ""
    bound = {
        "schema_version": dec.get("schema_version", "miskatonic.authorization-decision.v1"),
        "decision_id": dec.get("decision_id"),
        "allowed": dec.get("allowed"),
        "capability_name": dec.get("capability_name"),
        "policy_version": dec.get("policy_version"),
        "reason_code": dec.get("reason_code"),
        "reason": dec.get("reason"),
        "required_challenge": dec.get("required_challenge", False),
        "obligations": list(dec.get("obligations") or []),
        "work_order_id": dec.get("work_order_id"),
        "run_id": dec.get("run_id"),
        "attempt_id": dec.get("attempt_id"),
        "phase": dec.get("phase"),
        "state_digest": dec.get("state_digest"),
        "requested_effect_digest": dec.get("requested_effect_digest"),
        "decided_at": dec_str,
    }
    return f"sha256:{hashlib.sha256(json.dumps(bound, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()}"


@pytest.fixture
def dummy_keypair(tmp_path, monkeypatch):
    key_path = tmp_path / "test_private_key.pem"
    pub_key_path = tmp_path / "test_public_key.pem"
    der_path = tmp_path / "key.der"
    subprocess.run(["openssl", "genrsa", "-out", str(key_path), "2048"], capture_output=True, check=True)
    subprocess.run(["openssl", "rsa", "-in", str(key_path), "-pubout", "-out", str(pub_key_path)], capture_output=True, check=True)
    subprocess.run(["openssl", "pkey", "-in", str(key_path), "-pubout", "-outform", "DER", "-out", str(der_path)], capture_output=True, check=True)
    fp = f"sha256:{hashlib.sha256(der_path.read_bytes()).hexdigest()}"
    signer_config = {
        "schema_version": "miskatonic.review-trusted-signer.v1",
        "authority_id": "miskatonic-review-authority",
        "reviewer_principal": "review-authority-checker",
        "key_id": "review-authority-key-v1",
        "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
        "public_key_path": str(pub_key_path),
        "public_key_fingerprint": fp,
        "trust_root_version": "1.0.0",
        "lifecycle_state": "ACTIVE",
    }
    policy_file = tmp_path / "trusted-signers.json"
    policy_file.write_text(json.dumps(signer_config, indent=2), encoding="utf-8")
    monkeypatch.setattr(verifier_mod, "TRUSTED_SIGNERS_POLICY_PATH", policy_file)
    return key_path, signer_config


def build_evidence(tmp_path, mutate_rec=None, mutate_wrapper=None, mutate_result=None, mutate_decision=None):
    ledger_file = tmp_path / f"execution_{hashlib.md5(str(mutate_rec).encode()).hexdigest()[:8]}.jsonl"
    result_file = tmp_path / f"result_{hashlib.md5(str(mutate_result).encode()).hexdigest()[:8]}.json"

    auth_dec = {
        "schema_version": "miskatonic.authorization-decision.v1",
        "decision_id": "dec-100",
        "allowed": True,
        "capability_name": "val.exec",
        "policy_version": "1.0.0",
        "reason_code": "ALLOWED_POLICY",
        "reason": "Policy allowed execution",
        "required_challenge": False,
        "obligations": [],
        "work_order_id": "WO-ORG-TEST-01A",
        "run_id": "run_01",
        "attempt_id": "attempt_01",
        "phase": "VALIDATION",
        "state_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "requested_effect_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "decided_at": "2026-08-22T00:00:00Z",
    }
    if mutate_decision:
        mutate_decision(auth_dec)
    auth_dec["decision_digest"] = compute_auth_decision_digest(auth_dec)

    rec_dict = {
        "schema_version": "miskatonic.execution-event.v1",
        "work_order_id": "WO-ORG-TEST-01A",
        "wo_id": "WO-ORG-TEST-01A",
        "run_id": "run_01",
        "attempt_id": "attempt_01",
        "sequence": 1,
        "phase": "VALIDATION",
        "event_type": "COMMAND_EXECUTION",
        "timestamp": "2026-08-22T00:00:00Z",
        "cwd": "/tmp",
        "executor_principal": "agent-os-worker",
        "executor_provider": "agent-os",
        "authorization_decision_id": auth_dec["decision_id"],
        "authorization_decision_digest": auth_dec["decision_digest"],
        "requested_effect_digest": auth_dec["requested_effect_digest"],
        "authorization_decision": auth_dec,
        "capability_id": "val.exec",
        "repository_identity": "miskatonic-control-plane",
        "observed_head_sha": "1288045a7c805d6d19c657f7f28addcaf76d7283",
        "receipt_id": "rec-100",
        "command_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "command_summary": "pytest -q",
        "started_at": "2026-08-22T00:00:00Z",
        "completed_at": "2026-08-22T00:00:01Z",
        "duration_ms": 1000,
        "exit_code": 0,
        "stdout_sha256": None,
        "stderr_sha256": None,
        "status": "PASS",
    }
    if mutate_rec:
        mutate_rec(rec_dict)

    if "receipt_digest" not in rec_dict:
        rec_digest = f"sha256:{hashlib.sha256((json.dumps(rec_dict, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode('utf-8')).hexdigest()}"
        rec_dict["receipt_digest"] = rec_digest
    else:
        rec_digest = rec_dict["receipt_digest"]

    wrapper_event = {
        "schema_version": "miskatonic.work-order-ledger-event.v1",
        "ledger_sequence": 1,
        "work_order_id": "WO-ORG-TEST-01A",
        "wo_id": "WO-ORG-TEST-01A",
        "run_id": "run_01",
        "attempt_id": "attempt_01",
        "event_kind": "EXECUTION_RECEIPT",
        "timestamp": "2026-08-22T00:00:00Z",
        "receipt": rec_dict,
        "receipt_digest": rec_digest,
    }
    if mutate_wrapper:
        mutate_wrapper(wrapper_event)

    ledger_line = json.dumps(wrapper_event, sort_keys=True, separators=(",", ":")) + "\n"
    ledger_file.write_text(ledger_line, encoding="utf-8")
    ledger_digest = f"sha256:{hashlib.sha256(ledger_line.encode('utf-8')).hexdigest()}"

    result_data = {
        "schema_version": "miskatonic.execution-result.v1",
        "wo_id": "WO-ORG-TEST-01A",
        "run_id": "run_01",
        "attempt_id": "attempt_01",
        "derived_at": "2026-08-22T00:00:01Z",
        "ledger_sha256": ledger_digest,
        "terminal_verdict": "EXECUTION_EVIDENCE_LEDGER_READY",
        "fields": {
            "git": {
                "value": {"candidate_sha": "1288045a7c805d6d19c657f7f28addcaf76d7283"},
                "evidence_sequence": [1]
            },
            "pytest": {
                "value": {"status": "PASS", "attempts": 1, "exit_code": 0},
                "evidence_sequence": [1]
            }
        },
        "contradictions": [],
    }
    if mutate_result:
        mutate_result(result_data)

    result_file.write_text(json.dumps(result_data, indent=2) + "\n", encoding="utf-8")
    return ledger_file, result_file, ledger_digest


def test_verify_execution_evidence_attestation_success(tmp_path, dummy_keypair):
    key_path, signer_config = dummy_keypair
    ledger_file, result_file, _ = build_evidence(tmp_path)

    res = verify_execution_evidence_attestation(
        work_order_id="WO-ORG-TEST-01A",
        run_id="run_01",
        attempt_id="attempt_01",
        ledger_path=ledger_file,
        result_path=result_file,
        candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
        executor_principal="agent-os-worker",
        reviewer_principal="review-authority-checker",
        private_key_path=key_path,
        key_id="review-authority-key-v1",
    )

    assert res["verified"] is True
    assert res["work_order_id"] == "WO-ORG-TEST-01A"
    assert res["run_id"] == "run_01"
    assert res["attempt_id"] == "attempt_01"
    assert res["authorization_decision_id"] == "dec-100"
    assert res["producer_principal"] == "agent-os-worker"
    assert res["reviewer_principal"] == "review-authority-checker"


# Test A: custody receipt lacks authorization_decision -> REJECT (AUTHORIZATION_DECISION_MISSING)
def test_neg_a_missing_authorization_decision(tmp_path, dummy_keypair):
    key_path, _ = dummy_keypair
    def mutate(rec):
        rec.pop("authorization_decision", None)
    ledger_file, result_file, _ = build_evidence(tmp_path, mutate_rec=mutate)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=key_path,
        )
    assert "AUTHORIZATION_DECISION_MISSING" in str(exc.value)


# Test B: decision digest valid but capability differs -> REJECT (CAPABILITY_ID_MISMATCH)
def test_neg_b_capability_mismatch(tmp_path, dummy_keypair):
    key_path, _ = dummy_keypair
    def mutate_dec(dec):
        dec["capability_name"] = "other.capability"
    ledger_file, result_file, _ = build_evidence(tmp_path, mutate_decision=mutate_dec)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=key_path,
        )
    assert "CAPABILITY_ID_MISMATCH" in str(exc.value)


# Test C: work_order_id differs -> REJECT (WORK_ORDER_ID_MISMATCH)
def test_neg_c_work_order_id_mismatch(tmp_path, dummy_keypair):
    key_path, _ = dummy_keypair
    def mutate_dec(dec):
        dec["work_order_id"] = "WO-OTHER-01"
    ledger_file, result_file, _ = build_evidence(tmp_path, mutate_decision=mutate_dec)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=key_path,
        )
    assert "WORK_ORDER_ID_MISMATCH" in str(exc.value)


# Test D: run_id differs -> REJECT (RUN_ID_MISMATCH)
def test_neg_d_run_id_mismatch(tmp_path, dummy_keypair):
    key_path, _ = dummy_keypair
    def mutate_dec(dec):
        dec["run_id"] = "other_run_99"
    ledger_file, result_file, _ = build_evidence(tmp_path, mutate_decision=mutate_dec)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=key_path,
        )
    assert "RUN_ID_MISMATCH" in str(exc.value)


# Test E: attempt_id differs -> REJECT (ATTEMPT_ID_MISMATCH)
def test_neg_e_attempt_id_mismatch(tmp_path, dummy_keypair):
    key_path, _ = dummy_keypair
    def mutate_dec(dec):
        dec["attempt_id"] = "other_attempt_99"
    ledger_file, result_file, _ = build_evidence(tmp_path, mutate_decision=mutate_dec)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=key_path,
        )
    assert "ATTEMPT_ID_MISMATCH" in str(exc.value)


# Test J: signing with unregistered private key -> REJECT (REVIEW_SIGNER_NOT_TRUSTED)
def test_neg_j_unregistered_private_key(tmp_path, dummy_keypair):
    _, _ = dummy_keypair
    other_key = tmp_path / "other_key.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(other_key), "2048"], capture_output=True, check=True)
    ledger_file, result_file, _ = build_evidence(tmp_path)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=other_key,
            key_id="review-authority-key-v1",
        )
    assert "REVIEW_SIGNER_NOT_TRUSTED" in str(exc.value)


# Test K: trusted key fingerprint mismatch -> REJECT (REVIEW_SIGNER_NOT_TRUSTED)
def test_neg_k_trusted_fingerprint_mismatch(tmp_path, dummy_keypair, monkeypatch):
    key_path, signer_config = dummy_keypair
    bad_config = dict(signer_config)
    bad_config["public_key_fingerprint"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    policy_file = tmp_path / "bad_fp_policy.json"
    policy_file.write_text(json.dumps(bad_config, indent=2), encoding="utf-8")
    monkeypatch.setattr(verifier_mod, "TRUSTED_SIGNERS_POLICY_PATH", policy_file)
    ledger_file, result_file, _ = build_evidence(tmp_path)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=key_path,
        )
    assert ("REVIEW_TRUST_ROOT_INVALID" in str(exc.value) or "REVIEW_SIGNER_NOT_TRUSTED" in str(exc.value))


# Test L: reviewer_principal mismatch with trusted signer config -> REJECT (REVIEW_SIGNER_NOT_TRUSTED)
def test_neg_l_reviewer_principal_mismatch(tmp_path, dummy_keypair):
    key_path, _ = dummy_keypair
    ledger_file, result_file, _ = build_evidence(tmp_path)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            reviewer_principal="asserted-fake-reviewer",
            private_key_path=key_path,
        )
    assert "REVIEW_SIGNER_NOT_TRUSTED" in str(exc.value)


# Test M: producer assertion mismatch with receipt principal -> REJECT (EXECUTOR_PRINCIPAL_MISMATCH)
def test_neg_m_producer_assertion_mismatch(tmp_path, dummy_keypair):
    key_path, _ = dummy_keypair
    ledger_file, result_file, _ = build_evidence(tmp_path)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            executor_principal="asserted-fake-worker",
            private_key_path=key_path,
        )
    assert "EXECUTOR_PRINCIPAL_MISMATCH" in str(exc.value)


# Test N: bare execution-event-v1 line -> REJECT (CUSTODY_WRAPPER_REQUIRED)
def test_neg_n_bare_execution_event_rejected(tmp_path, dummy_keypair):
    key_path, _ = dummy_keypair
    ledger_file = tmp_path / "bare.jsonl"
    result_file = tmp_path / "res_bare.json"

    bare_line = json.dumps({
        "schema_version": "miskatonic.execution-event.v1",
        "work_order_id": "WO-ORG-TEST-01A",
        "run_id": "run_01",
        "attempt_id": "attempt_01",
        "sequence": 1,
        "phase": "VALIDATION",
        "event_type": "COMMAND_EXECUTION",
    }) + "\n"
    ledger_file.write_text(bare_line, encoding="utf-8")
    ledger_digest = f"sha256:{hashlib.sha256(bare_line.encode('utf-8')).hexdigest()}"

    result_data = {
        "schema_version": "miskatonic.execution-result.v1",
        "wo_id": "WO-ORG-TEST-01A",
        "run_id": "run_01",
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

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=key_path,
        )
    assert "CUSTODY_WRAPPER_REQUIRED" in str(exc.value)


# Test O: CONTROL_EVENT-only ledger -> REJECT (NO_AUTHENTICATED_EXECUTION_EVIDENCE)
def test_neg_o_control_event_only_ledger_rejected(tmp_path, dummy_keypair):
    key_path, _ = dummy_keypair
    ledger_file = tmp_path / "ctrl_only.jsonl"
    result_file = tmp_path / "res_ctrl.json"

    ledger_line = json.dumps({
        "schema_version": "miskatonic.work-order-ledger-event.v1",
        "ledger_sequence": 1,
        "work_order_id": "WO-CTRL-ONLY-01",
        "run_id": "run_01",
        "attempt_id": "attempt_01",
        "event_kind": "CONTROL_EVENT",
        "timestamp": "2026-08-22T00:00:00Z",
        "control_payload": {"event_type": "ARTIFACT_WITNESS"},
    }) + "\n"
    ledger_file.write_text(ledger_line, encoding="utf-8")
    ledger_digest = f"sha256:{hashlib.sha256(ledger_line.encode('utf-8')).hexdigest()}"

    result_data = {
        "schema_version": "miskatonic.execution-result.v1",
        "wo_id": "WO-CTRL-ONLY-01",
        "run_id": "run_01",
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

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-CTRL-ONLY-01",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=key_path,
        )
    assert "NO_AUTHENTICATED_EXECUTION_EVIDENCE" in str(exc.value)


# SECTION 28 SPECIFIC NEGATIVE FIXTURES FOR REVIEW TRUST
def test_review_trust_negative_a_default_signer_unconfigured_fails_closed(tmp_path, monkeypatch):
    """28A: default signer registry UNCONFIGURED -> production signing/verification rejected."""
    key_path = tmp_path / "key.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(key_path), "2048"], capture_output=True, check=True)
    unconf_policy = tmp_path / "unconf.json"
    unconf_policy.write_text(json.dumps({
        "schema_version": "miskatonic.review-trusted-signer.v1",
        "authority_id": "miskatonic-review-authority",
        "reviewer_principal": None,
        "key_id": None,
        "public_key_fingerprint": None,
        "trust_root_version": "1.0.0",
        "lifecycle_state": "UNCONFIGURED",
    }), encoding="utf-8")
    monkeypatch.setattr(verifier_mod, "TRUSTED_SIGNERS_POLICY_PATH", unconf_policy)
    ledger_file, result_file, _ = build_evidence(tmp_path)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=key_path,
        )
    assert "TRUSTED_SIGNER_UNAVAILABLE" in str(exc.value)


def test_review_trust_negative_b_wildcard_fingerprint_rejected(tmp_path, monkeypatch):
    """28B: wildcard fingerprint in policy -> REVIEW_TRUST_ROOT_INVALID."""
    key_path = tmp_path / "key.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(key_path), "2048"], capture_output=True, check=True)
    wild_policy = tmp_path / "wild.json"
    wild_policy.write_text(json.dumps({
        "schema_version": "miskatonic.review-trusted-signer.v1",
        "authority_id": "miskatonic-review-authority",
        "reviewer_principal": "review-authority-checker",
        "key_id": "key-1",
        "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
        "public_key_fingerprint": "*",
        "trust_root_version": "1.0.0",
        "lifecycle_state": "ACTIVE",
    }), encoding="utf-8")
    monkeypatch.setattr(verifier_mod, "TRUSTED_SIGNERS_POLICY_PATH", wild_policy)
    ledger_file, result_file, _ = build_evidence(tmp_path)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=key_path,
        )
    assert "REVIEW_TRUST_ROOT_INVALID" in str(exc.value)


def test_review_trust_negative_c_wildcard_reviewer_rejected(tmp_path, monkeypatch):
    """28C: wildcard reviewer in policy -> REVIEW_TRUST_ROOT_INVALID."""
    key_path = tmp_path / "key.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(key_path), "2048"], capture_output=True, check=True)
    wild_policy = tmp_path / "wild_rev.json"
    wild_policy.write_text(json.dumps({
        "schema_version": "miskatonic.review-trusted-signer.v1",
        "authority_id": "miskatonic-review-authority",
        "reviewer_principal": "*",
        "key_id": "key-1",
        "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
        "public_key_fingerprint": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "trust_root_version": "1.0.0",
        "lifecycle_state": "ACTIVE",
    }), encoding="utf-8")
    monkeypatch.setattr(verifier_mod, "TRUSTED_SIGNERS_POLICY_PATH", wild_policy)
    ledger_file, result_file, _ = build_evidence(tmp_path)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=key_path,
        )
    assert "REVIEW_TRUST_ROOT_INVALID" in str(exc.value)


def test_review_trust_negative_d_arbitrary_caller_trust_config_rejected(tmp_path, dummy_keypair):
    """28D: arbitrary caller trust config passed to production API -> REVIEW_TRUST_ROOT_INVALID."""
    key_path, signer_config = dummy_keypair
    ledger_file, result_file, _ = build_evidence(tmp_path)

    with pytest.raises(AuthorityError) as exc:
        verify_execution_evidence_attestation(
            work_order_id="WO-ORG-TEST-01A",
            run_id="run_01",
            attempt_id="attempt_01",
            ledger_path=ledger_file,
            result_path=result_file,
            candidate_sha="1288045a7c805d6d19c657f7f28addcaf76d7283",
            private_key_path=key_path,
            trusted_signer_config=signer_config,
        )
    assert "REVIEW_TRUST_ROOT_INVALID" in str(exc.value)
