"""Review Authority Independent Execution Evidence Verifier (WO-MSK-PROGRAM-EXECUTION-TRUTH-01E-R4)."""

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
    executor_principal: str | None = None,
    reviewer_principal: str | None = None,
    private_key_path: str | Path | None = None,
    key_id: str | None = None,
    trusted_signer_config: str | Path | dict[str, Any] | None = None,
    authorization_decision: str | Path | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Independently verifies execution evidence ledger & derived result contract (WO-01E-R4).

    Fails closed if:
    - ledger or result file absent
    - ledger or result digest mismatch
    - result not derivable from ledger
    - run_id / attempt_id / work_order_id mismatch
    - candidate_sha missing or mismatch
    - evidence sequence invalid
    - executor_principal == reviewer_principal (self-attestation prohibition)
    - authorization decision missing or unverified
    - custody wrapper identity or receipt digest mismatch
    - trusted signer verification failure
    """
    # Rule 1: Producer/Reviewer Separation (Section 30)
    if executor_principal and reviewer_principal and executor_principal.strip().lower() == reviewer_principal.strip().lower():
        raise AuthorityError(
            "EXECUTOR_REVIEWER_PRINCIPAL_COLLISION",
            f"Executor principal '{executor_principal}' cannot be review principal.",
        )

    # 1. Check evidence files presence
    ledger_file = Path(ledger_path)
    result_file = Path(result_path)

    if not ledger_file.exists():
        raise AuthorityError("EXECUTION_LEDGER_ABSENT", f"Execution ledger missing at {ledger_path}")
    if not result_file.exists():
        raise AuthorityError("EXECUTION_RESULT_ABSENT", f"Execution result missing at {result_path}")

    # 2. Compute ledger digest from file bytes
    ledger_digest = f"sha256:{hashlib.sha256(ledger_file.read_bytes()).hexdigest()}"

    # 3. Read and validate derived result contract
    try:
        result_data = read_json(str(result_file))
    except Exception as e:
        raise AuthorityError("RESULT_CORRUPT", f"Result JSON at {result_path} is corrupt: {e}") from e

    res_schema = result_data.get("schema_version")
    if not res_schema or res_schema != "miskatonic.execution-result.v1":
        raise AuthorityError(
            "SCHEMA_VERSION_UNSUPPORTED",
            f"Result schema_version '{res_schema}' != 'miskatonic.execution-result.v1'",
        )

    res_wo_id = result_data.get("work_order_id") or result_data.get("wo_id")
    if not res_wo_id:
        raise AuthorityError("WORK_ORDER_ID_MISSING", "Result work_order_id is missing.")
    if res_wo_id != work_order_id:
        raise AuthorityError(
            "WORK_ORDER_ID_MISMATCH",
            f"Result work_order_id '{res_wo_id}' != requested '{work_order_id}'",
        )

    res_run_id = result_data.get("run_id")
    if not res_run_id:
        raise AuthorityError("RUN_ID_MISSING", "Result run_id is missing.")
    if res_run_id != run_id:
        raise AuthorityError(
            "RUN_ID_MISMATCH",
            f"Result run_id '{res_run_id}' != requested '{run_id}'",
        )

    res_attempt_id = result_data.get("attempt_id")
    if not res_attempt_id:
        raise AuthorityError("ATTEMPT_ID_MISSING", "Result attempt_id is missing.")
    if res_attempt_id != attempt_id:
        raise AuthorityError(
            "ATTEMPT_ID_MISMATCH",
            f"Result attempt_id '{res_attempt_id}' != requested '{attempt_id}'",
        )

    res_ledger_sha = result_data.get("ledger_sha256")
    if not res_ledger_sha:
        raise AuthorityError("LEDGER_DIGEST_MISSING", "Result ledger_sha256 is missing.")
    if res_ledger_sha != ledger_digest:
        raise AuthorityError(
            "EXECUTION_LEDGER_DIGEST_MISMATCH",
            f"Result ledger_sha256 '{res_ledger_sha}' != computed '{ledger_digest}'",
        )

    # 4. Check signing key availability and resolve trusted signer
    if not private_key_path or not Path(private_key_path).is_file():
        raise AuthorityError(
            "TRUSTED_SIGNER_UNAVAILABLE",
            "Trusted signing key unavailable: private_key_path must be provided and exist.",
        )

    with tempfile.TemporaryDirectory() as directory:
        der_path = Path(directory, "key.der")
        res = subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key_path),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                str(der_path),
            ],
            capture_output=True,
        )
        if res.returncode != 0:
            raise AuthorityError(
                "TRUSTED_SIGNER_UNAVAILABLE",
                f"Private key at '{private_key_path}' is invalid RSA key.",
            )
        derived_key_fingerprint = f"sha256:{hashlib.sha256(der_path.read_bytes()).hexdigest()}"

    # Resolve trusted signer configuration (Section 6, 7, 8)
    if trusted_signer_config is None:
        default_signer_path = Path(__file__).resolve().parent.parent.parent / "policy" / "trusted-signers.json"
        if default_signer_path.is_file():
            trusted_signer = read_json(str(default_signer_path))
        else:
            raise AuthorityError(
                "TRUSTED_SIGNER_UNAVAILABLE",
                f"Default trusted signer configuration not found at {default_signer_path}",
            )
    elif isinstance(trusted_signer_config, (str, Path)):
        trusted_signer = read_json(str(trusted_signer_config))
    elif isinstance(trusted_signer_config, dict):
        trusted_signer = dict(trusted_signer_config)
    else:
        raise AuthorityError("REVIEW_SIGNER_NOT_TRUSTED", "Invalid trusted_signer_config type.")

    if trusted_signer.get("schema_version") != "miskatonic.review-trusted-signer.v1":
        raise AuthorityError("REVIEW_SIGNER_NOT_TRUSTED", "Trusted signer config invalid schema.")

    if trusted_signer.get("lifecycle_state") not in ("ACTIVE", "TRUSTED"):
        raise AuthorityError("REVIEW_SIGNER_NOT_TRUSTED", "Trusted signer is not in ACTIVE/TRUSTED state.")

    # Match derived fingerprint against trusted signer
    configured_fingerprint = trusted_signer.get("public_key_fingerprint")
    if configured_fingerprint and configured_fingerprint != "*" and configured_fingerprint != derived_key_fingerprint:
        raise AuthorityError(
            "REVIEW_SIGNER_NOT_TRUSTED",
            f"Derived key fingerprint '{derived_key_fingerprint}' != configured '{configured_fingerprint}'",
        )

    # Verify key_id
    configured_key_id = trusted_signer.get("key_id")
    if key_id is not None and configured_key_id and configured_key_id != "*" and key_id != configured_key_id:
        raise AuthorityError(
            "REVIEW_SIGNER_NOT_TRUSTED",
            f"Provided key_id '{key_id}' != configured '{configured_key_id}'",
        )
    signing_key_id = configured_key_id or key_id or "review-authority-key-v1"

    # Verify reviewer_principal
    configured_reviewer = trusted_signer.get("reviewer_principal")
    if not configured_reviewer or configured_reviewer == "*":
        final_reviewer_principal = reviewer_principal or "review-authority-checker"
    else:
        if reviewer_principal is not None and reviewer_principal.strip():
            if reviewer_principal.strip().lower() != configured_reviewer.strip().lower():
                raise AuthorityError(
                    "REVIEW_SIGNER_NOT_TRUSTED",
                    f"Caller reviewer_principal '{reviewer_principal}' != configured '{configured_reviewer}'",
                )
        final_reviewer_principal = configured_reviewer
    signing_algorithm = trusted_signer.get("algorithm", "RSASSA-PKCS1-v1_5-SHA256")
    trust_root_version = trusted_signer.get("trust_root_version", "1.0.0")

    # 6. Parse ledger events
    lines = ledger_file.read_text(encoding="utf-8").splitlines()
    events: list[dict[str, Any]] = []
    seq_set: set[int] = set()
    expected_seq = 1
    has_execution_receipt = False
    authenticated_producer: str | None = None
    last_auth_dec_id: str | None = None
    last_auth_dec_digest: str | None = None
    last_req_effect_digest: str | None = None

    for line_idx, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            raw_item = json.loads(line)
        except Exception as e:
            raise AuthorityError("EXECUTION_LEDGER_CORRUPT", f"Line {line_idx} is not valid JSON: {e}") from e

        # Section 4: Require exact custody wrapper identity
        if raw_item.get("schema_version") == "miskatonic.work-order-ledger-event.v1":
            event_kind = raw_item.get("event_kind")
            seq = raw_item.get("ledger_sequence") or line_idx

            if event_kind == "EXECUTION_RECEIPT":
                has_execution_receipt = True
                rec = raw_item.get("receipt")
                if not isinstance(rec, dict):
                    raise AuthorityError("EXECUTION_RECEIPT_CORRUPT", f"Line {line_idx} receipt is not a dict")

                # Exact wrapper identity (Section 4)
                wrap_wo = raw_item.get("work_order_id") or raw_item.get("wo_id")
                if not wrap_wo or wrap_wo != work_order_id:
                    raise AuthorityError(
                        "WORK_ORDER_ID_MISMATCH",
                        f"Wrapper work_order_id '{wrap_wo}' != requested '{work_order_id}'",
                    )
                wrap_run = raw_item.get("run_id")
                if not wrap_run or wrap_run != run_id:
                    raise AuthorityError(
                        "RUN_ID_MISMATCH",
                        f"Wrapper run_id '{wrap_run}' != requested '{run_id}'",
                    )
                wrap_attempt = raw_item.get("attempt_id")
                if not wrap_attempt or wrap_attempt != attempt_id:
                    raise AuthorityError(
                        "ATTEMPT_ID_MISMATCH",
                        f"Wrapper attempt_id '{wrap_attempt}' != requested '{attempt_id}'",
                    )

                wrap_rec_digest = raw_item.get("receipt_digest")
                rec_digest = rec.get("receipt_digest")
                if not wrap_rec_digest or wrap_rec_digest != rec_digest:
                    raise AuthorityError(
                        "RECEIPT_DIGEST_MISMATCH",
                        f"Wrapper receipt_digest '{wrap_rec_digest}' != receipt's receipt_digest '{rec_digest}'",
                    )

                # Section 9: Extract authenticated producer identity from receipt
                rec_producer = rec.get("executor_principal")
                if not rec_producer:
                    raise AuthorityError("PRODUCER_IDENTITY_MISSING", f"Line {line_idx} receipt missing executor_principal")
                if executor_principal and executor_principal.strip() and executor_principal.lower() != rec_producer.lower():
                    raise AuthorityError("EXECUTOR_PRINCIPAL_MISMATCH", f"Asserted executor '{executor_principal}' != authenticated '{rec_producer}'")
                authenticated_producer = rec_producer

                # Self-attestation check (Section 30)
                if authenticated_producer.lower() == final_reviewer_principal.lower():
                    raise AuthorityError(
                        "EXECUTOR_REVIEWER_PRINCIPAL_COLLISION",
                        f"Executor principal '{authenticated_producer}' cannot be review principal.",
                    )

                # Receipt identity agreement
                rec_wo = rec.get("work_order_id") or rec.get("wo_id")
                if not rec_wo or rec_wo != work_order_id:
                    raise AuthorityError("WORK_ORDER_ID_MISMATCH", f"Receipt work_order_id '{rec_wo}' != '{work_order_id}'")
                if not rec.get("run_id") or rec["run_id"] != run_id:
                    raise AuthorityError("RUN_ID_MISMATCH", f"Receipt run_id '{rec.get('run_id')}' != '{run_id}'")
                if not rec.get("attempt_id") or rec["attempt_id"] != attempt_id:
                    raise AuthorityError("ATTEMPT_ID_MISMATCH", f"Receipt attempt_id '{rec.get('attempt_id')}' != '{attempt_id}'")

                # Section 5: Recompute receipt digest with ONLY canonical JSON + newline
                cpy = dict(rec)
                provided_digest = cpy.pop("receipt_digest", None)
                if not provided_digest:
                    raise AuthorityError("EXECUTION_RECEIPT_DIGEST_MISSING", f"Line {line_idx} receipt missing receipt_digest")

                computed_digest = f"sha256:{hashlib.sha256((json.dumps(cpy, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode('utf-8')).hexdigest()}"
                if provided_digest != computed_digest:
                    raise AuthorityError("EXECUTION_RECEIPT_DIGEST_MISMATCH", f"Line {line_idx} receipt digest mismatch")

                # Section 2 & 3: Authorization decision is MANDATORY & complete chain verification
                auth_dec = rec.get("authorization_decision") or raw_item.get("authorization_decision")
                if not auth_dec and authorization_decision:
                    if isinstance(authorization_decision, (str, Path)):
                        auth_dec = read_json(str(authorization_decision))
                    elif isinstance(authorization_decision, dict):
                        auth_dec = authorization_decision
                    elif hasattr(authorization_decision, "model_dump"):
                        auth_dec = authorization_decision.model_dump(mode="json")
                if not auth_dec:
                    dec_file = ledger_file.parent / f"{rec.get('authorization_decision_id')}.json"
                    if not dec_file.is_file():
                        dec_file = ledger_file.parent / "authorization_decision.json"
                    if dec_file.is_file():
                        auth_dec = read_json(str(dec_file))
                if not auth_dec:
                    raise AuthorityError("AUTHORIZATION_DECISION_MISSING", f"Line {line_idx} execution receipt missing authorization_decision artifact")

                dec_dict = auth_dec.model_dump(mode="json") if hasattr(auth_dec, "model_dump") else dict(auth_dec)

                # Validate decision schema and mandatory fields
                if dec_dict.get("schema_version") != "miskatonic.authorization-decision.v1":
                    raise AuthorityError("AUTHORIZATION_DECISION_DIGEST_INVALID", f"Line {line_idx} decision invalid schema_version")

                if not dec_dict.get("allowed", False):
                    raise AuthorityError("AUTHORIZATION_DECISION_DENIED", f"Line {line_idx} decision allowed is False")

                # Verify decision digest
                dec_at = dec_dict.get("decided_at")
                if hasattr(dec_at, "isoformat"):
                    dec_str = dec_at.isoformat().replace("+00:00", "Z")
                else:
                    dec_str = str(dec_at).replace("+00:00", "Z") if dec_at else ""

                bound_dec = {
                    "schema_version": dec_dict.get("schema_version", "miskatonic.authorization-decision.v1"),
                    "decision_id": dec_dict.get("decision_id"),
                    "allowed": dec_dict.get("allowed"),
                    "capability_name": dec_dict.get("capability_name"),
                    "policy_version": dec_dict.get("policy_version"),
                    "reason_code": dec_dict.get("reason_code"),
                    "reason": dec_dict.get("reason"),
                    "required_challenge": dec_dict.get("required_challenge", False),
                    "obligations": list(dec_dict.get("obligations") or []),
                    "work_order_id": dec_dict.get("work_order_id"),
                    "run_id": dec_dict.get("run_id"),
                    "attempt_id": dec_dict.get("attempt_id"),
                    "phase": dec_dict.get("phase"),
                    "state_digest": dec_dict.get("state_digest"),
                    "requested_effect_digest": dec_dict.get("requested_effect_digest"),
                    "decided_at": dec_str,
                }
                computed_dec_digest = f"sha256:{hashlib.sha256(json.dumps(bound_dec, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()}"
                expected_dec_digest = dec_dict.get("decision_digest")

                if not expected_dec_digest or expected_dec_digest != computed_dec_digest:
                    raise AuthorityError("AUTHORIZATION_DECISION_DIGEST_INVALID", f"Line {line_idx} decision digest verification failed")

                # Exact chain equality
                if rec.get("authorization_decision_id") != dec_dict.get("decision_id"):
                    raise AuthorityError("AUTHORIZATION_DECISION_ID_MISMATCH", f"Line {line_idx} decision ID mismatch")
                if rec.get("authorization_decision_digest") != dec_dict.get("decision_digest"):
                    raise AuthorityError("AUTHORIZATION_DECISION_DIGEST_MISMATCH", f"Line {line_idx} decision digest mismatch")
                if rec.get("capability_id") != dec_dict.get("capability_name"):
                    raise AuthorityError("CAPABILITY_ID_MISMATCH", f"Line {line_idx} capability ID mismatch")

                dec_wo = dec_dict.get("work_order_id") or dec_dict.get("wo_id")
                if dec_wo != work_order_id:
                    raise AuthorityError("WORK_ORDER_ID_MISMATCH", f"Line {line_idx} decision work_order_id mismatch")
                if dec_dict.get("run_id") != run_id:
                    raise AuthorityError("RUN_ID_MISMATCH", f"Line {line_idx} decision run_id mismatch")
                if dec_dict.get("attempt_id") != attempt_id:
                    raise AuthorityError("ATTEMPT_ID_MISMATCH", f"Line {line_idx} decision attempt_id mismatch")
                if rec.get("phase") != dec_dict.get("phase"):
                    raise AuthorityError("PHASE_MISMATCH", f"Line {line_idx} decision phase mismatch")
                if rec.get("requested_effect_digest") != dec_dict.get("requested_effect_digest"):
                    raise AuthorityError("REQUESTED_EFFECT_DIGEST_MISMATCH", f"Line {line_idx} requested effect digest mismatch")

                last_auth_dec_id = dec_dict.get("decision_id")
                last_auth_dec_digest = dec_dict.get("decision_digest")
                last_req_effect_digest = dec_dict.get("requested_effect_digest")

                event = rec
                event["ledger_sequence"] = seq
            elif event_kind == "CONTROL_EVENT":
                event = raw_item
                event["ledger_sequence"] = seq
            else:
                event = raw_item
                event["ledger_sequence"] = seq
        else:
            # Bare execution-event without custody wrapper
            raise AuthorityError("CUSTODY_WRAPPER_REQUIRED", f"Line {line_idx} is not wrapped in miskatonic.work-order-ledger-event.v1")

        if seq != expected_seq:
            raise AuthorityError("EXECUTION_LEDGER_SEQUENCE_NON_MONOTONIC", f"Line {line_idx} sequence {seq} != expected {expected_seq}")
        expected_seq += 1
        seq_set.add(seq)
        events.append(event)

    if not has_execution_receipt:
        raise AuthorityError("NO_AUTHENTICATED_EXECUTION_EVIDENCE", "No authenticated execution evidence found in ledger (CONTROL_EVENT only history rejected)")

    # 7. Candidate SHA (Section 29)
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

    # 8. Evidence sequences & relevance
    fields = result_data.get("fields", {})
    for field_name, field_obj in fields.items():
        if isinstance(field_obj, dict):
            ev_seqs = field_obj.get("evidence_sequence", [])
            for seq in ev_seqs:
                if seq not in seq_set:
                    raise AuthorityError(
                        "EVIDENCE_SEQUENCE_INVALID",
                        f"Field '{field_name}' references non-existent sequence {seq}.",
                    )
                matching_event = next((e for e in events if e.get("ledger_sequence") == seq or e.get("sequence") == seq), None)
                if matching_event:
                    if field_name == "pytest" and "pytest" not in matching_event.get("command_summary", "").lower():
                        raise AuthorityError("EVIDENCE_SEQUENCE_IRRELEVANT", f"Field '{field_name}' references irrelevant event sequence {seq}.")

    # 9. Independent Result Re-Derivation
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
            f"Result pytest status '{res_pytest_status}' != independently derived status '{derived_pytest_status}'",
        )

    # 10. Signed execution attestation (Section 11)
    attestation_payload = {
        "schema_version": "miskatonic.review-execution-attestation.v1",
        "verified": True,
        "work_order_id": work_order_id,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "candidate_sha": observed_sha,
        "ledger_sha256": ledger_digest,
        "result_sha256": f"sha256:{hashlib.sha256(result_file.read_bytes()).hexdigest()}",
        "terminal_verdict": result_data.get("terminal_verdict"),
        "authorization_decision_id": last_auth_dec_id,
        "authorization_decision_digest": last_auth_dec_digest,
        "requested_effect_digest": last_req_effect_digest,
        "producer_principal": authenticated_producer,
        "executor_principal": authenticated_producer,
        "reviewer_principal": final_reviewer_principal,
        "signing_key_id": signing_key_id,
        "signing_key_fingerprint": derived_key_fingerprint,
        "key_fingerprint": derived_key_fingerprint,
        "signing_algorithm": signing_algorithm,
        "trust_root_version": trust_root_version,
    }

    signed_att = sign_attestation(attestation_payload, str(private_key_path), key_id=signing_key_id)
    return signed_att
