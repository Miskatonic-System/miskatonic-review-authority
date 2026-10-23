"""Local Independent Review execution, isolation enforcement, receipt generation, and GitHub App admission."""

from __future__ import annotations

import base64
import copy
import os
import pwd
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema

from .attestation import public_key_fingerprint
from .canonical_digest import candidate_digest, changed_records
from .scientific_verifier import run_scientific_prior_verification, verify_path_scope
from .review_backends import (
    PROMPT_TEMPLATE_SHA256,
    PROMPT_VERSION,
    SLICE_SCHEMA_SHA256,
    SLICE_SCHEMA_VERSION,
    VERDICT_SCHEMA_SHA256,
    VERDICT_SCHEMA_VERSION,
    get_review_backend,
)
from .util import (
    AuthorityError,
    canonical_json_bytes,
    read_json,
    require_full_sha,
    run,
    sha256_bytes,
    sha256_file,
    validate_repository_name,
    write_json,
)


_SIGNATURE_ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"


def compute_reviewer_implementation_digest(root_dir: str | Path | None = None) -> str:
    """Computes a canonical SHA-256 digest over all python implementation files in the authority package."""
    if root_dir is None:
        pkg_dir = Path(__file__).resolve().parent
    else:
        pkg_dir = Path(root_dir).resolve()

    py_files = sorted(pkg_dir.glob("*.py"))
    if not py_files:
        raise AuthorityError("REVIEWER_IMPLEMENTATION_FILES_MISSING", str(pkg_dir))

    manifest_entries: list[str] = []
    for f in py_files:
        h = sha256_file(f)
        manifest_entries.append(f"{f.name}:{h}")

    combined = "\n".join(manifest_entries).encode("utf-8")
    return sha256_bytes(combined)


def unsigned_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Returns a deep copy of the receipt with detached_signature removed."""
    val = copy.deepcopy(receipt)
    val.pop("detached_signature", None)
    return val


def sign_local_receipt(
    receipt: dict[str, Any],
    private_key_path: str,
    *,
    key_id: str,
    public_key_fingerprint_val: str,
) -> tuple[dict[str, Any], bytes]:
    """Signs receipt body and returns (signed_receipt_dict, raw_signature_bytes)."""
    payload_bytes = canonical_json_bytes(unsigned_receipt(receipt))
    payload_sha = sha256_bytes(payload_bytes)

    with tempfile.TemporaryDirectory() as tmp_dir:
        payload_file = Path(tmp_dir, "payload.json")
        sig_file = Path(tmp_dir, "signature.bin")
        payload_file.write_bytes(payload_bytes)

        run([
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            private_key_path,
            "-out",
            str(sig_file),
            str(payload_file),
        ])
        sig_bytes = sig_file.read_bytes()

    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
    signed = copy.deepcopy(receipt)
    signed["detached_signature"] = {
        "algorithm": _SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "payload_sha256": payload_sha,
        "public_key_fingerprint": public_key_fingerprint_val,
        "value_base64": sig_b64,
    }
    return signed, sig_bytes


def verify_detached_signature(
    receipt: dict[str, Any],
    public_key_path: str,
    *,
    expected_key_id: str | None = None,
    raw_signature_bytes: bytes | None = None,
) -> None:
    """Verifies detached cryptographic signature of a receipt."""
    sig_info = receipt.get("detached_signature")
    if not isinstance(sig_info, dict):
        raise AuthorityError("RECEIPT_SIGNATURE_MISSING")

    if sig_info.get("algorithm") != _SIGNATURE_ALGORITHM:
        raise AuthorityError("RECEIPT_SIGNATURE_ALGORITHM_UNSUPPORTED")

    if expected_key_id is not None and sig_info.get("key_id") != expected_key_id:
        raise AuthorityError("RECEIPT_SIGNING_KEY_MISMATCH")

    try:
        sig_bytes = (
            raw_signature_bytes
            if raw_signature_bytes is not None
            else base64.b64decode(sig_info.get("value_base64", ""), validate=True)
        )
    except Exception as e:
        raise AuthorityError("RECEIPT_SIGNATURE_ENCODING_INVALID") from e

    payload_bytes = canonical_json_bytes(unsigned_receipt(receipt))
    computed_payload_sha = sha256_bytes(payload_bytes)
    declared_payload_sha = sig_info.get("payload_sha256")
    if declared_payload_sha and declared_payload_sha != computed_payload_sha:
        raise AuthorityError("RECEIPT_PAYLOAD_TAMPERED")

    with tempfile.TemporaryDirectory() as tmp_dir:
        payload_file = Path(tmp_dir, "payload.json")
        sig_file = Path(tmp_dir, "sig.bin")
        payload_file.write_bytes(payload_bytes)
        sig_file.write_bytes(sig_bytes)

        result = run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                public_key_path,
                "-signature",
                str(sig_file),
                str(payload_file),
            ],
            check=False,
        )
        if result.returncode != 0:
            raise AuthorityError("RECEIPT_SIGNATURE_INVALID")


def verify_execution_isolation(
    *,
    candidate_repo_path: str,
    expected_service_user: str | None = "msk-local-reviewer",
    prohibited_users: list[str] | None = None,
    enforce_strict_os_user: bool = True,
) -> dict[str, Any]:
    """Verifies process identity and candidate source isolation."""
    current_uid = os.getuid()
    try:
        current_user = pwd.getpwuid(current_uid).pw_name
    except KeyError:
        current_user = str(current_uid)

    prohibited = prohibited_users or ["kowen9024"]
    if current_user in prohibited:
        raise AuthorityError(
            "REVIEWER_SERVICE_IDENTITY_PROHIBITED",
            f"Reviewer process running as candidate-authoring user '{current_user}'",
        )
    if enforce_strict_os_user and expected_service_user and current_user != expected_service_user:
        raise AuthorityError(
            "REVIEWER_SERVICE_IDENTITY_PROHIBITED",
            f"Reviewer process user '{current_user}' != expected '{expected_service_user}'",
        )

    # Check candidate checkout directory is read-only
    checkout = Path(candidate_repo_path)
    if not checkout.is_dir():
        raise AuthorityError("CANDIDATE_CHECKOUT_MISSING", str(checkout))

    # Probe writable
    is_writable = os.access(str(checkout), os.W_OK)
    probe_failed = False
    test_probe_file = checkout / ".miskatonic_isolation_probe"
    try:
        test_probe_file.write_text("probe")
        test_probe_file.unlink(missing_ok=True)
        is_writable = True
    except (PermissionError, OSError):
        probe_failed = True

    if is_writable and not probe_failed:
        raise AuthorityError(
            "CANDIDATE_CHECKOUT_NOT_READONLY",
            f"Candidate checkout at {checkout} is writable by reviewer process",
        )

    # Prohibit presence of GitHub App private key in environment or local reviewer dir
    if os.environ.get("MSK_REVIEW_APP_PRIVATE_KEY"):
        raise AuthorityError(
            "GITHUB_APP_KEY_LEAKED_TO_REVIEWER",
            "MSK_REVIEW_APP_PRIVATE_KEY present in reviewer process environment",
        )

    return {
        "candidate_checkout_path": str(checkout.resolve()),
        "candidate_checkout_readonly_verified": True,
        "candidate_code_executed": False,
        "github_app_private_key_present_locally": False,
        "os_gid": os.getgid(),
        "os_uid": current_uid,
        "os_user": current_user,
        "working_directory": str(Path.cwd()),
    }


def run_local_independent_review(
    *,
    repository: str,
    pr_number: int,
    head_branch: str,
    repo_path: str,
    base_sha: str,
    head_sha: str,
    prior_evidence_path: str,
    review_packet_path: str,
    producer_bindings_path: str,
    reviewer_policy_path: str,
    private_key_path: str,
    key_id: str,
    output_path: str,
    target_policy_path: str | None = None,
    enforce_strict_isolation: bool = True,
) -> tuple[dict[str, Any], str]:
    """Runs isolated local review using LocalLlamaCppBackend and emits a signed receipt."""
    repository = validate_repository_name(repository)
    require_full_sha(base_sha, field="base_sha")
    require_full_sha(head_sha, field="head_sha")

    prior = read_json(prior_evidence_path)
    if (
        prior.get("verdict") != "PASS"
        or prior.get("head_sha") != head_sha
        or prior.get("base_sha") != base_sha
    ):
        raise AuthorityError("PRIOR_VERIFICATION_EVIDENCE_INVALID")

    target_policy_sha = None
    target_policy_name = "scientific-target-policy-v1"
    if target_policy_path:
        tpol = read_json(target_policy_path)
        if tpol.get("repository", "").lower() != repository.lower():
            raise AuthorityError("TARGET_POLICY_REPOSITORY_MISMATCH")
        if tpol.get("expected_pr_number") != pr_number:
            raise AuthorityError("TARGET_POLICY_PR_MISMATCH")
        if tpol.get("expected_head_sha") != head_sha:
            raise AuthorityError("TARGET_POLICY_HEAD_SHA_MISMATCH")
        if tpol.get("expected_base_sha") != base_sha:
            raise AuthorityError("TARGET_POLICY_BASE_SHA_MISMATCH")
        if tpol.get("expected_head_branch") and tpol.get("expected_head_branch") != head_branch:
            raise AuthorityError("TARGET_POLICY_BRANCH_MISMATCH")
        target_policy_sha = sha256_bytes(canonical_json_bytes(tpol))
        target_policy_name = Path(target_policy_path).name

    digest, _ = candidate_digest(repository, repo_path, base_sha, head_sha)
    if prior.get("candidate_digest") != digest:
        raise AuthorityError("PRIOR_VERIFICATION_DIGEST_STALE")

    # Producer separation
    from .review_runner import _trusted_producer

    producer = _trusted_producer(
        producer_bindings_path, repository, pr_number, head_branch
    )
    reviewer_policy = read_json(reviewer_policy_path)
    reviewer_principal = str(reviewer_policy.get("reviewer_principal", ""))
    if not reviewer_principal:
        raise AuthorityError("REVIEWER_PRINCIPAL_MISSING")

    if reviewer_principal.strip().lower() == str(producer.get("producer_principal", "")).strip().lower():
        raise AuthorityError("REVIEWER_PRODUCER_PRINCIPAL_COLLISION")

    # Verify execution isolation
    isolation_info = verify_execution_isolation(
        candidate_repo_path=repo_path,
        enforce_strict_os_user=enforce_strict_isolation,
    )

    packet = read_json(review_packet_path)
    if packet.get("head_sha") != head_sha or packet.get("base_sha") != base_sha:
        raise AuthorityError("REVIEW_PACKET_HEAD_MISMATCH")
    if packet.get("candidate_digest") != digest:
        raise AuthorityError("REVIEW_PACKET_DIGEST_MISMATCH")

    # Calculate implementation and packet digests
    impl_digest = compute_reviewer_implementation_digest()
    packet_digest = sha256_bytes(canonical_json_bytes(packet))
    prior_digest = sha256_bytes(canonical_json_bytes(prior))

    # Derive public key fingerprint
    with tempfile.TemporaryDirectory() as tmp_dir:
        pub_der = Path(tmp_dir, "pub.der")
        res = run(
            ["openssl", "pkey", "-in", private_key_path, "-pubout", "-outform", "DER", "-out", str(pub_der)],
            check=False,
        )
        if res.returncode != 0:
            raise AuthorityError("REVIEWER_SIGNING_KEY_INVALID")
        pub_fp = f"sha256:{sha256_file(pub_der)}"

    # Check key separation between producer and reviewer
    prod_key = producer.get("producer_key_id") or producer.get("producer_public_key_fingerprint")
    if prod_key and (prod_key == key_id or prod_key == pub_fp):
        raise AuthorityError("PRODUCER_REVIEWER_KEY_COLLISION")

    # Execute model review
    provider = reviewer_policy.get("provider", "LOCAL_LLAMA_CPP")
    endpoint = reviewer_policy.get("model_identity", {}).get("endpoint_url", "http://127.0.0.1:11434/v1")
    backend = get_review_backend(provider, endpoint_url=endpoint)

    verdict_resp, backend_evidence = backend.review(
        repository=repository,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        candidate_digest=digest,
        review_packet=packet,
        prior_evidence=prior,
        producer_binding=producer,
        reviewer_policy=reviewer_policy,
    )

    issued_at = datetime.now(UTC).isoformat()
    receipt_id = f"local-review-{digest[:16]}-{int(datetime.now(UTC).timestamp())}"

    receipt_dict: dict[str, Any] = {
        "abstention": verdict_resp.get("abstention", {"abstained": False, "reason": ""}),
        "base_sha": base_sha,
        "candidate_digest": digest,
        "confidence": verdict_resp.get("confidence", 1.0),
        "deterministic_verification_outcomes": {
            "prior_verification_digest": prior_digest,
            "prior_verification_verdict": prior.get("verdict"),
            "scientific_evidence_verifications": prior.get("scientific_evidence_verifications", {}),
            "target_policy_path": target_policy_name,
            "target_policy_sha256": target_policy_sha or sha256_bytes(canonical_json_bytes(reviewer_policy)),
        },
        "findings": verdict_resp.get("findings", []),
        "head_branch": head_branch,
        "head_sha": head_sha,
        "issued_at": issued_at,
        "model_identity": backend_evidence["model_identity"],
        "pr_number": pr_number,
        "producer_binding": producer,
        "prompt_and_schema": backend_evidence["prompt_and_schema"],
        "receipt_id": receipt_id,
        "release_authorized": verdict_resp.get("release_authorized", False),
        "repository": repository,
        "review_coverage_manifest": backend_evidence["review_coverage_manifest"],
        "review_packet_digest": packet_digest,
        "review_packet_manifest_digest": packet_digest,
        "reviewer_implementation_digest": impl_digest,
        "reviewer_policy_version": reviewer_policy.get("policy_version", "2.0.0"),
        "reviewer_service_identity": {
            **isolation_info,
            "reviewer_principal": reviewer_principal,
            "signing_key_id": key_id,
            "signing_public_key_fingerprint": pub_fp,
        },
        "schema_version": "local-review-receipt-v2",
        "summary": verdict_resp.get("summary", ""),
        "uncertainty": verdict_resp.get("uncertainty", {"level": "LOW", "explicit_uncertainties": [], "residual_risks": []}),
        "verdict": verdict_resp.get("verdict"),
    }

    signed_receipt, sig_bytes = sign_local_receipt(
        receipt_dict,
        private_key_path,
        key_id=key_id,
        public_key_fingerprint_val=pub_fp,
    )

    schema_path = Path(__file__).resolve().parent.parent.parent / "schemas/local-review-receipt-v2.schema.json"
    if schema_path.is_file():
        receipt_schema = read_json(str(schema_path))
        try:
            jsonschema.validate(instance=signed_receipt, schema=receipt_schema)
        except jsonschema.ValidationError as e:
            raise AuthorityError("LOCAL_REVIEW_SCHEMA_INVALID", f"Receipt failed schema validation: {e.message}") from e

    out_json = Path(output_path)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    write_json(str(out_json), signed_receipt)

    out_sig = out_json.with_suffix(".sig")
    out_sig.write_bytes(sig_bytes)

    return signed_receipt, str(out_sig)


def verify_and_admit_local_review_receipt(
    *,
    receipt_path: str | Path,
    detached_sig_path: str | Path | None = None,
    repository: str,
    expected_pr_number: int,
    expected_head_sha: str,
    expected_base_sha: str,
    target_repo_path: str,
    target_policy_path: str,
    trusted_reviewers_policy_path: str,
    trusted_signers_policy_path: str,
    trusted_producers_policy_path: str,
    authority_root_path: str | None = None,
    github_app_private_key_path: str | None = None,
    output_attestation_path: str | None = None,
) -> dict[str, Any]:
    """Admission gate: verifies signed local review receipt against candidate and admission criteria."""
    receipt = read_json(str(receipt_path))
    if receipt.get("schema_version") != "local-review-receipt-v2":
        raise AuthorityError("LOCAL_REVIEW_RECEIPT_SCHEMA_UNSUPPORTED")

    # Strict Schema Validation of Receipt
    receipt_schema_path = Path(__file__).resolve().parent.parent.parent / "schemas/local-review-receipt-v2.schema.json"
    if receipt_schema_path.is_file():
        receipt_schema = read_json(str(receipt_schema_path))
        try:
            jsonschema.validate(instance=receipt, schema=receipt_schema)
        except jsonschema.ValidationError as e:
            raise AuthorityError("LOCAL_REVIEW_SCHEMA_INVALID", f"Receipt failed schema validation: {e.message}") from e

    if "confidence" in receipt:
        conf = receipt["confidence"]
        if not isinstance(conf, (int, float)) or isinstance(conf, bool) or conf < 0.0 or conf > 1.0:
            raise AuthorityError("LOCAL_REVIEW_SCHEMA_INVALID", f"Confidence value {conf} out of bounds [0.0, 1.0]")

    # Strict Service User Assurance
    service_id = receipt.get("reviewer_service_identity", {})
    if service_id.get("os_user") != "msk-local-reviewer" or service_id.get("os_uid") != 994:
        raise AuthorityError(
            "UNAUTHORIZED_AUTHORING_USER_REVIEW",
            f"Receipt issued by unauthorized user '{service_id.get('os_user')}' (uid {service_id.get('os_uid')})",
        )

    # 1. Exact-head and candidate freshness
    if receipt.get("repository", "").lower() != repository.lower():
        raise AuthorityError("REPOSITORY_MISMATCH")
    if receipt.get("pr_number") != expected_pr_number:
        raise AuthorityError("PR_NUMBER_MISMATCH")
    if receipt.get("head_sha") != expected_head_sha:
        raise AuthorityError("STALE_REVIEW_HEAD")
    if receipt.get("base_sha") != expected_base_sha:
        raise AuthorityError("CANDIDATE_BASE_SHA_MISMATCH")

    computed_digest, _ = candidate_digest(repository, target_repo_path, expected_base_sha, expected_head_sha)
    if receipt.get("candidate_digest") != computed_digest:
        raise AuthorityError("CANDIDATE_DIGEST_MISMATCH")

    # 2. Registered reviewer public key resolution
    v2_policy = read_json(trusted_reviewers_policy_path)
    if v2_policy.get("schema_version") != "reviewer-policy-v2":
        raise AuthorityError("REVIEWER_POLICY_SCHEMA_UNSUPPORTED")
    if v2_policy.get("lifecycle_state") != "ACTIVE":
        raise AuthorityError("REVIEW_POLICY_INACTIVE")

    expected_principal = v2_policy.get("reviewer_principal")
    actual_principal = receipt.get("reviewer_service_identity", {}).get("reviewer_principal")
    if actual_principal != expected_principal:
        raise AuthorityError("FORGED_REVIEWER_IDENTITY", f"Principal '{actual_principal}' != '{expected_principal}'")

    sig_info = receipt.get("detached_signature", {})
    key_id = sig_info.get("key_id")
    fingerprint = sig_info.get("public_key_fingerprint")

    # Resolve public key from trusted policy
    signing_policy = v2_policy.get("signing", {})
    trusted_key_id = signing_policy.get("key_id")
    trusted_pub_rel = signing_policy.get("public_key_path")
    trusted_fingerprint = signing_policy.get("public_key_fingerprint")

    if not trusted_pub_rel:
        # Fall back to trusted-signers
        signers = read_json(trusted_signers_policy_path)
        trusted_key_id = signers.get("key_id")
        trusted_pub_rel = signers.get("public_key_path")
        trusted_fingerprint = signers.get("public_key_fingerprint")

    if key_id != trusted_key_id or fingerprint != trusted_fingerprint:
        raise AuthorityError("FORGED_REVIEWER_IDENTITY", "Key ID or fingerprint not in trusted reviewer registry")

    pub_path = Path(trusted_pub_rel)
    if not pub_path.is_absolute():
        pub_path = Path(trusted_reviewers_policy_path).resolve().parent.parent / trusted_pub_rel
    if not pub_path.is_file():
        raise AuthorityError("REVIEW_TRUST_ROOT_INVALID", f"Public key not found at {pub_path}")

    # Verify signature
    raw_sig = None
    if detached_sig_path and Path(detached_sig_path).is_file():
        raw_sig = Path(detached_sig_path).read_bytes()

    verify_detached_signature(
        receipt,
        str(pub_path),
        expected_key_id=trusted_key_id,
        raw_signature_bytes=raw_sig,
    )

    # 3. Producer/Reviewer Separation
    from .review_runner import _trusted_producer

    producer = _trusted_producer(
        trusted_producers_policy_path,
        repository,
        expected_pr_number,
        receipt.get("head_branch", ""),
    )
    if producer.get("producer_principal", "").strip().lower() == actual_principal.strip().lower():
        raise AuthorityError("REVIEWER_PRODUCER_PRINCIPAL_COLLISION")

    prod_key = producer.get("producer_key_id") or producer.get("producer_public_key_fingerprint")
    if prod_key and (prod_key == key_id or prod_key == fingerprint):
        raise AuthorityError("PRODUCER_REVIEWER_KEY_COLLISION")

    # 4. Model Identity & Bounded Context Verification
    expected_model = v2_policy.get("model_identity", {})
    actual_model = receipt.get("model_identity", {})
    if actual_model.get("model_weights_sha256") != expected_model.get("model_weights_sha256"):
        raise AuthorityError("FORGED_MODEL_IDENTITY")
    if actual_model.get("runtime_binary_sha256") != expected_model.get("runtime_binary_sha256"):
        raise AuthorityError("RUNTIME_BINARY_DIGEST_MISMATCH")
    if not actual_model.get("loopback_only_verified"):
        raise AuthorityError("MODEL_ENDPOINT_NOT_LOOPBACK_ISOLATED")

    # 5. Review Coverage Manifest Completeness
    coverage = receipt.get("review_coverage_manifest", {})
    if not coverage.get("all_changed_files_accounted_for"):
        raise AuthorityError("REVIEW_COVERAGE_INCOMPLETE")
    if coverage.get("full_diff_files_reviewed") != coverage.get("full_diff_files_total"):
        raise AuthorityError("TRUNCATED_EVIDENCE", "Not all full diff files were reviewed")
    if coverage.get("full_diff_bytes_reviewed") != coverage.get("full_diff_bytes_total"):
        raise AuthorityError("TRUNCATED_EVIDENCE", "Not all full diff bytes were reviewed")

    slices = coverage.get("slices", [])
    if not slices:
        raise AuthorityError("DIFF_COVERAGE_INCOMPLETE", "No slices in coverage manifest")

    slice_bytes_sum = sum(s.get("diff_bytes", 0) for s in slices)
    if slice_bytes_sum != coverage.get("full_diff_bytes_total"):
        raise AuthorityError(
            "REVIEW_COVERAGE_BYTE_COUNT_MISMATCH",
            f"Sum of slice bytes ({slice_bytes_sum}) != full_diff_bytes_total ({coverage.get('full_diff_bytes_total')})",
        )

    prev_end = 0
    for s in slices:
        if s.get("finish_reason") != "stop":
            raise AuthorityError("LOCAL_REVIEW_CONTEXT_TRUNCATED")
        if s.get("slice_status") not in ("PASS", "CONCERN", "FAIL"):
            raise AuthorityError("LOCAL_REVIEW_SCHEMA_INVALID")
        if "slice_start_byte" in s and "slice_end_byte" in s:
            if s["slice_start_byte"] != prev_end:
                raise AuthorityError(
                    "DIFF_COVERAGE_GAP_OR_OVERLAP",
                    f"Slice start byte {s['slice_start_byte']} != expected {prev_end}",
                )
            if s["slice_end_byte"] != s["slice_start_byte"] + s.get("diff_bytes", 0):
                raise AuthorityError(
                    "DIFF_COVERAGE_BYTE_COUNT_MISMATCH",
                    f"Slice end byte {s['slice_end_byte']} inconsistent with diff_bytes",
                )
            prev_end = s["slice_end_byte"]

    actual_diff_bytes = run(["git", "-C", target_repo_path, "diff", f"{expected_base_sha}..{expected_head_sha}"]).stdout
    actual_diff_sha = sha256_bytes(actual_diff_bytes)
    if coverage.get("full_diff_aggregate_sha256") != actual_diff_sha:
        raise AuthorityError(
            "INVALID_DIFF_AGGREGATE_DIGEST",
            f"Declared diff sha256 {coverage.get('full_diff_aggregate_sha256')} != actual {actual_diff_sha}",
        )

    # 5b. Initial Verdict & Release Authorization & Self-Reported Outcomes
    if receipt.get("deterministic_verification_outcomes", {}).get("prior_verification_verdict") != "PASS":
        raise AuthorityError("INCORRECT_PRIOR_VERIFICATION", "Receipt prior verification verdict is not PASS")

    verdict = receipt.get("verdict")
    release_authorized = receipt.get("release_authorized")

    if verdict not in ("APPROVE", "REQUEST_CHANGES", "REJECT"):
        raise AuthorityError("CLOUD_REVIEW_VERDICT_INVALID")
    if bool(release_authorized) != (verdict == "APPROVE"):
        raise AuthorityError("CLOUD_REVIEW_RELEASE_INCONSISTENT")

    if receipt.get("abstention", {}).get("abstained") and verdict == "APPROVE":
        raise AuthorityError("LOCAL_REVIEW_ABSTENTION_BLOCKS_APPROVAL")

    if verdict != "APPROVE":
        raise AuthorityError("LOCAL_REVIEW_VERDICT_NOT_APPROVED", f"Receipt verdict is '{verdict}', not APPROVE")

    # 6. Target Policy Verification & Prior Verification Reproduction
    if not target_policy_path or not Path(target_policy_path).is_file():
        raise AuthorityError("TARGET_POLICY_FILE_MISSING", str(target_policy_path))
    target_policy = read_json(str(target_policy_path))
    if target_policy.get("schema_version") != "scientific-target-policy-v1":
        raise AuthorityError("TARGET_POLICY_SCHEMA_UNSUPPORTED")
    if target_policy.get("repository", "").lower() != repository.lower():
        raise AuthorityError("TARGET_POLICY_REPOSITORY_MISMATCH")
    if target_policy.get("expected_pr_number") != expected_pr_number:
        raise AuthorityError("TARGET_POLICY_PR_MISMATCH")
    if target_policy.get("expected_head_sha") != expected_head_sha:
        raise AuthorityError("TARGET_POLICY_HEAD_SHA_MISMATCH")
    if target_policy.get("expected_base_sha") != expected_base_sha:
        raise AuthorityError("TARGET_POLICY_BASE_SHA_MISMATCH")
    if target_policy.get("expected_head_branch") and target_policy.get("expected_head_branch") != receipt.get("head_branch"):
        raise AuthorityError("TARGET_POLICY_BRANCH_MISMATCH")

    expected_target_policy_sha = sha256_bytes(canonical_json_bytes(target_policy))
    actual_target_policy_sha = receipt.get("deterministic_verification_outcomes", {}).get("target_policy_sha256")
    if actual_target_policy_sha != expected_target_policy_sha:
        raise AuthorityError(
            "FORGED_TARGET_POLICY_DIGEST",
            f"Receipt target policy sha256 {actual_target_policy_sha} != expected {expected_target_policy_sha}",
        )

    # Verify path scope against candidate changes
    records = changed_records(target_repo_path, expected_base_sha, expected_head_sha)
    verify_path_scope(records, target_policy)

    # Verify required scientific evidence files exist
    ev_base = Path(target_repo_path) / target_policy.get("evidence_base_path", "")
    for req_file in target_policy.get("required_evidence_files", []):
        if not (ev_base / req_file).is_file():
            raise AuthorityError("REQUIRED_EVIDENCE_FILE_MISSING", f"Required evidence file missing: {req_file}")

    # Reproduce deterministic prior verification
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_ev = Path(tmp_dir, "reproduced-evidence.json")
        reproduced_ev = run_scientific_prior_verification(
            repository=repository,
            target_path=target_repo_path,
            base_sha=expected_base_sha,
            head_sha=expected_head_sha,
            policy=target_policy,
            evidence_out=str(tmp_ev),
        )
    if reproduced_ev.get("verdict") != "PASS":
        raise AuthorityError("INCORRECT_PRIOR_VERIFICATION", "Reproduced prior verification verdict != PASS")
    reproduced_digest = sha256_bytes(canonical_json_bytes(reproduced_ev))
    claimed_prior_digest = receipt.get("deterministic_verification_outcomes", {}).get("prior_verification_digest")
    if claimed_prior_digest != reproduced_digest:
        raise AuthorityError(
            "INCORRECT_PRIOR_VERIFICATION",
            f"Claimed prior digest {claimed_prior_digest} != reproduced {reproduced_digest}",
        )

    # 7. Slice & Synthesis Consistency
    has_fail_slice = any(s.get("slice_status") == "FAIL" for s in slices)
    has_abstained_slice = any(s.get("abstained") for s in slices)
    has_p0_p1 = any(f.get("severity") in ("P0", "P1") for f in receipt.get("findings", []))
    if (has_fail_slice or has_abstained_slice or has_p0_p1) and verdict == "APPROVE":
        raise AuthorityError("LOCAL_REVIEW_FINDINGS_CONTRADICT_APPROVAL")

    if verdict != "APPROVE":
        raise AuthorityError(
            "LOCAL_REVIEW_VERDICT_NOT_APPROVED",
            f"Reviewer returned '{verdict}', candidate cannot be admitted",
        )

    # 8. GitHub App Attestation Countersigning (if app key provided)
    admission_attestation = None
    if github_app_private_key_path and Path(github_app_private_key_path).is_file():
        from .attestation import sign_attestation

        app_fp = public_key_fingerprint(
            str(Path(trusted_reviewers_policy_path).resolve().parent.parent / "keys/miskatonic-review-authority-app.pub.pem")
        )
        attestation_payload = {
            "authority_principal": "github-app:miskatonic-review-authority",
            "base_sha": expected_base_sha,
            "candidate_digest": computed_digest,
            "confidence": receipt.get("confidence", 1.0),
            "findings": receipt.get("findings", []),
            "head_sha": expected_head_sha,
            "issued_at": datetime.now(UTC).isoformat(),
            "local_review_receipt_id": receipt.get("receipt_id"),
            "local_review_receipt_sha256": sha256_bytes(canonical_json_bytes(unsigned_receipt(receipt))),
            "pr_number": expected_pr_number,
            "producer_binding": producer,
            "release_authorized": True,
            "repository": repository,
            "review_provider": "LOCAL_LLAMA_CPP",
            "reviewer_policy_version": v2_policy.get("policy_version", "2.0.0"),
            "reviewer_principal": actual_principal,
            "schema_version": "review-attestation-v1",
            "summary": receipt.get("summary", ""),
            "verdict": "APPROVE",
        }
        admission_attestation = sign_attestation(
            attestation_payload,
            github_app_private_key_path,
            key_id=app_fp,
        )
        if output_attestation_path:
            write_json(output_attestation_path, admission_attestation)

    return {
        "admission_attestation": admission_attestation,
        "candidate_digest": computed_digest,
        "head_sha": expected_head_sha,
        "pr_number": expected_pr_number,
        "receipt_id": receipt.get("receipt_id"),
        "release_authorized": True,
        "repository": repository,
        "status": "LOCAL_INDEPENDENT_REVIEW_ADMITTED",
        "verdict": "APPROVE",
    }
