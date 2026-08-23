"""Unit tests for Review Attestation V2 schema, release gate derivation, signing, and verification.

Implements WO-RA-EVALUATOR-ATTESTATION-BINDING-01A specifications:
- Sections 45-48: Release gate combinations and mode constraints
- Section 50: Tamper tests (all fail closed)
- Section 37-39: Signed attestation v2 verification and ingress binding
"""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from miskatonic_review_authority.attestation import public_key_fingerprint, sign_attestation
from miskatonic_review_authority.attestation_v2 import (
    build_review_attestation_v2,
    derive_release_gate,
    sign_review_attestation_v2,
    validate_review_attestation_v2,
    verify_review_attestation_v2,
)
from miskatonic_review_authority.util import AuthorityError, canonical_json_bytes, read_json, sha256_bytes

RA_ROOT = Path(__file__).resolve().parent.parent


class TestReleaseGateDerivation(unittest.TestCase):
    """Sections 45-48: Mechanical Release Gate Derivation Tests."""

    def test_review_approve_and_evaluator_approve_production_mode_authorizes_release(self):
        gate, rel_auth = derive_release_gate(
            verdict="APPROVE",
            evaluator_recommendation="approve_candidate",
            attestation_mode="PRODUCTION_REVIEW",
        )
        self.assertTrue(gate["review_verdict_allows_release"])
        self.assertTrue(gate["evaluator_recommendation_allows_release"])
        self.assertTrue(gate["attestation_mode_allows_release"])
        self.assertTrue(rel_auth)

    def test_review_approve_and_evaluator_reject_production_mode_denies_release(self):
        gate, rel_auth = derive_release_gate(
            verdict="APPROVE",
            evaluator_recommendation="reject",
            attestation_mode="PRODUCTION_REVIEW",
        )
        self.assertTrue(gate["review_verdict_allows_release"])
        self.assertFalse(gate["evaluator_recommendation_allows_release"])
        self.assertTrue(gate["attestation_mode_allows_release"])
        self.assertFalse(rel_auth)

    def test_review_reject_and_evaluator_approve_production_mode_denies_release(self):
        gate, rel_auth = derive_release_gate(
            verdict="REJECT",
            evaluator_recommendation="approve_candidate",
            attestation_mode="PRODUCTION_REVIEW",
        )
        self.assertFalse(gate["review_verdict_allows_release"])
        self.assertTrue(gate["evaluator_recommendation_allows_release"])
        self.assertTrue(gate["attestation_mode_allows_release"])
        self.assertFalse(rel_auth)

    def test_controlled_integration_mode_always_denies_release(self):
        for verdict in ["APPROVE", "REQUEST_CHANGES", "REJECT"]:
            for rec in ["approve_candidate", "reject"]:
                gate, rel_auth = derive_release_gate(
                    verdict=verdict,
                    evaluator_recommendation=rec,
                    attestation_mode="CONTROLLED_INTEGRATION",
                )
                self.assertFalse(gate["attestation_mode_allows_release"])
                self.assertFalse(rel_auth)


class TestAttestationV2BuildingAndVerification(unittest.TestCase):
    """Sections 35-39, 50: Building, signing, verification, and tamper negatives."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.tmp_dir.name)

        # Generate ephemeral RSA keypair
        self.priv_key_path = self.work_dir / "private.pem"
        self.pub_key_path = self.work_dir / "public.pem"
        subprocess.run(["openssl", "genrsa", "-out", str(self.priv_key_path), "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", str(self.priv_key_path), "-pubout", "-out", str(self.pub_key_path)], check=True, capture_output=True)
        self.fingerprint = public_key_fingerprint(str(self.pub_key_path))
        self.key_id = f"test-key:{self.fingerprint}"

        # Sample valid evaluator ingress facts
        self.eval_ingress = {
            "schema_version": "evaluator-evidence-ingress-v1",
            "ingress_id": "evalingress-730c6a3001fb304f8d4b69590427a190615ce38ded2b46eaf1a10dbd81195eef",
            "ingress_sha256": "3d674e071f82d2612618d11260953620ff6231f11f911beda4f1b325cd04ba73",
            "review_authority_repository": "miskatonic-system/miskatonic-review-authority",
            "review_authority_sha": "bea82aea9b640a9f64b71a3f72a2119a2e02d691",
            "evaluator_repository": "Miskatonic-System/miskatonic-agent-evaluator",
            "evaluator_sha": "1f93eff471aa67486738742f70eaa396b9d70f8e",
            "control_plane_repository": "Miskatonic-System/miskatonic-control-plane",
            "control_plane_sha": "7bbb2ff093ea6201d4c20d43a094b372821c0239",
            "evaluation_request_id": "evalreq-3557587cfe7c895bbb27299ff0a879055b861b5b4ded5c4a0f745d29a6aa01cb",
            "evaluation_request_sha256": "44ac5aefa11bff2e9514ea830e13976394a4bf671786d7a0db25d7975ec61c8c",
            "evaluation_request_raw_sha256": "7b3a159802bd7fb91c373222e359cdaf13d449f79a965a992b7ea760e44bc67d",
            "evaluation_id": "eval-3df0a6765fc3",
            "evaluation_result_sha256": "e94a0cf4f39c3e0d296f660f281fe60e856ccbcf409e432c5b0a25971eb4dc57",
            "evaluation_result_raw_sha256": "e525231596da41481de34aac748cf28566cf5544489c2907f0dc53f7855ee64d",
            "evaluation_result_schema": "miskatonic.evaluation.v2",
            "custody_receipt_sha256": "058ad1bf9c1802c12786c560237832fcf6aecd8375cd1bd58e06211e3ee8b4ed",
            "custody_receipt_raw_sha256": "3b1c935a50732d4862a26bd74f59bf6722150a69cfa01105b19d42851c314ef1",
            "dispatch_id": "evaldispatch-937df514fab7e2ec12d74e08d4267cc6c5ec594fec4b2616fe805372ddb67b15",
            "dispatch_state_raw_sha256": "efe6c40afa2cdd089c3f4724674c40cb4d4b2c7f5c989b5b452ae8c92b49b526",
            "candidate_repository": "Miskatonic-System/miskatonic-control-plane",
            "baseline_sha": "7edc9c29363912d23ad8cd8c1d1d5a4b3e48f3a5",
            "candidate_sha": "6d948cadb22220e84d820cc7dcd69a0fad7ce866",
            "task_pack_id": "control-plane-orchestration-v1",
            "task_pack_sha256": "3ea0bfb98094d04920b70d436d4e1b2425389a1e6b2d61b8ff800e420ade1322",
            "recommendation": "reject",
            "evaluator_process_exit_code": 1,
            "request_contract_validation": "PASS",
            "result_contract_validation": "PASS",
            "request_result_binding": "PASS",
            "control_plane_custody_validation": "PASS",
            "dispatch_state_validation": "PASS",
            "evaluator_identity_validation": "PASS",
            "authority_effect": "EVIDENCE_ONLY",
            "ingested_at": "2026-08-22T23:55:51.874448Z",
        }

        self.candidate_repo = "Miskatonic-System/miskatonic-control-plane"
        self.base_sha = "7edc9c29363912d23ad8cd8c1d1d5a4b3e48f3a5"
        self.head_sha = "6d948cadb22220e84d820cc7dcd69a0fad7ce866"
        self.cand_digest = "a" * 64
        self.ra_sha = "bea82aea9b640a9f64b71a3f72a2119a2e02d691"

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _build_sample_attestation(self, **overrides):
        kwargs = {
            "authority_principal": "miskatonic.review-authority.production",
            "authority_workflow_run_id": "12345",
            "review_authority_sha": self.ra_sha,
            "attestation_mode": "PRODUCTION_REVIEW",
            "repository": self.candidate_repo,
            "pr_number": 42,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "candidate_digest": self.cand_digest,
            "producer_binding": {"producer_principal": "producer:control-plane"},
            "reviewer_principal": "reviewer:cloud-review",
            "review_provider": "openai-responses",
            "review_model_requested": "gpt-4o",
            "review_execution": {"test": "data"},
            "verdict": "APPROVE",
            "summary": "Sample summary",
            "findings": [],
            "confidence": 0.95,
            "reviewer_policy_version": "reviewer-policy-v1",
            "evaluator_evidence": self.eval_ingress,
        }
        kwargs.update(overrides)
        return build_review_attestation_v2(**kwargs)

    def test_build_and_sign_attestation_v2_success(self):
        attestation = self._build_sample_attestation()
        self.assertEqual(attestation["schema_version"], "review-attestation-v2")
        self.assertEqual(attestation["verdict"], "APPROVE")
        # Evaluator recommendation is 'reject', so release_authorized must be False even with APPROVE verdict
        self.assertFalse(attestation["release_authorized"])
        self.assertFalse(attestation["release_gate"]["evaluator_recommendation_allows_release"])

        signed = sign_review_attestation_v2(attestation, str(self.priv_key_path), key_id=self.key_id)
        self.assertIn("signature", signed)
        self.assertEqual(signed["signature"]["key_id"], self.key_id)

        # Verify signed artifact against evaluator ingress
        verify_review_attestation_v2(
            signed,
            str(self.pub_key_path),
            self.eval_ingress,
            expected_key_id=self.key_id,
        )

    # Section 50: Tamper Tests
    def _assert_tamper_fails(self, signed_attestation, tamper_func, expected_error="ATTESTATION_SIGNATURE_INVALID"):
        tampered = copy.deepcopy(signed_attestation)
        tamper_func(tampered)
        with self.assertRaises(AuthorityError) as ctx:
            verify_review_attestation_v2(
                tampered,
                str(self.pub_key_path),
                self.eval_ingress,
                expected_key_id=self.key_id,
            )
        self.assertTrue(
            expected_error in str(ctx.exception)
            or "ATTESTATION_SIGNATURE_INVALID" in str(ctx.exception)
            or "REVIEW_ATTESTATION_V2_SCHEMA_VIOLATION" in str(ctx.exception)
        )

    def test_tamper_ingress_sha256_in_signed_attestation(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a["evaluator_evidence"].__setitem__("ingress_sha256", "0" * 64),
            "ATTESTATION_SIGNATURE_INVALID",
        )

    def test_tamper_ingress_id(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a["evaluator_evidence"].__setitem__("ingress_id", "evalingress-" + "0" * 64),
            "ATTESTATION_SIGNATURE_INVALID",
        )

    def test_tamper_evaluator_sha(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a["evaluator_evidence"].__setitem__("evaluator_sha", "0" * 40),
            "ATTESTATION_SIGNATURE_INVALID",
        )

    def test_tamper_control_plane_sha(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a["evaluator_evidence"].__setitem__("control_plane_sha", "0" * 40),
            "ATTESTATION_SIGNATURE_INVALID",
        )

    def test_tamper_evaluation_id(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a["evaluator_evidence"].__setitem__("evaluation_id", "eval-other"),
            "ATTESTATION_SIGNATURE_INVALID",
        )

    def test_tamper_evaluation_result_sha256(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a["evaluator_evidence"].__setitem__("evaluation_result_sha256", "0" * 64),
            "ATTESTATION_SIGNATURE_INVALID",
        )

    def test_tamper_task_pack_sha256(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a["evaluator_evidence"].__setitem__("task_pack_sha256", "0" * 64),
            "ATTESTATION_SIGNATURE_INVALID",
        )

    def test_tamper_recommendation(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a["evaluator_evidence"].__setitem__("recommendation", "approve_candidate"),
            "RELEASE_GATE_DERIVATION_MISMATCH",
        )

    def test_tamper_candidate_repository(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a.__setitem__("repository", "evil/repo"),
            "ATTESTATION_SIGNATURE_INVALID",
        )

    def test_tamper_base_sha(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a.__setitem__("base_sha", "0" * 40),
            "ATTESTATION_SIGNATURE_INVALID",
        )

    def test_tamper_head_sha(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a.__setitem__("head_sha", "0" * 40),
            "ATTESTATION_SIGNATURE_INVALID",
        )

    def test_tamper_release_gate_boolean(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a["release_gate"].__setitem__("evaluator_recommendation_allows_release", True),
            "RELEASE_GATE_DERIVATION_MISMATCH",
        )

    def test_tamper_release_authorized(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a.__setitem__("release_authorized", True),
            "RELEASE_AUTHORIZED_INCONSISTENT",
        )

    def test_tamper_attestation_mode(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        self._assert_tamper_fails(
            signed,
            lambda a: a.__setitem__("attestation_mode", "CONTROLLED_INTEGRATION"),
            "RELEASE_GATE_DERIVATION_MISMATCH",
        )

    def test_tamper_key_id(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        tampered = copy.deepcopy(signed)
        with self.assertRaises(AuthorityError) as ctx:
            verify_review_attestation_v2(
                tampered,
                str(self.pub_key_path),
                self.eval_ingress,
                expected_key_id="other-key-id",
            )
        self.assertIn("ATTESTATION_SIGNING_KEY_MISMATCH", str(ctx.exception))

    def test_tamper_ingress_artifact_after_signing(self):
        signed = sign_review_attestation_v2(self._build_sample_attestation(), str(self.priv_key_path), key_id=self.key_id)
        tampered_ingress = copy.deepcopy(self.eval_ingress)
        tampered_ingress["recommendation"] = "approve_candidate"
        # Ingress digest mismatch or attestation mismatch
        with self.assertRaises(AuthorityError) as ctx:
            verify_review_attestation_v2(
                signed,
                str(self.pub_key_path),
                tampered_ingress,
                expected_key_id=self.key_id,
            )
        self.assertTrue(
            "INGRESS_ENVELOPE_DIGEST_MISMATCH" in str(ctx.exception)
            or "ATTESTATION_RECOMMENDATION_MISMATCH" in str(ctx.exception)
        )


if __name__ == "__main__":
    unittest.main()
