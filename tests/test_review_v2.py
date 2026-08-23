"""Unit tests for Review Authority V2 runner, fail-before-authority tests, and CLI.

Implements WO-RA-EVALUATOR-ATTESTATION-BINDING-01A specifications:
- Sections 30-34: Order of execution and independent cloud review
- Section 51: Fail-before-external-authority tests (0 cloud calls, 0 signing calls)
- Section 41: review-v2 and verify-attestation-v2 CLI integration
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from miskatonic_review_authority.attestation import public_key_fingerprint
from miskatonic_review_authority.cli import main as cli_main
from miskatonic_review_authority.review_v2 import run_review_v2
from miskatonic_review_authority.util import AuthorityError, read_json

RA_ROOT = Path(__file__).resolve().parent.parent
REAL_EVAL_ROOT = Path("/home/kowen9024/.miskatonic/worktrees/evaluator-contract").resolve()
REAL_CP_ROOT = Path("/home/kowen9024/.miskatonic/worktrees/evaluator-dispatch").resolve()
EXPLICIT_PY = Path("/usr/bin/python3.12")
if not EXPLICIT_PY.exists():
    EXPLICIT_PY = Path(sys.executable)


class TestReviewV2Runner(unittest.TestCase):
    """Sections 30-34, 45-51: run_review_v2 unit and regression tests."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.tmp_dir.name)

        # Ephemeral RSA keypair
        self.priv_key_path = self.work_dir / "private.pem"
        self.pub_key_path = self.work_dir / "public.pem"
        subprocess.run(["openssl", "genrsa", "-out", str(self.priv_key_path), "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", str(self.priv_key_path), "-pubout", "-out", str(self.pub_key_path)], check=True, capture_output=True)
        self.fingerprint = public_key_fingerprint(str(self.pub_key_path))
        self.key_id = f"test-key:{self.fingerprint}"

        # Pilot artifacts
        pilot_dir = Path("/tmp/miskatonic_pilot_custody/route-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/evaluation")
        self.req_path = self.work_dir / "evaluation-request.json"
        self.res_path = self.work_dir / "evaluation-result.json"
        self.cust_path = self.work_dir / "evaluator-result-custody-receipt.json"
        self.disp_path = self.work_dir / "evaluator-dispatch-state.json"
        self.ingr_path = self.work_dir / "evaluator-evidence-ingress.json"

        self.req_path.write_bytes((pilot_dir / "evaluation-request.json").read_bytes())
        self.res_path.write_bytes((pilot_dir / "evaluation-result.json").read_bytes())
        self.cust_path.write_bytes((pilot_dir / "evaluator-result-custody-receipt.json").read_bytes())
        self.disp_path.write_bytes((pilot_dir / "evaluator-dispatch-state.json").read_bytes())
        self.ingr_path.write_bytes((pilot_dir / "evaluator-evidence-ingress-r1.json").read_bytes())

        self.repo = "Miskatonic-System/miskatonic-control-plane"
        self.base_sha = "7edc9c29363912d23ad8cd8c1d1d5a4b3e48f3a5"
        self.head_sha = "6d948cadb22220e84d820cc7dcd69a0fad7ce866"
        self.cand_digest = "0" * 64

        # Prior evidence fixture
        self.prior_path = self.work_dir / "prior.json"
        self.prior_path.write_text(json.dumps({
            "verdict": "PASS",
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "candidate_digest": self.cand_digest,
        }), encoding="utf-8")

        # Producer bindings fixture
        self.producer_path = self.work_dir / "producers.json"
        self.producer_path.write_text(json.dumps({
            "bindings": [
                {
                    "repository": self.repo,
                    "pr_number": 42,
                    "head_branch": "agent/test",
                    "producer_principal": "producer:control-plane",
                }
            ]
        }), encoding="utf-8")

        # Reviewer policy fixture
        self.policy_path = self.work_dir / "policy.json"
        self.policy_path.write_text(json.dumps({
            "schema_version": "reviewer-policy-v1",
            "provider": "openai-responses",
            "reviewer_principal": "reviewer:cloud-review",
            "policy_version": "policy-v1",
            "max_diff_characters": 100000,
        }), encoding="utf-8")

        # Diff fixture
        self.diff_path = self.work_dir / "diff.patch"
        self.diff_path.write_text("--- a/test\n+++ b/test\n+line\n", encoding="utf-8")

        self.out_path = self.work_dir / "review-attestation-v2.json"

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _call_run_review_v2(self, **overrides):
        kwargs = {
            "repository": self.repo,
            "pr_number": 42,
            "head_branch": "agent/test",
            "repo_path": str(REAL_CP_ROOT),
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "prior_evidence_path": str(self.prior_path),
            "producer_bindings_path": str(self.producer_path),
            "reviewer_policy_path": str(self.policy_path),
            "private_key_path": str(self.priv_key_path),
            "key_id": self.key_id,
            "diff_path": str(self.diff_path),
            "output_path": str(self.out_path),
            "api_key": "test-key",
            "model": "gpt-4o",
            "authority_principal": "miskatonic.review-authority.test",
            "workflow_run_id": "run-123",
            "review_authority_root": RA_ROOT,
            "evaluator_root": REAL_EVAL_ROOT,
            "control_plane_root": REAL_CP_ROOT,
            "evaluator_python": EXPLICIT_PY,
            "evaluator_ingress_path": self.ingr_path,
            "evaluation_request_path": self.req_path,
            "evaluation_result_path": self.res_path,
            "custody_receipt_path": self.cust_path,
            "dispatch_state_path": self.disp_path,
            "attestation_mode": "PRODUCTION_REVIEW",
        }
        kwargs.update(overrides)
        with patch("miskatonic_review_authority.review_v2.verify_review_authority_source", return_value="c" * 40), \
             patch("miskatonic_review_authority.review_v2.candidate_digest", return_value=(self.cand_digest, {})):
            return run_review_v2(**kwargs)

    # Section 46: Review APPROVE + Evaluator REJECT -> verdict: APPROVE, release_authorized: false
    def test_production_review_approve_with_evaluator_reject_denies_release(self):
        with patch("miskatonic_review_authority.review_v2._call_openai") as mock_openai:
            mock_openai.return_value = (
                {
                    "verdict": "APPROVE",
                    "release_authorized": True,
                    "summary": "Review approved code changes.",
                    "findings": [],
                    "confidence": 0.98,
                },
                {"provider": "mock-openai"},
            )
            signed = self._call_run_review_v2()
            self.assertEqual(signed["verdict"], "APPROVE")
            self.assertFalse(signed["release_authorized"])
            self.assertFalse(signed["release_gate"]["evaluator_recommendation_allows_release"])
            self.assertTrue(signed["release_gate"]["review_verdict_allows_release"])

    # Section 48: Controlled Integration mode -> release_authorized: false
    def test_controlled_integration_mode_denies_release(self):
        signed = self._call_run_review_v2(
            attestation_mode="CONTROLLED_INTEGRATION",
            review_fixture={
                "verdict": "REQUEST_CHANGES",
                "release_authorized": False,
                "summary": "Controlled integration fixture.",
                "findings": [],
                "confidence": 1.0,
            },
        )
        self.assertEqual(signed["attestation_mode"], "CONTROLLED_INTEGRATION")
        self.assertEqual(signed["verdict"], "REQUEST_CHANGES")
        self.assertFalse(signed["release_authorized"])
        self.assertFalse(signed["release_gate"]["attestation_mode_allows_release"])

    # Section 51: Fail Before External Authority Tests
    def test_fail_before_cloud_review_on_invalid_ingress(self):
        bad_ingr = copy.deepcopy(read_json(self.ingr_path))
        bad_ingr["ingress_sha256"] = "0" * 64
        self.ingr_path.write_bytes(json.dumps(bad_ingr).encode("utf-8"))

        with patch("miskatonic_review_authority.review_v2._call_openai") as mock_openai, \
             patch("miskatonic_review_authority.review_v2.sign_attestation") as mock_sign:
            with self.assertRaises(AuthorityError):
                self._call_run_review_v2()
            self.assertEqual(mock_openai.call_count, 0)
            self.assertEqual(mock_sign.call_count, 0)

    def test_fail_before_cloud_review_on_candidate_mismatch(self):
        with patch("miskatonic_review_authority.review_v2._call_openai") as mock_openai, \
             patch("miskatonic_review_authority.review_v2.sign_attestation") as mock_sign:
            with self.assertRaises(AuthorityError) as ctx:
                self._call_run_review_v2(head_sha="0" * 40)
            self.assertEqual(mock_openai.call_count, 0)
            self.assertEqual(mock_sign.call_count, 0)
            self.assertIn("CANDIDATE_SHA_BINDING_MISMATCH", str(ctx.exception))

    def test_fail_before_cloud_review_on_invalid_prior_evidence(self):
        self.prior_path.write_text(json.dumps({"verdict": "FAIL"}), encoding="utf-8")
        with patch("miskatonic_review_authority.review_v2._call_openai") as mock_openai, \
             patch("miskatonic_review_authority.review_v2.sign_attestation") as mock_sign:
            with self.assertRaises(AuthorityError) as ctx:
                self._call_run_review_v2()
            self.assertEqual(mock_openai.call_count, 0)
            self.assertEqual(mock_sign.call_count, 0)
            self.assertIn("PRIOR_VERIFICATION_EVIDENCE_INVALID", str(ctx.exception))

    # Section 41: CLI review-v2 and verify-attestation-v2 entrypoint test
    def test_cli_review_v2_and_verify_attestation_v2(self):
        # 1. Run review-v2 in CONTROLLED_INTEGRATION mode
        argv_review = [
            "review-v2",
            "--repository", self.repo,
            "--pr-number", "42",
            "--head-branch", "agent/test",
            "--repo-path", str(REAL_CP_ROOT),
            "--base-sha", self.base_sha,
            "--head-sha", self.head_sha,
            "--prior-evidence", str(self.prior_path),
            "--producer-bindings", str(self.producer_path),
            "--reviewer-policy", str(self.policy_path),
            "--private-key", str(self.priv_key_path),
            "--key-id", self.key_id,
            "--diff", str(self.diff_path),
            "--output", str(self.out_path),
            "--authority-principal", "miskatonic.review-authority.test",
            "--workflow-run-id", "run-123",
            "--review-authority-root", str(RA_ROOT),
            "--evaluator-root", str(REAL_EVAL_ROOT),
            "--control-plane-root", str(REAL_CP_ROOT),
            "--evaluator-python", str(EXPLICIT_PY),
            "--evaluator-ingress", str(self.ingr_path),
            "--evaluation-request", str(self.req_path),
            "--evaluation-result", str(self.res_path),
            "--custody-receipt", str(self.cust_path),
            "--dispatch-state", str(self.disp_path),
            "--attestation-mode", "CONTROLLED_INTEGRATION",
        ]

        with patch("miskatonic_review_authority.review_v2.verify_review_authority_source", return_value="c" * 40), \
             patch("miskatonic_review_authority.review_v2.candidate_digest", return_value=(self.cand_digest, {})):
            with self.assertRaises(SystemExit) as ctx:
                cli_main(argv_review)
            self.assertEqual(ctx.exception.code, 0)

        self.assertTrue(self.out_path.exists())

        # 2. Run verify-attestation-v2
        argv_verify = [
            "verify-attestation-v2",
            "--attestation", str(self.out_path),
            "--evaluator-ingress", str(self.ingr_path),
            "--public-key", str(self.pub_key_path),
            "--key-id", self.key_id,
        ]
        with self.assertRaises(SystemExit) as ctx:
            cli_main(argv_verify)
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
