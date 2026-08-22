"""Comprehensive unit tests for Review Authority Evaluator Evidence Ingress.

Implements WO-RA-EVALUATOR-EVIDENCE-INGRESS-01A specifications:
- Contract lock tests (Section 49)
- Required negative tests 1-29 (Section 46)
- Valid negative evaluator judgment (Section 47)
- No authority promotion (Section 48)
- Idempotency and conflict handling (Sections 39, 40)
- CLI entrypoint testing (Section 41)
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from miskatonic_review_authority.cli import main as cli_main
from miskatonic_review_authority.evaluator_ingress import (
    EXPECTED_CONTROL_PLANE_REPO,
    EXPECTED_EVALUATOR_REPO,
    EXPECTED_REVIEW_AUTHORITY_REPO,
    compute_ingress_envelope_id,
    ingest_evaluator_evidence,
    load_upstream_evidence_lock,
    parse_and_validate_github_origin,
    recompute_control_plane_custody_receipt_sha256,
    verify_control_plane_checkout,
    verify_evaluator_checkout,
    verify_evaluator_python,
    verify_review_authority_source,
)
from miskatonic_review_authority.util import AuthorityError, canonical_json_bytes, read_json, sha256_bytes

RA_ROOT = Path(__file__).resolve().parent.parent
REAL_EVAL_ROOT = Path("/home/kowen9024/.miskatonic/worktrees/evaluator-contract").resolve()
REAL_CP_ROOT = Path("/home/kowen9024/.miskatonic/worktrees/evaluator-dispatch").resolve()
EXPLICIT_PY = Path("/usr/bin/python3.12")
if not EXPLICIT_PY.exists():
    EXPLICIT_PY = Path(sys.executable)


class TestContractLocksAndSchemas(unittest.TestCase):
    """Section 49: Contract Lock and Upstream Schema Tests."""

    def test_lock_file_matches_exact_upstream_digests(self):
        lock = load_upstream_evidence_lock(RA_ROOT)
        self.assertEqual(lock["schema_version"], "miskatonic.upstream-evidence-lock.v1")
        self.assertEqual(lock["evaluator_repository"], "Miskatonic-System/miskatonic-agent-evaluator")
        self.assertEqual(lock["evaluator_sha"], "1f93eff471aa67486738742f70eaa396b9d70f8e")
        self.assertEqual(lock["request_schema_sha256"], "330791179f2c27bebc2161752d0cf3f3eb75c65182b69787055a3558d593576f")
        self.assertEqual(lock["result_schema_sha256"], "5091affee5a7281cea41a480d94bc31fddeb2eed1605e06fdf55f0c0c8e7a658")
        self.assertEqual(lock["control_plane_repository"], "Miskatonic-System/miskatonic-control-plane")
        self.assertEqual(lock["control_plane_sha"], "7bbb2ff093ea6201d4c20d43a094b372821c0239")
        self.assertEqual(lock["custody_schema_sha256"], "52db2f1019bfa81c93d7fff3548c914d5905205e05a402651ddf359fc5e6fa4a")

    def test_no_copied_upstream_schemas_in_review_authority(self):
        schemas_dir = RA_ROOT / "schemas"
        self.assertFalse((schemas_dir / "evaluation-request-v1.schema.json").exists())
        self.assertFalse((schemas_dir / "evaluation-result-v2.schema.json").exists())
        self.assertFalse((schemas_dir / "evaluator-result-custody-receipt-v1.schema.json").exists())


class TestOriginParsing(unittest.TestCase):
    """Origin validation unit tests."""

    def test_valid_https_origin(self):
        self.assertEqual(
            parse_and_validate_github_origin("https://github.com/Miskatonic-System/miskatonic-review-authority.git"),
            "miskatonic-system/miskatonic-review-authority",
        )

    def test_valid_ssh_origin(self):
        self.assertEqual(
            parse_and_validate_github_origin("git@github.com:Miskatonic-System/miskatonic-review-authority.git"),
            "miskatonic-system/miskatonic-review-authority",
        )

    def test_untrusted_host_origin_fails(self):
        with self.assertRaises(AuthorityError) as ctx:
            parse_and_validate_github_origin("https://github.com.evil.example/Miskatonic-System/miskatonic-review-authority.git")
        self.assertIn("UNTRUSTED_GIT_HOST", str(ctx.exception))


class TestEvaluatorEvidenceIngress(unittest.TestCase):
    """Sections 46, 47, 48: Evidence ingestion, negative tests, and idempotency."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.tmp_dir.name)

        self.lock = load_upstream_evidence_lock(RA_ROOT)

        # Load actual pilot artifacts if present, else fallback
        pilot_dir = Path("/tmp/miskatonic_pilot_custody/route-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/evaluation")
        self.req_path = self.test_dir / "evaluation-request.json"
        self.res_path = self.test_dir / "evaluation-result.json"
        self.cust_path = self.test_dir / "evaluator-result-custody-receipt.json"
        self.disp_path = self.test_dir / "evaluator-dispatch-state.json"
        self.out_path = self.test_dir / "evaluator-evidence-ingress.json"

        if (pilot_dir / "evaluation-request.json").exists():
            self.req_path.write_bytes((pilot_dir / "evaluation-request.json").read_bytes())
            self.res_path.write_bytes((pilot_dir / "evaluation-result.json").read_bytes())
            self.cust_path.write_bytes((pilot_dir / "evaluator-result-custody-receipt.json").read_bytes())
            self.disp_path.write_bytes((pilot_dir / "evaluator-dispatch-state.json").read_bytes())
            self.req_data = read_json(self.req_path)
            self.res_data = read_json(self.res_path)
            self.cust_data = read_json(self.cust_path)
            self.disp_data = read_json(self.disp_path)
            self.req_id = self.req_data["request_id"]
            self.req_sha = self.req_data["request_sha256"]
            self.eval_id = self.res_data["evaluation_id"]
            self.result_sha = self.res_data["result_sha256"]
            self.dispatch_id = self.cust_data["dispatch_id"]
            self.cand_sha = self.req_data["candidate"]["candidate_sha"]
            self.base_sha = self.req_data["candidate"]["baseline_sha"]
            self.task_pack_id = self.req_data["evaluation_profile"]["task_pack_id"]
            self.task_pack_sha = self.req_data["evaluation_profile"]["task_pack_sha256"]

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _call_ingest(self, **overrides):
        kwargs = {
            "review_authority_root": RA_ROOT,
            "evaluator_root": REAL_EVAL_ROOT,
            "control_plane_root": REAL_CP_ROOT,
            "evaluator_python": EXPLICIT_PY,
            "evaluation_request_path": self.req_path,
            "evaluation_result_path": self.res_path,
            "custody_receipt_path": self.cust_path,
            "dispatch_state_path": self.disp_path,
            "output_path": self.out_path,
        }
        kwargs.update(overrides)
        with patch("miskatonic_review_authority.evaluator_ingress.verify_review_authority_source", return_value="2" * 40):
            return ingest_evaluator_evidence(**kwargs)

    # Section 47: Valid Negative Evaluator Judgment & Idempotency
    def test_valid_reject_evaluator_judgment_produces_ingress_ready_and_idempotent(self):
        res1 = self._call_ingest()
        self.assertEqual(res1["status"], "INGRESS_READY")
        self.assertEqual(res1["recommendation"], "reject")
        self.assertEqual(res1["authority_effect"], "EVIDENCE_ONLY")
        self.assertTrue(self.out_path.exists())

        envelope = read_json(self.out_path)
        self.assertEqual(envelope["schema_version"], "evaluator-evidence-ingress-v1")
        self.assertEqual(envelope["recommendation"], "reject")
        self.assertEqual(envelope["authority_effect"], "EVIDENCE_ONLY")
        self.assertEqual(envelope["evaluator_process_exit_code"], 1)

        # Idempotent re-entry check
        res2 = self._call_ingest()
        self.assertEqual(res2["status"], "IDEMPOTENT")
        self.assertEqual(res2["ingress_id"], res1["ingress_id"])
        self.assertEqual(res2["ingress_sha256"], res1["ingress_sha256"])

    # Section 48: No Authority Promotion Test
    def test_no_authority_promotion_assertions(self):
        res = self._call_ingest()
        envelope = read_json(self.out_path)
        env_text = json.dumps(envelope)

        # Ensure forbidden authority fields are strictly absent
        forbidden = [
            "release_authorized",
            "merge_authorized",
            "activation_authorized",
            "review_ratified",
            "runtime_capability_granted",
        ]
        for term in forbidden:
            self.assertNotIn(term, env_text)

        # Ensure recommendation is lowercase 'reject' and not uppercase Review Authority verdict
        self.assertEqual(envelope["recommendation"], "reject")
        self.assertNotIn('"REJECT"', env_text)
        self.assertNotIn('"REQUEST_CHANGES"', env_text)
        self.assertNotIn('"APPROVE"', env_text)

    # Negative Tests (Section 46)
    def test_neg_1_wrong_evaluator_checkout_sha(self):
        def side_effect(cmd, *args, **kwargs):
            cmd_str = " ".join(cmd)
            cwd = str(kwargs.get("cwd", ""))
            if "--is-inside-work-tree" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="true\n", stderr="")
            elif "rev-parse HEAD" in cmd_str and "contract" in cwd:
                return subprocess.CompletedProcess(cmd, 0, stdout="0" * 40 + "\n", stderr="")
            elif "remote get-url origin" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="https://github.com/Miskatonic-System/miskatonic-agent-evaluator.git\n", stderr="")
            elif "status --porcelain" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            elif "version_info" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="3.12.0\n", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="IMPORT_OK\n", stderr="")

        with patch("subprocess.run", side_effect=side_effect):
            with self.assertRaises(AuthorityError) as ctx:
                self._call_ingest()
            self.assertIn("EVALUATOR_SHA_MISMATCH", str(ctx.exception))

    def test_neg_2_dirty_evaluator_checkout(self):
        def side_effect(cmd, *args, **kwargs):
            cmd_str = " ".join(cmd)
            cwd = str(kwargs.get("cwd", ""))
            if "--is-inside-work-tree" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="true\n", stderr="")
            elif "status --porcelain" in cmd_str and "contract" in cwd:
                return subprocess.CompletedProcess(cmd, 0, stdout=" M dirty.py\n", stderr="")
            elif "remote get-url origin" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="https://github.com/Miskatonic-System/miskatonic-agent-evaluator.git\n", stderr="")
            elif "rev-parse HEAD" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout=self.lock["evaluator_sha"] + "\n", stderr="")
            elif "version_info" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="3.12.0\n", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="IMPORT_OK\n", stderr="")

        with patch("subprocess.run", side_effect=side_effect):
            with self.assertRaises(AuthorityError) as ctx:
                self._call_ingest()
            self.assertIn("EVALUATOR_CHECKOUT_DIRTY", str(ctx.exception))

    def test_neg_3_wrong_evaluator_origin(self):
        def side_effect(cmd, *args, **kwargs):
            cmd_str = " ".join(cmd)
            if "--is-inside-work-tree" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="true\n", stderr="")
            elif "remote get-url origin" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="https://github.com/evil/miskatonic-agent-evaluator.git\n", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="true\n", stderr="")

        with patch("subprocess.run", side_effect=side_effect):
            with self.assertRaises(AuthorityError) as ctx:
                self._call_ingest()
            self.assertIn("EVALUATOR_ORIGIN_MISMATCH", str(ctx.exception))

    def test_neg_4_python_under_312_fails(self):
        def side_effect(cmd, *args, **kwargs):
            cmd_str = " ".join(cmd)
            if "--is-inside-work-tree" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="true\n", stderr="")
            elif "version_info" in cmd_str:
                return subprocess.CompletedProcess(cmd, 1, stdout="3.11.0\n", stderr="")
            elif "remote get-url origin" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="https://github.com/Miskatonic-System/miskatonic-agent-evaluator.git\n", stderr="")
            elif "rev-parse HEAD" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout=self.lock["evaluator_sha"] + "\n", stderr="")
            elif "status --porcelain" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="true\n", stderr="")

        with patch("subprocess.run", side_effect=side_effect):
            with self.assertRaises(AuthorityError) as ctx:
                self._call_ingest()
            self.assertIn("EVALUATOR_PYTHON_VERSION_INCOMPATIBLE", str(ctx.exception))

    def test_neg_7_wrong_control_plane_checkout_sha(self):
        def side_effect(cmd, *args, **kwargs):
            cmd_str = " ".join(cmd)
            cwd = str(kwargs.get("cwd", ""))
            if "--is-inside-work-tree" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="true\n", stderr="")
            elif "rev-parse HEAD" in cmd_str and "dispatch" in cwd:
                return subprocess.CompletedProcess(cmd, 0, stdout="0" * 40 + "\n", stderr="")
            elif "remote get-url origin" in cmd_str and "dispatch" in cwd:
                return subprocess.CompletedProcess(cmd, 0, stdout="https://github.com/Miskatonic-System/miskatonic-control-plane.git\n", stderr="")
            elif "remote get-url origin" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="https://github.com/Miskatonic-System/miskatonic-agent-evaluator.git\n", stderr="")
            elif "rev-parse HEAD" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout=self.lock["evaluator_sha"] + "\n", stderr="")
            elif "status --porcelain" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            elif "version_info" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="3.12.0\n", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="IMPORT_OK\n", stderr="")

        with patch("subprocess.run", side_effect=side_effect):
            with self.assertRaises(AuthorityError) as ctx:
                self._call_ingest()
            self.assertIn("CONTROL_PLANE_SHA_MISMATCH", str(ctx.exception))

    def test_neg_8_dirty_control_plane_checkout(self):
        def side_effect(cmd, *args, **kwargs):
            cmd_str = " ".join(cmd)
            cwd = str(kwargs.get("cwd", ""))
            if "--is-inside-work-tree" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="true\n", stderr="")
            elif "status --porcelain" in cmd_str and "dispatch" in cwd:
                return subprocess.CompletedProcess(cmd, 0, stdout=" M dirty.py\n", stderr="")
            elif "remote get-url origin" in cmd_str and "dispatch" in cwd:
                return subprocess.CompletedProcess(cmd, 0, stdout="https://github.com/Miskatonic-System/miskatonic-control-plane.git\n", stderr="")
            elif "rev-parse HEAD" in cmd_str and "dispatch" in cwd:
                return subprocess.CompletedProcess(cmd, 0, stdout=self.lock["control_plane_sha"] + "\n", stderr="")
            elif "remote get-url origin" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="https://github.com/Miskatonic-System/miskatonic-agent-evaluator.git\n", stderr="")
            elif "rev-parse HEAD" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout=self.lock["evaluator_sha"] + "\n", stderr="")
            elif "status --porcelain" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            elif "version_info" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="3.12.0\n", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="IMPORT_OK\n", stderr="")

        with patch("subprocess.run", side_effect=side_effect):
            with self.assertRaises(AuthorityError) as ctx:
                self._call_ingest()
            self.assertIn("CONTROL_PLANE_CHECKOUT_DIRTY", str(ctx.exception))

    def test_neg_11_malformed_request(self):
        self.req_path.write_text("malformed json {", encoding="utf-8")
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("EVALUATION_REQUEST_MALFORMED", str(ctx.exception))

    def test_neg_12_malformed_result(self):
        self.res_path.write_text("malformed json {", encoding="utf-8")
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("EVALUATION_RESULT_MALFORMED", str(ctx.exception))

    def test_neg_14_result_request_mismatch(self):
        bad_res = copy.deepcopy(self.res_data)
        bad_res["request_id"] = "evalreq-" + "0" * 64
        self.res_path.write_bytes(json.dumps(bad_res).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("EVALUATOR_ARTIFACT_VALIDATION_FAILED", str(ctx.exception))

    def test_neg_16_custody_receipt_digest_tamper(self):
        bad_cust = copy.deepcopy(self.cust_data)
        bad_cust["receipt_sha256"] = "0" * 64
        self.cust_path.write_bytes(json.dumps(bad_cust).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("CONTROL_PLANE_CUSTODY_DIGEST_MISMATCH", str(ctx.exception))

    def test_neg_17_custody_raw_result_digest_tamper(self):
        bad_cust = copy.deepcopy(self.cust_data)
        bad_cust["evaluation_result_raw_sha256"] = "0" * 64
        bad_cust["receipt_sha256"] = recompute_control_plane_custody_receipt_sha256(bad_cust)
        self.cust_path.write_bytes(json.dumps(bad_cust).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("CONTROL_PLANE_RAW_RESULT_BINDING_MISMATCH", str(ctx.exception))

    def test_neg_18_custody_result_semantic_digest_mismatch(self):
        bad_cust = copy.deepcopy(self.cust_data)
        bad_cust["evaluation_result_sha256"] = "0" * 64
        bad_cust["receipt_sha256"] = recompute_control_plane_custody_receipt_sha256(bad_cust)
        self.cust_path.write_bytes(json.dumps(bad_cust).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("CONTROL_PLANE_RESULT_DIGEST_BINDING_MISMATCH", str(ctx.exception))

    def test_neg_19_custody_request_mismatch(self):
        bad_cust = copy.deepcopy(self.cust_data)
        bad_cust["evaluation_request_id"] = "evalreq-" + "0" * 64
        bad_cust["receipt_sha256"] = recompute_control_plane_custody_receipt_sha256(bad_cust)
        self.cust_path.write_bytes(json.dumps(bad_cust).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("CONTROL_PLANE_REQUEST_ID_BINDING_MISMATCH", str(ctx.exception))

    def test_neg_20_candidate_mismatch(self):
        bad_cust = copy.deepcopy(self.cust_data)
        bad_cust["candidate_sha"] = "0" * 40
        bad_cust["receipt_sha256"] = recompute_control_plane_custody_receipt_sha256(bad_cust)
        self.cust_path.write_bytes(json.dumps(bad_cust).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("CANDIDATE_SHA_BINDING_MISMATCH", str(ctx.exception))

    def test_neg_21_task_pack_mismatch(self):
        bad_cust = copy.deepcopy(self.cust_data)
        bad_cust["task_pack_id"] = "other-task-pack"
        bad_cust["receipt_sha256"] = recompute_control_plane_custody_receipt_sha256(bad_cust)
        self.cust_path.write_bytes(json.dumps(bad_cust).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("TASK_PACK_ID_BINDING_MISMATCH", str(ctx.exception))

    def test_neg_22_dispatch_state_not_complete(self):
        bad_disp = copy.deepcopy(self.disp_data)
        bad_disp["state"] = "STARTED"
        self.disp_path.write_bytes(json.dumps(bad_disp).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("DISPATCH_STATE_NOT_COMPLETE", str(ctx.exception))

    def test_neg_23_dispatch_id_mismatch(self):
        bad_disp = copy.deepcopy(self.disp_data)
        bad_disp["dispatch_id"] = "evaldispatch-" + "0" * 64
        self.disp_path.write_bytes(json.dumps(bad_disp).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("DISPATCH_ID_BINDING_MISMATCH", str(ctx.exception))

    def test_neg_24_dispatch_source_sha_mismatch(self):
        bad_disp = copy.deepcopy(self.disp_data)
        bad_disp["dispatch_source_sha"] = "0" * 40
        self.disp_path.write_bytes(json.dumps(bad_disp).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("DISPATCH_SOURCE_SHA_BINDING_MISMATCH", str(ctx.exception))

    def test_neg_5_request_schema_digest_drift(self):
        with patch.dict(self.lock, {"request_schema_sha256": "0" * 64}):
            with patch("miskatonic_review_authority.evaluator_ingress.load_upstream_evidence_lock", return_value=self.lock):
                with self.assertRaises(AuthorityError) as ctx:
                    self._call_ingest()
                self.assertIn("EVALUATOR_REQUEST_SCHEMA_DIGEST_MISMATCH", str(ctx.exception))

    def test_neg_6_result_schema_digest_drift(self):
        with patch.dict(self.lock, {"result_schema_sha256": "0" * 64}):
            with patch("miskatonic_review_authority.evaluator_ingress.load_upstream_evidence_lock", return_value=self.lock):
                with self.assertRaises(AuthorityError) as ctx:
                    self._call_ingest()
                self.assertIn("EVALUATOR_RESULT_SCHEMA_DIGEST_MISMATCH", str(ctx.exception))

    def test_neg_9_wrong_control_plane_origin(self):
        def side_effect(cmd, *args, **kwargs):
            cmd_str = " ".join(cmd)
            cwd = str(kwargs.get("cwd", ""))
            if "--is-inside-work-tree" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="true\n", stderr="")
            elif "remote get-url origin" in cmd_str and "dispatch" in cwd:
                return subprocess.CompletedProcess(cmd, 0, stdout="https://github.com/evil/miskatonic-control-plane.git\n", stderr="")
            elif "remote get-url origin" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="https://github.com/Miskatonic-System/miskatonic-agent-evaluator.git\n", stderr="")
            elif "rev-parse HEAD" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout=self.lock["evaluator_sha"] + "\n", stderr="")
            elif "status --porcelain" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            elif "version_info" in cmd_str:
                return subprocess.CompletedProcess(cmd, 0, stdout="3.12.0\n", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="IMPORT_OK\n", stderr="")

        with patch("subprocess.run", side_effect=side_effect):
            with self.assertRaises(AuthorityError) as ctx:
                self._call_ingest()
            self.assertIn("CONTROL_PLANE_ORIGIN_MISMATCH", str(ctx.exception))

    def test_neg_10_custody_schema_drift(self):
        with patch.dict(self.lock, {"custody_schema_sha256": "0" * 64}):
            with patch("miskatonic_review_authority.evaluator_ingress.load_upstream_evidence_lock", return_value=self.lock):
                with self.assertRaises(AuthorityError) as ctx:
                    self._call_ingest()
                self.assertIn("CONTROL_PLANE_CUSTODY_SCHEMA_DIGEST_MISMATCH", str(ctx.exception))

    def test_neg_13_bad_evaluator_semantic_result_digest(self):
        bad_res = copy.deepcopy(self.res_data)
        bad_res["result_sha256"] = "0" * 64
        self.res_path.write_bytes(json.dumps(bad_res).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("EVALUATOR_ARTIFACT_VALIDATION_FAILED", str(ctx.exception))

    def test_neg_15_wrong_evaluator_sha_in_result(self):
        from miskatonic_review_authority.evaluator_ingress import validate_evaluator_artifacts
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                ["eval_py"],
                0,
                stdout=json.dumps({
                    "success": True,
                    "facts": {
                        "evaluator_repository": "Miskatonic-System/miskatonic-agent-evaluator",
                        "evaluator_sha": "0" * 40,
                    },
                }),
                stderr="",
            )
            with self.assertRaises(AuthorityError) as ctx:
                validate_evaluator_artifacts(REAL_EVAL_ROOT, EXPLICIT_PY, {}, {}, self.lock)
            self.assertIn("EVALUATOR_EVIDENCE_IDENTITY_MISMATCH", str(ctx.exception))

    def test_neg_26_approve_with_exit_1_inconsistency_fails(self):
        bad_cust = copy.deepcopy(self.cust_data)
        bad_cust["recommendation"] = "approve_candidate"
        bad_cust["evaluator_process_exit_code"] = 1
        bad_cust["receipt_sha256"] = recompute_control_plane_custody_receipt_sha256(bad_cust)
        self.cust_path.write_bytes(json.dumps(bad_cust).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("CONTROL_PLANE_RECOMMENDATION_BINDING_MISMATCH", str(ctx.exception))

    def test_neg_28_dirty_review_authority_source(self):
        with patch("miskatonic_review_authority.evaluator_ingress.verify_review_authority_source", side_effect=AuthorityError("REVIEW_AUTHORITY_SOURCE_DIRTY", "dirty checkout")):
            with self.assertRaises(AuthorityError) as ctx:
                ingest_evaluator_evidence(
                    review_authority_root=RA_ROOT,
                    evaluator_root=REAL_EVAL_ROOT,
                    control_plane_root=REAL_CP_ROOT,
                    evaluator_python=EXPLICIT_PY,
                    evaluation_request_path=self.req_path,
                    evaluation_result_path=self.res_path,
                    custody_receipt_path=self.cust_path,
                    dispatch_state_path=self.disp_path,
                    output_path=self.out_path,
                )
            self.assertIn("REVIEW_AUTHORITY_SOURCE_DIRTY", str(ctx.exception))

    def test_neg_25_reject_with_exit_0_inconsistency_fails(self):
        bad_cust = copy.deepcopy(self.cust_data)
        bad_cust["evaluator_process_exit_code"] = 0
        bad_cust["receipt_sha256"] = recompute_control_plane_custody_receipt_sha256(bad_cust)
        self.cust_path.write_bytes(json.dumps(bad_cust).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("EVALUATOR_EXIT_RECOMMENDATION_INCONSISTENT", str(ctx.exception))

    def test_neg_27_source_authority_effect_not_none_fails(self):
        bad_cust = copy.deepcopy(self.cust_data)
        bad_cust["authority_effect"] = "EVIDENCE_ONLY"
        bad_cust["receipt_sha256"] = recompute_control_plane_custody_receipt_sha256(bad_cust)
        self.cust_path.write_bytes(json.dumps(bad_cust).encode("utf-8"))
        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertTrue(
            "INVALID_SOURCE_AUTHORITY_EFFECT" in str(ctx.exception)
            or "CONTROL_PLANE_CUSTODY_SCHEMA_VIOLATION" in str(ctx.exception)
        )

    def test_neg_29_existing_envelope_conflict_fails(self):
        # Create initial envelope
        self._call_ingest()

        # Modify the on-disk envelope to simulate a conflicting existing record
        existing = read_json(self.out_path)
        existing["candidate_sha"] = "0" * 40
        self.out_path.write_bytes(canonical_json_bytes(existing))

        with self.assertRaises(AuthorityError) as ctx:
            self._call_ingest()
        self.assertIn("EVALUATOR_EVIDENCE_INGRESS_CONFLICT", str(ctx.exception))


class TestCLIEntrypoint(unittest.TestCase):
    """Section 41: Test CLI ingest-evaluator-evidence entrypoint."""

    def test_cli_ingest_evaluator_evidence(self):
        # Run via cli_main in a temp dir
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_file = tmp_path / "cli-ingress.json"

            pilot_dir = Path("/tmp/miskatonic_pilot_custody/route-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/evaluation")
            req_file = pilot_dir / "evaluation-request.json"
            res_file = pilot_dir / "evaluation-result.json"
            cust_file = pilot_dir / "evaluator-result-custody-receipt.json"
            disp_file = pilot_dir / "evaluator-dispatch-state.json"

            argv = [
                "ingest-evaluator-evidence",
                "--review-authority-root", str(RA_ROOT),
                "--evaluator-root", str(REAL_EVAL_ROOT),
                "--evaluator-python", str(EXPLICIT_PY),
                "--control-plane-root", str(REAL_CP_ROOT),
                "--evaluation-request", str(req_file),
                "--evaluation-result", str(res_file),
                "--custody-receipt", str(cust_file),
                "--dispatch-state", str(disp_file),
                "--output", str(out_file),
            ]

            with patch("miskatonic_review_authority.evaluator_ingress.verify_review_authority_source", return_value="2" * 40):
                with self.assertRaises(SystemExit) as ctx:
                    cli_main(argv)
                self.assertEqual(ctx.exception.code, 0)

            self.assertTrue(out_file.exists())


if __name__ == "__main__":
    unittest.main()
