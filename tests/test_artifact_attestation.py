from pathlib import Path
import tempfile
import unittest

from miskatonic_review_authority.artifact_attestation import (
    build_artifact_attestation,
    sign_artifact_attestation,
    verify_artifact_attestation,
)
from miskatonic_review_authority.attestation import public_key_fingerprint
from miskatonic_review_authority.util import AuthorityError, run


class ArtifactAttestationTests(unittest.TestCase):
    def _keys(self, root: Path) -> tuple[Path, Path, str]:
        private = root / "private.pem"
        public = root / "public.pem"
        run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(private),
            ]
        )
        run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private),
                "-pubout",
                "-out",
                str(public),
            ]
        )
        return private, public, public_key_fingerprint(str(public))

    def _unsigned(self) -> dict:
        return build_artifact_attestation(
            authority_principal="github-app:miskatonic-review-authority",
            workflow_run_id="run-123",
            artifact_type="rciep.evaluation-result",
            artifact_id="result-001",
            artifact_schema_version="rciep.evaluation-result.v0.1",
            artifact_digest="a" * 64,
            scope={"evaluation_id": "eval-001"},
            producer_binding={"producer_principal": "evaluator:independent"},
            reviewer_principal="reviewer:independent",
            review_provider="deterministic-test",
            review_execution={"execution_id": "review-001"},
            verdict="APPROVE",
            release_authorized=True,
            summary="Exact artifact passed test policy.",
            findings=[],
            confidence=1.0,
            reviewer_policy_version="artifact-review-v1",
            issued_at="2026-08-10T00:00:00+00:00",
        )

    def test_signed_typed_artifact_attestation_binds_exact_rciep_result(self):
        with tempfile.TemporaryDirectory() as directory:
            private, public, key_id = self._keys(Path(directory))
            signed = sign_artifact_attestation(
                self._unsigned(), str(private), key_id=key_id
            )
            verify_artifact_attestation(
                signed,
                str(public),
                expected_key_id=key_id,
                expected_artifact_type="rciep.evaluation-result",
                expected_artifact_id="result-001",
                expected_artifact_schema_version="rciep.evaluation-result.v0.1",
                expected_artifact_digest="a" * 64,
            )

    def test_artifact_digest_tampering_invalidates_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            private, public, key_id = self._keys(Path(directory))
            signed = sign_artifact_attestation(
                self._unsigned(), str(private), key_id=key_id
            )
            signed["artifact_digest"] = "b" * 64
            with self.assertRaisesRegex(
                AuthorityError, "ATTESTATION_SIGNATURE_INVALID"
            ):
                verify_artifact_attestation(
                    signed, str(public), expected_key_id=key_id
                )

    def test_expected_binding_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            private, public, key_id = self._keys(Path(directory))
            signed = sign_artifact_attestation(
                self._unsigned(), str(private), key_id=key_id
            )
            with self.assertRaisesRegex(
                AuthorityError, "ARTIFACT_ATTESTATION_BINDING_MISMATCH"
            ):
                verify_artifact_attestation(
                    signed,
                    str(public),
                    expected_key_id=key_id,
                    expected_artifact_digest="c" * 64,
                )

    def test_reviewer_producer_collision_rejected(self):
        with self.assertRaisesRegex(
            AuthorityError, "REVIEWER_PRODUCER_PRINCIPAL_COLLISION"
        ):
            build_artifact_attestation(
                authority_principal="authority:test",
                workflow_run_id="run-1",
                artifact_type="rciep.evaluation-result",
                artifact_id="result-1",
                artifact_schema_version="rciep.evaluation-result.v0.1",
                artifact_digest="a" * 64,
                scope={},
                producer_binding={"producer_principal": "same:principal"},
                reviewer_principal="same:principal",
                review_provider="test",
                review_execution={},
                verdict="APPROVE",
                release_authorized=True,
                summary="",
                findings=[],
                confidence=1.0,
                reviewer_policy_version="1",
            )

    def test_non_approval_cannot_authorize_release(self):
        with self.assertRaisesRegex(
            AuthorityError, "ARTIFACT_ATTESTATION_RELEASE_INCONSISTENT"
        ):
            build_artifact_attestation(
                authority_principal="authority:test",
                workflow_run_id="run-1",
                artifact_type="rciep.evaluation-result",
                artifact_id="result-1",
                artifact_schema_version="rciep.evaluation-result.v0.1",
                artifact_digest="a" * 64,
                scope={},
                producer_binding={"producer_principal": "producer:test"},
                reviewer_principal="reviewer:test",
                review_provider="test",
                review_execution={},
                verdict="REQUEST_CHANGES",
                release_authorized=True,
                summary="",
                findings=[],
                confidence=1.0,
                reviewer_policy_version="1",
            )


if __name__ == "__main__":
    unittest.main()
