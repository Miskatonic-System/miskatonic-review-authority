from pathlib import Path
import tempfile
import unittest

from miskatonic_review_authority.attestation import public_key_fingerprint, sign_attestation, verify_attestation
from miskatonic_review_authority.util import AuthorityError, run


class AttestationTests(unittest.TestCase):
    def test_signed_attestation_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private.pem"
            public = root / "public.pem"
            run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)])
            run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)])
            value = {"schema_version": "review-attestation-v1", "verdict": "APPROVE", "release_authorized": True}
            key_id = public_key_fingerprint(str(public))
            signed = sign_attestation(value, str(private), key_id=key_id)
            verify_attestation(signed, str(public), expected_key_id=key_id)
            signed["verdict"] = "REJECT"
            with self.assertRaisesRegex(AuthorityError, "ATTESTATION_SIGNATURE_INVALID"):
                verify_attestation(signed, str(public), expected_key_id=key_id)


if __name__ == "__main__":
    unittest.main()
