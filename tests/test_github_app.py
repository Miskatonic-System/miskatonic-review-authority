from pathlib import Path
import base64
import json
import tempfile
import unittest

from miskatonic_review_authority.github_app import create_app_jwt
from miskatonic_review_authority.util import run


def _decode(segment: str):
    segment += "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment).decode("utf-8"))


class GitHubAppTests(unittest.TestCase):
    def test_jwt_binds_app_and_short_lifetime(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory, "key.pem")
            run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)])
            jwt = create_app_jwt("12345", str(key), now=1000)
            header, payload, signature = jwt.split(".")
            self.assertEqual(_decode(header), {"alg": "RS256", "typ": "JWT"})
            self.assertEqual(_decode(payload), {"exp": 1540, "iat": 940, "iss": "12345"})
            self.assertTrue(signature)


if __name__ == "__main__":
    unittest.main()
