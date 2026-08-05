import unittest

from miskatonic_review_authority.review_runner import _trusted_producer, _validate_review
from miskatonic_review_authority.util import AuthorityError


class ReviewValidationTests(unittest.TestCase):
    def test_non_approval_cannot_authorize_release(self):
        with self.assertRaisesRegex(AuthorityError, "CLOUD_REVIEW_RELEASE_INCONSISTENT"):
            _validate_review({
                "verdict": "REQUEST_CHANGES",
                "release_authorized": True,
                "summary": "no",
                "findings": [],
                "confidence": 1.0,
            })

    def test_producer_binding_is_authority_owned(self):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bindings.json")
            path.write_text(
                json.dumps({
                    "bindings": [{
                        "repository": "owner/repo",
                        "pr_number": 7,
                        "head_branch": "work/x",
                        "producer_principal": "producer:one",
                    }]
                }),
                encoding="utf-8",
            )
            binding = _trusted_producer(str(path), "owner/repo", 7, "work/x")
            self.assertEqual(binding["producer_principal"], "producer:one")


if __name__ == "__main__":
    unittest.main()
