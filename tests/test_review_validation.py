import unittest

from miskatonic_review_authority.review_runner import _validate_review
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


if __name__ == "__main__":
    unittest.main()
