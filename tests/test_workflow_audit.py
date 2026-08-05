from pathlib import Path
import tempfile
import unittest

from miskatonic_review_authority.workflow_audit import audit_workflows


class WorkflowAuditTests(unittest.TestCase):
    def test_rejects_movable_action_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            workflows = tmp / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text("steps:\n  - uses: actions/checkout@v5\n", encoding="utf-8")
            self.assertEqual(audit_workflows(str(tmp)), [".github/workflows/ci.yml:2:actions/checkout@v5"])

    def test_accepts_full_sha_and_local_action(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            workflows = tmp / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text(
                "steps:\n"
                "  - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09\n"
                "  - uses: ./local-action\n",
                encoding="utf-8",
            )
            self.assertEqual(audit_workflows(str(tmp)), [])


if __name__ == "__main__":
    unittest.main()
