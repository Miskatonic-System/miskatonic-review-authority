from pathlib import Path
import subprocess
import tempfile
import unittest

from miskatonic_review_authority.canonical_digest import candidate_digest


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


class CanonicalDigestTests(unittest.TestCase):
    def test_digest_is_stable_and_binds_modes_and_blobs(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory, "repo")
            repo.mkdir()
            _git(repo, "init")
            _git(repo, "config", "user.email", "test@example.com")
            _git(repo, "config", "user.name", "Test")
            (repo / "a.txt").write_text("one\n", encoding="utf-8")
            _git(repo, "add", "a.txt")
            _git(repo, "commit", "-m", "base")
            base = _git(repo, "rev-parse", "HEAD")
            (repo / "a.txt").write_text("two\n", encoding="utf-8")
            (repo / "b.txt").write_text("new\n", encoding="utf-8")
            _git(repo, "add", ".")
            _git(repo, "commit", "-m", "head")
            head = _git(repo, "rev-parse", "HEAD")
            first, record_one = candidate_digest("owner/repo", str(repo), base, head)
            second, record_two = candidate_digest("owner/repo", str(repo), base, head)
            self.assertEqual(first, second)
            self.assertEqual(record_one, record_two)
            self.assertEqual([item["path"] for item in record_one["records"]], ["a.txt", "b.txt"])


if __name__ == "__main__":
    unittest.main()
