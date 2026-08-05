from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import unittest

from miskatonic_review_authority.root import verify_root_record


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


class RootTests(unittest.TestCase):
    def test_root_binds_commit_and_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            repo = tmp / "prior"
            repo.mkdir()
            _git(repo, "init")
            _git(repo, "config", "user.email", "test@example.com")
            _git(repo, "config", "user.name", "Test")
            (repo / "src").mkdir()
            (repo / "src" / "x.py").write_text("x = 1\n", encoding="utf-8")
            file_hash = hashlib.sha256((repo / "src" / "x.py").read_bytes()).hexdigest()
            (repo / "manifest.json").write_text(json.dumps({"src/x.py": file_hash}) + "\n", encoding="utf-8")
            _git(repo, "add", ".")
            _git(repo, "commit", "-m", "root")
            commit = _git(repo, "rev-parse", "HEAD")
            manifest_hash = hashlib.sha256((repo / "manifest.json").read_bytes()).hexdigest()
            root = tmp / "root.json"
            root.write_text(json.dumps({
                "schema_version": "authority-root-v1",
                "repository": "owner/repo",
                "commit_sha": commit,
                "release_manifest_path": "manifest.json",
                "release_manifest_sha256": manifest_hash,
                "designation": "GENESIS_PRIOR_VERIFIER",
                "ratified_by": "trusted-starter:test",
                "authority_repository": "owner/authority"
            }), encoding="utf-8")
            evidence = verify_root_record(str(root), str(repo))
            self.assertEqual(evidence["commit_sha"], commit)
            self.assertEqual(evidence["verified_file_count"], 1)


if __name__ == "__main__":
    unittest.main()
