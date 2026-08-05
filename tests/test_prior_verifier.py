from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import unittest

from miskatonic_review_authority.prior_verifier import run_prior_verification


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def _write_manifest(repo: Path):
    entries = {}
    for directory in ["src", "schemas", "policies", "profiles"]:
        root = repo / directory
        if root.exists():
            for path in root.rglob("*"):
                if path.is_file():
                    relative = path.relative_to(repo).as_posix()
                    entries[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    entries["pyproject.toml"] = hashlib.sha256((repo / "pyproject.toml").read_bytes()).hexdigest()
    destination = repo / "provenance" / "release-manifest-v0.1.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(entries, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class PriorVerifierTests(unittest.TestCase):
    def test_previous_release_code_evaluates_candidate_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            prior = tmp / "prior"
            prior.mkdir()
            (prior / "src/miskatonic_control").mkdir(parents=True)
            (prior / "src/miskatonic_control/policy.py").write_text(
                "import re, fnmatch\n"
                "def matches_any_pattern(path, patterns): return any(fnmatch.fnmatchcase(path,p) for p in patterns)\n"
                "def verify_path_against_policies(path, manifest, role_policy, baseline_policy, profile):\n"
                "  if not any(re.search(p,path) for p in role_policy.get('allowed_modify_patterns',[])): return False,'role'\n"
                "  if not matches_any_pattern(path,manifest.get('allowed_paths',[])): return False,'manifest'\n"
                "  for p in baseline_policy.get('forbidden_modify_patterns',[]):\n"
                "    if re.search(p,path): return False,'baseline'\n"
                "  for p in role_policy.get('forbidden_modify_patterns',[]):\n"
                "    if re.search(p,path): return False,'role-forbidden'\n"
                "  if matches_any_pattern(path,manifest.get('forbidden_paths',[])): return False,'manifest-forbidden'\n"
                "  if matches_any_pattern(path,manifest.get('sealed_paths',[])): return False,'sealed'\n"
                "  return True,''\n",
                encoding="utf-8",
            )
            (prior / "src/miskatonic_control/git_patch.py").write_text(
                "def check_modes_and_gitlinks(repo_dir, commit_ref='HEAD', cached=False): return None\n",
                encoding="utf-8",
            )
            (prior / "manifest.json").write_text(json.dumps({
                "src/miskatonic_control/policy.py": hashlib.sha256((prior / "src/miskatonic_control/policy.py").read_bytes()).hexdigest(),
                "src/miskatonic_control/git_patch.py": hashlib.sha256((prior / "src/miskatonic_control/git_patch.py").read_bytes()).hexdigest(),
            }) + "\n", encoding="utf-8")
            _git(prior, "init")
            _git(prior, "config", "user.email", "test@example.com")
            _git(prior, "config", "user.name", "Test")
            _git(prior, "add", ".")
            _git(prior, "commit", "-m", "prior")
            prior_commit = _git(prior, "rev-parse", "HEAD")

            target = tmp / "target"
            target.mkdir()
            for directory in ["src", "schemas", "policies", "profiles"]:
                (target / directory).mkdir()
            (target / "src/x.py").write_text("x=1\n", encoding="utf-8")
            (target / "schemas/s.json").write_text("{}\n", encoding="utf-8")
            (target / "policies/p.json").write_text("{}\n", encoding="utf-8")
            (target / "profiles/r.json").write_text("{}\n", encoding="utf-8")
            (target / "pyproject.toml").write_text("[project]\nname='x'\nversion='0'\n", encoding="utf-8")
            _write_manifest(target)
            _git(target, "init")
            _git(target, "config", "user.email", "test@example.com")
            _git(target, "config", "user.name", "Test")
            _git(target, "add", ".")
            _git(target, "commit", "-m", "base")
            base = _git(target, "rev-parse", "HEAD")
            (target / "src/x.py").write_text("x=2\n", encoding="utf-8")
            _write_manifest(target)
            _git(target, "add", ".")
            _git(target, "commit", "-m", "head")
            head = _git(target, "rev-parse", "HEAD")

            root_record = tmp / "root.json"
            root_record.write_text(json.dumps({
                "schema_version":"authority-root-v1",
                "repository":"owner/control",
                "commit_sha":prior_commit,
                "release_manifest_path":"manifest.json",
                "release_manifest_sha256":hashlib.sha256((prior / "manifest.json").read_bytes()).hexdigest(),
                "designation":"GENESIS_PRIOR_VERIFIER",
                "ratified_by":"trusted-starter:test",
                "authority_repository":"owner/authority"
            }), encoding="utf-8")
            policy = tmp / "policy.json"
            policy.write_text(json.dumps({
                "schema_version":"prior-verification-policy-v1",
                "policy_version":"1",
                "repository":"owner/control",
                "allowed_paths":["src/**","provenance/release-manifest-v0.1.json"],
                "allowed_modify_patterns":["^(src/.*|provenance/release-manifest-v0\\.1\\.json)$"],
                "forbidden_paths":[],"sealed_paths":[],"forbidden_modify_patterns":[],
                "baseline_forbidden_modify_patterns":[],"project_specific_control_files":[],"sealed_namespaces":[],
                "required_unchanged_patterns":[],"candidate_release_manifest":"provenance/release-manifest-v0.1.json",
                "manifest_excluded_path_fragments":["__pycache__",".egg-info/"],
                "manifest_include_dirs":["src","schemas","policies","profiles"],
                "manifest_include_files":["pyproject.toml"],
                "required_manifest_entries":["src/x.py"]
            }), encoding="utf-8")
            evidence_path = tmp / "evidence.json"
            evidence = run_prior_verification(
                repository="owner/control", target_path=str(target), base_sha=base, head_sha=head,
                prior_control_path=str(prior), root_record_path=str(root_record), policy_path=str(policy),
                evidence_out=str(evidence_path)
            )
            self.assertEqual(evidence["verdict"], "PASS")
            self.assertTrue(evidence_path.is_file())


if __name__ == "__main__":
    unittest.main()
