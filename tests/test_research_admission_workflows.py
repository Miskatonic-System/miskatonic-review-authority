"""Complete workflow parsing and the exact blocked-command regression.

BaseLoader preserves GitHub's YAML key `on` as a string rather than applying
YAML 1.1 boolean coercion. It constructs only plain strings/lists/mappings.
Actions expression/semantic validation also runs separately with actionlint.
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
REJECTED = "55ccdde031957e6fa68cdab97327f056a2ac50fa"
WORKFLOW = ".github/workflows/admit-research-evidence.yml"
WORKFLOWS = sorted((REPO / ".github/workflows").glob("*.y*ml"))


def frozen_bytes(path):
    return subprocess.check_output(["git", "show", f"{REJECTED}:{path}"], cwd=REPO)


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_complete_workflow_yaml_parses(path):
    document = yaml.load(path.read_bytes(), Loader=yaml.BaseLoader)
    assert isinstance(document, dict)
    assert "on" in document
    assert isinstance(document["jobs"], dict)
    assert document["jobs"]
    for job in document["jobs"].values():
        assert isinstance(job, dict)
        assert "steps" in job or "uses" in job


def test_rejected_workflow_remains_an_invalid_yaml_negative_control():
    with pytest.raises(yaml.YAMLError):
        yaml.load(frozen_bytes(WORKFLOW), Loader=yaml.BaseLoader)


def test_command_quoting_preserves_installation_and_admission_guards():
    document = yaml.load((REPO / WORKFLOW).read_bytes(), Loader=yaml.BaseLoader)
    previous_commands = re.findall(
        r"^\s*run: (python3 -m pip install .+)$",
        frozen_bytes(WORKFLOW).decode(),
        re.MULTILINE,
    )
    assert len(previous_commands) == 2
    assert set(document["on"]) == {"workflow_dispatch"}
    assert set(document["jobs"]) == {"prepare", "admit"}
    for name, previous in zip(("prepare", "admit"), previous_commands, strict=True):
        job = document["jobs"][name]
        assert job["if"] == (
            "github.repository == 'Miskatonic-System/miskatonic-review-authority' "
            "&& github.ref == 'refs/heads/main'"
        )
        assert len(job["steps"]) == 3
        assert job["steps"][1]["run"] == previous
        assert "--require-hashes" in previous
        assert "--only-binary=:all:" in previous
        assert (
            f"--phase {'plan' if name == 'prepare' else 'admit'}"
            in (job["steps"][2]["run"])
        )
    assert document["jobs"]["admit"]["needs"] == "prepare"
    assert document["jobs"]["admit"]["environment"] == "research-evidence-admission"


def test_yaml_dependency_is_test_only():
    previous = tomllib.loads(frozen_bytes("pyproject.toml").decode())
    current = tomllib.loads((REPO / "pyproject.toml").read_text())
    old_tests = previous["project"]["optional-dependencies"]["test"]
    new_tests = current["project"]["optional-dependencies"]["test"]
    assert new_tests == [*old_tests, "PyYAML==6.0.3"]
    current["project"]["optional-dependencies"]["test"] = old_tests
    assert current == previous
    requirements = "policy/research-admission/requirements-v1.txt"
    assert (REPO / requirements).read_bytes() == frozen_bytes(requirements)
