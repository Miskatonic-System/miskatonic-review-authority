from __future__ import annotations

import re
from pathlib import Path

from .util import AuthorityError


USES_PATTERN = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
FULL_SHA_REFERENCE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml)?@[0-9a-f]{40}$")


def audit_workflows(root: str) -> list[str]:
    violations: list[str] = []
    workflow_root = Path(root, ".github", "workflows")
    if not workflow_root.exists():
        return violations
    for path in sorted(workflow_root.glob("*.y*ml")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = USES_PATTERN.match(line)
            if not match:
                continue
            reference = match.group(1).strip('"\'')
            if reference.startswith("./"):
                continue
            if not FULL_SHA_REFERENCE.fullmatch(reference):
                violations.append(f"{path.relative_to(root)}:{line_number}:{reference}")
    return violations


def require_pinned_workflows(root: str) -> None:
    violations = audit_workflows(root)
    if violations:
        raise AuthorityError("UNPINNED_ACTION_REFERENCE", ";".join(violations))
