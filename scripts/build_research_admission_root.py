"""Deterministic, offline assembly of a proposed authority root. No activation."""

import argparse
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


policy = root / "policy/research-admission/causalis-b2-r2-v1.json"
p = json.loads(policy.read_text())
paths = sorted(
    [
        *root.glob("src/miskatonic_review_authority/*.py"),
        *root.glob("schemas/*.json"),
        *root.glob(".github/workflows/*.yml"),
        *root.glob("policy/research-admission/requirements-*.txt"),
        root / "scripts/build_research_admission_root.py",
    ]
)
items = []
for path in paths:
    data = path.read_bytes()
    items.append(
        {
            "path": path.relative_to(root).as_posix(),
            "git_blob_sha": hashlib.sha1(
                f"blob {len(data)}\0".encode() + data
            ).hexdigest(),
            "sha256": sha(path),
        }
    )
value = {
    "schema_version": "research-admission-authority-root-v1",
    "designation": "PROPOSED_RESEARCH_ASSURANCE_SUCCESSOR",
    "authority_repository": "Miskatonic-System/miskatonic-review-authority",
    "predecessor_commit": "a87e863173950c7f73072d1647780b3492ab0a43",
    "predecessor_root": {
        "path": "roots/local-review-authority-v2.1.0.json",
        "sha256": sha(root / "roots/local-review-authority-v2.1.0.json"),
    },
    "preserved_local_review_policy": {
        "path": "policy/trusted-reviewers-v2.1.json",
        "sha256": sha(root / "policy/trusted-reviewers-v2.1.json"),
    },
    "routes": {
        "LOCAL_REVIEW_V2_1": "PRESERVED_UNCHANGED",
        "EXTERNAL_EVIDENCE_ADMISSION_V1": "REQUIRES_CANONICAL_MERGE_AND_EXPLICIT_RATIFICATION",
    },
    "ratifying_principal": p["authorization_principal"],
    "policy_path": policy.relative_to(root).as_posix(),
    "policy_sha256": sha(policy),
    "implementation_objects": items,
    "activation": "AUTHENTICATED_EXACT_HEAD_AUTHORITY_PR_RATIFICATION_AND_CANONICAL_MERGE",
    "revoked": False,
    "revocation_semantics": "Revoke this root/case by a separately governed canonical authority change; any canonical-head movement invalidates an in-flight old workflow. Expired/revoked authorization and conflicting/partially consumed reservations never silently retry.",
    "rollback_semantics": "Rollback disables only this scoped alternative; preserved Local Review V2.1 semantics remain unchanged. Historical receipts stay immutable and do not authorize future heads.",
}
output = root / "roots/research-admission-authority-v1.json"
expected = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
parser = argparse.ArgumentParser(
    description="Build the proposed root manifest offline; never ratify it."
)
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
if args.check:
    if output.read_bytes() != expected:
        raise SystemExit("PROPOSED root does not reproduce")
    print("PROPOSED root reproduces byte-identically; no ratification claimed")
else:
    output.write_bytes(expected)
    print("PROPOSED successor root generated; no ratification claimed")
