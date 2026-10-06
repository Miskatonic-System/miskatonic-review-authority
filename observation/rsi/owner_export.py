"""Owner-local passive export. Invoke separately after a native action completes."""

import argparse
import json
import sys
from pathlib import Path

from . import projection as p

CONFIG = {
    "component": "review",
    "owner_repository": "Miskatonic-System/miskatonic-review-authority",
    "schemas": {
        "review-attestation-v1": {
            "candidate_repository": "repository",
            "candidate_sha": "head_sha",
            "disposition": "verdict",
            "occurred_at": "issued_at",
            "policy_version": "reviewer_policy_version",
            "review_principal": "reviewer_principal",
        }
    },
    "unavailable_metadata_fields": ["attestation_identity"],
}
IMPLEMENTATION_DIGEST = p.digest(
    Path(__file__).read_bytes() + b"\x00" + Path(p.__file__).read_bytes()
)


def attempt_export(native_bytes, owner_release="UNKNOWN"):
    return p.attempt(native_bytes, CONFIG, IMPLEMENTATION_DIGEST, owner_release)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_artifact", type=Path)
    parser.add_argument("--owner-release", default="UNKNOWN")
    args = parser.parse_args()
    try:
        result = attempt_export(args.native_artifact.read_bytes(), args.owner_release)
    except OSError:
        result = {
            "status": "OBSERVATION_EXPORT_FAILED",
            "reason": "NATIVE_ARTIFACT_UNAVAILABLE",
            "authority": "NONE",
        }
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result["status"] == "OBSERVATION_EXPORT_EMITTED" else 1


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
