from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .attestation import public_key_fingerprint, verify_attestation
from .check_publisher import publish_check
from .prior_verifier import run_prior_verification
from .review_runner import run_review
from .util import AuthorityError, read_json
from .workflow_audit import require_pinned_workflows


def _prior_verify(args: argparse.Namespace) -> int:
    evidence = run_prior_verification(
        repository=args.repository,
        target_path=args.target_path,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        prior_control_path=args.prior_control_path,
        root_record_path=args.root_record,
        policy_path=args.policy,
        evidence_out=args.evidence_out,
    )
    print(json.dumps({"verdict": evidence["verdict"], "candidate_digest": evidence["candidate_digest"]}, sort_keys=True))
    return 0


def _publish_check(args: argparse.Namespace) -> int:
    token = os.environ.get(args.token_env, "")
    summary = args.summary
    if args.evidence and Path(args.evidence).is_file():
        evidence = read_json(args.evidence)
        summary = json.dumps(evidence, sort_keys=True, indent=2)[:65000]
    result = publish_check(
        token=token,
        repository=args.repository,
        head_sha=args.head_sha,
        name=args.name,
        conclusion=args.conclusion,
        title=args.title,
        summary=summary,
        details_url=args.details_url,
    )
    print(json.dumps({"check_run_id": result.get("id"), "app": result.get("app", {}).get("slug")}, sort_keys=True))
    return 0


def _review(args: argparse.Namespace) -> int:
    signed = run_review(
        repository=args.repository,
        pr_number=args.pr_number,
        head_branch=args.head_branch,
        repo_path=args.repo_path,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        prior_evidence_path=args.prior_evidence,
        producer_bindings_path=args.producer_bindings,
        reviewer_policy_path=args.reviewer_policy,
        private_key_path=args.private_key,
        key_id=args.key_id,
        diff_path=args.diff,
        output_path=args.output,
        api_key=os.environ.get(args.api_key_env, ""),
        model=os.environ.get(args.model_env, ""),
        authority_principal=args.authority_principal,
        workflow_run_id=args.workflow_run_id,
    )
    print(json.dumps({"verdict": signed["verdict"], "release_authorized": signed["release_authorized"]}, sort_keys=True))
    return 0


def _verify_attestation(args: argparse.Namespace) -> int:
    attestation = read_json(args.attestation)
    verify_attestation(attestation, args.public_key, expected_key_id=args.key_id)
    print(json.dumps({"signature": "valid", "verdict": attestation.get("verdict")}, sort_keys=True))
    return 0


def _key_fingerprint(args: argparse.Namespace) -> int:
    print(public_key_fingerprint(args.public_key))
    return 0


def _audit_actions(args: argparse.Namespace) -> int:
    require_pinned_workflows(args.root)
    print("All external actions and reusable workflows are pinned to full commit SHAs.")
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Miskatonic external review authority")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prior = subparsers.add_parser("prior-verify")
    prior.add_argument("--repository", required=True)
    prior.add_argument("--target-path", required=True)
    prior.add_argument("--base-sha", required=True)
    prior.add_argument("--head-sha", required=True)
    prior.add_argument("--prior-control-path", required=True)
    prior.add_argument("--root-record", required=True)
    prior.add_argument("--policy", required=True)
    prior.add_argument("--evidence-out", required=True)
    prior.set_defaults(func=_prior_verify)

    check = subparsers.add_parser("publish-check")
    check.add_argument("--token-env", default="GH_APP_TOKEN")
    check.add_argument("--repository", required=True)
    check.add_argument("--head-sha", required=True)
    check.add_argument("--name", required=True)
    check.add_argument("--conclusion", required=True)
    check.add_argument("--title", required=True)
    check.add_argument("--summary", default="")
    check.add_argument("--evidence")
    check.add_argument("--details-url")
    check.set_defaults(func=_publish_check)

    review = subparsers.add_parser("review")
    review.add_argument("--repository", required=True)
    review.add_argument("--pr-number", type=int, required=True)
    review.add_argument("--head-branch", required=True)
    review.add_argument("--repo-path", required=True)
    review.add_argument("--base-sha", required=True)
    review.add_argument("--head-sha", required=True)
    review.add_argument("--prior-evidence", required=True)
    review.add_argument("--producer-bindings", required=True)
    review.add_argument("--reviewer-policy", required=True)
    review.add_argument("--private-key", required=True)
    review.add_argument("--key-id", required=True)
    review.add_argument("--diff", required=True)
    review.add_argument("--output", required=True)
    review.add_argument("--api-key-env", default="MSK_CLOUD_REVIEW_API_KEY")
    review.add_argument("--model-env", default="MSK_CLOUD_REVIEW_MODEL")
    review.add_argument("--authority-principal", required=True)
    review.add_argument("--workflow-run-id", required=True)
    review.set_defaults(func=_review)

    verify = subparsers.add_parser("verify-attestation")
    verify.add_argument("--attestation", required=True)
    verify.add_argument("--public-key", required=True)
    verify.add_argument("--key-id", required=True)
    verify.set_defaults(func=_verify_attestation)

    fingerprint = subparsers.add_parser("key-fingerprint")
    fingerprint.add_argument("--public-key", required=True)
    fingerprint.set_defaults(func=_key_fingerprint)

    audit = subparsers.add_parser("audit-actions")
    audit.add_argument("--root", default=".")
    audit.set_defaults(func=_audit_actions)

    args = parser.parse_args(argv)
    try:
        result = args.func(args)
    except AuthorityError as error:
        print(json.dumps({"error": error.code, "detail": error.detail}, sort_keys=True), file=sys.stderr)
        raise SystemExit(1) from error
    raise SystemExit(result)


if __name__ == "__main__":
    main()
