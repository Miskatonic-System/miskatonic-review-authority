from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .attestation import public_key_fingerprint, verify_attestation
from .check_publisher import publish_check
from .github_api import verify_pr_head
from .github_app import create_installation_token
from .local_review import run_local_independent_review, verify_and_admit_local_review_receipt
from .prior_verifier import run_prior_verification
from .review_runner import run_review
from .util import AuthorityError, read_json
from .workflow_audit import require_pinned_workflows


def _local_review(args: argparse.Namespace) -> int:
    if args.allow_current_user:
        raise AuthorityError(
            "SERVICE_IDENTITY_BYPASS_PROHIBITED",
            "--allow-current-user is not permitted for production review",
        )
    signed_receipt, sig_path = run_local_independent_review(
        repository=args.repository,
        pr_number=args.pr_number,
        head_branch=args.head_branch,
        repo_path=args.repo_path,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        prior_evidence_path=args.prior_evidence,
        review_packet_path=args.review_packet,
        producer_bindings_path=args.producer_bindings,
        reviewer_policy_path=args.reviewer_policy,
        private_key_path=args.private_key,
        key_id=args.key_id,
        output_path=args.output,
        target_policy_path=args.target_policy,
        enforce_strict_isolation=True,
    )
    print(
        json.dumps(
            {
                "receipt_id": signed_receipt["receipt_id"],
                "release_authorized": signed_receipt["release_authorized"],
                "signature_file": sig_path,
                "status": "LOCAL_REVIEW_COMPLETED",
                "verdict": signed_receipt["verdict"],
            },
            sort_keys=True,
        )
    )
    return 0


def _admit_local_review(args: argparse.Namespace) -> int:
    if args.publish_check:
        token = os.environ.get(args.token_env, "")
        if not token:
            raise AuthorityError("GH_APP_TOKEN_MISSING", "publish_check requires GH_APP_TOKEN")
        check_name = args.check_name or "miskatonic/independent-local-review"
        if check_name == "miskatonic/independent-cloud-review" or "cloud" in check_name.lower():
            raise AuthorityError(
                "LOCAL_REVIEW_IMPERSONATING_CLOUD_REVIEW",
                "Local review cannot publish cloud review check",
            )
        if check_name not in ("miskatonic/independent-local-review", "miskatonic/independent-review"):
            raise AuthorityError(
                "ARBITRARY_CHECK_NAME_PROHIBITED",
                f"Check name '{check_name}' is not an authorized local review check name",
            )
        if args.also_publish_cloud_review:
            raise AuthorityError(
                "LOCAL_REVIEW_IMPERSONATING_CLOUD_REVIEW",
                "also_publish_cloud_review is prohibited for local reviews",
            )

    sig_path = args.detached_sig
    if not sig_path:
        cand_sig = Path(args.receipt).with_suffix(".sig")
        if cand_sig.is_file():
            sig_path = str(cand_sig)

    admission = verify_and_admit_local_review_receipt(
        receipt_path=args.receipt,
        detached_sig_path=sig_path,
        repository=args.repository,
        expected_pr_number=args.pr_number,
        expected_head_sha=args.expected_head_sha,
        expected_base_sha=args.expected_base_sha,
        target_repo_path=args.target_repo_path,
        target_policy_path=args.target_policy,
        trusted_reviewers_policy_path=args.trusted_reviewers_policy,
        trusted_signers_policy_path=args.trusted_signers_policy,
        trusted_producers_policy_path=args.trusted_producers_policy,
        github_app_private_key_path=args.github_app_private_key,
        output_attestation_path=args.output_attestation,
    )

    if args.publish_check:
        check_name = args.check_name or "miskatonic/independent-local-review"
        receipt_data = read_json(args.receipt)
        summary = json.dumps(receipt_data, sort_keys=True, indent=2)[:65000]
        publish_check(
            token=token,
            repository=args.repository,
            head_sha=args.expected_head_sha,
            name=check_name,
            conclusion="success",
            title=f"Local Review: {admission['status']}",
            summary=summary,
            details_url=args.details_url,
        )

    print(json.dumps(admission, sort_keys=True))
    return 0


def _ratify_v2_policy(args: argparse.Namespace) -> int:
    rat_path = Path(args.ratification_record)
    if not rat_path.is_file():
        raise AuthorityError("RATIFICATION_RECORD_MISSING", str(rat_path))
    data = read_json(str(rat_path))
    if data.get("schema_version") != "local-review-ratification-v2":
        raise AuthorityError("RATIFICATION_SCHEMA_UNSUPPORTED")
    if data.get("designation") != "LOCAL_REVIEW_V2_AUTHORITY_RATIFICATION":
        raise AuthorityError("RATIFICATION_DESIGNATION_INVALID")
    print(
        json.dumps(
            {
                "designation": data["designation"],
                "ratification_id": data["ratification_id"],
                "ratified_at": data["ratified_at"],
                "ratified_by": data["ratified_by"],
                "status": "LOCAL_REVIEW_AUTHORITY_ACTIVE",
            },
            sort_keys=True,
        )
    )
    return 0


def _create_app_token(args: argparse.Namespace) -> int:
    app_id = os.environ.get(args.app_id_env, "")
    result = create_installation_token(
        app_id=app_id,
        private_key_path=args.private_key,
        owner=args.owner,
        repositories=args.repository,
        permissions={
            "actions": "read",
            "checks": "write",
            "contents": "read",
            "pull_requests": "read",
        },
    )
    token = result["token"]
    print(f"::add-mask::{token}")
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        raise AuthorityError("GITHUB_OUTPUT_MISSING")
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write(f"token={token}\n")
        handle.write(f"installation_id={result['installation_id']}\n")
        handle.write(f"expires_at={result['expires_at']}\n")
    print(
        json.dumps(
            {
                "expires_at": result["expires_at"],
                "installation_id": result["installation_id"],
            },
            sort_keys=True,
        )
    )
    return 0


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
        review_packet_out=args.review_packet_out,
        packet_manifest_out=args.packet_manifest_out,
        max_packet_characters=args.max_packet_characters,
    )
    print(
        json.dumps(
            {
                "candidate_digest": evidence["candidate_digest"],
                "verdict": evidence["verdict"],
            },
            sort_keys=True,
        )
    )
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
    print(
        json.dumps(
            {
                "app": result.get("app", {}).get("slug"),
                "check_run_id": result.get("id"),
            },
            sort_keys=True,
        )
    )
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
        review_packet_path=args.review_packet,
        output_path=args.output,
        api_key=os.environ.get(args.api_key_env, ""),
        model=os.environ.get(args.model_env, ""),
        authority_principal=args.authority_principal,
        workflow_run_id=args.workflow_run_id,
    )
    print(
        json.dumps(
            {
                "release_authorized": signed["release_authorized"],
                "verdict": signed["verdict"],
            },
            sort_keys=True,
        )
    )
    return 0


def _verify_attestation(args: argparse.Namespace) -> int:
    attestation = read_json(args.attestation)
    verify_attestation(attestation, args.public_key, expected_key_id=args.key_id)
    print(
        json.dumps(
            {"signature": "valid", "verdict": attestation.get("verdict")},
            sort_keys=True,
        )
    )
    return 0


def _key_fingerprint(args: argparse.Namespace) -> int:
    print(public_key_fingerprint(args.public_key))
    return 0


def _audit_actions(args: argparse.Namespace) -> int:
    require_pinned_workflows(args.root)
    print("All external actions and reusable workflows are pinned to full commit SHAs.")
    return 0


def _verify_pr_head_cmd(args: argparse.Namespace) -> int:
    token = os.environ.get(args.token_env, "")
    actual_head = verify_pr_head(
        token=token,
        repository=args.repository,
        pr_number=args.pr_number,
        expected_head_sha=args.expected_head_sha,
    )
    print(
        json.dumps(
            {
                "head_sha": actual_head,
                "pr_number": args.pr_number,
                "status": "verified",
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Miskatonic external review authority")
    subparsers = parser.add_subparsers(dest="command", required=True)

    app_token = subparsers.add_parser("create-app-token")
    app_token.add_argument("--app-id-env", default="MSK_REVIEW_APP_ID")
    app_token.add_argument("--private-key", required=True)
    app_token.add_argument("--owner", required=True)
    app_token.add_argument("--repository", action="append", required=True)
    app_token.set_defaults(func=_create_app_token)

    prior = subparsers.add_parser("prior-verify")
    prior.add_argument("--repository", required=True)
    prior.add_argument("--target-path", required=True)
    prior.add_argument("--base-sha", required=True)
    prior.add_argument("--head-sha", required=True)
    prior.add_argument("--prior-control-path", default=None)
    prior.add_argument("--root-record", default=None)
    prior.add_argument("--policy", required=True)
    prior.add_argument("--evidence-out", required=True)
    prior.add_argument("--review-packet-out", default=None)
    prior.add_argument("--packet-manifest-out", default=None)
    prior.add_argument("--max-packet-characters", type=int, default=500000)
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
    review.add_argument("--diff", default=None)
    review.add_argument("--review-packet", default=None)
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

    stale_head = subparsers.add_parser("verify-pr-head")
    stale_head.add_argument("--token-env", default="GH_APP_TOKEN")
    stale_head.add_argument("--repository", required=True)
    stale_head.add_argument("--pr-number", type=int, required=True)
    stale_head.add_argument("--expected-head-sha", required=True)
    stale_head.set_defaults(func=_verify_pr_head_cmd)

    local_rev = subparsers.add_parser("local-review")
    local_rev.add_argument("--repository", required=True)
    local_rev.add_argument("--pr-number", type=int, required=True)
    local_rev.add_argument("--head-branch", required=True)
    local_rev.add_argument("--repo-path", required=True)
    local_rev.add_argument("--base-sha", required=True)
    local_rev.add_argument("--head-sha", required=True)
    local_rev.add_argument("--prior-evidence", required=True)
    local_rev.add_argument("--review-packet", required=True)
    local_rev.add_argument("--target-policy", required=True)
    local_rev.add_argument("--producer-bindings", default="policy/trusted-producers.json")
    local_rev.add_argument("--reviewer-policy", default="policy/trusted-reviewers-v2.json")
    local_rev.add_argument("--private-key", required=True)
    local_rev.add_argument("--key-id", required=True)
    local_rev.add_argument("--output", required=True)
    local_rev.add_argument("--allow-current-user", action="store_true", default=False)
    local_rev.set_defaults(func=_local_review)

    admit_rev = subparsers.add_parser("admit-local-review")
    admit_rev.add_argument("--receipt", required=True)
    admit_rev.add_argument("--detached-sig", default=None)
    admit_rev.add_argument("--repository", required=True)
    admit_rev.add_argument("--pr-number", type=int, required=True)
    admit_rev.add_argument("--expected-head-sha", required=True)
    admit_rev.add_argument("--expected-base-sha", required=True)
    admit_rev.add_argument("--target-repo-path", required=True)
    admit_rev.add_argument("--target-policy", required=True)
    admit_rev.add_argument("--trusted-reviewers-policy", default="policy/trusted-reviewers-v2.json")
    admit_rev.add_argument("--trusted-signers-policy", default="policy/trusted-signers.json")
    admit_rev.add_argument("--trusted-producers-policy", default="policy/trusted-producers.json")
    admit_rev.add_argument("--github-app-private-key", default=None)
    admit_rev.add_argument("--output-attestation", default=None)
    admit_rev.add_argument("--publish-check", action="store_true", default=False)
    admit_rev.add_argument("--also-publish-cloud-review", action="store_true", default=False)
    admit_rev.add_argument("--check-name", default="miskatonic/independent-local-review")
    admit_rev.add_argument("--token-env", default="GH_APP_TOKEN")
    admit_rev.add_argument("--details-url", default=None)
    admit_rev.set_defaults(func=_admit_local_review)

    ratify = subparsers.add_parser("ratify-v2-policy")
    ratify.add_argument("--ratification-record", default="roots/local-review-authority-v2.0.0.json")
    ratify.set_defaults(func=_ratify_v2_policy)

    args = parser.parse_args(argv)
    try:
        result = args.func(args)
    except AuthorityError as error:
        print(
            json.dumps({"detail": error.detail, "error": error.code}, sort_keys=True),
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    raise SystemExit(result)


if __name__ == "__main__":
    main()
