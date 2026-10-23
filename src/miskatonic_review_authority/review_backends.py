"""Provider-neutral review backends and execution contracts for Miskatonic Review Authority."""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Protocol

import jsonschema

from .canonical_digest import ChangeRecord, changed_records
from .util import AuthorityError, canonical_json_bytes, sha256_bytes, sha256_file


PROMPT_VERSION = "miskatonic-local-review-prompt-v2.0"
SLICE_SCHEMA_VERSION = "miskatonic-local-review-slice-schema-v2.0"
VERDICT_SCHEMA_VERSION = "miskatonic-local-review-verdict-schema-v2.0"

_SLICE_REVIEW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "slice_id",
        "reviewed_paths",
        "slice_status",
        "findings",
        "uncertainty_level",
        "uncertainty_notes",
        "abstained",
        "abstention_reason",
        "summary",
    ],
    "properties": {
        "slice_id": {"type": "string"},
        "reviewed_paths": {"type": "array", "items": {"type": "string"}},
        "slice_status": {"type": "string", "enum": ["PASS", "CONCERN", "FAIL"]},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["severity", "title", "details", "path"],
                "properties": {
                    "severity": {"type": "string", "enum": ["P0", "P1", "P2", "P3", "INFO"]},
                    "title": {"type": "string"},
                    "details": {"type": "string"},
                    "path": {"type": "string"},
                },
            },
        },
        "uncertainty_level": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"]},
        "uncertainty_notes": {"type": "string"},
        "abstained": {"type": "boolean"},
        "abstention_reason": {"type": "string"},
        "summary": {"type": "string"},
    },
}

_FINAL_VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "verdict",
        "release_authorized",
        "summary",
        "findings",
        "confidence",
        "uncertainty",
        "abstention",
        "scientific_verification_assessment",
    ],
    "properties": {
        "verdict": {"type": "string", "enum": ["APPROVE", "REQUEST_CHANGES", "REJECT"]},
        "release_authorized": {"type": "boolean"},
        "summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["severity", "title", "details", "path"],
                "properties": {
                    "severity": {"type": "string", "enum": ["P0", "P1", "P2", "P3", "INFO"]},
                    "title": {"type": "string"},
                    "details": {"type": "string"},
                    "path": {"type": "string"},
                },
            },
        },
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "uncertainty": {
            "type": "object",
            "additionalProperties": False,
            "required": ["level", "explicit_uncertainties", "residual_risks"],
            "properties": {
                "level": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"]},
                "explicit_uncertainties": {"type": "array", "items": {"type": "string"}},
                "residual_risks": {"type": "array", "items": {"type": "string"}},
            },
        },
        "abstention": {
            "type": "object",
            "additionalProperties": False,
            "required": ["abstained", "reason"],
            "properties": {
                "abstained": {"type": "boolean"},
                "reason": {"type": "string"},
            },
        },
        "scientific_verification_assessment": {
            "type": "object",
            "additionalProperties": False,
            "required": ["prior_verification_accepted", "negative_findings_preserved", "notes"],
            "properties": {
                "prior_verification_accepted": {"type": "boolean"},
                "negative_findings_preserved": {"type": "boolean"},
                "notes": {"type": "string"},
            },
        },
    },
}

_FROZEN_PROMPT_TEMPLATE = (
    "You are an independent scientific code reviewer operating under Miskatonic Review Authority V2 policy. /no_think\n"
    "Examine the provided code diff slice or synthesis packet against deterministic scientific requirements, "
    "exact custody, and non-claims preservation. Never equate plausible responses with proof of completion. "
    "If uncertain or missing context, explicitly state uncertainty or set abstained=true. "
    "Return only the requested structured JSON object."
)

PROMPT_TEMPLATE_SHA256 = sha256_bytes(_FROZEN_PROMPT_TEMPLATE.encode("utf-8"))
SLICE_SCHEMA_SHA256 = sha256_bytes(canonical_json_bytes(_SLICE_REVIEW_SCHEMA))
VERDICT_SCHEMA_SHA256 = sha256_bytes(canonical_json_bytes(_FINAL_VERDICT_SCHEMA))


class ReviewBackend(Protocol):
    """Protocol for independent reviewer implementations."""

    def review(
        self,
        *,
        repository: str,
        pr_number: int,
        base_sha: str,
        head_sha: str,
        candidate_digest: str,
        review_packet: dict[str, Any],
        prior_evidence: dict[str, Any],
        producer_binding: dict[str, Any],
        reviewer_policy: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Executes review and returns (verdict_dict, backend_evidence_dict)."""
        ...


class LocalLlamaCppBackend:
    """Independent reviewer backend backed by local llama.cpp / Qwen runtime."""

    def __init__(self, endpoint_url: str = "http://127.0.0.1:11434/v1") -> None:
        self.endpoint_url = endpoint_url.rstrip("/")

    def _verify_loopback_endpoint(self) -> None:
        parsed = urllib.parse.urlparse(self.endpoint_url)
        hostname = (parsed.hostname or "").lower()
        if hostname not in ("127.0.0.1", "localhost", "::1"):
            raise AuthorityError(
                "MODEL_ENDPOINT_NOT_LOOPBACK_ISOLATED",
                f"Configured endpoint {self.endpoint_url} is not strictly bound to loopback",
            )

    def _verify_model_identity(self, model_policy: dict[str, Any]) -> None:
        self._verify_loopback_endpoint()
        model_path = Path(model_policy.get("model_path", ""))
        if not model_path.is_file():
            raise AuthorityError("MODEL_FILE_NOT_FOUND", str(model_path))

        expected_weights_sha = model_policy.get("model_weights_sha256")
        expected_size = model_policy.get("model_size_bytes")
        if expected_size is not None and model_path.stat().st_size != expected_size:
            raise AuthorityError(
                "MODEL_FILE_SIZE_MISMATCH",
                f"Model size {model_path.stat().st_size} != expected {expected_size}",
            )

        actual_weights_sha = sha256_file(model_path)
        if expected_weights_sha and actual_weights_sha != expected_weights_sha:
            raise AuthorityError(
                "FORGED_MODEL_IDENTITY",
                f"Model file sha256 {actual_weights_sha} != expected {expected_weights_sha}",
            )

        binary_path = Path(model_policy.get("runtime_binary_path", ""))
        if not binary_path.is_file():
            raise AuthorityError(
                "RUNTIME_BINARY_NOT_FOUND",
                f"Runtime binary not found at {binary_path}",
            )
        expected_bin_sha = model_policy.get("runtime_binary_sha256")
        if not expected_bin_sha:
            raise AuthorityError(
                "RUNTIME_BINARY_DIGEST_MISSING",
                "runtime_binary_sha256 not configured in reviewer policy",
            )
        actual_bin_sha = sha256_file(binary_path)
        if actual_bin_sha != expected_bin_sha:
            raise AuthorityError(
                "RUNTIME_BINARY_DIGEST_MISMATCH",
                f"Runtime binary sha256 {actual_bin_sha} != expected {expected_bin_sha}",
            )

        # Check live endpoint
        try:
            req = urllib.request.Request(
                f"{self.endpoint_url}/models",
                headers={"User-Agent": "miskatonic-review-authority/0.2"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            live_models = [m.get("id") for m in data.get("data", [])]
            exp_model_name = model_policy.get("model_name", "")
            if not any(exp_model_name in str(m) for m in live_models):
                raise AuthorityError(
                    "LOADED_MODEL_MISMATCH",
                    f"Live models {live_models} does not contain {exp_model_name}",
                )
        except urllib.error.URLError as e:
            raise AuthorityError("MODEL_ENDPOINT_UNAVAILABLE", str(e)) from e

    def _call_llama_json_schema(
        self,
        *,
        messages: list[dict[str, str]],
        schema_name: str,
        schema: dict[str, Any],
        timeout: int = 600,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        payload = {
            "messages": messages,
            "temperature": 0.0,
            "seed": 42,
            "chat_template_kwargs": {"enable_thinking": False},
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": schema_name,
                    "strict": True,
                    "schema": schema,
                },
            },
        }
        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.endpoint_url}/chat/completions",
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "miskatonic-review-authority/0.2",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[-4000:]
            raise AuthorityError(
                "LOCAL_REVIEW_REQUEST_FAILED", f"HTTP {error.code}: {detail}"
            ) from error
        except Exception as error:
            raise AuthorityError(
                "LOCAL_REVIEW_MODEL_NONRESPONSE", str(error)
            ) from error

        choices = resp_json.get("choices", [])
        if not choices:
            raise AuthorityError("LOCAL_REVIEW_OUTPUT_MISSING", "No choices returned by local model")

        choice = choices[0]
        finish_reason = choice.get("finish_reason")
        if finish_reason != "stop":
            raise AuthorityError(
                "LOCAL_REVIEW_CONTEXT_TRUNCATED",
                f"Model response finish_reason was '{finish_reason}', expected 'stop'",
            )

        content_raw = choice.get("message", {}).get("content", "")
        if not content_raw:
            raise AuthorityError("LOCAL_REVIEW_OUTPUT_MISSING", "Empty content from local model")

        try:
            parsed = json.loads(content_raw)
        except Exception as e:
            raise AuthorityError("LOCAL_REVIEW_SCHEMA_INVALID", f"Content is not JSON: {e}") from e

        try:
            jsonschema.validate(instance=parsed, schema=schema)
        except jsonschema.ValidationError as e:
            raise AuthorityError(
                "LOCAL_REVIEW_SCHEMA_INVALID",
                f"Model response failed schema validation: {e.message}",
            ) from e

        if "confidence" in parsed:
            conf = parsed["confidence"]
            if not isinstance(conf, (int, float)) or isinstance(conf, bool) or conf < 0.0 or conf > 1.0:
                raise AuthorityError(
                    "LOCAL_REVIEW_SCHEMA_INVALID",
                    f"Confidence value {conf} out of bounds [0.0, 1.0]",
                )

        if "release_authorized" in parsed and "verdict" in parsed:
            if bool(parsed["release_authorized"]) != (parsed["verdict"] == "APPROVE"):
                raise AuthorityError(
                    "CLOUD_REVIEW_RELEASE_INCONSISTENT",
                    f"release_authorized ({parsed['release_authorized']}) inconsistent with verdict ({parsed['verdict']})",
                )

        usage = resp_json.get("usage", {})
        call_metrics = {
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
            "finish_reason": finish_reason,
            "prompt_sha256": sha256_bytes(req_data),
            "response_sha256": sha256_bytes(content_raw.encode("utf-8")),
        }
        return parsed, call_metrics

    def review(
        self,
        *,
        repository: str,
        pr_number: int,
        base_sha: str,
        head_sha: str,
        candidate_digest: str,
        review_packet: dict[str, Any],
        prior_evidence: dict[str, Any],
        producer_binding: dict[str, Any],
        reviewer_policy: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        model_policy = reviewer_policy.get("model_identity", {})
        self._verify_model_identity(model_policy)

        # Verify prompt and schema matches policy if declared
        prompt_and_schema = reviewer_policy.get("prompt_and_schema", {})
        if prompt_and_schema:
            if prompt_and_schema.get("prompt_template_sha256") != PROMPT_TEMPLATE_SHA256:
                raise AuthorityError("REVIEW_PROMPT_OR_SCHEMA_MISMATCH", "Prompt template sha256 mismatch")
            if prompt_and_schema.get("slice_schema_sha256") != SLICE_SCHEMA_SHA256:
                raise AuthorityError("REVIEW_PROMPT_OR_SCHEMA_MISMATCH", "Slice schema sha256 mismatch")
            if prompt_and_schema.get("verdict_schema_sha256") != VERDICT_SCHEMA_SHA256:
                raise AuthorityError("REVIEW_PROMPT_OR_SCHEMA_MISMATCH", "Verdict schema sha256 mismatch")

        # Partition FULL_DIFF_REVIEWED paths into bounded slices
        changed_manifest = review_packet.get("changed_file_manifest", [])
        full_diff_files = [
            f for f in changed_manifest if f.get("classification") == "FULL_DIFF_REVIEWED"
        ]
        max_slice_chars = min(int(reviewer_policy.get("max_slice_characters", 12000)), 12000)

        # Slice diff string by individual files to guarantee bounded context
        source_diff = review_packet.get("source_diff") or review_packet.get("diff", "")
        # Split diff into chunks per file header
        diff_by_file: dict[str, str] = {}
        for entry in full_diff_files:
            path = entry["path"]
            marker = f"diff --git a/{path} b/{path}"
            idx = source_diff.find(marker)
            if idx == -1:
                raise AuthorityError(
                    "DIFF_COVERAGE_INCOMPLETE",
                    f"File '{path}' classified as FULL_DIFF_REVIEWED has no diff marker",
                )
            next_idx = source_diff.find("diff --git ", idx + len(marker))
            chunk = source_diff[idx:] if next_idx == -1 else source_diff[idx:next_idx]
            if not chunk.strip():
                raise AuthorityError(
                    "DIFF_COVERAGE_INCOMPLETE",
                    f"File '{path}' classified as FULL_DIFF_REVIEWED has empty diff section",
                )
            diff_by_file[path] = chunk

        # Break any file diffs exceeding max_slice_chars into atomic parts
        atomic_chunks: list[tuple[list[str], str]] = []
        for f in full_diff_files:
            p = f["path"]
            p_diff = diff_by_file.get(p, "")
            if len(p_diff) <= max_slice_chars:
                atomic_chunks.append(([p], p_diff))
            else:
                lines = p_diff.splitlines(keepends=True)
                cur_chunk = ""
                cur_part = 1
                for line in lines:
                    if len(cur_chunk) + len(line) > max_slice_chars and cur_chunk:
                        atomic_chunks.append(([f"{p} [part {cur_part}]"], cur_chunk))
                        cur_chunk = line
                        cur_part += 1
                    else:
                        cur_chunk += line
                if cur_chunk:
                    atomic_chunks.append(([f"{p} [part {cur_part}]"], cur_chunk))

        # Group atomic chunks into slices <= max_slice_chars
        current_slice_paths: list[str] = []
        current_slice_diff = ""
        slice_groups: list[tuple[list[str], str]] = []

        for paths, chunk in atomic_chunks:
            if len(current_slice_diff) + len(chunk) > max_slice_chars and current_slice_paths:
                slice_groups.append((list(current_slice_paths), current_slice_diff))
                current_slice_paths = list(paths)
                current_slice_diff = chunk
            else:
                current_slice_paths.extend(paths)
                current_slice_diff += chunk

        if current_slice_paths:
            slice_groups.append((list(current_slice_paths), current_slice_diff))

        if not slice_groups:
            # Even if 0 full diff files, create single empty slice
            slice_groups.append(([], ""))

        # Verify exact diff reconstruction
        reconstructed_diff = "".join(slice_text for _, slice_text in slice_groups)
        if reconstructed_diff != source_diff:
            raise AuthorityError(
                "DIFF_RECONSTRUCTION_MISMATCH",
                "Concatenated slice text does not equal original diff bytes",
            )
        reconstructed_sha = sha256_bytes(reconstructed_diff.encode("utf-8"))
        canonical_diff_sha = sha256_bytes(source_diff.encode("utf-8"))
        if reconstructed_sha != canonical_diff_sha:
            raise AuthorityError(
                "INVALID_DIFF_AGGREGATE_DIGEST",
                f"Reconstructed diff sha256 {reconstructed_sha} != canonical {canonical_diff_sha}",
            )

        # Execute review on each slice
        slice_records: list[dict[str, Any]] = []
        all_slice_findings: list[dict[str, Any]] = []
        max_tokens_seen = 0
        current_byte_offset = 0

        for slice_idx, (paths, slice_diff_text) in enumerate(slice_groups, 1):
            slice_id = f"slice_{slice_idx:04d}"
            diff_bytes = len(slice_diff_text.encode("utf-8"))
            slice_start_byte = current_byte_offset
            slice_end_byte = current_byte_offset + diff_bytes
            current_byte_offset = slice_end_byte

            slice_prompt = json.dumps(
                {
                    "task": "Review candidate slice code changes",
                    "slice_id": slice_id,
                    "repository": repository,
                    "pr_number": pr_number,
                    "base_sha": base_sha,
                    "head_sha": head_sha,
                    "candidate_digest": candidate_digest,
                    "paths_in_slice": paths,
                    "slice_diff": slice_diff_text,
                    "instructions": (
                        "Evaluate changes in this slice for correctness, integrity, and non-claims preservation. "
                        "FINDINGS GUIDELINES: Findings represent defects, issues, or risks. Do NOT classify passing tests or successful verifications as P0 or P1. "
                        "- P0: Catastrophic defect, security breach, unauthorized credential access, or corrupted custody. "
                        "- P1: Critical defect or scientific inconsistency requiring changes before approval. "
                        "- P2 / P3: Non-critical issue or minor defect. "
                        "- INFO: Neutral observation or confirmation of compliance. "
                        "If the code in this slice is correct, verified, and has no defects, findings should be empty or use INFO. "
                        "Do not abstain simply because this slice is part of a larger codebase; use uncertainty_level "
                        "for bounded context. Set abstained=true only if diff is corrupted or completely unreviewable."
                    ),
                },
                ensure_ascii=False,
            )
            messages = [
                {"role": "system", "content": _FROZEN_PROMPT_TEMPLATE},
                {"role": "user", "content": slice_prompt},
            ]
            slice_resp, metrics = self._call_llama_json_schema(
                messages=messages,
                schema_name="miskatonic_slice_review_v2",
                schema=_SLICE_REVIEW_SCHEMA,
            )

            for finding in slice_resp.get("findings", []):
                all_slice_findings.append(finding)

            max_tokens_seen = max(max_tokens_seen, metrics.get("total_tokens", 0))

            slice_records.append(
                {
                    "slice_id": slice_id,
                    "paths": paths,
                    "slice_start_byte": slice_start_byte,
                    "slice_end_byte": slice_end_byte,
                    "diff_bytes": diff_bytes,
                    "diff_sha256": sha256_bytes(slice_diff_text.encode("utf-8")),
                    "prompt_sha256": metrics["prompt_sha256"],
                    "response_sha256": metrics["response_sha256"],
                    "prompt_tokens": metrics["prompt_tokens"],
                    "completion_tokens": metrics["completion_tokens"],
                    "finish_reason": metrics["finish_reason"],
                    "slice_status": slice_resp.get("slice_status"),
                    "uncertainty_level": slice_resp.get("uncertainty_level"),
                    "abstained": slice_resp.get("abstained", False),
                    "findings_count": len(slice_resp.get("findings", [])),
                    "summary": slice_resp.get("summary", ""),
                }
            )

        # Final synthesis pass
        slice_summaries_for_prompt = [
            {
                "slice_id": s["slice_id"],
                "paths": s["paths"],
                "slice_status": s["slice_status"],
                "uncertainty_level": s["uncertainty_level"],
                "abstained": s["abstained"],
                "findings_count": s["findings_count"],
                "summary": s["summary"],
            }
            for s in slice_records
        ]
        # Deduplicate accumulated findings for prompt
        unique_findings: list[dict[str, Any]] = []
        seen_findings: set[tuple[str, str, str]] = set()
        for f in all_slice_findings:
            key = (str(f.get("path")), str(f.get("title")), str(f.get("severity")))
            if key not in seen_findings:
                seen_findings.add(key)
                unique_findings.append(f)

        synthesis_prompt = json.dumps(
            {
                "task": "Synthesize final independent review verdict",
                "repository": repository,
                "pr_number": pr_number,
                "base_sha": base_sha,
                "head_sha": head_sha,
                "candidate_digest": candidate_digest,
                "deterministic_prior_verification": prior_evidence.get(
                    "scientific_evidence_verifications", {}
                ),
                "total_changed_files": len(changed_manifest),
                "full_diff_files_count": len(full_diff_files),
                "slice_reviews": slice_summaries_for_prompt,
                "accumulated_findings": unique_findings[:40],
                "instructions": (
                    "Synthesize the final review verdict. If prior verification passed and slice reviews identified no "
                    "critical bugs (P0/P1), produce APPROVE with release_authorized=true and abstention.abstained=false. "
                    "IMPORTANT: confidence must be a float between 0.0 and 1.0 (e.g., 1.0 for high confidence; do NOT output 100). "
                    "IMPORTANT: If verdict is APPROVE, findings must NOT contain any P0 or P1 severity items (use P2, P3, or INFO for non-blocking observations). "
                    "If any critical issues (P0 or P1) exist or any slice reported FAIL, you MUST produce REQUEST_CHANGES with release_authorized=false."
                ),
            },
            ensure_ascii=False,
        )
        synth_messages = [
            {"role": "system", "content": _FROZEN_PROMPT_TEMPLATE},
            {"role": "user", "content": synthesis_prompt},
        ]
        synthesis_resp, synth_metrics = self._call_llama_json_schema(
            messages=synth_messages,
            schema_name="miskatonic_final_verdict_v2",
            schema=_FINAL_VERDICT_SCHEMA,
            timeout=600,
        )

        verdict = synthesis_resp.get("verdict")
        release_authorized = synthesis_resp.get("release_authorized", False)

        # Fail-closed rules enforcement
        if bool(release_authorized) != (verdict == "APPROVE"):
            raise AuthorityError(
                "CLOUD_REVIEW_RELEASE_INCONSISTENT",
                f"release_authorized ({release_authorized}) inconsistent with verdict ({verdict})",
            )

        # Abstention check
        any_slice_abstained = any(s["abstained"] for s in slice_records)
        synth_abstained = synthesis_resp.get("abstention", {}).get("abstained", False)
        if (any_slice_abstained or synth_abstained) and verdict == "APPROVE":
            raise AuthorityError(
                "LOCAL_REVIEW_ABSTENTION_BLOCKS_APPROVAL",
                "Model approval cannot proceed when any slice or synthesis was abstained",
            )

        # Fail slice check
        any_slice_fail = any(s["slice_status"] == "FAIL" for s in slice_records)
        slice_p0_p1 = [f for f in all_slice_findings if f.get("severity") in ("P0", "P1")]
        synth_p0_p1 = [f for f in synthesis_resp.get("findings", []) if f.get("severity") in ("P0", "P1")]
        if (any_slice_fail or slice_p0_p1 or synth_p0_p1) and verdict == "APPROVE":
            raise AuthorityError(
                "LOCAL_REVIEW_FINDINGS_CONTRADICT_APPROVAL",
                f"Model cannot approve candidate with FAIL slice ({any_slice_fail}), slice P0/P1 ({slice_p0_p1}), or synth P0/P1 ({synth_p0_p1})",
            )

        # High-severity finding conservation: synthesis may not omit slice P0/P1
        synth_findings = synthesis_resp.get("findings", [])
        for f in slice_p0_p1:
            matched = any(
                sf.get("path") == f.get("path") and sf.get("severity") == f.get("severity")
                for sf in synth_findings
            )
            if not matched:
                raise AuthorityError(
                    "HIGH_SEVERITY_FINDING_SUPPRESSED",
                    f"Synthesis suppressed slice P0/P1 finding: {f.get('title')} on path {f.get('path')}",
                )

        total_diff_bytes = len(source_diff.encode("utf-8"))
        reviewed_bytes_sum = sum(s["diff_bytes"] for s in slice_records)
        if reviewed_bytes_sum != total_diff_bytes:
            raise AuthorityError(
                "REVIEW_COVERAGE_BYTE_COUNT_MISMATCH",
                f"Sum of reviewed slice bytes ({reviewed_bytes_sum}) != total diff bytes ({total_diff_bytes})",
            )

        all_slice_base_paths = set()
        for s in slice_records:
            for p in s["paths"]:
                base_p = p.split(" [part ")[0]
                all_slice_base_paths.add(base_p)
        expected_full_paths = {f["path"] for f in full_diff_files}
        if not expected_full_paths.issubset(all_slice_base_paths):
            missing = expected_full_paths - all_slice_base_paths
            raise AuthorityError(
                "REVIEW_COVERAGE_INCOMPLETE",
                f"Files missing from review slices: {sorted(missing)}",
            )

        review_coverage_manifest = {
            "all_changed_files_accounted_for": True,
            "classification_counts": review_packet.get("classification_counts", {}),
            "full_diff_aggregate_sha256": canonical_diff_sha,
            "full_diff_bytes_reviewed": reviewed_bytes_sum,
            "full_diff_bytes_total": total_diff_bytes,
            "full_diff_files_reviewed": len(full_diff_files),
            "full_diff_files_total": len(full_diff_files),
            "max_slice_characters_budget": max_slice_chars,
            "max_slice_tokens_observed": max_tokens_seen,
            "slice_count": len(slice_records),
            "slices": slice_records,
            "synthesis_call": synth_metrics,
            "total_changed_files": len(changed_manifest),
        }

        backend_evidence = {
            "model_identity": {
                "backend": "LOCAL_LLAMA_CPP",
                "context_window_tokens": 16384,
                "endpoint_url": self.endpoint_url,
                "loopback_only_verified": True,
                "model_name": model_policy.get("model_name"),
                "model_path": model_policy.get("model_path"),
                "model_size_bytes": model_policy.get("model_size_bytes"),
                "model_weights_sha256": model_policy.get("model_weights_sha256"),
                "runtime_binary_path": model_policy.get("runtime_binary_path"),
                "runtime_binary_sha256": model_policy.get("runtime_binary_sha256"),
            },
            "prompt_and_schema": {
                "prompt_template_sha256": PROMPT_TEMPLATE_SHA256,
                "prompt_version": PROMPT_VERSION,
                "slice_schema_sha256": SLICE_SCHEMA_SHA256,
                "slice_schema_version": SLICE_SCHEMA_VERSION,
                "verdict_schema_sha256": VERDICT_SCHEMA_SHA256,
                "verdict_schema_version": VERDICT_SCHEMA_VERSION,
            },
            "review_coverage_manifest": review_coverage_manifest,
        }

        return synthesis_resp, backend_evidence


class OpenAIResponsesBackend:
    """Legacy OpenAI Responses review backend for V1 compatibility (inactive by default)."""

    def review(
        self,
        *,
        repository: str,
        pr_number: int,
        base_sha: str,
        head_sha: str,
        candidate_digest: str,
        review_packet: dict[str, Any],
        prior_evidence: dict[str, Any],
        producer_binding: dict[str, Any],
        reviewer_policy: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        lifecycle = reviewer_policy.get("lifecycle_state", "ACTIVE")
        if lifecycle == "INACTIVE":
            raise AuthorityError(
                "EXTERNAL_CLOUD_POLICY_INACTIVE",
                "OpenAI Responses review policy is INACTIVE under V2 authority recovery rules",
            )
        # Import and invoke legacy review runner logic if active
        from .review_runner import _call_openai

        api_key = reviewer_policy.get("api_key", "")
        model = reviewer_policy.get("model", "")
        prompt = json.dumps(
            {
                "task": "Review candidate for release authorization",
                "repository": repository,
                "pr_number": pr_number,
                "base_sha": base_sha,
                "head_sha": head_sha,
                "candidate_digest": candidate_digest,
                "producer": producer_binding,
                "prior_verification": prior_evidence,
                "review_packet": review_packet,
            },
            ensure_ascii=False,
        )
        review_data, provider_evidence = _call_openai(
            api_key=api_key, model=model, prompt=prompt
        )
        return review_data, {"provider_evidence": provider_evidence}


def get_review_backend(provider: str, **kwargs: Any) -> ReviewBackend:
    """Factory to retrieve reviewer backends."""
    if provider == "LOCAL_LLAMA_CPP":
        endpoint = kwargs.get("endpoint_url", "http://127.0.0.1:11434/v1")
        return LocalLlamaCppBackend(endpoint_url=endpoint)
    elif provider == "openai-responses":
        return OpenAIResponsesBackend()
    raise AuthorityError("REVIEW_PROVIDER_UNSUPPORTED", f"Unknown provider: {provider}")
