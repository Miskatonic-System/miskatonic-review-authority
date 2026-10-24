from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from miskatonic_review_authority.scientific_verifier import (
    _B2_R1_EXPECTED_TOTALS,
    _B2_R1_REQUIRED_FILES,
    verify_scientific_evidence,
)
from miskatonic_review_authority.util import AuthorityError

BASE = "d90892e3c2fdd66f2ffb13b17f7302b8689a9ced"
EVID = "artifacts/causalis-b2-exact-edge-reconciliation-00a-r1"
POLICY = {"verification_profile": "causalis_b2_r1", "evidence_base_path": EVID}


def _w(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(obj if isinstance(obj, str) else json.dumps(obj))


def _build(root: Path, *, verdict: str = "ACCEPT_WITH_LIMITATIONS") -> Path:
    hist = root / "artifacts/causalis-b2-resource-causality-00a/b2_scientific_claim_authority.json"
    _w(hist, {"x": 1})
    d = root / EVID
    counts = {"EVENT_LINEAGE_EDGE_PARITY_EXACT": 48, "OBSERVED_EDGE_DISAGREEMENT": 8}
    _w(
        d / "b2_r1_canonical_predecessor.json",
        {
            "canonical_base": BASE,
            "merge_parent_check": {
                "first_parent_is_predecessor_pr_base": True,
                "second_parent_is_predecessor_accepted_head": True,
            },
        },
    )
    _w(
        d / "b2_r1_historical_artifact_preservation.json",
        {
            "all_byte_identical": True,
            "file_count": 1,
            "files": [
                {
                    "path": str(hist.relative_to(root)),
                    "canonical_base_sha256": hashlib.sha256(hist.read_bytes()).hexdigest(),
                }
            ],
        },
    )
    _w(
        d / "b2_r1_aggregate_metric_reconciliation.json",
        {
            "all_expected_values_verified": True,
            "metrics": [{"metric": k, "recomputed": v} for k, v in _B2_R1_EXPECTED_TOTALS.items()],
            "causal_depth_distribution": [{"depth": str(i)} for i in range(6)],
        },
    )
    fixtures = {f"F{i}": {"disposition": "OBSERVED_EDGE_DISAGREEMENT"} for i in range(8)}
    for i in range(48):
        fixtures[f"X{i}"] = {
            "disposition": "EVENT_LINEAGE_EDGE_PARITY_EXACT",
            "correspondence": {"status": "COMPLETE"},
            "edge_relation": {"missing_in_wolfram": 0, "extra_in_wolfram": 0},
        }
    _w(
        d / "b2_r1_wolfram_edge_relation_audit.json",
        {"fixture_count": 56, "wolfram_primary_calls_made": 0, "disposition_counts": counts, "fixtures": fixtures},
    )
    _w(
        d / "b2_r1_negative_controls.json",
        {k: {"pass": True} for k in ("control_A_R014", "control_B_R004", "control_C_missing_result")},
    )
    _w(d / "b2_r1_scientific_claim_supersession.json", {"records": [{"id": "S1"}], "r1_fixture_dispositions": counts})
    _w(d / "independent_b2_r1_review.md", f"# Review\n\nVERDICT: {verdict}\n")
    for rf in _B2_R1_REQUIRED_FILES:
        if not (d / rf).exists():
            _w(d / rf, "{}" if rf.endswith(".json") else "# placeholder\n")
    return d


def test_r1_profile_accepts_valid_evidence(tmp_path):
    _build(tmp_path)
    summary, hashes = verify_scientific_evidence(str(tmp_path), POLICY, BASE, "f" * 40)
    assert summary["independent_review_verdict"] == "ACCEPT_WITH_LIMITATIONS"
    assert summary["max_causal_depth"] == 5
    assert set(hashes) == set(_B2_R1_REQUIRED_FILES)


def test_r1_profile_rejects_tampered_history(tmp_path):
    _build(tmp_path)
    (tmp_path / "artifacts/causalis-b2-resource-causality-00a/b2_scientific_claim_authority.json").write_text("{}")
    with pytest.raises(AuthorityError):
        verify_scientific_evidence(str(tmp_path), POLICY, BASE, "f" * 40)


def test_r1_profile_rejects_non_accepting_review(tmp_path):
    _build(tmp_path, verdict="REVISE")
    with pytest.raises(AuthorityError):
        verify_scientific_evidence(str(tmp_path), POLICY, BASE, "f" * 40)


def test_r1_profile_rejects_exact_without_basis(tmp_path):
    d = _build(tmp_path)
    p = d / "b2_r1_wolfram_edge_relation_audit.json"
    a = json.loads(p.read_text())
    a["fixtures"]["X0"]["edge_relation"]["extra_in_wolfram"] = 3
    p.write_text(json.dumps(a))
    with pytest.raises(AuthorityError):
        verify_scientific_evidence(str(tmp_path), POLICY, BASE, "f" * 40)


def test_r1_profile_rejects_wrong_base(tmp_path):
    _build(tmp_path)
    with pytest.raises(AuthorityError):
        verify_scientific_evidence(str(tmp_path), POLICY, "e" * 40, "f" * 40)
