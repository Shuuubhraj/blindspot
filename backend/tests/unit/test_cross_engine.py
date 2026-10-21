"""Unit tests for engine cross-check: when two different engines report the
same file+line, confidence rises one level and the boost is recorded."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from blindspot.core.models import Base, Finding
from blindspot.pipeline.orchestrator import _bump_confidence, add_finding


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _finding_dict(engine_name, rule_id="BS-C01"):
    return {
        "engine": engine_name,
        "rule_id": rule_id,
        "title": "Test finding",
        "severity": "high",
        "confidence": "low",
        "validation_status": "static",
        "file_path": "src/Main.java",
        "line_start": 42,
        "line_end": 42,
        "snippet": "MessageDigest.getInstance(\"MD5\")",
        "description": "MD5 in use",
        "provenance": [],
    }


def test_bump_confidence_steps():
    assert _bump_confidence("low") == "medium"
    assert _bump_confidence("medium") == "high"
    assert _bump_confidence("high") == "high"
    assert _bump_confidence("bogus") == "medium"


def test_cross_engine_merge_boosts_confidence():
    s = _session()
    nxt_counter = {"n": 0}

    def nxt():
        nxt_counter["n"] += 1
        return f"t-{nxt_counter['n']:04d}"

    row1 = add_finding(s, "scan1", nxt, _finding_dict("custom"))
    assert row1.confidence == "low"
    s.flush()

    # Same engine, same location: merged, no boost.
    row2 = add_finding(s, "scan1", nxt, _finding_dict("custom", "BS-C02"))
    assert row2.id == row1.id
    assert row2.confidence == "low"

    # Different engine, same location: merged AND boosted.
    row3 = add_finding(s, "scan1", nxt, _finding_dict("mobsf", "mobsfscan-x"))
    assert row3.id == row1.id
    assert row3.confidence == "medium"
    assert "Corroborated by a second engine (mobsf)" in (row3.confidence_rationale or "")
    engines = {p.get("engine") for p in (row3.provenance or [])}
    assert {"custom", "mobsf"} <= engines

    # Third engine: boost again, capped at high.
    row4 = add_finding(s, "scan1", nxt, _finding_dict("ai", "ai:llm-review"))
    assert row4.confidence == "high"
    assert row4.validation_status == "ai-corroborated"


def test_different_location_no_merge():
    s = _session()
    nxt_counter = {"n": 0}

    def nxt():
        nxt_counter["n"] += 1
        return f"t-{nxt_counter['n']:04d}"

    f1 = _finding_dict("custom")
    f2 = _finding_dict("mobsf")
    f2["line_start"] = 99
    r1 = add_finding(s, "scan1", nxt, f1)
    r2 = add_finding(s, "scan1", nxt, f2)
    assert r1.id != r2.id
    assert r2.confidence == "low"  # no boost without a merge
