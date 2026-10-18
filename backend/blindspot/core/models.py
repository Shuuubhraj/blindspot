"""SQLAlchemy models for scans, findings, rule executions and AI reviews."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (JSON, DateTime, Float, ForeignKey, Integer, String,
                        Text, create_engine)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    file_name: Mapped[str] = mapped_column(String(512), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    file_size: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    # queued|running|completed|failed|cancelled
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    package_name: Mapped[str] = mapped_column(String(512), default="")
    app_name: Mapped[str] = mapped_column(String(512), default="")
    version_name: Mapped[str] = mapped_column(String(128), default="")
    version_code: Mapped[str] = mapped_column(String(128), default="")
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")

    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan")
    executions: Mapped[list["RuleExecution"]] = relationship(
        "RuleExecution", back_populates="scan", cascade="all, delete-orphan")
    stages: Mapped[list["StageRun"]] = relationship(
        "StageRun", back_populates="scan", cascade="all, delete-orphan")
    ai_reviews: Mapped[list["AIReview"]] = relationship(
        "AIReview", back_populates="scan", cascade="all, delete-orphan")
    events: Mapped[list["ScanEvent"]] = relationship(
        "ScanEvent", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), default="")
    title: Mapped[str] = mapped_column(String(512), default="")
    severity: Mapped[str] = mapped_column(String(16), default="informational")
    confidence: Mapped[str] = mapped_column(String(16), default="low")
    validation_status: Mapped[str] = mapped_column(String(32), default="static")
    # static|heuristic|ai-corroborated|ai-evidence-supported|ai-unverified
    category: Mapped[str] = mapped_column(String(32), default="")
    owasp: Mapped[list] = mapped_column(JSON, default=list)
    cwe: Mapped[list] = mapped_column(JSON, default=list)
    file_path: Mapped[str] = mapped_column(String(1024), default="")
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snippet: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    engine: Mapped[str] = mapped_column(String(16), default="custom")
    rule_version: Mapped[str] = mapped_column(String(16), default="")
    provenance: Mapped[list] = mapped_column(JSON, default=list)
    severity_rationale: Mapped[str] = mapped_column(Text, default="")
    confidence_rationale: Mapped[str] = mapped_column(Text, default="")
    review_status: Mapped[str] = mapped_column(String(32), default="open")
    # open|confirmed|rejected|accepted_risk|needs_review
    review_note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")


class RuleExecution(Base):
    __tablename__ = "rule_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), default="")
    engine: Mapped[str] = mapped_column(String(16), default="custom")
    status: Mapped[str] = mapped_column(String(16), default="not_run")
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str] = mapped_column(Text, default="")

    scan: Mapped["Scan"] = relationship("Scan", back_populates="executions")


class StageRun(Base):
    __tablename__ = "stage_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), index=True)
    name: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(16), default="pending")
    # pending|running|completed|failed|skipped|cancelled
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    note: Mapped[str] = mapped_column(Text, default="")

    scan: Mapped["Scan"] = relationship("Scan", back_populates="stages")


class AIReview(Base):
    __tablename__ = "ai_reviews"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), index=True)
    model: Mapped[str] = mapped_column(String(128), default="")
    prompt_version: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(32), default="skipped")
    # completed|skipped|failed
    files_reviewed: Mapped[int] = mapped_column(Integer, default=0)
    findings_proposed: Mapped[int] = mapped_column(Integer, default=0)
    findings_accepted: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="ai_reviews")


class ScanEvent(Base):
    """Timestamped per-scan log: what ran, what broke. Powers the Scan Log
    view and the JSON export's event_log section."""
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    level: Mapped[str] = mapped_column(String(16), default="info")
    # info|warn|error
    source: Mapped[str] = mapped_column(String(64), default="")
    # stage name, tool name, or "scan"
    message: Mapped[str] = mapped_column(Text, default="")

    scan: Mapped["Scan"] = relationship("Scan", back_populates="events")


def get_engine(database_url: str):
    return create_engine(database_url, future=True)


def init_db(engine) -> None:
    Base.metadata.create_all(engine)
