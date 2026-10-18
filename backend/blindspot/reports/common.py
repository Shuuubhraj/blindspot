"""Shared report data assembly: one DB read producing everything the
HTML/PDF/JSON exporters need."""

from __future__ import annotations

from ..core.db import session_scope
from ..core.models import AIReview as AIReviewRow
from ..core.models import Finding as FindingRow
from ..core.models import RuleExecution as ExecRow
from ..core.models import Scan as ScanRow
from ..core.models import ScanEvent as ScanEventRow
from ..core.models import StageRun as StageRow
from ..rules.registry import get_registry

_SEV_ORDER = ["critical", "high", "medium", "low", "informational"]
_OWASP_2024 = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}


def _human_size(n: int | None) -> str:
    if not n:
        return "-"
    n = int(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n} B"


def finding_to_dict(f: FindingRow) -> dict:
    return {
        "finding_id": f.id, "title": f.title, "severity": f.severity,
        "confidence": f.confidence, "validation_status": f.validation_status,
        "rule_id": f.rule_id, "category": f.category,
        "owasp": f.owasp or [], "cwe": f.cwe or [],
        "file_path": f.file_path, "line_start": f.line_start,
        "line_end": f.line_end, "snippet": f.snippet,
        "description": f.description, "impact": f.impact,
        "remediation": f.remediation, "engine": f.engine,
        "rule_version": f.rule_version, "provenance": f.provenance or [],
        "severity_rationale": f.severity_rationale,
        "confidence_rationale": f.confidence_rationale,
        "review_status": f.review_status, "review_note": f.review_note,
    }


def build_report_data(scan_id: str) -> dict | None:
    with session_scope() as s:
        scan = s.get(ScanRow, scan_id)
        if not scan:
            return None
        findings = (s.query(FindingRow).filter_by(scan_id=scan_id).all())
        stages = (s.query(StageRow).filter_by(scan_id=scan_id)
                  .order_by(StageRow.id).all())
        execs = s.query(ExecRow).filter_by(scan_id=scan_id).all()
        ai_rows = (s.query(AIReviewRow).filter_by(scan_id=scan_id)
                   .order_by(AIReviewRow.id.desc()).all())
        events = (s.query(ScanEventRow).filter_by(scan_id=scan_id)
                  .order_by(ScanEventRow.id).all())
        cfg = dict(scan.config_json or {})
        sdk = cfg.get("_sdk", {}) or {}

        findings.sort(key=lambda f: (_SEV_ORDER.index(f.severity)
                                     if f.severity in _SEV_ORDER else 9,
                                     f.rule_id))
        counts = {sev: 0 for sev in _SEV_ORDER}
        owasp_counts: dict[str, int] = {}
        for f in findings:
            if f.severity in counts:
                counts[f.severity] += 1
            for o in f.owasp or []:
                owasp_counts[o] = owasp_counts.get(o, 0) + 1

        exec_by_status: dict[str, int] = {}
        for e in execs:
            exec_by_status[e.status] = exec_by_status.get(e.status, 0) + 1

        try:
            registry = get_registry()
            rule_versions = {rid: r.version for rid, r in registry.items()}
        except Exception:
            rule_versions = {}

        findings = [finding_to_dict(f) for f in findings]
        ai_findings = [f for f in findings
                       if f["engine"] == "ai"
                       or str(f["validation_status"]).startswith("ai-")
                       or any(str(p.get("engine")) == "ai"
                              for p in f["provenance"])]

        return {
            "scan_id": scan.id,
            "file_name": scan.file_name,
            "sha256": scan.sha256,
            "file_size": scan.file_size,
            "file_size_human": _human_size(scan.file_size),
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else "",
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else "",
            "package_name": scan.package_name,
            "app_name": scan.app_name,
            "version_name": scan.version_name,
            "version_code": scan.version_code,
            "min_sdk": sdk.get("min"),
            "target_sdk": sdk.get("target"),
            "counts": counts,
            "total_findings": len(findings),
            "owasp_counts": owasp_counts,
            "owasp_names": _OWASP_2024,
            "findings": findings,
            "ai_findings": ai_findings,
            "stages": [{
                "name": st.name, "status": st.status,
                "duration_ms": round(st.duration_ms, 1), "note": st.note,
            } for st in stages],
            "executions": exec_by_status,
            "rules_total": len(execs),
            "rule_versions": rule_versions,
            "limitations": cfg.get("_notes", []),
            "errors": cfg.get("_errors", []),
            "ai": cfg.get("_ai", {}),
            "ai_rows": [{
                "model": a.model, "status": a.status,
                "files_reviewed": a.files_reviewed,
                "findings_proposed": a.findings_proposed,
                "findings_accepted": a.findings_accepted,
                "error": a.error,
            } for a in ai_rows],
            "event_log": [{
                "ts": e.ts.isoformat() if e.ts else "",
                "level": e.level, "source": e.source, "message": e.message,
            } for e in events],
            "scan_error": scan.error,
        }
