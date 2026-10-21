"""Scan orchestration: staged pipeline with live progress and cancellation.

Stages:
  validate -> extract -> metadata -> decompile -> mobsfscan ->
  custom_rules -> ai_review -> normalize -> finalize

A failing stage preserves earlier results and records what coverage is
missing. Cancellation is cooperative: checked between stages, between
rules, and inside tool subprocesses.
"""

from __future__ import annotations

import queue
import threading
import time
import traceback
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..ai.ollama import OllamaClient
from ..ai.review import AIReviewer
from ..analysis.apk import collect_apk_info, validate_apk
from ..analysis.decompile import try_apktool, try_jadx
from ..analysis.manifest import load_manifest, refine_app_name_from_decoded_manifest
from ..analysis.tools import detect_tools, run_mobsfscan
from ..config import settings
from ..core.db import session_scope
from ..core.models import AIReview as AIReviewRow
from ..core.models import Finding as FindingRow
from ..core.models import RuleExecution as ExecRow
from ..core.models import Scan as ScanRow
from ..core.models import ScanEvent as ScanEventRow
from ..core.models import StageRun as StageRow
from ..core.workspace import cleanup_workspace, make_workspace, safe_extract_zip
from ..rules.base import (Engine, RuleResult, RuleStatus, ScanContext,
                          Severity)
from ..rules.registry import enabled_rules, get_registry

STAGES = ["validate", "extract", "metadata", "decompile", "mobsfscan",
          "custom_rules", "ai_review", "normalize", "finalize"]

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _utcnow():
    return datetime.now(timezone.utc)


class ScanJob:
    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self.cancel = threading.Event()
        self.listeners: list[queue.Queue] = []
        self.lock = threading.Lock()
        self.progress: dict[str, Any] = {
            "stage": "queued", "percent": 0.0, "checks_run": 0,
            "findings_so_far": 0, "elapsed_s": 0.0,
        }
        self.started_at = time.time()
        self.thread: threading.Thread | None = None


_jobs: dict[str, ScanJob] = {}
_jobs_lock = threading.Lock()


def get_job(scan_id: str) -> ScanJob | None:
    with _jobs_lock:
        return _jobs.get(scan_id)


def subscribe(scan_id: str) -> "queue.Queue[dict]":
    job = get_job(scan_id)
    q: queue.Queue[dict] = queue.Queue()
    if job:
        with job.lock:
            job.listeners.append(q)
    return q


def unsubscribe(scan_id: str, q: "queue.Queue[dict]") -> None:
    job = get_job(scan_id)
    if job:
        with job.lock:
            if q in job.listeners:
                job.listeners.remove(q)


def emit(scan_id: str, event: str, data: dict) -> None:
    job = get_job(scan_id)
    if not job:
        return
    with job.lock:
        for q in job.listeners:
            try:
                q.put_nowait({"event": event, "data": data})
            except queue.Full:
                pass


def cancel_scan(scan_id: str) -> bool:
    job = get_job(scan_id)
    if job and not job.cancel.is_set():
        job.cancel.set()
        emit(scan_id, "progress", {"stage": "cancelling"})
        return True
    return False


def start_scan(scan_id: str, apk_path: Path, file_name: str, config: dict) -> ScanJob:
    job = ScanJob(scan_id)
    with _jobs_lock:
        _jobs[scan_id] = job
    t = threading.Thread(target=_run_scan,
                         args=(scan_id, apk_path, file_name, config),
                         daemon=True, name=f"scan-{scan_id[:8]}")
    job.thread = t
    t.start()
    return job


# ---------------------------------------------------------------------------
# internal helpers
# ---------------------------------------------------------------------------

def _update_progress(job: ScanJob, **fields: Any) -> None:
    with job.lock:
        job.progress.update(fields)
        job.progress["elapsed_s"] = round(time.time() - job.started_at, 1)
        snapshot = dict(job.progress)
    emit(job.scan_id, "progress", snapshot)


def log_event(scan_id: str, level: str, source: str, message: str) -> None:
    """Append a timestamped entry to the per-scan troubleshooting log.

    Best-effort: logging must never break a scan.
    """
    try:
        with session_scope() as s:
            s.add(ScanEventRow(scan_id=scan_id, level=level, source=source,
                               message=message[:2000]))
    except Exception:  # noqa: BLE001 - logging is non-fatal by design
        pass


@contextmanager
def _stage(scan_id: str, name: str, fatal: bool = True):
    """Run a named stage, recording status/timing in the DB.

    fatal=False: a stage exception is recorded as failed with its error, but
    the scan continues with the remaining stages (missing coverage is then
    visible in the report's limitations).
    """
    started = _utcnow()
    with session_scope() as s:
        s.add(StageRow(scan_id=scan_id, name=name, status="running",
                       started_at=started))
    log_event(scan_id, "info", name, f"Stage started: {name}")
    note: dict[str, str] = {}
    try:
        yield note
        status = "completed"
    except _Cancelled:
        status = "cancelled"
        log_event(scan_id, "warn", name, f"Stage cancelled: {name}")
        raise
    except Exception as exc:  # noqa: BLE001 - stage failure must not kill scan
        status = "failed"
        note["error"] = f"{type(exc).__name__}: {exc}"
        log_event(scan_id, "error", name,
                  f"Stage failed: {name}: {type(exc).__name__}: {exc}")
        if fatal:
            raise
    finally:
        finished = _utcnow()
        dur_s = (finished - started).total_seconds()
        if status == "completed":
            log_event(scan_id, "info", name,
                      f"Stage completed: {name} ({dur_s:.1f}s)")
        with session_scope() as s:
            row = (s.query(StageRow)
                   .filter_by(scan_id=scan_id, name=name)
                   .order_by(StageRow.id.desc()).first())
            if row:
                row.status = status
                row.finished_at = finished
                row.duration_ms = (finished - started).total_seconds() * 1000
                row.note = note.get("error", note.get("note", ""))[:2000]


class _Cancelled(Exception):
    pass


def _check_cancel(job: ScanJob) -> None:
    if job.cancel.is_set():
        raise _Cancelled()


def _finding_seq(scan_id: str) -> Callable[[], str]:
    counter = {"n": 0}

    def nxt() -> str:
        counter["n"] += 1
        return f"{scan_id[:8]}-{counter['n']:04d}"
    return nxt


def persist_finding(session, scan_id: str, fid: str, f: dict[str, Any]) -> FindingRow:
    row = FindingRow(
        id=fid, scan_id=scan_id,
        rule_id=str(f.get("rule_id", ""))[:32],
        title=str(f.get("title", ""))[:512],
        severity=str(f.get("severity", "informational")),
        confidence=str(f.get("confidence", "low")),
        validation_status=str(f.get("validation_status", "static")),
        category=str(f.get("category", ""))[:32],
        owasp=list(f.get("owasp", []) or []),
        cwe=list(f.get("cwe", []) or []),
        file_path=str(f.get("file_path", ""))[:1024],
        line_start=f.get("line_start"), line_end=f.get("line_end"),
        snippet=str(f.get("snippet", ""))[:8000],
        description=str(f.get("description", ""))[:8000],
        impact=str(f.get("impact", ""))[:4000],
        remediation=str(f.get("remediation", ""))[:8000],
        engine=str(f.get("engine", "custom")),
        rule_version=str(f.get("rule_version", ""))[:16],
        provenance=list(f.get("provenance", []) or []),
        severity_rationale=str(f.get("severity_rationale", ""))[:2000],
        confidence_rationale=str(f.get("confidence_rationale", ""))[:2000],
    )
    session.add(row)
    return row


def _mergeable(existing: FindingRow, new: dict[str, Any]) -> bool:
    """Conservative cross-engine dedup: exact same file + line."""
    if not existing.file_path or not new.get("file_path"):
        return False
    if existing.line_start is None or new.get("line_start") is None:
        return False
    return (existing.file_path == new["file_path"]
            and existing.line_start == new["line_start"])


def _bump_confidence(value: str) -> str:
    order = ["low", "medium", "high"]
    try:
        idx = order.index(value)
    except ValueError:
        return "medium"
    return order[min(idx + 1, 2)]


def add_finding(session, scan_id: str, nxt: Callable[[], str],
                f: dict[str, Any]) -> FindingRow | None:
    """Insert a finding, merging exact duplicates across engines.

    Cross-engine corroboration: when a second, different engine reports the
    exact same file+line, confidence rises one level - two independent
    detectors agreeing is stronger evidence than one. The boost is recorded
    in confidence_rationale so it is auditable, never silent.
    """
    f.setdefault("provenance", []).insert(
        0, {"engine": f.get("engine", "custom"),
            "rule_id": f.get("rule_id", ""),
            "title": f.get("title", "")})
    if f.get("file_path") and f.get("line_start") is not None:
        for row in session.query(FindingRow).filter_by(scan_id=scan_id).all():
            if _mergeable(row, f):
                prov = list(row.provenance or [])
                new_engine = f.get("engine")
                known_engines = {p.get("engine") for p in prov if p.get("engine")}
                prov.append({"engine": new_engine, "rule_id": f.get("rule_id"),
                             "title": f.get("title")})
                row.provenance = prov
                if new_engine == Engine.AI.value and row.validation_status in (
                        "static", "heuristic"):
                    row.validation_status = "ai-corroborated"
                if new_engine and new_engine not in known_engines:
                    # A genuinely different engine agrees on this location.
                    old_conf = row.confidence or "low"
                    row.confidence = _bump_confidence(old_conf)
                    note = (f"Corroborated by a second engine ({new_engine}) "
                            f"at the same location; confidence {old_conf} -> "
                            f"{row.confidence}.")
                    row.confidence_rationale = (
                        (row.confidence_rationale or "") + " " + note).strip()
                return row  # merged, no new row
    return persist_finding(session, scan_id, nxt(), f)


def rule_result_to_finding(rule, res: RuleResult) -> dict[str, Any] | None:
    if res.status == RuleStatus.FINDING:
        validation = "static"
    elif res.status == RuleStatus.NEEDS_REVIEW:
        validation = "heuristic"
    else:
        return None
    return {
        "engine": Engine.CUSTOM.value,
        "rule_id": res.rule_id,
        "title": res.title,
        "severity": res.severity.value if res.severity else "informational",
        "confidence": res.confidence.value if res.confidence else "low",
        "validation_status": validation,
        "category": rule.category,
        "owasp": res.owasp, "cwe": res.cwe,
        "description": res.summary,
        "impact": "",
        "remediation": res.remediation,
        "rule_version": res.rule_version,
        "severity_rationale": res.severity_rationale,
        "confidence_rationale": res.confidence_rationale,
        "file_path": res.evidence[0].file_path if res.evidence else "",
        "line_start": res.evidence[0].line_start if res.evidence else None,
        "line_end": res.evidence[0].line_end if res.evidence else None,
        "snippet": "\n\n".join(
            e.snippet for e in res.evidence if e.snippet)[:8000],
        "provenance": [],
    }


# ---------------------------------------------------------------------------
# main scan
# ---------------------------------------------------------------------------

def _run_scan(scan_id: str, apk_path: Path, file_name: str, config: dict) -> None:
    job = get_job(scan_id)
    assert job is not None
    nxt = _finding_seq(scan_id)
    workspace: Path | None = None
    notes: list[str] = []        # limitations for the report
    errors: list[str] = []
    ctx: ScanContext | None = None
    tools = detect_tools()

    def progress(stage: str, percent: float | None, **kw: Any) -> None:
        quiet = kw.pop("quiet", False)
        _update_progress(job, stage=stage, percent=percent, **kw)
        # Persist milestone messages to the scan log so the live feed can be
        # backfilled when the user navigates away and comes back mid-scan.
        if kw.get("message") and not quiet:
            log_event(scan_id, "info", stage, str(kw["message"]))

    try:
        with session_scope() as s:
            row = s.get(ScanRow, scan_id)
            if row is None:
                s.add(ScanRow(id=scan_id, file_name=file_name, status="running",
                              config_json=config))
            else:
                row.status = "running"
                row.config_json = config
        ai_cfg = "on" if config.get("enable_ai_review") else "off"
        log_event(scan_id, "info", "scan",
                  f"Scan started: {file_name} "
                  f"(ai_review={ai_cfg}, model={config.get('ai_model') or 'auto'})")

        # ---- validate -----------------------------------------------------
        with _stage(scan_id, "validate") as st:
            progress("validate", 2, message="Validating APK package…")
            _check_cancel(job)
            vr = validate_apk(apk_path)
            if not vr.ok:
                raise ValueError(f"upload validation failed: {vr.error}")
            with session_scope() as s:
                row = s.get(ScanRow, scan_id)
                row.sha256 = vr.sha256
                row.file_size = vr.file_size

        # ---- extract ------------------------------------------------------
        with _stage(scan_id, "extract") as st:
            progress("extract", 8, message="Extracting APK contents…")
            _check_cancel(job)
            _, workspace = make_workspace(scan_id)
            extracted = workspace / "extracted"
            entries = safe_extract_zip(apk_path, extracted)
            st["note"] = f"extracted {len(entries)} entries"

        # ---- metadata -----------------------------------------------------
        with _stage(scan_id, "metadata") as st:
            progress("metadata", 15, message="Parsing AndroidManifest.xml…")
            _check_cancel(job)
            manifest, manifest_text_path, merr = load_manifest(extracted)
            if merr:
                errors.append(merr)
                notes.append(f"Manifest parsing: {merr}. Manifest-based checks skipped.")
            apk_info = collect_apk_info(extracted, entries)
            with session_scope() as s:
                vr2 = validate_apk(apk_path)
                apk_info.sha256 = vr2.sha256
                apk_info.file_size = vr2.file_size
                apk_info.file_name = file_name
            ctx = ScanContext(
                scan_id=scan_id, workdir=workspace, apk_path=apk_path,
                apk=apk_info, manifest=manifest,
                manifest_xml_path=manifest_text_path,
                res_dir=extracted / "res" if (extracted / "res").is_dir() else None,
                assets_dir=(extracted / "assets"
                            if (extracted / "assets").is_dir() else None),
                lib_dir=(extracted / "lib" if (extracted / "lib").is_dir() else None),
                apk_entries=entries, tools=tools, config=config,
            )
            # extra source roots (test hook / advanced use)
            for extra in config.get("extra_java_roots", []) or []:
                p = Path(extra)
                if p.is_dir():
                    ctx.java_roots.append(p)
            if manifest:
                with session_scope() as s:
                    row = s.get(ScanRow, scan_id)
                    row.package_name = manifest.package
                    row.app_name = manifest.app_name
                    row.version_name = manifest.version_name
                    row.version_code = manifest.version_code
                    # SDK levels live in config_json (no schema migration needed
                    # for existing databases).
                    cfg = dict(row.config_json or {})
                    cfg["_sdk"] = {"min": manifest.min_sdk,
                                   "target": manifest.target_sdk}
                    row.config_json = cfg
            progress("metadata", 20, message="Collecting app metadata…")

        assert ctx is not None

        # ---- decompile ----------------------------------------------------
        with _stage(scan_id, "decompile") as st:
            progress("decompile", 25, message="Decompiling bytecode with jadx + apktool…")
            _check_cancel(job)
            jadx_out = workspace / "jadx"
            apktool_out = workspace / "apktool"
            log_event(scan_id, "info", "decompile",
                      "Decompiling: jadx + apktool running in parallel")
            # jadx and apktool are independent: run them concurrently to
            # roughly halve decompile time on multi-core machines.
            with ThreadPoolExecutor(max_workers=2,
                                    thread_name_prefix="decompile") as pool:
                fut_jadx = pool.submit(try_jadx, apk_path, jadx_out,
                                       settings.tool_timeout_s, job.cancel)
                fut_apktool = pool.submit(try_apktool, apk_path, apktool_out,
                                          settings.tool_timeout_s, job.cancel)
                src_dir, note = fut_jadx.result()
                dec_dir, note2 = fut_apktool.result()
            if src_dir:
                ctx.java_roots.append(src_dir)
                log_event(scan_id, "info", "jadx", note)
            else:
                notes.append(note)
                log_event(scan_id, "warn", "jadx", note)
            if dec_dir:
                smali = dec_dir / "smali"
                ctx.smali_dir = smali if smali.is_dir() else None
                res = dec_dir / "res"
                if res.is_dir() and ctx.res_dir is None:
                    ctx.res_dir = res
                log_event(scan_id, "info", "apktool", note2)
            else:
                notes.append(note2)
                log_event(scan_id, "warn", "apktool", note2)
            st["note"] = "; ".join(n for n in (note, note2) if n)

        # apktool resolves @string/app_name references when decoding, so if
        # our binary-XML parse left the app name empty, recover it here.
        if dec_dir and manifest is not None and not manifest.app_name:
            refined = refine_app_name_from_decoded_manifest(dec_dir)
            if refined:
                manifest.app_name = refined
                with session_scope() as s:
                    row = s.get(ScanRow, scan_id)
                    row.app_name = refined
                log_event(scan_id, "info", "metadata",
                          f"App name resolved from decoded manifest: {refined}")

        # ---- mobsfscan (third-party static analysis) ------------------------
        with _stage(scan_id, "mobsfscan", fatal=False) as st:
            progress("mobsfscan", 40,
                     message="Running MobSFScan…")
            _check_cancel(job)
            tp_dir = workspace / "mobsfscan"
            tp_dir.mkdir(exist_ok=True)
            with session_scope() as s:
                findings, note = run_mobsfscan(
                    ctx.java_roots, tp_dir,
                    timeout_s=settings.tool_timeout_s, cancel=job.cancel)
                _check_cancel(job)
                for f in findings:
                    add_finding(s, scan_id, nxt, f)
                s.add(ExecRow(scan_id=scan_id, rule_id="mobsfscan:scan",
                              engine="mobsfscan",
                              status="completed" if findings or "skipped" not in note else "not_run",
                              error="" if findings or "skipped" not in note else note))
                if "skipped" in note or "not installed" in note:
                    notes.append(note)
                s.flush()
            progress("mobsfscan", 55,
                     findings_so_far=_count_findings(scan_id),
                     message="MobSFScan finished")

        # ---- custom rules -------------------------------------------------
        with _stage(scan_id, "custom_rules") as st:
            rules = enabled_rules(config)
            total = len(rules)
            progress("custom_rules", 58, checks_run=0,
                     message=f"Running {total} custom checks…")
            with session_scope() as s:
                for i, rule in enumerate(rules):
                    _check_cancel(job)
                    res = rule.run(ctx)
                    s.add(ExecRow(scan_id=scan_id, rule_id=rule.id,
                                  engine=Engine.CUSTOM.value,
                                  status=res.status.value,
                                  duration_ms=res.duration_ms,
                                  error=(res.error or "")[:2000]))
                    f = rule_result_to_finding(rule, res)
                    if f:
                        add_finding(s, scan_id, nxt, f)
                    if i % 10 == 0:
                        s.flush()
                        progress("custom_rules", 58 + 25 * (i + 1) / max(total, 1),
                                 checks_run=i + 1,
                                 findings_so_far=_count_findings(session=s, scan_id=scan_id),
                                 message=f"Custom checks {i + 1}/{total}…", quiet=True)
                s.flush()
            progress("custom_rules", 83, checks_run=total,
                     findings_so_far=_count_findings(scan_id),
                     message="Custom checks complete")

        # ---- AI review ----------------------------------------------------
        ai_meta: dict[str, Any] = {"status": "skipped", "model": "",
                                   "error": "AI review disabled in scan config"}
        if config.get("enable_ai_review"):
            with _stage(scan_id, "ai_review", fatal=False) as st:
                progress("ai_review", 86, message="Starting AI review…")
                _check_cancel(job)
                model = config.get("ai_model") or settings.ai_model
                client = OllamaClient(settings.ollama_url)
                if not model:
                    models = client.list_models()
                    model = models[0] if models else ""
                reviewer = AIReviewer(client)

                def _ai_progress(msg: str, pct: float = 88) -> None:
                    progress("ai_review", pct, message=msg)

                ai_findings, ai_meta = reviewer.run(
                    ctx, model, progress=_ai_progress, cancel=job.cancel)
                with session_scope() as s:
                    for f in ai_findings:
                        _add_ai_finding(s, scan_id, nxt, f)
                    s.add(AIReviewRow(
                        scan_id=scan_id, model=ai_meta.get("model", ""),
                        prompt_version=ai_meta.get("prompt_version", ""),
                        status=ai_meta.get("status", "skipped"),
                        files_reviewed=ai_meta.get("files_reviewed", 0),
                        findings_proposed=ai_meta.get("findings_proposed", 0),
                        findings_accepted=ai_meta.get("findings_accepted", 0),
                        error=str(ai_meta.get("error", ""))[:2000],
                        started_at=_utcnow(), finished_at=_utcnow()))
                if ai_meta.get("status") != "completed":
                    notes.append(f"AI review: {ai_meta.get('error', 'skipped')}")
                st["note"] = (f"model={ai_meta.get('model')}, "
                              f"accepted={ai_meta.get('findings_accepted')}, "
                              f"libs_skipped={ai_meta.get('library_files_skipped', 0)}")
        else:
            with session_scope() as s:
                s.add(StageRow(scan_id=scan_id, name="ai_review", status="skipped",
                               started_at=_utcnow(), finished_at=_utcnow(),
                               note="disabled in scan configuration"))
            notes.append("AI review disabled in scan configuration.")
        progress("ai_review", 90, findings_so_far=_count_findings(scan_id),
                 message="AI review complete")

        # ---- normalize ----------------------------------------------------
        with _stage(scan_id, "normalize"):
            progress("normalize", 94, message="Merging findings across engines…")
            _check_cancel(job)
            # severity/confidence already independent per finding; normalize
            # unknown severities defensively.
            with session_scope() as s:
                for row in s.query(FindingRow).filter_by(scan_id=scan_id).all():
                    if row.severity not in _SEV_ORDER:
                        row.severity = "informational"

        # ---- finalize -----------------------------------------------------
        with _stage(scan_id, "finalize"):
            progress("finalize", 98, message="Building report…")
            with session_scope() as s:
                row = s.get(ScanRow, scan_id)
                row.status = "completed"
                row.finished_at = _utcnow()
        total = _count_findings(scan_id)
        log_event(scan_id, "info", "scan",
                  f"Scan completed: {total} finding(s)")
        for n in notes:
            log_event(scan_id, "warn", "scan", f"Limitation: {n}")
        progress("done", 100, findings_so_far=total)
        emit(scan_id, "done", {"scan_id": scan_id})

    except _Cancelled:
        with session_scope() as s:
            row = s.get(ScanRow, scan_id)
            if row:
                row.status = "cancelled"
                row.finished_at = _utcnow()
        log_event(scan_id, "warn", "scan", "Scan cancelled by user")
        if workspace:
            cleanup_workspace(workspace)
        emit(scan_id, "error", {"message": "scan cancelled"})
    except Exception as exc:  # noqa: BLE001 - never lose the error
        tb = traceback.format_exc(limit=5)
        with session_scope() as s:
            row = s.get(ScanRow, scan_id)
            if row:
                row.status = "failed"
                row.error = f"{type(exc).__name__}: {exc}"
                row.finished_at = _utcnow()
        errors.append(f"{type(exc).__name__}: {exc}")
        log_event(scan_id, "error", "scan",
                  f"Scan failed: {type(exc).__name__}: {exc}")
        if workspace:
            cleanup_workspace(workspace)
        emit(scan_id, "error", {"message": f"scan failed: {exc}", "trace": tb[-2000:]})
    finally:
        # stash notes/errors for the API layer (also persisted below)
        job.progress["notes"] = notes
        job.progress["errors"] = errors
        with session_scope() as s:
            row = s.get(ScanRow, scan_id)
            if row and row.status in ("completed", "failed", "cancelled"):
                cfg = dict(row.config_json or {})
                cfg["_notes"] = notes
                cfg["_errors"] = errors
                cfg["_ai"] = ai_meta if "ai_meta" in dir() else {}
                row.config_json = cfg


def _add_ai_finding(session, scan_id: str, nxt, f: dict[str, Any]) -> None:
    """Insert an AI finding, corroborating deterministic ones on proximity."""
    if f.get("file_path") and f.get("line_start") is not None:
        for row in session.query(FindingRow).filter_by(scan_id=scan_id).all():
            if (row.file_path == f["file_path"] and row.line_start is not None
                    and abs(row.line_start - f["line_start"]) <= 3):
                prov = list(row.provenance or [])
                prov.append({"engine": "ai", "rule_id": "ai:llm-review",
                             "title": f["title"],
                             "model": f.get("ai_model", "")})
                row.provenance = prov
                row.validation_status = "ai-corroborated"
                return
    f["provenance"] = []
    persist_finding(session, scan_id, nxt(), f)


def _count_findings(scan_id: str, session=None) -> int:
    def _count(s) -> int:
        return s.query(FindingRow).filter_by(scan_id=scan_id).count()
    if session is not None:
        return _count(session)
    with session_scope() as s:
        return _count(s)


def get_scan_summary(scan_id: str) -> dict[str, Any] | None:
    """Assemble the full status payload for GET /api/scans/{id}."""
    job = get_job(scan_id)
    with session_scope() as s:
        row = s.get(ScanRow, scan_id)
        if not row:
            return None
        stages = (s.query(StageRow).filter_by(scan_id=scan_id)
                  .order_by(StageRow.id).all())
        findings = s.query(FindingRow).filter_by(scan_id=scan_id).all()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0,
                  "informational": 0}
        for f in findings:
            if f.severity in counts:
                counts[f.severity] += 1
        execs = s.query(ExecRow).filter_by(scan_id=scan_id).all()
        ai_rows = (s.query(AIReviewRow).filter_by(scan_id=scan_id)
                   .order_by(AIReviewRow.id.desc()).all())
        cfg = dict(row.config_json or {})
        prog = dict(job.progress) if job else {}
        elapsed = (row.finished_at - row.created_at).total_seconds() \
            if row.finished_at else (time.time() - job.started_at if job else 0)
        return {
            "scan_id": row.id,
            "status": row.status,
            "file_name": row.file_name,
            "sha256": row.sha256,
            "file_size": row.file_size,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "finished_at": row.finished_at.isoformat() if row.finished_at else None,
            "error": row.error,
            "progress": {
                "stage": prog.get("stage", row.status),
                "percent": prog.get("percent"),
                "checks_run": prog.get("checks_run", len(execs)),
                "findings_so_far": prog.get("findings_so_far", len(findings)),
                "elapsed_s": round(elapsed, 1),
                "stages": [{
                    "name": st.name, "status": st.status,
                    "started_at": st.started_at.isoformat() if st.started_at else None,
                    "finished_at": st.finished_at.isoformat() if st.finished_at else None,
                    "duration_ms": round(st.duration_ms, 1),
                    "note": st.note,
                } for st in stages],
            },
            "metadata": {
                "package_name": row.package_name,
                "app_name": row.app_name,
                "version_name": row.version_name,
                "version_code": row.version_code,
                "sha256": row.sha256,
                "min_sdk": (cfg.get("_sdk") or {}).get("min"),
                "target_sdk": (cfg.get("_sdk") or {}).get("target"),
                "file_size": row.file_size,
            },
            "counts": counts,
            "limitations": cfg.get("_notes", []),
            "errors": cfg.get("_errors", []),
            "ai": {
                "status": ai_rows[0].status if ai_rows else cfg.get("_ai", {}).get("status", "skipped"),
                "model": ai_rows[0].model if ai_rows else cfg.get("_ai", {}).get("model", ""),
                "detail": cfg.get("_ai", {}).get("error", ""),
            },
            "scan_config": {
                "enable_ai_review": bool(cfg.get("enable_ai_review")),
                "ai_model": cfg.get("ai_model") or "",
                "disabled_rules": cfg.get("disabled_rules") or [],
            },
            "rules_executed": len(execs),
        }
