"""Blindspot REST API.

Serves the Security Console frontend and the `blindspot` CLI.
Default bind is localhost-only; set BLINDSPOT_API_TOKEN to require a token.
"""

from __future__ import annotations

import asyncio
import json
import queue
import shutil
import uuid
from pathlib import Path
from typing import Any

from fastapi import (Depends, FastAPI, File, Form, Header, HTTPException,
                     Query, UploadFile)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse

from ..ai.ollama import OllamaClient
from ..analysis.apk import validate_apk
from ..analysis.tools import detect_tools
from ..config import settings
from ..core.db import session_scope
from ..core.models import Finding as FindingRow
from ..core.models import Scan as ScanRow
from ..core.workspace import cleanup_workspace
from ..pipeline import orchestrator
from ..reports import render_html, render_json, render_pdf
from ..reports.common import finding_to_dict

_CHUNK = 1024 * 256


def _check_pdf() -> tuple[bool, str]:
    """PDF export uses ReportLab (pure Python, no system libraries), so it
    is always available on every platform - no Pango/Cairo/GTK setup."""
    try:
        import reportlab  # noqa: F401
        return True, ""
    except Exception as exc:  # noqa: BLE001 - missing dep means no PDF
        return False, f"PDF export needs the 'reportlab' package: {exc}"


_PDF_AVAILABLE, _PDF_HINT = _check_pdf()


def _require_token(x_api_token: str | None = Header(default=None)):
    if settings.api_token and x_api_token != settings.api_token:
        raise HTTPException(status_code=401, detail="invalid API token")


def create_app() -> FastAPI:
    settings.ensure_dirs()
    app = FastAPI(title="Blindspot API", version="4.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"], allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    @app.post("/api/scans", dependencies=[Depends(_require_token)])
    async def create_scan(
        file: UploadFile = File(...),
        config: str = Form(default="{}"),
    ) -> dict[str, Any]:
        try:
            cfg = json.loads(config) if config else {}
            if not isinstance(cfg, dict):
                raise ValueError("config must be a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"bad config JSON: {exc}")
        scan_id = uuid.uuid4().hex
        apk_path = settings.upload_dir / f"{scan_id}.apk"
        # stream to disk with an early size guard
        size = 0
        limit = settings.max_upload_mb * 1024 * 1024
        try:
            with open(apk_path, "wb") as out:
                while True:
                    chunk = await file.read(_CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        out.close()
                        apk_path.unlink(missing_ok=True)
                        raise HTTPException(
                            status_code=413,
                            detail=f"upload exceeds {settings.max_upload_mb} MB limit")
                    out.write(chunk)
        finally:
            await file.close()
        vr = validate_apk(apk_path)
        if not vr.ok:
            apk_path.unlink(missing_ok=True)
            raise HTTPException(status_code=422, detail=vr.error)
        with session_scope() as s:
            s.add(ScanRow(id=scan_id, file_name=file.filename or "upload.apk",
                          sha256=vr.sha256, file_size=vr.file_size,
                          status="queued", config_json=cfg))
        orchestrator.start_scan(scan_id, apk_path, file.filename or "upload.apk", cfg)
        return {"scan_id": scan_id, "status": "running"}

    # ------------------------------------------------------------------
    @app.get("/api/scans", dependencies=[Depends(_require_token)])
    def list_scans() -> list[dict[str, Any]]:
        with session_scope() as s:
            rows = s.query(ScanRow).order_by(ScanRow.created_at.desc()).all()
            out = []
            for r in rows:
                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0,
                          "informational": 0}
                for f in s.query(FindingRow).filter_by(scan_id=r.id).all():
                    if f.severity in counts:
                        counts[f.severity] += 1
                out.append({
                    "scan_id": r.id, "package_name": r.package_name,
                    "app_name": r.app_name, "status": r.status,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "counts": counts,
                })
            return out

    # ------------------------------------------------------------------
    @app.get("/api/scans/{scan_id}", dependencies=[Depends(_require_token)])
    def get_scan(scan_id: str) -> dict[str, Any]:
        summary = orchestrator.get_scan_summary(scan_id)
        if summary is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return summary

    # ------------------------------------------------------------------
    @app.get("/api/scans/{scan_id}/events", dependencies=[Depends(_require_token)])
    async def scan_events(scan_id: str):
        q = orchestrator.subscribe(scan_id)

        async def gen():
            try:
                # initial snapshot
                summary = orchestrator.get_scan_summary(scan_id)
                if summary is None:
                    yield 'event: error\ndata: {"message": "scan not found"}\n\n'
                    return
                yield f"event: progress\ndata: {json.dumps(summary['progress'])}\n\n"
                if summary["status"] in ("completed", "failed", "cancelled"):
                    yield f'event: done\ndata: {json.dumps({"scan_id": scan_id})}\n\n'
                    return
                while True:
                    try:
                        msg = await asyncio.to_thread(q.get, True, 20)
                    except queue.Empty:
                        yield ": heartbeat\n\n"
                        summary = orchestrator.get_scan_summary(scan_id)
                        if summary and summary["status"] in (
                                "completed", "failed", "cancelled"):
                            yield f'event: done\ndata: {json.dumps({"scan_id": scan_id})}\n\n'
                            return
                        continue
                    yield f"event: {msg['event']}\ndata: {json.dumps(msg['data'])}\n\n"
                    if msg["event"] in ("done", "error"):
                        return
            finally:
                orchestrator.unsubscribe(scan_id, q)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    # ------------------------------------------------------------------
    @app.get("/api/scans/{scan_id}/findings", dependencies=[Depends(_require_token)])
    def list_findings(
        scan_id: str,
        severity: str | None = Query(default=None),
        confidence: str | None = Query(default=None),
        owasp: str | None = Query(default=None),
        engine: str | None = Query(default=None),
        review_status: str | None = Query(default=None),
        q: str | None = Query(default=None),
        sort: str = Query(default="severity"),
        limit: int = Query(default=2000, le=10000),
    ) -> dict[str, Any]:
        with session_scope() as s:
            if not s.get(ScanRow, scan_id):
                raise HTTPException(status_code=404, detail="scan not found")
            rows = s.query(FindingRow).filter_by(scan_id=scan_id).all()
            sevs = {x.strip() for x in severity.split(",")} if severity else None
            out = []
            for f in rows:
                if sevs and f.severity not in sevs:
                    continue
                if confidence and f.confidence != confidence:
                    continue
                if engine and f.engine != engine:
                    continue
                if review_status and f.review_status != review_status:
                    continue
                if owasp and owasp not in (f.owasp or []):
                    continue
                if q:
                    ql = q.lower()
                    hay = " ".join([f.title, f.file_path, f.rule_id,
                                    f.snippet or "", f.description or ""]).lower()
                    if ql not in hay:
                        continue
                out.append(finding_to_dict(f))
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                        "informational": 4}
            conf_rank = {"high": 0, "medium": 1, "low": 2}
            if sort == "confidence":
                out.sort(key=lambda d: (conf_rank.get(d["confidence"], 9),
                                        sev_rank.get(d["severity"], 9)))
            else:
                out.sort(key=lambda d: (sev_rank.get(d["severity"], 9),
                                        conf_rank.get(d["confidence"], 9)))
            return {"findings": out[:limit], "total": len(out)}

    # ------------------------------------------------------------------
    @app.patch("/api/scans/{scan_id}/findings/{finding_id}",
               dependencies=[Depends(_require_token)])
    def review_finding(scan_id: str, finding_id: str,
                       body: dict[str, Any]) -> dict[str, Any]:
        status = body.get("review_status")
        if status not in ("confirmed", "rejected", "accepted_risk",
                          "needs_review", "open"):
            raise HTTPException(status_code=400, detail="bad review_status")
        with session_scope() as s:
            f = s.get(FindingRow, finding_id)
            if not f or f.scan_id != scan_id:
                raise HTTPException(status_code=404, detail="finding not found")
            f.review_status = status
            f.review_note = str(body.get("note", ""))[:2000]
            s.flush()
            return finding_to_dict(f)

    # ------------------------------------------------------------------
    @app.post("/api/scans/{scan_id}/cancel", dependencies=[Depends(_require_token)])
    def cancel(scan_id: str) -> dict[str, Any]:
        with session_scope() as s:
            if not s.get(ScanRow, scan_id):
                raise HTTPException(status_code=404, detail="scan not found")
        ok = orchestrator.cancel_scan(scan_id)
        return {"status": "cancelling" if ok else "not_running"}

    # ------------------------------------------------------------------
    @app.delete("/api/scans/{scan_id}", dependencies=[Depends(_require_token)])
    def delete_scan(scan_id: str) -> dict[str, Any]:
        orchestrator.cancel_scan(scan_id)
        with session_scope() as s:
            row = s.get(ScanRow, scan_id)
            if not row:
                raise HTTPException(status_code=404, detail="scan not found")
            s.delete(row)
        cleanup_workspace(settings.workspace_root / scan_id)
        (settings.upload_dir / f"{scan_id}.apk").unlink(missing_ok=True)
        return {"deleted": scan_id}

    # ------------------------------------------------------------------
    @app.get("/api/scans/{scan_id}/report.html", dependencies=[Depends(_require_token)])
    def report_html(scan_id: str):
        text = render_html(scan_id)
        if text is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return Response(content=text, media_type="text/html",
                        headers={"Content-Disposition":
                                 f"attachment; filename=blindspot-{scan_id[:8]}.html"})

    @app.get("/api/scans/{scan_id}/report.pdf", dependencies=[Depends(_require_token)])
    def report_pdf(scan_id: str):
        if not _PDF_AVAILABLE:
            raise HTTPException(status_code=503, detail=_PDF_HINT)
        try:
            pdf = render_pdf(scan_id)
        except Exception as exc:  # noqa: BLE001 - report the real cause
            raise HTTPException(status_code=500,
                                detail=f"PDF generation failed: {exc}")
        if pdf is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return Response(content=pdf, media_type="application/pdf",
                        headers={"Content-Disposition":
                                 f"attachment; filename=blindspot-{scan_id[:8]}.pdf"})

    @app.get("/api/scans/{scan_id}/log", dependencies=[Depends(_require_token)])
    def scan_log(scan_id: str) -> dict[str, Any]:
        """Per-scan troubleshooting log: what ran, what broke, in order."""
        from ..core.models import ScanEvent as ScanEventRow
        with session_scope() as s:
            if not s.get(ScanRow, scan_id):
                raise HTTPException(status_code=404, detail="scan not found")
            rows = (s.query(ScanEventRow).filter_by(scan_id=scan_id)
                    .order_by(ScanEventRow.id).all())
            return {"scan_id": scan_id, "events": [
                {"ts": r.ts.isoformat() if r.ts else None,
                 "level": r.level, "source": r.source,
                 "message": r.message} for r in rows]}

    @app.get("/api/scans/{scan_id}/report.json", dependencies=[Depends(_require_token)])
    def report_json(scan_id: str):
        text = render_json(scan_id)
        if text is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return Response(content=text, media_type="application/json",
                        headers={"Content-Disposition":
                                 f"attachment; filename=blindspot-{scan_id[:8]}.json"})

    # ------------------------------------------------------------------
    @app.get("/api/rules", dependencies=[Depends(_require_token)])
    def list_rules() -> list[dict[str, Any]]:
        from ..rules.registry import get_registry
        try:
            reg = get_registry()
        except Exception as exc:
            raise HTTPException(status_code=500,
                                detail=f"rule registry failed to load: {exc}")
        return [{
            "id": r.id, "title": r.title, "description": r.description,
            "category": r.category,
            "default_severity": r.default_severity.value,
            "owasp": r.owasp, "cwe": r.cwe, "masvs": r.masvs,
            "enabled_by_default": r.enabled_by_default, "version": r.version,
        } for r in reg.values()]

    # ------------------------------------------------------------------
    @app.get("/api/system/status", dependencies=[Depends(_require_token)])
    def system_status() -> dict[str, Any]:
        tools = detect_tools()
        client = OllamaClient(settings.ollama_url)
        ollama_ok = client.is_available()
        return {
            "tools": {**tools, "ollama": {
                "available": ollama_ok,
                "models": client.list_models() if ollama_ok else [],
                "url": settings.ollama_url,
            }},
            "pdf": {"available": _PDF_AVAILABLE,
                    "hint": _PDF_HINT if not _PDF_AVAILABLE else ""},
            "limits": {
                "max_upload_mb": settings.max_upload_mb,
                "max_extract_mb": settings.max_extract_mb,
                "scan_timeout_s": settings.scan_timeout_s,
                "tool_timeout_s": settings.tool_timeout_s,
                "retention_days": settings.retention_days,
            },
        }

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # serve a built frontend if present
    dist = Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "dist"
    if dist.is_dir():
        from fastapi.responses import FileResponse
        from fastapi.staticfiles import StaticFiles

        @app.get("/{full_path:path}")
        def spa_fallback(full_path: str):
            """SPA fallback: serve real files when they exist, otherwise the
            SPA shell (index.html) for client-side routes (/history,
            /scans/{id}, …). Registered BEFORE the StaticFiles mount."""
            if full_path.startswith("api/"):
                raise HTTPException(status_code=404, detail="Not Found")
            dist_resolved = dist.resolve()
            candidate = (dist_resolved / full_path).resolve()
            if str(candidate).startswith(str(dist_resolved)) and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(dist_resolved / "index.html")

        app.mount("/", StaticFiles(directory=str(dist), html=True), name="frontend")

    return app


app = create_app()
