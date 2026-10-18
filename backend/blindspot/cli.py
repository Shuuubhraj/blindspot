"""Blindspot CLI: scan APKs, inspect results and export reports.

Talks to the Blindspot API (default http://127.0.0.1:8000, override with
BLINDSPOT_URL). Start the API first with `blindspot serve`.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import httpx
import typer
import uvicorn

app = typer.Typer(help="Blindspot - local-first Android APK security assessment")


def _base_url() -> str:
    return os.environ.get("BLINDSPOT_URL", "http://127.0.0.1:8000")


def _client() -> httpx.Client:
    token = os.environ.get("BLINDSPOT_API_TOKEN", "")
    headers = {"X-API-Token": token} if token else {}
    # trust_env=False: never route localhost API calls through system proxies
    return httpx.Client(base_url=_base_url(), headers=headers, timeout=60, trust_env=False)


@app.command()
def serve(host: str = typer.Option("127.0.0.1", help="bind address (localhost-only by default)"),
          port: int = typer.Option(8000)) -> None:
    """Start the Blindspot API + console."""
    uvicorn.run("blindspot.api.app:app", host=host, port=port)


@app.command()
def scan(apk: Path = typer.Argument(..., help="APK file to assess"),
         enable_ai: bool = typer.Option(False, "--ai", help="enable local Ollama AI review"),
         ai_model: str = typer.Option("", help="Ollama model for AI review"),
         wait: bool = typer.Option(True, help="wait for completion and print summary")) -> None:
    """Upload an APK and run a full security assessment."""
    if not apk.is_file():
        typer.echo(f"not found: {apk}", err=True)
        raise typer.Exit(2)
    config = {"enable_ai_review": enable_ai, "ai_model": ai_model or None}
    with _client() as c, open(apk, "rb") as f:
        r = c.post("/api/scans", files={"file": (apk.name, f, "application/vnd.android.package-archive")},
                   data={"config": json.dumps(config)}, timeout=300)
    if r.status_code not in (200, 201):
        typer.echo(f"upload failed ({r.status_code}): {r.text[:500]}", err=True)
        raise typer.Exit(1)
    scan_id = r.json()["scan_id"]
    typer.echo(f"scan started: {scan_id}")
    if not wait:
        return
    with _client() as c:
        while True:
            s = c.get(f"/api/scans/{scan_id}", timeout=30).json()
            p = s["progress"]
            pct = f"{p['percent']:.0f}%" if p.get("percent") is not None else "…"
            typer.echo(f"\r[{s['status']}] stage={p['stage']} {pct} "
                       f"checks={p['checks_run']} findings={p['findings_so_far']} "
                       f"{p['elapsed_s']}s", nl=False)
            if s["status"] in ("completed", "failed", "cancelled"):
                typer.echo()
                break
            time.sleep(3)
    summary(scan_id)


@app.command(name="status")
def summary(scan_id: str = typer.Argument(...)) -> None:
    """Show scan status, counts and limitations."""
    with _client() as c:
        s = c.get(f"/api/scans/{scan_id}").json()
    typer.echo(f"scan    : {s['scan_id']} [{s['status']}]")
    m = s["metadata"]
    typer.echo(f"package : {m['package_name']} {m['version_name']} ({m['version_code']})")
    typer.echo(f"sha256  : {m['sha256']}")
    typer.echo("findings: " + ", ".join(f"{k}={v}" for k, v in s["counts"].items()))
    typer.echo(f"rules executed: {s['rules_executed']}")
    for lim in s["limitations"]:
        typer.echo(f"  ! {lim}")
    if s["error"]:
        typer.echo(f"error: {s['error']}", err=True)


@app.command()
def findings(scan_id: str = typer.Argument(...),
             severity: str = typer.Option("", help="comma-separated severities"),
             limit: int = typer.Option(50)) -> None:
    """List findings for a scan."""
    params: dict = {"limit": limit}
    if severity:
        params["severity"] = severity
    with _client() as c:
        d = c.get(f"/api/scans/{scan_id}/findings", params=params).json()
    for f in d["findings"]:
        loc = f["file_path"] or ""
        if f["line_start"]:
            loc += f":{f['line_start']}"
        typer.echo(f"[{f['severity']:>12}] {f['title']}")
        typer.echo(f"  {f['finding_id']} rule={f['rule_id']} {loc}")
    typer.echo(f"total: {d['total']}")


@app.command()
def report(scan_id: str = typer.Argument(...),
           format: str = typer.Option("html", help="html|pdf|json"),
           output: Path | None = typer.Option(None, "-o", "--output")) -> None:
    """Download the assessment report."""
    if format not in ("html", "pdf", "json"):
        typer.echo("format must be html|pdf|json", err=True)
        raise typer.Exit(2)
    output = output or Path(f"blindspot-{scan_id[:8]}.{format}")
    with _client() as c:
        r = c.get(f"/api/scans/{scan_id}/report.{format}", timeout=300)
    if r.status_code != 200:
        typer.echo(f"report failed ({r.status_code}): {r.text[:300]}", err=True)
        raise typer.Exit(1)
    output.write_bytes(r.content)
    typer.echo(f"wrote {output} ({len(r.content)} bytes)")


@app.command()
def rules() -> None:
    """List all detection rules in the registry."""
    with _client() as c:
        data = c.get("/api/rules").json()
    typer.echo(f"{len(data)} rules")
    for r in data:
        typer.echo(f"  {r['id']:10} [{r['default_severity']:>12}] {r['title']}")


@app.command()
def system() -> None:
    """Show tool readiness and limits."""
    with _client() as c:
        data = c.get("/api/system/status").json()
    for tool, ok in data["tools"].items():
        if tool == "ollama":
            typer.echo(f"  ollama: {'available' if ok['available'] else 'NOT available'}"
                       f" models={ok['models']}")
        else:
            typer.echo(f"  {tool}: {'available' if ok else 'NOT available'}")
    typer.echo(f"limits: {data['limits']}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
