"""Integration tests for the Blindspot REST API.

These tests exercise the full scan pipeline over HTTP using an isolated
data directory (separate SQLite DB and workspaces). The fixture APK is a
real APK parsed by our own AXML decoder and androguard.
"""
import json
import os
import time

import pytest

FIXTURE_APK = os.path.join(os.path.dirname(__file__), "..", "fixtures", "test-app.apk")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("blindspot-data")
    os.environ["BLINDSPOT_DATA_DIR"] = str(data_dir)
    # import after env is set so config/db pick up the isolated dir
    from starlette.testclient import TestClient

    from blindspot.api.app import app

    with TestClient(app) as c:
        yield c


def _upload(client, config=None):
    with open(FIXTURE_APK, "rb") as fh:
        files = {"file": ("test-app.apk", fh, "application/vnd.android.package-archive")}
        data = {"config": json.dumps(config or {})}
        r = client.post("/api/scans", files=files, data=data)
    assert r.status_code == 200, r.text
    return r.json()["scan_id"]


def _wait(client, scan_id, timeout=240):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/scans/{scan_id}")
        assert r.status_code == 200, r.text
        body = r.json()
        if body["status"] in ("completed", "failed", "cancelled"):
            return body
        time.sleep(3)
    raise TimeoutError(f"scan {scan_id} did not finish in {timeout}s")


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_upload_and_full_scan(client):
    sid = _upload(client, {"enable_ai_review": False})
    scan = _wait(client, sid)
    assert scan["status"] == "completed", scan.get("error")
    r = client.get(f"/api/scans/{sid}/findings", params={"limit": 500})
    assert r.status_code == 200
    findings = r.json()
    assert findings["total"] >= 15, "fixture APK should produce real findings"
    severities = {f["severity"] for f in findings["findings"]}
    assert "high" in severities and "medium" in severities
    # every finding must carry real provenance, never fabricated evidence
    for f in findings["findings"]:
        assert f["engine"] in ("custom", "mobsf", "ai")
        assert f["rule_id"]
        assert f["severity"] in ("critical", "high", "medium", "low", "informational")
        assert f["confidence"] in ("high", "medium", "low")
        assert isinstance(f["provenance"], list) and f["provenance"]


def test_mobsfscan_stage_wired(client):
    """The mobsfscan stage must run in every scan and reach a terminal
    state (completed / not_run) - never silently missing."""
    sid = _upload(client, {"enable_ai_review": False})
    scan = _wait(client, sid)
    assert scan["status"] == "completed", scan.get("error")
    stages = {st["name"]: st["status"]
              for st in scan["progress"]["stages"]}
    assert "mobsfscan" in stages, f"stages: {sorted(stages)}"
    assert stages["mobsfscan"] in ("completed", "not_run"), stages["mobsfscan"]
    assert "third_party" not in stages, "old stage name must be gone"


def test_missing_tools_reported_as_limitations(client):
    sid = _upload(client, {"enable_ai_review": False})
    scan = _wait(client, sid)
    lims = " ".join(scan["limitations"]).lower()
    assert "jadx" in lims and "apktool" in lims, f"limitations: {scan['limitations']}"
    assert scan["status"] == "completed", "missing optional tools must not fail the scan"


def test_ai_unavailable_is_graceful(client):
    sid = _upload(client, {"enable_ai_review": True, "ai_model": "llama3.1:8b"})
    scan = _wait(client, sid)
    assert scan["status"] == "completed"
    assert scan["ai"]["status"] == "skipped", scan["ai"]
    assert "ollama" in scan["ai"]["detail"].lower()
    findings = client.get(f"/api/scans/{sid}/findings", params={"limit": 5}).json()
    assert not any(f["validation_status"] == "ai_reviewed" for f in findings["findings"])


def test_reject_non_apk(client):
    r = client.post(
        "/api/scans",
        files={"file": ("evil.txt", b"not an apk at all", "text/plain")},
        data={"config": "{}"},
    )
    assert r.status_code in (400, 415, 422), r.text


def test_reject_bad_zip(client):
    r = client.post(
        "/api/scans",
        files={"file": ("bad.apk", b"PK\x03\x04corrupted", "application/vnd.android.package-archive")},
        data={"config": "{}"},
    )
    assert r.status_code in (400, 415, 422), r.text


def test_cancel_scan(client, monkeypatch):
    import blindspot.pipeline.orchestrator as orch

    real_check = orch._check_cancel

    def slow_check(job):
        real_check(job)
        time.sleep(0.8)  # stretch the pipeline so cancel lands mid-run

    monkeypatch.setattr(orch, "_check_cancel", slow_check)
    sid = _upload(client, {"enable_ai_review": False})
    # wait until the scan is actually running, then cancel
    for _ in range(30):
        if client.get(f"/api/scans/{sid}").json()["status"] == "running":
            break
        time.sleep(1)
    r = client.post(f"/api/scans/{sid}/cancel")
    assert r.status_code in (200, 409), r.text
    scan = _wait(client, sid)
    assert scan["status"] == "cancelled", f"got {scan['status']}"


def test_export_formats(client):
    sid = _upload(client, {"enable_ai_review": False})
    _wait(client, sid)
    r = client.get(f"/api/scans/{sid}/report.json")
    assert r.status_code == 200
    data = r.json()
    assert data["total_findings"] >= 10  # fixture APK alone yields ~21 findings
    assert data["format_version"] == "1.0"
    r = client.get(f"/api/scans/{sid}/report.html")
    assert r.status_code == 200 and "Blindspot" in r.text
    # self-contained: no external stylesheets, scripts, images or fonts
    for tag in ('<link ', '<script src="http', "<img src=\"http", "@import url(http"):
        assert tag not in r.text, f"external resource reference found: {tag}"
    r = client.get(f"/api/scans/{sid}/report.pdf")
    assert r.status_code == 200
    assert r.content[:5] == b"%PDF-"


def test_delete_scan(client):
    sid = _upload(client, {"enable_ai_review": False})
    _wait(client, sid)
    r = client.delete(f"/api/scans/{sid}")
    assert r.status_code in (200, 204), r.text
    assert client.get(f"/api/scans/{sid}").status_code == 404


def test_rules_and_system_endpoints(client):
    rules = client.get("/api/rules").json()
    assert len(rules) >= 100
    assert all(r["id"].startswith("BS-") for r in rules)
    owasp = {o for r in rules for o in r["owasp"]}
    assert owasp <= {f"M{i}" for i in range(1, 11)}, owasp
    assert owasp, "rules should cover several OWASP Mobile Top 10 categories"
    sys = client.get("/api/system/status").json()
    assert "tools" in sys and "mobsfscan" in sys["tools"]
    assert "semgrep" not in sys["tools"], "semgrep was removed in v5"


def test_v2_scan_log_and_config(client):
    sid = _upload(client, {"enable_ai_review": False})
    scan = _wait(client, sid)
    assert scan["status"] == "completed", scan.get("error")
    # scan summary carries the effective config (no more "AI skipped?" mystery)
    assert scan["scan_config"]["enable_ai_review"] is False
    # per-scan troubleshooting log
    r = client.get(f"/api/scans/{sid}/log")
    assert r.status_code == 200, r.text
    events = r.json()["events"]
    assert len(events) >= 5, f"expected a populated scan log, got {len(events)}"
    sources = {e["source"] for e in events}
    assert "scan" in sources and "decompile" in sources, sources
    assert any("Scan started" in e["message"] for e in events)
    assert any("Scan completed" in e["message"] for e in events)
    assert all(e["level"] in ("info", "warn", "error") for e in events)
    # log for unknown scan -> 404
    assert client.get("/api/scans/does-not-exist/log").status_code == 404
    # JSON export embeds the event log
    data = client.get(f"/api/scans/{sid}/report.json").json()
    assert "event_log" in data and len(data["event_log"]) >= 5


def test_v2_system_status_pdf(client):
    sys = client.get("/api/system/status").json()
    assert "pdf" in sys and isinstance(sys["pdf"]["available"], bool)


def test_v4_pdf_report_renders(client):
    """PDF export works with zero system setup (ReportLab, pure Python)."""
    sid = _upload(client, {"enable_ai_review": False})
    _wait(client, sid)
    r = client.get(f"/api/scans/{sid}/report.pdf")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-", "not a real PDF document"
    assert len(r.content) > 5000, "PDF suspiciously small"


def test_v4_html_report_sections_and_metadata(client):
    sid = _upload(client, {"enable_ai_review": False})
    _wait(client, sid)
    html = client.get(f"/api/scans/{sid}/report.html").text
    # dedicated AI section
    assert 'id="ai-review"' in html
    assert "AI review" in html
    # cover metadata: app name, SDK, size, author credit
    assert "App name" in html
    assert "SDK (min / target)" in html
    assert "Developed by" in html and "shuuubhraj" in html


def test_v4_system_status_pdf_always_available(client):
    sys = client.get("/api/system/status").json()
    assert sys["pdf"]["available"] is True


def test_spa_fallback_serves_index(client):
    """Client-side routes serve the SPA shell; API 404s stay JSON."""
    for path in ("/history", "/scans/abc123", "/scans/abc123/findings"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert "text/html" in r.headers["content-type"]
        assert "Blindspot" in r.text
    r = client.get("/api/scans/does-not-exist")
    assert r.status_code == 404
    assert r.headers["content-type"] == "application/json"


def test_hotfix7_progress_events_carry_feed_messages(client, monkeypatch):
    """Every pipeline stage must emit progress events with a human-readable
    message, so the Live Scan 'Behind the scenes' feed is alive from the
    first second (hotfix-7: the feed used to stay empty until AI review)."""
    import blindspot.pipeline.orchestrator as orch

    seen = []
    real_emit = orch.emit

    def spy(scan_id, event, data):
        if event == "progress":
            seen.append(dict(data))
        return real_emit(scan_id, event, data)

    monkeypatch.setattr(orch, "emit", spy)
    sid = _upload(client, {"enable_ai_review": False})
    scan = _wait(client, sid)
    assert scan["status"] == "completed", scan.get("error")

    by_stage: dict = {}
    for d in seen:
        by_stage.setdefault(d.get("stage"), []).append(d)
    assert seen, "no progress events captured at all"
    for stage in ("validate", "extract", "metadata", "decompile",
                  "mobsfscan", "custom_rules", "normalize", "finalize"):
        assert stage in by_stage, f"no progress events for stage {stage}"
        assert any(d.get("message") for d in by_stage[stage]), \
            f"stage {stage} never sent a feed message"
