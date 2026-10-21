"""Unit tests for AI review file selection: library exclusion and
first-party prioritization (no Ollama needed)."""
from pathlib import Path

from blindspot.ai.review import _is_library, select_review_files
from blindspot.rules.base import ManifestData, ScanContext


def _ctx(tmp_path: Path, package: str = "com.example.app") -> ScanContext:
    # app code
    app_dir = tmp_path / "src" / "com" / "example" / "app"
    app_dir.mkdir(parents=True)
    (app_dir / "LoginActivity.java").write_text(
        "class LoginActivity { String password = \"x\"; }")
    # library code bundled in the APK
    lib_dir = tmp_path / "src" / "android" / "support" / "v4" / "app"
    lib_dir.mkdir(parents=True)
    (lib_dir / "NotificationCompat.java").write_text(
        "class NotificationCompat { PendingIntent pi; String password; }")
    ctx = ScanContext(scan_id="t", workdir=tmp_path,
                      apk_path=tmp_path / "a.apk")
    ctx.java_roots = [tmp_path / "src"]
    ctx.manifest = ManifestData(package=package)
    return ctx


def test_library_files_excluded(tmp_path):
    ctx = _ctx(tmp_path)
    files, stats = select_review_files(ctx)
    rels = [p.relative_to(tmp_path / "src").as_posix() for p, _ in files]
    assert not any(r.startswith("android/support/") for r in rels), rels
    assert any("LoginActivity.java" in r for r in rels), rels
    assert stats["library_files_skipped"] >= 1
    assert stats["fallback_to_libraries"] is False


def test_fallback_when_only_libraries(tmp_path):
    lib_dir = tmp_path / "src" / "okhttp3"
    lib_dir.mkdir(parents=True)
    (lib_dir / "OkHttpClient.java").write_text(
        "class OkHttpClient { String token = \"x\"; }")
    ctx = ScanContext(scan_id="t", workdir=tmp_path,
                      apk_path=tmp_path / "a.apk")
    ctx.java_roots = [tmp_path / "src"]
    ctx.manifest = ManifestData(package="com.example.app")
    files, stats = select_review_files(ctx)
    assert len(files) == 1  # fallback reviews the library file, not nothing
    assert stats["fallback_to_libraries"] is True


def test_is_library_prefixes():
    assert _is_library("android/support/v4/app/Foo.java")
    assert _is_library("androidx/core/app/Bar.java")
    assert _is_library("okhttp3/OkHttpClient.java")
    assert _is_library("kotlin/collections/X.kt")
    assert not _is_library("com/example/app/LoginActivity.java")
    assert not _is_library("jakhar/aseem/diva/MainActivity.java")


def _norm_ctx(tmp_path: Path) -> ScanContext:
    src = tmp_path / "src" / "com" / "example" / "app"
    src.mkdir(parents=True)
    (src / "LoginActivity.java").write_text(
        "class LoginActivity { String password = \"x\"; }")
    ctx = ScanContext(scan_id="t", workdir=tmp_path,
                      apk_path=tmp_path / "a.apk")
    ctx.java_roots = [tmp_path / "src"]
    ctx.manifest = ManifestData(package="com.example.app")
    return ctx


def test_validate_ai_finding_bans_em_dashes(tmp_path):
    """Model output with em-dashes must be sanitized (house style bans them)."""
    from blindspot.ai.review import validate_ai_finding
    ctx = _norm_ctx(tmp_path)
    raw = {
        "title": "Hardcoded secret \u2014 API key",
        "description": "The key is embedded \u2014 never do this.",
        "why_unsafe": "Anyone can read it \u2014 trivial extraction.",
        "impact": "Account takeover.",
        "preconditions": "Decompile the APK \u2014 jadx works.",
        "remediation": "Move to server \u2014 use vault.",
        "file_path": "src/com/example/app/LoginActivity.java",
        "line_start": 1, "line_end": 1,
        "code": "String password = \"x\";",
        "confidence": 0.9,
    }
    out = validate_ai_finding(raw, ctx)
    assert out is not None
    for key in ("title", "description", "impact", "remediation", "snippet"):
        assert "\u2014" not in out[key], key
        assert "\u2013" not in out[key], key


def test_validate_ai_finding_composes_rich_description(tmp_path):
    """why_unsafe and preconditions fold into description as labeled sections."""
    from blindspot.ai.review import validate_ai_finding
    ctx = _norm_ctx(tmp_path)
    raw = {
        "title": "Hardcoded secret",
        "description": "An API key is hardcoded.",
        "why_unsafe": "Anyone with the APK can extract it.",
        "preconditions": "Attacker decompiles the APK.",
        "file_path": "src/com/example/app/LoginActivity.java",
        "line_start": 1, "line_end": 1,
        "code": "String password = \"x\";",
        "confidence": 0.9,
    }
    out = validate_ai_finding(raw, ctx)
    assert out is not None
    assert "An API key is hardcoded." in out["description"]
    assert "Why this is unsafe:" in out["description"]
    assert "Anyone with the APK can extract it." in out["description"]
    assert "Preconditions:" in out["description"]
    assert "why_unsafe" not in out  # dropped keys must not leak into the record
    assert "preconditions" not in out


def test_validate_ai_finding_omits_empty_sections(tmp_path):
    from blindspot.ai.review import validate_ai_finding
    ctx = _norm_ctx(tmp_path)
    raw = {
        "title": "Hardcoded secret",
        "description": "An API key is hardcoded.",
        "file_path": "src/com/example/app/LoginActivity.java",
        "line_start": 1, "line_end": 1,
        "code": "String password = \"x\";",
        "confidence": 0.9,
    }
    out = validate_ai_finding(raw, ctx)
    assert out is not None
    assert out["description"] == "An API key is hardcoded."


# ---------------------------------------------------------------------------
# Snippet-targeted review selection
# ---------------------------------------------------------------------------

from blindspot.ai.review import (
    _merge_windows,
    _pattern_hit_lines,
    build_snippet_prompt,
    select_review_snippets,
)


def _snippet_ctx(tmp_path: Path) -> ScanContext:
    app_dir = tmp_path / "src" / "com" / "example" / "app"
    app_dir.mkdir(parents=True)
    lines = [f"// filler line {i}" for i in range(1, 101)]
    lines[49] = 'String password = "hunter2"; // line 50'
    lines[79] = 'webView.loadUrl(url); // line 80'
    (app_dir / "Main.java").write_text("\n".join(lines))
    ctx = ScanContext(scan_id="t", workdir=tmp_path,
                      apk_path=tmp_path / "a.apk")
    ctx.java_roots = [tmp_path / "src"]
    ctx.manifest = ManifestData(package="com.example.app")
    return ctx


def test_pattern_hit_lines(tmp_path):
    ctx = _snippet_ctx(tmp_path)
    text = (tmp_path / "src" / "com" / "example" / "app" / "Main.java").read_text()
    hits = _pattern_hit_lines(text)
    assert 50 in hits and 80 in hits
    assert 10 not in hits


def test_merge_windows_overlapping():
    merged = _merge_windows([50, 55], radius=10, total_lines=200)
    assert merged == [(40, 65)]


def test_merge_windows_disjoint():
    merged = _merge_windows([50, 150], radius=10, total_lines=200)
    assert merged == [(40, 60), (140, 160)]


def test_merge_windows_clamped():
    merged = _merge_windows([5], radius=10, total_lines=200)
    assert merged == [(1, 15)]


def test_select_review_snippets(tmp_path):
    ctx = _snippet_ctx(tmp_path)
    snippets, stats = select_review_snippets(ctx, radius=5)
    assert len(snippets) == 2
    rels = {(s[0], s[1], s[2]) for s in snippets}
    assert any(r[1] == 45 and r[2] == 55 for r in rels)  # around line 50
    assert any(r[1] == 75 and r[2] == 85 for r in rels)  # around line 80
    assert stats["snippets_selected"] == 2


def test_snippet_prompt_has_absolute_lines(tmp_path):
    ctx = _snippet_ctx(tmp_path)
    snippets, _ = select_review_snippets(ctx, radius=5)
    prompt = build_snippet_prompt(snippets)
    assert "absolute lines 45-55" in prompt
    assert "absolute lines 75-85" in prompt
    assert "ABSOLUTE file line numbers" in prompt
