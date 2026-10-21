"""Unit tests for BS-W01 .. BS-W15 (webview_rules).

Each rule is tested against a vulnerable fixture (expected status) and a
secure alternative (expected PASS), plus a NOT_APPLICABLE case with no
java_roots.
"""

from __future__ import annotations

from pathlib import Path

# The registry imports every category module; sibling modules may not exist
# yet in this repo snapshot, so stub the missing ones to avoid a hard import
# failure. Stubs are only installed when the real import fails.
try:
    from blindspot.rules import webview_rules as wr
except ImportError:  # pragma: no cover - repo assembly race
    import sys
    import types

    for _name in ("manifest_rules", "storage_rules", "network_rules",
                  "crypto_rules", "auth_rules", "platform_rules"):
        _full = f"blindspot.rules.{_name}"
        if _full not in sys.modules:
            _mod = types.ModuleType(_full)
            _mod.RULES = []
            sys.modules[_full] = _mod
    from blindspot.rules import webview_rules as wr

from blindspot.rules.base import (
    Component,
    ManifestData,
    RuleStatus,
    ScanContext,
    Severity,
)


def make_ctx(tmp_path: Path) -> ScanContext:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    return ScanContext(
        scan_id="test",
        workdir=tmp_path,
        apk_path=tmp_path / "app.apk",
        java_roots=[src],
    )


def write(ctx: ScanContext, name: str, code: str) -> None:
    path = ctx.java_roots[0] / name
    path.write_text(code, encoding="utf-8")


def run(rule, ctx):
    return rule.run(ctx)


# ---------------------------------------------------------------------------
# BS-W01
# ---------------------------------------------------------------------------

def test_w01_escalated_to_high(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        import android.webkit.WebView;
        public class A {
            void f(WebView w) {
                w.getSettings().setJavaScriptEnabled(true);
                w.addJavascriptInterface(new Object(), "b");
            }
        }
    """)
    r = run(wr.RULES[0], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert r.evidence[0].line_start == 5


def test_w01_medium_alone(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebView w) {
                w.getSettings().setJavaScriptEnabled(true);
            }
        }
    """)
    r = run(wr.RULES[0], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM


def test_w01_disabled_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "public class A { void f() { s.setJavaScriptEnabled(false); } }\n")
    assert run(wr.RULES[0], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W02
# ---------------------------------------------------------------------------

def test_w02_dangerous_bridge_high(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "Bridge.java", """
        public class Bridge {
            public void runCmd(String c) {
                try { Runtime.getRuntime().exec(c); } catch (Exception e) {}
            }
        }
    """)
    write(ctx, "Main.java", """
        public class Main {
            void f(android.webkit.WebView w) {
                w.addJavascriptInterface(new Bridge(), "bridge");
            }
        }
    """)
    r = run(wr.RULES[1], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH


def test_w02_benign_bridge_medium(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "Bridge.java", """
        public class Bridge {
            public String hello() { return "hi"; }
        }
    """)
    write(ctx, "Main.java", """
        public class Main {
            void f(android.webkit.WebView w) {
                w.addJavascriptInterface(new Bridge(), "bridge");
            }
        }
    """)
    r = run(wr.RULES[1], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM


def test_w02_no_bridge_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "Main.java", "public class Main { void f() {} }\n")
    assert run(wr.RULES[1], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W03
# ---------------------------------------------------------------------------

def test_w03_universal_access_high(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebSettings s) {
                s.setAllowUniversalAccessFromFileURLs(true);
            }
        }
    """)
    r = run(wr.RULES[2], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH


def test_w03_file_access_medium(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebSettings s) {
                s.setAllowFileAccess(true);
            }
        }
    """)
    r = run(wr.RULES[2], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM


def test_w03_disabled_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "public class A { void f() { s.setAllowFileAccess(false); } }\n")
    assert run(wr.RULES[2], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W04
# ---------------------------------------------------------------------------

def test_w04_http_finding(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebView w) {
                w.loadUrl("http://example.com/page");
            }
        }
    """)
    r = run(wr.RULES[3], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM


def test_w04_dynamic_needs_review(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebView w, String path) {
                w.loadUrl("https://example.com/" + path);
            }
        }
    """)
    r = run(wr.RULES[3], ctx)
    assert r.status == RuleStatus.NEEDS_REVIEW


def test_w04_constant_https_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebView w) {
                w.loadUrl("https://example.com/page");
            }
        }
    """)
    assert run(wr.RULES[3], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W05
# ---------------------------------------------------------------------------

def test_w05_no_override_needs_review(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebView w, String url) {
                w.loadUrl(url);
            }
        }
    """)
    assert run(wr.RULES[4], ctx).status == RuleStatus.NEEDS_REVIEW


def test_w05_override_present_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        import android.webkit.WebViewClient;
        public class A extends WebViewClient {
            @Override
            public boolean shouldOverrideUrlLoading(android.webkit.WebView v, String u) {
                return u.startsWith("https://example.com");
            }
            void f(android.webkit.WebView w, String url) { w.loadUrl(url); }
        }
    """)
    assert run(wr.RULES[4], ctx).status == RuleStatus.PASS


def test_w05_constant_url_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebView w) { w.loadUrl("https://example.com"); }
        }
    """)
    assert run(wr.RULES[4], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W06
# ---------------------------------------------------------------------------

def test_w06_always_allow_finding(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebSettings s) {
                s.setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
            }
        }
    """)
    r = run(wr.RULES[5], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM


def test_w06_never_allow_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebSettings s) {
                s.setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW);
            }
        }
    """)
    assert run(wr.RULES[5], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W07
# ---------------------------------------------------------------------------

def test_w07_concat_needs_review(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebView w, String token) {
                w.evaluateJavascript("javascript:setToken('" + token + "')", null);
            }
        }
    """)
    assert run(wr.RULES[6], ctx).status == RuleStatus.NEEDS_REVIEW


def test_w07_constant_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebView w) {
                w.evaluateJavascript("javascript:doInit()", null);
            }
        }
    """)
    assert run(wr.RULES[6], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W08
# ---------------------------------------------------------------------------

def test_w08_concat_finding(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        import android.database.Cursor;
        public class A {
            void f(android.database.sqlite.SQLiteDatabase db, String id) {
                Cursor c = db.rawQuery("SELECT * FROM users WHERE id = '" + id + "'", null);
            }
        }
    """)
    r = run(wr.RULES[7], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert "CWE-89" in r.cwe


def test_w08_parameterized_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        import android.database.Cursor;
        public class A {
            void f(android.database.sqlite.SQLiteDatabase db, String id) {
                Cursor c = db.rawQuery("SELECT * FROM users WHERE id = ?", new String[]{id});
            }
        }
    """)
    assert run(wr.RULES[7], ctx).status == RuleStatus.PASS


def test_w08_format_finding(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.database.sqlite.SQLiteDatabase db, String name) {
                db.execSQL(String.format("DELETE FROM t WHERE name='%s'", name));
            }
        }
    """)
    assert run(wr.RULES[7], ctx).status == RuleStatus.FINDING


# ---------------------------------------------------------------------------
# BS-W09
# ---------------------------------------------------------------------------

def test_w09_concat_finding(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(String target) {
                try { Runtime.getRuntime().exec("ping -c 1 " + target); }
                catch (Exception e) {}
            }
        }
    """)
    r = run(wr.RULES[8], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert "CWE-78" in r.cwe


def test_w09_constant_array_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f() {
                try { Runtime.getRuntime().exec(new String[]{"ls", "-l"}); }
                catch (Exception e) {}
            }
        }
    """)
    assert run(wr.RULES[8], ctx).status == RuleStatus.PASS


def test_w09_constant_string_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f() {
                try { Runtime.getRuntime().exec("id"); }
                catch (Exception e) {}
            }
        }
    """)
    assert run(wr.RULES[8], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W10
# ---------------------------------------------------------------------------

def test_w10_intent_input_needs_review(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        import java.io.File;
        public class A {
            void f(android.content.Intent i) {
                String name = i.getStringExtra("name");
                File f = new File(getFilesDir(), name);
            }
            java.io.File getFilesDir() { return null; }
        }
    """)
    r = run(wr.RULES[9], ctx)
    assert r.status == RuleStatus.NEEDS_REVIEW
    assert "CWE-22" in r.cwe


def test_w10_no_intent_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        import java.io.File;
        public class A {
            void f(String name) {
                File f = new File(getFilesDir(), name);
            }
            java.io.File getFilesDir() { return null; }
        }
    """)
    assert run(wr.RULES[9], ctx).status == RuleStatus.PASS


def test_w10_constant_name_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        import java.io.File;
        public class A {
            void f(android.content.Intent i) {
                String unused = i.getStringExtra("x");
                File f = new File(getFilesDir(), "fixed.txt");
            }
            java.io.File getFilesDir() { return null; }
        }
    """)
    assert run(wr.RULES[9], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W11
# ---------------------------------------------------------------------------

def test_w11_deserialization_finding(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        import java.io.*;
        public class A {
            Object f(InputStream in) throws Exception {
                ObjectInputStream ois = new ObjectInputStream(in);
                return ois.readObject();
            }
        }
    """)
    r = run(wr.RULES[10], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM
    assert "CWE-502" in r.cwe


def test_w11_no_deserialization_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "public class A { void f() {} }\n")
    assert run(wr.RULES[10], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W12
# ---------------------------------------------------------------------------

def test_w12_external_storage_high(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        import dalvik.system.DexClassLoader;
        public class A {
            void f() {
                String p = android.os.Environment.getExternalStorageDirectory() + "/plug.dex";
                new DexClassLoader(p, "/data/out", null, getClass().getClassLoader());
            }
        }
    """)
    r = run(wr.RULES[11], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH


def test_w12_variable_path_needs_review(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        import dalvik.system.PathClassLoader;
        public class A {
            void f(String dexPath) {
                new PathClassLoader(dexPath, getClass().getClassLoader());
            }
        }
    """)
    assert run(wr.RULES[11], ctx).status == RuleStatus.NEEDS_REVIEW


def test_w12_constant_path_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        import dalvik.system.DexClassLoader;
        public class A {
            void f() {
                new DexClassLoader("/data/app/plugin.dex", "/data/out", null, getClass().getClassLoader());
            }
        }
    """)
    assert run(wr.RULES[11], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W13
# ---------------------------------------------------------------------------

def test_w13_reflection_needs_review(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f() throws Exception {
                java.lang.reflect.Method m = Runtime.class.getDeclaredMethod("exec", String.class);
                m.invoke(Runtime.getRuntime(), "id");
            }
        }
    """)
    assert run(wr.RULES[12], ctx).status == RuleStatus.NEEDS_REVIEW


def test_w13_plain_reflection_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f() throws Exception {
                java.lang.reflect.Method m = String.class.getDeclaredMethod("length");
                m.invoke("hello");
            }
        }
    """)
    assert run(wr.RULES[12], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W14
# ---------------------------------------------------------------------------

def test_w14_info_finding(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebSettings s) {
                s.setDomStorageEnabled(true);
                String password = "s3cret";
                s.setAllowFileAccessFromFileURLs(true);
                s.setGeolocationEnabled(true);
                w.loadUrl(i.getStringExtra("target"));
                w.loadUrl("file:///android_asset/index.html");
                s.setSavePassword(true);
                android.webkit.CookieManager.getInstance().setAcceptThirdPartyCookies(w, true);
                s.setDatabaseEnabled(true);
            }
        }
    """)
    r = run(wr.RULES[13], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.INFO


def test_w14_absent_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "public class A { void f() {} }\n")
    assert run(wr.RULES[13], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-W15
# ---------------------------------------------------------------------------

def test_w15_bridge_sink_high(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "Bridge.java", """
        import android.webkit.JavascriptInterface;
        public class Bridge {
            @JavascriptInterface
            public void run(String cmd) {
                try { Runtime.getRuntime().exec(cmd); } catch (Exception e) {}
            }
        }
    """)
    r = run(wr.RULES[14], ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert r.evidence[0].line_start == 4  # the @JavascriptInterface line


def test_w15_benign_bridge_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "Bridge.java", """
        import android.webkit.JavascriptInterface;
        public class Bridge {
            @JavascriptInterface
            public String version() { return "1.0"; }
        }
    """)
    assert run(wr.RULES[14], ctx).status == RuleStatus.PASS


def test_w15_sink_outside_bridge_passes(tmp_path):
    # Sensitive sink exists but NOT inside the @JavascriptInterface method.
    ctx = make_ctx(tmp_path)
    write(ctx, "Bridge.java", """
        import android.webkit.JavascriptInterface;
        public class Bridge {
            @JavascriptInterface
            public String version() { return "1.0"; }
            public void helper(String cmd) {
                try { Runtime.getRuntime().exec(cmd); } catch (Exception e) {}
            }
        }
    """)
    assert run(wr.RULES[14], ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# NOT_APPLICABLE + registry invariants
# ---------------------------------------------------------------------------

def test_not_applicable_without_java_roots(tmp_path):
    ctx = ScanContext(scan_id="t", workdir=tmp_path, apk_path=tmp_path / "a.apk", java_roots=[])
    for rule in wr.RULES:
        r = rule.run(ctx)
        assert r.status == RuleStatus.NOT_APPLICABLE, rule.id


def test_rule_ids_unique_and_count(tmp_path):
    ids = [r.id for r in wr.RULES]
    assert len(ids) == 30
    assert ids == [f"BS-W{i:02d}" for i in range(1, 31)]
    assert len(set(ids)) == 30
    for rule in wr.RULES:
        assert rule.category == "webview"
        for tag in rule.owasp:
            assert tag in {f"M{i}" for i in range(1, 11)}, rule.id
        for cwe in rule.cwe:
            assert cwe.startswith("CWE-"), rule.id
        allowed_masvs = {"MSTG-STORAGE", "MSTG-CRYPTO", "MSTG-AUTH", "MSTG-NETWORK",
                         "MSTG-PLATFORM", "MSTG-CODE", "MSTG-RESILIENCE"}
        for m in rule.masvs:
            assert m in allowed_masvs, rule.id


def test_all_results_carry_rationales(tmp_path):
    ctx = make_ctx(tmp_path)
    ctx.manifest = ManifestData(
        package="com.example",
        activities=[Component(kind="activity", name=".Main", exported=True)],
        raw_xml=(
            "<manifest>\n"
            "  <application>\n"
            '    <activity android:name=".Main" android:exported="true" />\n'
            "  </application>\n"
            "</manifest>"
        ),
    )
    write(ctx, "All.java", """
        import android.webkit.WebView; import android.webkit.WebSettings;
        import java.io.*; import dalvik.system.DexClassLoader;
        import android.webkit.JavascriptInterface;
        public class All {
            void f(WebView w, WebSettings s, String x, android.content.Intent i,
                   android.database.sqlite.SQLiteDatabase db, InputStream in) throws Exception {
                s.setJavaScriptEnabled(true);
                w.addJavascriptInterface(new Bridge(), "b");
                s.setAllowFileAccess(true);
                s.setAllowUniversalAccessFromFileURLs(true);
                w.loadUrl("http://e.com/" + x);
                w.loadUrl(x);
                s.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
                w.evaluateJavascript("j('" + x + "')", null);
                db.rawQuery("SELECT * FROM t WHERE a='" + x + "'", null);
                Runtime.getRuntime().exec("ping " + x);
                String n = i.getStringExtra("n");
                File f2 = new File(getFilesDir(), n);
                ObjectInputStream o = new ObjectInputStream(in); o.readObject();
                new DexClassLoader(x, "/o", null, getClass().getClassLoader());
                Runtime.class.getDeclaredMethod("exec", String.class).invoke(Runtime.getRuntime(), x);
                s.setDomStorageEnabled(true);
                String password = "s3cret";
                s.setAllowFileAccessFromFileURLs(true);
                s.setGeolocationEnabled(true);
                w.loadUrl(i.getStringExtra("target"));
                w.loadUrl("file:///android_asset/index.html");
                s.setSavePassword(true);
                android.webkit.CookieManager.getInstance().setAcceptThirdPartyCookies(w, true);
                s.setDatabaseEnabled(true);
            }
            java.io.File getFilesDir() { return null; }
        }
        class Bridge {
            @JavascriptInterface
            public void run(String c) { try { Runtime.getRuntime().exec(c); } catch (Exception e) {} }
            public void helper(String c) { try { Runtime.getRuntime().exec(c); } catch (Exception e) {} }
        }
        class VClient extends android.webkit.WebViewClient {
            public void onReceivedSslError(android.webkit.WebView v, android.webkit.SslErrorHandler h, android.net.http.SslError e) { h.proceed(); }
        }
    """)
    for rule in wr.RULES:
        r = rule.run(ctx)
        assert r.status in (RuleStatus.FINDING, RuleStatus.NEEDS_REVIEW), (rule.id, r.status)
        assert r.severity is not None, rule.id
        assert r.confidence is not None, rule.id
        assert r.severity_rationale, rule.id
        assert r.confidence_rationale, rule.id
        for ev in r.evidence:
            assert ev.line_start is not None and ev.line_start >= 1, rule.id


# ---------------------------------------------------------------------------
# BS-W16 .. BS-W30 (appended)
# ---------------------------------------------------------------------------

_w_by_id = {r.id: r for r in wr.RULES}


def _wtest(rule_id, ctx):
    return _w_by_id[rule_id].run(ctx)


def test_w16_file_access_true(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setAllowFileAccess(true); } }\n")
    r = _wtest("BS-W16", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH


def test_w16_file_access_false_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setAllowFileAccess(false); } }\n")
    assert _wtest("BS-W16", ctx).status == RuleStatus.PASS


def test_w17_universal_access_true(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setAllowUniversalAccessFromFileURLs(true); } }\n")
    r = _wtest("BS-W17", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH


def test_w17_absent_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setJavaScriptEnabled(true); } }\n")
    assert _wtest("BS-W17", ctx).status == RuleStatus.PASS


def test_w18_mixed_content_always_allow(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW); } }\n")
    r = _wtest("BS-W18", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM


def test_w18_never_allow_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW); } }\n")
    assert _wtest("BS-W18", ctx).status == RuleStatus.PASS


def test_w19_dom_storage_with_secret_keyword(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A {\n  void f(android.webkit.WebSettings s) {\n    s.setDomStorageEnabled(true);\n    String password = \"x\";\n  }\n}\n")
    r = _wtest("BS-W19", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM


def test_w19_dom_storage_alone_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setDomStorageEnabled(true); } }\n")
    assert _wtest("BS-W19", ctx).status == RuleStatus.PASS


def test_w20_geolocation_no_check(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setGeolocationEnabled(true); } }\n")
    r = _wtest("BS-W20", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.LOW


def test_w20_geolocation_with_check_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A {\n  void f(android.webkit.WebSettings s) {\n    if (checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION) == 0) {\n      s.setGeolocationEnabled(true);\n    }\n  }\n}\n")
    assert _wtest("BS-W20", ctx).status == RuleStatus.PASS


def test_w21_bridge_with_http_load(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebView w) {
                w.addJavascriptInterface(new Object(), "b");
                w.loadUrl("http://example.com/page");
            }
        }
    """)
    r = _wtest("BS-W21", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH


def test_w21_bridge_with_https_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", """
        public class A {
            void f(android.webkit.WebView w) {
                w.addJavascriptInterface(new Object(), "b");
                w.loadUrl("https://example.com/page");
            }
        }
    """)
    assert _wtest("BS-W21", ctx).status == RuleStatus.PASS


def test_w22_loadurl_intent_extra(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebView w, android.content.Intent i) { w.loadUrl(i.getStringExtra(\"u\")); } }\n")
    r = _wtest("BS-W22", ctx)
    assert r.status == RuleStatus.NEEDS_REVIEW
    assert r.severity == Severity.HIGH


def test_w22_constant_url_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebView w) { w.loadUrl(\"https://example.com\"); } }\n")
    assert _wtest("BS-W22", ctx).status == RuleStatus.PASS


def test_w23_file_url_load(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebView w) { w.loadUrl(\"file:///android_asset/x.html\"); } }\n")
    r = _wtest("BS-W23", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM


def test_w23_https_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebView w) { w.loadUrl(\"https://example.com\"); } }\n")
    assert _wtest("BS-W23", ctx).status == RuleStatus.PASS


def test_w24_exported_activity_with_js(tmp_path):
    ctx = make_ctx(tmp_path)
    ctx.manifest = ManifestData(
        package="com.example",
        activities=[Component(kind="activity", name=".Main", exported=True)],
    )
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setJavaScriptEnabled(true); } }\n")
    r = _wtest("BS-W24", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH


def test_w24_not_exported_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    ctx.manifest = ManifestData(
        package="com.example",
        activities=[Component(kind="activity", name=".Main", exported=False)],
    )
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setJavaScriptEnabled(true); } }\n")
    assert _wtest("BS-W24", ctx).status == RuleStatus.PASS


def test_w24_no_manifest_not_applicable(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setJavaScriptEnabled(true); } }\n")
    assert _wtest("BS-W24", ctx).status == RuleStatus.NOT_APPLICABLE


def test_w25_http_loadurl(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebView w) { w.loadUrl(\"http://example.com/\"); } }\n")
    r = _wtest("BS-W25", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM


def test_w25_https_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebView w) { w.loadUrl(\"https://example.com/\"); } }\n")
    assert _wtest("BS-W25", ctx).status == RuleStatus.PASS


def test_w26_save_password_true(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setSavePassword(true); } }\n")
    r = _wtest("BS-W26", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.LOW


def test_w26_save_password_false_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setSavePassword(false); } }\n")
    assert _wtest("BS-W26", ctx).status == RuleStatus.PASS


def test_w27_third_party_cookies_true(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebView w) { android.webkit.CookieManager.getInstance().setAcceptThirdPartyCookies(w, true); } }\n")
    r = _wtest("BS-W27", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.LOW


def test_w27_third_party_cookies_false_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebView w) { android.webkit.CookieManager.getInstance().setAcceptThirdPartyCookies(w, false); } }\n")
    assert _wtest("BS-W27", ctx).status == RuleStatus.PASS


def test_w28_ssl_error_proceed(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "C.java", """
        class C extends android.webkit.WebViewClient {
            public void onReceivedSslError(android.webkit.WebView v, android.webkit.SslErrorHandler h, android.net.http.SslError e) {
                h.proceed();
            }
        }
    """)
    r = _wtest("BS-W28", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM


def test_w28_ssl_error_cancel_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "C.java", """
        class C extends android.webkit.WebViewClient {
            public void onReceivedSslError(android.webkit.WebView v, android.webkit.SslErrorHandler h, android.net.http.SslError e) {
                h.cancel();
            }
        }
    """)
    assert _wtest("BS-W28", ctx).status == RuleStatus.PASS


def test_w29_database_enabled_true(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setDatabaseEnabled(true); } }\n")
    r = _wtest("BS-W29", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.LOW


def test_w29_database_enabled_false_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "A.java", "class A { void f(android.webkit.WebSettings s) { s.setDatabaseEnabled(false); } }\n")
    assert _wtest("BS-W29", ctx).status == RuleStatus.PASS


def test_w30_unannotated_bridge_sink(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "Bridge2.java", """
        public class Bridge2 {
            public void doSecret(String c) {
                try { Runtime.getRuntime().exec(c); } catch (Exception e) {}
            }
        }
    """)
    write(ctx, "Main.java", """
        public class Main {
            void f(android.webkit.WebView w) { w.addJavascriptInterface(new Bridge2(), "b2"); }
        }
    """)
    r = _wtest("BS-W30", ctx)
    assert r.status == RuleStatus.NEEDS_REVIEW
    assert r.severity == Severity.MEDIUM


def test_w30_fully_annotated_passes(tmp_path):
    ctx = make_ctx(tmp_path)
    write(ctx, "Bridge3.java", """
        public class Bridge3 {
            @android.webkit.JavascriptInterface
            public void run(String c) {
                try { Runtime.getRuntime().exec(c); } catch (Exception e) {}
            }
        }
    """)
    write(ctx, "Main.java", """
        public class Main {
            void f(android.webkit.WebView w) { w.addJavascriptInterface(new Bridge3(), "b3"); }
        }
    """)
    assert _wtest("BS-W30", ctx).status == RuleStatus.PASS
