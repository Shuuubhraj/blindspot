"""Unit tests for blindspot.rules.network_rules (BS-N01 .. BS-N20).

ScanContext objects are built directly against tmp_path fixture files:
no APKs, no tools, no network. Each rule is tested in its vulnerable,
clean, and (where meaningful) NOT_APPLICABLE configurations.

The sibling rule modules (manifest_rules, storage_rules, ...) may not
exist yet while other modules are written in parallel, so the loader
below stubs any missing ones before importing the real registry.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
_RULES_DIR = _BACKEND / "blindspot" / "rules"
_SIBLINGS = (
    "manifest_rules", "storage_rules", "network_rules", "crypto_rules",
    "webview_rules", "auth_rules", "platform_rules",
)


def _load_rules_package():
    if "blindspot.rules.network_rules" in sys.modules:
        return sys.modules["blindspot.rules.network_rules"]
    pkg = types.ModuleType("blindspot.rules")
    pkg.__path__ = [str(_RULES_DIR)]
    sys.modules["blindspot.rules"] = pkg
    for name in _SIBLINGS:
        fullname = f"blindspot.rules.{name}"
        path = _RULES_DIR / f"{name}.py"
        if path.exists():
            spec = importlib.util.spec_from_file_location(fullname, str(path))
            mod = importlib.util.module_from_spec(spec)
            sys.modules[fullname] = mod
            spec.loader.exec_module(mod)
        else:  # sibling module not written yet: stub so registry imports
            stub = types.ModuleType(fullname)
            stub.RULES = []
            sys.modules[fullname] = stub
    # populate the package namespace like the real __init__ would
    for name in _SIBLINGS:
        setattr(pkg, name, sys.modules[f"blindspot.rules.{name}"])
    return sys.modules["blindspot.rules.network_rules"]


_net = _load_rules_package()
RULES = _net.RULES
_by_id = {r.id: r for r in RULES}

_base = sys.modules["blindspot.rules.base"]
ManifestData = _base.ManifestData
Permission = _base.Permission
ScanContext = _base.ScanContext
RuleStatus = _base.RuleStatus
Severity = _base.Severity


# ---------------------------------------------------------------------------
# Context builders
# ---------------------------------------------------------------------------

def make_ctx(tmp_path: Path, manifest=None, java_files: dict | None = None,
             res_files: dict | None = None, manifest_xml: str = "") -> ScanContext:
    workdir = tmp_path / "work"
    workdir.mkdir(exist_ok=True)
    src = workdir / "src"
    src.mkdir(exist_ok=True)
    java_roots = []
    if java_files:
        for rel, content in java_files.items():
            p = src / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        java_roots = [src]
    res_dir = None
    if res_files:
        res_dir = workdir / "res"
        for rel, content in res_files.items():
            p = res_dir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
    manifest_xml_path = None
    if manifest_xml:
        manifest_xml_path = workdir / "AndroidManifest.xml"
        manifest_xml_path.write_text(manifest_xml)
        if manifest is not None:
            manifest.raw_xml = manifest_xml
    return ScanContext(
        scan_id="test-scan",
        workdir=workdir,
        apk_path=workdir / "app.apk",
        manifest=manifest,
        manifest_xml_path=manifest_xml_path,
        java_roots=java_roots,
        res_dir=res_dir,
    )


def manifest_with(**kwargs) -> ManifestData:
    m = ManifestData(package="com.example.app")
    for k, v in kwargs.items():
        setattr(m, k, v)
    return m


def run(rule_id: str, ctx) -> object:
    return _by_id[rule_id].run(ctx)


def assert_rationales(result):
    assert result.severity_rationale, f"{result.rule_id}: missing severity_rationale"
    assert result.confidence_rationale, f"{result.rule_id}: missing confidence_rationale"


# ---------------------------------------------------------------------------
# Registry sanity
# ---------------------------------------------------------------------------

def test_rules_count_and_ids_unique():
    assert len(RULES) == 20
    ids = [r.id for r in RULES]
    assert ids == [f"BS-N{i:02d}" for i in range(1, 21)]
    assert all(r.category == "network" for r in RULES)


def test_all_findings_carry_rationales(tmp_path):
    # vulnerable fixture for every rule that can produce FINDING/NEEDS_REVIEW
    java = {
        "Vuln.java": "\n".join([
            "package com.example;",
            "import javax.net.ssl.*;",
            "class Vuln implements X509TrustManager {",
            "  public void checkServerTrusted(java.security.cert.X509Certificate[] c, String t) {}",
            "  public void checkClientTrusted(java.security.cert.X509Certificate[] c, String t) {}",
            "  public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }",
            "}",
            "class W {",
            "  void m() {",
            '    String u = "http://api.example.com/data";',
            '    String h = "https://api.example.com/login?token=abc";',
            "    HttpsURLConnection.setDefaultHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);",
            '    javax.net.ssl.SSLContext.getInstance("SSLv3");',
            "  }",
            "}",
        ])
    }
    m = manifest_with(
        uses_cleartext_traffic=True,
        permissions=[Permission(name="android.permission.INTERNET")],
        network_security_config="@xml/netsec",
    )
    res = {"xml/netsec.xml": (
        "<network-security-config>"
        '<base-config cleartextTrafficPermitted="true"/>'
        "</network-security-config>"
    )}
    ctx = make_ctx(tmp_path, manifest=m, java_files=java, res_files=res,
                   manifest_xml='<manifest><application android:usesCleartextTraffic="true"/></manifest>')
    for rule in RULES:
        res_ = rule.run(ctx)
        if res_.status in (RuleStatus.FINDING, RuleStatus.NEEDS_REVIEW):
            assert_rationales(res_)
            assert res_.severity is not None, rule.id


# ---------------------------------------------------------------------------
# BS-N01
# ---------------------------------------------------------------------------

def test_n01_vulnerable(tmp_path):
    m = manifest_with(uses_cleartext_traffic=True)
    xml = ('<manifest package="com.example">\n'
           '  <application android:usesCleartextTraffic="true">\n'
           '  </application>\n</manifest>')
    ctx = make_ctx(tmp_path, manifest=m, manifest_xml=xml)
    r = run("BS-N01", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert "M5" in r.owasp and "CWE-319" in r.cwe
    assert_rationales(r)
    ev = r.evidence[0]
    assert ev.line_start == 2  # real line of the attribute
    assert "usesCleartextTraffic" in ev.snippet


def test_n01_clean(tmp_path):
    ctx = make_ctx(tmp_path, manifest=manifest_with(uses_cleartext_traffic=False))
    r = run("BS-N01", ctx)
    assert r.status == RuleStatus.PASS


def test_n01_not_applicable(tmp_path):
    ctx = make_ctx(tmp_path, manifest=None)
    r = run("BS-N01", ctx)
    assert r.status == RuleStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# BS-N02
# ---------------------------------------------------------------------------

def test_n02_vulnerable_two_hosts(tmp_path):
    java = {"A.java": (
        "class A {\n"
        '  String a = "http://api.example.com/data";\n'
        '  String b = "http://evil.example.org/x";\n'
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N02", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM
    assert len(r.evidence) == 2  # one per distinct host
    assert_rationales(r)
    assert r.evidence[0].line_start == 2


def test_n02_clean_https_only(tmp_path):
    java = {"A.java": 'class A { String a = "https://api.example.com/data"; }\n'}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N02", ctx).status == RuleStatus.PASS


def test_n02_local_hosts_excluded(tmp_path):
    java = {"A.java": (
        "class A {\n"
        '  String a = "http://127.0.0.1:8080/api";\n'
        '  String b = "http://10.0.2.2/x";\n'
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N02", ctx).status == RuleStatus.PASS


def test_n02_not_applicable(tmp_path):
    ctx = make_ctx(tmp_path)
    assert run("BS-N02", ctx).status == RuleStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# BS-N03
# ---------------------------------------------------------------------------

_TRUST_ALL_JAVA = (
    "package com.example;\n"
    "import javax.net.ssl.X509TrustManager;\n"
    "class TrustAll implements X509TrustManager {\n"
    "  public void checkClientTrusted(java.security.cert.X509Certificate[] c, String t) {}\n"
    "  public void checkServerTrusted(java.security.cert.X509Certificate[] c, String t) {\n"
    "    // nothing here\n"
    "  }\n"
    "  public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }\n"
    "}\n"
)

def test_n03_vulnerable(tmp_path):
    ctx = make_ctx(tmp_path, java_files={"T.java": _TRUST_ALL_JAVA})
    r = run("BS-N03", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.CRITICAL
    assert "CWE-295" in r.cwe
    assert_rationales(r)


def test_n03_clean_real_verifier(tmp_path):
    java = {"T.java": (
        "class Strict implements javax.net.ssl.X509TrustManager {\n"
        "  public void checkServerTrusted(java.security.cert.X509Certificate[] c, String t)\n"
        "      throws java.security.cert.CertificateException {\n"
        "    defaultTm.checkServerTrusted(c, t);\n"
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N03", ctx).status == RuleStatus.PASS


def test_n03_not_applicable(tmp_path):
    ctx = make_ctx(tmp_path)
    assert run("BS-N03", ctx).status == RuleStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# BS-N04
# ---------------------------------------------------------------------------

def test_n04_allow_all_verifier(tmp_path):
    java = {"A.java": (
        "class A {\n"
        "  void m() {\n"
        "    HttpsURLConnection.setDefaultHostnameVerifier(\n"
        "        SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);\n"
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N04", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert "CWE-297" in r.cwe
    assert_rationales(r)


def test_n04_custom_verifier_returns_true(tmp_path):
    java = {"A.java": (
        "class Lenient implements javax.net.ssl.HostnameVerifier {\n"
        "  public boolean verify(String h, javax.net.ssl.SSLSession s) {\n"
        "    return true;\n"
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N04", ctx)
    assert r.status == RuleStatus.FINDING
    assert_rationales(r)


def test_n04_clean_strict_verifier(tmp_path):
    java = {"A.java": (
        "class Strict implements javax.net.ssl.HostnameVerifier {\n"
        "  public boolean verify(String h, javax.net.ssl.SSLSession s) {\n"
        '    return h.equals("api.example.com");\n'
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N04", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N05
# ---------------------------------------------------------------------------

def test_n05_vulnerable(tmp_path):
    java = {"W.java": (
        "class W extends android.webkit.WebViewClient {\n"
        "  public void onReceivedSslError(android.webkit.WebView v,\n"
        "      android.webkit.SslErrorHandler handler, android.net.http.SslError e) {\n"
        "    handler.proceed();\n"
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N05", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert "CWE-295" in r.cwe
    assert_rationales(r)
    assert r.evidence[0].line_start == 2


def test_n05_clean_cancel(tmp_path):
    java = {"W.java": (
        "class W extends android.webkit.WebViewClient {\n"
        "  public void onReceivedSslError(android.webkit.WebView v,\n"
        "      android.webkit.SslErrorHandler handler, android.net.http.SslError e) {\n"
        "    handler.cancel();\n"
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N05", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N06
# ---------------------------------------------------------------------------

def test_n06_vulnerable(tmp_path):
    java = {"A.java": (
        "class A {\n"
        "  void m(HttpsURLConnection c) {\n"
        "    c.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);\n"
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N06", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert_rationales(r)


def test_n06_clean_default_verifier(tmp_path):
    java = {"A.java": (
        "class A {\n"
        "  void m(HttpsURLConnection c) {\n"
        "    c.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());\n"
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N06", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N07
# ---------------------------------------------------------------------------

def test_n07_vulnerable_weak_protocols(tmp_path):
    java = {"A.java": (
        "class A {\n"
        '  void m() throws Exception { javax.net.ssl.SSLContext.getInstance("SSLv3"); }\n'
        '  void n() throws Exception { javax.net.ssl.SSLContext.getInstance("TLSv1"); }\n'
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N07", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM
    assert "CWE-327" in r.cwe
    assert len(r.evidence) == 2
    assert_rationales(r)


def test_n07_clean_modern_tls(tmp_path):
    java = {"A.java": (
        "class A {\n"
        '  void m() throws Exception { javax.net.ssl.SSLContext.getInstance("TLSv1.3"); }\n'
        '  void n(javax.net.ssl.SSLSocket s) { s.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"}); }\n'
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N07", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N08
# ---------------------------------------------------------------------------

def test_n08_no_pinning_is_info_not_vulnerability(tmp_path):
    java = {"A.java": 'class A { String u = "https://api.example.com/"; }\n'}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N08", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.INFO
    assert "not a vulnerability" in r.summary.lower()


def test_n08_pinning_present_passes(tmp_path):
    java = {"A.java": (
        "class A {\n"
        "  okhttp3.CertificatePinner p = new okhttp3.CertificatePinner.Builder()\n"
        '      .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")\n'
        "      .build();\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N08", ctx)
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N09
# ---------------------------------------------------------------------------

_NSC_BAD = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<network-security-config>\n"
    '  <base-config cleartextTrafficPermitted="true">\n'
    '    <trust-anchors><certificates src="user"/></trust-anchors>\n'
    "  </base-config>\n"
    "  <debug-overrides>\n"
    '    <trust-anchors><certificates src="user"/></trust-anchors>\n'
    "  </debug-overrides>\n"
    "</network-security-config>\n"
)

def test_n09_vulnerable(tmp_path):
    m = manifest_with(network_security_config="@xml/netsec")
    ctx = make_ctx(tmp_path, manifest=m, res_files={"xml/netsec.xml": _NSC_BAD})
    r = run("BS-N09", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH  # cleartext is the top severity
    # cleartext base-config + user CA in base-config + debug-overrides + user CA in debug-overrides
    assert len(r.evidence) == 4
    assert_rationales(r)
    assert r.evidence[0].line_start == 3  # real line of cleartextTrafficPermitted


def test_n09_clean(tmp_path):
    good = ('<network-security-config><base-config cleartextTrafficPermitted="false">'
            '<trust-anchors><certificates src="system"/></trust-anchors>'
            "</base-config></network-security-config>")
    m = manifest_with(network_security_config="@xml/netsec")
    ctx = make_ctx(tmp_path, manifest=m, res_files={"xml/netsec.xml": good})
    assert run("BS-N09", ctx).status == RuleStatus.PASS


def test_n09_not_applicable_no_config_ref(tmp_path):
    ctx = make_ctx(tmp_path, manifest=manifest_with())
    assert run("BS-N09", ctx).status == RuleStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# BS-N10
# ---------------------------------------------------------------------------

def test_n10_vulnerable(tmp_path):
    java = {"A.java": 'class A { String s = "ws://socket.example.com/chat"; }\n'}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N10", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM
    assert_rationales(r)


def test_n10_clean_wss(tmp_path):
    java = {"A.java": 'class A { String s = "wss://socket.example.com/chat"; }\n'}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N10", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N11
# ---------------------------------------------------------------------------

def test_n11_vulnerable(tmp_path):
    java = {"A.java": (
        "class A {\n"
        "  void m() {\n"
        "    try {\n"
        '      fetch("https://api.example.com/data");\n'
        "    } catch (javax.net.ssl.SSLException e) {\n"
        '      fetch("http://api.example.com/data");\n'
        "    }\n"
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N11", ctx)
    assert r.status == RuleStatus.NEEDS_REVIEW
    assert_rationales(r)


def test_n11_clean(tmp_path):
    java = {"A.java": (
        "class A {\n"
        '  String docs = "http://developer.example.com/guide";\n'
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N11", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N12
# ---------------------------------------------------------------------------

def test_n12_vulnerable(tmp_path):
    java = {"A.java": (
        "class A {\n"
        "  java.net.Proxy p = new java.net.Proxy(java.net.Proxy.Type.HTTP,\n"
        '      new java.net.InetSocketAddress("10.0.0.5", 8080));\n'
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N12", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.LOW
    assert_rationales(r)


def test_n12_clean(tmp_path):
    java = {"A.java": "class A { void m() {} }\n"}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N12", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N13
# ---------------------------------------------------------------------------

def test_n13_vulnerable(tmp_path):
    java = {"A.java": (
        "class A {\n"
        '  String u = "https://api.example.com/login?token=" + token;\n'
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N13", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM
    assert "CWE-598" in r.cwe
    assert_rationales(r)
    # secret value must be redacted in the evidence description
    assert "token=<redacted>" in r.evidence[0].description


def test_n13_clean(tmp_path):
    java = {"A.java": (
        "class A {\n"
        '  String u = "https://api.example.com/login?next=/home";\n'
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N13", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N14
# ---------------------------------------------------------------------------

def test_n14_vulnerable(tmp_path):
    java = {"A.java": (
        "class A {\n"
        "  void m(java.net.HttpURLConnection c) {\n"
        '    c.setRequestProperty("Authorization", "Bearer " + token);\n'
        "    c.setInstanceFollowRedirects(true);\n"
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N14", ctx)
    assert r.status == RuleStatus.NEEDS_REVIEW
    assert_rationales(r)


def test_n14_clean_no_auth(tmp_path):
    java = {"A.java": (
        "class A {\n"
        "  void m(java.net.HttpURLConnection c) {\n"
        "    c.setInstanceFollowRedirects(true);\n"
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N14", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N15
# ---------------------------------------------------------------------------

def test_n15_vulnerable(tmp_path):
    xml = ('<network-security-config>'
           '<domain-config cleartextTrafficPermitted="true">'
           "<domain>legacy.example.com</domain>"
           "</domain-config></network-security-config>")
    m = manifest_with(network_security_config="@xml/netsec")
    ctx = make_ctx(tmp_path, manifest=m, res_files={"xml/netsec.xml": xml})
    r = run("BS-N15", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert_rationales(r)
    assert "legacy.example.com" in r.evidence[0].description


def test_n15_clean(tmp_path):
    xml = ('<network-security-config>'
           '<domain-config cleartextTrafficPermitted="false">'
           "<domain>api.example.com</domain>"
           "</domain-config></network-security-config>")
    m = manifest_with(network_security_config="@xml/netsec")
    ctx = make_ctx(tmp_path, manifest=m, res_files={"xml/netsec.xml": xml})
    assert run("BS-N15", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N16
# ---------------------------------------------------------------------------

def test_n16_vulnerable(tmp_path):
    java = {"A.java": (
        "class A {\n"
        "  okhttp3.logging.HttpLoggingInterceptor log =\n"
        "      new okhttp3.logging.HttpLoggingInterceptor();\n"
        "  void m() { log.setLevel(okhttp3.logging.HttpLoggingInterceptor.Level.BODY); }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N16", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM
    assert "CWE-532" in r.cwe
    assert_rationales(r)


def test_n16_clean(tmp_path):
    java = {"A.java": (
        "class A {\n"
        "  okhttp3.logging.HttpLoggingInterceptor log =\n"
        "      new okhttp3.logging.HttpLoggingInterceptor();\n"
        "  void m() { log.setLevel(okhttp3.logging.HttpLoggingInterceptor.Level.NONE); }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N16", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N17
# ---------------------------------------------------------------------------

def test_n17_vulnerable(tmp_path):
    java = {"A.java": (
        "class A {\n"
        "  void m() throws Exception {\n"
        "    javax.net.ssl.TrustManager[] trustAll = new javax.net.ssl.TrustManager[] { new TrustAll() };\n"
        '    javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");\n'
        "    sc.init(null, trustAll, new java.security.SecureRandom());\n"
        "    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());\n"
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N17", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert_rationales(r)


def test_n17_clean(tmp_path):
    java = {"A.java": (
        "class A {\n"
        "  void m() throws Exception {\n"
        '    javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLSv1.3");\n'
        "    sc.init(null, null, null);\n"
        "  }\n"
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N17", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N18
# ---------------------------------------------------------------------------

def test_n18_inventory(tmp_path):
    java = {"A.java": (
        "class A {\n"
        '  String a = "https://api.example.com/v1";\n'
        '  String b = "https://cdn.example.net/assets";\n'
        '  String c = "https://api.example.com/v2";\n'
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N18", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.INFO
    assert "api.example.com" in r.summary and "cdn.example.net" in r.summary
    assert len(r.evidence) == 2  # deduplicated by host
    assert_rationales(r)


def test_n18_clean(tmp_path):
    java = {"A.java": "class A { void m() {} }\n"}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N18", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N19
# ---------------------------------------------------------------------------

def test_n19_vulnerable(tmp_path):
    java = {"A.java": (
        "class A {\n"
        '  String dev = "http://10.0.2.2:8080/api";\n'
        '  String local = "http://localhost:3000/health";\n'
        "}\n"
    )}
    ctx = make_ctx(tmp_path, java_files=java)
    r = run("BS-N19", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.LOW
    assert "M8" in r.owasp
    assert_rationales(r)


def test_n19_clean(tmp_path):
    java = {"A.java": 'class A { String a = "https://api.example.com/"; }\n'}
    ctx = make_ctx(tmp_path, java_files=java)
    assert run("BS-N19", ctx).status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-N20
# ---------------------------------------------------------------------------

def test_n20_vulnerable(tmp_path):
    m = manifest_with(permissions=[Permission(name="android.permission.INTERNET")])
    ctx = make_ctx(tmp_path, manifest=m)
    r = run("BS-N20", ctx)
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.INFO
    assert_rationales(r)


def test_n20_clean_with_config(tmp_path):
    m = manifest_with(
        permissions=[Permission(name="android.permission.INTERNET")],
        network_security_config="@xml/netsec",
    )
    ctx = make_ctx(tmp_path, manifest=m)
    assert run("BS-N20", ctx).status == RuleStatus.PASS


def test_n20_not_applicable_no_internet(tmp_path):
    m = manifest_with(permissions=[])
    ctx = make_ctx(tmp_path, manifest=m)
    assert run("BS-N20", ctx).status == RuleStatus.NOT_APPLICABLE
