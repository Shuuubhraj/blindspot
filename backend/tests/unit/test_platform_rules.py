"""Unit tests for BS-P01 .. BS-P20 (platform rules).

Each rule is tested vulnerable -> expected status, clean -> PASS, and
NOT_APPLICABLE where the contract defines it. ScanContext is built directly
with ManifestData/Component/IntentFilter fixtures and tmp_path sources.
"""

from pathlib import Path

import pytest

from blindspot.rules.base import (
    ApkInfo,
    Component,
    IntentFilter,
    ManifestData,
    RuleStatus,
    ScanContext,
    Severity,
)
from blindspot.rules.platform_rules import RULES

RULES_BY_ID = {r.id: r for r in RULES}

VIEW = "android.intent.action.VIEW"
BROWSABLE = "android.intent.category.BROWSABLE"


def _make_ctx(tmp_path: Path, manifest=None, java_files=None,
              apk=None, apk_entries=None, assets_files=None):
    workdir = tmp_path / "work"
    workdir.mkdir(exist_ok=True)
    src = workdir / "src"
    src.mkdir(exist_ok=True)
    for rel, content in (java_files or {}).items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    assets = None
    if assets_files is not None:
        assets = workdir / "assets"
        assets.mkdir(exist_ok=True)
        for rel, content in assets_files.items():
            p = assets / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
    return ScanContext(
        scan_id="test",
        workdir=workdir,
        apk_path=workdir / "app.apk",
        apk=apk or ApkInfo(),
        manifest=manifest,
        java_roots=[src],
        assets_dir=assets,
        apk_entries=apk_entries or [],
    )


def _deep_activity(name="com.example.DeepLink", scheme="https", exported=True):
    return Component(
        kind="activity",
        name=name,
        exported=exported,
        intent_filters=[IntentFilter(
            actions=[VIEW],
            categories=[BROWSABLE],
            data=[{"scheme": scheme, "host": "example.com"}],
        )],
    )


def _raw_xml(activity_name, auto_verify):
    av = ' android:autoVerify="true"' if auto_verify else ""
    return (
        '<manifest><application>'
        f'<activity android:name="{activity_name}">'
        f'<intent-filter{av}>'
        f'<action android:name="{VIEW}"/>'
        f'<category android:name="{BROWSABLE}"/>'
        '<data android:scheme="https" android:host="example.com"/>'
        '</intent-filter></activity>'
        '</application></manifest>'
    )


def _manifest(components, raw_xml="", **kw):
    acts = [c for c in components if c.kind == "activity"]
    return ManifestData(package="com.example", activities=acts,
                        receivers=[c for c in components if c.kind == "receiver"],
                        providers=[c for c in components if c.kind == "provider"],
                        raw_xml=raw_xml, **kw)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_registry_has_all_20_rules_in_order():
    assert [r.id for r in RULES] == [f"BS-P{i:02d}" for i in range(1, 21)]
    assert all(r.category == "platform" for r in RULES)
    assert len({r.id for r in RULES}) == 20


# ---------------------------------------------------------------------------
# BS-P01
# ---------------------------------------------------------------------------

def test_p01_finding_without_autoverify(tmp_path):
    m = _manifest([_deep_activity()],
                  raw_xml=_raw_xml("com.example.DeepLink", auto_verify=False))
    res = RULES_BY_ID["BS-P01"].run(_make_ctx(tmp_path, manifest=m))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.severity_rationale and res.confidence_rationale
    assert any(e.file_path == "AndroidManifest.xml" and e.line_start is None
               for e in res.evidence)


def test_p01_pass_with_autoverify(tmp_path):
    m = _manifest([_deep_activity()],
                  raw_xml=_raw_xml("com.example.DeepLink", auto_verify=True))
    res = RULES_BY_ID["BS-P01"].run(_make_ctx(tmp_path, manifest=m))
    assert res.status == RuleStatus.PASS


def test_p01_needs_review_when_raw_xml_missing(tmp_path):
    m = _manifest([_deep_activity()], raw_xml="")
    res = RULES_BY_ID["BS-P01"].run(_make_ctx(tmp_path, manifest=m))
    assert res.status == RuleStatus.NEEDS_REVIEW


def test_p01_not_applicable_without_manifest(tmp_path):
    res = RULES_BY_ID["BS-P01"].run(_make_ctx(tmp_path))
    assert res.status == RuleStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# BS-P02
# ---------------------------------------------------------------------------

def test_p02_needs_review_custom_scheme(tmp_path):
    m = _manifest([_deep_activity(scheme="myapp")])
    res = RULES_BY_ID["BS-P02"].run(_make_ctx(tmp_path, manifest=m))
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert res.severity_rationale and res.confidence_rationale


def test_p02_pass_https_only(tmp_path):
    m = _manifest([_deep_activity(scheme="https")])
    res = RULES_BY_ID["BS-P02"].run(_make_ctx(tmp_path, manifest=m))
    assert res.status == RuleStatus.PASS


def test_p02_not_applicable_without_manifest(tmp_path):
    res = RULES_BY_ID["BS-P02"].run(_make_ctx(tmp_path))
    assert res.status == RuleStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# BS-P03
# ---------------------------------------------------------------------------

_DEEP_SINK = """package com.example;
import android.net.Uri;
public class DeepLink {
    void onCreate() {
        Uri data = getIntent().getData();
        webView.loadUrl(data.toString());
    }
}
"""

def test_p03_needs_review_uri_to_sink(tmp_path):
    m = _manifest([_deep_activity()])
    ctx = _make_ctx(tmp_path, manifest=m,
                    java_files={"com/example/DeepLink.java": _DEEP_SINK})
    res = RULES_BY_ID["BS-P03"].run(ctx)
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert res.evidence and res.evidence[0].line_start == 5


def test_p03_pass_no_uri_read(tmp_path):
    m = _manifest([_deep_activity()])
    ctx = _make_ctx(tmp_path, manifest=m,
                    java_files={"com/example/DeepLink.java":
                                "package com.example;\npublic class DeepLink {}\n"})
    res = RULES_BY_ID["BS-P03"].run(ctx)
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P04
# ---------------------------------------------------------------------------

_IMPLICIT = """package com.example;
import android.content.Intent;
public class Share {
    void go(android.content.Context c, String token) {
        Intent i = new Intent("com.example.SHARE");
        i.putExtra("auth_token", token);
        c.startActivity(i);
    }
}
"""

_EXPLICIT = """package com.example;
import android.content.Intent;
public class Share {
    void go(android.content.Context c, String token) {
        Intent i = new Intent("com.example.SHARE");
        i.setPackage(c.getPackageName());
        i.putExtra("auth_token", token);
        c.startActivity(i);
    }
}
"""

def test_p04_finding_implicit_sensitive_extras(tmp_path):
    res = RULES_BY_ID["BS-P04"].run(
        _make_ctx(tmp_path, java_files={"com/example/Share.java": _IMPLICIT}))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.LOW
    assert res.severity_rationale and res.confidence_rationale


def test_p04_pass_explicit_target(tmp_path):
    res = RULES_BY_ID["BS-P04"].run(
        _make_ctx(tmp_path, java_files={"com/example/Share.java": _EXPLICIT}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P05
# ---------------------------------------------------------------------------

_REDIRECT = """package com.example;
import android.content.Intent;
public class Relay {
    void onCreate() {
        Intent nested = (Intent) getIntent().getParcelableExtra("nested_intent");
        startActivity(nested);
    }
}
"""

_REDIRECT_VALIDATED = """package com.example;
import android.content.Intent;
public class Relay {
    void onCreate() {
        Intent nested = (Intent) getIntent().getParcelableExtra("nested_intent");
        if (nested.getAction() != null && nested.getAction().equals("com.example.ALLOWED")) {
            startActivity(nested);
        }
    }
}
"""

def test_p05_finding_high_no_validation(tmp_path):
    res = RULES_BY_ID["BS-P05"].run(
        _make_ctx(tmp_path, java_files={"com/example/Relay.java": _REDIRECT}))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.severity_rationale and res.confidence_rationale


def test_p05_needs_review_with_validation(tmp_path):
    res = RULES_BY_ID["BS-P05"].run(
        _make_ctx(tmp_path, java_files={"com/example/Relay.java": _REDIRECT_VALIDATED}))
    assert res.status == RuleStatus.NEEDS_REVIEW


def test_p05_pass_no_redirection(tmp_path):
    res = RULES_BY_ID["BS-P05"].run(
        _make_ctx(tmp_path, java_files={"com/example/Ok.java": "class Ok {}\n"}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P06
# ---------------------------------------------------------------------------

_RECV = """package com.example;
import android.content.*;
public class MyRecv extends BroadcastReceiver {
    public void onReceive(Context c, Intent intent) {
        String cmd = intent.getStringExtra("cmd");
        handle(cmd);
    }
    void handle(String s) {}
}
"""

_RECV_CHECKED = """package com.example;
import android.content.*;
public class MyRecv extends BroadcastReceiver {
    public void onReceive(Context c, Intent intent) {
        c.enforceCallingPermission("com.example.PERM", "nope");
        String cmd = intent.getStringExtra("cmd");
    }
}
"""

def _recv_manifest(exported=True):
    return _manifest([Component(kind="receiver", name="com.example.MyRecv",
                               exported=exported)])

def test_p06_finding_receiver_trusts_extras(tmp_path):
    ctx = _make_ctx(tmp_path, manifest=_recv_manifest(),
                    java_files={"com/example/MyRecv.java": _RECV})
    res = RULES_BY_ID["BS-P06"].run(ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM


def test_p06_pass_sender_checked(tmp_path):
    ctx = _make_ctx(tmp_path, manifest=_recv_manifest(),
                    java_files={"com/example/MyRecv.java": _RECV_CHECKED})
    res = RULES_BY_ID["BS-P06"].run(ctx)
    assert res.status == RuleStatus.PASS


def test_p06_pass_not_exported(tmp_path):
    ctx = _make_ctx(tmp_path, manifest=_recv_manifest(exported=False),
                    java_files={"com/example/MyRecv.java": _RECV})
    res = RULES_BY_ID["BS-P06"].run(ctx)
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P07
# ---------------------------------------------------------------------------

_PROV = """package com.example;
import android.content.*;
import android.database.Cursor;
import android.net.Uri;
public class MyProv extends ContentProvider {
    public Cursor query(Uri uri, String[] p, String s, String[] a, String o) {
        String id = uri.getLastPathSegment();
        return db.rawQuery("SELECT * FROM t WHERE id=" + id, null);
    }
}
"""

def _prov_manifest():
    return _manifest([Component(kind="provider", name="com.example.MyProv",
                               exported=True, authorities="com.example.prov")])

def test_p07_needs_review_unsanitized_uri(tmp_path):
    ctx = _make_ctx(tmp_path, manifest=_prov_manifest(),
                    java_files={"com/example/MyProv.java": _PROV})
    res = RULES_BY_ID["BS-P07"].run(ctx)
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert res.severity_rationale and res.confidence_rationale


def test_p07_pass_no_provider(tmp_path):
    res = RULES_BY_ID["BS-P07"].run(_make_ctx(tmp_path, manifest=_manifest([])))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P08
# ---------------------------------------------------------------------------

_TRAVERSAL = """package com.example;
import android.net.Uri;
import java.io.File;
public class Files {
    File open(Uri uri) {
        return new File(getContext().getFilesDir(), uri.getPath());
    }
    android.content.Context getContext() { return null; }
}
"""

def test_p08_finding_path_traversal(tmp_path):
    res = RULES_BY_ID["BS-P08"].run(
        _make_ctx(tmp_path, java_files={"com/example/Files.java": _TRAVERSAL}))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert "CWE-22" in res.cwe


def test_p08_pass_clean(tmp_path):
    res = RULES_BY_ID["BS-P08"].run(
        _make_ctx(tmp_path, java_files={"com/example/Ok.java": "class Ok {}\n"}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P09
# ---------------------------------------------------------------------------

def test_p09_inventory_finding(tmp_path):
    apk = ApkInfo(native_libs=["lib/arm64-v8a/libfoo.so", "lib/armeabi-v7a/libfoo.so"])
    res = RULES_BY_ID["BS-P09"].run(_make_ctx(tmp_path, apk=apk))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO
    assert "libfoo.so" in res.summary


def test_p09_pass_no_native_libs(tmp_path):
    res = RULES_BY_ID["BS-P09"].run(_make_ctx(tmp_path))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P10
# ---------------------------------------------------------------------------

_VAR_LOAD = "package a;\npublic class N {\n void f(String libName) {\n System.loadLibrary(libName);\n }\n}\n"
_EXT_LOAD = 'package a;\npublic class N {\n void f() {\n System.load("/sdcard/evil/libx.so");\n }\n}\n'
_LITERAL_LOAD = 'package a;\npublic class N {\n static { System.loadLibrary("native-lib"); }\n}\n'

def test_p10_needs_review_variable_loadlibrary(tmp_path):
    res = RULES_BY_ID["BS-P10"].run(
        _make_ctx(tmp_path, java_files={"a/N.java": _VAR_LOAD}))
    assert res.status == RuleStatus.NEEDS_REVIEW


def test_p10_needs_review_writable_path(tmp_path):
    res = RULES_BY_ID["BS-P10"].run(
        _make_ctx(tmp_path, java_files={"a/N.java": _EXT_LOAD}))
    assert res.status == RuleStatus.NEEDS_REVIEW


def test_p10_pass_literal_loadlibrary(tmp_path):
    res = RULES_BY_ID["BS-P10"].run(
        _make_ctx(tmp_path, java_files={"a/N.java": _LITERAL_LOAD}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P11
# ---------------------------------------------------------------------------

def test_p11_finding_test_endpoint(tmp_path):
    src = 'package a;\npublic class C {\n String U = "https://staging.example.com/debug/api";\n}\n'
    res = RULES_BY_ID["BS-P11"].run(
        _make_ctx(tmp_path, java_files={"a/C.java": src}))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.LOW


def test_p11_pass_production_url(tmp_path):
    src = 'package a;\npublic class C {\n String U = "https://api.example.com/v1";\n}\n'
    res = RULES_BY_ID["BS-P11"].run(
        _make_ctx(tmp_path, java_files={"a/C.java": src}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P12
# ---------------------------------------------------------------------------

def test_p12_finding_source_map(tmp_path):
    res = RULES_BY_ID["BS-P12"].run(
        _make_ctx(tmp_path, apk_entries=["assets/www/app.js.map"]))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.LOW


def test_p12_finding_asset_map_file(tmp_path):
    res = RULES_BY_ID["BS-P12"].run(
        _make_ctx(tmp_path, assets_files={"www/bundle.js.map": "{}"}))
    assert res.status == RuleStatus.FINDING


def test_p12_pass_no_maps(tmp_path):
    res = RULES_BY_ID["BS-P12"].run(
        _make_ctx(tmp_path, apk_entries=["assets/www/app.js"]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P13
# ---------------------------------------------------------------------------

def test_p13_inventory_third_party(tmp_path):
    files = {
        "com/google/gson/Gson.java": "package com.google.gson;\npublic class Gson {}\n",
        "com/example/App.java": "package com.example;\npublic class App {}\n",
    }
    res = RULES_BY_ID["BS-P13"].run(_make_ctx(tmp_path, java_files=files))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO
    assert "com.google.gson" in res.summary


def test_p13_pass_first_party_only(tmp_path):
    res = RULES_BY_ID["BS-P13"].run(
        _make_ctx(tmp_path, java_files={"com/example/App.java": "package com.example;\n"}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P14
# ---------------------------------------------------------------------------

_FAIL_OPEN = """package a;
import android.content.pm.PackageManager;
public class T {
    boolean check(PackageManager pm, String pkg) {
        try {
            Object s = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures[0];
            return verify(s);
        } catch (Exception e) {
            return true;
        }
    }
    boolean verify(Object o) { return false; }
}
"""

_SIGCHECK = """package a;
import android.content.pm.PackageManager;
public class T {
    boolean check(PackageManager pm, String pkg) {
        Object s = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures[0];
        return verify(s);
    }
    boolean verify(Object o) { return false; }
}
"""

def test_p14_needs_review_fail_open(tmp_path):
    res = RULES_BY_ID["BS-P14"].run(
        _make_ctx(tmp_path, java_files={"a/T.java": _FAIL_OPEN}))
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert res.confidence.name == "MEDIUM"
    assert "fails open" in res.summary


def test_p14_needs_review_custom_check(tmp_path):
    res = RULES_BY_ID["BS-P14"].run(
        _make_ctx(tmp_path, java_files={"a/T.java": _SIGCHECK}))
    assert res.status == RuleStatus.NEEDS_REVIEW


def test_p14_pass_no_sigcheck(tmp_path):
    res = RULES_BY_ID["BS-P14"].run(
        _make_ctx(tmp_path, java_files={"a/T.java": "package a;\npublic class T {}\n"}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P15 / BS-P16 (informational, never FINDING)
# ---------------------------------------------------------------------------

def test_p15_pass_info_when_absent(tmp_path):
    res = RULES_BY_ID["BS-P15"].run(
        _make_ctx(tmp_path, java_files={"a/T.java": "package a;\npublic class T {}\n"}))
    assert res.status == RuleStatus.PASS
    assert res.severity == Severity.INFO


def test_p15_pass_info_when_present(tmp_path):
    src = "package a;\npublic class T {\n boolean r() { return new RootBeer(null).isRooted(); }\n}\n"
    res = RULES_BY_ID["BS-P15"].run(_make_ctx(tmp_path, java_files={"a/T.java": src}))
    assert res.status == RuleStatus.PASS
    assert res.severity == Severity.INFO


def test_p16_pass_info_when_absent(tmp_path):
    res = RULES_BY_ID["BS-P16"].run(
        _make_ctx(tmp_path, java_files={"a/T.java": "package a;\npublic class T {}\n"}))
    assert res.status == RuleStatus.PASS
    assert res.severity == Severity.INFO


def test_p16_pass_info_when_present(tmp_path):
    src = "package a;\npublic class T {\n void t() { checkSignatures(); }\n void checkSignatures() {}\n}\n"
    res = RULES_BY_ID["BS-P16"].run(_make_ctx(tmp_path, java_files={"a/T.java": src}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P17
# ---------------------------------------------------------------------------

def test_p17_finding_debug_activity(tmp_path):
    m = _manifest([Component(kind="activity", name="com.example.DebugActivity",
                            exported=True)])
    res = RULES_BY_ID["BS-P17"].run(_make_ctx(tmp_path, manifest=m))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM


def test_p17_pass_normal_activity(tmp_path):
    m = _manifest([Component(kind="activity", name="com.example.MainActivity",
                            exported=True)])
    res = RULES_BY_ID["BS-P17"].run(_make_ctx(tmp_path, manifest=m))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P18
# ---------------------------------------------------------------------------

_PI_MUTABLE = """package a;
import android.app.PendingIntent;
import android.content.Intent;
public class P {
    PendingIntent f(android.content.Context c, Intent i) {
        return PendingIntent.getActivity(c, 0, i, 0);
    }
}
"""

_PI_IMMUTABLE = """package a;
import android.app.PendingIntent;
import android.content.Intent;
public class P {
    PendingIntent f(android.content.Context c, Intent i) {
        return PendingIntent.getActivity(c, 0, i, PendingIntent.FLAG_IMMUTABLE);
    }
}
"""

def test_p18_finding_missing_flag_immutable(tmp_path):
    m = _manifest([], target_sdk=33)
    res = RULES_BY_ID["BS-P18"].run(
        _make_ctx(tmp_path, manifest=m, java_files={"a/P.java": _PI_MUTABLE}))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM


def test_p18_pass_flag_immutable(tmp_path):
    m = _manifest([], target_sdk=33)
    res = RULES_BY_ID["BS-P18"].run(
        _make_ctx(tmp_path, manifest=m, java_files={"a/P.java": _PI_IMMUTABLE}))
    assert res.status == RuleStatus.PASS


def test_p18_not_applicable_below_31(tmp_path):
    m = _manifest([], target_sdk=30)
    res = RULES_BY_ID["BS-P18"].run(
        _make_ctx(tmp_path, manifest=m, java_files={"a/P.java": _PI_MUTABLE}))
    assert res.status == RuleStatus.NOT_APPLICABLE


def test_p18_not_applicable_unknown_target(tmp_path):
    m = _manifest([])
    res = RULES_BY_ID["BS-P18"].run(
        _make_ctx(tmp_path, manifest=m, java_files={"a/P.java": _PI_MUTABLE}))
    assert res.status == RuleStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# BS-P19
# ---------------------------------------------------------------------------

_PREF = """package com.example;
import android.preference.PreferenceActivity;
public class SettingsActivity extends PreferenceActivity {
}
"""

_PREF_SAFE = """package com.example;
import android.preference.PreferenceActivity;
public class SettingsActivity extends PreferenceActivity {
    protected boolean isValidFragment(String name) { return true; }
}
"""

def _pref_manifest():
    return _manifest([Component(kind="activity",
                               name="com.example.SettingsActivity",
                               exported=True)])

def test_p19_finding_no_isvalidfragment(tmp_path):
    ctx = _make_ctx(tmp_path, manifest=_pref_manifest(),
                    java_files={"com/example/SettingsActivity.java": _PREF})
    res = RULES_BY_ID["BS-P19"].run(ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert "CWE-926" in res.cwe


def test_p19_pass_with_override(tmp_path):
    ctx = _make_ctx(tmp_path, manifest=_pref_manifest(),
                    java_files={"com/example/SettingsActivity.java": _PREF_SAFE})
    res = RULES_BY_ID["BS-P19"].run(ctx)
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-P20
# ---------------------------------------------------------------------------

def test_p20_finding_debug_signed(tmp_path):
    res = RULES_BY_ID["BS-P20"].run(
        _make_ctx(tmp_path, apk=ApkInfo(is_debug_signed=True)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.severity_rationale and res.confidence_rationale


def test_p20_pass_release_signed(tmp_path):
    res = RULES_BY_ID["BS-P20"].run(
        _make_ctx(tmp_path, apk=ApkInfo(is_debug_signed=False)))
    assert res.status == RuleStatus.PASS


def test_p20_not_applicable_when_unknown(tmp_path):
    res = RULES_BY_ID["BS-P20"].run(
        _make_ctx(tmp_path, apk=ApkInfo(is_debug_signed=None)))
    assert res.status == RuleStatus.NOT_APPLICABLE
