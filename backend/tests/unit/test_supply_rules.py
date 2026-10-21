"""Unit tests for the BS-D01..BS-D20 supply-chain detection rules.

Each rule gets a vulnerable fixture (expecting FINDING or NEEDS_REVIEW)
and a clean fixture (expecting PASS). APK-entry based rules build a
ScanContext with apk_entries; native-library rules create real .so files
under a lib_dir.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

# NOTE: the repo is mid-build and blindspot/rules/__init__.py -> registry.py
# imports sibling category modules (manifest_rules, storage_rules, ...) that
# do not exist yet, so a normal `import blindspot.rules.supply_rules` fails
# at collection time through no fault of this module. Load the rule package
# by file location instead, which exercises the exact same code paths.
_RULES_DIR = Path(__file__).resolve().parents[2] / "blindspot" / "rules"


def _load(modname: str, filename: str):
    spec = importlib.util.spec_from_file_location(modname, _RULES_DIR / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_pkg = types.ModuleType("blindspot.rules")
_pkg.__path__ = [str(_RULES_DIR)]
sys.modules.setdefault("blindspot.rules", _pkg)
_base = _load("blindspot.rules.base", "base.py")
_load("blindspot.rules.common", "common.py")
_supply = _load("blindspot.rules.supply_rules", "supply_rules.py")

RuleStatus = _base.RuleStatus
ScanContext = _base.ScanContext
Severity = _base.Severity
RULES = _supply.RULES

RULES_BY_ID = {r.id: r for r in RULES}


@pytest.fixture
def make_ctx(tmp_path):
    counter = {"n": 0}

    def _make(*files: tuple[str, str]) -> ScanContext:
        counter["n"] += 1
        src = tmp_path / f"src{counter['n']}"
        src.mkdir(parents=True, exist_ok=True)
        for name, content in files:
            p = src / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return ScanContext(
            scan_id="test",
            workdir=tmp_path,
            apk_path=tmp_path / "app.apk",
            java_roots=[src],
        )

    return _make


def ctx_entries(tmp_path, entries):
    return ScanContext(
        scan_id="test",
        workdir=tmp_path,
        apk_path=tmp_path / "x.apk",
        apk_entries=list(entries),
    )


def ctx_lib(tmp_path, files):
    lib = tmp_path / "lib" / "arm64-v8a"
    lib.mkdir(parents=True, exist_ok=True)
    for name, data in files:
        (lib / name).write_bytes(data)
    return ScanContext(
        scan_id="test",
        workdir=tmp_path,
        apk_path=tmp_path / "x.apk",
        lib_dir=tmp_path / "lib",
    )


def run(rule_id, ctx):
    return RULES_BY_ID[rule_id].run(ctx)


def test_registry_has_20_rules():
    assert len(RULES) == 20
    assert [r.id for r in RULES] == [f"BS-D{i:02d}" for i in range(1, 21)]
    assert all(r.category == "supply-chain" for r in RULES)


# ---------------------------------------------------------------- BS-D01

def test_d01_admob_entries_is_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["classes.dex", "com/google/android/gms/ads/AdActivity.class"])
    res = run("BS-D01", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.LOW
    assert res.severity_rationale and res.confidence_rationale
    assert "AdMob" in res.summary


def test_d01_ads_source_path_is_finding(make_ctx):
    res = run("BS-D01", make_ctx(("com/facebook/ads/AdView.java", "package com.facebook.ads;\npublic class AdView {}")))
    assert res.status == RuleStatus.FINDING
    assert "Meta Audience Network" in res.summary


def test_d01_no_sdk_passes(tmp_path):
    ctx = ctx_entries(tmp_path, ["classes.dex", "com/example/App.class"])
    res = run("BS-D01", ctx)
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D02

def test_d02_amplitude_is_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["com/amplitude/api/Amplitude.class"])
    res = run("BS-D02", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.LOW
    assert "Amplitude" in res.summary


def test_d02_no_sdk_passes(tmp_path):
    res = run("BS-D02", ctx_entries(tmp_path, ["classes.dex"]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D03

def test_d03_sentry_is_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["io/sentry/Sentry.class"])
    res = run("BS-D03", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.LOW


def test_d03_no_sdk_passes(tmp_path):
    res = run("BS-D03", ctx_entries(tmp_path, ["classes.dex"]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D04

def test_d04_stripe_is_medium_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["com/stripe/android/Stripe.class"])
    res = run("BS-D04", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.severity_rationale and res.confidence_rationale


def test_d04_no_sdk_passes(tmp_path):
    res = run("BS-D04", ctx_entries(tmp_path, ["classes.dex"]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D05

def test_d05_facebook_sdk_is_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["com/facebook/AccessToken.class"])
    res = run("BS-D05", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.LOW


def test_d05_react_native_only_passes(tmp_path):
    # com/facebook/react belongs to React Native, not the Facebook SDK
    ctx = ctx_entries(tmp_path, ["com/facebook/react/ReactActivity.class"])
    res = run("BS-D05", ctx)
    assert res.status == RuleStatus.PASS


def test_d05_no_sdk_passes(tmp_path):
    res = run("BS-D05", ctx_entries(tmp_path, ["classes.dex"]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D06

D06_VULN = 'public class BuildConfig { public static final String NET = "okhttp/3.12.0"; }\n'


def test_d06_old_okhttp_is_high_finding(make_ctx):
    res = run("BS-D06", make_ctx(("BuildConfig.java", D06_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.cwe == ["CWE-1104"]
    assert res.severity_rationale and res.confidence_rationale
    assert "3.12.0" in res.evidence[0].snippet


def test_d06_new_okhttp_passes(make_ctx):
    res = run("BS-D06", make_ctx(("BuildConfig.java", D06_VULN.replace("3.12.0", "4.9.3"))))
    assert res.status == RuleStatus.PASS


def test_d06_unparseable_version_needs_review(make_ctx):
    res = run("BS-D06", make_ctx(("BuildConfig.java", D06_VULN.replace("3.12.0", "latest"))))
    assert res.status == RuleStatus.NEEDS_REVIEW


def test_d06_no_okhttp_passes(make_ctx):
    res = run("BS-D06", make_ctx(("A.java", "public class A {}")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D07

D07_GSON = '// dependency com.google.code.gson:gson:2.8.6\npublic class App {}\n'


def test_d07_old_gson_is_finding(make_ctx):
    res = run("BS-D07", make_ctx(("App.java", D07_GSON)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert "CVE-2022-25647" in RULES_BY_ID["BS-D07"].description
    assert res.severity_rationale and res.confidence_rationale


def test_d07_old_jackson_is_finding(make_ctx):
    src = '// dependency com.fasterxml.jackson.core:jackson-databind:2.11.4\npublic class App {}\n'
    res = run("BS-D07", make_ctx(("App.java", src)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM


def test_d07_new_gson_passes(make_ctx):
    res = run("BS-D07", make_ctx(("App.java", D07_GSON.replace("2.8.6", "2.10.1"))))
    assert res.status == RuleStatus.PASS


def test_d07_unparseable_version_needs_review(make_ctx):
    res = run("BS-D07", make_ctx(("App.java", D07_GSON.replace("2.8.6", "SNAPSHOT"))))
    assert res.status == RuleStatus.NEEDS_REVIEW


# ---------------------------------------------------------------- BS-D08

def test_d08_suspicious_so_string_is_high_finding(tmp_path):
    data = b"\x7fELF" + b"\x00" * 64 + b"/system/bin/sh" + b"\x00" * 64
    res = run("BS-D08", ctx_lib(tmp_path, [("libfoo.so", data)]))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.severity_rationale and res.confidence_rationale
    assert res.evidence[0].file_path.endswith("libfoo.so")


def test_d08_clean_so_passes(tmp_path):
    data = b"\x7fELF" + b"\x00" * 64 + b"harmless symbol names here"
    res = run("BS-D08", ctx_lib(tmp_path, [("libfoo.so", data)]))
    assert res.status == RuleStatus.PASS


def test_d08_no_lib_dir_passes(tmp_path):
    res = run("BS-D08", ctx_entries(tmp_path, ["classes.dex"]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D09

D09_VULN = 'public class L { void m(String p) { System.load(p); } }\n'


def test_d09_variable_load_is_finding(make_ctx):
    res = run("BS-D09", make_ctx(("L.java", D09_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.severity_rationale and res.confidence_rationale
    assert res.evidence[0].line_start == 1  # real line number


def test_d09_literal_load_passes(make_ctx):
    src = 'public class L { void m() { System.load("/data/app/libfoo.so"); } }\n'
    res = run("BS-D09", make_ctx(("L.java", src)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D10

def test_d10_single_letter_segments_is_info_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["classes.dex", "a/b.class", "c.class"])
    res = run("BS-D10", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO
    assert res.severity_rationale and res.confidence_rationale


def test_d10_normal_packages_pass(tmp_path):
    ctx = ctx_entries(tmp_path, ["classes.dex", "com/example/App.class", "res/layout/a.xml"])
    res = run("BS-D10", ctx)
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D11

def test_d11_dexguard_is_info_finding(make_ctx):
    res = run("BS-D11", make_ctx(("A.java", "// processed by DexGuard\npublic class A {}\n")))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO


def test_d11_no_dexguard_passes(make_ctx):
    res = run("BS-D11", make_ctx(("A.java", "public class A {}\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D12

def test_d12_flutter_so_is_info_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["lib/arm64-v8a/libflutter.so", "classes.dex"])
    res = run("BS-D12", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO
    assert res.severity_rationale and res.confidence_rationale


def test_d12_no_flutter_passes(tmp_path):
    res = run("BS-D12", ctx_entries(tmp_path, ["classes.dex"]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D13

def test_d13_react_native_is_info_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["com/facebook/react/ReactActivity.class"])
    res = run("BS-D13", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO


def test_d13_no_rn_passes(tmp_path):
    res = run("BS-D13", ctx_entries(tmp_path, ["classes.dex"]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D14

def test_d14_cordova_is_info_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["org/apache/cordova/CordovaActivity.class"])
    res = run("BS-D14", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO


def test_d14_capacitor_is_info_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["com/getcapacitor/Bridge.class"])
    res = run("BS-D14", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO


def test_d14_no_hybrid_passes(tmp_path):
    res = run("BS-D14", ctx_entries(tmp_path, ["classes.dex"]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D15

def test_d15_unity_so_is_info_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["lib/armeabi-v7a/libunity.so"])
    res = run("BS-D15", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO


def test_d15_no_unity_passes(tmp_path):
    res = run("BS-D15", ctx_entries(tmp_path, ["classes.dex"]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D16

def test_d16_xamarin_so_is_info_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["lib/arm64-v8a/libmonodroid.so"])
    res = run("BS-D16", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO
    assert res.severity_rationale and res.confidence_rationale


def test_d16_no_xamarin_passes(tmp_path):
    res = run("BS-D16", ctx_entries(tmp_path, ["classes.dex"]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D17

def test_d17_three_trackers_is_info_finding(tmp_path):
    ctx = ctx_entries(tmp_path, [
        "com/google/android/gms/ads/AdActivity.class",
        "com/amplitude/api/Amplitude.class",
        "io/sentry/Sentry.class",
        "classes.dex",
    ])
    res = run("BS-D17", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO
    assert res.severity_rationale and res.confidence_rationale
    # one finding listing all three distinct trackers
    assert "AdMob" in res.summary
    assert "Amplitude" in res.summary
    assert "Sentry" in res.summary


def test_d17_two_trackers_passes(tmp_path):
    ctx = ctx_entries(tmp_path, [
        "com/amplitude/api/Amplitude.class",
        "io/sentry/Sentry.class",
    ])
    res = run("BS-D17", ctx)
    assert res.status == RuleStatus.PASS


def test_d17_no_trackers_passes(tmp_path):
    res = run("BS-D17", ctx_entries(tmp_path, ["classes.dex"]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D18

def test_d18_unstripped_so_is_finding(tmp_path):
    data = b"\x7fELF" + b"\x00" * 32 + b".symtab" + b"\x00" * 32
    res = run("BS-D18", ctx_lib(tmp_path, [("libfoo.so", data)]))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.LOW
    assert res.severity_rationale and res.confidence_rationale


def test_d18_stripped_so_passes(tmp_path):
    data = b"\x7fELF" + b"\x00" * 32 + b".dynsym" + b"\x00" * 32
    res = run("BS-D18", ctx_lib(tmp_path, [("libfoo.so", data)]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D19

D19_VULN = (
    "import android.telephony.SmsManager;\n"
    "public class T {\n"
    "    private native String getImei();\n"
    "    void m() { SmsManager.getDefault(); }\n"
    "}\n"
)


def test_d19_jni_with_sms_needs_review(make_ctx):
    res = run("BS-D19", make_ctx(("T.java", D19_VULN)))
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert res.severity == Severity.MEDIUM
    assert res.severity_rationale and res.confidence_rationale
    assert res.evidence[0].line_start == 3  # the native declaration line


def test_d19_native_without_sensitive_api_passes(make_ctx):
    src = "public class N { private native int add(int a, int b); }\n"
    res = run("BS-D19", make_ctx(("N.java", src)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-D20

def test_d20_support_lib_is_finding(tmp_path):
    ctx = ctx_entries(tmp_path, ["android/support/v4/app/Fragment.class"])
    res = run("BS-D20", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.LOW
    assert res.cwe == ["CWE-1104"]
    assert res.severity_rationale and res.confidence_rationale


def test_d20_old_androidx_is_finding(make_ctx):
    src = '// uses androidx.appcompat:appcompat:0.9.0\npublic class A {}\n'
    res = run("BS-D20", make_ctx(("A.java", src)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.LOW


def test_d20_modern_androidx_passes(tmp_path):
    ctx = ctx_entries(tmp_path, ["androidx/appcompat/app/AppCompatActivity.class"])
    res = run("BS-D20", ctx)
    assert res.status == RuleStatus.PASS
