#!/usr/bin/env python3
"""Build backend/tests/fixtures/test-app.apk - a VALID synthetic APK fixture.

The APK is a real zip archive whose AndroidManifest.xml is REAL binary AXML
(encoded with blindspot's own axml.encode_axml). It contains intentionally
insecure configuration (debuggable, cleartext, exported components, dangerous
permissions) plus synthetic secret-bearing files. Nothing here is a real app,
real key, or real secret.

After writing, the script re-reads the APK from disk, parses
AndroidManifest.xml back with axml.parse_axml, and asserts that package,
debuggable, SDK levels and permissions round-trip correctly. It also tries
androguard (if installed in backend/.venv) as a second-opinion parse, and
prints a zip listing + SHA-256.

Usage (from backend/):
    .venv/bin/python tests/fixtures/make_fixture_apk.py
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import zipfile
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent          # backend/tests/fixtures
BACKEND_DIR = THIS_DIR.parent.parent                # backend/
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from blindspot.analysis.axml import ANDROID_NS, XAttr, XElement, encode_axml, parse_axml

OUT = THIS_DIR / "test-app.apk"

PACKAGE = "com.blindspot.testapp"

PERMISSIONS = [
    "android.permission.INTERNET",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
]


def A(name: str, value: object) -> XAttr:
    """android:-namespaced attribute."""
    return XAttr(ANDROID_NS, name, value)


def P(name: str, value: object) -> XAttr:
    """Plain (un-namespaced) attribute."""
    return XAttr("", name, value)


def E(name: str, attrs: list[XAttr] | None = None,
      children: list[XElement] | None = None) -> XElement:
    return XElement(name=name, attrs=attrs or [], children=children or [])


def build_manifest() -> bytes:
    """Construct the manifest tree and encode it as real binary AXML."""

    def data_el() -> XElement:
        return E("data", [A("scheme", "https"),
                          A("host", "testapp.blindspot.example"),
                          A("path", "/applink")])

    main_filter = E("intent-filter", children=[
        E("action", [A("name", "android.intent.action.VIEW")]),
        E("category", [A("name", "android.intent.category.DEFAULT")]),
        E("category", [A("name", "android.intent.category.BROWSABLE")]),
        data_el(),  # deliberately NO android:autoVerify attribute
    ])

    sms_filter = E("intent-filter", children=[
        E("action", [A("name", "android.provider.Telephony.SMS_RECEIVED")]),
    ])

    application = E("application", [
        A("label", "@string/app_name"),
        A("debuggable", True),
        A("allowBackup", True),
        A("usesCleartextTraffic", True),
    ], children=[
        E("activity", [
            A("name", PACKAGE + ".MainActivity"),
            A("exported", True),          # exported, no android:permission
        ], children=[main_filter]),
        E("activity", [
            A("name", PACKAGE + ".DebugActivity"),
            A("exported", True),          # debug activity exported
        ]),
        E("receiver", [
            A("name", PACKAGE + ".SmsReceiver"),
            A("exported", True),          # exported, no android:permission
        ], children=[sms_filter]),
        E("provider", [
            A("name", PACKAGE + ".TestProvider"),
            A("authorities", PACKAGE + ".files"),
            A("exported", True),
            A("grantUriPermissions", True),
            # deliberately NO android:readPermission / android:writePermission
        ]),
    ])

    manifest = E("manifest", [
        P("package", PACKAGE),
        A("versionCode", 1),
        A("versionName", "1.0"),
    ], children=[
        E("uses-sdk", [A("minSdkVersion", 21), A("targetSdkVersion", 28)]),
        *[E("uses-permission", [A("name", p)]) for p in PERMISSIONS],
        application,
    ])
    return encode_axml(manifest)


STRINGS_XML = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Blindspot Test App</string>
    <string name="api_key">AIzaSyD-testkey-1234567890abcdef</string>
    <string name="welcome">Welcome to the synthetic fixture app</string>
</resources>
"""

# ---------------------------------------------------------------------------
# Clearly synthetic, non-functional PEM. This is NOT a real key: the body is
# a human-readable label, not base64 key material, and will not parse as one.
# ---------------------------------------------------------------------------
FAKE_PEM = """-----BEGIN RSA PRIVATE KEY-----
FAKE TEST KEY \u2014 NOT REAL.
Synthetic fixture for the Blindspot scanner test suite.
This block contains no key material and cannot be used cryptographically.
-----END RSA PRIVATE KEY-----
"""

# 64 bytes of dummy content, documented as synthetic (not a real .so).
NATIVE_SO = b"BLINDSPOT_SYNTHETIC_TEST_FIXTURE_NOT_A_REAL_BINARY__" + b"\x00" * 12
assert len(NATIVE_SO) == 64, len(NATIVE_SO)

MANIFEST_MF = """Manifest-Version: 1.0
Created-By: blindspot-fixture-generator (synthetic test fixture)
X-Fixture: true
"""


def assert_zip_safety(entries: dict[str, bytes]) -> None:
    """Every entry must use forward slashes, be relative, and contain no '..'."""
    for name in entries:
        assert "\\" not in name, f"backslash in entry: {name}"
        assert not name.startswith("/"), f"absolute entry: {name}"
        parts = name.split("/")
        assert ".." not in parts, f"parent traversal in entry: {name}"
        assert all(p not in ("", ".") for p in parts), f"empty/dot segment: {name}"


def main() -> None:
    entries: dict[str, bytes] = {
        "AndroidManifest.xml": build_manifest(),
        "res/values/strings.xml": STRINGS_XML.encode("utf-8"),
        "assets/private_key.pem": FAKE_PEM.encode("utf-8"),
        "lib/armeabi-v7a/libnative.so": NATIVE_SO,
        "META-INF/MANIFEST.MF": MANIFEST_MF.encode("utf-8"),
    }
    assert_zip_safety(entries)

    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)

    size = OUT.stat().st_size
    sha256 = hashlib.sha256(OUT.read_bytes()).hexdigest()
    print(f"wrote {OUT}  ({size} bytes, sha256={sha256})")

    # ---- verify: read back from disk and re-parse the AXML manifest ----
    with zipfile.ZipFile(OUT) as zf:
        names = zf.namelist()
        axml_bytes = zf.read("AndroidManifest.xml")
        strings_back = zf.read("res/values/strings.xml").decode("utf-8")
        pem_back = zf.read("assets/private_key.pem").decode("utf-8")
        so_back = zf.read("lib/armeabi-v7a/libnative.so")
    assert names == list(entries), f"zip entries changed: {names}"
    assert '<string name="api_key">' in strings_back
    assert "FAKE TEST KEY" in pem_back
    assert len(so_back) == 64

    root = parse_axml(axml_bytes)
    assert root.name == "manifest", root.name
    assert root.attr("package") == PACKAGE, root.attr("package")
    assert root.attr("versionCode", ANDROID_NS) == 1
    assert root.attr("versionName", ANDROID_NS) == "1.0"

    uses_sdk = root.find("uses-sdk")
    assert uses_sdk is not None
    assert uses_sdk.attr("minSdkVersion", ANDROID_NS) == 21
    assert uses_sdk.attr("targetSdkVersion", ANDROID_NS) == 28

    perms = {p.attr("name", ANDROID_NS) for p in root.findall("uses-permission")}
    assert perms == set(PERMISSIONS), perms

    app = root.find("application")
    assert app is not None
    assert app.attr("debuggable", ANDROID_NS) is True
    assert app.attr("allowBackup", ANDROID_NS) is True
    assert app.attr("usesCleartextTraffic", ANDROID_NS) is True

    acts = {a.attr("name", ANDROID_NS): a for a in app.findall("activity")}
    assert acts[PACKAGE + ".MainActivity"].attr("exported", ANDROID_NS) is True
    assert acts[PACKAGE + ".DebugActivity"].attr("exported", ANDROID_NS) is True
    recvs = app.findall("receiver")
    assert len(recvs) == 1 and recvs[0].attr("exported", ANDROID_NS) is True
    provs = app.findall("provider")
    assert len(provs) == 1
    assert provs[0].attr("exported", ANDROID_NS) is True
    assert provs[0].attr("grantUriPermissions", ANDROID_NS) is True
    assert provs[0].attr("readPermission", ANDROID_NS) is None
    assert provs[0].attr("writePermission", ANDROID_NS) is None
    # deep link intent-filter has no autoVerify attribute
    filt = acts[PACKAGE + ".MainActivity"].find("intent-filter")
    assert filt is not None
    data_el = filt.find("data")
    assert data_el is not None and data_el.attr("autoVerify", ANDROID_NS) is None
    print("AXML round-trip verification: PASS "
          "(package, debuggable, SDK levels, 7 permissions, components)")

    # ---- second opinion: androguard (optional) ----
    try:
        from androguard.core.apk import APK  # type: ignore
    except ImportError:
        print("androguard: SKIPPED (not importable from this interpreter)")
    else:
        try:
            apk = APK(str(OUT))
            print(f"androguard: package={apk.get_package()} "
                  f"version={apk.get_androidversion_name()} "
                  f"({apk.get_androidversion_code()})")
            print(f"androguard: permissions={sorted(apk.get_permissions())}")
            print(f"androguard: debuggable={apk.get_attribute_value('application', 'debuggable')}")
        except Exception as exc:  # noqa: BLE001
            print(f"androguard: SKIPPED (parse failed: {exc})")

    # ---- zip listing ----
    print("zip listing:")
    subprocess.run(["unzip", "-l", str(OUT)], check=True)


if __name__ == "__main__":
    main()
