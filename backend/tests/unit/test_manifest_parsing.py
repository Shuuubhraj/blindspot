"""Unit tests for manifest app-name handling (hotfix-7).

Regression: DIVA's manifest stores android:label as a resource reference,
and the UI rendered the parser's "<type:0x01>" placeholder as the app name.
Unresolved references must never leak into the UI - app_name falls back to
"" so consumers use the package/file name, and apktool's decoded manifest
(which resolves @string/...) is used for best-effort recovery.
"""
import pytest

from blindspot.analysis.axml import ANDROID_NS, XAttr, XElement
from blindspot.analysis.manifest import (
    ManifestData,
    _parse_application,
    _unresolved_ref,
    refine_app_name_from_decoded_manifest,
)


def _app_el(label_value):
    return XElement(name="application", attrs=[
        XAttr(ns=ANDROID_NS, name="label", value=label_value),
    ])


def test_unresolved_ref_detection():
    assert _unresolved_ref("@string/app_name")
    assert _unresolved_ref("@0x7f0a0001")
    assert _unresolved_ref("<type:0x01>")
    assert not _unresolved_ref("Diva")
    assert not _unresolved_ref("")


def test_reference_label_never_becomes_app_name():
    for bad in ("@string/app_name", "@0x7f0a0001", "<type:0x01>"):
        m = ManifestData()
        _parse_application(_app_el(bad), m)
        assert m.app_name == "", f"leaked placeholder for {bad!r}"


def test_literal_label_kept():
    m = ManifestData()
    _parse_application(_app_el("Diva"), m)
    assert m.app_name == "Diva"


def test_refine_from_apktool_decoded_manifest(tmp_path):
    dec = tmp_path / "apktool"
    dec.mkdir()
    (dec / "AndroidManifest.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        ' package="jakhar.aseem.diva">\n'
        '  <application android:label="Diva" android:debuggable="true" />\n'
        '</manifest>', encoding="utf-8")
    assert refine_app_name_from_decoded_manifest(dec) == "Diva"


def test_refine_missing_or_unresolved(tmp_path):
    assert refine_app_name_from_decoded_manifest(tmp_path / "nope") == ""
    dec = tmp_path / "apktool2"
    dec.mkdir()
    (dec / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application android:label="@string/app_name" /></manifest>',
        encoding="utf-8")
    assert refine_app_name_from_decoded_manifest(dec) == ""
    # malformed XML must not raise
    dec2 = tmp_path / "apktool3"
    dec2.mkdir()
    (dec2 / "AndroidManifest.xml").write_text("not xml at all", encoding="utf-8")
    assert refine_app_name_from_decoded_manifest(dec2) == ""
