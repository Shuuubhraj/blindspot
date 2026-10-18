"""Unit tests for blindspot.rules.manifest_rules (BS-M01 .. BS-M20).

Every rule gets at least one vulnerable -> FINDING/NEEDS_REVIEW test and one
clean -> PASS test, exercised through Rule.run() so applies() is covered too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from blindspot.rules.base import (
    Component,
    CustomPermission,
    IntentFilter,
    ManifestData,
    Permission,
    RuleStatus,
    ScanContext,
    Severity,
)
from blindspot.rules.manifest_rules import RULES

RULES_BY_ID = {r.id: r for r in RULES}


def _ctx(manifest: ManifestData | None = None, **kwargs) -> ScanContext:
    return ScanContext(
        scan_id="test-scan",
        workdir=Path("/tmp/blindspot-manifest-test"),
        apk_path=Path("/tmp/blindspot-manifest-test/app.apk"),
        manifest=manifest,
        **kwargs,
    )


def _run(rule_id: str, manifest: ManifestData | None, **kwargs):
    return RULES_BY_ID[rule_id].run(_ctx(manifest, **kwargs))


def _perm(name: str) -> Permission:
    return Permission(name=name)


# ---------------------------------------------------------------------------
# Registry sanity
# ---------------------------------------------------------------------------

def test_rule_count_and_ids():
    assert len(RULES) == 20
    expected = {f"BS-M{i:02d}" for i in range(1, 21)}
    assert set(RULES_BY_ID) == expected


def test_all_rules_manifest_category():
    for rule in RULES:
        assert rule.category == "manifest", rule.id


def test_applies_returns_not_applicable_when_manifest_none():
    for rule in RULES:
        res = rule.run(_ctx(None))
        assert res.status == RuleStatus.NOT_APPLICABLE, rule.id
        assert res.rule_id == rule.id


def test_every_finding_carries_rationales():
    # BS-M01 debuggable as representative: rationales must be non-empty.
    res = _run("BS-M01", ManifestData(debuggable=True))
    assert res.status == RuleStatus.FINDING
    assert res.severity_rationale
    assert res.confidence_rationale
    assert res.owasp == ["M8"]
    assert res.cwe == ["CWE-489"]


# ---------------------------------------------------------------------------
# BS-M01 debuggable
# ---------------------------------------------------------------------------

def test_m01_debuggable_finding():
    res = _run("BS-M01", ManifestData(debuggable=True))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.evidence and res.evidence[0].file_path == "AndroidManifest.xml"
    assert res.evidence[0].line_start is None


def test_m01_debuggable_pass():
    res = _run("BS-M01", ManifestData(debuggable=False))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M02 allowBackup
# ---------------------------------------------------------------------------

def test_m02_backup_defaulted_finding():
    # ManifestData defaults allow_backup=True (attribute absent -> defaulted).
    res = _run("BS-M02", ManifestData(allow_backup=True))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.owasp == ["M9"] and res.cwe == ["CWE-312"]


def test_m02_backup_disabled_pass():
    res = _run("BS-M02", ManifestData(allow_backup=False))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M03 usesCleartextTraffic=true
# ---------------------------------------------------------------------------

def test_m03_cleartext_true_finding():
    res = _run("BS-M03", ManifestData(uses_cleartext_traffic=True))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.owasp == ["M5"] and res.cwe == ["CWE-319"]


def test_m03_cleartext_false_pass():
    res = _run("BS-M03", ManifestData(uses_cleartext_traffic=False))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M04 SDK policy
# ---------------------------------------------------------------------------

def test_m04_outdated_target_sdk_finding():
    res = _run("BS-M04", ManifestData(target_sdk=29, min_sdk=23))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert any("targetSdkVersion" in e.description for e in res.evidence)


def test_m04_old_min_sdk_separate_evidence():
    res = _run("BS-M04", ManifestData(target_sdk=33, min_sdk=21))
    assert res.status == RuleStatus.FINDING
    assert any("minSdkVersion" in e.description for e in res.evidence)


def test_m04_modern_sdks_pass():
    res = _run("BS-M04", ManifestData(target_sdk=34, min_sdk=26))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M05 dangerous permissions per group
# ---------------------------------------------------------------------------

def test_m05_dangerous_permissions_finding():
    res = _run(
        "BS-M05",
        ManifestData(permissions=[
            _perm("android.permission.READ_SMS"),
            _perm("android.permission.CAMERA"),
        ]),
    )
    assert res.status == RuleStatus.FINDING
    # SMS group -> MEDIUM overall
    assert res.severity == Severity.MEDIUM
    assert len(res.evidence) == 2
    assert any("SMS" in e.description for e in res.evidence)


def test_m05_low_group_only():
    res = _run("BS-M05", ManifestData(permissions=[_perm("android.permission.CAMERA")]))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.LOW


def test_m05_normal_permissions_pass():
    res = _run(
        "BS-M05",
        ManifestData(permissions=[
            _perm("android.permission.INTERNET"),
            _perm("android.permission.ACCESS_NETWORK_STATE"),
        ]),
    )
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M06 excessive scope
# ---------------------------------------------------------------------------

def test_m06_three_distinct_groups_finding():
    res = _run(
        "BS-M06",
        ManifestData(permissions=[
            _perm("android.permission.READ_SMS"),
            _perm("android.permission.CAMERA"),
            _perm("android.permission.ACCESS_FINE_LOCATION"),
        ]),
    )
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM


def test_m06_two_groups_pass():
    res = _run(
        "BS-M06",
        ManifestData(permissions=[
            _perm("android.permission.READ_SMS"),
            _perm("android.permission.RECEIVE_SMS"),
            _perm("android.permission.CAMERA"),
        ]),
    )
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M07 exported activity
# ---------------------------------------------------------------------------

def test_m07_exported_activity_no_permission_finding():
    res = _run(
        "BS-M07",
        ManifestData(activities=[
            Component(kind="activity", name=".Main", exported=True),
        ]),
    )
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.cwe == ["CWE-926"]


def test_m07_guarded_or_internal_pass():
    res = _run(
        "BS-M07",
        ManifestData(activities=[
            Component(kind="activity", name=".Main", exported=True,
                      permission="com.example.PERM"),
            Component(kind="activity", name=".Internal", exported=False),
        ]),
    )
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M08 exported service
# ---------------------------------------------------------------------------

def test_m08_exported_service_no_permission_finding():
    res = _run(
        "BS-M08",
        ManifestData(services=[
            Component(kind="service", name=".Sync", exported=True),
        ]),
    )
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH


def test_m08_guarded_service_pass():
    res = _run(
        "BS-M08",
        ManifestData(services=[
            Component(kind="service", name=".Sync", exported=True,
                      permission="android.permission.BIND_JOB_SERVICE"),
        ]),
    )
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M09 exported receiver
# ---------------------------------------------------------------------------

def test_m09_exported_receiver_no_permission_finding():
    res = _run(
        "BS-M09",
        ManifestData(receivers=[
            Component(kind="receiver", name=".Boot", exported=True),
        ]),
    )
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.cwe == ["CWE-927"]


def test_m09_internal_receiver_pass():
    res = _run(
        "BS-M09",
        ManifestData(receivers=[
            Component(kind="receiver", name=".Boot", exported=False),
        ]),
    )
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M10 exported provider
# ---------------------------------------------------------------------------

def test_m10_exported_provider_no_rw_permission_finding():
    res = _run(
        "BS-M10",
        ManifestData(providers=[
            Component(kind="provider", name=".Data", exported=True,
                      authorities="com.example.data"),
        ]),
    )
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH


def test_m10_provider_with_read_permission_pass():
    res = _run(
        "BS-M10",
        ManifestData(providers=[
            Component(kind="provider", name=".Data", exported=True,
                      authorities="com.example.data",
                      read_permission="com.example.READ"),
        ]),
    )
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M11 grantUriPermissions
# ---------------------------------------------------------------------------

def test_m11_grant_uri_permissions_finding():
    res = _run(
        "BS-M11",
        ManifestData(providers=[
            Component(kind="provider", name=".Files", exported=True,
                      authorities="com.example.files",
                      grant_uri_permissions=True),
        ]),
    )
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM


def test_m11_no_grant_pass():
    res = _run(
        "BS-M11",
        ManifestData(providers=[
            Component(kind="provider", name=".Files", exported=True,
                      authorities="com.example.files",
                      grant_uri_permissions=False),
        ]),
    )
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M12 task hijacking
# ---------------------------------------------------------------------------

_TASK_RAW = (
    '<manifest package="com.example.app"><application>'
    '<activity android:name=".Main" android:exported="true" '
    'android:launchMode="singleTask" android:taskAffinity="com.evil.app">'
    '<intent-filter/></activity></application></manifest>'
)


def test_m12_singletask_foreign_affinity_finding():
    m = ManifestData(
        package="com.example.app",
        target_sdk=30,
        activities=[Component(kind="activity", name=".Main", exported=True)],
        raw_xml=_TASK_RAW,
    )
    res = _run("BS-M12", m)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.cwe == ["CWE-451"]


def test_m12_affinity_equal_to_package_pass():
    raw = _TASK_RAW.replace('android:taskAffinity="com.evil.app"',
                            'android:taskAffinity="com.example.app"')
    m = ManifestData(
        package="com.example.app",
        target_sdk=30,
        activities=[Component(kind="activity", name=".Main", exported=True)],
        raw_xml=raw,
    )
    res = _run("BS-M12", m)
    assert res.status == RuleStatus.PASS


def test_m12_no_raw_xml_pass_with_note():
    m = ManifestData(
        package="com.example.app",
        activities=[Component(kind="activity", name=".Main", exported=True)],
        raw_xml="",
    )
    res = _run("BS-M12", m)
    assert res.status == RuleStatus.PASS
    assert "unavailable" in res.summary


# ---------------------------------------------------------------------------
# BS-M13 weak custom permission
# ---------------------------------------------------------------------------

def test_m13_weak_custom_permission_finding():
    m = ManifestData(
        custom_permissions=[CustomPermission(name="com.example.MYPERM",
                                             protection_level="normal")],
        activities=[Component(kind="activity", name=".A", exported=True,
                              permission="com.example.MYPERM")],
    )
    res = _run("BS-M13", m)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.owasp == ["M3"]


def test_m13_signature_permission_pass():
    m = ManifestData(
        custom_permissions=[CustomPermission(name="com.example.MYPERM",
                                             protection_level="signature")],
        activities=[Component(kind="activity", name=".A", exported=True,
                              permission="com.example.MYPERM")],
    )
    res = _run("BS-M13", m)
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M14 intent-filter exposure (needs review)
# ---------------------------------------------------------------------------

def test_m14_intent_filter_no_permission_needs_review():
    m = ManifestData(
        target_sdk=30,
        activities=[Component(
            kind="activity", name=".Deep", exported=True,
            intent_filters=[IntentFilter(actions=["android.intent.action.VIEW"])])],
    )
    res = _run("BS-M14", m)
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert "intent" in res.summary.lower()


def test_m14_no_intent_filters_pass():
    m = ManifestData(
        activities=[Component(kind="activity", name=".A", exported=True)],
    )
    res = _run("BS-M14", m)
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M15 network security config (informational)
# ---------------------------------------------------------------------------

def test_m15_no_nsc_informational():
    res = _run("BS-M15", ManifestData(network_security_config=None))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO
    assert res.owasp == ["M5"]


def test_m15_nsc_present_pass():
    res = _run("BS-M15", ManifestData(network_security_config="@xml/nsc"))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M16 backup rules content
# ---------------------------------------------------------------------------

def _res_ctx(tmp_path: Path, manifest: ManifestData, xml_text: str | None):
    xml_dir = tmp_path / "res" / "xml"
    xml_dir.mkdir(parents=True, exist_ok=True)
    if xml_text is not None:
        (xml_dir / "backup_rules.xml").write_text(xml_text)
    return _ctx(manifest, res_dir=tmp_path / "res")


def test_m16_sensitive_include_needs_review(tmp_path):
    xml = ('<full-backup-content>'
           '<include domain="database" path="." />'
           '<include domain="sharedpref" path="." />'
           '</full-backup-content>')
    m = ManifestData(full_backup_content="@xml/backup_rules")
    res = RULES_BY_ID["BS-M16"].run(_res_ctx(tmp_path, m, xml))
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert res.owasp == ["M9"]
    assert "database" in res.summary


def test_m16_no_sensitive_include_pass(tmp_path):
    xml = ('<full-backup-content>'
           '<exclude domain="database" path="." />'
           '</full-backup-content>')
    m = ManifestData(full_backup_content="@xml/backup_rules")
    res = RULES_BY_ID["BS-M16"].run(_res_ctx(tmp_path, m, xml))
    assert res.status == RuleStatus.PASS


def test_m16_no_rules_referenced_pass(tmp_path):
    m = ManifestData()
    res = RULES_BY_ID["BS-M16"].run(_res_ctx(tmp_path, m, None))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M17 cleartext default
# ---------------------------------------------------------------------------

def test_m17_unset_with_old_target_finding():
    res = _run("BS-M17", ManifestData(uses_cleartext_traffic=None, target_sdk=27))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM


def test_m17_unset_with_new_target_pass():
    res = _run("BS-M17", ManifestData(uses_cleartext_traffic=None, target_sdk=30))
    assert res.status == RuleStatus.PASS


def test_m17_explicit_false_pass():
    res = _run("BS-M17", ManifestData(uses_cleartext_traffic=False, target_sdk=27))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M18 implicit export
# ---------------------------------------------------------------------------

_IMPLICIT_RAW = (
    '<manifest package="com.example.app"><application>'
    '<activity android:name=".Implicit">'
    '<intent-filter><action android:name="android.intent.action.VIEW"/>'
    '</intent-filter></activity>'
    '<activity android:name=".Explicit" android:exported="true">'
    '<intent-filter><action android:name="android.intent.action.VIEW"/>'
    '</intent-filter></activity>'
    '</application></manifest>'
)


def test_m18_implicit_export_finding():
    m = ManifestData(package="com.example.app", target_sdk=29, raw_xml=_IMPLICIT_RAW)
    res = _run("BS-M18", m)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.cwe == ["CWE-926"]
    descs = " ".join(e.description for e in res.evidence)
    assert ".Implicit" in descs
    assert ".Explicit" not in descs


def test_m18_target_31_no_implicit_export_pass():
    m = ManifestData(package="com.example.app", target_sdk=31, raw_xml=_IMPLICIT_RAW)
    res = _run("BS-M18", m)
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M19 package visibility
# ---------------------------------------------------------------------------

def test_m19_query_all_packages_finding():
    res = _run(
        "BS-M19",
        ManifestData(permissions=[
            _perm("android.permission.QUERY_ALL_PACKAGES"),
        ]),
    )
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.owasp == ["M6"]


def test_m19_no_such_permissions_pass():
    res = _run("BS-M19", ManifestData(permissions=[_perm("android.permission.INTERNET")]))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-M20 exported attack surface
# ---------------------------------------------------------------------------

def test_m20_six_exported_informational():
    comps = [
        Component(kind="activity", name=f".A{i}", exported=True) for i in range(4)
    ] + [
        Component(kind="service", name=".S1", exported=True),
        Component(kind="receiver", name=".R1", exported=True),
    ]
    m = ManifestData(activities=comps[:4], services=[comps[4]], receivers=[comps[5]])
    res = _run("BS-M20", m)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.INFO
    assert len(res.evidence) == 6


def test_m20_five_exported_pass():
    comps = [Component(kind="activity", name=f".A{i}", exported=True) for i in range(5)]
    res = _run("BS-M20", ManifestData(activities=comps))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# Error isolation: a rule must never raise out of run()
# ---------------------------------------------------------------------------

def test_run_never_raises_on_broken_manifest():
    class Broken:
        pass
    res = RULES_BY_ID["BS-M01"].run(_ctx(Broken()))  # type: ignore[arg-type]
    assert res.status in (RuleStatus.ERROR, RuleStatus.NOT_APPLICABLE, RuleStatus.PASS)
