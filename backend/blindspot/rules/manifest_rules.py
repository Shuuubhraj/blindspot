"""Manifest & Android configuration detection rules (BS-M01 .. BS-M20).

BS-M01 Debuggable application (android:debuggable=true)
BS-M02 Backup enabled (android:allowBackup=true, explicit or defaulted)
BS-M03 Cleartext traffic explicitly allowed
BS-M04 Outdated targetSdkVersion / pre-runtime-permission minSdkVersion
BS-M05 Dangerous permissions declared (one inventory per permission group)
BS-M06 Excessive permission scope (3+ dangerous perms, distinct sensitive groups)
BS-M07 Exported activity without a permission guard
BS-M08 Exported service without a permission guard
BS-M09 Exported broadcast receiver without a permission guard
BS-M10 Exported content provider without read/write permission guards
BS-M11 Content provider with grantUriPermissions=true
BS-M12 Task-hijacking configuration (singleTask + foreign taskAffinity)
BS-M13 Exported component guarded only by a weak (normal/dangerous) custom permission
BS-M14 Intent-filter-reachable component without permission guard (review inventory)
BS-M15 No networkSecurityConfig referenced (informational inventory)
BS-M16 Backup/extraction rules XML includes sensitive domains
BS-M17 Cleartext traffic defaulted on (unset + targetSdk < 28)
BS-M18 Implicitly exported component (intent-filter, no android:exported, targetSdk < 31)
BS-M19 Broad package visibility (QUERY_ALL_PACKAGES / REQUEST_INSTALL_PACKAGES)
BS-M20 Large exported attack surface (6+ exported components, informational)

Evidence convention: manifest attributes have no line numbers, so every
Evidence uses file_path="AndroidManifest.xml" with line_start/line_end None
and a description naming the exact attribute/component. Raw-XML regex helpers
are used for attributes (launchMode, taskAffinity, android:exported presence)
that the parsed Component model does not carry.

Note on BS-M05: the framework returns one RuleResult per rule, so the
"one finding per dangerous permission group" requirement is implemented as
one RuleResult carrying one Evidence entry per dangerous permission, each
entry labelled with its group and group severity.
"""

from __future__ import annotations

import re
from typing import Optional

from .base import (
    Component,
    Confidence,
    Evidence,
    ManifestData,
    Rule,
    RuleResult,
    ScanContext,
    Severity,
    finding,
    needs_review,
    pass_result,
)
from .common import read_text_capped

MANIFEST_PATH = "AndroidManifest.xml"

_OWASP_MTOP10 = "https://owasp.org/projects/mobile-top-10"


def _cwe(num: int) -> str:
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------

def _mev(description: str, snippet: str = "") -> Evidence:
    """Manifest evidence: never invent line numbers for XML attributes."""
    return Evidence(
        file_path=MANIFEST_PATH,
        snippet=snippet or description,
        description=description,
        line_start=None,
        line_end=None,
    )


def _component_desc(comp: Component, note: str) -> str:
    return f"<{comp.kind} android:name=\"{comp.name}\"> {note}"


def _all_components(m: ManifestData) -> list[Component]:
    return list(m.activities) + list(m.services) + list(m.receivers) + list(m.providers)


def _guard_of(comp: Component) -> Optional[str]:
    """Any permission-like guard on the component (providers use read/write)."""
    return comp.permission or comp.read_permission or comp.write_permission


# ---------------------------------------------------------------------------
# Raw-XML helpers (for attributes the parsed model does not carry)
# ---------------------------------------------------------------------------

_TAG_RE = re.compile(
    r"<(activity|activity-alias|service|receiver|provider)\b([^>]*?)>",
    re.IGNORECASE | re.DOTALL,
)
_NAME_RE = re.compile(r'android:name\s*=\s*"([^"]+)"')
_INTENT_FILTER_RE = re.compile(r"<intent-filter\b", re.IGNORECASE)
_LAUNCHMODE_RE = re.compile(r'android:launchMode\s*=\s*"([^"]+)"', re.IGNORECASE)
_TASKAFFINITY_RE = re.compile(r'android:taskAffinity\s*=\s*"([^"]*)"', re.IGNORECASE)
_EXPORTED_ATTR_RE = re.compile(r'android:exported\s*=\s*"(true|false)"', re.IGNORECASE)


def _xml_tags(raw_xml: str):
    """Yield (kind, attrs, name, has_intent_filter) for each component tag."""
    for m in _TAG_RE.finditer(raw_xml):
        raw_kind = m.group(1).lower()
        kind = "activity" if raw_kind == "activity-alias" else raw_kind
        attrs = m.group(2)
        name_m = _NAME_RE.search(attrs)
        name = name_m.group(1) if name_m else ""
        close = raw_xml.find(f"</{m.group(1)}>", m.end())
        body = raw_xml[m.end():close] if close != -1 else ""
        yield kind, attrs, name, _INTENT_FILTER_RE.search(body) is not None


def _match_component_tag(
    raw_xml: str, kind: str, comp_name: str, package: str
) -> Optional[str]:
    """Return the attribute string of the XML tag best matching a Component.

    Matches exactly on full name, then on package-relative ".Name", and only
    falls back to short-class-name matching when exactly one tag matches.
    """
    if not raw_xml or not comp_name:
        return None
    short = comp_name.split(".")[-1]
    exact: list[str] = []
    short_hits: list[str] = []
    for tag_kind, attrs, xml_name, _ in _xml_tags(raw_xml):
        if tag_kind != kind or not xml_name:
            continue
        if xml_name == comp_name or (comp_name.startswith(".") and package + comp_name == xml_name):
            exact.append(attrs)
        elif xml_name.split(".")[-1] == short:
            short_hits.append(attrs)
    if exact:
        return exact[0]
    if len(short_hits) == 1:
        return short_hits[0]
    return None


# ---------------------------------------------------------------------------
# Permission group model (BS-M05 / BS-M06)
# ---------------------------------------------------------------------------

# permission short name -> (sensitive group, group severity)
_DANGEROUS_GROUPS: dict[str, tuple[str, Severity]] = {
    "READ_SMS": ("SMS", Severity.MEDIUM),
    "RECEIVE_SMS": ("SMS", Severity.MEDIUM),
    "SEND_SMS": ("SMS", Severity.MEDIUM),
    "RECEIVE_MMS": ("SMS", Severity.MEDIUM),
    "RECEIVE_WAP_PUSH": ("SMS", Severity.MEDIUM),
    "READ_CELL_BROADCASTS": ("SMS", Severity.MEDIUM),
    "READ_CALL_LOG": ("Call log", Severity.MEDIUM),
    "WRITE_CALL_LOG": ("Call log", Severity.MEDIUM),
    "PROCESS_OUTGOING_CALLS": ("Call log", Severity.MEDIUM),
    "READ_CONTACTS": ("Contacts", Severity.LOW),
    "WRITE_CONTACTS": ("Contacts", Severity.LOW),
    "GET_ACCOUNTS": ("Contacts", Severity.LOW),
    "ACCESS_FINE_LOCATION": ("Location", Severity.MEDIUM),
    "ACCESS_COARSE_LOCATION": ("Location", Severity.MEDIUM),
    "ACCESS_BACKGROUND_LOCATION": ("Location", Severity.MEDIUM),
    "RECORD_AUDIO": ("Microphone", Severity.LOW),
    "CAMERA": ("Camera", Severity.LOW),
    "READ_EXTERNAL_STORAGE": ("Storage", Severity.LOW),
    "WRITE_EXTERNAL_STORAGE": ("Storage", Severity.LOW),
    "MANAGE_EXTERNAL_STORAGE": ("Storage", Severity.MEDIUM),
    "READ_MEDIA_IMAGES": ("Storage", Severity.LOW),
    "READ_MEDIA_VIDEO": ("Storage", Severity.LOW),
    "READ_MEDIA_AUDIO": ("Storage", Severity.LOW),
    "READ_PHONE_STATE": ("Phone", Severity.LOW),
    "READ_PHONE_NUMBERS": ("Phone", Severity.LOW),
    "CALL_PHONE": ("Phone", Severity.LOW),
    "ANSWER_PHONE_CALLS": ("Phone", Severity.LOW),
    "READ_CALENDAR": ("Calendar", Severity.LOW),
    "WRITE_CALENDAR": ("Calendar", Severity.LOW),
    "BODY_SENSORS": ("Body sensors", Severity.LOW),
    "BODY_SENSORS_BACKGROUND": ("Body sensors", Severity.LOW),
}


def _dangerous_hits(m: ManifestData) -> list[tuple[str, str, Severity]]:
    """Return (full permission name, group, group severity) for dangerous perms."""
    hits: list[tuple[str, str, Severity]] = []
    for perm in m.permissions:
        short = perm.name.split(".")[-1].upper()
        if short in _DANGEROUS_GROUPS:
            group, sev = _DANGEROUS_GROUPS[short]
            hits.append((perm.name, group, sev))
    return hits


# ---------------------------------------------------------------------------
# Backup-rules XML helpers (BS-M16)
# ---------------------------------------------------------------------------

_INCLUDE_RE = re.compile(r"<include\b[^>]*>", re.IGNORECASE)
_DOMAIN_RE = re.compile(r'domain\s*=\s*"([^"]+)"', re.IGNORECASE)
_SENSITIVE_DOMAINS = {"database", "sharedpref", "shared_prefs", "file", "files", "external", "root"}


def _resolve_xml_resource(ctx: ScanContext, value: str):
    v = value.strip()
    if v.startswith("@xml/"):
        name = v[len("@xml/"):]
    elif v.startswith("@"):
        return None
    else:
        name = v
    if not name or not ctx.res_dir:
        return None
    p = ctx.res_dir / "xml" / f"{name}.xml"
    return p if p.is_file() else None


# ===========================================================================
# Rule implementations
# ===========================================================================

class DebuggableRule(Rule):
    """BS-M01: android:debuggable=true in the application tag."""

    id = "BS-M01"
    title = "Application is debuggable"
    description = (
        "The <application> tag sets android:debuggable=\"true\". Debuggable builds "
        "allow any local process with adb access to attach a debugger, inspect "
        "memory, and step through code on a user device."
    )
    rationale = (
        "Debuggable release builds remove a key local protection boundary: an "
        "attacker with brief physical/adb access (or malware already on the "
        "device) can attach jdb/IDA, dump secrets from memory, and bypass "
        "client-side checks without rooting or repackaging."
    )
    category = "manifest"
    default_severity = Severity.HIGH
    owasp = ["M8"]
    cwe = ["CWE-489"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Remove android:debuggable=\"true\" from the release manifest (or set it "
        "to false). Keep debuggable builds internal only; verify the shipped APK "
        "with `aapt dump badging` / apkanalyzer and in CI."
    )
    references = [_cwe(489), _OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        if m.debuggable:
            explicit = 'android:debuggable="true"' in (m.raw_xml or "")
            snippet = (
                'android:debuggable="true"'
                if explicit
                else "application tag parsed with debuggable=true"
            )
            return finding(
                self,
                "Application tag sets android:debuggable=\"true\". The app can be "
                "attached by a debugger on any device with adb access.",
                [_mev(
                    "Application is debuggable"
                    + (" (explicit attribute)" if explicit else " (parsed flag)"),
                    snippet,
                )],
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "HIGH: a debuggable release build exposes the running process to "
                    "debugger attachment on user devices, enabling memory inspection, "
                    "secret extraction, and bypass of local protections."
                ),
                confidence_rationale=(
                    "HIGH: the flag is a literal boolean on the application tag, "
                    "parsed directly from the decoded manifest."
                ),
            )
        return pass_result(self, "android:debuggable is not enabled.")


class BackupEnabledRule(Rule):
    """BS-M02: android:allowBackup=true (explicit or defaulted)."""

    id = "BS-M02"
    title = "Application backup enabled"
    description = (
        "android:allowBackup is true (either explicitly set or left at its "
        "default). App data can be backed up via adb and restored onto another "
        "device, exposing files, databases, and shared preferences."
    )
    rationale = (
        "Auto Backup / adb backup copies the app's private data directory. If "
        "the app stores tokens, credentials, or PII in files, SQLite, or "
        "shared preferences, an attacker with brief device access can extract "
        "them without root."
    )
    category = "manifest"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-312"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Set android:allowBackup=\"false\" unless backup is a genuine product "
        "requirement. If backup is required, use a restrictive "
        "android:fullBackupContent / android:dataExtractionRules file that "
        "excludes sensitive files, and encrypt sensitive data at rest."
    )
    references = [_cwe(312), _OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        if m.allow_backup:
            explicit = 'android:allowBackup="true"' in (m.raw_xml or "")
            origin = "explicitly set" if explicit else "defaulted (attribute absent)"
            return finding(
                self,
                f"android:allowBackup is true ({origin}). App-private data can be "
                "extracted via adb backup / Auto Backup and restored elsewhere.",
                [_mev(
                    f"allowBackup=true ({origin})",
                    'android:allowBackup="true"' if explicit
                    else "android:allowBackup attribute absent; Android defaults it to true",
                )],
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "MEDIUM: backup exposes app-private storage to anyone with adb "
                    "access; impact depends on what sensitive data the app stores, "
                    "which cannot be fully determined from the manifest alone."
                ),
                confidence_rationale=(
                    "HIGH: allowBackup is a manifest-level boolean; when the "
                    "attribute is absent Android defaults it to true, which is "
                    "documented platform behavior."
                ),
            )
        return pass_result(self, "android:allowBackup is false; backups are disabled.")


class CleartextTrafficRule(Rule):
    """BS-M03: android:usesCleartextTraffic=true."""

    id = "BS-M03"
    title = "Cleartext HTTP traffic explicitly allowed"
    description = (
        "The application tag sets android:usesCleartextTraffic=\"true\", opting "
        "out of Android's cleartext-traffic block and permitting HTTP URLs."
    )
    rationale = (
        "Cleartext HTTP exposes all request/response data, cookies, and tokens "
        "to passive network observers. Explicitly opting out of the platform "
        "default (block cleartext for targetSdk >= 28) signals the app may "
        "actually transmit data over HTTP."
    )
    category = "manifest"
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Remove android:usesCleartextTraffic=\"true\" (or set it to false) and "
        "migrate endpoints to HTTPS. If a specific legacy host must stay on "
        "HTTP, scope the exception to that host in a network security config "
        "instead of allowing cleartext globally."
    )
    references = [_cwe(319), _OWASP_MTOP10,
                  "https://developer.android.com/training/articles/security-config"]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        if m.uses_cleartext_traffic is True:
            return finding(
                self,
                "android:usesCleartextTraffic=\"true\": the app explicitly permits "
                "cleartext HTTP traffic, so sensitive data may traverse the "
                "network unencrypted.",
                [_mev(
                    "Application allows cleartext traffic",
                    'android:usesCleartextTraffic="true"',
                )],
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "HIGH: cleartext HTTP exposes credentials, tokens, and PII to "
                    "any passive network observer; the opt-out is global to the app."
                ),
                confidence_rationale=(
                    "HIGH: the attribute value is read directly from the decoded "
                    "manifest application tag."
                ),
            )
        return pass_result(self, "usesCleartextTraffic is not set to true.")


class SdkPolicyRule(Rule):
    """BS-M04: outdated targetSdkVersion / pre-runtime-permission minSdkVersion."""

    id = "BS-M04"
    title = "Outdated SDK policy (targetSdk / minSdk)"
    description = (
        "targetSdkVersion below 30 misses modern platform security behaviors; "
        "minSdkVersion below 23 means the app can install on devices without "
        "the runtime-permission model (permissions granted at install time)."
    )
    rationale = (
        "Each targetSdk level gates platform hardening (scoped storage, "
        "package visibility, background restrictions, cleartext defaults). "
        "minSdk < 23 keeps the install-time permission model on old devices, "
        "where users cannot revoke dangerous permissions at runtime."
    )
    category = "manifest"
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Raise targetSdkVersion to 30 or higher (ideally the latest) and test "
        "against the new behavior changes. Raise minSdkVersion to 23+ so the "
        "runtime permission model applies on all supported devices."
    )
    references = [_OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        evidence: list[Evidence] = []
        notes: list[str] = []
        if m.target_sdk is not None and m.target_sdk < 30:
            notes.append(f"targetSdkVersion={m.target_sdk} is below the recommended minimum of 30")
            evidence.append(_mev(
                f"targetSdkVersion {m.target_sdk} is outdated (< 30); modern platform "
                "security behaviors are not enforced",
                f"android:targetSdkVersion=\"{m.target_sdk}\"",
            ))
        if m.min_sdk is not None and m.min_sdk < 23:
            notes.append(
                f"minSdkVersion={m.min_sdk} predates the runtime-permission model "
                "(API 23): dangerous permissions are granted at install time"
            )
            evidence.append(_mev(
                f"minSdkVersion {m.min_sdk} < 23: no runtime permissions on those "
                "devices; dangerous permissions granted at install, not revocable",
                f"android:minSdkVersion=\"{m.min_sdk}\"",
            ))
        if not notes:
            return pass_result(
                self,
                "targetSdkVersion is 30+ and minSdkVersion is 23+ (or undeclared).",
            )
        return finding(
            self,
            "Weak SDK policy: " + "; ".join(notes) + ".",
            evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: an outdated targetSdk forfeits platform hardening applied "
                "per API level; minSdk < 23 additionally removes runtime permission "
                "control on old devices. Both widen the attack surface but do not "
                "directly disclose data by themselves."
            ),
            confidence_rationale=(
                "HIGH: SDK versions are literal integers from the manifest's "
                "<uses-sdk> declaration."
            ),
        )


class DangerousPermissionsRule(Rule):
    """BS-M05: dangerous permissions declared, inventoried per permission group."""

    id = "BS-M05"
    title = "Dangerous permissions declared"
    description = (
        "The manifest requests permissions classified dangerous by Android "
        "(SMS, call log, contacts, location, microphone, camera, storage, "
        "phone, calendar, body sensors). Results are grouped by sensitive "
        "permission group with per-group severity."
    )
    rationale = (
        "Dangerous permissions gate access to sensitive user data and device "
        "capabilities. Over-requesting them increases privacy impact and the "
        "blast radius of a compromised app or SDK."
    )
    category = "manifest"
    default_severity = Severity.LOW
    owasp = ["M6"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Request only permissions the app genuinely needs; prefer scoped "
        "alternatives (photo picker, approximate location, one-time "
        "permissions). Justify each dangerous permission in the Play Data "
        "safety section and handle denial gracefully."
    )
    references = [_OWASP_MTOP10,
                  "https://developer.android.com/training/permissions/requesting"]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        hits = _dangerous_hits(m)
        if not hits:
            return pass_result(self, "No dangerous permissions declared.")
        by_group: dict[str, list[str]] = {}
        group_sev: dict[str, Severity] = {}
        for full, group, sev in hits:
            by_group.setdefault(group, []).append(full)
            cur = group_sev.get(group, Severity.LOW)
            order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            group_sev[group] = sev if order.index(sev) > order.index(cur) else cur
        evidence = [
            _mev(
                f"Dangerous permission '{perm}' (group: {group}, "
                f"group severity: {group_sev[group].value})",
                f"<uses-permission android:name=\"{perm}\" />",
            )
            for perm, group, _ in hits
        ]
        overall = max((group_sev[g] for g in group_sev),
                      key=lambda s: ["low", "medium", "high", "critical"].index(s.value))
        summary = (
            f"{len(hits)} dangerous permission(s) across {len(by_group)} sensitive "
            "group(s): "
            + "; ".join(f"{g}: {', '.join(sorted(p.split('.')[-1] for p in ps))}"
                        for g, ps in sorted(by_group.items()))
            + "."
        )
        return finding(
            self, summary, evidence,
            severity=overall,
            confidence=Confidence.HIGH,
            severity_rationale=(
                f"{overall.value.upper()}: SMS, call-log, and precise/background "
                "location permissions are MEDIUM because they enable surveillance-"
                "grade data collection; other dangerous groups (contacts, camera, "
                "microphone, storage, phone, calendar, sensors) are LOW as "
                "privacy-relevant but less directly exfiltrative on their own."
            ),
            confidence_rationale=(
                "HIGH: permissions are literal <uses-permission> entries parsed "
                "from the manifest; Android's dangerous classification is "
                "documented platform behavior."
            ),
        )


class ExcessivePermissionScopeRule(Rule):
    """BS-M06: 3+ dangerous permissions from distinct sensitive groups."""

    id = "BS-M06"
    title = "Excessive permission scope"
    description = (
        "The app requests dangerous permissions spanning three or more "
        "distinct sensitive groups (e.g. SMS + location + camera), which is "
        "disproportionate for most single-purpose apps."
    )
    rationale = (
        "Breadth of permission requests correlates with privacy risk and with "
        "abuse potential if the app (or an embedded SDK) is compromised. Each "
        "additional sensitive group multiplies the data an attacker can reach "
        "through one install."
    )
    category = "manifest"
    default_severity = Severity.MEDIUM
    owasp = ["M6"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Apply least privilege: drop permission groups not required for core "
        "features, request permissions in context (when the feature is used), "
        "and re-audit third-party SDKs that may be pulling in permissions via "
        "manifest merging."
    )
    references = [_OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        hits = _dangerous_hits(m)
        groups = sorted({group for _, group, _ in hits})
        if len(groups) < 3:
            return pass_result(
                self,
                f"Dangerous permissions span {len(groups)} sensitive group(s); "
                "below the excessive-scope threshold of 3.",
            )
        return finding(
            self,
            f"App requests dangerous permissions from {len(groups)} distinct "
            f"sensitive groups ({', '.join(groups)}): excessive scope for a "
            "typical app.",
            [_mev(
                f"Sensitive group '{group}': "
                + ", ".join(sorted(p.split('.')[-1] for p, g, _ in hits if g == group)),
                f"permissions: {', '.join(sorted(p for p, g, _ in hits if g == group))}",
            ) for group in groups],
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: spanning 3+ sensitive groups materially increases the "
                "privacy blast radius of compromise or SDK abuse, though scope "
                "alone does not prove data is exfiltrated."
            ),
            confidence_rationale=(
                "HIGH: group membership is derived from literal manifest "
                "permissions against Android's documented dangerous groups."
            ),
        )


class ExportedActivityRule(Rule):
    """BS-M07: exported activity without android:permission."""

    id = "BS-M07"
    title = "Exported activity without permission guard"
    description = (
        "One or more activities are exported (reachable by other apps) without "
        "an android:permission restriction, so any app on the device can start "
        "them, potentially bypassing UI flows or leaking data via intents."
    )
    rationale = (
        "Exported activities are entry points into the app. Without a "
        "permission guard, malicious apps can launch them directly, inject "
        "extras, hijack flows (e.g. login, payment), or harvest data the "
        "activity exposes."
    )
    category = "manifest"
    default_severity = Severity.HIGH
    owasp = ["M8"]
    cwe = ["CWE-926"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Set android:exported=\"false\" for activities that need no external "
        "access. For activities that must be reachable, protect them with a "
        "signature-level android:permission and validate all incoming intent "
        "extras."
    )
    references = [_cwe(926), _OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        exposed = [a for a in m.activities if a.exported and not a.permission]
        if not exposed:
            return pass_result(self, "No exported activities lack a permission guard.")
        return finding(
            self,
            f"{len(exposed)} exported activit{'y' if len(exposed) == 1 else 'ies'} "
            "with no android:permission: "
            + ", ".join(a.name for a in exposed) + ".",
            [_mev(_component_desc(a, "exported with no android:permission guard"),
                   f'android:exported="true" on <activity android:name="{a.name}"> '
                   "(no android:permission)")
             for a in exposed],
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "HIGH: an unguarded exported activity is directly launchable by "
                "any app on the device, enabling intent spoofing, flow bypass, "
                "and data extraction through extras."
            ),
            confidence_rationale=(
                "HIGH: exported state and the absence of a permission attribute "
                "come straight from the parsed activity declarations."
            ),
        )


class ExportedServiceRule(Rule):
    """BS-M08: exported service without android:permission."""

    id = "BS-M08"
    title = "Exported service without permission guard"
    description = (
        "One or more services are exported without an android:permission "
        "restriction, allowing any app to bind to or start them in the "
        "background."
    )
    rationale = (
        "Exported services run without a UI, so abuse is invisible to the "
        "user. Unguarded services can be started/bound by malware to trigger "
        "privileged operations or siphon data the service handles."
    )
    category = "manifest"
    default_severity = Severity.HIGH
    owasp = ["M8"]
    cwe = ["CWE-926"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Set android:exported=\"false\" for internal services. For services "
        "that must be reachable cross-app, require a signature-level "
        "android:permission and validate caller identity / incoming intents."
    )
    references = [_cwe(926), _OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        exposed = [s for s in m.services if s.exported and not s.permission]
        if not exposed:
            return pass_result(self, "No exported services lack a permission guard.")
        return finding(
            self,
            f"{len(exposed)} exported service(s) with no android:permission: "
            + ", ".join(s.name for s in exposed) + ".",
            [_mev(_component_desc(s, "exported with no android:permission guard"),
                   f'android:exported="true" on <service android:name="{s.name}"> '
                   "(no android:permission)")
             for s in exposed],
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "HIGH: an unguarded exported service can be started or bound by "
                "any app, running privileged code invisibly in the background."
            ),
            confidence_rationale=(
                "HIGH: exported state and the absence of a permission attribute "
                "come straight from the parsed service declarations."
            ),
        )


class ExportedReceiverRule(Rule):
    """BS-M09: exported broadcast receiver without android:permission."""

    id = "BS-M09"
    title = "Exported broadcast receiver without permission guard"
    description = (
        "One or more broadcast receivers are exported without an "
        "android:permission restriction, so any app can send them crafted "
        "broadcasts."
    )
    rationale = (
        "Receivers act on intents from other apps. An unguarded exported "
        "receiver can be triggered by malware with forged extras, driving "
        "state changes, downloads, or data exfiltration paths in the app."
    )
    category = "manifest"
    default_severity = Severity.HIGH
    owasp = ["M8"]
    cwe = ["CWE-927"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Set android:exported=\"false\" for receivers handling internal or "
        "system broadcasts. For receivers that must accept external "
        "broadcasts, require a signature-level android:permission and validate "
        "all extras and sender identity."
    )
    references = [_cwe(927), _OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        exposed = [r for r in m.receivers if r.exported and not r.permission]
        if not exposed:
            return pass_result(self, "No exported receivers lack a permission guard.")
        return finding(
            self,
            f"{len(exposed)} exported receiver(s) with no android:permission: "
            + ", ".join(r.name for r in exposed) + ".",
            [_mev(_component_desc(r, "exported with no android:permission guard"),
                   f'android:exported="true" on <receiver android:name="{r.name}"> '
                   "(no android:permission)")
             for r in exposed],
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "HIGH: any app on the device can send crafted broadcasts to an "
                "unguarded exported receiver, driving app logic with attacker-"
                "controlled extras."
            ),
            confidence_rationale=(
                "HIGH: exported state and the absence of a permission attribute "
                "come straight from the parsed receiver declarations."
            ),
        )


class ExportedProviderRule(Rule):
    """BS-M10: exported content provider without read/write permission."""

    id = "BS-M10"
    title = "Exported content provider without read/write permission"
    description = (
        "A content provider is exported (has authorities and is reachable by "
        "other apps) without android:readPermission or "
        "android:writePermission, so any app can query, insert, update, or "
        "delete its data."
    )
    rationale = (
        "Providers commonly back app databases. Without read/write permission "
        "guards, any installed app can read rows (tokens, PII) or write rows "
        "(tampering, injection into app logic)."
    )
    category = "manifest"
    default_severity = Severity.HIGH
    owasp = ["M8"]
    cwe = ["CWE-926"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Set android:exported=\"false\" for providers that are app-internal. "
        "For providers that must be shared, set android:readPermission and "
        "android:writePermission (signature level where possible), use "
        "path-permissions for granularity, and validate all query parameters."
    )
    references = [_cwe(926), _OWASP_MTOP10,
                  "https://developer.android.com/guide/topics/manifest/provider-element"]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        exposed = [p for p in m.providers
                   if p.exported and not (p.read_permission or p.write_permission)]
        if not exposed:
            return pass_result(
                self, "No exported providers lack read/write permission guards.")
        return finding(
            self,
            f"{len(exposed)} exported provider(s) with no readPermission/writePermission: "
            + ", ".join(p.name for p in exposed) + ".",
            [_mev(
                _component_desc(
                    p, f"exported, authorities=\"{p.authorities or '?'}\", no "
                        "android:readPermission / android:writePermission"),
                f'android:exported="true" on <provider android:name="{p.name}" '
                f'android:authorities="{p.authorities or "?"}"> '
                "(no readPermission/writePermission)")
             for p in exposed],
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "HIGH: an unguarded exported provider exposes its backing data "
                "to arbitrary apps for read and write, enabling theft and "
                "tampering of app data."
            ),
            confidence_rationale=(
                "HIGH: exported state, authorities, and the absence of "
                "read/write permission attributes come straight from the "
                "parsed provider declarations."
            ),
        )


class GrantUriPermissionsRule(Rule):
    """BS-M11: content provider with grantUriPermissions=true."""

    id = "BS-M11"
    title = "Provider grants URI permissions"
    description = (
        "A content provider sets android:grantUriPermissions=\"true\", allowing "
        "temporary per-URI access grants to other apps."
    )
    rationale = (
        "grantUriPermissions is the mechanism behind confused-deputy attacks: "
        "if the app grants URIs carelessly (e.g. to a WebView, share target, "
        "or via FLAG_GRANT_* on untrusted intents), recipients gain read/write "
        "access beyond what the provider's static permissions allow."
    )
    category = "manifest"
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Only set grantUriPermissions=\"true\" when temporary URI grants are "
        "genuinely needed. Scope grants with <grant-uri-permission> path "
        "restrictions, prefer FLAG_GRANT_READ_URI_PERMISSION over write, and "
        "revoke grants with revokeUriPermission when done."
    )
    references = [_OWASP_MTOP10,
                  "https://developer.android.com/guide/topics/manifest/provider-element"]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        flagged = [p for p in m.providers if p.grant_uri_permissions]
        if not flagged:
            return pass_result(self, "No providers set grantUriPermissions=true.")
        return finding(
            self,
            f"{len(flagged)} provider(s) set grantUriPermissions=true: "
            + ", ".join(p.name for p in flagged) + ".",
            [_mev(
                _component_desc(
                    p, "android:grantUriPermissions=\"true\""
                    + (" (exported)" if p.exported else " (not exported)")),
                f'<provider android:name="{p.name}" '
                'android:grantUriPermissions="true">')
             for p in flagged],
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: URI grants are a legitimate sharing mechanism, but on "
                "an exported provider (or one reachable via intents) careless "
                "grants enable confused-deputy data access by third-party apps."
            ),
            confidence_rationale=(
                "HIGH: the grantUriPermissions flag is a literal boolean on the "
                "parsed provider declaration."
            ),
        )


class TaskHijackingRule(Rule):
    """BS-M12: exported singleTask activity with a foreign taskAffinity."""

    id = "BS-M12"
    title = "Task-hijacking-prone activity configuration"
    description = (
        "An exported activity uses android:launchMode=\"singleTask\" together "
        "with an android:taskAffinity that is set, non-empty, and different "
        "from the app's package - the classic task-hijacking (strandhogg-style) "
        "configuration."
    )
    rationale = (
        "A singleTask activity with a foreign taskAffinity can be lured into "
        "an attacker's task (or lure the attacker's activity into the victim "
        "task), enabling UI spoofing, phishing overlays, and interception of "
        "intents/credentials."
    )
    category = "manifest"
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-451"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Use the default launchMode (standard) unless singleTask is required; "
        "never set taskAffinity to another app's affinity - leave it empty or "
        "equal to the package name. For sensitive activities, also set "
        "android:excludeFromRecents and validate the task on resume."
    )
    references = [_cwe(451), _OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        raw = m.raw_xml or ""
        if not raw:
            return pass_result(
                self,
                "Decoded manifest XML text is unavailable; launchMode/taskAffinity "
                "could not be evaluated.",
            )
        flagged: list[tuple[Component, str, str]] = []
        for comp in m.activities:
            if not comp.exported:
                continue
            attrs = _match_component_tag(raw, "activity", comp.name, m.package)
            if attrs is None:
                continue
            lm = _LAUNCHMODE_RE.search(attrs)
            ta = _TASKAFFINITY_RE.search(attrs)
            if lm and lm.group(1).lower() == "singletask" and ta:
                affinity = ta.group(1)
                if affinity and affinity != m.package:
                    flagged.append((comp, lm.group(1), affinity))
        if not flagged:
            return pass_result(
                self,
                "No exported singleTask activity uses a foreign taskAffinity.",
            )
        return finding(
            self,
            "Task-hijacking-prone configuration: "
            + "; ".join(
                f"{c.name} (launchMode={lm}, taskAffinity=\"{ta}\")"
                for c, lm, ta in flagged) + ".",
            [_mev(
                _component_desc(
                    c, f'exported, android:launchMode="{lm}", '
                       f'android:taskAffinity="{ta}" (differs from package '
                       f'"{m.package}")'),
                f'<activity android:name="{c.name}" android:exported="true" '
                f'android:launchMode="{lm}" android:taskAffinity="{ta}">')
             for c, lm, ta in flagged],
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: the configuration is the documented prerequisite for "
                "task-hijacking/UI-spoofing attacks, but exploitation still "
                "requires a malicious app installed on the same device."
            ),
            confidence_rationale=(
                "HIGH: launchMode and taskAffinity values are read from the "
                "actual activity tags in the decoded manifest XML, and the "
                "affinity is compared against the app's own package name."
            ),
        )


class WeakCustomPermissionRule(Rule):
    """BS-M13: exported component guarded only by a normal/dangerous custom permission."""

    id = "BS-M13"
    title = "Exported component guarded by weak custom permission"
    description = (
        "An exported component requires a custom <permission> whose "
        "protectionLevel is \"normal\" or \"dangerous\". Any app - including "
        "malware - can declare and hold such a permission, so the guard is "
        "effectively no access control."
    )
    rationale = (
        "Only signature (or signatureOrSystem) protection levels restrict a "
        "permission to apps signed with the same key. A normal/dangerous custom "
        "permission guarding an exported component gives a false sense of "
        "protection while remaining obtainable by any third-party app."
    )
    category = "manifest"
    default_severity = Severity.MEDIUM
    owasp = ["M3"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Change the custom permission's android:protectionLevel to \"signature\" "
        "(or remove the component's exported exposure if cross-app access is "
        "not needed). Audit every exported component that references the weak "
        "permission."
    )
    references = [_OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        weak = {p.name: p.protection_level
                for p in m.custom_permissions
                if (p.protection_level or "").lower() in ("normal", "dangerous")}
        if not weak:
            return pass_result(
                self, "No custom permissions with normal/dangerous protection level.")
        flagged: list[tuple[Component, str, str]] = []
        for comp in _all_components(m):
            if not comp.exported:
                continue
            for guard in (comp.permission, comp.read_permission, comp.write_permission):
                if guard and guard in weak:
                    flagged.append((comp, guard, weak[guard]))
                    break
        if not flagged:
            return pass_result(
                self,
                "Weak custom permissions exist but guard no exported components.",
            )
        return finding(
            self,
            "Exported component(s) guarded only by weak custom permission(s): "
            + "; ".join(
                f"{c.name} requires '{g}' (protectionLevel={lvl})"
                for c, g, lvl in flagged) + ".",
            [_mev(
                _component_desc(
                    c, f"exported, guarded by custom permission '{g}' with "
                       f'protectionLevel="{lvl}" (any app can hold it)'),
                f'<permission android:name="{g}" android:protectionLevel="{lvl}" /> '
                f'guards <{c.kind} android:name="{c.name}">')
             for c, g, lvl in flagged],
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: the 'guard' is obtainable by any app, so the exported "
                "component is effectively unprotected - equivalent in practice "
                "to BS-M07..BS-M10, but one step removed."
            ),
            confidence_rationale=(
                "HIGH: both the component's permission reference and the custom "
                "permission's protectionLevel are parsed from the manifest."
            ),
        )


class IntentFilterExposureRule(Rule):
    """BS-M14: intent-filter-reachable component without permission (review)."""

    id = "BS-M14"
    title = "Intent-filter-reachable component without permission guard"
    description = (
        "Components that declare intent filters are reachable by other apps "
        "(explicitly exported, or implicitly exported on targetSdk < 31) yet "
        "carry no permission guard. Listed for manual review of whether the "
        "exposure is intentional."
    )
    rationale = (
        "Intent filters advertise entry points to the whole device. Even when "
        "exposure is intentional (share targets, deep links), the absence of "
        "any permission check means any app can invoke the component with "
        "arbitrary extras; each such component deserves an explicit review "
        "decision."
    )
    category = "manifest"
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "For each listed component decide: if external access is not needed, "
        "set android:exported=\"false\"; if it is needed, add a permission "
        "guard (signature level where possible) and validate all incoming "
        "intents. Record the decision so the exposure is intentional, not "
        "accidental."
    )
    references = [_OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        legacy_implicit = m.target_sdk is None or m.target_sdk < 31
        flagged: list[tuple[Component, str]] = []
        for comp in _all_components(m):
            if not comp.intent_filters:
                continue
            if _guard_of(comp):
                continue
            if comp.exported:
                flagged.append((comp, "explicitly exported"))
            elif legacy_implicit:
                flagged.append((comp, "implicitly exported (intent-filter, targetSdk < 31)"))
        if not flagged:
            return pass_result(
                self,
                "No intent-filter components lack a permission guard.",
            )
        return needs_review(
            self,
            "Components reachable via intent filters with no permission guard "
            "(review whether exposure is intentional): "
            + "; ".join(f"{c.name} <{c.kind}> ({how})" for c, how in flagged) + ".",
            [_mev(
                _component_desc(
                    c, f"{how}; declares intent-filter(s) with no permission guard"),
                f'<{c.kind} android:name="{c.name}"> declares '
                f"{len(c.intent_filters)} intent-filter(s), no permission")
             for c, how in flagged],
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "MEDIUM: intent-filter reachability without any permission check "
                "is the standard setup for component-hijacking issues; severity "
                "depends on what the component does with attacker input, which "
                "needs manual review."
            ),
            confidence_rationale=(
                "MEDIUM: reachability is certain from the intent filters, but "
                "whether the exposure is a vulnerability or intended behavior "
                "(share target, deep link) cannot be decided statically."
            ),
        )


class NoNetworkSecurityConfigRule(Rule):
    """BS-M15: no networkSecurityConfig referenced (informational inventory)."""

    id = "BS-M15"
    title = "No network security configuration referenced"
    description = (
        "The manifest does not reference a network security configuration "
        "(android:networkSecurityConfig). Informational inventory only: this "
        "is not a vulnerability by itself."
    )
    rationale = (
        "A network security config is where pinning, cleartext exceptions, "
        "debug CA trust, and per-domain TLS policy live. Its absence is worth "
        "inventorying because it means none of those controls are declared, "
        "but it is not evidence of insecure networking."
    )
    category = "manifest"
    default_severity = Severity.INFO
    owasp = ["M5"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "No action required by this finding alone. Consider adding a network "
        "security config to declare certificate pinning, restrict cleartext "
        "traffic per-domain, and distrust user CAs in release builds."
    )
    references = [_OWASP_MTOP10,
                  "https://developer.android.com/training/articles/security-config"]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        if m.network_security_config:
            return pass_result(
                self,
                f"Network security config referenced: {m.network_security_config}.",
            )
        return finding(
            self,
            "No android:networkSecurityConfig is referenced in the manifest. "
            "Informational: no pinning, per-domain TLS policy, or cleartext "
            "exceptions are declared.",
            [_mev(
                "android:networkSecurityConfig attribute absent from <application>",
                "android:networkSecurityConfig not declared",
            )],
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "INFORMATIONAL: the absence of a network security config is "
                "inventory metadata, not a vulnerability; it only means no "
                "declarative network controls exist."
            ),
            confidence_rationale=(
                "HIGH: the attribute is either present on the application tag "
                "or it is not; absence is directly observed."
            ),
        )


class BackupRulesContentRule(Rule):
    """BS-M16: backup/extraction rules XML includes sensitive domains."""

    id = "BS-M16"
    title = "Backup rules include sensitive domains"
    description = (
        "android:fullBackupContent or android:dataExtractionRules points at an "
        "XML resource whose <include> rules cover sensitive domains (database, "
        "sharedpref, files), meaning those files are included in backups."
    )
    rationale = (
        "Backup inclusion rules decide exactly which app-private files leave "
        "the device via Auto Backup / adb backup. Including databases, "
        "shared preferences, or files pulls tokens, credentials, and PII into "
        "backups that can be restored onto attacker-controlled devices."
    )
    category = "manifest"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Narrow the backup rules: use <exclude> for databases, shared "
        "preferences, and any files holding secrets or tokens - or set "
        "android:allowBackup=\"false\" if backup is not required. Encrypt "
        "sensitive data at rest regardless."
    )
    references = [_OWASP_MTOP10,
                  "https://developer.android.com/guide/topics/data/autobackup"]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        refs = [v for v in (m.full_backup_content, m.data_extraction_rules) if v]
        if not refs:
            return pass_result(
                self, "No fullBackupContent/dataExtractionRules XML referenced.")
        sensitive: list[tuple[str, str]] = []  # (ref, domains)
        unverifiable: list[str] = []
        for ref in refs:
            path = _resolve_xml_resource(ctx, ref)
            if path is None:
                unverifiable.append(ref)
                continue
            text = read_text_capped(path)
            if text is None:
                unverifiable.append(ref)
                continue
            domains = sorted({
                d.group(1).lower()
                for tag in _INCLUDE_RE.findall(text)
                if (d := _DOMAIN_RE.search(tag)) and d.group(1).lower() in _SENSITIVE_DOMAINS
            })
            if domains:
                sensitive.append((ref, ", ".join(domains)))
        if not sensitive and not unverifiable:
            return pass_result(
                self,
                "Backup rules XML inspected: no <include> rules cover sensitive "
                "domains.",
            )
        parts: list[str] = []
        evidence: list[Evidence] = []
        for ref, domains in sensitive:
            parts.append(f"{ref} includes sensitive domain(s): {domains}")
            evidence.append(_mev(
                f"Backup rules {ref} include sensitive domain(s): {domains}",
                f"{ref}: <include domain=\"{domains}\" ... />",
            ))
        for ref in unverifiable:
            parts.append(
                f"{ref} is referenced but the XML could not be found in decoded "
                "resources, so its include rules cannot be verified")
            evidence.append(_mev(
                f"Backup rules resource {ref} referenced but not found; includes "
                "unverifiable",
                f"android:fullBackupContent/android:dataExtractionRules=\"{ref}\" "
                "(file not found in decoded resources)",
            ))
        return needs_review(
            self,
            "Backup/extraction rules need review: " + "; ".join(parts) + ".",
            evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM if sensitive else Confidence.LOW,
            severity_rationale=(
                "MEDIUM: backing up databases/shared preferences/files moves "
                "app-private data (potentially tokens, credentials, PII) off the "
                "device; actual impact depends on what the app stores there."
            ),
            confidence_rationale=(
                "MEDIUM: sensitive <include> domains were read from the actual "
                "backup-rules XML; LOW where the referenced file could not be "
                "found and the rules could not be verified."
            ),
        )


class CleartextDefaultRule(Rule):
    """BS-M17: usesCleartextTraffic unset + targetSdk < 28 (defaults true)."""

    id = "BS-M17"
    title = "Cleartext traffic allowed by platform default"
    description = (
        "android:usesCleartextTraffic is not set and targetSdkVersion is below "
        "28, so Android defaults cleartext traffic to permitted for this app."
    )
    rationale = (
        "Before API 28 the platform default allowed cleartext HTTP. An old "
        "targetSdk silently inherits that permissive default, so the app may "
        "transmit data over HTTP without any explicit opt-in visible in the "
        "manifest."
    )
    category = "manifest"
    default_severity = Severity.MEDIUM
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Set android:usesCleartextTraffic=\"false\" explicitly and raise "
        "targetSdkVersion to 28+. Migrate all endpoints to HTTPS; scope any "
        "unavoidable HTTP exception to a single host via a network security "
        "config."
    )
    references = [_cwe(319), _OWASP_MTOP10,
                  "https://developer.android.com/training/articles/security-config"]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        if m.uses_cleartext_traffic is True:
            return pass_result(
                self, "Covered by BS-M03: cleartext is explicitly enabled.")
        if m.uses_cleartext_traffic is False:
            return pass_result(self, "usesCleartextTraffic is explicitly false.")
        # unset at this point
        if m.target_sdk is None:
            return needs_review(
                self,
                "android:usesCleartextTraffic is unset and targetSdkVersion is "
                "unknown, so the platform default (which permits cleartext "
                "below API 28) cannot be determined.",
                [_mev("usesCleartextTraffic unset; targetSdkVersion unknown",
                       "android:usesCleartextTraffic attribute absent, "
                       "targetSdkVersion unknown")],
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                severity_rationale=(
                    "MEDIUM: if the targetSdk is below 28 the platform default "
                    "permits cleartext HTTP app-wide."
                ),
                confidence_rationale=(
                    "LOW: without the targetSdk the actual default behavior "
                    "cannot be determined from the manifest."
                ),
            )
        if m.target_sdk < 28:
            return finding(
                self,
                f"android:usesCleartextTraffic is unset and targetSdkVersion="
                f"{m.target_sdk} (< 28), so the platform default permits "
                "cleartext HTTP traffic.",
                [_mev(
                    f"usesCleartextTraffic unset with targetSdkVersion={m.target_sdk} "
                    "(< 28): platform default allows cleartext",
                    "android:usesCleartextTraffic attribute absent; "
                    f"android:targetSdkVersion=\"{m.target_sdk}\"",
                )],
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "MEDIUM: cleartext HTTP may be used without any explicit "
                    "opt-in, exposing data to passive observers; MEDIUM rather "
                    "than HIGH because no explicit cleartext opt-out was made "
                    "and actual HTTP usage is unconfirmed."
                ),
                confidence_rationale=(
                    "HIGH: the attribute's absence and the targetSdk value are "
                    "directly observed, and the pre-28 default-allow behavior "
                    "is documented platform behavior."
                ),
            )
        return pass_result(
            self,
            f"usesCleartextTraffic unset but targetSdkVersion={m.target_sdk} "
            ">= 28, so the platform default blocks cleartext.",
        )


class ImplicitExportRule(Rule):
    """BS-M18: intent-filter component without android:exported on targetSdk<31."""

    id = "BS-M18"
    title = "Implicitly exported component (missing android:exported)"
    description = (
        "A component declares intent filters but its tag has no "
        "android:exported attribute, and targetSdkVersion is below 31 - so the "
        "platform implicitly exports it, making it reachable by other apps."
    )
    rationale = (
        "Before API 31, components with intent filters defaulted to exported. "
        "Developers often relied on this implicitly, leaving entry points "
        "exposed without a conscious export decision or permission guard."
    )
    category = "manifest"
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-926"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Add an explicit android:exported=\"true\" or \"false\" to every "
        "component (required for targetSdk 31+ anyway). Set it to false unless "
        "external access is genuinely required, and guard exported components "
        "with a permission."
    )
    references = [_cwe(926), _OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        raw = m.raw_xml or ""
        if not raw:
            comps = [c for c in _all_components(m) if c.intent_filters]
            if comps and (m.target_sdk is None or m.target_sdk < 31):
                return needs_review(
                    self,
                    "Decoded manifest XML text is unavailable, so the presence "
                    "of android:exported attributes cannot be verified for "
                    f"{len(comps)} intent-filter component(s) on "
                    f"targetSdk={m.target_sdk}.",
                    [_mev(
                        f"<{c.kind} android:name=\"{c.name}\"> has intent-filter(s); "
                        "android:exported attribute presence unverifiable "
                        "(no manifest XML text)",
                        f"<{c.kind} android:name=\"{c.name}\">") for c in comps],
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    severity_rationale=(
                        "MEDIUM: if these components lack android:exported on "
                        "targetSdk < 31 they are implicitly exported."
                    ),
                    confidence_rationale=(
                        "LOW: without the manifest XML text the android:exported "
                        "attribute cannot actually be inspected."
                    ),
                )
            return pass_result(
                self, "Manifest XML text unavailable; nothing to evaluate.")
        if m.target_sdk is not None and m.target_sdk >= 31:
            return pass_result(
                self,
                f"targetSdkVersion={m.target_sdk} >= 31: android:exported is "
                "mandatory, so implicit export cannot occur.",
            )
        flagged: list[tuple[str, str]] = []  # (kind, name)
        for kind, attrs, name, has_if in _xml_tags(raw):
            if has_if and name and _EXPORTED_ATTR_RE.search(attrs) is None:
                flagged.append((kind, name))
        if not flagged:
            return pass_result(
                self,
                "Every intent-filter component declares android:exported explicitly.",
            )
        return finding(
            self,
            f"{len(flagged)} component(s) with intent filters lack "
            f"android:exported and are implicitly exported (targetSdk="
            f"{m.target_sdk}): "
            + ", ".join(f"<{k}> {n}" for k, n in flagged) + ".",
            [_mev(
                f"<{kind} android:name=\"{name}\"> declares intent-filter(s) but "
                "no android:exported attribute: implicitly exported on "
                "targetSdk < 31",
                f'<{kind} android:name="{name}"> '
                "(intent-filter present, android:exported absent)")
             for kind, name in flagged],
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: implicitly exported components are reachable by other "
                "apps without a conscious export decision; exploitability "
                "depends on what each component does with external intents."
            ),
            confidence_rationale=(
                "HIGH: the absence of the android:exported attribute on an "
                "intent-filter tag is observed directly in the decoded manifest "
                "XML, and implicit export below API 31 is documented platform "
                "behavior."
            ),
        )


class PackageVisibilityRule(Rule):
    """BS-M19: broad package visibility permissions."""

    id = "BS-M19"
    title = "Broad package visibility requested"
    description = (
        "The manifest requests QUERY_ALL_PACKAGES or REQUEST_INSTALL_PACKAGES, "
        "which grant visibility into all installed apps or the ability to "
        "trigger package installation."
    )
    rationale = (
        "QUERY_ALL_PACKAGES lets the app enumerate every installed package "
        "(fingerprinting users, detecting security tools). "
        "REQUEST_INSTALL_PACKAGES lets it prompt installation of APKs, a "
        "classic vector for dropper behavior. Both are privacy/security "
        "sensitive and Play-restricted."
    )
    category = "manifest"
    default_severity = Severity.MEDIUM
    owasp = ["M6"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Prefer <queries> package-visibility declarations scoped to the "
        "specific packages or intent actions you need. Only keep "
        "QUERY_ALL_PACKAGES / REQUEST_INSTALL_PACKAGES with a documented, "
        "user-facing core feature and be prepared to justify it in Play "
        "review."
    )
    references = [_OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        watched = {"QUERY_ALL_PACKAGES", "REQUEST_INSTALL_PACKAGES"}
        hits = [p.name for p in m.permissions if p.name.split(".")[-1].upper() in watched]
        if not hits:
            return pass_result(self, "No broad package-visibility permissions declared.")
        return finding(
            self,
            "Broad package visibility permission(s) declared: "
            + ", ".join(sorted(hits)) + ".",
            [_mev(
                f"Declares '{perm}': "
                + ("visibility into all installed packages"
                   if perm.split(".")[-1].upper() == "QUERY_ALL_PACKAGES"
                   else "can request installation of packages (APKs)"),
                f"<uses-permission android:name=\"{perm}\" />")
             for perm in sorted(hits)],
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: package enumeration enables user fingerprinting and "
                "security-tool detection; install-request capability enables "
                "dropper-style flows. Both meaningfully expand what the app can "
                "learn and do beyond its own sandbox."
            ),
            confidence_rationale=(
                "HIGH: the permissions are literal <uses-permission> entries in "
                "the manifest."
            ),
        )


class ExportedAttackSurfaceRule(Rule):
    """BS-M20: 6+ exported components (informational attack-surface inventory)."""

    id = "BS-M20"
    title = "Large exported attack surface"
    description = (
        "Six or more components are exported, giving other apps a broad set of "
        "entry points into the app. Informational inventory of the exported "
        "attack surface."
    )
    rationale = (
        "Every exported component is an IPC entry point an attacker app can "
        "reach. A large exported surface is not a vulnerability by itself, but "
        "it multiplies the value of any single component-level flaw and "
        "deserves an explicit inventory during review."
    )
    category = "manifest"
    default_severity = Severity.INFO
    owasp = ["M8"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Inventory-driven hardening: set android:exported=\"false\" on every "
        "component that does not need cross-app reachability, and ensure the "
        "remaining exported components carry permission guards and validate "
        "all incoming intents."
    )
    references = [_OWASP_MTOP10]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> RuleResult:
        m: ManifestData = ctx.manifest  # type: ignore[assignment]
        exported = [c for c in _all_components(m) if c.exported]
        if len(exported) < 6:
            return pass_result(
                self,
                f"{len(exported)} exported component(s); below the large-surface "
                "threshold of 6.",
            )
        by_kind: dict[str, list[str]] = {}
        for c in exported:
            by_kind.setdefault(c.kind, []).append(c.name)
        return finding(
            self,
            f"{len(exported)} exported components "
            f"({', '.join(f'{len(v)} {k}' for k, v in sorted(by_kind.items()))}): "
            "broad IPC attack surface.",
            [_mev(
                f"Exported <{c.kind} android:name=\"{c.name}\">"
                + ("" if _guard_of(c) else " (no permission guard)"),
                f'<{c.kind} android:name="{c.name}" android:exported="true">')
             for c in exported],
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "INFORMATIONAL: component count alone is not a vulnerability; "
                "it is attack-surface inventory to scope manual review."
            ),
            confidence_rationale=(
                "HIGH: the exported flags are parsed directly from the "
                "manifest component declarations."
            ),
        )


# ---------------------------------------------------------------------------
# Module rule list
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    DebuggableRule(),
    BackupEnabledRule(),
    CleartextTrafficRule(),
    SdkPolicyRule(),
    DangerousPermissionsRule(),
    ExcessivePermissionScopeRule(),
    ExportedActivityRule(),
    ExportedServiceRule(),
    ExportedReceiverRule(),
    ExportedProviderRule(),
    GrantUriPermissionsRule(),
    TaskHijackingRule(),
    WeakCustomPermissionRule(),
    IntentFilterExposureRule(),
    NoNetworkSecurityConfigRule(),
    BackupRulesContentRule(),
    CleartextDefaultRule(),
    ImplicitExportRule(),
    PackageVisibilityRule(),
    ExportedAttackSurfaceRule(),
]
