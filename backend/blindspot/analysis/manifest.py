"""AndroidManifest.xml parsing: binary AXML -> ManifestData.

Primary parser is Blindspot's own AXML decoder (analysis.axml), which keeps
manifest parsing dependency-free and deterministic. androguard is used only
as an optional enrichment source when available.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..rules.base import (Component, CustomPermission, IntentFilter,
                          ManifestData, Permission)
from .axml import ANDROID_NS, XAttr, XElement, manifest_to_text, parse_axml

A = ANDROID_NS

# AOSP protection levels for well-known permissions (partial map; unknown -> "unknown")
_PROTECTION_LEVELS = {
    # dangerous
    "android.permission.READ_CALENDAR": "dangerous",
    "android.permission.WRITE_CALENDAR": "dangerous",
    "android.permission.CAMERA": "dangerous",
    "android.permission.READ_CONTACTS": "dangerous",
    "android.permission.WRITE_CONTACTS": "dangerous",
    "android.permission.GET_ACCOUNTS": "dangerous",
    "android.permission.ACCESS_FINE_LOCATION": "dangerous",
    "android.permission.ACCESS_COARSE_LOCATION": "dangerous",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "dangerous",
    "android.permission.RECORD_AUDIO": "dangerous",
    "android.permission.READ_PHONE_STATE": "dangerous",
    "android.permission.READ_PHONE_NUMBERS": "dangerous",
    "android.permission.CALL_PHONE": "dangerous",
    "android.permission.ANSWER_PHONE_CALLS": "dangerous",
    "android.permission.READ_CALL_LOG": "dangerous",
    "android.permission.WRITE_CALL_LOG": "dangerous",
    "android.permission.ADD_VOICEMAIL": "dangerous",
    "android.permission.USE_SIP": "dangerous",
    "android.permission.PROCESS_OUTGOING_CALLS": "dangerous",
    "android.permission.BODY_SENSORS": "dangerous",
    "android.permission.SEND_SMS": "dangerous",
    "android.permission.RECEIVE_SMS": "dangerous",
    "android.permission.READ_SMS": "dangerous",
    "android.permission.RECEIVE_WAP_PUSH": "dangerous",
    "android.permission.RECEIVE_MMS": "dangerous",
    "android.permission.READ_EXTERNAL_STORAGE": "dangerous",
    "android.permission.WRITE_EXTERNAL_STORAGE": "dangerous",
    "android.permission.ACCESS_MEDIA_LOCATION": "dangerous",
    "android.permission.READ_MEDIA_IMAGES": "dangerous",
    "android.permission.READ_MEDIA_VIDEO": "dangerous",
    "android.permission.READ_MEDIA_AUDIO": "dangerous",
    "android.permission.ACTIVITY_RECOGNITION": "dangerous",
    "android.permission.BLUETOOTH_CONNECT": "dangerous",
    "android.permission.BLUETOOTH_SCAN": "dangerous",
    "android.permission.UWB_RANGING": "dangerous",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED": "dangerous",
    "android.permission.POST_NOTIFICATIONS": "dangerous",
    # signature
    "android.permission.REQUEST_INSTALL_PACKAGES": "signature",
    "android.permission.QUERY_ALL_PACKAGES": "normal",  # normal since API 30 w/ Play policy
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "signature",
    "android.permission.BIND_DEVICE_ADMIN": "signature",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "signature",
    "android.permission.SYSTEM_ALERT_WINDOW": "signature",
    "android.permission.WRITE_SETTINGS": "signature",
    # normal (common subset)
    "android.permission.INTERNET": "normal",
    "android.permission.ACCESS_NETWORK_STATE": "normal",
    "android.permission.ACCESS_WIFI_STATE": "normal",
    "android.permission.VIBRATE": "normal",
    "android.permission.WAKE_LOCK": "normal",
    "android.permission.RECEIVE_BOOT_COMPLETED": "normal",
    "android.permission.FOREGROUND_SERVICE": "normal",
    "android.permission.USE_BIOMETRIC": "normal",
    "android.permission.USE_FINGERPRINT": "normal",
    "android.permission.NFC": "normal",
    "android.permission.BLUETOOTH": "normal",
    "android.permission.BLUETOOTH_ADMIN": "normal",
}


def protection_level(name: str) -> str:
    return _PROTECTION_LEVELS.get(name, "unknown")


def _bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def _int(value: object) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _parse_intent_filter(el: XElement) -> IntentFilter:
    f = IntentFilter()
    for child in el.children:
        if child.name == "action":
            name = child.attr("name", A)
            if name:
                f.actions.append(str(name))
        elif child.name == "category":
            name = child.attr("name", A)
            if name:
                f.categories.append(str(name))
        elif child.name == "data":
            f.data.append({a.name: str(a.value) for a in child.attrs})
    return f


def _parse_component(el: XElement, kind: str) -> Component:
    name = el.attr("name", A)
    exported_raw = el.attr("exported", A)
    exported = _bool(exported_raw) if exported_raw is not None else False
    return Component(
        kind=kind,
        name=str(name or ""),
        exported=exported,
        permission=_s(el.attr("permission", A)),
        read_permission=_s(el.attr("readPermission", A)),
        write_permission=_s(el.attr("writePermission", A)),
        grant_uri_permissions=_bool(el.attr("grantUriPermissions", A)),
        authorities=_s(el.attr("authorities", A)),
        intent_filters=[_parse_intent_filter(c) for c in el.children
                        if c.name == "intent-filter"],
    )


def _s(value: object) -> Optional[str]:
    return str(value) if value is not None else None


def parse_manifest_bytes(data: bytes) -> tuple[ManifestData, str]:
    """Parse raw AndroidManifest.xml bytes. Returns (ManifestData, text).

    Handles binary AXML and (non-standard but tolerated) plain-text XML.
    Raises ValueError when the manifest cannot be parsed at all.
    """
    stripped = data.lstrip()
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<manifest"):
        root = _parse_text_manifest(data)
        text = data.decode("utf-8", errors="replace")
    else:
        root = parse_axml(data)
        text = manifest_to_text(root)
    if root.name != "manifest":
        raise ValueError(f"unexpected manifest root: {root.name!r}")
    return _build_manifest(root), text


def _parse_text_manifest(data: bytes) -> XElement:
    import xml.etree.ElementTree as ET

    def convert(el: ET.Element) -> XElement:
        xe = XElement(name=el.tag.split("}")[-1])
        for k, v in el.attrib.items():
            if k.startswith("{"):
                uri, _, local = k[1:].partition("}")
                xe.attrs.append(XAttr(ns=uri, name=local, value=v))
            else:
                xe.attrs.append(XAttr(ns="", name=k, value=v))
        for child in el:
            xe.children.append(convert(child))
        return xe

    return convert(ET.fromstring(data))


def _build_manifest(root: XElement) -> ManifestData:
    m = ManifestData()
    m.package = str(root.attr("package") or "")
    m.version_name = str(root.attr("versionName", A) or "")
    m.version_code = str(root.attr("versionCode", A) or "")
    for child in root.children:
        if child.name == "uses-sdk":
            m.min_sdk = _int(child.attr("minSdkVersion", A))
            m.target_sdk = _int(child.attr("targetSdkVersion", A))
            m.max_sdk = _int(child.attr("maxSdkVersion", A))
        elif child.name == "uses-permission":
            name = child.attr("name", A)
            if name:
                m.permissions.append(
                    Permission(name=str(name), protection_level=protection_level(str(name))))
        elif child.name == "permission":
            name = child.attr("name", A)
            if name:
                m.custom_permissions.append(CustomPermission(
                    name=str(name),
                    protection_level=str(child.attr("protectionLevel", A) or "unknown")))
        elif child.name == "application":
            _parse_application(child, m)
    return m


def _unresolved_ref(s: str) -> bool:
    """True when a manifest string is an unresolved resource reference
    (``@string/app_name``, ``@0x7f0a0001``) rather than a real value."""
    return s.startswith("@") or s.startswith("<type:")


def _parse_application(app: XElement, m: ManifestData) -> None:
    label = str(app.attr("label", A) or "")
    # Never surface an unresolved @string/... reference as the app name -
    # leave it empty so every consumer falls back to package/file name.
    m.app_name = "" if _unresolved_ref(label) else label
    dbg = app.attr("debuggable", A)
    m.debuggable = _bool(dbg) if dbg is not None else False
    backup = app.attr("allowBackup", A)
    m.allow_backup = _bool(backup) if backup is not None else True
    ct = app.attr("usesCleartextTraffic", A)
    m.uses_cleartext_traffic = _bool(ct) if ct is not None else None
    m.network_security_config = _s(app.attr("networkSecurityConfig", A))
    m.backup_rules = _s(app.attr("backupRules", A))
    m.full_backup_content = _s(app.attr("fullBackupContent", A))
    m.data_extraction_rules = _s(app.attr("dataExtractionRules", A))
    kinds = {"activity": m.activities, "service": m.services,
             "receiver": m.receivers, "provider": m.providers}
    for child in app.children:
        if child.name in kinds:
            kinds[child.name].append(_parse_component(child, child.name))


def load_manifest(extracted_dir: Path) -> tuple[ManifestData | None, Path | None, str]:
    """Load AndroidManifest.xml from an extracted APK dir.

    Returns (manifest or None, path to decoded text manifest or None, error).
    """
    manifest_bin = extracted_dir / "AndroidManifest.xml"
    if not manifest_bin.is_file():
        return None, None, "AndroidManifest.xml not found after extraction"
    try:
        data = manifest_bin.read_bytes()
    except OSError as exc:
        return None, None, f"cannot read AndroidManifest.xml: {exc}"
    try:
        manifest, text = parse_manifest_bytes(data)
    except Exception as exc:  # noqa: BLE001 - malformed manifests must not kill scans
        return None, None, f"manifest parse failed: {type(exc).__name__}: {exc}"
    text_path = extracted_dir / "AndroidManifest.decoded.xml"
    try:
        text_path.write_text(text, encoding="utf-8")
    except OSError:
        text_path = None  # type: ignore[assignment]
    return manifest, text_path, ""


def refine_app_name_from_decoded_manifest(dec_dir: Path) -> str:
    """Best-effort app-name recovery from a decoded (plain-XML) manifest.

    apktool resolves ``@string/app_name`` references when it decodes
    resources, so when our binary-XML parse left ``app_name`` empty this
    can recover the real display name (e.g. "Diva"). Returns "" when the
    decoded manifest is missing or the label is still a reference.
    Never raises - refinement must not break a scan.
    """
    try:
        import xml.etree.ElementTree as ET

        mf = dec_dir / "AndroidManifest.xml"
        if not mf.is_file():
            return ""
        root = ET.parse(str(mf)).getroot()
        ns = "{http://schemas.android.com/apk/res/android}"
        for app in root.iter("application"):
            label = app.get(f"{ns}label") or ""
            if label and not _unresolved_ref(label):
                return label
    except Exception:  # noqa: BLE001 - best effort only
        pass
    return ""
