"""Platform, IPC, deep-link, binary-protection and supply-chain rules (BS-P01 .. BS-P20).

Each rule implements genuinely distinct detection logic against the scan
context. Manifest rules inspect ctx.manifest (components with intent
filters); source rules scan decompiled Java/Kotlin under ctx.java_roots;
package rules inspect ctx.apk (native libs, signing state) and ctx.assets_dir.

Rule index:
  BS-P01  deep link without android:autoVerify (app links)
  BS-P02  unsafe custom URL scheme on exported activity
  BS-P03  deep-link data reaches sensitive sinks (needs review)
  BS-P04  implicit intent carrying sensitive extras
  BS-P05  intent redirection via Parcelable extra
  BS-P06  exported broadcast receiver trusts extras without sender check
  BS-P07  content provider uses unsanitized URI input (needs review)
  BS-P08  content provider path traversal via uri.getPath()
  BS-P09  native library inventory (informational, never a vuln)
  BS-P10  dynamic native loading from writable location (needs review)
  BS-P11  test/debug/staging endpoints hardcoded in code
  BS-P12  embedded source maps / build artifacts in assets
  BS-P13  third-party dependency inventory (informational)
  BS-P14  weak / bypassable signature verification (needs review)
  BS-P15  root detection absent (informational PASS, never a finding)
  BS-P16  anti-tamper checks absent (informational PASS, never a finding)
  BS-P17  exported debug/test/staging activity
  BS-P18  PendingIntent mutability on targetSdk >= 31
  BS-P19  fragment injection via exported PreferenceActivity
  BS-P20  APK signed with the Android debug certificate
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import (
    Confidence,
    Evidence,
    IntentFilter,
    Rule,
    RuleStatus,
    ScanContext,
    Severity,
    finding,
    needs_review,
    not_applicable,
    pass_result,
)
from .common import (
    evidence_from_hit,
    evidence_simple,
    grep,
    iter_files,
    iter_source_files,
    iter_text_artifacts,
    read_text_capped,
)

_CATEGORY = "platform"

_VIEW = "android.intent.action.VIEW"
_BROWSABLE = "android.intent.category.BROWSABLE"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _manifest(ctx: ScanContext):
    return ctx.manifest


def _is_web_deep_link(f: IntentFilter) -> bool:
    """VIEW + BROWSABLE with an http/https data scheme (app-link candidate)."""
    return (
        _VIEW in f.actions
        and _BROWSABLE in f.categories
        and any((d.get("scheme") or "").lower() in ("http", "https") for d in f.data)
    )


def _is_any_deep_link(f: IntentFilter) -> bool:
    """VIEW + BROWSABLE with any data scheme (app link or custom scheme)."""
    return _VIEW in f.actions and _BROWSABLE in f.categories and bool(f.data)


def _deep_link_activities(ctx: ScanContext, web_only: bool = False):
    m = ctx.manifest
    if m is None:
        return []
    pred = _is_web_deep_link if web_only else _is_any_deep_link
    return [a for a in m.activities if a.exported and any(pred(f) for f in a.intent_filters)]


def _manifest_evidence(description: str) -> Evidence:
    """Evidence for manifest attributes: no real line numbers exist."""
    return Evidence(
        file_path="AndroidManifest.xml",
        snippet="",
        description=description,
        line_start=None,
        line_end=None,
    )


def _class_name_to_paths(ctx: ScanContext, class_name: str) -> list[Path]:
    """Map a manifest component class name to decompiled source files."""
    name = class_name or ""
    pkg = ctx.manifest.package if ctx.manifest and ctx.manifest.package else ""
    if name.startswith("."):
        name = pkg + name
    elif "." not in name and pkg:
        name = pkg + "." + name
    rel = name.replace(".", "/")
    out: list[Path] = []
    for root in ctx.java_roots:
        if not root or not root.is_dir():
            continue
        for ext in (".java", ".kt"):
            p = root / (rel + ext)
            try:
                if p.is_file() and not p.is_symlink():
                    out.append(p)
            except OSError:
                continue
    return out


def _activity_blocks(raw_xml: str):
    """Yield (android:name, block_text) for each <activity> element."""
    for m in re.finditer(r"<activity\b.*?</activity>|<activity\b[^>]*/>", raw_xml, re.S):
        block = m.group(0)
        nm = re.search(r'android:name\s*=\s*"([^"]+)"', block)
        yield (nm.group(1) if nm else ""), block


def _auto_verify_for(ctx: ScanContext, activity_name: str):
    """True/False/None: does the manifest declare autoVerify=true for this activity?"""
    m = ctx.manifest
    if m is None:
        return None
    raw = m.raw_xml or ""
    if not raw.strip():
        return None
    short = activity_name.rsplit(".", 1)[-1]
    found = False
    for name, block in _activity_blocks(raw):
        if not name:
            continue
        if name == activity_name or name.endswith("." + short) or name == short:
            found = True
            if 'android:autoVerify="true"' in block:
                return True
    return False if found else None


_VALIDATION_HINTS = (
    "validate", "sanitiz", "whitelist", "allowlist", "verify",
    "startsWith(", "equals(", "matches(", "checkCallingPermission",
    "enforceCallingPermission", "getSendingPackage", "Binder.getCallingUid",
)

_SENSITIVE_EXTRA_KEYS = (
    "password", "passwd", "pwd", "token", "secret", "api_key", "apikey",
    "auth", "session", "credential", "pin", "otp", "ssn",
)


def _has_validation_hint(text: str) -> bool:
    low = text.lower()
    return any(h.lower() in low for h in _VALIDATION_HINTS)


# ---------------------------------------------------------------------------
# BS-P01  deep link without android:autoVerify
# ---------------------------------------------------------------------------

class DeepLinkNoAutoVerify(Rule):
    id = "BS-P01"
    title = "Deep link declared without android:autoVerify"
    description = (
        "An exported activity handles http/https VIEW+BROWSABLE deep links but "
        "does not declare android:autoVerify=\"true\", so the OS will not "
        "verify the digital-asset-links association and the link opens via the "
        "system disambiguation dialog instead of as a verified app link."
    )
    rationale = (
        "Without autoVerify, any other app can claim the same URLs; users may "
        "be routed to a lookalike app and hand credentials or session data to "
        "an attacker-controlled activity."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-940"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Add android:autoVerify=\"true\" to the <intent-filter> and publish a "
        "valid assetlinks.json at https://<host>/.well-known/assetlinks.json "
        "containing the app's signing-certificate SHA-256 fingerprint."
    )
    references = ["https://developer.android.com/training/app-links"]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> "finding":
        m = ctx.manifest
        assert m is not None
        findings: list[Evidence] = []
        needs: list[Evidence] = []
        for act in _deep_link_activities(ctx, web_only=True):
            verdict = _auto_verify_for(ctx, act.name)
            ev = _manifest_evidence(
                f"Exported activity '{act.name}' handles http/https deep links "
                f"(android:autoVerify={'true' if verdict else 'not set' if verdict is False else 'unknown'})."
            )
            if verdict is True:
                continue
            if verdict is False:
                findings.append(ev)
            else:
                needs.append(ev)
        if findings:
            return finding(
                self,
                f"{len(findings)} exported activit(ies) declare http/https deep links "
                "without android:autoVerify=\"true\".",
                evidence=findings,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "Medium: unclaimed deep links let a malicious app intercept the "
                    "URLs, but exploitation needs the user to pick the wrong app "
                    "and the target URLs to carry sensitive state."
                ),
                confidence_rationale=(
                    "High: the manifest declares VIEW+BROWSABLE http/https data "
                    "and no autoVerify attribute is present in the activity block."
                ),
            )
        if needs:
            return needs_review(
                self,
                "Deep-link activities found, but the raw manifest text is not "
                "available so the autoVerify attribute could not be verified.",
                evidence=needs,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                severity_rationale=(
                    "Medium: same impact as a missing autoVerify if it is absent."
                ),
                confidence_rationale=(
                    "Low: apktool manifest decoding failed or was unavailable, "
                    "so the attribute state is unknown."
                ),
            )
        return pass_result(
            self,
            "No exported http/https deep-link activities without autoVerify found.",
        )


# ---------------------------------------------------------------------------
# BS-P02  unsafe custom URL scheme
# ---------------------------------------------------------------------------

class UnsafeCustomScheme(Rule):
    id = "BS-P02"
    title = "Unsafe custom URL scheme on exported activity"
    description = (
        "An exported activity is reachable through a custom URL scheme "
        "(e.g. myapp://). Custom schemes are not namespaced: any app on the "
        "device can register the same scheme and intercept the links."
    )
    rationale = (
        "Custom schemes have no ownership verification, so a malicious app can "
        "hijack links meant for this app, capture tokens in redirect URIs, or "
        "drive the exported activity with attacker-controlled data."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-940"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Prefer verified https app links (android:autoVerify) for sensitive "
        "flows such as OAuth redirects. If a custom scheme is required, keep "
        "the scheme long and app-specific, validate the full URI in code, and "
        "never place secrets in the redirect URI."
    )
    references = ["https://developer.android.com/training/app-links"]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> "needs_review":
        m = ctx.manifest
        assert m is not None
        evs: list[Evidence] = []
        for act in m.activities:
            if not act.exported:
                continue
            schemes = {
                (d.get("scheme") or "").lower()
                for f in act.intent_filters
                for d in f.data
                if d.get("scheme")
            }
            custom = {s for s in schemes if s not in ("http", "https")}
            if custom:
                evs.append(_manifest_evidence(
                    f"Exported activity '{act.name}' handles custom scheme(s): "
                    f"{', '.join(sorted(custom))}."
                ))
        if evs:
            return needs_review(
                self,
                f"{len(evs)} exported activit(ies) handle custom URL schemes, which "
                "any app on the device can also claim.",
                evidence=evs,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "Medium: scheme hijacking can intercept OAuth tokens or "
                    "drive the activity, but impact depends on what data the "
                    "activity accepts from the URI."
                ),
                confidence_rationale=(
                    "Medium: the scheme declaration is certain, but whether the "
                    "activity validates incoming URIs needs code review."
                ),
            )
        return pass_result(self, "No custom URL schemes on exported activities.")


# ---------------------------------------------------------------------------
# BS-P03  deep-link data reaches sensitive sinks
# ---------------------------------------------------------------------------

_SINK_PATTERNS = (
    "loadUrl(", "new File(", "execSQL(", "rawQuery(", "Runtime.getRuntime().exec(",
    ".exec(", "openFileOutput(", "openFileInput(", "FileInputStream(",
    "FileOutputStream(", "RandomAccessFile(", "loadDataWithBaseURL(",
)


class DeepLinkToSink(Rule):
    id = "BS-P03"
    title = "Deep-link URI data flows into sensitive sinks"
    description = (
        "A deep-link activity reads getIntent().getData()/getDataString() and "
        "the same class also invokes sensitive sinks (WebView.loadUrl, file "
        "APIs, SQL execution, process execution). Attacker-controlled URI "
        "content may reach those sinks."
    )
    rationale = (
        "Deep-link URIs are attacker-controlled input. Passing them into file "
        "paths, SQL, WebView loads or process execution without validation "
        "enables path traversal, injection or open-redirect style abuse."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M4"]
    cwe = ["CWE-20"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Validate every deep-link URI before use: allowlist expected "
        "hosts/paths, reject \"..\" segments, use UriMatcher, never build file "
        "paths or SQL by string concatenation, and never loadUrl() an "
        "unvalidated deep-link URI."
    )
    references = ["https://developer.android.com/training/app-links/deep-linking"]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None and bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> "needs_review":
        evs: list[Evidence] = []
        for act in _deep_link_activities(ctx, web_only=False):
            for path in _class_name_to_paths(ctx, act.name):
                hits = grep(
                    r"getIntent\s*\(\s*\)\s*\.\s*(getData|getDataString)\s*\(\s*\)",
                    iter([path]),
                )
                if not hits:
                    continue
                text = read_text_capped(path) or ""
                sinks = [s for s in _SINK_PATTERNS if s in text]
                if sinks:
                    evs.append(evidence_from_hit(
                        ctx, hits[0],
                        f"Deep-link activity '{act.name}' reads the incoming URI; "
                        f"the same class uses sink(s): {', '.join(sinks)}.",
                    ))
        if evs:
            return needs_review(
                self,
                f"{len(evs)} deep-link activit(ies) read getIntent().getData()/getDataString() "
                "in a class that also invokes file/SQL/WebView/exec sinks.",
                evidence=evs,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                severity_rationale=(
                    "Medium: if the URI reaches a sink unvalidated, path "
                    "traversal, SQL injection or WebView abuse is possible."
                ),
                confidence_rationale=(
                    "Low: co-occurrence in one class is a heuristic; actual "
                    "data flow from the URI to the sink needs taint analysis."
                ),
            )
        return pass_result(
            self,
            "No deep-link activity reads the incoming URI alongside sensitive sinks.",
        )


# ---------------------------------------------------------------------------
# BS-P04  implicit intent with sensitive extras
# ---------------------------------------------------------------------------

class ImplicitIntentSensitiveExtras(Rule):
    id = "BS-P04"
    title = "Implicit intent carries sensitive extras"
    description = (
        "Code builds an implicit Intent (action string, no target component) "
        "and attaches sensitive extras (password, token, secret...). Any app "
        "registering the action can receive the extras."
    )
    rationale = (
        "Implicit intents are broadcast to every app matching the action. "
        "Placing credentials or tokens in extras exposes them to any "
        "eavesdropping app that declares the same action."
    )
    category = _CATEGORY
    default_severity = Severity.LOW
    owasp = ["M8"]
    cwe = ["CWE-927"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Use explicit intents (setClass/setComponent/setPackage) for sensitive "
        "data, or encrypt extras and verify the recipient. Prefer result "
        "callbacks over passing secrets through intents at all."
    )
    references = [
        "https://developer.android.com/privacy-and-security/risks/intent-redirection"
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> "finding":
        key_alt = "|".join(_SENSITIVE_EXTRA_KEYS)
        extra_hits = grep(
            rf"putExtra\s*\(\s*\"[^\"]*(?:{key_alt})[^\"]*\"",
            iter_source_files(ctx),
            flags=re.IGNORECASE,
        )
        evs: list[Evidence] = []
        for hit in extra_hits:
            text = read_text_capped(hit.path)
            if not text:
                continue
            lines = text.splitlines()
            lo = max(0, hit.line_no - 1 - 40)
            hi = min(len(lines), hit.line_no + 40)
            window = "\n".join(lines[lo:hi])
            implicit = re.search(r"new\s+Intent\s*\(\s*\"", window)
            sent = re.search(r"startActivity\s*\(|sendBroadcast\s*\(|startService\s*\(", window)
            explicit = re.search(r"setClass\s*\(|setComponent\s*\(|setPackage\s*\(", window)
            if implicit and sent and not explicit:
                evs.append(evidence_from_hit(
                    ctx, hit,
                    "Sensitive extra attached near an implicit Intent that is "
                    "started/broadcast without setClass/setComponent/setPackage.",
                ))
        if evs:
            return finding(
                self,
                f"{len(evs)} location(s) attach sensitive extras to an implicit "
                "intent that is sent without a pinned target component.",
                evidence=evs,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "Low: exposure requires another app to register the same "
                    "action, but credentials in transit between components "
                    "should never rely on that being absent."
                ),
                confidence_rationale=(
                    "Medium: the implicit Intent construction, sensitive extra "
                    "key and send call are all present in nearby lines; exact "
                    "data flow is inferred statically."
                ),
            )
        return pass_result(
            self, "No implicit intents carrying sensitive extras detected."
        )


# ---------------------------------------------------------------------------
# BS-P05  intent redirection
# ---------------------------------------------------------------------------

class IntentRedirection(Rule):
    id = "BS-P05"
    title = "Intent redirection from untrusted Parcelable extra"
    description = (
        "Code extracts an Intent from an incoming Parcelable extra "
        "(getIntent().getParcelableExtra(...)) and forwards it with "
        "startActivity/startService/sendBroadcast, letting the sender choose "
        "the target component and extras."
    )
    rationale = (
        "A malicious sender can craft the nested intent to launch private "
        "components, grant URI permissions, or trigger privileged actions in "
        "the victim app's identity - a classic intent-redirection primitive."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M8"]
    cwe = ["CWE-927"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Never forward an intent received from another app. If unavoidable, "
        "verify getComponent()/getPackage() against an allowlist, strip "
        "FLAG_GRANT_* flags, and confirm the sender with "
        "checkCallingPermission() before acting on it."
    )
    references = [
        "https://developer.android.com/privacy-and-security/risks/intent-redirection"
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> "RuleResult":
        hits = grep(
            r"\(\s*Intent\s*\)\s*getIntent\s*\(\s*\)\s*\.\s*getParcelableExtra\s*\("
            r"|Intent\s+(\w+)\s*=\s*getIntent\s*\(\s*\)\s*\.\s*getParcelableExtra\s*\("
            r"|getIntent\s*\(\s*\)\s*\.\s*getParcelableExtra\s*\(",
            iter_source_files(ctx),
        )
        # dedupe: the alternation can match the same line several times
        _seen: set[tuple[str, int]] = set()
        _uniq = []
        for h in hits:
            key = (str(h.path), h.line_no)
            if key not in _seen:
                _seen.add(key)
                _uniq.append(h)
        hits = _uniq
        evs: list[Evidence] = []
        validated_any = False
        for hit in hits:
            text = read_text_capped(hit.path)
            if not text:
                continue
            lines = text.splitlines()
            # capture the variable holding the nested intent, if any
            var = None
            mvar = re.search(
                r"Intent\s+(\w+)\s*=\s*(?:\(\s*Intent\s*\)\s*)?getIntent\s*\(\s*\)"
                r"\s*\.\s*getParcelableExtra",
                hit.line,
            )
            if mvar:
                var = mvar.group(1)
            rest = "\n".join(lines[hit.line_no - 1:])
            forwarded = False
            if var:
                forwarded = bool(re.search(
                    rf"(startActivity|startService|sendBroadcast|startForegroundService)"
                    rf"\s*\(\s*{re.escape(var)}\b", rest))
            if not forwarded:
                # chained form: startActivity((Intent) getIntent().getParcelableExtra(...))
                forwarded = bool(re.search(
                    r"(startActivity|startService|sendBroadcast)\s*\(\s*"
                    r"(?:\(\s*Intent\s*\)\s*)?getIntent\s*\(\s*\)\s*\.\s*getParcelableExtra",
                    rest))
            if forwarded:
                if _has_validation_hint(text):
                    validated_any = True
                evs.append(evidence_from_hit(
                    ctx, hit,
                    "Nested Intent taken from getIntent().getParcelableExtra() "
                    "and forwarded to startActivity/startService/sendBroadcast.",
                ))
        if evs and not validated_any:
            return finding(
                self,
                f"{len(evs)} location(s) forward an Intent extracted from an "
                "incoming Parcelable extra with no visible validation.",
                evidence=evs,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "High: intent redirection lets an attacker invoke arbitrary "
                    "exported or even private components and exfiltrate data "
                    "with the victim app's privileges."
                ),
                confidence_rationale=(
                    "Medium: extraction and forwarding calls are confirmed in "
                    "source; absence of validation is inferred from the file."
                ),
            )
        if evs:
            return needs_review(
                self,
                f"{len(evs)} location(s) forward a nested Intent, but the file "
                "contains validation hints that need manual review.",
                evidence=evs,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                severity_rationale=(
                    "Medium: validation may mitigate the primitive, but "
                    "allowlist correctness must be confirmed by a human."
                ),
                confidence_rationale=(
                    "Low: forwarding is confirmed but the adequacy of the "
                    "validation logic is unknown statically."
                ),
            )
        return pass_result(
            self, "No intent-redirection pattern (Parcelable extra forwarded) found."
        )


# ---------------------------------------------------------------------------
# BS-P06  exported receiver trusts extras
# ---------------------------------------------------------------------------

class ReceiverTrustsExtras(Rule):
    id = "BS-P06"
    title = "Exported broadcast receiver trusts intent extras without sender check"
    description = (
        "An exported broadcast receiver reads intent extras but performs no "
        "sender verification (no permission on the receiver, no "
        "checkCallingPermission/enforceCallingPermission/getSendingPackage). "
        "Any app can send it crafted broadcasts."
    )
    rationale = (
        "Exported receivers accept broadcasts from any app. Acting on extras "
        "without verifying the sender lets a malicious app drive app logic, "
        "spoof events, or inject data into privileged workflows."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-927"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Set android:exported=\"false\" where possible; otherwise declare a "
        "signature-level permission on the <receiver>, verify the sender with "
        "checkCallingPermission() or compare getSendingPackage() against an "
        "allowlist, and validate every extra before use."
    )
    references = [
        "https://developer.android.com/guide/components/broadcasts#security"
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None and bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> "finding":
        m = ctx.manifest
        assert m is not None
        evs: list[Evidence] = []
        for rcv in m.receivers:
            if not rcv.exported:
                continue
            for path in _class_name_to_paths(ctx, rcv.name):
                text = read_text_capped(path)
                if not text:
                    continue
                extra_hits = grep(r"get\w+Extra\s*\(", iter([path]))
                if not extra_hits:
                    continue
                if _has_validation_hint(text):
                    continue
                evs.append(_manifest_evidence(
                    f"Exported receiver '{rcv.name}' reads intent extras with no "
                    "sender-permission check observed in its class."
                ))
                evs.append(evidence_from_hit(ctx, extra_hits[0],
                    f"Receiver '{rcv.name}' consumes extras."))
        if evs:
            return finding(
                self,
                "Exported broadcast receiver(s) consume intent extras without "
                "any sender verification in their implementation.",
                evidence=evs,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "Medium: any installed app can send broadcasts to an "
                    "exported receiver; impact depends on what the receiver "
                    "does with the extras."
                ),
                confidence_rationale=(
                    "Medium: export status comes from the manifest and extra "
                    "consumption from source; absence of a sender check is "
                    "inferred from the receiver class file."
                ),
            )
        return pass_result(
            self,
            "No exported receiver consuming extras without a sender check found.",
        )


# ---------------------------------------------------------------------------
# BS-P07  content provider unsanitized URI input
# ---------------------------------------------------------------------------

_provider_method_pat = r"public\s+\S+\s+(query|insert|update|delete|openFile|getType)\s*\("


class ProviderUnsafeInput(Rule):
    id = "BS-P07"
    title = "Content provider uses unsanitized URI input"
    description = (
        "A ContentProvider implementation overrides query/insert/update/delete/"
        "openFile and consumes unsanitized URI parts (uri.getPath(), "
        "uri.getLastPathSegment(), getQueryParameter()) with no visible "
        "validation, allowlist or UriMatcher-based routing."
    )
    rationale = (
        "Provider URIs are attacker-controlled. Unsanitized path segments can "
        "reach file APIs or SQL, enabling path traversal or injection through "
        "the provider interface."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M4"]
    cwe = ["CWE-20"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Route all provider URIs through UriMatcher, validate path segments "
        "against an allowlist, reject \"..\" and absolute paths, use "
        "parameterized queries, and never concatenate URI input into file "
        "paths or SQL."
    )
    references = [
        "https://developer.android.com/guide/topics/providers/content-provider-creating"
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None and bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> "needs_review":
        m = ctx.manifest
        assert m is not None
        evs: list[Evidence] = []
        for prov in m.providers:
            for path in _class_name_to_paths(ctx, prov.name):
                text = read_text_capped(path) or ""
                method_hits = [
                    h for h in grep(
                        _provider_method_pat,
                        iter([path]))
                ]
                if not method_hits:
                    continue
                uri_hits = grep(
                    r"\buri\s*\.\s*(getPath|getLastPathSegment|getQueryParameter|getPathSegments)\s*\(",
                    iter([path]),
                    flags=re.IGNORECASE,
                )
                if not uri_hits:
                    continue
                if _has_validation_hint(text):
                    continue
                evs.append(evidence_from_hit(
                    ctx, uri_hits[0],
                    f"Provider '{prov.name}' consumes unsanitized URI input "
                    "with no validation/allowlist observed.",
                ))
        if evs:
            return needs_review(
                self,
                f"{len(evs)} provider(s) consume URI path/query input without "
                "visible validation or UriMatcher routing.",
                evidence=evs,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                severity_rationale=(
                    "Medium: unsanitized provider input can reach file or SQL "
                    "operations, enabling traversal or injection."
                ),
                confidence_rationale=(
                    "Low: usage of URI accessors is confirmed, but whether "
                    "the values reach a sink unvalidated needs data-flow "
                    "review."
                ),
            )
        return pass_result(
            self, "No content provider with unsanitized URI input detected."
        )


# ---------------------------------------------------------------------------
# BS-P08  provider path traversal
# ---------------------------------------------------------------------------

class ProviderPathTraversal(Rule):
    id = "BS-P08"
    title = "Content provider builds file path from URI (path traversal)"
    description = (
        "Code constructs a java.io.File using a URI-derived path segment, "
        "e.g. new File(getContext().getFilesDir(), uri.getPath()). Without "
        "canonicalization, \"..\" segments escape the intended directory."
    )
    rationale = (
        "Provider URIs are attacker-controlled. Concatenating URI paths into "
        "file constructors is a textbook path-traversal primitive that can "
        "read or write arbitrary app-private files."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M4"]
    cwe = ["CWE-22"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Never build file paths from URI input. Resolve the file, then check "
        "file.getCanonicalPath().startsWith(baseDir.getCanonicalPath()); "
        "reject \"..\", absolute paths and symlinks."
    )
    references = ["https://cwe.mitre.org/data/definitions/22.html"]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> "finding":
        hits = grep(
            r"new\s+File\s*\([^;{]*\buri\s*\.\s*(getPath|getLastPathSegment|toString)\s*\(",
            iter_source_files(ctx),
        )
        evs = [
            evidence_from_hit(ctx, h,
                "File constructed from URI-derived path without visible "
                "canonicalization.")
            for h in hits[:50]
        ]
        if evs:
            return finding(
                self,
                f"{len(hits)} location(s) build a File from URI-derived input, "
                "a path-traversal primitive.",
                evidence=evs,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "Medium: traversal through a provider can read/write "
                    "app-private files; impact is bounded by the app sandbox "
                    "unless combined with other flaws."
                ),
                confidence_rationale=(
                    "Medium: the File-from-URI construction is confirmed in "
                    "source; canonicalization checks elsewhere in the file "
                    "were not verified."
                ),
            )
        return pass_result(
            self, "No File constructions from URI-derived paths detected."
        )


# ---------------------------------------------------------------------------
# BS-P09  native library inventory
# ---------------------------------------------------------------------------

class NativeLibInventory(Rule):
    id = "BS-P09"
    title = "Native library inventory"
    description = (
        "Lists the native (.so) libraries packaged with the APK. This is an "
        "inventory observation, not a vulnerability; it feeds binary-protection "
        "review (e.g. spotting outdated OpenSSL or missing hardening)."
    )
    rationale = (
        "Native code is opaque to Java-level checks. Knowing which .so files "
        "ship (and their ABIs) is the starting point for memory-safety and "
        "supply-chain review of native dependencies."
    )
    category = _CATEGORY
    default_severity = Severity.INFO
    owasp = ["M7"]
    cwe = []
    masvs = ["MSTG-CODE"]
    remediation = (
        "No action required from this inventory alone. Review the listed "
        "libraries for known-vulnerable versions and confirm they are built "
        "with modern hardening (PIE, RELRO, stack canaries)."
    )

    def applies(self, ctx: ScanContext) -> bool:
        return True  # ctx.apk is always present; empty list is a valid PASS

    def check(self, ctx: ScanContext) -> "finding":
        libs = list(ctx.apk.native_libs or [])
        if not libs:
            return pass_result(self, "No native libraries (.so) packaged in the APK.")
        evs = [
            evidence_simple(ctx, lib, f"Native library packaged: {lib}")
            for lib in libs[:50]
        ]
        return finding(
            self,
            f"APK ships {len(libs)} native librar(ies): {', '.join(libs[:10])}"
            + (" ..." if len(libs) > 10 else ""),
            evidence=evs,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            severity_rationale="Informational: inventory only, not a vulnerability.",
            confidence_rationale=(
                "High: the list comes directly from the APK's lib/ entries."
            ),
        )


# ---------------------------------------------------------------------------
# BS-P10  dynamic native loading from writable location
# ---------------------------------------------------------------------------

_WRITABLE_LOC = (
    "getExternalStorage", "Environment.getExternal", "getExternalFilesDir",
    "getExternalCacheDir", "getFilesDir()", "getCacheDir()", "/sdcard",
    "/data/local/tmp",
)


class DynamicNativeLoad(Rule):
    id = "BS-P10"
    title = "Native library loaded from variable or writable location"
    description = (
        "Code calls System.loadLibrary() with a non-literal (variable) "
        "library name, or System.load()/Runtime.load() with a path under a "
        "writable location (external storage, filesDir, cache). An attacker "
        "who can plant a .so there achieves code execution in the app process."
    )
    rationale = (
        "Loading native code from attacker-writable storage breaks the APK "
        "signature boundary: a malicious .so planted on shared storage runs "
        "with the app's full privileges. Variable library names can likewise "
        "be influenced via app data."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M7"]
    cwe = ["CWE-494"]
    masvs = ["MSTG-CODE"]
    remediation = (
        "Load native libraries only with System.loadLibrary(\"<literal-name>\") "
        "so the loader resolves them from the APK's trusted lib directory. "
        "Never System.load() a path under external storage or other writable "
        "directories; verify checksums if a path must be dynamic."
    )
    references = ["https://cwe.mitre.org/data/definitions/494.html"]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> "needs_review":
        evs: list[Evidence] = []
        lib_hits = grep(r"System\s*\.\s*loadLibrary\s*\(", iter_source_files(ctx))
        for h in lib_hits:
            if not re.search(r"loadLibrary\s*\(\s*\"", h.line):
                evs.append(evidence_from_hit(
                    ctx, h,
                    "System.loadLibrary() called with a non-literal (variable) argument."))
        load_hits = grep(
            r"(System\s*\.\s*load\s*\(|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*load\s*\()",
            iter_source_files(ctx),
        )
        for h in load_hits:
            if any(w in h.line for w in _WRITABLE_LOC):
                evs.append(evidence_from_hit(
                    ctx, h,
                    "System.load()/Runtime.load() with a path under a writable location."))
        if evs:
            return needs_review(
                self,
                f"{len(evs)} native-load call(s) use a variable library name or "
                "a writable-location path.",
                evidence=evs[:50],
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                severity_rationale=(
                    "Medium: a planted .so executes with the app's privileges, "
                    "but requires the attacker to write to that location."
                ),
                confidence_rationale=(
                    "Low: the call shape is suspicious, but whether the "
                    "variable/path is actually attacker-influenced needs "
                    "data-flow review."
                ),
            )
        return pass_result(
            self,
            "Native libraries are loaded via literal System.loadLibrary() names only.",
        )


# ---------------------------------------------------------------------------
# BS-P11  test/debug endpoints
# ---------------------------------------------------------------------------

_TEST_EP_MARKERS = ("/test", "/debug", "/staging", "/dev.", "localhost", "127.0.0.1", "10.0.2.2")


class TestEndpoints(Rule):
    id = "BS-P11"
    title = "Test/debug/staging endpoints in code"
    description = (
        "Source or config contains URLs pointing at test, debug, staging or "
        "localhost backends. Shipping non-production endpoints can leak data "
        "to unhardened servers or enable attacks against weaker test systems."
    )
    rationale = (
        "Test backends typically lack production hardening, logging controls "
        "and data-retention policies; leftover references also reveal internal "
        "infrastructure to anyone who decompiles the app."
    )
    category = _CATEGORY
    default_severity = Severity.LOW
    owasp = ["M8"]
    cwe = []
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Remove test/debug/staging URLs from release builds; drive endpoints "
        "from build flavors or remote config instead of hardcoded strings, "
        "and ensure production builds cannot reach non-production backends."
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots) or ctx.res_dir is not None or ctx.assets_dir is not None

    def check(self, ctx: ScanContext) -> "finding":
        marker_alt = "|".join(re.escape(mk) for mk in _TEST_EP_MARKERS)
        files = list(iter_source_files(ctx)) + list(iter_text_artifacts(ctx))
        hits = grep(
            rf"\"https?://[^\"]*(?:{marker_alt})[^\"]*\"",
            iter(files),
            flags=re.IGNORECASE,
        )
        evs = [
            evidence_from_hit(ctx, h, "Hardcoded non-production endpoint URL.")
            for h in hits[:50]
        ]
        if evs:
            return finding(
                self,
                f"{len(hits)} hardcoded URL(s) reference test/debug/staging/localhost backends.",
                evidence=evs,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "Low: usually a hygiene/information-disclosure issue, "
                    "escalating only if the test backend holds real data."
                ),
                confidence_rationale=(
                    "High: the URL strings are read verbatim from the app's "
                    "own code or resources."
                ),
            )
        return pass_result(
            self, "No test/debug/staging/localhost endpoint URLs detected."
        )


# ---------------------------------------------------------------------------
# BS-P12  embedded source maps / build artifacts
# ---------------------------------------------------------------------------

class BuildArtifacts(Rule):
    id = "BS-P12"
    title = "Embedded source maps or build artifacts"
    description = (
        "The package contains source-map files (*.js.map, *.map) or similar "
        "build artifacts, typically under assets/. They expose original "
        "source structure, filenames and sometimes source content."
    )
    rationale = (
        "Source maps are a reverse-engineering shortcut: they reveal original "
        "filenames, directory layout and occasionally embedded sources, "
        "lowering the cost of finding vulnerabilities."
    )
    category = _CATEGORY
    default_severity = Severity.LOW
    owasp = ["M7"]
    cwe = []
    masvs = ["MSTG-CODE"]
    remediation = (
        "Exclude *.map / *.js.map and other build artifacts from release "
        "APKs (packaging excludes in the web build config, ProGuard/R8 "
        "mapping files kept server-side only)."
    )

    def applies(self, ctx: ScanContext) -> bool:
        return True  # works off apk_entries alone

    def check(self, ctx: ScanContext) -> "finding":
        found: list[str] = []
        for entry in ctx.apk_entries or []:
            low = entry.lower()
            if low.endswith(".js.map") or low.endswith(".map"):
                found.append(entry)
        if ctx.assets_dir and ctx.assets_dir.is_dir():
            for p in iter_files([ctx.assets_dir], {".map"}):
                rel = str(p.relative_to(ctx.assets_dir))
                if rel not in found:
                    found.append(f"assets/{rel}")
        evs = [
            evidence_simple(ctx, e, f"Build artifact packaged: {e}")
            for e in found[:50]
        ]
        if evs:
            return finding(
                self,
                f"{len(found)} source-map/build artifact file(s) packaged in the APK.",
                evidence=evs,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "Low: aids reverse engineering but is not directly "
                    "exploitable on its own."
                ),
                confidence_rationale=(
                    "High: the files are present in the APK entry list."
                ),
            )
        return pass_result(self, "No source maps or build artifacts packaged.")


# ---------------------------------------------------------------------------
# BS-P13  third-party dependency inventory
# ---------------------------------------------------------------------------

_THIRD_PARTY_PREFIXES = (
    "com.google", "com.facebook", "com.squareup", "com.amazonaws",
    "com.microsoft", "com.huawei", "com.tencent", "com.alibaba",
    "com.dropbox", "com.stripe", "com.paypal", "com.twilio",
    "com.onesignal", "com.mixpanel", "com.segment", "com.appsflyer",
    "com.adjust", "com.crashlytics", "com.bugsnag", "io.sentry",
    "io.reactivex", "okhttp3", "retrofit2", "org.apache",
    "org.bouncycastle", "org.json", "org.greenrobot", "org.slf4j",
)


class DependencyInventory(Rule):
    id = "BS-P13"
    title = "Third-party dependency inventory"
    description = (
        "Lists distinct third-party SDK/library package prefixes observed in "
        "the decompiled sources. Inventory only; version and vulnerability "
        "matching is out of scope for this check."
    )
    rationale = (
        "Supply-chain risk starts with knowing what is bundled. Each "
        "third-party SDK expands the attack surface and inherits the "
        "vulnerabilities of its version."
    )
    category = _CATEGORY
    default_severity = Severity.INFO
    owasp = ["M2"]
    cwe = []
    masvs = []
    remediation = (
        "Keep this inventory under review: pin SDK versions, track advisories "
        "for each listed library, and remove SDKs the app no longer needs."
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> "finding":
        seen: set[str] = set()
        for root in ctx.java_roots:
            if not root or not root.is_dir():
                continue
            for path in iter_source_files(ctx):
                try:
                    rel = path.relative_to(root)
                except ValueError:
                    continue
                parts = rel.parts[:-1]
                if not parts:
                    continue
                prefix3 = ".".join(parts[:3])
                if prefix3 in seen:
                    continue
                low = prefix3.lower()
                if low.startswith(("android.", "androidx.", "java.", "kotlin.", "kotlinx.")):
                    continue
                if any(low == tp or low.startswith(tp + ".") or
                       ".".join(parts[:2]).lower() == tp or
                       parts[0].lower() == tp
                       for tp in _THIRD_PARTY_PREFIXES):
                    seen.add(prefix3)
        if not seen:
            return pass_result(
                self, "No recognized third-party SDK package prefixes observed."
            )
        evs = [
            evidence_simple(ctx, pfx, f"Third-party package prefix observed: {pfx}")
            for pfx in sorted(seen)[:50]
        ]
        return finding(
            self,
            f"{len(seen)} third-party SDK prefix(es) observed: "
            f"{', '.join(sorted(seen)[:10])}" + (" ..." if len(seen) > 10 else ""),
            evidence=evs,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            severity_rationale="Informational: inventory only, not a vulnerability.",
            confidence_rationale=(
                "High: prefixes are read from the actual decompiled package "
                "directory layout."
            ),
        )


# ---------------------------------------------------------------------------
# BS-P14  weak signature verification
# ---------------------------------------------------------------------------

_SIG_PATTERNS = (
    r"checkSignatures\s*\(",
    r"GET_SIGNATURES\b",
    r"GET_SIGNING_CERTIFICATES\b",
    r"\.signatures\b",
    r"signingInfo\b",
    r"hasSignatures\s*\(",
)


class WeakSignatureVerification(Rule):
    id = "BS-P14"
    title = "Weak or bypassable signature verification"
    description = (
        "Custom signature/certificate verification logic was found "
        "(checkSignatures, GET_SIGNATURES/SIGNING_CERTIFICATES, signature "
        "hash comparison). Some implementations fail open - e.g. returning "
        "true from an exception handler - or compare against attacker-visible "
        "constants without failing closed."
    )
    rationale = (
        "Anti-tamper checks that fail open are worse than none: they give a "
        "false sense of protection while a repackaged app passes them "
        "trivially."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M7"]
    cwe = ["CWE-347"]
    masvs = ["MSTG-RESILIENCE"]
    remediation = (
        "Compare the full signing-certificate digest (SHA-256) against the "
        "expected value, fail closed on any exception, perform the check in "
        "native code where feasible, and layer it with Play Integrity API "
        "attestation rather than relying on it alone."
    )
    references = ["https://cwe.mitre.org/data/definitions/347.html"]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> "needs_review":
        pat = "|".join(_SIG_PATTERNS)
        hits = grep(pat, iter_source_files(ctx))
        evs: list[Evidence] = []
        fail_open = False
        for h in hits[:50]:
            text = read_text_capped(h.path) or ""
            lines = text.splitlines()
            lo = max(0, h.line_no - 1 - 25)
            hi = min(len(lines), h.line_no + 25)
            window = "\n".join(lines[lo:hi])
            if re.search(r"catch\s*\([^)]*\)\s*\{[^}]*return\s+true", window, re.S):
                fail_open = True
                evs.append(evidence_from_hit(
                    ctx, h,
                    "Signature check with 'return true' inside an exception "
                    "handler: fails open."))
            else:
                evs.append(evidence_from_hit(
                    ctx, h,
                    "Custom signature/certificate verification logic found; "
                    "verify it fails closed."))
        if evs:
            summary = (
                f"{len(hits)} signature-verification reference(s) found"
                + ("; at least one returns true from an exception handler (fails open)."
                   if fail_open else
                   "; verify the comparison fails closed and covers the full certificate.")
            )
            return needs_review(
                self,
                summary,
                evidence=evs,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM if fail_open else Confidence.LOW,
                severity_rationale=(
                    "Medium: a bypassable tamper check undermines repackaging "
                    "defenses while appearing to protect the app."
                ),
                confidence_rationale=(
                    "Medium: fail-open exception handling confirmed in source."
                    if fail_open else
                    "Low: verification logic exists but its correctness needs "
                    "manual review."
                ),
            )
        return pass_result(
            self, "No custom signature/certificate verification logic detected."
        )


# ---------------------------------------------------------------------------
# BS-P15  root detection absent (informational only, never a finding)
# ---------------------------------------------------------------------------

_ROOT_HINTS = (
    "RootBeer", "isRooted", "RootUtil", "rootBeer", "checkRoot",
    "isDeviceRooted", "/system/bin/su", "/system/xbin/su", "which su",
    "test-keys", "SafetyNet", "PlayIntegrity",
)


class RootDetectionAbsent(Rule):
    id = "BS-P15"
    title = "No root detection observed (informational)"
    description = (
        "No references to common root-detection libraries or checks "
        "(RootBeer, isRooted, su-binary checks, Play Integrity) were found in "
        "the decompiled sources. This is informational: absence of root "
        "detection is a threat-model decision, not a vulnerability, and this "
        "rule never produces a FINDING."
    )
    rationale = (
        "Rooted devices weaken the OS security model. Whether an app must "
        "detect them depends on its risk profile; the scanner reports the "
        "observation so the assessor can decide."
    )
    category = _CATEGORY
    default_severity = Severity.INFO
    owasp = ["M7"]
    cwe = []
    masvs = ["MSTG-RESILIENCE"]
    remediation = (
        "Decide per threat model: if the app handles high-value transactions, "
        "add layered root detection (RootBeer-style checks plus Play "
        "Integrity verdicts) and degrade gracefully; for low-risk apps, "
        "document the accepted risk."
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> "RuleResult":
        pat = "|".join(re.escape(h) for h in _ROOT_HINTS)
        hits = grep(pat, iter_source_files(ctx))
        r = pass_result(
            self,
            "Root-detection references found in sources."
            if hits else
            "No root-detection references observed in decompiled sources "
            "(RootBeer/isRooted/su checks/Play Integrity); decide per threat "
            "model whether root detection is required. This is not a finding.",
        )
        r.severity = Severity.INFO  # informational PASS, never a FINDING
        return r


# ---------------------------------------------------------------------------
# BS-P16  anti-tamper absent (informational only, never a finding)
# ---------------------------------------------------------------------------

_TAMPER_HINTS = (
    "checkSignatures", "GET_SIGNING_CERTIFICATES", "signingInfo",
    "verifyInstaller", "getInstallerPackageName", "tamper", "integrity",
    "SafetyNet", "PlayIntegrity", "AppIntegrity", "apkSignature",
)


class AntiTamperAbsent(Rule):
    id = "BS-P16"
    title = "No anti-tamper checks observed (informational)"
    description = (
        "No signature verification, installer verification, or integrity "
        "attestation references were found in the decompiled sources. "
        "Informational only: whether tamper detection is required depends on "
        "the threat model, and this rule never produces a FINDING."
    )
    rationale = (
        "Repackaging/tampering defenses are a resilience decision. The "
        "scanner records their absence so the assessor can weigh it against "
        "the app's risk profile."
    )
    category = _CATEGORY
    default_severity = Severity.INFO
    owasp = ["M7"]
    cwe = []
    masvs = ["MSTG-RESILIENCE"]
    remediation = (
        "If repackaging is in scope, add layered tamper response: verify the "
        "signing certificate at runtime, check the installer package, and use "
        "Play Integrity API verdicts server-side."
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> "RuleResult":
        pat = "|".join(_TAMPER_HINTS)
        hits = grep(pat, iter_source_files(ctx), flags=re.IGNORECASE)
        r = pass_result(
            self,
            "Anti-tamper/integrity references found in sources."
            if hits else
            "No signature/tamper/integrity check references observed in "
            "decompiled sources; decide per threat model whether anti-tamper "
            "controls are required. This is not a finding.",
        )
        r.severity = Severity.INFO  # informational PASS, never a FINDING
        return r


# ---------------------------------------------------------------------------
# BS-P17  exported debug/test activity
# ---------------------------------------------------------------------------

_DEBUG_NAME_HINTS = ("debug", "test", "staging")


class ExportedDebugActivity(Rule):
    id = "BS-P17"
    title = "Exported debug/test/staging activity"
    description = (
        "An exported activity's class name contains debug/test/staging, "
        "suggesting a development or test screen is reachable by any app on "
        "the device."
    )
    rationale = (
        "Debug and test activities often expose internal state, feature "
        "flags, mock data or privileged operations without production-grade "
        "access control; exporting them hands that surface to every app."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = []
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Remove debug/test activities from release builds (build-type source "
        "sets) or set android:exported=\"false\" and gate them behind a "
        "signature-level permission and debug-only build flags."
    )

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None

    def check(self, ctx: ScanContext) -> "finding":
        m = ctx.manifest
        assert m is not None
        evs = [
            _manifest_evidence(
                f"Exported activity '{a.name}' has a debug/test-like name.")
            for a in m.activities
            if a.exported and any(h in a.name.lower() for h in _DEBUG_NAME_HINTS)
        ]
        if evs:
            return finding(
                self,
                f"{len(evs)} exported activit(ies) look like debug/test screens.",
                evidence=evs,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "Medium: test screens frequently expose internal "
                    "functionality or data; any app can launch an exported "
                    "activity."
                ),
                confidence_rationale=(
                    "Medium: export status is certain; the debug/test nature "
                    "is inferred from the class name and needs confirmation."
                ),
            )
        return pass_result(
            self, "No exported activities with debug/test-like names."
        )


# ---------------------------------------------------------------------------
# BS-P18  PendingIntent mutability (targetSdk >= 31)
# ---------------------------------------------------------------------------

_PI_METHODS = ("getActivity", "getService", "getBroadcast", "getForegroundService")


class PendingIntentMutability(Rule):
    id = "BS-P18"
    title = "Mutable PendingIntent without FLAG_IMMUTABLE (targetSdk 31+)"
    description = (
        "PendingIntent.getActivity/getService/getBroadcast is called without "
        "FLAG_IMMUTABLE (or with FLAG_MUTABLE) in an app targeting SDK 31+. "
        "A mutable PendingIntent lets the receiving app fill in unspecified "
        "intent fields, enabling intent redirection and privilege confusion."
    )
    rationale = (
        "Since Android 12, apps must declare PendingIntent mutability. A "
        "mutable PendingIntent handed to another app lets that app mutate the "
        "underlying intent - including the component and extras - executed "
        "with the creator's identity."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-927"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Pass PendingIntent.FLAG_IMMUTABLE unless the PendingIntent genuinely "
        "needs the receiver to fill in extras; if mutability is required, "
        "restrict the base intent (explicit component, no sensitive extras) "
        "and document why."
    )
    references = [
        "https://developer.android.com/about/versions/12/behavior-changes-12"
        "#pending-intent-mutability"
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return (
            bool(ctx.java_roots)
            and ctx.manifest is not None
            and ctx.manifest.target_sdk is not None
            and ctx.manifest.target_sdk >= 31
        )

    def _statement(self, path: Path, start_line: int) -> str:
        """Join lines from start_line until parens balance (bounded)."""
        text = read_text_capped(path) or ""
        lines = text.splitlines()
        depth = 0
        parts: list[str] = []
        started = False
        for line in lines[start_line - 1:start_line + 7]:
            for ch in line:
                if ch == "(":
                    depth += 1
                    started = True
                elif ch == ")":
                    depth -= 1
            parts.append(line)
            if started and depth <= 0:
                break
        return "\n".join(parts)

    def check(self, ctx: ScanContext) -> "finding":
        pat = r"PendingIntent\s*\.\s*(getActivity|getService|getBroadcast|getForegroundService)\s*\("
        hits = grep(pat, iter_source_files(ctx))
        evs: list[Evidence] = []
        for h in hits[:50]:
            stmt = self._statement(h.path, h.line_no)
            if "FLAG_IMMUTABLE" in stmt:
                continue
            mutable = "FLAG_MUTABLE" in stmt
            evs.append(evidence_from_hit(
                ctx, h,
                "PendingIntent created without FLAG_IMMUTABLE"
                + (" (FLAG_MUTABLE set)" if mutable else "") + "."))
        if evs:
            return finding(
                self,
                f"{len(evs)} PendingIntent creation(s) lack FLAG_IMMUTABLE on "
                f"targetSdk {ctx.manifest.target_sdk}.",  # type: ignore[union-attr]
                evidence=evs,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "Medium: a mutable PendingIntent can be abused for intent "
                    "redirection, but exploitation needs a malicious receiver "
                    "app and a sensitive base intent."
                ),
                confidence_rationale=(
                    "High: the PendingIntent factory call and the absence of "
                    "FLAG_IMMUTABLE are read directly from the call statement."
                ),
            )
        return pass_result(
            self,
            "All PendingIntent creations declare FLAG_IMMUTABLE (or none found).",
        )


def _dummy_hit(path: Path):
    """Fallback so evidence_from_hit never receives None."""
    from .common import Hit
    return Hit(path=path, line_no=1, line="", match=re.search(r"", ""))


# ---------------------------------------------------------------------------
# BS-P19  fragment injection
# ---------------------------------------------------------------------------

class FragmentInjection(Rule):
    id = "BS-P19"
    title = "Fragment injection via exported PreferenceActivity"
    description = (
        "An exported PreferenceActivity subclass does not override "
        "isValidFragment(). On Android < 4.4 this allows fragment injection; "
        "on newer versions the missing override still signals unreviewed "
        "fragment loading from an exported component."
    )
    rationale = (
        "PreferenceActivity instantiates fragments named by the launching "
        "intent's \":android:show_fragment\" extra. Without isValidFragment() "
        "restricting the allowlist, a malicious app can load arbitrary "
        "fragments in the victim's process."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-926"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Override isValidFragment() to allowlist only the app's own fragment "
        "classes, set android:exported=\"false\" where possible, and prefer "
        "PreferenceFragmentCompat / AndroidX Preference library over the "
        "legacy PreferenceActivity."
    )
    references = ["https://cwe.mitre.org/data/definitions/926.html"]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None and bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> "finding":
        m = ctx.manifest
        assert m is not None
        evs: list[Evidence] = []
        for act in m.activities:
            if not act.exported:
                continue
            for path in _class_name_to_paths(ctx, act.name):
                text = read_text_capped(path) or ""
                if "extends PreferenceActivity" not in text:
                    continue
                if "isValidFragment" in text:
                    continue
                hits = grep(r"extends\s+PreferenceActivity", iter([path]))
                hit = hits[0] if hits else _dummy_hit(path)
                evs.append(evidence_from_hit(
                    ctx, hit,
                    f"Exported PreferenceActivity '{act.name}' has no "
                    "isValidFragment() override."))
        if evs:
            return finding(
                self,
                f"{len(evs)} exported PreferenceActivit(ies) lack isValidFragment().",
                evidence=evs,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "Medium: fragment injection is a known primitive on older "
                    "platforms; on modern Android the missing override still "
                    "marks unvalidated fragment loading."
                ),
                confidence_rationale=(
                    "High: export status from the manifest, class hierarchy "
                    "and missing override confirmed in source."
                ),
            )
        return pass_result(
            self,
            "No exported PreferenceActivity without isValidFragment() found.",
        )


# ---------------------------------------------------------------------------
# BS-P20  debug certificate
# ---------------------------------------------------------------------------

class DebugCertificate(Rule):
    id = "BS-P20"
    title = "APK signed with the Android debug certificate"
    description = (
        "The APK's signing certificate is the well-known Android debug key. "
        "Debug-signed builds must never ship: the private key is public, so "
        "anyone can sign a lookalike app and replace or impersonate it."
    )
    rationale = (
        "The debug keystore (androiddebugkey) is identical on every "
        "development machine and its credentials are public knowledge. A "
        "debug-signed release can be trivially re-signed by an attacker, "
        "defeating signature-based trust, updates and tamper checks."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M7"]
    cwe = ["CWE-798"]
    masvs = ["MSTG-RESILIENCE"]
    remediation = (
        "Sign release builds with a dedicated, securely stored release key "
        "(Play App Signing recommended); never distribute debug-signed APKs."
    )
    references = ["https://cwe.mitre.org/data/definitions/798.html"]

    def applies(self, ctx: ScanContext) -> bool:
        # Unknown signing state must never be treated as debug-signed.
        return ctx.apk.is_debug_signed is not None

    def check(self, ctx: ScanContext) -> "finding":
        if ctx.apk.is_debug_signed:
            ev = _manifest_evidence(
                "APK signing analysis identified the Android debug certificate."
            )
            ev.file_path = "META-INF/CERT.RSA"
            return finding(
                self,
                "APK is signed with the public Android debug certificate.",
                evidence=[ev],
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "High: the debug private key is public knowledge, so the "
                    "signature provides no authenticity and the app can be "
                    "impersonated or replaced."
                ),
                confidence_rationale=(
                    "High: certificate fingerprint matched the known debug "
                    "key during package analysis."
                ),
            )
        return pass_result(self, "APK is not signed with the debug certificate.")


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    DeepLinkNoAutoVerify(),
    UnsafeCustomScheme(),
    DeepLinkToSink(),
    ImplicitIntentSensitiveExtras(),
    IntentRedirection(),
    ReceiverTrustsExtras(),
    ProviderUnsafeInput(),
    ProviderPathTraversal(),
    NativeLibInventory(),
    DynamicNativeLoad(),
    TestEndpoints(),
    BuildArtifacts(),
    DependencyInventory(),
    WeakSignatureVerification(),
    RootDetectionAbsent(),
    AntiTamperAbsent(),
    ExportedDebugActivity(),
    PendingIntentMutability(),
    FragmentInjection(),
    DebugCertificate(),
]

assert [r.id for r in RULES] == [f"BS-P{i:02d}" for i in range(1, 21)], \
    "platform rule IDs must be BS-P01..BS-P20 in order"
