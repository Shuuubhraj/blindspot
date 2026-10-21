"""Supply-chain and third-party SDK rules (BS-D01 .. BS-D20).

These rules go deeper than the platform inventory checks (BS-P09 native
library inventory, BS-P13 dependency inventory): instead of listing what is
bundled, they identify specific advertising, analytics, crash-reporting
and payment SDKs, flag end-of-life or CVE-affected library versions,
inspect native libraries for suspicious markers, detect the cross-platform
framework in use, and take a census of third-party trackers.

Rule index:
  BS-D01  advertising SDK detected (AdMob, Meta Audience Network, ...)
  BS-D02  analytics SDK detected (Firebase Analytics, Mixpanel, ...)
  BS-D03  crash-reporting SDK detected (Crashlytics, Sentry, ...)
  BS-D04  payment SDK detected (Stripe, Braintree, Razorpay, ...)
  BS-D05  Facebook SDK data sharing
  BS-D06  OkHttp version with known CVEs (< 4.1)
  BS-D07  Gson / Jackson-databind version with known CVEs
  BS-D08  suspicious strings in native libraries
  BS-D09  native library loaded from a variable path
  BS-D10  R8/ProGuard obfuscation markers
  BS-D11  DexGuard detected
  BS-D12  Flutter framework detected
  BS-D13  React Native framework detected
  BS-D14  Cordova / Capacitor framework detected
  BS-D15  Unity framework detected
  BS-D16  Xamarin framework detected
  BS-D17  tracker census (3 or more distinct trackers)
  BS-D18  unstripped native library (.symtab present)
  BS-D19  JNI bridge to sensitive Android APIs (needs review)
  BS-D20  deprecated Android Support library / ancient AndroidX
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import (
    Confidence,
    Rule,
    RuleResult,
    ScanContext,
    Severity,
    finding,
    needs_review,
    pass_result,
)
from .common import (
    evidence_from_hit,
    evidence_simple,
    grep,
    iter_source_files,
    iter_text_artifacts,
    read_text_capped,
)

_CATEGORY = "supply-chain"


class _SupplyRule(Rule):
    category = _CATEGORY
    masvs = ["MSTG-CODE"]

    def applies(self, ctx: ScanContext) -> bool:
        return True


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _source_rel_paths(ctx: ScanContext) -> list[str]:
    """Workspace-relative paths of decompiled sources, forward slashes."""
    roots = [r for r in (ctx.java_roots or []) if r and r.is_dir()]
    rels: list[str] = []
    for p in iter_source_files(ctx):
        for r in roots:
            try:
                rels.append(str(p.relative_to(r)).replace("\\", "/"))
                break
            except ValueError:
                continue
    return rels


def _find_sdks(
    ctx: ScanContext,
    table: list[tuple[str, str]],
    excludes: tuple[str, ...] = (),
) -> list[tuple[str, str, str]]:
    """Match (display name, path fragment) against APK entries and sources.

    Returns (display, fragment, location) for each fragment observed.
    Matching is case-insensitive; fragments must not appear inside an
    excluded substring.
    """
    entries = list(ctx.apk_entries or [])
    src_rels = _source_rel_paths(ctx)
    out: list[tuple[str, str, str]] = []
    for display, frag in table:
        needle = frag.lower()
        loc: str | None = None
        for e in entries:
            low = e.lower()
            if needle in low and not any(x.lower() in low for x in excludes):
                loc = e
                break
        if loc is None:
            for s in src_rels:
                low = s.lower()
                if needle in low and not any(x.lower() in low for x in excludes):
                    loc = s
                    break
        if loc is not None:
            out.append((display, frag, loc))
    return out


def _parse_version(token: str):
    """Parse 'major.minor[.patch]' -> (major, minor, patch) or None."""
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", token.strip())
    if not m:
        return None
    parts = [int(g) for g in m.groups() if g is not None]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _version_lt(found: tuple[int, ...], threshold: tuple[int, ...]) -> bool:
    f = tuple(found) + (0,) * (3 - len(found))
    t = tuple(threshold) + (0,) * (3 - len(threshold))
    return f < t


def _iter_so_files(ctx: ScanContext):
    """Yield native .so files under ctx.lib_dir (recursive, guarded)."""
    lib = ctx.lib_dir
    if not lib or not lib.is_dir():
        return
    for p in lib.rglob("*.so"):
        try:
            if p.is_file() and not p.is_symlink() and p.stat().st_size <= 50_000_000:
                yield p
        except OSError:
            continue


# ---------------------------------------------------------------------------
# SDK fragment tables: (display name, path fragment)
# ---------------------------------------------------------------------------

_D01_AD = [
    ("Google Mobile Ads (AdMob)", "com/google/android/gms/ads"),
    ("Meta Audience Network", "com/facebook/ads"),
    ("Unity Ads", "com/unity3d/ads"),
    ("AppLovin", "com/applovin"),
    ("ironSource", "com/ironsource"),
]

_D02_ANALYTICS = [
    ("Firebase Analytics", "com/google/firebase/analytics"),
    ("Mixpanel", "com/mixpanel"),
    ("Amplitude", "com/amplitude"),
    ("Flurry", "com/flurry"),
]

_D03_CRASH = [
    ("Fabric", "io/fabric"),
    ("Crashlytics", "com/crashlytics"),
    ("Sentry", "io/sentry"),
    ("Bugsnag", "com/bugsnag"),
]

_D04_PAYMENT = [
    ("Stripe", "com/stripe"),
    ("Braintree", "com/braintree"),
    ("Razorpay", "com/razorpay"),
    ("PayU Money", "com/payumoney"),
]

_D05_FACEBOOK = [("Facebook SDK", "com/facebook/")]
_D05_EXCLUDES = ("com/facebook/react/",)

_D12_FLUTTER = [("Flutter", "libflutter.so"), ("Flutter", "io/flutter/")]
_D13_RN = [("React Native", "com/facebook/react/")]
_D14_CORDOVA = [("Cordova/Capacitor", "org/apache/cordova/"), ("Cordova/Capacitor", "capacitor")]
_D15_UNITY = [("Unity", "libunity.so")]
_D16_XAMARIN = [("Xamarin", "monodroid"), ("Xamarin", "monoruntime"), ("Xamarin", "libmono")]

# Union used by the tracker census (BS-D17).
_TRACKER_TABLE = (
    _D01_AD + _D02_ANALYTICS + _D03_CRASH + _D05_FACEBOOK
    + _D12_FLUTTER + _D13_RN + _D14_CORDOVA + _D15_UNITY + _D16_XAMARIN
)


class _SdkRule(_SupplyRule):
    """Base for SDK-presence rules backed by a fragment table."""

    fragments: list[tuple[str, str]] = []
    excludes: tuple[str, ...] = ()
    kind_label = "Third-party SDK"
    empty_summary = "No matching SDK package paths detected."

    def _emit(
        self,
        ctx: ScanContext,
        found: list[tuple[str, str, str]],
        severity: Severity,
        severity_rationale: str,
        summary_head: str,
    ) -> RuleResult:
        if not found:
            return pass_result(self, self.empty_summary)
        names = ", ".join(d for d, _, _ in found)
        evs = [
            evidence_simple(ctx, loc, f"{self.kind_label} detected: {d} ({frag}).")
            for d, frag, loc in found[:50]
        ]
        return finding(
            self,
            f"{summary_head}: {names}.",
            evidence=evs,
            severity=severity,
            confidence=Confidence.HIGH,
            severity_rationale=severity_rationale,
            confidence_rationale=(
                "High: the SDK package paths are observed verbatim in the "
                "APK entry list or the decompiled source tree."
            ),
        )


# ---------------------------------------------------------------------------
# BS-D01  advertising SDK detected
# ---------------------------------------------------------------------------

class AdSdkDetected(_SdkRule):
    id = "BS-D01"
    title = "Advertising SDK detected"
    description = (
        "The app bundles a third-party advertising SDK (AdMob, Meta Audience "
        "Network, Unity Ads, AppLovin or ironSource). Ad SDKs routinely "
        "collect device identifiers and behavioural data and greatly expand "
        "the data-sharing surface of the app."
    )
    rationale = (
        "Advertising SDKs are a top source of unexpected data exfiltration: "
        "they fingerprint devices, build ad profiles and have a history of "
        "vulnerabilities that expose host-app data. Their presence must be "
        "a conscious, reviewed decision."
    )
    fragments = _D01_AD
    kind_label = "Advertising SDK"
    empty_summary = "No advertising SDK package paths detected."
    default_severity = Severity.LOW
    owasp = ["M4"]
    cwe = []
    remediation = (
        "Confirm each ad SDK is genuinely needed and pinned to a current, "
        "patched version. Disable unnecessary data collection in the SDK "
        "configuration (e.g. limit ad tracking, delay init until consent) "
        "and disclose the SDKs in the app's privacy policy."
    )
    references = ["https://owasp.org/www-project-mobile-top-10/"]

    def check(self, ctx: ScanContext) -> RuleResult:
        found = _find_sdks(ctx, self.fragments, self.excludes)
        return self._emit(
            ctx, found, Severity.LOW,
            "Low: SDK presence alone is not a vulnerability, but ad SDKs "
            "collect identifiers and behavioural data, so each one needs a "
            "privacy review.",
            f"{len(found)} advertising SDK(s) detected",
        )


# ---------------------------------------------------------------------------
# BS-D02  analytics SDK detected
# ---------------------------------------------------------------------------

class AnalyticsSdkDetected(_SdkRule):
    id = "BS-D02"
    title = "Analytics SDK detected"
    description = (
        "The app bundles a third-party analytics SDK (Firebase Analytics, "
        "Mixpanel, Amplitude or Flurry). Analytics SDKs observe user "
        "behaviour and often receive screen contents, custom events and "
        "device metadata."
    )
    rationale = (
        "Misconfigured analytics routinely leak PII: developers log emails, "
        "tokens or screen snapshots as 'events'. Knowing which analytics "
        "SDKs are present focuses the review of what is actually sent to "
        "them."
    )
    fragments = _D02_ANALYTICS
    kind_label = "Analytics SDK"
    empty_summary = "No analytics SDK package paths detected."
    default_severity = Severity.LOW
    owasp = ["M4"]
    cwe = []
    remediation = (
        "Audit every analytics event for PII before logging it, disable "
        "automatic screen-view and user-ID collection where not needed, "
        "pin the SDK to a patched version, and document the data flow in "
        "the privacy policy."
    )
    references = ["https://owasp.org/www-project-mobile-top-10/"]

    def check(self, ctx: ScanContext) -> RuleResult:
        found = _find_sdks(ctx, self.fragments, self.excludes)
        return self._emit(
            ctx, found, Severity.LOW,
            "Low: presence alone is not a vulnerability, but analytics SDKs "
            "are a classic PII exfiltration vector when events are logged "
            "carelessly.",
            f"{len(found)} analytics SDK(s) detected",
        )


# ---------------------------------------------------------------------------
# BS-D03  crash-reporting SDK detected
# ---------------------------------------------------------------------------

class CrashSdkDetected(_SdkRule):
    id = "BS-D03"
    title = "Crash-reporting SDK detected"
    description = (
        "The app bundles a crash-reporting SDK (Fabric, Crashlytics, Sentry "
        "or Bugsnag). Crash reports capture stack traces, breadcrumbs and "
        "sometimes custom keys that may contain secrets or user data."
    )
    rationale = (
        "Crash dumps are shipped to third-party servers and retained there. "
        "Secrets accidentally attached as custom keys or visible in stack "
        "frames become a persistent third-party data leak."
    )
    fragments = _D03_CRASH
    kind_label = "Crash-reporting SDK"
    empty_summary = "No crash-reporting SDK package paths detected."
    default_severity = Severity.LOW
    owasp = ["M4"]
    cwe = []
    remediation = (
        "Never attach secrets, tokens or PII as custom crash-report keys. "
        "Scrub breadcrumbs of sensitive data, pin the SDK version, and "
        "confirm crash data retention meets the app's privacy policy."
    )
    references = ["https://owasp.org/www-project-mobile-top-10/"]

    def check(self, ctx: ScanContext) -> RuleResult:
        found = _find_sdks(ctx, self.fragments, self.excludes)
        return self._emit(
            ctx, found, Severity.LOW,
            "Low: presence alone is not a vulnerability, but crash payloads "
            "leave the device and are a known secret/PII leakage channel.",
            f"{len(found)} crash-reporting SDK(s) detected",
        )


# ---------------------------------------------------------------------------
# BS-D04  payment SDK detected
# ---------------------------------------------------------------------------

class PaymentSdkDetected(_SdkRule):
    id = "BS-D04"
    title = "Payment SDK detected"
    description = (
        "The app bundles a payment SDK (Stripe, Braintree, Razorpay or PayU "
        "Money). Payment SDKs handle card and financial data, so an "
        "outdated or mis-integrated payment SDK is a direct path to "
        "financial-data compromise."
    )
    rationale = (
        "Payment SDKs are high-value targets: they process PANs and auth "
        "tokens, and older versions have shipped with CVEs. Their presence "
        "raises the assurance bar for the whole app."
    )
    fragments = _D04_PAYMENT
    kind_label = "Payment SDK"
    empty_summary = "No payment SDK package paths detected."
    default_severity = Severity.MEDIUM
    owasp = ["M4"]
    cwe = []
    remediation = (
        "Pin the payment SDK to the latest stable release, follow the "
        "vendor's PCI-relevant integration guide (never handle raw PANs in "
        "app code - use tokens), and include the SDK version in the security "
        "review scope for every release."
    )
    references = ["https://owasp.org/www-project-mobile-top-10/"]

    def check(self, ctx: ScanContext) -> RuleResult:
        found = _find_sdks(ctx, self.fragments, self.excludes)
        return self._emit(
            ctx, found, Severity.MEDIUM,
            "Medium: payment SDKs touch financial data, so their presence "
            "demands version and integration review even though presence "
            "alone is not a vulnerability.",
            f"{len(found)} payment SDK(s) detected",
        )


# ---------------------------------------------------------------------------
# BS-D05  Facebook SDK data sharing
# ---------------------------------------------------------------------------

class FacebookSdkDetected(_SdkRule):
    id = "BS-D05"
    title = "Facebook SDK present (data sharing)"
    description = (
        "The core Facebook SDK (com/facebook, excluding React Native's own "
        "com/facebook/react packages) is bundled. The SDK collects app "
        "events, device signals and advertising IDs and shares them with "
        "Meta by default."
    )
    rationale = (
        "The Facebook SDK's default configuration enables automatic event "
        "logging and advertiser-ID collection, which has repeatedly caused "
        "undeclared data sharing with Meta, including from health and "
        "finance apps."
    )
    fragments = _D05_FACEBOOK
    excludes = _D05_EXCLUDES
    kind_label = "Facebook SDK"
    empty_summary = "No Facebook SDK package paths detected."
    default_severity = Severity.LOW
    owasp = ["M4"]
    cwe = []
    remediation = (
        "If the SDK is required, disable auto event logging and advertiser "
        "ID collection (setAutoLogAppEventsEnabled(false), "
        "setAdvertiserIDCollectionEnabled(false)) unless strictly needed, "
        "keep it updated, and disclose Meta data sharing in the privacy "
        "policy."
    )
    references = ["https://developers.facebook.com/docs/app-events/"]

    def check(self, ctx: ScanContext) -> RuleResult:
        found = _find_sdks(ctx, self.fragments, self.excludes)
        return self._emit(
            ctx, found, Severity.LOW,
            "Low: presence alone is not a vulnerability, but the SDK shares "
            "app events and device signals with Meta under its defaults, so "
            "its configuration needs review.",
            "Facebook SDK detected",
        )


# ---------------------------------------------------------------------------
# BS-D06  OkHttp with known CVEs
# ---------------------------------------------------------------------------

class OkHttpOldVersion(_SupplyRule):
    id = "BS-D06"
    title = "OkHttp version with known CVEs"
    description = (
        "An OkHttp version string below 4.1 was found in the app. The OkHttp "
        "3.x line is end-of-life and several CVEs were published against it; "
        "apps stuck on 3.x miss certificate-handling and connection-pool "
        "security fixes."
    )
    rationale = (
        "OkHttp is the HTTP layer for most Android apps. CVEs in the TLS "
        "and connection handling of old versions directly undermine the "
        "confidentiality of every API call the app makes."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-1104"]
    remediation = (
        "Upgrade OkHttp to the latest 4.x or 5.x release, verify the "
        "version in the built APK (BuildConfig / dependency tree), and "
        "re-run the scan to confirm the old version string is gone."
    )
    references = ["https://square.github.io/okhttp/changelog/"]

    def applies(self, ctx: ScanContext) -> bool:
        return (
            bool(ctx.java_roots)
            or ctx.res_dir is not None
            or ctx.assets_dir is not None
        )

    def check(self, ctx: ScanContext) -> RuleResult:
        files = list(iter_source_files(ctx)) + list(iter_text_artifacts(ctx))
        hits = grep(r"(?<![\w.])okhttp3?/([^\s\"'<>;:,]+)", iter(files), flags=re.IGNORECASE)
        vuln: list[tuple] = []
        unknown: list = []
        seen: set[str] = set()
        for h in hits:
            token = h.match.group(1)
            if token in seen:
                continue
            seen.add(token)
            ver = _parse_version(token)
            if ver is None:
                unknown.append(h)
            elif _version_lt(ver, (4, 1, 0)):
                vuln.append((h, token))
        if vuln:
            evs = [
                evidence_from_hit(
                    ctx, h,
                    f"OkHttp version '{token}' is below 4.1 (3.x is "
                    "end-of-life with published CVEs).",
                )
                for h, token in vuln[:20]
            ]
            return finding(
                self,
                f"OkHttp version(s) below 4.1 detected: "
                f"{', '.join(t for _, t in vuln[:5])}.",
                evidence=evs,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "High: a CVE-affected HTTP/TLS layer undermines the "
                    "confidentiality and integrity of all app network traffic."
                ),
                confidence_rationale=(
                    "Medium: the version string is read verbatim from the "
                    "app, but version strings can be stale or duplicated "
                    "across repackaged libraries."
                ),
            )
        if unknown:
            return needs_review(
                self,
                "OkHttp version strings found but could not be parsed; "
                "confirm the bundled version is 4.1 or newer.",
                evidence=[
                    evidence_from_hit(ctx, h, "Unparseable OkHttp version string.")
                    for h in unknown[:20]
                ],
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                severity_rationale=(
                    "Medium: if the bundled OkHttp is a 3.x release it "
                    "carries published CVEs."
                ),
                confidence_rationale=(
                    "Low: the version token could not be parsed, so the "
                    "actual version is unknown."
                ),
            )
        return pass_result(
            self, "No OkHttp version below 4.1 detected in the app."
        )


# ---------------------------------------------------------------------------
# BS-D07  Gson / Jackson-databind with known CVEs
# ---------------------------------------------------------------------------

class JsonLibOldVersion(_SupplyRule):
    id = "BS-D07"
    title = "Gson / Jackson-databind version with known CVEs"
    description = (
        "Gson below 2.8.9 (CVE-2022-25647, deserialization of untrusted "
        "data) or jackson-databind below 2.12 (multiple deserialization "
        "CVEs) was detected in the app. Both libraries parse untrusted "
        "server responses, so a deserialization flaw is remotely reachable."
    )
    rationale = (
        "JSON parsers sit on the trust boundary between the app and the "
        "network. Deserialization CVEs in these libraries have enabled "
        "denial of service and, in gadget-chain scenarios, worse."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-1104", "CWE-502"]
    remediation = (
        "Upgrade Gson to 2.8.9 or newer and jackson-databind to 2.12 or "
        "newer (2.13+ preferred), then verify the resolved versions in the "
        "release dependency tree."
    )
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-25647",
        "https://github.com/FasterXML/jackson-databind/security/advisories",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return (
            bool(ctx.java_roots)
            or ctx.res_dir is not None
            or ctx.assets_dir is not None
        )

    def check(self, ctx: ScanContext) -> RuleResult:
        files = list(iter_source_files(ctx)) + list(iter_text_artifacts(ctx))
        checks = [
            ("Gson", r"(?<![\w.])gson\s*[:/\-]\s*([^\s\"'<>;:,]+)", (2, 8, 9),
             "CVE-2022-25647"),
            ("jackson-databind", r"(?<![\w.])jackson-databind\s*[:/\-]\s*([^\s\"'<>;:,]+)",
             (2, 12, 0), "multiple deserialization CVEs"),
        ]
        vuln: list[tuple] = []
        unknown: list = []
        seen: set[str] = set()
        for lib, pat, threshold, cve_note in checks:
            for h in grep(pat, iter(files), flags=re.IGNORECASE):
                token = h.match.group(1)
                key = (lib, token)
                if key in seen:
                    continue
                seen.add(key)
                ver = _parse_version(token)
                if ver is None:
                    unknown.append((h, lib, token))
                elif _version_lt(ver, threshold):
                    vuln.append((h, lib, token, cve_note))
        if vuln:
            evs = [
                evidence_from_hit(
                    ctx, h,
                    f"{lib} version '{token}' is affected by {cve_note}.",
                )
                for h, lib, token, cve_note in vuln[:20]
            ]
            return finding(
                self,
                "Vulnerable JSON library version(s): "
                + ", ".join(f"{lib} {token}" for _, lib, token, _ in vuln[:5])
                + ".",
                evidence=evs,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "Medium: deserialization flaws in the JSON layer are "
                    "remotely reachable through server responses, but "
                    "exploitability depends on gadget availability."
                ),
                confidence_rationale=(
                    "Medium: the version string is read verbatim from the "
                    "app, but it can be stale or duplicated across "
                    "repackaged libraries."
                ),
            )
        if unknown:
            return needs_review(
                self,
                "Gson/jackson-databind version strings found but could not "
                "be parsed; confirm Gson >= 2.8.9 and jackson-databind >= 2.12.",
                evidence=[
                    evidence_from_hit(ctx, h, f"Unparseable {lib} version string.")
                    for h, lib, _ in unknown[:20]
                ],
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                severity_rationale=(
                    "Medium: if the bundled version predates the fixed "
                    "releases it carries deserialization CVEs."
                ),
                confidence_rationale=(
                    "Low: the version token could not be parsed, so the "
                    "actual version is unknown."
                ),
            )
        return pass_result(
            self, "No vulnerable Gson or jackson-databind version detected."
        )


# ---------------------------------------------------------------------------
# BS-D08  suspicious strings in native libraries
# ---------------------------------------------------------------------------

_SUSPICIOUS_SO_MARKERS = (
    (b"su\x00", "embedded 'su' string (root/su reference)"),
    (b"/system/bin/sh", "reference to /system/bin/sh"),
    (b"chmod 777", "world-writable chmod marker"),
    (b"/data/local/tmp", "reference to /data/local/tmp staging path"),
)


class SuspiciousNativeStrings(_SupplyRule):
    id = "BS-D08"
    title = "Suspicious strings in native libraries"
    description = (
        "A bundled native library (.so) contains suspicious strings: an "
        "embedded 'su' reference, /system/bin/sh, 'chmod 777' or "
        "/data/local/tmp. Such markers are common in rooting helpers, "
        "packers and repackaged-malware payloads."
    )
    rationale = (
        "Legitimate app native code rarely references su or world-writable "
        "chmod patterns. Their presence in a shipped .so warrants manual "
        "review - it can indicate a trojanized or repackaged library."
    )
    default_severity = Severity.HIGH
    owasp = ["M4"]
    cwe = []
    remediation = (
        "Identify which library contains the marker and why. If it is not "
        "from a trusted, pinned dependency, remove it; verify APK provenance "
        "and rebuild from clean sources."
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        evs = []
        for so in _iter_so_files(ctx):
            try:
                data = so.read_bytes()
            except OSError:
                continue
            for marker, label in _SUSPICIOUS_SO_MARKERS:
                if marker in data:
                    evs.append(evidence_simple(
                        ctx, so,
                        f"Suspicious marker in native library: {label}.",
                    ))
                    break
        if evs:
            return finding(
                self,
                f"{len(evs)} native librar(ies) contain suspicious strings "
                "(su/sh/chmod-777/tmp-path markers).",
                evidence=evs[:20],
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "High: these markers are characteristic of rooting "
                    "helpers or trojanized native payloads running with the "
                    "app's privileges."
                ),
                confidence_rationale=(
                    "Medium: the byte markers are confirmed in the .so, but "
                    "a benign explanation (e.g. a root-detection library "
                    "referencing su) needs human review."
                ),
            )
        return pass_result(
            self, "No suspicious su/sh/chmod/tmp markers in native libraries."
        )


# ---------------------------------------------------------------------------
# BS-D09  native library loaded from a variable path
# ---------------------------------------------------------------------------

class NativeLoadVariable(_SupplyRule):
    id = "BS-D09"
    title = "Native library loaded from a variable path"
    description = (
        "Code calls System.load() with a non-literal (variable) argument. "
        "The loaded path is therefore computed at runtime and may be "
        "influenced by app data, preferences or intent extras."
    )
    rationale = (
        "System.load() with a variable path lets an attacker who controls "
        "the variable redirect native loading to a malicious .so, which "
        "then executes with the app's full privileges."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M4"]
    cwe = ["CWE-494"]
    remediation = (
        "Prefer System.loadLibrary() with a literal library name so the "
        "loader resolves it from the APK's trusted lib directory. If a "
        "dynamic path is unavoidable, validate it against an allowlist and "
        "verify the file's signature or checksum before loading."
    )
    references = ["https://cwe.mitre.org/data/definitions/494.html"]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r"System\s*\.\s*load\s*\(\s*[A-Za-z_$]",
            iter_source_files(ctx),
        )
        evs = [
            evidence_from_hit(
                ctx, h,
                "System.load() called with a non-literal (variable) path argument.",
            )
            for h in hits[:50]
        ]
        if evs:
            return finding(
                self,
                f"{len(hits)} System.load() call(s) use a variable path instead "
                "of a string literal.",
                evidence=evs,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "Medium: a redirected native load executes attacker code "
                    "with app privileges, but requires control over the "
                    "variable's value."
                ),
                confidence_rationale=(
                    "Medium: the non-literal argument is confirmed in "
                    "source; whether the variable is attacker-influenced "
                    "needs data-flow review."
                ),
            )
        return pass_result(
            self, "System.load() is only called with string literals."
        )


# ---------------------------------------------------------------------------
# BS-D10  R8/ProGuard obfuscation markers
# ---------------------------------------------------------------------------

_SINGLE_LETTER_SEG = re.compile(r"(^|/)[A-Za-z](/|$)")


class ObfuscationMarkers(_SupplyRule):
    id = "BS-D10"
    title = "R8/ProGuard-style obfuscation markers"
    description = (
        "APK entries contain single-letter package segments (e.g. a/b.class), "
        "the classic fingerprint of R8/ProGuard name obfuscation. This is an "
        "informational observation about the app's binary-protection posture."
    )
    rationale = (
        "Obfuscation raises the cost of reverse engineering and repackaging. "
        "Its absence on a release build is a hardening gap worth noting; its "
        "presence is a positive signal recorded here for the report."
    )
    default_severity = Severity.INFO
    owasp = ["M4"]
    cwe = []
    remediation = (
        "No action required if the app is already obfuscated. If no "
        "obfuscation markers are found on a release build, enable R8 "
        "(minifyEnabled true) for release variants."
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        matched = [
            e for e in (ctx.apk_entries or []) if _SINGLE_LETTER_SEG.search(e)
        ]
        if not matched:
            return pass_result(
                self, "No single-letter package segments observed in APK entries."
            )
        evs = [
            evidence_simple(
                ctx, e,
                "Single-letter path segment, consistent with R8/ProGuard "
                "name obfuscation.",
            )
            for e in matched[:20]
        ]
        return finding(
            self,
            f"{len(matched)} APK entr(ies) show single-letter package "
            "segments consistent with R8/ProGuard obfuscation.",
            evidence=evs,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            severity_rationale="Informational: a hardening observation, not a vulnerability.",
            confidence_rationale=(
                "High: the path segments are observed verbatim in the APK "
                "entry list; single-letter segments are the standard "
                "R8/ProGuard output shape."
            ),
        )


# ---------------------------------------------------------------------------
# BS-D11  DexGuard detected
# ---------------------------------------------------------------------------

class DexGuardDetected(_SupplyRule):
    id = "BS-D11"
    title = "DexGuard detected"
    description = (
        "Strings referencing DexGuard were found in the decompiled sources. "
        "DexGuard is a commercial hardening tool (string encryption, "
        "tamper detection, root detection); its presence is recorded as a "
        "binary-protection observation."
    )
    rationale = (
        "Knowing the hardening stack matters for scoping a pentest: "
        "DexGuard-protected apps need Frida/objection-based dynamic "
        "approaches rather than pure static analysis."
    )
    default_severity = Severity.INFO
    owasp = ["M4"]
    cwe = []
    remediation = (
        "No action required. Ensure the DexGuard configuration is actually "
        "applied to the release build (not just the dependency present) and "
        "kept current."
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"dexguard", iter_source_files(ctx), flags=re.IGNORECASE)
        if not hits:
            return pass_result(self, "No DexGuard references in sources.")
        evs = [
            evidence_from_hit(ctx, h, "DexGuard reference in source.")
            for h in hits[:20]
        ]
        return finding(
            self,
            f"{len(hits)} DexGuard reference(s) found in decompiled sources.",
            evidence=evs,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            severity_rationale="Informational: a hardening observation, not a vulnerability.",
            confidence_rationale=(
                "High: the DexGuard strings are read verbatim from the "
                "app's own sources."
            ),
        )


# ---------------------------------------------------------------------------
# Framework detection rules (BS-D12 .. BS-D16)
# ---------------------------------------------------------------------------

class _FrameworkRule(_SdkRule):
    kind_label = "Framework"
    empty_summary = "No framework markers detected."


class FlutterDetected(_FrameworkRule):
    id = "BS-D12"
    title = "Flutter framework detected"
    description = (
        "The app embeds the Flutter engine (libflutter.so) or Flutter "
        "framework classes (io/flutter). Flutter apps concentrate logic in "
        "native Dart snapshots, which changes the analysis approach."
    )
    rationale = (
        "Framework identification scopes the assessment: Flutter's Dart "
        "code needs snapshot analysis rather than Java review, and known "
        "Flutter CVEs apply to the bundled engine version."
    )
    fragments = _D12_FLUTTER
    default_severity = Severity.INFO
    owasp = ["M4"]
    cwe = []
    remediation = (
        "No action required. Keep the Flutter engine updated and review "
        "Dart-side code with Flutter-aware tooling."
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        found = _find_sdks(ctx, self.fragments, self.excludes)
        return self._emit(
            ctx, found, Severity.INFO,
            "Informational: framework identification, not a vulnerability.",
            "Flutter framework detected",
        )


class ReactNativeDetected(_FrameworkRule):
    id = "BS-D13"
    title = "React Native framework detected"
    description = (
        "The app bundles React Native (com/facebook/react). JavaScript "
        "bundles shipped in assets/ deserve the same secret and logic "
        "review as native code."
    )
    rationale = (
        "React Native apps often hide API keys and business logic in the "
        "JS bundle, which static Java-only reviews miss entirely."
    )
    fragments = _D13_RN
    default_severity = Severity.INFO
    owasp = ["M4"]
    cwe = []
    remediation = (
        "No action required. Include the JS bundle (assets/) in secret "
        "scanning and keep the React Native version patched."
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        found = _find_sdks(ctx, self.fragments, self.excludes)
        return self._emit(
            ctx, found, Severity.INFO,
            "Informational: framework identification, not a vulnerability.",
            "React Native framework detected",
        )


class CordovaDetected(_FrameworkRule):
    id = "BS-D14"
    title = "Cordova / Capacitor framework detected"
    description = (
        "The app is built on Apache Cordova or Capacitor "
        "(org/apache/cordova). Hybrid apps run in a WebView with a "
        "JavaScript bridge, inheriting WebView attack surface."
    )
    rationale = (
        "Cordova/Capacitor apps expose native plugins to JavaScript; a "
        "WebView misconfiguration or plugin flaw becomes a native-code "
        "execution primitive."
    )
    fragments = _D14_CORDOVA
    default_severity = Severity.INFO
    owasp = ["M4"]
    cwe = []
    remediation = (
        "No action required. Harden the WebView (no setJavaScriptEnabled "
        "unless needed, no addJavascriptInterface on untrusted content) "
        "and audit the plugin list."
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        found = _find_sdks(ctx, self.fragments, self.excludes)
        return self._emit(
            ctx, found, Severity.INFO,
            "Informational: framework identification, not a vulnerability.",
            "Cordova / Capacitor framework detected",
        )


class UnityDetected(_FrameworkRule):
    id = "BS-D15"
    title = "Unity framework detected"
    description = (
        "The app embeds the Unity engine (libunity.so). Game logic lives in "
        "managed DLLs / IL2CPP binaries rather than Java."
    )
    rationale = (
        "Unity apps need DLL/IL2CPP-aware review; Java-level checks see "
        "only the thin player activity wrapper."
    )
    fragments = _D15_UNITY
    default_severity = Severity.INFO
    owasp = ["M4"]
    cwe = []
    remediation = (
        "No action required. Keep the Unity player updated and review "
        "managed assemblies for embedded secrets."
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        found = _find_sdks(ctx, self.fragments, self.excludes)
        return self._emit(
            ctx, found, Severity.INFO,
            "Informational: framework identification, not a vulnerability.",
            "Unity framework detected",
        )


class XamarinDetected(_FrameworkRule):
    id = "BS-D16"
    title = "Xamarin framework detected"
    description = (
        "The app embeds the Xamarin/Mono runtime (monodroid, MonoRuntime, "
        "libmono). App logic lives in .NET assemblies bundled with the APK."
    )
    rationale = (
        "Xamarin apps need assembly-level review (decompile the DLLs); "
        "Java-level checks only see the Mono runtime host."
    )
    fragments = _D16_XAMARIN
    default_severity = Severity.INFO
    owasp = ["M4"]
    cwe = []
    remediation = (
        "No action required. Decompile bundled assemblies for secret and "
        "logic review and keep the Xamarin runtime patched."
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        found = _find_sdks(ctx, self.fragments, self.excludes)
        return self._emit(
            ctx, found, Severity.INFO,
            "Informational: framework identification, not a vulnerability.",
            "Xamarin framework detected",
        )


# ---------------------------------------------------------------------------
# BS-D17  tracker census
# ---------------------------------------------------------------------------

class TrackerCensus(_SupplyRule):
    id = "BS-D17"
    title = "Tracker census: 3 or more distinct third-party trackers"
    description = (
        "Three or more distinct third-party trackers or data-collecting SDKs "
        "were identified (advertising, analytics, crash reporting, Facebook "
        "SDK, or cross-platform frameworks). Each tracker is an independent "
        "data-sharing relationship."
    )
    rationale = (
        "Tracker accumulation is how apps end up sharing data with a dozen "
        "companies nobody approved: each SDK phones home with identifiers, "
        "and the union of their data enables cross-app profiling."
    )
    default_severity = Severity.INFO
    owasp = ["M4"]
    cwe = []
    remediation = (
        "Inventory every tracker against a business need, remove SDKs that "
        "are no longer used, configure the rest for minimal collection, "
        "and disclose all of them in the privacy policy."
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        found = _find_sdks(ctx, _TRACKER_TABLE, _D05_EXCLUDES)
        seen: dict[str, str] = {}
        for display, _frag, loc in found:
            seen.setdefault(display, loc)
        if len(seen) < 3:
            return pass_result(
                self,
                f"Only {len(seen)} distinct tracker(s) identified "
                "(threshold is 3).",
            )
        names = sorted(seen)
        evs = [
            evidence_simple(ctx, seen[n], f"Tracker present: {n}.")
            for n in names[:30]
        ]
        return finding(
            self,
            f"{len(seen)} distinct third-party trackers identified: "
            f"{', '.join(names)}.",
            evidence=evs,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Informational: a privacy-posture observation, not a "
                "vulnerability on its own."
            ),
            confidence_rationale=(
                "High: each tracker's package paths are observed verbatim "
                "in the APK entry list or the decompiled source tree."
            ),
        )


# ---------------------------------------------------------------------------
# BS-D18  unstripped native library
# ---------------------------------------------------------------------------

class UnstrippedNativeLib(_SupplyRule):
    id = "BS-D18"
    title = "Unstripped native library (.symtab present)"
    description = (
        "A bundled native library still contains the .symtab symbol table, "
        "meaning it was shipped unstripped. Symbol tables expose function "
        "and variable names, easing reverse engineering of the native code."
    )
    rationale = (
        "Stripping symbols is basic native-code hygiene: it removes the "
        "free function-name map that reverse engineers use to navigate "
        "proprietary algorithms and locate security checks."
    )
    default_severity = Severity.LOW
    owasp = ["M4"]
    cwe = []
    remediation = (
        "Strip release native libraries (llvm-strip / arm-linux-androideabi-"
        "strip, or packagingOptions with doNotStrip exclusions removed) and "
        "confirm .symtab is gone from the shipped .so files."
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        evs = []
        for so in _iter_so_files(ctx):
            try:
                data = so.read_bytes()
            except OSError:
                continue
            if b".symtab" in data:
                evs.append(evidence_simple(
                    ctx, so,
                    "Native library contains the .symtab section name: "
                    "shipped unstripped.",
                ))
        if evs:
            return finding(
                self,
                f"{len(evs)} native librar(ies) ship with symbol tables "
                "(.symtab present).",
                evidence=evs[:20],
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "Low: aids reverse engineering but is not directly "
                    "exploitable."
                ),
                confidence_rationale=(
                    "Medium: the .symtab section name is confirmed in the "
                    ".so bytes; a full section-header parse was not performed."
                ),
            )
        return pass_result(
            self, "No unstripped native libraries (.symtab) detected."
        )


# ---------------------------------------------------------------------------
# BS-D19  JNI bridge to sensitive APIs
# ---------------------------------------------------------------------------

_SENSITIVE_JNI_APIS = (
    "SmsManager", "LocationManager", "android.hardware.Camera",
    "CameraManager", "TelephonyManager", "AudioRecord", "MediaRecorder",
)


class JniSensitiveBridge(_SupplyRule):
    id = "BS-D19"
    title = "JNI native method in class touching sensitive APIs"
    description = (
        "A class declares native methods and also references sensitive "
        "Android APIs (SMS, location, camera, telephony, audio capture). "
        "Sensitive operations may be tunnelled through native code, where "
        "Java-level taint tracking cannot follow."
    )
    rationale = (
        "Moving sensitive API calls into JNI is a known analysis-evasion "
        "technique: permissions still gate the calls, but static review "
        "loses visibility into what data is collected and where it goes."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M4"]
    cwe = []
    remediation = (
        "Review the native implementations behind these declarations: "
        "confirm which sensitive APIs they invoke, what data they collect, "
        "and where that data is sent. Keep the JNI layer minimal and "
        "audited."
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        native_hits = grep(
            r"^\s*(?:public|private|protected)?\s*(?:static\s+)?native\s+\S+\s+\w+\s*\(",
            iter_source_files(ctx),
        )
        evs = []
        for h in native_hits:
            text = read_text_capped(h.path) or ""
            if any(api in text for api in _SENSITIVE_JNI_APIS):
                apis = [a for a in _SENSITIVE_JNI_APIS if a in text]
                evs.append(evidence_from_hit(
                    ctx, h,
                    f"Native method declared in a class referencing "
                    f"sensitive API(s): {', '.join(apis)}.",
                ))
        if evs:
            return needs_review(
                self,
                f"{len(evs)} native method declaration(s) found in classes "
                "that also reference sensitive Android APIs.",
                evidence=evs[:30],
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                severity_rationale=(
                    "Medium: if sensitive data flows through the JNI "
                    "boundary unchecked, collection can evade Java-level "
                    "controls."
                ),
                confidence_rationale=(
                    "Low: co-occurrence of a native declaration and a "
                    "sensitive API reference is a heuristic; the actual "
                    "native behaviour needs binary review."
                ),
            )
        return pass_result(
            self,
            "No native methods declared in classes touching sensitive APIs.",
        )


# ---------------------------------------------------------------------------
# BS-D20  deprecated Android Support library / ancient AndroidX
# ---------------------------------------------------------------------------

class DeprecatedSupportLib(_SupplyRule):
    id = "BS-D20"
    title = "Deprecated Android Support library or pre-1.0 AndroidX"
    description = (
        "The app still bundles the deprecated android.support libraries "
        "(no security updates since 2018, superseded by AndroidX) or an "
        "AndroidX dependency with a 0.x version, which predates the stable "
        "1.0 API and its security fixes."
    )
    rationale = (
        "Unmaintained libraries never receive security patches. The "
        "android.support line is frozen since 2018; known issues in it "
        "will never be fixed, and 0.x AndroidX releases predate hardening "
        "work that landed in 1.0."
    )
    default_severity = Severity.LOW
    owasp = ["M10"]
    cwe = ["CWE-1104"]
    remediation = (
        "Migrate android.support usages to AndroidX (1.x or newer) and "
        "upgrade any 0.x AndroidX dependencies to current stable releases."
    )
    references = ["https://developer.android.com/jetpack/androidx/migrate"]

    def check(self, ctx: ScanContext) -> RuleResult:
        evs = []
        for e in (ctx.apk_entries or []):
            if "android/support/" in e.lower():
                evs.append(evidence_simple(
                    ctx, e,
                    "Deprecated android.support library path in APK entries.",
                ))
        for rel in _source_rel_paths(ctx):
            if "android/support/" in rel.lower():
                evs.append(evidence_simple(
                    ctx, rel,
                    "Deprecated android.support package in decompiled sources.",
                ))
        files = list(iter_source_files(ctx)) + list(iter_text_artifacts(ctx))
        for h in grep(
            r"androidx[\w.\-:]*[:/\-]\s*(0\.\d[\d.]*)",
            iter(files),
            flags=re.IGNORECASE,
        ):
            evs.append(evidence_from_hit(
                ctx, h,
                f"Pre-1.0 AndroidX version string: '{h.match.group(1)}'.",
            ))
        if evs:
            return finding(
                self,
                f"{len(evs)} deprecated android.support reference(s) or "
                "pre-1.0 AndroidX version(s) detected.",
                evidence=evs[:30],
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "Low: unmaintained libraries miss future security "
                    "patches, but no specific exploitable flaw is asserted."
                ),
                confidence_rationale=(
                    "Medium: the deprecated paths and version strings are "
                    "observed verbatim, but version strings can be stale."
                ),
            )
        return pass_result(
            self, "No deprecated android.support or pre-1.0 AndroidX detected."
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    AdSdkDetected(),
    AnalyticsSdkDetected(),
    CrashSdkDetected(),
    PaymentSdkDetected(),
    FacebookSdkDetected(),
    OkHttpOldVersion(),
    JsonLibOldVersion(),
    SuspiciousNativeStrings(),
    NativeLoadVariable(),
    ObfuscationMarkers(),
    DexGuardDetected(),
    FlutterDetected(),
    ReactNativeDetected(),
    CordovaDetected(),
    UnityDetected(),
    XamarinDetected(),
    TrackerCensus(),
    UnstrippedNativeLib(),
    JniSensitiveBridge(),
    DeprecatedSupportLib(),
]

__all__ = ["RULES"]
