"""WebView, input validation and injection detection rules (BS-W01 .. BS-W30).

Category: "webview"

Rule inventory:
  BS-W01  WebView JavaScript enabled (escalates when a JS bridge is also exposed)
  BS-W02  addJavascriptInterface exposing an object with sensitive methods
  BS-W03  WebView file access enabled (incl. universal/file-URL access)
  BS-W04  WebView loads cleartext HTTP or dynamically built URLs
  BS-W05  loadUrl with non-constant URL but no shouldOverrideUrlLoading
  BS-W06  WebView mixed content always allowed
  BS-W07  evaluateJavascript with string concatenation
  BS-W08  SQL injection via concatenated rawQuery/query/execSQL
  BS-W09  Command injection via Runtime.exec with concatenated input
  BS-W10  Path traversal via File built from intent/user input (heuristic)
  BS-W11  Unsafe deserialization (ObjectInputStream / XMLDecoder)
  BS-W12  Dynamic code loading with non-constant dex path
  BS-W13  Reflection reaching sensitive APIs (Runtime/SmsManager/WebView)
  BS-W14  WebView database/DOM storage enabled (informational)
  BS-W15  @JavascriptInterface method that reaches a sensitive sink
  BS-W16  WebView setAllowFileAccess / setAllowFileAccessFromFileURLs enabled
  BS-W17  WebView setAllowUniversalAccessFromFileURLs enabled
  BS-W18  WebView mixed content always allowed (explicit policy)
  BS-W19  WebView DOM storage enabled with sensitive keywords nearby
  BS-W20  WebView geolocation enabled without a permission check nearby
  BS-W21  addJavascriptInterface in a file that loads cleartext HTTP URLs
  BS-W22  loadUrl with an intent extra passed inline
  BS-W23  file:// URL passed to WebView.loadUrl
  BS-W24  JavaScript-enabled WebView in an exported activity
  BS-W25  Cleartext http:// URL passed to WebView loading APIs
  BS-W26  WebView setSavePassword(true) (deprecated credential saving)
  BS-W27  WebView setAcceptThirdPartyCookies(true)
  BS-W28  WebViewClient.onReceivedSslError calls handler.proceed()
  BS-W29  WebView setDatabaseEnabled(true)
  BS-W30  Unannotated JS-bridge method reaching a sensitive sink

Injection rules (W08-W10) treat a dangerous API alone as a heuristic:
FINDING requires string concatenation / String.format of variables reaching
the sink; otherwise NEEDS_REVIEW (W10) or PASS.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import (
    Confidence,
    Evidence,
    ManifestData,
    Rule,
    RuleResult,
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
    iter_source_files,
    read_text_capped,
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SENSITIVE_OPS_RX = re.compile(
    r"Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec"
    r"|FileOutputStream|openFileOutput\s*\(|openFileInput\s*\("
    r"|getSharedPreferences\s*\(|\.edit\s*\(\s*\)"
    r"|sendTextMessage\s*\(|sendMultipartTextMessage\s*\("
    r"|\.rawQuery\s*\(|\.execSQL\s*\(|SQLiteDatabase"
    r"|HttpURLConnection|OkHttpClient|loadUrl\s*\("
    r"|getSystemService\s*\("
)


def _arg_after_call(line: str, call_rx: str) -> str:
    """Return the text after the opening paren of the first call match."""
    m = re.search(call_rx, line)
    if not m:
        return ""
    return line[m.end():]


def _strip_string_literals(text: str) -> str:
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)


def _has_concat_or_format(arg: str) -> bool:
    """True when the call argument builds a string dynamically."""
    code = _strip_string_literals(arg)
    return ("+" in code) or ("String.format" in code)


def _is_constant_string(arg: str) -> bool:
    stripped = arg.strip()
    if not stripped.startswith('"'):
        return False
    code = _strip_string_literals(stripped)
    return "+" not in code and "String.format" not in code


def _files_with_hits(ctx: ScanContext, pattern: str) -> dict[Path, list]:
    out: dict[Path, list] = {}
    for hit in grep(pattern, iter_source_files(ctx)):
        out.setdefault(hit.path, []).append(hit)
    return out


def _read(path: Path) -> str:
    return read_text_capped(path) or ""


def _class_of_bridge_arg(arg: str) -> str | None:
    m = re.search(r"new\s+([A-Za-z_][\w$]*)\s*\(", arg)
    return m.group(1) if m else None


def _find_class_text(ctx: ScanContext, class_name: str) -> str | None:
    """Return the full text of the file that defines class_name, if found."""
    rx = re.compile(r"\bclass\s+" + re.escape(class_name) + r"\b")
    for path in iter_source_files(ctx):
        text = _read(path)
        if text and rx.search(text):
            return text
    return None


# ---------------------------------------------------------------------------
# BS-W01
# ---------------------------------------------------------------------------

class WebViewJavaScriptEnabledRule(Rule):
    id = "BS-W01"
    title = "WebView JavaScript enabled"
    description = (
        "Detects WebView.setJavaScriptEnabled(true). Enabling JavaScript "
        "widens the attack surface of every page the WebView loads."
    )
    rationale = (
        "JavaScript execution inside a WebView allows XSS, malicious pages and "
        "bridge abuse. Risk rises sharply when combined with "
        "addJavascriptInterface, which hands web content a Java object."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-749"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Disable JavaScript unless the WebView genuinely needs it. If it is "
        "required, only load trusted HTTPS content, validate every URL in "
        "shouldOverrideUrlLoading, and never combine JavaScript with an "
        "addJavascriptInterface bridge that reaches native functionality."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebSettings#setJavaScriptEnabled(boolean)",
        "https://cheatsheetseries.owasp.org/cheatsheets/Android_Application_Security_Cheatsheet.html",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"setJavaScriptEnabled\s*\(\s*true\s*\)", iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No setJavaScriptEnabled(true) calls found in decompiled sources.")
        escalated: list[Evidence] = []
        plain: list[Evidence] = []
        for hit in hits:
            text = _read(hit.path)
            if "addJavascriptInterface" in text:
                escalated.append(evidence_from_hit(
                    ctx, hit,
                    "setJavaScriptEnabled(true) and addJavascriptInterface() in the same file"))
            else:
                plain.append(evidence_from_hit(ctx, hit, "setJavaScriptEnabled(true)"))
        if escalated:
            return finding(
                self,
                f"JavaScript enabled in a WebView that also exposes an "
                f"addJavascriptInterface bridge ({len(escalated)} call site(s)). "
                f"Web content can invoke native Java methods.",
                evidence=escalated + plain,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "HIGH: JavaScript plus a JS bridge lets loaded web content call "
                    "into native code; this is the classic WebView bridge-escape "
                    "configuration. Escalated from MEDIUM because the bridge is present."),
                confidence_rationale=(
                    "MEDIUM: both calls were found in the same file, but it is not "
                    "proven that the bridged methods are reachable from untrusted "
                    "web content or that the WebView loads attacker-controlled pages."),
            )
        return finding(
            self,
            f"WebView.setJavaScriptEnabled(true) found at {len(plain)} call site(s).",
            evidence=plain,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: JavaScript in a WebView materially widens attack surface "
                "(XSS, malicious ads/pages) but is a legitimate feature on its own."),
            confidence_rationale=(
                "HIGH: setJavaScriptEnabled(true) is a direct, unambiguous API call."),
        )


# ---------------------------------------------------------------------------
# BS-W02
# ---------------------------------------------------------------------------

class JavascriptInterfaceExposureRule(Rule):
    id = "BS-W02"
    title = "addJavascriptInterface exposes a native object to web content"
    description = (
        "Detects WebView.addJavascriptInterface() and inspects the bridged "
        "class for public methods performing sensitive operations (process "
        "execution, file I/O, SharedPreferences writes, SMS, database or "
        "network access)."
    )
    rationale = (
        "Any object registered with addJavascriptInterface becomes callable "
        "from JavaScript running in the WebView. If its methods perform "
        "sensitive operations, a malicious or compromised page can abuse them."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-749"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Avoid addJavascriptInterface. Prefer postMessage/WebMessage channels, "
        "expose only @JavascriptInterface-annotated methods that do no "
        "sensitive work, restrict the WebView to trusted HTTPS origins, and "
        "validate URLs in shouldOverrideUrlLoading."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        by_file = _files_with_hits(ctx, r"addJavascriptInterface\s*\(")
        if not by_file:
            return pass_result(self, "No addJavascriptInterface() calls found.")
        dangerous: list[Evidence] = []
        plain: list[Evidence] = []
        for path, hits in by_file.items():
            for hit in hits:
                cls = _class_of_bridge_arg(_arg_after_call(hit.line, r"addJavascriptInterface\s*\("))
                class_text = _find_class_text(ctx, cls) if cls else None
                if class_text and _SENSITIVE_OPS_RX.search(class_text):
                    dangerous.append(evidence_from_hit(
                        ctx, hit,
                        f"Bridge class '{cls}' contains methods performing sensitive "
                        f"operations (process exec, file I/O, SMS, DB or network)"))
                else:
                    plain.append(evidence_from_hit(
                        ctx, hit,
                        f"addJavascriptInterface registers '{cls or 'an object'}' with web content"))
        if dangerous:
            return finding(
                self,
                f"addJavascriptInterface exposes object(s) whose class performs "
                f"sensitive operations ({len(dangerous)} call site(s)).",
                evidence=dangerous + plain,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "HIGH: the bridged class reaches process execution, file I/O, "
                    "SMS, database or network APIs, so web content could drive "
                    "those operations if it can reach the bridge."),
                confidence_rationale=(
                    "MEDIUM: the bridge registration and the sensitive operations "
                    "are real, but it is not statically proven that the sensitive "
                    "methods are the ones reachable from JavaScript, nor that the "
                    "WebView loads untrusted content."),
            )
        return finding(
            self,
            f"addJavascriptInterface() exposes native object(s) to web content "
            f"({len(plain)} call site(s)); no obviously sensitive operations "
            f"found in the bridged class.",
            evidence=plain,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "MEDIUM: any JS bridge expands the attack surface even when the "
                "bridged methods look benign, because method bodies or subclasses "
                "may change and content origin is unverified here."),
            confidence_rationale=(
                "MEDIUM: the bridge call is real; the absence of sensitive "
                "operations is a heuristic over the bridged class text and may "
                "miss obfuscated or inherited code."),
        )


# ---------------------------------------------------------------------------
# BS-W03
# ---------------------------------------------------------------------------

class WebViewFileAccessRule(Rule):
    id = "BS-W03"
    title = "WebView file access enabled"
    description = (
        "Detects setAllowFileAccess(true), setAllowFileAccessFromFileURLs(true) "
        "and setAllowUniversalAccessFromFileURLs(true). The latter two let "
        "file:// pages reach other origins and are high risk."
    )
    rationale = (
        "File-scheme access in a WebView lets loaded pages read local files. "
        "Universal access from file URLs additionally breaks the same-origin "
        "policy for file:// pages, enabling theft of local data."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-693"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Leave setAllowFileAccess(false) unless the WebView must read local "
        "files. Never enable setAllowUniversalAccessFromFileURLs or "
        "setAllowFileAccessFromFileURLs; serve local content over https with "
        "WebViewAssetLoader instead."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebSettings",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        universal = grep(
            r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)"
            r"|setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)",
            iter_source_files(ctx))
        file_access = grep(r"setAllowFileAccess\s*\(\s*true\s*\)", iter_source_files(ctx))
        if not universal and not file_access:
            return pass_result(self, "No WebView file-access settings enabled.")
        evidence = [evidence_from_hit(
            ctx, h, "Universal/file-URL access from file:// pages enabled")
            for h in universal]
        evidence += [evidence_from_hit(ctx, h, "setAllowFileAccess(true)")
                     for h in file_access]
        if universal:
            return finding(
                self,
                f"WebView allows file:// pages to access other origins "
                f"({len(universal)} call site(s)).",
                evidence=evidence,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "HIGH: this breaks the same-origin policy for file:// content, "
                    "letting a local page read arbitrary files and exfiltrate them."),
                confidence_rationale=(
                    "HIGH: the enabling call is explicit and unambiguous."),
            )
        return finding(
            self,
            f"WebView.setAllowFileAccess(true) found ({len(file_access)} call site(s)).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: file access lets WebView pages reach the local file "
                "system; impact depends on what content the WebView loads."),
            confidence_rationale=(
                "HIGH: the enabling call is explicit and unambiguous."),
        )


# ---------------------------------------------------------------------------
# BS-W04
# ---------------------------------------------------------------------------

class WebViewInsecureUrlLoadingRule(Rule):
    id = "BS-W04"
    title = "WebView loads cleartext HTTP or dynamically built URLs"
    description = (
        "Detects loadUrl/loadDataWithBaseURL calls with an http:// URL (FINDING) "
        "or with a dynamically constructed / non-constant URL (NEEDS_REVIEW)."
    )
    rationale = (
        "Cleartext HTTP in a WebView exposes page content and any credentials "
        "to network interception. Dynamically built URLs may route the WebView "
        "to attacker-influenced destinations."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M4"]
    cwe = []
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Load only https:// URLs in WebViews. Build URLs from allow-listed "
        "constants, validate them in shouldOverrideUrlLoading, and never pass "
        "raw intent data or user input into loadUrl."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebView#loadUrl(java.lang.String)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"\.loadUrl\s*\(|\.loadDataWithBaseURL\s*\(", iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No WebView loadUrl/loadDataWithBaseURL calls found.")
        http_hits: list[Evidence] = []
        dynamic_hits: list[Evidence] = []
        for hit in hits:
            arg = _arg_after_call(hit.line, r"\.load(?:Url|DataWithBaseURL)\s*\(")
            if re.search(r'"http://', arg):
                http_hits.append(evidence_from_hit(
                    ctx, hit, "WebView loads a cleartext http:// URL"))
            elif not _is_constant_string(arg):
                dynamic_hits.append(evidence_from_hit(
                    ctx, hit, "WebView loads a dynamically constructed URL"))
        if http_hits:
            return finding(
                self,
                f"WebView loads cleartext http:// content ({len(http_hits)} call site(s)).",
                evidence=http_hits + dynamic_hits,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "MEDIUM: cleartext HTTP allows network interception and "
                    "modification of page content and any credentials entered."),
                confidence_rationale=(
                    "HIGH: the http:// URL is a literal in the call."),
            )
        if dynamic_hits:
            return needs_review(
                self,
                f"WebView loads dynamically constructed URLs ({len(dynamic_hits)} "
                f"call site(s)); destinations need manual review.",
                evidence=dynamic_hits,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                severity_rationale=(
                    "MEDIUM: a dynamically built URL is a prerequisite for open "
                    "redirect / intent-driven WebView abuse if the input is "
                    "attacker-controlled."),
                confidence_rationale=(
                    "LOW: concatenation of a variable was observed, but the "
                    "source of the variable (trusted constant vs. user/intent "
                    "input) and exploitability were not established."),
            )
        return pass_result(
            self,
            "All WebView loadUrl/loadDataWithBaseURL calls use constant https URLs.")


# ---------------------------------------------------------------------------
# BS-W05
# ---------------------------------------------------------------------------

class WebViewMissingUrlOverrideRule(Rule):
    id = "BS-W05"
    title = "WebView loads dynamic URLs without shouldOverrideUrlLoading"
    description = (
        "Flags files that call loadUrl with a non-constant URL but never "
        "override WebViewClient.shouldOverrideUrlLoading, so navigation is "
        "never validated."
    )
    rationale = (
        "Without shouldOverrideUrlLoading there is no central choke point to "
        "validate navigation destinations, making open-redirect and "
        "intent-scheme abuse harder to prevent."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M4"]
    cwe = []
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Set a WebViewClient and override shouldOverrideUrlLoading to "
        "allow-list schemes/hosts, block javascript: and intent: URLs unless "
        "explicitly required, and reject unexpected destinations."
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        by_file = _files_with_hits(ctx, r"\.loadUrl\s*\(")
        if not by_file:
            return pass_result(self, "No loadUrl calls found.")
        evidence: list[Evidence] = []
        for path, hits in by_file.items():
            text = _read(path)
            if "shouldOverrideUrlLoading" in text:
                continue
            for hit in hits:
                arg = _arg_after_call(hit.line, r"\.loadUrl\s*\(")
                if not _is_constant_string(arg):
                    evidence.append(evidence_from_hit(
                        ctx, hit,
                        "loadUrl with non-constant URL; file has no "
                        "shouldOverrideUrlLoading override"))
        if not evidence:
            return pass_result(
                self,
                "All non-constant loadUrl calls are in files that override "
                "shouldOverrideUrlLoading, or all loadUrls are constant.")
        return needs_review(
            self,
            f"{len(evidence)} loadUrl call(s) use non-constant URLs in files "
            f"without shouldOverrideUrlLoading.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "MEDIUM: without URL validation there is no choke point to stop "
                "open redirects or malicious scheme handling; real impact "
                "depends on whether navigation is attacker-influenced."),
            confidence_rationale=(
                "LOW: only the absence of the override and a non-constant URL "
                "were observed; whether navigation is actually attacker "
                "controlled is not proven."),
        )


# ---------------------------------------------------------------------------
# BS-W06
# ---------------------------------------------------------------------------

class WebViewMixedContentRule(Rule):
    id = "BS-W06"
    title = "WebView mixed content always allowed"
    description = (
        "Detects setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW), which lets an "
        "https page load cleartext http subresources."
    )
    rationale = (
        "Mixed content undermines the confidentiality of an https page: "
        "scripts, frames and resources can be intercepted and modified on the "
        "network."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Use MIXED_CONTENT_NEVER_ALLOW (default from API 21) or at minimum "
        "MIXED_CONTENT_COMPATIBILITY_MODE, and fix the underlying http "
        "subresources instead of relaxing the policy."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebSettings#MIXED_CONTENT_ALWAYS_ALLOW",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r"setMixedContentMode\s*\(\s*(?:[A-Za-z_][\w.]*\.)?MIXED_CONTENT_ALWAYS_ALLOW\s*\)"
            r"|setMixedContentMode\s*\(\s*0\s*\)",
            iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No MIXED_CONTENT_ALWAYS_ALLOW usage found.")
        return finding(
            self,
            f"WebView mixed content policy set to ALWAYS_ALLOW ({len(hits)} call site(s)).",
            evidence=[evidence_from_hit(ctx, h, "Mixed content always allowed") for h in hits],
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: cleartext subresources on an https page can be "
                "intercepted and modified, weakening transport security."),
            confidence_rationale=(
                "HIGH: the ALWAYS_ALLOW constant is passed explicitly."),
        )


# ---------------------------------------------------------------------------
# BS-W07
# ---------------------------------------------------------------------------

class EvaluateJavascriptConcatRule(Rule):
    id = "BS-W07"
    title = "evaluateJavascript with string concatenation"
    description = (
        "Detects WebView.evaluateJavascript() calls that concatenate variables "
        "into the JavaScript string (XSS-style injection into the page context)."
    )
    rationale = (
        "Building the evaluated script by concatenation lets untrusted data "
        "break out of string literals and execute arbitrary JavaScript in the "
        "WebView's page context."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M4"]
    cwe = ["CWE-95"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Do not interpolate variables into evaluated scripts. Pass data via "
        "JSON-encoded arguments, postMessage, or a properly annotated JS "
        "bridge with input validation."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebView#evaluateJavascript(java.lang.String,%20android.webkit.ValueCallback%3Cjava.lang.String%3E)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"\.evaluateJavascript\s*\(", iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No evaluateJavascript calls found.")
        flagged = [h for h in hits
                   if _has_concat_or_format(_arg_after_call(h.line, r"\.evaluateJavascript\s*\("))]
        if not flagged:
            return pass_result(
                self, "All evaluateJavascript calls use constant script strings.")
        return needs_review(
            self,
            f"evaluateJavascript builds the script by string concatenation "
            f"({len(flagged)} call site(s)).",
            evidence=[evidence_from_hit(
                ctx, h, "Variable concatenated into evaluated JavaScript") for h in flagged],
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "MEDIUM: injected script runs in the WebView page context with "
                "access to the DOM and any JS bridge; impact is bounded by what "
                "the page can reach."),
            confidence_rationale=(
                "LOW: string concatenation was observed, but whether the "
                "concatenated variable carries attacker-controlled data is not "
                "proven; exploitability not confirmed."),
        )


# ---------------------------------------------------------------------------
# BS-W08
# ---------------------------------------------------------------------------

class SqlInjectionRule(Rule):
    id = "BS-W08"
    title = "SQL injection via concatenated query"
    description = (
        "Detects rawQuery/query/execSQL calls whose SQL is built with string "
        "concatenation or String.format of variables. Parameterized queries "
        "with ? placeholders pass."
    )
    rationale = (
        "Concatenating values into SQL lets attacker-controlled input alter "
        "the query structure, enabling data theft or modification in the local "
        "database."
    )
    category = "webview"
    default_severity = Severity.HIGH
    owasp = ["M4"]
    cwe = ["CWE-89"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Use parameterized queries with ? placeholders and selectionArgs / "
        "bind arguments. Never concatenate values into SQL strings."
    )
    references = [
        "https://developer.android.com/reference/android/database/sqlite/SQLiteDatabase#rawQuery(java.lang.String,%20java.lang.String%5B%5D)",
        "https://owasp.org/www-community/attacks/SQL_Injection",
    ]

    _CALL_RX = r"\.(?:rawQuery|execSQL|query)\s*\("

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(self._CALL_RX, iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No rawQuery/query/execSQL calls found.")
        flagged: list[Evidence] = []
        for hit in hits:
            arg = _arg_after_call(hit.line, self._CALL_RX)
            if _has_concat_or_format(arg):
                flagged.append(evidence_from_hit(
                    ctx, hit, "SQL built with string concatenation/String.format"))
        if not flagged:
            return pass_result(
                self, "All SQL calls use constant or parameterized queries.")
        return finding(
            self,
            f"SQL statement built by concatenating variables ({len(flagged)} call site(s)).",
            evidence=flagged,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "HIGH: SQL injection in the local database can exfiltrate or "
                "corrupt app data; concatenated values are the classic "
                "injection pattern."),
            confidence_rationale=(
                "MEDIUM: concatenation of variables into the SQL string is "
                "directly observed, but whether any variable is "
                "attacker-controlled (vs. app-internal) is not proven; "
                "exploitability not confirmed."),
        )


# ---------------------------------------------------------------------------
# BS-W09
# ---------------------------------------------------------------------------

class CommandInjectionRule(Rule):
    id = "BS-W09"
    title = "Command injection via Runtime.exec with concatenated input"
    description = (
        "Detects Runtime.getRuntime().exec() calls whose command is built with "
        "string concatenation or String.format. Constant string arrays pass."
    )
    rationale = (
        "Passing concatenated input to exec() lets attacker-controlled data "
        "inject extra shell commands or arguments, leading to arbitrary "
        "command execution in the app's process context."
    )
    category = "webview"
    default_severity = Severity.HIGH
    owasp = ["M4"]
    cwe = ["CWE-78"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Never build shell commands by concatenation. Pass a constant String[] "
        "argument array to exec(), avoid shell interpreters (sh -c), and "
        "validate/allow-list any external input."
    )
    references = [
        "https://owasp.org/www-community/attacks/Command_Injection",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"\.exec\s*\(", iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No .exec() calls found.")
        flagged: list[Evidence] = []
        for hit in hits:
            arg = _arg_after_call(hit.line, r"\.exec\s*\(")
            if _has_concat_or_format(arg):
                flagged.append(evidence_from_hit(
                    ctx, hit, "Command built with string concatenation/String.format"))
        if not flagged:
            return pass_result(
                self, "All .exec() calls use constant commands or argument arrays.")
        return finding(
            self,
            f"Runtime.exec() command built by concatenating variables "
            f"({len(flagged)} call site(s)).",
            evidence=flagged,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "HIGH: command injection yields arbitrary command execution in "
                "the app's sandbox context."),
            confidence_rationale=(
                "MEDIUM: concatenation into the command string is directly "
                "observed, but whether the variable is attacker-controlled is "
                "not proven; exploitability not confirmed."),
        )


# ---------------------------------------------------------------------------
# BS-W10
# ---------------------------------------------------------------------------

class PathTraversalRule(Rule):
    id = "BS-W10"
    title = "Path traversal via File built from intent/user input"
    description = (
        "Heuristic: files that read intent extras (getStringExtra/getExtras/ "
        "getData) and also build a java.io.File from a variable or "
        "concatenated path are flagged for review."
    )
    rationale = (
        "Constructing file paths from external input without canonicalization "
        "and validation allows ../ traversal to read or write outside the "
        "intended directory."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M4"]
    cwe = ["CWE-22"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Canonicalize paths with getCanonicalPath(), verify the result stays "
        "inside the intended directory, and prefer fixed allow-listed file "
        "names over raw input."
    )
    references = [
        "https://owasp.org/www-community/attacks/Path_Traversal",
    ]

    _INPUT_RX = re.compile(r"getStringExtra\s*\(|getExtras\s*\(\s*\)|getData\s*\(\s*\)")
    _FILE_RX = r"new\s+File\s*\("

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def _arg_is_variable(self, arg: str) -> bool:
        # Strip string literals and method calls (getFilesDir(), getCacheDir(),
        # ...) so only bare identifiers / concatenation count as variable.
        code = _strip_string_literals(arg)
        code = re.sub(r"[A-Za-z_][\w$]*\s*\(", "(", code)
        return bool(re.search(r"[A-Za-z_][\w$]*", code)) or ("+" in code)

    def check(self, ctx: ScanContext) -> RuleResult:
        by_file = _files_with_hits(ctx, self._FILE_RX)
        if not by_file:
            return pass_result(self, "No new File(...) constructions found.")
        evidence: list[Evidence] = []
        for path, hits in by_file.items():
            text = _read(path)
            if not self._INPUT_RX.search(text):
                continue
            for hit in hits:
                arg = _arg_after_call(hit.line, self._FILE_RX)
                if self._arg_is_variable(arg):
                    evidence.append(evidence_from_hit(
                        ctx, hit,
                        "File path built from a variable in a file that also "
                        "reads intent extras/data"))
        if not evidence:
            return pass_result(
                self, "No File constructions from variables in intent-input files.")
        return needs_review(
            self,
            f"{len(evidence)} File construction(s) use variable path components "
            f"in files that read intent extras or URI data.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "MEDIUM: path traversal can escape the intended directory and "
                "reach sensitive files; impact depends on the operation and "
                "the app's file permissions."),
            confidence_rationale=(
                "LOW: only a variable path component and the presence of "
                "intent-input reads in the same file were observed. It is not "
                "proven that the intent data actually reaches the File "
                "constructor, nor that canonicalization is absent; "
                "exploitability not confirmed."),
        )


# ---------------------------------------------------------------------------
# BS-W11
# ---------------------------------------------------------------------------

class UnsafeDeserializationRule(Rule):
    id = "BS-W11"
    title = "Unsafe Java deserialization"
    description = (
        "Detects ObjectInputStream.readObject() and XMLDecoder.readObject() "
        "usage, which deserialize attacker-influenced byte streams into live "
        "objects."
    )
    rationale = (
        "Java deserialization of untrusted data can trigger gadget chains "
        "leading to arbitrary code execution or denial of service."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M4"]
    cwe = ["CWE-502"]
    masvs = ["MSTG-CODE"]
    remediation = (
        "Avoid serializing sensitive objects. Prefer JSON with a strict "
        "schema, validate and integrity-check any data before deserialization, "
        "and never deserialize data from untrusted sources."
    )
    references = [
        "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        read_hits = grep(r"\.readObject\s*\(\s*\)", iter_source_files(ctx))
        if not read_hits:
            return pass_result(self, "No readObject() calls found.")
        evidence: list[Evidence] = []
        for hit in read_hits:
            text = _read(hit.path)
            if "ObjectInputStream" in text or "XMLDecoder" in text:
                kind = "ObjectInputStream" if "ObjectInputStream" in text else "XMLDecoder"
                evidence.append(evidence_from_hit(
                    ctx, hit, f"Deserialization via {kind}.readObject()"))
        if not evidence:
            return pass_result(
                self, "readObject() calls found but no ObjectInputStream/XMLDecoder usage.")
        return finding(
            self,
            f"Unsafe deserialization API used ({len(evidence)} call site(s)).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "MEDIUM: deserializing untrusted data can lead to code "
                "execution; impact depends on the data source and available "
                "gadget classes."),
            confidence_rationale=(
                "MEDIUM: the deserialization API is really used, but it is not "
                "proven that the deserialized bytes come from an untrusted "
                "source; exploitability not confirmed."),
        )


# ---------------------------------------------------------------------------
# BS-W12
# ---------------------------------------------------------------------------

class DynamicCodeLoadingRule(Rule):
    id = "BS-W12"
    title = "Dynamic code loading with non-constant dex path"
    description = (
        "Detects DexClassLoader/PathClassLoader/InMemoryDexClassLoader with a "
        "non-constant code path. Paths from external storage are HIGH; other "
        "variable paths are NEEDS_REVIEW."
    )
    rationale = (
        "Loading code from a non-constant or writable location lets an "
        "attacker substitute malicious dex code, especially from external "
        "storage or a URL."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-494"]
    masvs = ["MSTG-CODE"]
    remediation = (
        "Load code only from the app's private, read-only directories. Never "
        "load dex from external storage, downloads or network URLs, and "
        "verify integrity (signature/hash) before loading."
    )
    references = [
        "https://developer.android.com/reference/dalvik/system/DexClassLoader",
    ]

    _LOADER_RX = r"new\s+(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader)\s*\("
    _EXTERNAL_RX = re.compile(
        r"getExternalStorage|getExternalFilesDir|getExternalCacheDir|http://|https://|"
        r"Environment\.MEDIA|/sdcard|/storage/emulated")

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(self._LOADER_RX, iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No dynamic class loader usage found.")
        high_ev: list[Evidence] = []
        review_ev: list[Evidence] = []
        for hit in hits:
            arg = _arg_after_call(hit.line, self._LOADER_RX).strip()
            if _is_constant_string(arg):
                continue
            if self._EXTERNAL_RX.search(arg):
                high_ev.append(evidence_from_hit(
                    ctx, hit, "Dex path from external storage / URL"))
                continue
            # Variable path: trace a same-file assignment like
            #   String p = Environment.getExternalStorageDirectory() + "/x.dex";
            first_ident = re.match(r"([A-Za-z_][\w$]*)", arg)
            text = _read(hit.path)
            traced_external = False
            if first_ident and text:
                traced_external = bool(re.search(
                    r"\b" + re.escape(first_ident.group(1)) + r"\s*=[^;]*"
                    r"(getExternalStorage|getExternalFilesDir|getExternalCacheDir"
                    r"|http://|https://|/sdcard|/storage/emulated)",
                    text))
            if traced_external:
                high_ev.append(evidence_from_hit(
                    ctx, hit,
                    f"Dex path variable '{first_ident.group(1)}' is assigned "
                    f"from external storage / URL in the same file"))
            else:
                review_ev.append(evidence_from_hit(
                    ctx, hit, "Dynamic code loading with non-constant path"))
        if not high_ev and not review_ev:
            return pass_result(
                self, "All class loaders use constant, app-internal paths.")
        evidence = high_ev + review_ev
        if high_ev:
            return finding(
                self,
                f"Dynamic code loading from external storage/URL ({len(high_ev)} call site(s)).",
                evidence=evidence,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "HIGH: dex loaded from writable external storage or a URL "
                    "can be replaced by an attacker, leading to code execution."),
                confidence_rationale=(
                    "MEDIUM: the loader call and the external-storage/URL path "
                    "source are observed, but actual write access by an "
                    "attacker and integrity checks are not established."),
            )
        return needs_review(
            self,
            f"Dynamic code loading with a variable path ({len(review_ev)} call site(s)).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "MEDIUM: loading code from a variable path is risky if the "
                "location is attacker-influenced."),
            confidence_rationale=(
                "LOW: the path is a variable, but its origin and whether it is "
                "attacker-writable are not established; exploitability not "
                "confirmed."),
        )


# ---------------------------------------------------------------------------
# BS-W13
# ---------------------------------------------------------------------------

class ReflectionSensitiveApiRule(Rule):
    id = "BS-W13"
    title = "Reflection reaching sensitive APIs"
    description = (
        "Heuristic: files that look up methods by string name "
        "(getDeclaredMethod/getMethod) and invoke them, in code that also "
        "touches Runtime, SmsManager or WebView internals."
    )
    rationale = (
        "Reflection with string method names is used to hide sensitive API "
        "usage from static review (evasion) or to reach hidden/internal APIs, "
        "both of which deserve manual inspection."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = []
    masvs = ["MSTG-CODE"]
    remediation = (
        "Avoid reflection for sensitive APIs; call them directly so usage is "
        "auditable. If reflection is unavoidable, restrict method names to a "
        "fixed allow-list and document why it is needed."
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        by_file = _files_with_hits(ctx, r"getDeclaredMethod\s*\(\s*\"|getMethod\s*\(\s*\"")
        if not by_file:
            return pass_result(self, "No reflective method lookups with string names found.")
        evidence: list[Evidence] = []
        for path, hits in by_file.items():
            text = _read(path)
            if ".invoke(" not in text:
                continue
            if not re.search(r"\bRuntime\b|\bSmsManager\b|\bWebView\b", text):
                continue
            for hit in hits:
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    "Reflective method lookup by string name with invoke() near "
                    "Runtime/SmsManager/WebView usage"))
        if not evidence:
            return pass_result(
                self, "Reflective lookups found but none reach sensitive APIs via invoke().")
        return needs_review(
            self,
            f"Reflection by string method name near sensitive APIs "
            f"({len(evidence)} call site(s)).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "MEDIUM: reflection can hide or reach sensitive behavior "
                "(e.g. Runtime.exec, SMS, WebView internals); real impact "
                "depends on which method is actually invoked."),
            confidence_rationale=(
                "LOW: only the reflective lookup, an invoke() call and nearby "
                "mentions of Runtime/SmsManager/WebView were observed. It is "
                "not proven that the reflected method is a sensitive one or "
                "that this is evasion; manual review required."),
        )


# ---------------------------------------------------------------------------
# BS-W14
# ---------------------------------------------------------------------------

class WebViewStorageEnabledRule(Rule):
    id = "BS-W14"
    title = "WebView database/DOM storage enabled"
    description = (
        "Informational: detects setDatabaseEnabled(true) and "
        "setDomStorageEnabled(true). Enabling web storage is not a "
        "vulnerability on its own, but stored web data widens exposure if "
        "other storage issues exist."
    )
    rationale = (
        "Web SQL / DOM storage lets web content persist data on the device. "
        "It is a legitimate feature; the risk is contextual (sensitive data "
        "stored by pages, cross-origin leakage)."
    )
    category = "webview"
    default_severity = Severity.INFO
    owasp = ["M9"]
    cwe = []
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Enable DOM/database storage only if the WebView content needs it. "
        "Audit what the loaded pages store, and clear storage on logout or "
        "session end if it may hold sensitive data."
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r"setDatabaseEnabled\s*\(\s*true\s*\)|setDomStorageEnabled\s*\(\s*true\s*\)",
            iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No WebView database/DOM storage enabled.")
        return finding(
            self,
            f"WebView database/DOM storage enabled ({len(hits)} call site(s)); "
            f"informational only.",
            evidence=[evidence_from_hit(
                ctx, h, "WebView web storage enabled") for h in hits],
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "INFO: enabling web storage is a legitimate WebView feature, "
                "not a vulnerability by itself; recorded so reviewers can "
                "correlate it with storage-related findings."),
            confidence_rationale=(
                "HIGH: the enabling call is explicit and unambiguous."),
        )


# ---------------------------------------------------------------------------
# BS-W15
# ---------------------------------------------------------------------------

class JavascriptInterfaceSinkRule(Rule):
    id = "BS-W15"
    title = "@JavascriptInterface method reaches a sensitive sink"
    description = (
        "Data-flow check: finds methods annotated @JavascriptInterface and "
        "verifies by brace-scoped body analysis whether the method body itself "
        "reaches a sensitive sink (process exec, file write, SQL, SMS, "
        "network, WebView loadUrl). Distinct from BS-W02, which assesses the "
        "exposed surface rather than the flow into sinks."
    )
    rationale = (
        "A JS-bridge method that directly performs sensitive operations gives "
        "web content a one-call path to those operations; this is the "
        "exploitable core of bridge abuse."
    )
    category = "webview"
    default_severity = Severity.HIGH
    owasp = ["M4"]
    cwe = ["CWE-749"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Do not put sensitive operations inside @JavascriptInterface methods. "
        "Move privileged work server-side or behind explicit user "
        "confirmation, validate all arguments, and restrict the WebView to "
        "trusted origins."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/JavascriptInterface",
    ]

    _ANNO_RX = re.compile(r"@JavascriptInterface\b")
    _METHOD_RX = re.compile(
        r"@JavascriptInterface\s*(?:@[^\n]*\s*)*"
        r"(?:public|private|protected)?\s*[\w<>\[\].,\s]+\s+(\w+)\s*\([^)]*\)\s*\{"
    )
    _SINK_RX = re.compile(
        r"\.exec\s*\(|FileOutputStream|openFileOutput\s*\(|getSharedPreferences\s*\("
        r"|\.rawQuery\s*\(|\.execSQL\s*\(|sendTextMessage\s*\("
        r"|HttpURLConnection|loadUrl\s*\("
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def _method_body(self, text: str, brace_open: int) -> str | None:
        depth = 0
        for i in range(brace_open, len(text)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[brace_open:i + 1]
        return None

    def check(self, ctx: ScanContext) -> RuleResult:
        by_file = _files_with_hits(ctx, r"@JavascriptInterface\b")
        if not by_file:
            return pass_result(self, "No @JavascriptInterface methods found.")
        evidence: list[Evidence] = []
        for path, hits in by_file.items():
            text = _read(path)
            if not text:
                continue
            for m in self._METHOD_RX.finditer(text):
                name = m.group(1)
                brace_open = m.end() - 1
                body = self._method_body(text, brace_open)
                if body is None:
                    continue
                sink = self._SINK_RX.search(body)
                if sink:
                    anno_line = text.count("\n", 0, m.start()) + 1
                    evidence.append(evidence_simple(
                        ctx, path,
                        f"@JavascriptInterface method '{name}' calls sensitive "
                        f"sink '{sink.group(0).strip()}'",
                        snippet=body[:1200],
                        line_start=anno_line,
                        line_end=anno_line))
        if not evidence:
            return pass_result(
                self, "@JavascriptInterface methods found but none reach a sensitive sink.")
        return finding(
            self,
            f"@JavascriptInterface method(s) directly reach sensitive sink(s) "
            f"({len(evidence)} method(s)).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "HIGH: a bridge method that itself executes commands, writes "
                "files, queries databases or sends SMS gives web content "
                "direct native capability."),
            confidence_rationale=(
                "MEDIUM: the annotation, the method body and the sink call are "
                "all real and scoped to the same method, but it is not proven "
                "that the WebView loads attacker-reachable content; "
                "exploitability not confirmed."),
        )


# ---------------------------------------------------------------------------
# BS-W16
# ---------------------------------------------------------------------------

class WebViewAllowFileAccessRule(Rule):
    id = "BS-W16"
    title = "WebView file access toggles enabled"
    description = (
        "Detects WebSettings.setAllowFileAccess(true) and "
        "setAllowFileAccessFromFileURLs(true). Complements BS-W03 with a "
        "dedicated finding for the two file-access toggles (universal access "
        "is covered separately by BS-W17)."
    )
    rationale = (
        "File-scheme access lets WebView pages read local files. Allowing "
        "file:// pages to load other file:// resources additionally enables "
        "cross-file data theft when combined with script execution."
    )
    category = "webview"
    default_severity = Severity.HIGH
    owasp = ["M8"]
    cwe = ["CWE-693"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Keep setAllowFileAccess(false) unless the WebView must read local "
        "files. Never enable setAllowFileAccessFromFileURLs; serve local "
        "content over https with WebViewAssetLoader instead."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccess(boolean)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r"setAllowFileAccess\s*\(\s*true\s*\)"
            r"|setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)",
            iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No WebView file-access toggles enabled.")
        return finding(
            self,
            f"WebView file access enabled ({len(hits)} call site(s)).",
            evidence=[evidence_from_hit(
                ctx, h, "WebView file-access toggle enabled") for h in hits],
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "HIGH: file:// access lets WebView content reach the local "
                "file system; file-URL-to-file-URL access further enables "
                "theft of local files by loaded pages."),
            confidence_rationale=(
                "HIGH: the enabling calls are explicit and unambiguous."),
        )


# ---------------------------------------------------------------------------
# BS-W17
# ---------------------------------------------------------------------------

class WebViewUniversalFileAccessRule(Rule):
    id = "BS-W17"
    title = "WebView universal access from file URLs enabled"
    description = (
        "Detects "
        "WebSettings.setAllowUniversalAccessFromFileURLs(true), which lets "
        "file:// pages access content from any origin."
    )
    rationale = (
        "Universal access from file URLs breaks the same-origin policy for "
        "file:// content: a local page can read arbitrary files and send "
        "them to a remote server."
    )
    category = "webview"
    default_severity = Severity.HIGH
    owasp = ["M8"]
    cwe = ["CWE-693"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Never enable setAllowUniversalAccessFromFileURLs. Serve local "
        "content over https with WebViewAssetLoader and keep the default "
        "same-origin enforcement."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs(boolean)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)",
            iter_source_files(ctx))
        if not hits:
            return pass_result(
                self, "No setAllowUniversalAccessFromFileURLs(true) calls found.")
        return finding(
            self,
            f"WebView allows file:// pages to access any origin "
            f"({len(hits)} call site(s)).",
            evidence=[evidence_from_hit(
                ctx, h, "Universal access from file:// URLs enabled")
                for h in hits],
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "HIGH: this disables same-origin checks for file:// pages, "
                "allowing a local page to exfiltrate arbitrary local files."),
            confidence_rationale=(
                "HIGH: the enabling call is explicit and unambiguous."),
        )


# ---------------------------------------------------------------------------
# BS-W18
# ---------------------------------------------------------------------------

class WebViewMixedContentExplicitRule(Rule):
    id = "BS-W18"
    title = "WebView mixed-content policy explicitly relaxed"
    description = (
        "Detects an explicit mixed-content policy of MIXED_CONTENT_ALWAYS_ALLOW "
        "(or the raw constant 0) on WebSettings. Complements BS-W06 with a "
        "dedicated policy finding."
    )
    rationale = (
        "An explicit ALWAYS_ALLOW policy is a deliberate weakening of "
        "transport security: https pages may pull scripts and frames over "
        "cleartext http, which a network attacker can modify."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Remove the explicit call and rely on the default "
        "MIXED_CONTENT_NEVER_ALLOW, or at minimum use "
        "MIXED_CONTENT_COMPATIBILITY_MODE. Fix the underlying http "
        "subresources instead of relaxing the policy."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebSettings#MIXED_CONTENT_ALWAYS_ALLOW",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r"setMixedContentMode\s*\(\s*(?:[A-Za-z_][\w.]*\.)?MIXED_CONTENT_ALWAYS_ALLOW\s*\)"
            r"|setMixedContentMode\s*\(\s*0\s*\)",
            iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No explicit mixed-content relaxation found.")
        return finding(
            self,
            f"WebView mixed-content policy explicitly set to ALWAYS_ALLOW "
            f"({len(hits)} call site(s)).",
            evidence=[evidence_from_hit(
                ctx, h, "Mixed-content policy explicitly relaxed") for h in hits],
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: cleartext subresources on an https page can be "
                "intercepted and modified, undermining page integrity."),
            confidence_rationale=(
                "HIGH: the ALWAYS_ALLOW constant is passed explicitly."),
        )


# ---------------------------------------------------------------------------
# BS-W19
# ---------------------------------------------------------------------------

class WebViewDomStorageSensitiveRule(Rule):
    id = "BS-W19"
    title = "WebView DOM storage enabled near sensitive data"
    description = (
        "Detects setDomStorageEnabled(true) where sensitive keywords "
        "(password, token, secret, auth, credential, session, api_key) appear "
        "within 10 lines, suggesting web content may persist secrets in DOM "
        "storage."
    )
    rationale = (
        "DOM storage persists across sessions in the app's data directory. "
        "When pages handled by the WebView deal with credentials or tokens, "
        "those values may end up in localStorage/sessionStorage where other "
        "vulnerabilities (backup, file access) can expose them."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-312"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Enable DOM storage only if the WebView content needs it. Avoid "
        "storing credentials or tokens in web storage; keep them in "
        "EncryptedSharedPreferences or the Android Keystore, and clear web "
        "storage on logout."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebSettings#setDomStorageEnabled(boolean)",
    ]

    _KEYWORD_RX = re.compile(
        r"password|passwd|pwd|token|secret|api[_-]?key|auth|credential|session",
        re.IGNORECASE)

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"setDomStorageEnabled\s*\(\s*true\s*\)", iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No setDomStorageEnabled(true) calls found.")
        flagged: list[Evidence] = []
        for hit in hits:
            text = _read(hit.path)
            if not text:
                continue
            lines = text.splitlines()
            lo = max(0, hit.line_no - 1 - 10)
            hi = min(len(lines), hit.line_no + 10)
            window = "\n".join(lines[lo:hi])
            kw = self._KEYWORD_RX.search(window)
            if kw:
                flagged.append(evidence_from_hit(
                    ctx, hit,
                    f"DOM storage enabled with sensitive keyword "
                    f"'{kw.group(0)}' nearby"))
        if not flagged:
            return pass_result(
                self,
                "DOM storage is enabled but no sensitive keywords were found "
                "nearby (see BS-W14 for the informational record).")
        return finding(
            self,
            f"WebView DOM storage enabled near sensitive data "
            f"({len(flagged)} call site(s)).",
            evidence=flagged,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "MEDIUM: secrets handled around a DOM-storage-enabled WebView "
                "may be persisted in web storage, where backup or file-access "
                "issues can expose them."),
            confidence_rationale=(
                "MEDIUM: the enabling call and the sensitive keyword are both "
                "real and close together, but it is not proven that the secret "
                "actually reaches web storage."),
        )


# ---------------------------------------------------------------------------
# BS-W20
# ---------------------------------------------------------------------------

class WebViewGeolocationNoPermissionCheckRule(Rule):
    id = "BS-W20"
    title = "WebView geolocation enabled without a permission check nearby"
    description = (
        "Detects setGeolocationEnabled(true) where no location-permission "
        "check (checkSelfPermission / requestPermissions / ACCESS_FINE_LOCATION) "
        "appears within 15 lines."
    )
    rationale = (
        "Enabling WebView geolocation without verifying the location "
        "permission suggests the permission flow is missing or handled "
        "elsewhere; pages could then request location the app never "
        "properly authorized."
    )
    category = "webview"
    default_severity = Severity.LOW
    owasp = ["M9"]
    cwe = ["CWE-276"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Request ACCESS_FINE_LOCATION / ACCESS_COARSE_LOCATION at runtime "
        "with checkSelfPermission before enabling WebView geolocation, and "
        "implement onGeolocationPermissionsShowPrompt to gate per-origin "
        "access behind user consent."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebSettings#setGeolocationEnabled(boolean)",
    ]

    _PERM_RX = re.compile(
        r"checkSelfPermission|requestPermissions|ACCESS_FINE_LOCATION|"
        r"ACCESS_COARSE_LOCATION|onGeolocationPermissionsShowPrompt")

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"setGeolocationEnabled\s*\(\s*true\s*\)", iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No setGeolocationEnabled(true) calls found.")
        flagged: list[Evidence] = []
        for hit in hits:
            text = _read(hit.path)
            if not text:
                continue
            lines = text.splitlines()
            lo = max(0, hit.line_no - 1 - 15)
            hi = min(len(lines), hit.line_no + 15)
            window = "\n".join(lines[lo:hi])
            if not self._PERM_RX.search(window):
                flagged.append(evidence_from_hit(
                    ctx, hit,
                    "Geolocation enabled with no location-permission check nearby"))
        if not flagged:
            return pass_result(
                self,
                "Geolocation is enabled but a permission check was found nearby.")
        return finding(
            self,
            f"WebView geolocation enabled without a nearby permission check "
            f"({len(flagged)} call site(s)).",
            evidence=flagged,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "LOW: missing permission gating is usually a correctness and "
                "privacy-hygiene issue; pages could prompt for location the "
                "app did not deliberately authorize."),
            confidence_rationale=(
                "MEDIUM: the enabling call is real and no permission check "
                "appears nearby, but the check could live in another method "
                "or file."),
        )


# ---------------------------------------------------------------------------
# BS-W21
# ---------------------------------------------------------------------------

class JavascriptInterfaceWithHttpUrlRule(Rule):
    id = "BS-W21"
    title = "JS bridge exposed in a file that loads cleartext HTTP URLs"
    description = (
        "Flags files that both register an addJavascriptInterface bridge and "
        "load a cleartext http:// URL into a WebView: the worst combination "
        "of bridge exposure and network attackability."
    )
    rationale = (
        "A JS bridge is most dangerous when the WebView loads "
        "network-attacker-controlled content. Cleartext HTTP pages can be "
        "modified on-path, so a bridge reachable from them is directly "
        "exploitable by a network attacker."
    )
    category = "webview"
    default_severity = Severity.HIGH
    owasp = ["M5", "M8"]
    cwe = ["CWE-749"]
    masvs = ["MSTG-PLATFORM", "MSTG-NETWORK"]
    remediation = (
        "Load only https:// URLs in any WebView that exposes a JS bridge, "
        "validate navigation in shouldOverrideUrlLoading, and minimize the "
        "bridge surface to annotated methods with no sensitive operations."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        by_file = _files_with_hits(ctx, r"addJavascriptInterface\s*\(")
        if not by_file:
            return pass_result(self, "No addJavascriptInterface() calls found.")
        evidence: list[Evidence] = []
        for path, hits in by_file.items():
            text = _read(path)
            if not text:
                continue
            http_load = re.search(
                r"\.load(?:Url|DataWithBaseURL)\s*\([^)]*\"http://", text)
            if not http_load:
                continue
            for hit in hits:
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    "addJavascriptInterface bridge in a file that loads a "
                    "cleartext http:// URL into a WebView"))
        if not evidence:
            return pass_result(
                self,
                "JS bridges found, but no file loads cleartext http:// URLs.")
        return finding(
            self,
            f"JS bridge exposed where the WebView loads cleartext HTTP "
            f"({len(evidence)} call site(s)).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "HIGH: a network attacker can modify cleartext pages and "
                "drive the exposed JS bridge, turning a passive MITM into "
                "native code execution paths."),
            confidence_rationale=(
                "MEDIUM: the bridge and the http:// load are both real and in "
                "the same file, but it is not proven that the bridged page "
                "is the cleartext one or that the bridge reaches sensitive "
                "operations."),
        )


# ---------------------------------------------------------------------------
# BS-W22
# ---------------------------------------------------------------------------

class LoadUrlIntentExtraRule(Rule):
    id = "BS-W22"
    title = "loadUrl with an intent extra passed inline"
    description = (
        "Detects loadUrl() calls that pass getStringExtra() (or another "
        "intent getter) directly as the URL argument. External apps can send "
        "such intents, so the destination may be attacker-controlled."
    )
    rationale = (
        "An intent extra used verbatim as a WebView URL lets any app that "
        "can fire the intent steer the WebView to javascript:, file:// or "
        "phishing destinations."
    )
    category = "webview"
    default_severity = Severity.HIGH
    owasp = ["M4"]
    cwe = ["CWE-940"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Never pass raw intent extras into loadUrl. Validate the URL against "
        "an allow-list of schemes and hosts, and reject javascript:, file: "
        "and intent: schemes unless explicitly required."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebView#loadUrl(java.lang.String)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r"\.loadUrl\s*\([^)]*get(?:StringExtra|Extras|Intent|Data)\s*\(",
            iter_source_files(ctx))
        if not hits:
            return pass_result(
                self, "No loadUrl() calls with inline intent extras found.")
        return needs_review(
            self,
            f"loadUrl() receives an intent extra directly "
            f"({len(hits)} call site(s)); verify the destination is validated.",
            evidence=[evidence_from_hit(
                ctx, h, "Intent extra passed directly into loadUrl()")
                for h in hits],
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            severity_rationale=(
                "HIGH: if the extra is attacker-controlled, this is an open "
                "redirect into WebView with javascript:/file: scheme risk."),
            confidence_rationale=(
                "LOW: the intent getter inside loadUrl() is directly observed, "
                "but whether external apps can reach this intent and whether "
                "any validation happens was not established; manual review "
                "required."),
        )


# ---------------------------------------------------------------------------
# BS-W23
# ---------------------------------------------------------------------------

class FileUrlLoadRule(Rule):
    id = "BS-W23"
    title = "file:// URL passed to WebView.loadUrl"
    description = (
        "Detects loadUrl() calls with a file:// URL literal. Combined with "
        "JavaScript or file-access settings, local files become readable by "
        "web content."
    )
    rationale = (
        "Loading file:// URLs places local files in the WebView origin. "
        "With JavaScript enabled or file-access toggles on, scripts can read "
        "those files and exfiltrate them."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-693"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Avoid file:// URLs in WebViews. Serve local content over https "
        "with WebViewAssetLoader, disable JavaScript where possible, and "
        "keep file-access toggles off."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebView#loadUrl(java.lang.String)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"\.loadUrl\s*\(\s*\"file://", iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No file:// URLs passed to loadUrl().")
        return finding(
            self,
            f"WebView loads file:// URLs ({len(hits)} call site(s)).",
            evidence=[evidence_from_hit(
                ctx, h, "file:// URL passed to loadUrl()") for h in hits],
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: local files enter the WebView origin; exploitability "
                "depends on JavaScript and file-access settings, which should "
                "be reviewed alongside."),
            confidence_rationale=(
                "HIGH: the file:// URL literal is directly in the loadUrl() call."),
        )


# ---------------------------------------------------------------------------
# BS-W24
# ---------------------------------------------------------------------------

class ExportedActivityWebViewRule(Rule):
    id = "BS-W24"
    title = "JavaScript-enabled WebView in an exported activity"
    description = (
        "Combines manifest and code analysis: flags the app when an "
        "exported activity exists (android:exported=\"true\", from the parsed "
        "manifest activities list or a raw_xml fallback) and decompiled "
        "sources enable WebView JavaScript. External apps can then reach the "
        "WebView."
    )
    rationale = (
        "An exported activity hosting a JavaScript-enabled WebView is "
        "reachable by any app on the device. A malicious app can fire an "
        "intent at it and, if the URL is influenced, drive the WebView to "
        "attacker content with script execution."
    )
    category = "webview"
    default_severity = Severity.HIGH
    owasp = ["M8"]
    cwe = ["CWE-749"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Set android:exported=\"false\" on activities hosting WebViews "
        "unless external access is genuinely required. If export is needed, "
        "never derive the loaded URL from the incoming intent without "
        "allow-list validation, and keep JavaScript disabled when possible."
    )
    references = [
        "https://developer.android.com/guide/topics/manifest/activity-element#exported",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.manifest is not None and bool(ctx.java_roots)

    def _raw_xml_exported_lines(self, raw_xml: str) -> dict[str, int]:
        """Map activity android:name -> manifest line for exported activities."""
        out: dict[str, int] = {}
        lines = raw_xml.splitlines()
        i = 0
        while i < len(lines):
            if "<activity" in lines[i]:
                start = i
                block: list[str] = []
                while i < len(lines) and ">" not in lines[i]:
                    block.append(lines[i])
                    i += 1
                if i < len(lines):
                    block.append(lines[i])
                blob = "\n".join(block)
                if 'android:exported="true"' in blob:
                    nm = re.search(r'android:name="([^"]+)"', blob)
                    out[nm.group(1) if nm else "(unnamed)"] = start + 1
            i += 1
        return out

    def _exported_activities(self, ctx: ScanContext) -> list[tuple[str, int | None]]:
        """Return (activity name, manifest line or None) for exported activities."""
        m = ctx.manifest
        assert m is not None
        line_by_name = self._raw_xml_exported_lines(m.raw_xml) if m.raw_xml else {}
        out: list[tuple[str, int | None]] = []
        for comp in m.activities:
            if comp.kind == "activity" and comp.exported:
                line = line_by_name.get(comp.name)
                if line is None:
                    # simple-name matching (".Main" vs "com.example.Main")
                    simple = comp.name.rsplit(".", 1)[-1]
                    for nm, ln in line_by_name.items():
                        if nm.rsplit(".", 1)[-1] == simple:
                            line = ln
                            break
                out.append((comp.name, line))
        if out:
            return out
        return [(nm, ln) for nm, ln in line_by_name.items()]

    def check(self, ctx: ScanContext) -> RuleResult:
        exported = self._exported_activities(ctx)
        if not exported:
            return pass_result(self, "No exported activities declared in the manifest.")
        js_hits = grep(r"setJavaScriptEnabled\s*\(\s*true\s*\)", iter_source_files(ctx))
        if not js_hits:
            return pass_result(
                self, "Exported activities exist but no WebView JavaScript is enabled.")
        evidence: list[Evidence] = []
        mpath = ctx.manifest_xml_path or "AndroidManifest.xml"
        for name, line in exported:
            snippet = ""
            if line and ctx.manifest and ctx.manifest.raw_xml:
                raw_lines = ctx.manifest.raw_xml.splitlines()
                if 1 <= line <= len(raw_lines):
                    snippet = raw_lines[line - 1].strip()
            evidence.append(evidence_simple(
                ctx, mpath,
                f"Exported activity '{name}' declared in manifest",
                snippet=snippet or f'android:exported="true" on {name}',
                line_start=line, line_end=line))
        evidence += [evidence_from_hit(
            ctx, h, "WebView JavaScript enabled") for h in js_hits[:10]]
        names = ", ".join(n for n, _ in exported[:5])
        return finding(
            self,
            f"Exported activit(ies) ({names}) combined with JavaScript-enabled "
            f"WebView(s); external apps can reach script-capable WebViews.",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "HIGH: any on-device app can launch the exported activity; if "
                "the WebView URL derives from the intent, this becomes "
                "remote script execution in the app's context."),
            confidence_rationale=(
                "MEDIUM: the exported activity and the JavaScript toggle are "
                "both real, but it is not proven that the WebView lives in "
                "the exported activity or that its URL is intent-influenced."),
        )


# ---------------------------------------------------------------------------
# BS-W25
# ---------------------------------------------------------------------------

class HttpUrlLoadRule(Rule):
    id = "BS-W25"
    title = "Cleartext http:// URL passed to WebView loading APIs"
    description = (
        "Detects loadUrl() and loadDataWithBaseURL() calls with an http:// "
        "URL literal. Narrower than BS-W04: this rule fires only on literal "
        "cleartext URLs, not on dynamically built ones."
    )
    rationale = (
        "Cleartext HTTP pages in a WebView can be intercepted and modified "
        "on-path, exposing page content and any credentials entered."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M4"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Load only https:// URLs in WebViews and fix the underlying http "
        "endpoints instead of accepting cleartext."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebView#loadUrl(java.lang.String)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r"\.load(?:Url|DataWithBaseURL)\s*\([^)]{0,200}\"http://",
            iter_source_files(ctx))
        if not hits:
            return pass_result(
                self, "No http:// literals passed to WebView loading APIs.")
        return finding(
            self,
            f"WebView loads cleartext http:// URLs ({len(hits)} call site(s)).",
            evidence=[evidence_from_hit(
                ctx, h, "Cleartext http:// URL passed to WebView") for h in hits],
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "MEDIUM: cleartext page loads allow network interception and "
                "modification of content and credentials."),
            confidence_rationale=(
                "HIGH: the http:// URL is a literal inside the loading call."),
        )


# ---------------------------------------------------------------------------
# BS-W26
# ---------------------------------------------------------------------------

class WebViewSavePasswordRule(Rule):
    id = "BS-W26"
    title = "WebView credential saving enabled (setSavePassword)"
    description = (
        "Detects WebSettings.setSavePassword(true). The API is deprecated "
        "and stores web-form credentials in plaintext app storage."
    )
    rationale = (
        "setSavePassword(true) asks the WebView to remember usernames and "
        "passwords in plaintext. Besides being deprecated, it keeps "
        "credentials where backup or file-access issues can expose them."
    )
    category = "webview"
    default_severity = Severity.LOW
    owasp = ["M9"]
    cwe = ["CWE-312"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Remove setSavePassword(true) calls. Rely on the platform autofill "
        "framework or the app's own encrypted credential storage instead."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebSettings#setSavePassword(boolean)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"setSavePassword\s*\(\s*true\s*\)", iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No setSavePassword(true) calls found.")
        return finding(
            self,
            f"WebView credential saving enabled ({len(hits)} call site(s)).",
            evidence=[evidence_from_hit(
                ctx, h, "setSavePassword(true): deprecated plaintext credential "
                "saving") for h in hits],
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "LOW: the API is deprecated and stores credentials in "
                "plaintext, but exploitation requires access to app-private "
                "storage or backups."),
            confidence_rationale=(
                "HIGH: the enabling call is explicit and unambiguous."),
        )


# ---------------------------------------------------------------------------
# BS-W27
# ---------------------------------------------------------------------------

class WebViewThirdPartyCookiesRule(Rule):
    id = "BS-W27"
    title = "WebView third-party cookies accepted"
    description = (
        "Detects CookieManager.setAcceptThirdPartyCookies(webView, true), "
        "which lets cross-site content set cookies in the WebView."
    )
    rationale = (
        "Third-party cookies enable cross-site tracking inside the WebView "
        "and widen the impact of cookie-based session handling flaws."
    )
    category = "webview"
    default_severity = Severity.LOW
    owasp = ["M9"]
    cwe = []
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Keep third-party cookies disabled (the default). Enable them only "
        "for specific trusted flows and document why."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/CookieManager#setAcceptThirdPartyCookies(android.webkit.WebView,%20boolean)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r"setAcceptThirdPartyCookies\s*\([^,]+,\s*true\s*\)",
            iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No setAcceptThirdPartyCookies(true) calls found.")
        return finding(
            self,
            f"WebView accepts third-party cookies ({len(hits)} call site(s)).",
            evidence=[evidence_from_hit(
                ctx, h, "setAcceptThirdPartyCookies(..., true)") for h in hits],
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "LOW: third-party cookies are mainly a tracking and session-"
                "hygiene concern rather than a direct exploit primitive."),
            confidence_rationale=(
                "HIGH: the enabling call is explicit and unambiguous."),
        )


# ---------------------------------------------------------------------------
# BS-W28
# ---------------------------------------------------------------------------

class WebViewClientSslErrorProceedRule(Rule):
    id = "BS-W28"
    title = "WebViewClient.onReceivedSslError calls handler.proceed()"
    description = (
        "Detects a WebViewClient.onReceivedSslError() override that calls "
        "handler.proceed(), continuing page loads despite TLS certificate "
        "errors. WebView-focused counterpart to BS-N05."
    )
    rationale = (
        "Proceeding past SSL errors lets attackers intercept WebView traffic "
        "with invalid certificates, exposing credentials and session data "
        "entered in the page."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M5"]
    cwe = ["CWE-295"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Call handler.cancel() (or the super implementation) on certificate "
        "errors and show the user a meaningful error instead of proceeding."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"onReceivedSslError", iter_source_files(ctx), max_hits=100)
        evidence: list[Evidence] = []
        for hit in hits:
            text = read_text_capped(hit.path)
            if text is None:
                continue
            lines = text.splitlines()
            method_text = "\n".join(lines[hit.line_no - 1: hit.line_no + 25])
            if re.search(r"\.\s*proceed\s*\(\s*\)", method_text):
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    "onReceivedSslError() calls handler.proceed()"))
        if not evidence:
            return pass_result(self, "No WebView SSL-error bypass found.")
        return finding(
            self,
            f"{len(evidence)} WebViewClient(s) ignore TLS certificate errors.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "MEDIUM: ignoring certificate errors exposes WebView traffic "
                "to interception; severity is one step below the network-"
                "stack equivalent because it is scoped to WebView pages."),
            confidence_rationale=(
                "MEDIUM: handler.proceed() was confirmed inside "
                "onReceivedSslError, but it is not proven which pages the "
                "affected WebView loads."),
        )


# ---------------------------------------------------------------------------
# BS-W29
# ---------------------------------------------------------------------------

class WebViewDatabaseEnabledRule(Rule):
    id = "BS-W29"
    title = "WebView database API enabled"
    description = (
        "Detects WebSettings.setDatabaseEnabled(true), which enables the "
        "Web SQL database API for web content. Dedicated finding split out "
        "from the informational BS-W14."
    )
    rationale = (
        "The Web SQL database lets pages persist structured data on the "
        "device. If pages store sensitive data, backup or file-access issues "
        "can expose it."
    )
    category = "webview"
    default_severity = Severity.LOW
    owasp = ["M9"]
    cwe = []
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Enable the database API only if WebView content needs it, audit "
        "what pages store, and clear web storage on logout when it may hold "
        "sensitive data."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebSettings#setDatabaseEnabled(boolean)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"setDatabaseEnabled\s*\(\s*true\s*\)", iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No setDatabaseEnabled(true) calls found.")
        return finding(
            self,
            f"WebView database API enabled ({len(hits)} call site(s)).",
            evidence=[evidence_from_hit(
                ctx, h, "setDatabaseEnabled(true)") for h in hits],
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "LOW: the database API is a legitimate feature; risk is "
                "contextual to what pages store."),
            confidence_rationale=(
                "MEDIUM: the enabling call is explicit, but whether any page "
                "actually persists sensitive data is not established."),
        )


# ---------------------------------------------------------------------------
# BS-W30
# ---------------------------------------------------------------------------

class UnannotatedBridgeSinkRule(Rule):
    id = "BS-W30"
    title = "Unannotated JS-bridge method reaches a sensitive sink"
    description = (
        "Finds classes registered via addJavascriptInterface and flags "
        "public methods that reach a sensitive sink (process exec, file "
        "write, SQL, SMS, network, loadUrl) but lack the "
        "@JavascriptInterface annotation. On API 17+ only annotated methods "
        "are exposed, so this usually indicates dead code or a "
        "forgotten annotation - either way it deserves review."
    )
    rationale = (
        "A sensitive operation inside a bridge class that a developer "
        "intended to expose (but forgot to annotate), or that becomes "
        "exposed on older platforms, gives web content a direct path to "
        "native capabilities."
    )
    category = "webview"
    default_severity = Severity.MEDIUM
    owasp = ["M8"]
    cwe = ["CWE-749"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Annotate only the bridge methods that must be exposed, keep "
        "sensitive operations out of bridge classes entirely, and validate "
        "all bridge arguments."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/JavascriptInterface",
    ]

    _SINK_RX = re.compile(
        r"\.exec\s*\(|FileOutputStream|openFileOutput\s*\(|getSharedPreferences\s*\("
        r"|\.rawQuery\s*\(|\.execSQL\s*\(|sendTextMessage\s*\("
        r"|HttpURLConnection|loadUrl\s*\("
    )
    _METHOD_RX = re.compile(
        r"(public|protected)\s+[\w<>\[\].,\s]+\s+(\w+)\s*\([^)]*\)\s*\{"
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def _method_body(self, text: str, brace_open: int) -> str | None:
        depth = 0
        for i in range(brace_open, len(text)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[brace_open:i + 1]
        return None

    def check(self, ctx: ScanContext) -> RuleResult:
        by_file = _files_with_hits(ctx, r"addJavascriptInterface\s*\(")
        if not by_file:
            return pass_result(self, "No addJavascriptInterface() calls found.")
        evidence: list[Evidence] = []
        for path, hits in by_file.items():
            for hit in hits:
                cls = _class_of_bridge_arg(
                    _arg_after_call(hit.line, r"addJavascriptInterface\s*\("))
                if not cls:
                    continue
                class_text = _find_class_text(ctx, cls)
                if not class_text:
                    continue
                for m in self._METHOD_RX.finditer(class_text):
                    name = m.group(2)
                    # skip annotated methods (BS-W15 territory); accept both
                    # short and fully-qualified annotation spellings
                    before = class_text[max(0, m.start() - 120):m.start()]
                    if "JavascriptInterface" in before:
                        continue
                    body = self._method_body(class_text, m.end() - 1)
                    if body and self._SINK_RX.search(body):
                        anno_line = class_text.count("\n", 0, m.start()) + 1
                        evidence.append(evidence_simple(
                            ctx, path,
                            f"Bridge class '{cls}' has unannotated method "
                            f"'{name}' reaching a sensitive sink",
                            snippet=body[:1200],
                            line_start=anno_line,
                            line_end=anno_line))
                        break  # one finding per bridge class is enough
        if not evidence:
            return pass_result(
                self,
                "No unannotated bridge methods reaching sensitive sinks found.")
        return needs_review(
            self,
            f"{len(evidence)} bridge class(es) contain unannotated method(s) "
            f"reaching sensitive sinks.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "MEDIUM: a sensitive sink inside a bridge class is one "
                "annotation (or one old platform) away from web reachability."),
            confidence_rationale=(
                "LOW: the method, the missing annotation and the sink are "
                "real, but whether the method was meant to be exposed and "
                "whether the WebView loads untrusted content are not proven; "
                "manual review required."),
        )

# ---------------------------------------------------------------------------
# Module rule list
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    WebViewJavaScriptEnabledRule(),
    JavascriptInterfaceExposureRule(),
    WebViewFileAccessRule(),
    WebViewInsecureUrlLoadingRule(),
    WebViewMissingUrlOverrideRule(),
    WebViewMixedContentRule(),
    EvaluateJavascriptConcatRule(),
    SqlInjectionRule(),
    CommandInjectionRule(),
    PathTraversalRule(),
    UnsafeDeserializationRule(),
    DynamicCodeLoadingRule(),
    ReflectionSensitiveApiRule(),
    WebViewStorageEnabledRule(),
    JavascriptInterfaceSinkRule(),
    WebViewAllowFileAccessRule(),
    WebViewUniversalFileAccessRule(),
    WebViewMixedContentExplicitRule(),
    WebViewDomStorageSensitiveRule(),
    WebViewGeolocationNoPermissionCheckRule(),
    JavascriptInterfaceWithHttpUrlRule(),
    LoadUrlIntentExtraRule(),
    FileUrlLoadRule(),
    ExportedActivityWebViewRule(),
    HttpUrlLoadRule(),
    WebViewSavePasswordRule(),
    WebViewThirdPartyCookiesRule(),
    WebViewClientSslErrorProceedRule(),
    WebViewDatabaseEnabledRule(),
    UnannotatedBridgeSinkRule(),
]

__all__ = ["RULES"]
