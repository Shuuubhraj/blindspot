"""WebView, input validation and injection detection rules (BS-W01 .. BS-W15).

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
]

__all__ = ["RULES"]
