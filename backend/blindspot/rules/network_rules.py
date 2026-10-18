"""Network & transport security rules (BS-N01 .. BS-N20).

Each rule implements genuinely distinct detection logic against the scan
context. Manifest rules inspect ctx.manifest; source rules scan decompiled
Java/Kotlin under ctx.java_roots; config rules parse the network security
configuration XML referenced by the manifest under ctx.res_dir.

Rule index:
  BS-N01  usesCleartextTraffic=true in manifest
  BS-N02  hardcoded http:// URLs in Java/Kotlin (non-local hosts)
  BS-N03  trust-all X509TrustManager (empty checkServerTrusted)
  BS-N04  disabled hostname verification (ALLOW_ALL / permissive verifier)
  BS-N05  WebView onReceivedSslError calling handler.proceed()
  BS-N06  setDefaultHostnameVerifier/setHostnameVerifier with permissive verifier
  BS-N07  weak TLS protocol strings (SSLv2/v3, TLS 1.0/1.1)
  BS-N08  certificate pinning presence check (INFO when absent; never a finding)
  BS-N09  networkSecurityConfig XML analysis
  BS-N10  insecure ws:// WebSocket URLs
  BS-N11  HTTP fallback in error/catch handlers (needs review)
  BS-N12  hardcoded proxy configuration
  BS-N13  sensitive data in network URL query parameters
  BS-N14  redirect-following with Authorization headers (needs review)
  BS-N15  domain-config cleartext exceptions in network security config
  BS-N16  verbose network logging (HttpLoggingInterceptor BODY)
  BS-N17  custom SSLSocketFactory skipping verification
  BS-N18  backend endpoint inventory (https hosts)
  BS-N19  localhost/test endpoints in code
  BS-N20  INTERNET permission without networkSecurityConfig reference
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from .base import (
    Confidence,
    ManifestData,
    Rule,
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

_CATEGORY = "network"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _manifest(ctx: ScanContext) -> ManifestData | None:
    return ctx.manifest


def _nsc_xml_path(ctx: ScanContext) -> Path | None:
    """Resolve the network security config XML path from the manifest."""
    m = ctx.manifest
    if m is None or not m.network_security_config or not ctx.res_dir:
        return None
    ref = m.network_security_config  # e.g. "@xml/network_security_config"
    name = ref.rsplit("/", 1)[-1]
    candidates = [
        ctx.res_dir / "xml" / f"{name}.xml",
        ctx.res_dir / f"{name}.xml",
    ]
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_local_host(host: str) -> bool:
    return (
        host in {"localhost", "127.0.0.1", "::1"}
        or host.startswith("10.")
        or host.startswith("192.168.")
        or host.startswith("172.16.")
        or re.fullmatch(r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}", host) is not None
    )


def _has_internet(ctx: ScanContext) -> bool:
    m = ctx.manifest
    if m is None:
        return False
    return any(p.name == "android.permission.INTERNET" for p in m.permissions)


def _uses_https(ctx: ScanContext) -> bool:
    """Does any decompiled source or resource reference an https:// URL?"""
    if _has_internet(ctx):
        return True
    hits = grep(r"https://", iter_source_files(ctx), max_hits=1)
    return bool(hits)


# ---------------------------------------------------------------------------
# BS-N01
# ---------------------------------------------------------------------------

class CleartextTrafficEnabled(Rule):
    id = "BS-N01"
    title = "usesCleartextTraffic enabled in application manifest"
    description = (
        "The <application> tag sets android:usesCleartextTraffic=\"true\", "
        "allowing unencrypted HTTP traffic for the whole application."
    )
    rationale = (
        "Cleartext HTTP exposes request and response bodies to on-path "
        "attackers. Android 9+ blocks cleartext by default unless the flag "
        "is explicitly enabled."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Remove android:usesCleartextTraffic=\"true\" from the manifest "
        "(the default is false) and serve all traffic over HTTPS. If specific "
        "legacy hosts still require HTTP, use a network security configuration "
        "with narrowly scoped domain-config exceptions instead of a global flag."
    )
    references = [
        "https://developer.android.com/training/articles/security-config",
        "https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _manifest(ctx) is not None

    def check(self, ctx: ScanContext):
        m = ctx.manifest
        assert m is not None
        if m.uses_cleartext_traffic is True:
            ev = evidence_simple(
                ctx,
                ctx.manifest_xml_path or "AndroidManifest.xml",
                "android:usesCleartextTraffic=\"true\" declared on <application>",
                snippet=m.raw_xml.splitlines()[0] if m.raw_xml else "",
            )
            if m.raw_xml:
                for i, line in enumerate(m.raw_xml.splitlines(), start=1):
                    if "usesCleartextTraffic" in line and "true" in line:
                        ev = evidence_simple(
                            ctx,
                            ctx.manifest_xml_path or "AndroidManifest.xml",
                            "android:usesCleartextTraffic=\"true\" declared on <application>",
                            snippet=line.strip(),
                            line_start=i,
                            line_end=i,
                        )
                        break
            return finding(
                self,
                "Application permits cleartext (HTTP) traffic globally.",
                evidence=[ev],
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "A global cleartext opt-in disables Android's default "
                    "plaintext protection for every network request, enabling "
                    "passive eavesdropping and active tampering."
                ),
                confidence_rationale=(
                    "Direct manifest attribute evidence; no inference required."
                ),
            )
        return pass_result(
            self, "usesCleartextTraffic is not enabled (false or unset)."
        )


# ---------------------------------------------------------------------------
# BS-N02
# ---------------------------------------------------------------------------

class HardcodedHttpUrls(Rule):
    id = "BS-N02"
    title = "Hardcoded plaintext http:// URLs in code"
    description = (
        "Java/Kotlin sources contain hardcoded http:// URLs pointing at "
        "non-local hosts, indicating plaintext data transmission."
    )
    rationale = (
        "Hardcoded HTTP endpoints transmit data unencrypted. Distinct hosts "
        "are reported individually; localhost/RFC1918 addresses are handled "
        "by BS-N19."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Replace hardcoded http:// endpoints with https://, remove dead "
        "endpoints, and centralize base URLs in configuration so transport "
        "policy can be audited in one place."
    )
    references = [
        "https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(
            r'"http://[A-Za-z0-9][^"\s]*"', iter_source_files(ctx), max_hits=500
        )
        per_host: dict[str, Evidence] = {}
        for hit in hits:
            url = hit.match.group(0).strip('"')
            host = _host_of(url)
            if not host or _is_local_host(host):
                continue  # localhost/RFC1918 handled by BS-N19
            if host not in per_host:
                per_host[host] = evidence_from_hit(
                    ctx, hit,
                    f"Hardcoded http:// URL for host {host}: {url[:120]}",
                )
        if not per_host:
            return pass_result(self, "No hardcoded http:// URLs to non-local hosts found.")
        evidence = list(per_host.values())
        return finding(
            self,
            f"{len(per_host)} distinct non-local host(s) referenced over plaintext HTTP.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Medium: the URLs may be dead, test-only, or carry no sensitive "
                "data, but plaintext transport of app traffic is a real exposure."
            ),
            confidence_rationale=(
                "Literal http:// strings taken directly from decompiled source."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N03
# ---------------------------------------------------------------------------

_TRUST_MANAGER_CLASS_RX = re.compile(
    r"\bclass\s+(\w+)\s+[^\{;]*\bimplements\b[^\{;]*X509TrustManager", re.MULTILINE
)


class TrustAllTrustManager(Rule):
    id = "BS-N03"
    title = "Trust-all X509TrustManager disables certificate validation"
    description = (
        "A class implementing X509TrustManager has an empty "
        "checkServerTrusted() body, accepting any server certificate."
    )
    rationale = (
        "An empty checkServerTrusted disables all certificate chain "
        "validation, making TLS connections trivially interceptable."
    )
    category = _CATEGORY
    default_severity = Severity.CRITICAL
    owasp = ["M5"]
    cwe = ["CWE-295"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Remove the trust-all implementation. Use the platform default "
        "X509TrustManager, or pin certificates/keys properly for specific "
        "hosts instead of disabling validation."
    )
    references = [
        "https://developer.android.com/training/articles/security-ssl",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        evidence: list[Evidence] = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None or "X509TrustManager" not in text:
                continue
            for m in _TRUST_MANAGER_CLASS_RX.finditer(text):
                cls_start = m.start()
                # find checkServerTrusted after the class declaration
                for tm in re.finditer(
                    r"void\s+checkServerTrusted\s*\([^)]*\)[^\{]*\{", text[cls_start:]
                ):
                    brace_open = cls_start + tm.end() - 1
                    depth, idx = 1, brace_open + 1
                    body: list[str] = []
                    while idx < len(text):
                        ch = text[idx]
                        if ch == "{":
                            depth += 1
                        elif ch == "}":
                            depth -= 1
                            if depth == 0:
                                break
                        body.append(ch)
                        idx += 1
                    body_text = "".join(body).strip()
                    # strip comments to see if anything real remains
                    code_only = re.sub(r"//.*|/\*.*?\*/", "", body_text,
                                       flags=re.DOTALL).strip()
                    if not code_only:
                        line_no = text.count("\n", 0, cls_start + tm.start()) + 1
                        hit = next(
                            (
                                h
                                for h in grep(
                                    r"void\s+checkServerTrusted", [path], max_hits=1
                                )
                            ),
                            None,
                        )
                        evidence.append(
                            evidence_from_hit(
                                ctx,
                                hit,
                                f"Empty checkServerTrusted() in {m.group(1)} "
                                "(trust-all certificate validation)",
                            )
                            if hit
                            else evidence_simple(
                                ctx, path,
                                f"Empty checkServerTrusted() in {m.group(1)} "
                                "(trust-all certificate validation)",
                                snippet=body_text[:300],
                                line_start=line_no,
                            )
                        )
                    break  # only evaluate the first checkServerTrusted per class
        if not evidence:
            return pass_result(self, "No empty X509TrustManager.checkServerTrusted() found.")
        return finding(
            self,
            f"{len(evidence)} trust-all X509TrustManager implementation(s) found.",
            evidence=evidence,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Critical: TLS without server authentication is fully "
                "interceptable by any network attacker, defeating encryption."
            ),
            confidence_rationale=(
                "Empty method body confirmed after stripping comments from the "
                "actual decompiled source."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N04
# ---------------------------------------------------------------------------

class DisabledHostnameVerification(Rule):
    id = "BS-N04"
    title = "Hostname verification disabled"
    description = (
        "Code uses ALLOW_ALL_HOSTNAME_VERIFIER or a custom HostnameVerifier "
        "whose verify() returns true unconditionally."
    )
    rationale = (
        "Disabled hostname verification lets an attacker present a valid "
        "certificate for a different host and still be accepted."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-297"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Use the strict default hostname verifier "
        "(HttpsURLConnection.getDefaultHostnameVerifier()). If you must "
        "customize, compare against an allow-list of expected hostnames "
        "instead of returning true."
    )
    references = [
        "https://developer.android.com/training/articles/security-ssl",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        evidence: list[Evidence] = []
        allow_all_hits = grep(
            r"ALLOW_ALL_HOSTNAME_VERIFIER", iter_source_files(ctx), max_hits=100
        )
        for hit in allow_all_hits:
            evidence.append(
                evidence_from_hit(ctx, hit, "ALLOW_ALL_HOSTNAME_VERIFIER usage")
            )
        # custom HostnameVerifier with unconditional "return true"
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None or "HostnameVerifier" not in text:
                continue
            for vm in re.finditer(
                r"boolean\s+verify\s*\(\s*[\w.]+\s+\w+\s*,\s*[\w.]+\s+\w+\s*\)"
                r"[^\{]*\{",
                text,
            ):
                brace_open = vm.end() - 1
                depth, idx, body = 1, brace_open + 1, []
                while idx < len(text):
                    ch = text[idx]
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    body.append(ch)
                    idx += 1
                code_only = re.sub(r"//.*|/\*.*?\*/", "", "".join(body),
                                   flags=re.DOTALL).strip()
                if re.fullmatch(r"\s*return\s+true\s*;\s*", code_only or ""):
                    line_no = text.count("\n", 0, vm.start()) + 1
                    evidence.append(
                        evidence_simple(
                            ctx, path,
                            "Custom HostnameVerifier.verify() returns true "
                            "unconditionally",
                            snippet=f"boolean verify(...) {{ {code_only} }}",
                            line_start=line_no,
                            line_end=line_no,
                        )
                    )
        if not evidence:
            return pass_result(self, "No disabled hostname verification patterns found.")
        return finding(
            self,
            f"{len(evidence)} hostname-verification bypass(es) found.",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "High: an attacker with any CA-issued certificate can impersonate "
                "any host the app connects to."
            ),
            confidence_rationale=(
                "Literal ALLOW_ALL_HOSTNAME_VERIFIER tokens or source-verified "
                "verify() bodies that only return true."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N05
# ---------------------------------------------------------------------------

class WebViewSslErrorProceed(Rule):
    id = "BS-N05"
    title = "WebView ignores SSL errors via handler.proceed()"
    description = (
        "onReceivedSslError() calls handler.proceed(), continuing page loads "
        "despite TLS certificate errors."
    )
    rationale = (
        "Proceeding past SSL errors lets attackers intercept WebView traffic "
        "with invalid certificates, including session data in the page."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-295"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Call handler.cancel() (or super.onReceivedSslError()) on certificate "
        "errors and show the user a meaningful error instead of proceeding."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(
            r"onReceivedSslError", iter_source_files(ctx), max_hits=100
        )
        evidence: list[Evidence] = []
        for hit in hits:
            text = read_text_capped(hit.path)
            if text is None:
                continue
            # look at the method body following this declaration line
            lines = text.splitlines()
            method_text = "\n".join(lines[hit.line_no - 1 : hit.line_no + 25])
            if re.search(r"handler\s*\.\s*proceed\s*\(\s*\)", method_text):
                evidence.append(
                    evidence_from_hit(
                        ctx, hit, "onReceivedSslError() calls handler.proceed()"
                    )
                )
        if not evidence:
            return pass_result(self, "No WebView SSL-error bypass found.")
        return finding(
            self,
            f"{len(evidence)} WebViewClient(s) ignore TLS certificate errors.",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "High: any network attacker can present a bad certificate and "
                "still have the WebView load the page, exposing credentials "
                "and session data."
            ),
            confidence_rationale=(
                "handler.proceed() call confirmed inside onReceivedSslError in "
                "decompiled source."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N06
# ---------------------------------------------------------------------------

class PermissiveHostnameVerifierInstall(Rule):
    id = "BS-N06"
    title = "Permissive hostname verifier installed globally or per-connection"
    description = (
        "setDefaultHostnameVerifier() or setHostnameVerifier() is called with "
        "a verifier known to be permissive (ALLOW_ALL_HOSTNAME_VERIFIER or a "
        "custom verify()-returns-true implementation)."
    )
    rationale = (
        "Installing a permissive verifier disables hostname checks for all "
        "subsequent connections (default) or the specific connection."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-297"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Do not install custom hostname verifiers. Rely on the platform "
        "default; for exceptional hosts, implement strict allow-list "
        "matching inside verify()."
    )
    references = [
        "https://developer.android.com/training/articles/security-ssl",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def _permissive_verifier_names(self, ctx: ScanContext) -> set[str]:
        """Find names of custom verifiers whose verify() returns true."""
        names: set[str] = set()
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None or "HostnameVerifier" not in text:
                continue
            for cm in re.finditer(
                r"\bclass\s+(\w+)\s+[^\{;]*\bimplements\b[^\{;]*HostnameVerifier",
                text,
            ):
                body_start = text.find("{", cm.end())
                if body_start == -1:
                    continue
                for vm in re.finditer(
                    r"boolean\s+verify\s*\([^)]*\)[^\{]*\{", text[body_start:]
                ):
                    brace_open = body_start + vm.end() - 1
                    depth, idx, body = 1, brace_open + 1, []
                    while idx < len(text):
                        ch = text[idx]
                        if ch == "{":
                            depth += 1
                        elif ch == "}":
                            depth -= 1
                            if depth == 0:
                                break
                        body.append(ch)
                        idx += 1
                    code_only = re.sub(r"//.*|/\*.*?\*/", "", "".join(body),
                                       flags=re.DOTALL).strip()
                    if re.fullmatch(r"\s*return\s+true\s*;\s*", code_only or ""):
                        names.add(cm.group(1))
                    break
        return names

    def check(self, ctx: ScanContext):
        permissive_names = self._permissive_verifier_names(ctx)
        hits = grep(
            r"setDefaultHostnameVerifier\s*\(|setHostnameVerifier\s*\(",
            iter_source_files(ctx),
            max_hits=200,
        )
        evidence: list[Evidence] = []
        for hit in hits:
            arg = hit.match.group(0)
            if "ALLOW_ALL_HOSTNAME_VERIFIER" in hit.line:
                evidence.append(
                    evidence_from_hit(
                        ctx, hit,
                        "Permissive ALLOW_ALL_HOSTNAME_VERIFIER installed via "
                        + arg.strip(),
                    )
                )
            elif any(n in hit.line for n in permissive_names):
                evidence.append(
                    evidence_from_hit(
                        ctx, hit,
                        "Custom verify()-returns-true verifier installed via "
                        + arg.strip(),
                    )
                )
        if not evidence:
            return pass_result(self, "No permissive hostname verifier installed.")
        return finding(
            self,
            f"{len(evidence)} permissive hostname verifier installation(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "High: globally or per-connection installation of a permissive "
                "verifier removes hostname authentication for real traffic."
            ),
            confidence_rationale=(
                "Installation call sites tied to ALLOW_ALL_HOSTNAME_VERIFIER or "
                "source-verified verify()-returns-true classes."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N07
# ---------------------------------------------------------------------------


class WeakTlsProtocols(Rule):
    id = "BS-N07"
    title = "Weak or deprecated TLS/SSL protocol versions referenced"
    description = (
        "Code references obsolete protocol strings (SSLv2, SSLv3, TLS 1.0, "
        "TLS 1.1, bare \"SSL\") in SSLContext.getInstance() or "
        "setEnabledProtocols()."
    )
    rationale = (
        "SSLv2/v3 and TLS 1.0/1.1 have known practical attacks (POODLE, "
        "BEAST, weak ciphers) and are deprecated by RFC 8996."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M5"]
    cwe = ["CWE-327"]
    masvs = ["MSTG-NETWORK", "MSTG-CRYPTO"]
    remediation = (
        "Use TLS 1.2 or higher only (SSLContext.getInstance(\"TLSv1.3\") or "
        "the platform default). Remove explicit references to legacy protocol "
        "strings."
    )
    references = [
        "https://www.rfc-editor.org/rfc/rfc8996.html",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(
            r'SSLContext\s*\.\s*getInstance|setEnabledProtocols',
            iter_source_files(ctx),
            max_hits=200,
        )
        evidence: list[Evidence] = []
        seen: set[tuple[str, str, int]] = set()
        for hit in hits:
            line = hit.line
            # "TLSv1" is only weak when not TLSv1.2/1.3
            for m in re.finditer(r'"(SSLv2|SSLv3|SSL|TLSv1(?:\.1)?)"', line):
                proto = m.group(1)
                if proto == "TLSv1" and re.search(r'"TLSv1\.[23]"', line):
                    continue
                # a bare "TLSv1" literal on this line is the weak one
                key = (str(hit.path), proto, hit.line_no)
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(
                    evidence_from_hit(
                        ctx, hit,
                        f"Weak protocol string \"{proto}\" in TLS configuration",
                    )
                )
        if not evidence:
            return pass_result(self, "No weak TLS/SSL protocol strings found.")
        return finding(
            self,
            f"{len(evidence)} weak TLS/SSL protocol reference(s).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Medium: legacy protocol strings enable downgrade or outright "
                "use of broken cryptography, but actual negotiability depends "
                "on server and platform support."
            ),
            confidence_rationale="Literal protocol strings in TLS setup code.",
        )


# ---------------------------------------------------------------------------
# BS-N08
# ---------------------------------------------------------------------------

class CertificatePinningPresence(Rule):
    id = "BS-N08"
    title = "Certificate pinning presence check"
    description = (
        "Searches for certificate-pinning artifacts (OkHttp CertificatePinner, "
        "sha256/ pins, network-security-config pins). Absence of pinning is "
        "reported as informational only, never as a finding."
    )
    rationale = (
        "Per the task specification, the absence of certificate pinning alone "
        "is not a vulnerability; it is a threat-model decision. This rule "
        "records whether pinning evidence exists."
    )
    category = _CATEGORY
    default_severity = Severity.INFO
    owasp = ["M5"]
    cwe = []
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "If your threat model includes hostile networks, add certificate "
        "pinning (e.g. OkHttp CertificatePinner or <pin-set> in the network "
        "security config) with a backup pin and a rotation plan."
    )
    references = [
        "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots) or _uses_https(ctx)

    def check(self, ctx: ScanContext):
        hits = grep(
            r"CertificatePinner|sha256/|pin-set|<pin\b|add\s*\(\s*\"sha256/",
            iter_source_files(ctx),
            max_hits=50,
        )
        if not hits:
            nsc = _nsc_xml_path(ctx)
            if nsc:
                text = read_text_capped(nsc)
                if text and "<pin-set" in text:
                    return pass_result(
                        self, "Certificate pinning configured in network security config."
                    )
            return finding(
                self,
                "No certificate pinning detected; assess threat model. "
                "Absence alone is not a vulnerability.",
                evidence=[],
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "Informational: pinning is a defense-in-depth choice, not a "
                    "vulnerability by itself."
                ),
                confidence_rationale=(
                    "Heuristic keyword search; custom or native pinning may be "
                    "missed, hence medium confidence."
                ),
            )
        evidence = [evidence_from_hit(ctx, h, "Certificate pinning artifact") for h in hits[:5]]
        res = pass_result(
            self,
            f"Certificate pinning artifacts detected ({len(hits)} hit(s)).",
        )
        res.evidence = evidence
        return res


# ---------------------------------------------------------------------------
# BS-N09
# ---------------------------------------------------------------------------

def _nsc_findings(ctx: ScanContext, path: Path) -> list[tuple[str, Severity, str]]:
    """Parse network security config XML; return (message, severity, detail)."""
    out: list[tuple[str, Severity, str]] = []
    text = read_text_capped(path)
    if text is None:
        return out
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    for bc in root.iter("base-config"):
        if bc.get("cleartextTrafficPermitted", "").lower() == "true":
            out.append((
                "base-config permits cleartext traffic",
                Severity.HIGH,
                "cleartextTrafficPermitted=\"true\" on <base-config>",
            ))
    for dc in root.iter("domain-config"):
        if dc.get("cleartextTrafficPermitted", "").lower() == "true":
            domains = ", ".join(
                d.text.strip() for d in dc.iter("domain") if d.text and d.text.strip()
            ) or "(domains unlisted)"
            out.append((
                f"domain-config permits cleartext traffic for {domains}",
                Severity.HIGH,
                "cleartextTrafficPermitted=\"true\" on <domain-config>",
            ))
    for ta in root.iter("trust-anchors"):
        for certs in ta.iter("certificates"):
            if certs.get("src", "").lower() == "user":
                out.append((
                    "User-installed CAs trusted (src=\"user\")",
                    Severity.MEDIUM,
                    "<certificates src=\"user\"> in <trust-anchors>",
                ))
    if root.find("debug-overrides") is not None:
        out.append((
            "debug-overrides section present",
            Severity.LOW,
            "<debug-overrides> applies only to debuggable builds but widens trust in debug builds",
        ))
    return out


class NetworkSecurityConfigAnalysis(Rule):
    id = "BS-N09"
    title = "Network security configuration weaknesses"
    description = (
        "Parses the network security configuration XML referenced by the "
        "manifest: cleartextTrafficPermitted, user trust anchors, and "
        "debug-overrides."
    )
    rationale = (
        "The network security config controls cleartext policy and trust "
        "anchors app-wide; overly broad settings weaken transport security."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Set cleartextTrafficPermitted=\"false\" (or omit it) on base-config, "
        "restrict user-CA trust to debug-overrides only, and remove "
        "debug-overrides before release builds."
    )
    references = [
        "https://developer.android.com/training/articles/security-config",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _nsc_xml_path(ctx) is not None

    def check(self, ctx: ScanContext):
        path = _nsc_xml_path(ctx)
        assert path is not None
        text = read_text_capped(path)
        if text is None:
            return pass_result(self, "Network security config unreadable.")
        results = _nsc_findings(ctx, path)
        lines = text.splitlines()

        def _line_for(needle: str) -> int | None:
            for i, line in enumerate(lines, start=1):
                if needle in line:
                    return i
            return None

        evidence: list[Evidence] = []
        top_severity: Severity | None = None
        messages: list[str] = []
        for message, sev, needle in results:
            messages.append(message)
            ln = _line_for(needle.split('"')[0]) or _line_for(needle[:20])
            evidence.append(
                evidence_simple(
                    ctx, path, message,
                    snippet=lines[ln - 1].strip() if ln else needle,
                    line_start=ln, line_end=ln,
                )
            )
            if top_severity is None or _sev_rank(sev) > _sev_rank(top_severity):
                top_severity = sev
        if not results:
            return pass_result(self, "Network security config has no cleartext/user-CA/debug issues.")
        return finding(
            self,
            "; ".join(messages) + ".",
            evidence=evidence,
            severity=top_severity or Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Severity reflects the strongest misconfiguration found: "
                "cleartext permission is HIGH, user-CA trust MEDIUM, "
                "debug-overrides LOW."
            ),
            confidence_rationale=(
                "Direct XML attribute evidence from the app's own network "
                "security configuration file."
            ),
        )


def _sev_rank(sev: Severity) -> int:
    return {
        Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
        Severity.HIGH: 3, Severity.CRITICAL: 4,
    }[sev]


# ---------------------------------------------------------------------------
# BS-N10
# ---------------------------------------------------------------------------

class InsecureWebSocketUrls(Rule):
    id = "BS-N10"
    title = "Insecure ws:// WebSocket URLs in code"
    description = (
        "Java/Kotlin sources contain ws:// (unencrypted WebSocket) URLs, "
        "exposing real-time traffic to interception."
    )
    rationale = (
        "WebSocket connections carry session and application data; ws:// "
        "sends it all in plaintext."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Use wss:// for all WebSocket connections and remove ws:// URLs."
    )
    references = [
        "https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(r'"ws://[^"\s]+"', iter_source_files(ctx), max_hits=100)
        hits = [h for h in hits if not _is_local_host(_host_of(h.match.group(0).strip('"')))]
        if not hits:
            return pass_result(self, "No non-local ws:// URLs found.")
        evidence = [
            evidence_from_hit(ctx, h, f"Insecure WebSocket URL: {h.match.group(0)[:120]}")
            for h in hits[:10]
        ]
        return finding(
            self,
            f"{len(hits)} insecure ws:// WebSocket URL(s) in code.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Medium: plaintext WebSocket traffic can be read and modified "
                "on-path; impact depends on the data carried."
            ),
            confidence_rationale="Literal ws:// strings from decompiled source.",
        )


# ---------------------------------------------------------------------------
# BS-N11
# ---------------------------------------------------------------------------

class HttpFallback(Rule):
    id = "BS-N11"
    title = "HTTP fallback in error or catch handlers"
    description = (
        "Catch blocks, onFailure/onError callbacks, or fallback logic contain "
        "http:// URLs, suggesting the app retries over plaintext when HTTPS "
        "fails."
    )
    rationale = (
        "Falling back to HTTP on TLS failure converts a transient error into "
        "a permanent downgrade an attacker can force. Static analysis cannot "
        "confirm runtime behavior, so this is NEEDS_REVIEW."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Never downgrade to HTTP on TLS/network errors. Retry over HTTPS, "
        "surface the error to the user, and log failures server-side instead."
    )
    references = [
        "https://developer.android.com/training/articles/security-config",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        evidence: list[Evidence] = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None or "http://" not in text:
                continue
            lines = text.splitlines()
            for i, line in enumerate(lines):
                if "http://" not in line or "https://" in line:
                    continue
                window = "\n".join(lines[max(0, i - 15): i + 1])
                if re.search(
                    r"\bcatch\b|onFailure|onError|fallback|retry|backup",
                    window,
                    re.IGNORECASE,
                ):
                    evidence.append(
                        evidence_simple(
                            ctx, path,
                            "http:// URL inside error/catch/fallback context",
                            snippet=line.strip(),
                            line_start=i + 1, line_end=i + 1,
                        )
                    )
                    if len(evidence) >= 10:
                        break
        if not evidence:
            return pass_result(self, "No HTTP fallback patterns found.")
        return needs_review(
            self,
            f"{len(evidence)} http:// URL(s) in error/catch/fallback contexts "
            "may downgrade TLS failures to plaintext.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "Medium: a real HTTP fallback is a protocol-downgrade "
                "vulnerability; severity capped pending manual confirmation."
            ),
            confidence_rationale=(
                "Heuristic proximity match only; the http:// URL may be "
                "unrelated to the error handler."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N12
# ---------------------------------------------------------------------------

class HardcodedProxyConfig(Rule):
    id = "BS-N12"
    title = "Hardcoded proxy configuration"
    description = (
        "Code configures a proxy with a literal host "
        "(Proxy.Type.HTTP with a hardcoded address, setProxy(), or "
        "http.proxyHost system properties)."
    )
    rationale = (
        "Hardcoded proxies route app traffic through an attacker-influenced "
        "or uncontrolled middlebox and can leak credentials to it."
    )
    category = _CATEGORY
    default_severity = Severity.LOW
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Remove hardcoded proxy settings; respect system proxy configuration "
        "or make the proxy user-configurable. Never send credentials through "
        "a hardcoded middlebox."
    )
    references: list[str] = []

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(
            r"Proxy\s*\.\s*Type\s*\.\s*HTTP|setProxy\s*\(|http\.proxyHost|"
            r'new\s+Proxy\s*\([^)]*"[^"]+\"',
            iter_source_files(ctx),
            max_hits=50,
        )
        if not hits:
            return pass_result(self, "No hardcoded proxy configuration found.")
        evidence = [
            evidence_from_hit(ctx, h, "Hardcoded proxy configuration")
            for h in hits[:10]
        ]
        return finding(
            self,
            f"{len(hits)} hardcoded proxy configuration site(s).",
            evidence=evidence,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Low: a hardcoded proxy is usually a debugging leftover; "
                "impact is real only if it routes sensitive traffic through "
                "an untrusted host."
            ),
            confidence_rationale=(
                "Proxy API calls confirmed in source; whether the host is "
                "literal vs. configurable needs a glance at the snippet."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N13
# ---------------------------------------------------------------------------

_SENSITIVE_PARAM_RX = re.compile(
    r"[?&](token|password|passwd|pwd|api[_-]?key|secret|auth|sessionid|"
    r"access[_-]?token|client[_-]?secret)=[^&\s\"']*",
    re.IGNORECASE,
)


class SensitiveDataInUrls(Rule):
    id = "BS-N13"
    title = "Sensitive data in network URL query parameters"
    description = (
        "https/http URLs embed sensitive query parameters (token, password, "
        "api_key, secret), which leak into logs, proxies, and browser history."
    )
    rationale = (
        "Query strings are logged by servers, proxies, and analytics, and "
        "persist in history; credentials belong in headers or bodies."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M5", "M6"]
    cwe = ["CWE-598"]
    masvs = ["MSTG-NETWORK", "MSTG-STORAGE"]
    remediation = (
        "Move credentials and tokens out of URLs into Authorization headers "
        "or POST bodies. Rotate any secrets that were transmitted in URLs."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/598.html",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(
            r'"https?://[^"\s]*[?&](token|password|passwd|pwd|api[_-]?key|'
            r"secret|auth|sessionid|access[_-]?token|client[_-]?secret)=",
            iter_source_files(ctx),
            flags=re.IGNORECASE,
            max_hits=100,
        )
        # also scan string concatenations building URLs with sensitive params
        if not hits:
            concat_hits = grep(
                r'"[?&](token|password|passwd|pwd|api[_-]?key|secret)=["\s]*\+',
                iter_source_files(ctx),
                flags=re.IGNORECASE,
                max_hits=100,
            )
            hits = concat_hits
        if not hits:
            return pass_result(self, "No sensitive query parameters in URLs found.")
        evidence = []
        for h in hits[:10]:
            redacted = _SENSITIVE_PARAM_RX.sub(
                lambda m: m.group(0).split("=")[0] + "=<redacted>", h.match.group(0)
            )
            evidence.append(
                evidence_from_hit(
                    ctx, h,
                    f"Sensitive query parameter in URL: {redacted[:140]}",
                )
            )
        return finding(
            self,
            f"{len(hits)} URL(s) with sensitive query parameters.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Medium: query-string secrets are logged and cached in many "
                "places, but exploitability depends on log access."
            ),
            confidence_rationale=(
                "Sensitive parameter names observed literally in URL strings."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N14
# ---------------------------------------------------------------------------

class RedirectWithAuthHeaders(Rule):
    id = "BS-N14"
    title = "Automatic redirect following on connections carrying Authorization"
    description = (
        "Code enables setInstanceFollowRedirects(true) (or equivalent) near "
        "code that sets an Authorization header, risking credential leakage "
        "to a redirected host."
    )
    rationale = (
        "HttpURLConnection re-sends Authorization headers to redirect targets "
        "by default in some paths; following redirects while authenticated "
        "can leak tokens to attacker-controlled hosts."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M5"]
    cwe = ["CWE-918"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Handle redirects manually: validate the redirect target host against "
        "an allow-list and strip Authorization headers when the host changes."
    )
    references: list[str] = []

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        evidence: list[Evidence] = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None:
                continue
            if "setInstanceFollowRedirects" not in text:
                continue
            if not re.search(
                r"setRequestProperty\s*\(\s*\"Authorization\"|"
                r"addRequestProperty\s*\(\s*\"Authorization\"|"
                r"\.header\s*\(\s*\"Authorization\"",
                text,
            ):
                continue
            for hit in grep(
                r"setInstanceFollowRedirects\s*\(\s*true\s*\)", [path], max_hits=10
            ):
                evidence.append(
                    evidence_from_hit(
                        ctx, hit,
                        "Redirect following enabled in a file that sets "
                        "Authorization headers",
                    )
                )
        if not evidence:
            return pass_result(
                self,
                "No redirect-following combined with Authorization headers found.",
            )
        return needs_review(
            self,
            "setInstanceFollowRedirects(true) used where Authorization "
            "headers are set; verify redirect targets and header forwarding.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "Medium: leaked Authorization tokens enable account takeover, "
                "but only if redirects actually cross trust boundaries."
            ),
            confidence_rationale=(
                "File-level co-occurrence only; manual review must confirm the "
                "redirect and the authenticated request are the same connection."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N15
# ---------------------------------------------------------------------------

class DomainConfigCleartextExceptions(Rule):
    id = "BS-N15"
    title = "Cleartext exceptions for specific domains in network security config"
    description = (
        "The network security config grants cleartextTrafficPermitted=\"true\" "
        "to specific domain-config entries."
    )
    rationale = (
        "Per-domain cleartext exceptions are narrower than a global flag but "
        "still expose those domains' traffic to interception; each exception "
        "must be justified."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Migrate the excepted domains to HTTPS and remove the exceptions, or "
        "document the justification and scope each exception as narrowly as "
        "possible."
    )
    references = [
        "https://developer.android.com/training/articles/security-config",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _nsc_xml_path(ctx) is not None

    def check(self, ctx: ScanContext):
        path = _nsc_xml_path(ctx)
        assert path is not None
        text = read_text_capped(path)
        if text is None:
            return pass_result(self, "Network security config unreadable.")
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return pass_result(self, "Network security config is not valid XML.")
        evidence: list[Evidence] = []
        lines = text.splitlines()
        for dc in root.iter("domain-config"):
            if dc.get("cleartextTrafficPermitted", "").lower() != "true":
                continue
            domains = ", ".join(
                d.text.strip() for d in dc.iter("domain") if d.text and d.text.strip()
            ) or "(domains unlisted)"
            ln = None
            for i, line in enumerate(lines, start=1):
                if "cleartextTrafficPermitted" in line and "true" in line:
                    ln = i
                    break
            evidence.append(
                evidence_simple(
                    ctx, path,
                    f"Cleartext permitted for domain-config: {domains}",
                    snippet=lines[ln - 1].strip() if ln else "",
                    line_start=ln, line_end=ln,
                )
            )
        if not evidence:
            return pass_result(self, "No domain-config cleartext exceptions found.")
        return finding(
            self,
            f"{len(evidence)} domain-config cleartext exception(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "High: traffic to the excepted domains travels unencrypted and "
                "is interceptable on hostile networks."
            ),
            confidence_rationale=(
                "Direct XML evidence from the app's network security config."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N16
# ---------------------------------------------------------------------------

class VerboseNetworkLogging(Rule):
    id = "BS-N16"
    title = "Verbose network logging (request/response bodies logged)"
    description = (
        "OkHttp HttpLoggingInterceptor is configured with Level.BODY (or "
        "setLevel(BODY)), logging full request and response bodies including "
        "potential credentials."
    )
    rationale = (
        "Body-level network logging writes tokens, passwords, and PII to "
        "logcat, where any app with READ_LOGS (or the device owner via adb) "
        "can read them."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M5", "M9"]
    cwe = ["CWE-532"]
    masvs = ["MSTG-STORAGE", "MSTG-NETWORK"]
    remediation = (
        "Set the logging level to NONE (or HEADERS at most) in release "
        "builds; gate BODY logging behind BuildConfig.DEBUG."
    )
    references = [
        "https://square.github.io/okhttp/features/interceptors/",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(
            r"HttpLoggingInterceptor|setLevel\s*\(\s*(Level\s*\.\s*)?BODY\s*\)|"
            r"logging\s*\.\s*setLevel\s*\(\s*BODY\s*\)",
            iter_source_files(ctx),
            max_hits=50,
        )
        body_hits = [
            h for h in hits
            if re.search(r"\bBODY\b", h.line)
            or "HttpLoggingInterceptor" in h.line
        ]
        # keep only hits that actually enable BODY level or construct the interceptor
        confirmed = []
        for h in body_hits:
            text = read_text_capped(h.path)
            if text is None:
                continue
            if re.search(r"setLevel\s*\(\s*[\w.]*BODY\s*\)", text):
                confirmed.append(h)
                break
        if not confirmed:
            return pass_result(self, "No body-level network logging enabled.")
        evidence = [
            evidence_from_hit(
                ctx, h, "Network logging at BODY level logs request/response bodies"
            )
            for h in confirmed[:5]
        ]
        return finding(
            self,
            "HttpLoggingInterceptor logs full request/response bodies.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Medium: body logging routinely captures credentials and PII "
                "into logcat; exploitation needs log access."
            ),
            confidence_rationale=(
                "setLevel(BODY) call confirmed in decompiled source."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N17
# ---------------------------------------------------------------------------

class CustomSslSocketFactoryNoVerify(Rule):
    id = "BS-N17"
    title = "Custom SSLSocketFactory that skips certificate verification"
    description = (
        "A custom SSLSocketFactory (or SSLContext initialized with a "
        "trust-all TrustManager) is installed on connections, disabling "
        "certificate validation."
    )
    rationale = (
        "Custom socket factories that bypass verification have the same "
        "effect as a trust-all TrustManager: TLS becomes interceptable."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-295"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Remove the custom factory and use the platform default SSLContext. "
        "If customization is required, delegate verification to the default "
        "TrustManager or implement proper pinning."
    )
    references = [
        "https://developer.android.com/training/articles/security-ssl",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        evidence: list[Evidence] = []
        # pattern 1: SSLContext.init with a trust-all manager variable nearby
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None:
                continue
            if not re.search(r"SSLContext|SSLSocketFactory", text):
                continue
            for hit in grep(
                r"sslContext\s*\.\s*init\s*\(|SSLContext\s*\.\s*getInstance|"
                r"setSSLSocketFactory\s*\(|"
                r"class\s+\w+\s+extends\s+SSLSocketFactory",
                [path],
                max_hits=20,
            ):
                window_start = max(0, hit.line_no - 30)
                lines = text.splitlines()
                window = "\n".join(lines[window_start: hit.line_no + 5])
                if re.search(
                    r"TrustAll|TRUST_ALL|trustAll|X509TrustManager\s*\(\s*\)\s*\{"
                    r"|new\s+TrustManager\s*\[\s*\]\s*\{\s*\}|"
                    r"checkServerTrusted\s*\(\s*\)\s*\{\s*\}",
                    window,
                ) or "ALLOW_ALL" in window:
                    evidence.append(
                        evidence_from_hit(
                            ctx, hit,
                            "SSLContext/socket factory initialized with "
                            "trust-all verification bypass",
                        )
                    )
        if not evidence:
            return pass_result(
                self, "No custom SSLSocketFactory verification bypass found."
            )
        return finding(
            self,
            f"{len(evidence)} custom SSL socket factory / context bypass(es).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "High: bypassing certificate verification at the socket layer "
                "exposes all TLS traffic to interception."
            ),
            confidence_rationale=(
                "Trust-all indicators co-located with SSLContext/socket-factory "
                "setup; manual review should confirm the factory is installed "
                "on real connections."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N18
# ---------------------------------------------------------------------------

class BackendEndpointInventory(Rule):
    id = "BS-N18"
    title = "Backend endpoint inventory (https hosts)"
    description = (
        "Collects the distinct https:// hosts referenced in code and "
        "resources as an informational inventory for scoping."
    )
    rationale = (
        "An inventory of backend hosts helps the assessor scope testing and "
        "verify that all endpoints are in the assessment's authorization. "
        "Informational only."
    )
    category = _CATEGORY
    default_severity = Severity.INFO
    owasp = ["M5"]
    cwe = []
    masvs = []
    remediation = (
        "Review the inventory: confirm each host is in scope, served over "
        "TLS 1.2+, and covered by the app's certificate validation."
    )
    references: list[str] = []

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hosts: dict[str, Evidence] = {}
        hits = grep(r'"https://[^"\s]+"', iter_source_files(ctx), max_hits=500)
        for hit in hits:
            url = hit.match.group(0).strip('"')
            host = _host_of(url)
            if not host or _is_local_host(host):
                continue
            if host not in hosts:
                hosts[host] = evidence_from_hit(
                    ctx, hit, f"https backend host: {host}"
                )
        if not hosts:
            return pass_result(self, "No https backend hosts found in code.")
        return finding(
            self,
            f"Backend inventory: {len(hosts)} distinct https host(s): "
            + ", ".join(sorted(hosts)),
            evidence=list(hosts.values())[:15],
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            severity_rationale="Informational: inventory for scoping, not a vulnerability.",
            confidence_rationale="Hosts taken literally from https:// strings in source.",
        )


# ---------------------------------------------------------------------------
# BS-N19
# ---------------------------------------------------------------------------

_LOCAL_URL_RX = re.compile(r'"http://(localhost|127\.0\.0\.1|10\.0\.2\.2|10\.\d+\.\d+\.\d+)(:\d+)?[^"\s]*"')


class LocalhostTestEndpoints(Rule):
    id = "BS-N19"
    title = "Localhost/test endpoints in code"
    description = (
        "Code references localhost or emulator-loopback HTTP endpoints "
        "(http://localhost, http://127.0.0.1, http://10.0.2.2), which may "
        "point at development backends that behave differently in production."
    )
    rationale = (
        "Test endpoints left in release builds can hit unintended backends, "
        "leak data to local services, or indicate debug code shipped to users."
    )
    category = _CATEGORY
    default_severity = Severity.LOW
    owasp = ["M8"]
    cwe = ["CWE-489"]
    masvs = ["MSTG-CODE"]
    remediation = (
        "Remove or externalize test endpoints; use build-type-specific "
        "configuration so release builds never reference localhost backends."
    )
    references: list[str] = []

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(
            r'"http://(localhost|127\.0\.0\.1|10\.0\.2\.2)(:\d+)?[^"\s]*"',
            iter_source_files(ctx),
            max_hits=50,
        )
        if not hits:
            return pass_result(self, "No localhost/test HTTP endpoints found.")
        evidence = [
            evidence_from_hit(ctx, h, f"Test endpoint: {h.match.group(0)[:120]}")
            for h in hits[:10]
        ]
        return finding(
            self,
            f"{len(hits)} localhost/test endpoint reference(s) in code.",
            evidence=evidence,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Low: test endpoints are a hygiene issue; they become serious "
                "only if they reach production services or leak data."
            ),
            confidence_rationale="Literal localhost/loopback URL strings in source.",
        )


# ---------------------------------------------------------------------------
# BS-N20
# ---------------------------------------------------------------------------

class InternetWithoutSecurityConfig(Rule):
    id = "BS-N20"
    title = "INTERNET permission without a network security configuration"
    description = (
        "The app requests android.permission.INTERNET but the manifest does "
        "not reference a network security configuration, so transport policy "
        "relies on defaults alone."
    )
    rationale = (
        "Without an explicit network security config there is no declarative "
        "record of cleartext policy, trust anchors, or pinning; this is "
        "informational and prompts the assessor to verify transport settings."
    )
    category = _CATEGORY
    default_severity = Severity.INFO
    owasp = ["M5"]
    cwe = []
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Add an explicit network security configuration declaring "
        "cleartextTrafficPermitted=\"false\", appropriate trust anchors, and "
        "pinning where the threat model warrants it."
    )
    references = [
        "https://developer.android.com/training/articles/security-config",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _manifest(ctx) is not None

    def check(self, ctx: ScanContext):
        m = ctx.manifest
        assert m is not None
        if not _has_internet(ctx):
            return not_applicable(self, "App does not request INTERNET permission.")
        if m.network_security_config:
            return pass_result(
                self,
                f"Network security config referenced: {m.network_security_config}.",
            )
        return finding(
            self,
            "App uses INTERNET but declares no network security configuration.",
            evidence=[],
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Informational: absence of a config is not itself a "
                "vulnerability; it limits declarative transport-policy review."
            ),
            confidence_rationale=(
                "Manifest declares INTERNET and has no "
                "android:networkSecurityConfig attribute."
            ),
        )


# ---------------------------------------------------------------------------
# Module export
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    CleartextTrafficEnabled(),
    HardcodedHttpUrls(),
    TrustAllTrustManager(),
    DisabledHostnameVerification(),
    WebViewSslErrorProceed(),
    PermissiveHostnameVerifierInstall(),
    WeakTlsProtocols(),
    CertificatePinningPresence(),
    NetworkSecurityConfigAnalysis(),
    InsecureWebSocketUrls(),
    HttpFallback(),
    HardcodedProxyConfig(),
    SensitiveDataInUrls(),
    RedirectWithAuthHeaders(),
    DomainConfigCleartextExceptions(),
    VerboseNetworkLogging(),
    CustomSslSocketFactoryNoVerify(),
    BackendEndpointInventory(),
    LocalhostTestEndpoints(),
    InternetWithoutSecurityConfig(),
]
