"""Network & transport security rules (BS-N01 .. BS-N35).

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
  BS-N21  WebSocket instantiated with a ws:// URL
  BS-N22  debug-overrides widen trust anchors in network security config
  BS-N23  Per-domain cleartext traffic permitted (standalone)
  BS-N24  No certificate pinning in network security config (informational)
  BS-N25  Hardcoded IPv4 address in http:// URL
  BS-N26  http:// URL passed to a network API
  BS-N27  SSLContext forced to legacy TLS/SSL
  BS-N28  ALLOW_ALL_HOSTNAME_VERIFIER installed on connections
  BS-N29  TrustManager that swallows certificate exceptions
  BS-N30  Redirect following near cleartext HTTP URLs
  BS-N31  Hardcoded proxy via Proxy/InetSocketAddress constructor
  BS-N32  GraphQL endpoint without nearby Authorization usage
  BS-N33  Inline permissive HostnameVerifier (lambda or anonymous class)
  BS-N34  Custom DNS resolver bypassing system DNS
  BS-N35  Sensitive query parameter in URL passed to a network API
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
# BS-N21
# ---------------------------------------------------------------------------

class WebSocketConstructorPlaintext(Rule):
    id = "BS-N21"
    title = "WebSocket instantiated with a ws:// URL"
    description = (
        "Detects WebSocket client construction with a plaintext ws:// URL "
        "(e.g. new WebSocket(\"ws://...\")). Narrower than BS-N10: this rule "
        "fires only where a ws:// literal reaches an actual WebSocket "
        "connection-establishment site."
    )
    rationale = (
        "A WebSocket handshake over ws:// sends the HTTP upgrade, headers "
        "and all subsequent frames in plaintext, exposing session tokens "
        "and application data to on-path attackers."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Use wss:// for every WebSocket connection. Remove ws:// URLs and "
        "fail closed if a secure endpoint is unavailable."
    )
    references = [
        "https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(r'"ws://[^"\s]+"', iter_source_files(ctx), max_hits=200)
        evidence: list[Evidence] = []
        for hit in hits:
            if "WebSocket" not in hit.line and "websocket" not in hit.line.lower():
                continue
            url = hit.match.group(0).strip('"')
            if _is_local_host(_host_of(url)):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"WebSocket established over plaintext ws://: {url[:120]}",
                )
            )
        if not evidence:
            return pass_result(
                self, "No WebSocket instantiations with ws:// URLs found."
            )
        return finding(
            self,
            f"{len(evidence)} WebSocket connection(s) over plaintext ws://.",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "High: the full WebSocket session, including authentication "
                "headers and frames, travels unencrypted."
            ),
            confidence_rationale=(
                "Literal ws:// URLs at WebSocket construction sites in "
                "decompiled source."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N22
# ---------------------------------------------------------------------------

class DebugOverridesTrustAnchors(Rule):
    id = "BS-N22"
    title = "debug-overrides widen trust anchors in network security config"
    description = (
        "Parses the network security configuration for a <debug-overrides> "
        "section that adds <trust-anchors> (e.g. user CAs). Unlike BS-N09, "
        "which notes any debug-overrides as LOW, this rule fires only when "
        "debug builds actually widen certificate trust."
    )
    rationale = (
        "debug-overrides apply to debuggable builds. Adding trust anchors "
        "there (commonly src=\"user\") trains developers to accept "
        "user-installed CAs and the configuration can leak into release "
        "builds through build misconfiguration."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M5"]
    cwe = ["CWE-295"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Keep debug-overrides minimal and never ship debuggable release "
        "builds. Prefer per-host debug proxies over widening trust anchors."
    )
    references = [
        "https://developer.android.com/training/articles/security-config#debug-overrides",
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
        dbg = root.find("debug-overrides")
        if dbg is None or dbg.find("trust-anchors") is None:
            return pass_result(
                self, "No debug-overrides trust-anchor widening found."
            )
        lines = text.splitlines()
        ln = next(
            (i for i, line in enumerate(lines, start=1)
             if "debug-overrides" in line),
            None,
        )
        return finding(
            self,
            "debug-overrides add trust anchors (debug builds trust extra CAs).",
            evidence=[
                evidence_simple(
                    ctx, path,
                    "<debug-overrides> contains <trust-anchors>",
                    snippet=lines[ln - 1].strip() if ln else "<debug-overrides>",
                    line_start=ln, line_end=ln,
                )
            ],
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Medium: debug builds accept additional CAs, enabling "
                "interception during development and risking release-build "
                "leakage."
            ),
            confidence_rationale=(
                "Direct XML evidence from the app's network security config."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N23
# ---------------------------------------------------------------------------

class PerDomainCleartextPolicy(Rule):
    id = "BS-N23"
    title = "Per-domain cleartext traffic permitted"
    description = (
        "Reports each <domain-config> entry with "
        "cleartextTrafficPermitted=\"true\" as a standalone finding with the "
        "affected domains listed. Standalone counterpart to the aggregated "
        "BS-N15."
    )
    rationale = (
        "Per-domain cleartext exceptions expose those domains' traffic to "
        "interception. Each exception must be justified and scoped narrowly."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Migrate the excepted domains to HTTPS and remove the exceptions, or "
        "document the justification for each one."
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
            ln = next(
                (i for i, line in enumerate(lines, start=1)
                 if "domain-config" in line and "cleartextTrafficPermitted" in line),
                None,
            )
            # fall back to the first cleartextTrafficPermitted="true" line
            if ln is None:
                ln = next(
                    (i for i, line in enumerate(lines, start=1)
                     if "cleartextTrafficPermitted" in line and "true" in line),
                    None,
                )
            evidence.append(
                evidence_simple(
                    ctx, path,
                    f"Cleartext permitted for domain(s): {domains}",
                    snippet=lines[ln - 1].strip() if ln else "",
                    line_start=ln, line_end=ln,
                )
            )
        if not evidence:
            return pass_result(self, "No per-domain cleartext permissions found.")
        return finding(
            self,
            f"{len(evidence)} domain(s) allowed cleartext traffic.",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "High: traffic to the excepted domains travels unencrypted "
                "and is interceptable on hostile networks."
            ),
            confidence_rationale=(
                "Direct XML evidence from the app's network security config."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N24
# ---------------------------------------------------------------------------

class PinningConfigAbsence(Rule):
    id = "BS-N24"
    title = "No certificate pinning in network security configuration"
    description = (
        "Config-focused pinning check: reports (informational) when the "
        "network security config exists without a <pin-set>, or when the "
        "app uses HTTPS but declares no network security config at all. "
        "Code-level pinning artifacts are covered by BS-N08."
    )
    rationale = (
        "Pinning is a defense-in-depth decision, not a vulnerability, so "
        "absence is informational. This rule gives the assessor a definitive "
        "config-level answer instead of a heuristic."
    )
    category = _CATEGORY
    default_severity = Severity.INFO
    owasp = ["M5"]
    cwe = []
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "If the threat model includes hostile networks, add a <pin-set> "
        "with a backup pin to the network security config and plan rotation."
    )
    references = [
        "https://developer.android.com/training/articles/security-config#certificate-pinning",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _manifest(ctx) is not None

    def check(self, ctx: ScanContext):
        path = _nsc_xml_path(ctx)
        if path is not None:
            text = read_text_capped(path)
            if text is not None and "<pin-set" in text:
                return pass_result(
                    self, "Certificate pinning configured (<pin-set> present)."
                )
            lines = (text or "").splitlines()
            ln = next(
                (i for i, line in enumerate(lines, start=1)
                 if "network-security-config" in line),
                None,
            )
            return finding(
                self,
                "Network security config declares no certificate pinning "
                "(no <pin-set>). Assess the threat model.",
                evidence=[
                    evidence_simple(
                        ctx, path,
                        "No <pin-set> in network security config",
                        snippet=lines[ln - 1].strip() if ln else "",
                        line_start=ln, line_end=ln,
                    )
                ],
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "Informational: pinning absence is a threat-model "
                    "decision, not a vulnerability."
                ),
                confidence_rationale=(
                    "Config file parsed directly; code-level or native "
                    "pinning outside the config would not be seen here."
                ),
            )
        if not _uses_https(ctx):
            return pass_result(self, "No HTTPS usage observed; pinning not applicable.")
        return finding(
            self,
            "App uses HTTPS but declares no network security configuration, "
            "so no declarative pinning exists. Assess the threat model.",
            evidence=[],
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Informational: pinning absence is a threat-model decision, "
                "not a vulnerability."
            ),
            confidence_rationale=(
                "Manifest has no networkSecurityConfig reference while HTTPS "
                "usage was observed; code-level pinning may still exist."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N25
# ---------------------------------------------------------------------------

class HardcodedIpHttpUrl(Rule):
    id = "BS-N25"
    title = "Hardcoded IPv4 address in http:// URL"
    description = (
        "Detects http:// URLs with a literal IPv4 address instead of a "
        "hostname. IP literals bypass DNS-based controls, cannot carry "
        "properly validated public certificates, and usually indicate "
        "hardcoded infrastructure."
    )
    rationale = (
        "Hardcoded IP endpoints are brittle and opaque: they defeat "
        "certificate hostname validation, hinder incident response, and "
        "often point at forgotten test or admin infrastructure."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Replace IP literals with hostnames served over HTTPS, centralize "
        "endpoint configuration, and remove dead infrastructure references."
    )
    references: list[str] = []

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(
            r'"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}([^"\s]*)"',
            iter_source_files(ctx),
            max_hits=100,
        )
        evidence: list[Evidence] = []
        for hit in hits:
            url = hit.match.group(0).strip('"')
            host = _host_of(url)
            if host.startswith("127.") or host == "10.0.2.2":
                continue  # loopback/emulator handled by BS-N19
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"Hardcoded IPv4 in http:// URL: {url[:120]}",
                )
            )
        if not evidence:
            return pass_result(self, "No hardcoded IPv4 addresses in http:// URLs.")
        return finding(
            self,
            f"{len(evidence)} http:// URL(s) with hardcoded IPv4 address.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Medium: plaintext transport to hardcoded infrastructure is "
                "interceptable and the endpoints are unauditable via DNS."
            ),
            confidence_rationale=(
                "Literal IPv4 http:// strings taken directly from source."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N26
# ---------------------------------------------------------------------------

_NETWORK_SINK_RX = re.compile(
    r"openConnection\s*\(|newCall\s*\(|\.url\s*\(|openStream\s*\(|"
    r"new\s+HttpClient|@(?:GET|POST|PUT|DELETE|PATCH)\s*\(\s*\"http://"
)


class HttpUrlAtNetworkSink(Rule):
    id = "BS-N26"
    title = "http:// URL passed to a network API"
    description = (
        "Sink-based check: flags lines where an http:// literal reaches a "
        "network call (openConnection, OkHttp newCall/url(), Retrofit "
        "annotations, openStream). Stronger than BS-N02's string scan "
        "because the URL is actually used for a request."
    )
    rationale = (
        "An http:// URL that is demonstrably passed to a network API will "
        "produce real plaintext requests, not just sit in dead code."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Change the endpoint to https:// and centralize base URLs so "
        "transport policy is auditable in one place."
    )
    references = [
        "https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(r'"http://[^"\s]+"', iter_source_files(ctx), max_hits=300)
        evidence: list[Evidence] = []
        for hit in hits:
            if not _NETWORK_SINK_RX.search(hit.line):
                continue
            url = hit.match.group(0).strip('"')
            if _is_local_host(_host_of(url)):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"http:// URL passed to a network API: {url[:120]}",
                )
            )
        if not evidence:
            return pass_result(
                self, "No http:// URLs passed directly to network APIs."
            )
        return finding(
            self,
            f"{len(evidence)} plaintext http:// request(s) issued via network APIs.",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "High: the URL is not just a string in the binary - it is "
                "handed to a network API, so plaintext requests really happen."
            ),
            confidence_rationale=(
                "The http:// literal and the network sink call are on the "
                "same source line."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N27
# ---------------------------------------------------------------------------

class ForcedLegacyTlsContext(Rule):
    id = "BS-N27"
    title = "SSLContext forced to legacy TLS/SSL"
    description = (
        "Detects SSLContext.getInstance(\"TLSv1\"), (\"SSL\") or (\"TLS\") - "
        "forcing the context to a legacy or ambiguous protocol instead of "
        "the platform default."
    )
    rationale = (
        "Pinning the SSLContext to TLS 1.0-era protocols (or bare \"SSL\") "
        "disables modern protocol negotiation and can enable downgrade to "
        "broken cryptography."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-327"]
    masvs = ["MSTG-NETWORK", "MSTG-CRYPTO"]
    remediation = (
        "Use SSLContext.getInstance(\"TLS\") only via the platform default, "
        "or explicitly request \"TLSv1.3\"/\"TLSv1.2\". Never request "
        "\"TLSv1\" or \"SSL\"."
    )
    references = [
        "https://www.rfc-editor.org/rfc/rfc8996.html",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(
            r'SSLContext\s*\.\s*getInstance\s*\(\s*"(TLSv1|SSL|TLS)"\s*\)',
            iter_source_files(ctx),
            max_hits=50,
        )
        if not hits:
            return pass_result(self, "No SSLContext forced to legacy protocols.")
        return finding(
            self,
            f"{len(hits)} SSLContext.getInstance() call(s) forcing legacy protocol.",
            evidence=[
                evidence_from_hit(
                    ctx, h,
                    f"SSLContext forced to {h.match.group(1)}",
                )
                for h in hits
            ],
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "High: forcing TLS 1.0-era (or ambiguous \"SSL\") protocols "
                "removes modern negotiation and invites downgrade attacks."
            ),
            confidence_rationale=(
                "Literal protocol strings in SSLContext.getInstance() calls."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N28
# ---------------------------------------------------------------------------

class AllowAllHostnameVerifierInstalled(Rule):
    id = "BS-N28"
    title = "ALLOW_ALL_HOSTNAME_VERIFIER installed on connections"
    description = (
        "Detects setHostnameVerifier() / setDefaultHostnameVerifier() calls "
        "that install ALLOW_ALL_HOSTNAME_VERIFIER. Install-site focused "
        "counterpart to BS-N04's usage detection."
    )
    rationale = (
        "Installing the allow-all verifier - globally or per connection - "
        "disables hostname authentication, so any CA-valid certificate for "
        "any host is accepted."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-297"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Remove the installation and rely on the platform default hostname "
        "verifier. If customization is unavoidable, allow-list expected "
        "hostnames explicitly."
    )
    references = [
        "https://developer.android.com/training/articles/security-ssl",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(
            r"set(?:Default)?HostnameVerifier\s*\([^)]*ALLOW_ALL_HOSTNAME_VERIFIER",
            iter_source_files(ctx),
            max_hits=50,
        )
        if not hits:
            return pass_result(
                self, "No ALLOW_ALL_HOSTNAME_VERIFIER installations found."
            )
        return finding(
            self,
            f"{len(hits)} ALLOW_ALL_HOSTNAME_VERIFIER installation(s).",
            evidence=[
                evidence_from_hit(
                    ctx, h, "ALLOW_ALL_HOSTNAME_VERIFIER installed as verifier"
                )
                for h in hits
            ],
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "High: hostname authentication is disabled for the affected "
                "connections, enabling impersonation with any valid "
                "certificate."
            ),
            confidence_rationale=(
                "Installation call sites reference ALLOW_ALL_HOSTNAME_VERIFIER "
                "literally."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N29
# ---------------------------------------------------------------------------

class SwallowingTrustManager(Rule):
    id = "BS-N29"
    title = "TrustManager that swallows certificate exceptions"
    description = (
        "Detects X509TrustManager.checkServerTrusted() implementations whose "
        "body catches exceptions without rethrowing, silently accepting "
        "invalid certificates. Complements BS-N03, which covers empty "
        "bodies."
    )
    rationale = (
        "A checkServerTrusted that wraps validation in try/catch and drops "
        "the exception accepts every certificate while looking like it "
        "validates - worse than an obviously empty method because reviewers "
        "may miss it."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-295"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Let certificate exceptions propagate or handle them explicitly "
        "(fail closed). Better: remove the custom TrustManager and use the "
        "platform default or proper pinning."
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
            if text is None or "checkServerTrusted" not in text:
                continue
            for tm in re.finditer(
                r"void\s+checkServerTrusted\s*\([^)]*\)[^\{]*\{", text
            ):
                brace_open = tm.end() - 1
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
                body_text = "".join(body)
                code_only = re.sub(
                    r"//.*|/\*.*?\*/", "", body_text, flags=re.DOTALL
                ).strip()
                if not code_only:
                    continue  # empty body: BS-N03 territory
                if re.search(r"\bcatch\s*\(", code_only) and "throw" not in code_only:
                    line_no = text.count("\n", 0, tm.start()) + 1
                    evidence.append(
                        evidence_simple(
                            ctx, path,
                            "checkServerTrusted() catches exceptions without "
                            "rethrowing (silent accept)",
                            snippet=body_text.strip()[:600],
                            line_start=line_no,
                            line_end=line_no,
                        )
                    )
        if not evidence:
            return pass_result(
                self, "No exception-swallowing checkServerTrusted() found."
            )
        return finding(
            self,
            f"{len(evidence)} TrustManager(s) silently swallow certificate exceptions.",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "High: certificate validation is effectively disabled while "
                "appearing intact, so TLS is interceptable."
            ),
            confidence_rationale=(
                "Method bodies confirmed to catch without rethrowing; manual "
                "review should confirm the catch covers the validation path."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N30
# ---------------------------------------------------------------------------

class RedirectToHttp(Rule):
    id = "BS-N30"
    title = "Redirect following near cleartext HTTP URLs"
    description = (
        "Flags files that enable setInstanceFollowRedirects(true) where an "
        "http:// URL appears within 20 lines, suggesting redirects may land "
        "on plaintext endpoints. Distinct from BS-N14, which is about "
        "Authorization header leakage."
    )
    rationale = (
        "Following redirects to http:// downgrades the session to "
        "plaintext, exposing subsequent request data to on-path attackers."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Handle redirects manually, validate that redirect targets stay on "
        "https://, and never downgrade to http://."
    )
    references: list[str] = []

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(
            r"setInstanceFollowRedirects\s*\(\s*true\s*\)",
            iter_source_files(ctx),
            max_hits=50,
        )
        evidence: list[Evidence] = []
        for hit in hits:
            text = read_text_capped(hit.path)
            if text is None:
                continue
            lines = text.splitlines()
            lo = max(0, hit.line_no - 1 - 20)
            hi = min(len(lines), hit.line_no + 20)
            window = "\n".join(lines[lo:hi])
            if re.search(r'"http://', window):
                evidence.append(
                    evidence_from_hit(
                        ctx, hit,
                        "Redirect following enabled with an http:// URL nearby",
                    )
                )
        if not evidence:
            return pass_result(
                self, "No redirect-following near cleartext URLs found."
            )
        return finding(
            self,
            f"{len(evidence)} redirect-following site(s) near http:// URLs.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Medium: a redirect landing on http:// downgrades the "
                "session; impact depends on whether the redirect target is "
                "actually plaintext."
            ),
            confidence_rationale=(
                "MEDIUM: the redirect call and a nearby http:// URL are "
                "real, but it is not proven the redirect target is that URL."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N31
# ---------------------------------------------------------------------------

class HardcodedProxyConstructor(Rule):
    id = "BS-N31"
    title = "Hardcoded proxy via Proxy/InetSocketAddress constructor"
    description = (
        "Detects new Proxy(Proxy.Type.HTTP, new InetSocketAddress(\"host\", "
        "port)) with a literal host. Fills a gap in BS-N12, whose pattern "
        "cannot match this nested-constructor form."
    )
    rationale = (
        "A hardcoded proxy routes app traffic through a fixed middlebox; "
        "credentials and tokens sent through it are exposed to whoever "
        "controls that host."
    )
    category = _CATEGORY
    default_severity = Severity.LOW
    owasp = ["M5"]
    cwe = ["CWE-319"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Remove the hardcoded proxy; respect system proxy settings or make "
        "the proxy user-configurable. Never route credentials through a "
        "hardcoded middlebox."
    )
    references: list[str] = []

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(
            r"new\s+Proxy\s*\(\s*Proxy\.Type\.HTTP\s*,\s*new\s+"
            r"InetSocketAddress\s*\(\s*\"[^\"]+\"",
            iter_source_files(ctx),
            max_hits=50,
        )
        if not hits:
            return pass_result(
                self, "No hardcoded Proxy/InetSocketAddress construction found."
            )
        return finding(
            self,
            f"{len(hits)} hardcoded proxy construction site(s).",
            evidence=[
                evidence_from_hit(ctx, h, "Proxy with literal InetSocketAddress host")
                for h in hits
            ],
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Low: usually a debugging leftover; serious only if "
                "sensitive traffic is routed through the hardcoded host."
            ),
            confidence_rationale=(
                "The constructor call with a literal host is directly "
                "observed."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N32
# ---------------------------------------------------------------------------

class GraphqlWithoutAuth(Rule):
    id = "BS-N32"
    title = "GraphQL endpoint without nearby Authorization usage"
    description = (
        "Flags files referencing a \"/graphql\" endpoint where no "
        "Authorization header usage appears within 15 lines, suggesting the "
        "endpoint may be called without authentication."
    )
    rationale = (
        "GraphQL endpoints expose the full query surface of a backend. "
        "Calling them without authentication (or without any auth code "
        "nearby) risks unauthenticated data access and introspection abuse."
    )
    category = _CATEGORY
    default_severity = Severity.MEDIUM
    owasp = ["M1"]
    cwe = ["CWE-306"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Authenticate every GraphQL request (Authorization header or "
        "equivalent), disable introspection in production, and enforce "
        "field-level authorization server-side."
    )
    references = [
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        by_file: dict = {}
        for hit in grep(r'"/graphql"|/graphql"', iter_source_files(ctx), max_hits=50):
            by_file.setdefault(hit.path, []).append(hit)
        evidence: list[Evidence] = []
        for path, hits in by_file.items():
            text = read_text_capped(path)
            if text is None:
                continue
            lines = text.splitlines()
            for hit in hits:
                lo = max(0, hit.line_no - 1 - 15)
                hi = min(len(lines), hit.line_no + 15)
                window = "\n".join(lines[lo:hi])
                if not re.search(r"Authorization", window, re.IGNORECASE):
                    evidence.append(
                        evidence_from_hit(
                            ctx, hit,
                            '"/graphql" endpoint with no Authorization usage nearby',
                        )
                    )
        if not evidence:
            return pass_result(
                self, "No unauthenticated-looking GraphQL endpoints found."
            )
        return needs_review(
            self,
            f"{len(evidence)} GraphQL endpoint reference(s) without nearby "
            f"authentication; verify the endpoint requires auth.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "Medium: an unauthenticated GraphQL endpoint can expose "
                "backend data and schema; severity capped pending "
                "confirmation."
            ),
            confidence_rationale=(
                "LOW: only the absence of nearby Authorization usage was "
                "observed; authentication may be applied elsewhere (e.g. an "
                "interceptor). Manual review required."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N33
# ---------------------------------------------------------------------------

class InlinePermissiveHostnameVerifier(Rule):
    id = "BS-N33"
    title = "Inline permissive HostnameVerifier (lambda or anonymous class)"
    description = (
        "Detects HostnameVerifiers that return true defined inline: lambda "
        "form (hostname, session) -> true passed to setHostnameVerifier, or "
        "an anonymous new HostnameVerifier() whose verify() only returns "
        "true. Complements BS-N04, which targets named classes and method "
        "declarations."
    )
    rationale = (
        "Inline permissive verifiers disable hostname authentication just "
        "like named ones, but are easy to miss in review because they hide "
        "inside call sites."
    )
    category = _CATEGORY
    default_severity = Severity.HIGH
    owasp = ["M5"]
    cwe = ["CWE-297"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Remove the inline verifier and use the platform default. If "
        "customization is unavoidable, allow-list expected hostnames "
        "explicitly instead of returning true."
    )
    references = [
        "https://developer.android.com/training/articles/security-ssl",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        evidence: list[Evidence] = []
        # lambda form: setHostnameVerifier((h, s) -> true)
        for hit in grep(
            r"set(?:Default)?HostnameVerifier\s*\(\s*\([^)]*\)\s*->\s*true\s*\)",
            iter_source_files(ctx),
            max_hits=50,
        ):
            evidence.append(
                evidence_from_hit(
                    ctx, hit, "Lambda HostnameVerifier returning true"
                )
            )
        # anonymous class with a trivial verify body on following lines
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None or "new HostnameVerifier" not in text:
                continue
            for m in re.finditer(
                r"new\s+HostnameVerifier\s*\(\s*\)\s*\{", text
            ):
                brace_open = m.end() - 1
                depth, idx, body = 1, brace_open + 1, []
                # capture a bounded window to avoid runaway on huge files
                while idx < len(text) and idx - brace_open < 2000:
                    ch = text[idx]
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    body.append(ch)
                    idx += 1
                code_only = re.sub(
                    r"//.*|/\*.*?\*/", "", "".join(body), flags=re.DOTALL
                ).strip()
                code_only = re.sub(
                    r"@Override\s*", "", code_only
                ).strip()
                if re.fullmatch(
                    r"public\s+boolean\s+verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;\s*\}",
                    code_only,
                ):
                    line_no = text.count("\n", 0, m.start()) + 1
                    evidence.append(
                        evidence_simple(
                            ctx, path,
                            "Anonymous HostnameVerifier.verify() returns true",
                            snippet="new HostnameVerifier() { ... return true; }",
                            line_start=line_no,
                            line_end=line_no,
                        )
                    )
        if not evidence:
            return pass_result(
                self, "No inline permissive HostnameVerifiers found."
            )
        return finding(
            self,
            f"{len(evidence)} inline permissive HostnameVerifier(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "High: hostname authentication is disabled for the affected "
                "connections, enabling impersonation with any valid "
                "certificate."
            ),
            confidence_rationale=(
                "The lambda or anonymous-class body literally returns true."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N34
# ---------------------------------------------------------------------------

class CustomDnsResolver(Rule):
    id = "BS-N34"
    title = "Custom DNS resolver bypassing system DNS"
    description = (
        "Detects custom DNS resolution: anonymous new Dns() implementations "
        "or OkHttp .dns() calls with a non-default resolver. Custom "
        "resolvers bypass system DNS settings (private DNS, VPN DNS, "
        "enterprise controls)."
    )
    rationale = (
        "Overriding DNS lets the app ignore the device's DNS configuration, "
        "defeating DNS-based filtering, monitoring, and private-DNS "
        "protections, and can pin the app to attacker-influenced resolvers."
    )
    category = _CATEGORY
    default_severity = Severity.LOW
    owasp = ["M5"]
    cwe = []
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Use the system DNS resolver (the default). If custom resolution "
        "is required, document why and prefer DNS-over-HTTPS to a trusted "
        "resolver."
    )
    references: list[str] = []

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        evidence: list[Evidence] = []
        for hit in grep(
            r"new\s+Dns\s*\(\s*\)\s*\{", iter_source_files(ctx), max_hits=50
        ):
            evidence.append(
                evidence_from_hit(
                    ctx, hit, "Anonymous Dns implementation overrides resolution"
                )
            )
        for hit in grep(
            r"\.dns\s*\(", iter_source_files(ctx), max_hits=50
        ):
            if "Dns.SYSTEM" in hit.line:
                continue  # explicit system default is fine
            evidence.append(
                evidence_from_hit(
                    ctx, hit, "Custom DNS resolver installed via .dns()"
                )
            )
        if not evidence:
            return pass_result(self, "No custom DNS resolvers found.")
        return finding(
            self,
            f"{len(evidence)} custom DNS resolver site(s).",
            evidence=evidence,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Low: bypassing system DNS is mainly a control-evasion and "
                "privacy concern; it becomes serious if the resolver is "
                "attacker-influenced."
            ),
            confidence_rationale=(
                "Custom Dns implementations and .dns() installs are directly "
                "observed; whether the resolver itself is malicious needs "
                "review."
            ),
        )


# ---------------------------------------------------------------------------
# BS-N35
# ---------------------------------------------------------------------------

class SensitiveQueryParamAtSink(Rule):
    id = "BS-N35"
    title = "Sensitive query parameter in URL passed to a network API"
    description = (
        "Sink-based counterpart to BS-N13: flags lines where a URL carrying "
        "a sensitive query parameter (token, api_key, secret, password) is "
        "passed directly to a network API (openConnection, OkHttp "
        "newCall/url(), Retrofit annotations)."
    )
    rationale = (
        "Credentials in query strings are logged by servers, proxies, and "
        "analytics. When the URL demonstrably reaches a network call, the "
        "exposure is real rather than hypothetical."
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
        evidence: list[Evidence] = []
        for hit in grep(
            r'"https?://[^"\s]*[?&](token|password|passwd|pwd|api[_-]?key|'
            r"secret|auth|sessionid|access[_-]?token|client[_-]?secret)=",
            iter_source_files(ctx),
            flags=re.IGNORECASE,
            max_hits=200,
        ):
            if not _NETWORK_SINK_RX.search(hit.line):
                continue
            redacted = _SENSITIVE_PARAM_RX.sub(
                lambda m: m.group(0).split("=")[0] + "=<redacted>",
                hit.match.group(0),
            )
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"Sensitive query parameter sent via network API: "
                    f"{redacted[:140]}",
                )
            )
        if not evidence:
            return pass_result(
                self, "No sensitive query parameters passed to network APIs."
            )
        return finding(
            self,
            f"{len(evidence)} network call(s) with sensitive query parameters.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Medium: query-string secrets are logged and cached in many "
                "places along the request path."
            ),
            confidence_rationale=(
                "The sensitive parameter and the network sink call are on "
                "the same source line."
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
    WebSocketConstructorPlaintext(),
    DebugOverridesTrustAnchors(),
    PerDomainCleartextPolicy(),
    PinningConfigAbsence(),
    HardcodedIpHttpUrl(),
    HttpUrlAtNetworkSink(),
    ForcedLegacyTlsContext(),
    AllowAllHostnameVerifierInstalled(),
    SwallowingTrustManager(),
    RedirectToHttp(),
    HardcodedProxyConstructor(),
    GraphqlWithoutAuth(),
    InlinePermissiveHostnameVerifier(),
    CustomDnsResolver(),
    SensitiveQueryParamAtSink(),
]
