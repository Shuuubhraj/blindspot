"""Authentication, authorization and business-logic detection rules.

Rule inventory (all category "auth"):
  BS-A01  Client-side-only authorization decision (NEEDS_REVIEW)
  BS-A02  Hardcoded authentication bypass / backdoor credential
  BS-A03  Hardcoded test accounts in authentication code
  BS-A04  Auth token persisted in plaintext SharedPreferences
  BS-A05  Token used without expiry/refresh handling (NEEDS_REVIEW)
  BS-A06  Authentication secrets written to logs or stack traces
  BS-A07  Weak local PIN authentication without lockout (NEEDS_REVIEW)
  BS-A08  Insecure biometric fallback to weak local check (NEEDS_REVIEW)
  BS-A09  Hardcoded privileged roles enabling hidden features
  BS-A10  Authorization flag trusted from client-controlled input (NEEDS_REVIEW)
  BS-A11  Biometric authentication without CryptoObject
  BS-A12  OAuth implicit flow (response_type=token)
  BS-A13  Auth token in URL query string
  BS-A14  Device-credential fallback without isDeviceSecure check (NEEDS_REVIEW)
  BS-A15  Hardcoded test credential pairs near login code

NEEDS_REVIEW discipline: several of these checks can only observe the
client. A client-side indicator is NOT proof that the server fails to
enforce the same policy. Every NEEDS_REVIEW result states explicitly
what static analysis cannot prove, so an assessor must confirm
server-side behavior before calling anything a vulnerability.
"""

from __future__ import annotations

import re

from .base import (
    Confidence,
    Rule,
    ScanContext,
    Severity,
    finding,
    needs_review,
    pass_result,
)
from .common import evidence_from_hit, grep, iter_source_files, read_text_capped


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

_MAX_EVIDENCE = 10


def _server_validation_rx() -> re.Pattern:
    """Indicators that a role/token/permission is checked against a server."""
    return re.compile(
        r"(verify|validat|check|enforce).{0,40}(role|permission|token|auth|subscription|purchase|receipt)"
        r"|/api/|/auth/|authenticate\s*\(|checkCallingPermission|enforceCallingPermission"
        r"|queryPurchases|verifyPurchase|billingClient|validateReceipt",
        re.IGNORECASE,
    )


def _server_validated_anywhere(ctx: ScanContext) -> bool:
    """True if any decompiled source shows a server-side auth validation."""
    rx = _server_validation_rx()
    for path in iter_source_files(ctx):
        text = read_text_capped(path)
        if text and rx.search(text):
            return True
    return False


def _hits_to_evidence(ctx, hits, description, limit=_MAX_EVIDENCE):
    return [evidence_from_hit(ctx, h, description) for h in hits[:limit]]


# ---------------------------------------------------------------------------
# BS-A01 client-side-only authorization
# ---------------------------------------------------------------------------

class ClientSideOnlyAuthorization(Rule):
    id = "BS-A01"
    title = "Client-side-only authorization decision"
    description = (
        "Detects role/privilege flags (isAdmin, isPremium, role.equals(\"admin\"), "
        "getRole(), userType) used to gate features in client conditionals."
    )
    rationale = (
        "Authorization enforced only in the client is a classic CWE-602 "
        "client-side enforcement weakness. An attacker who repackages or "
        "hooks the app can flip the flag and reach the gated feature."
    )
    category = "auth"
    default_severity = Severity.HIGH
    owasp = ["M3"]
    cwe = ["CWE-602"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Enforce every authorization decision on the server for the "
        "authenticated session. Treat client-side role flags as UI hints "
        "only: the server must re-derive the caller's privileges from the "
        "session token on each privileged request. If offline use is "
        "required, bind the role claim inside a server-signed token and "
        "validate the signature locally."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/602.html",
        "https://mas.owasp.org/MASVS/",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        gate_hits = []
        role_rx = re.compile(
            r"\bisAdmin\b|\bisPremium\b|\bisVip\b|\bgetRole\s*\(\s*\)|\buserType\b"
            r"|\brole\b\s*\.\s*equals\s*\(",
            re.IGNORECASE,
        )
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if not text:
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                if "if" in line and "(" in line and role_rx.search(line):
                    m = role_rx.search(line)
                    gate_hits.append(
                        type("H", (), {"path": path, "line_no": i, "line": line, "match": m})()
                    )
                    if len(gate_hits) >= 200:
                        break
        if not gate_hits:
            return pass_result(
                self,
                "No client-side role/privilege gating conditionals found in decompiled sources.",
            )
        if _server_validated_anywhere(ctx):
            return pass_result(
                self,
                "Role/privilege gating is present, but sources also show "
                "server-side validation of role/token/permission, so the "
                "client check is not the sole enforcement point observed.",
            )
        return needs_review(
            self,
            "Client-side role/privilege flag gates a feature, and no "
            "server-side validation of the role/token/permission was found "
            "in the decompiled sources. Client-side indicator only; server "
            "enforcement cannot be confirmed statically. Verify on the "
            "backend that privileged endpoints re-derive the caller's role "
            "from the session rather than trusting the client flag.",
            evidence=_hits_to_evidence(
                ctx, gate_hits, "Role/privilege flag used in a client conditional"
            ),
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            severity_rationale=(
                "If the server trusts the client flag, an attacker can "
                "unlock privileged features by flipping it (High). Downgraded "
                "to an indicator because server behavior is unverified."
            ),
            confidence_rationale=(
                "Static analysis can only observe the client: the conditional "
                "exists, but whether the server independently enforces the "
                "same authorization cannot be proven from the APK."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A02 hardcoded authentication bypass
# ---------------------------------------------------------------------------

class HardcodedAuthBypass(Rule):
    id = "BS-A02"
    title = "Hardcoded authentication bypass / backdoor credential"
    description = (
        "Detects credentials compared against string literals "
        "(e.g. password.equals(\"admin123\")), backdoor usernames, and "
        "BuildConfig.DEBUG-gated skip-auth paths."
    )
    rationale = (
        "A hardcoded credential or debug bypass lets anyone who decompiles "
        "the APK authenticate as a privileged user (CWE-798). Debug-gated "
        "bypasses are especially dangerous because they are easy to forget "
        "and trivial to activate in a repackaged build."
    )
    category = "auth"
    default_severity = Severity.CRITICAL
    owasp = ["M3"]
    cwe = ["CWE-798"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Remove all hardcoded credentials and debug bypasses from the "
        "client. Authentication must always be verified server-side "
        "against credentials the client never stores. Gate any test login "
        "helpers behind build flavors that never ship to production, and "
        "add CI checks that fail the release build if bypass markers are "
        "present."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASVS/",
    ]

    _LITERAL_BACKDOORS = {
        "admin", "administrator", "root", "password", "1234", "12345",
        "123456", "qwerty", "letmein", "backdoor", "debug", "test",
    }

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = []
        cred_rx = re.compile(
            r"\b(password|passwd|pwd|username|userName|loginId|credential|secret|pin|otp)\b"
            r"\s*\.\s*equals(?:IgnoreCase)?\s*\(\s*\"([^\"]{1,64})\"\s*\)",
            re.IGNORECASE,
        )
        lit_rx = re.compile(
            r"\.\s*equals(?:IgnoreCase)?\s*\(\s*\"([^\"]{1,32})\"\s*\)",
            re.IGNORECASE,
        )
        debug_rx = re.compile(r"\bBuildConfig\s*\.\s*DEBUG\b")
        bypass_rx = re.compile(
            r"\b(skipAuth|bypassLogin|forceLogin|autoLogin|debugLogin|skipLogin)\b",
            re.IGNORECASE,
        )
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if not text:
                continue
            low = text.lower()
            auth_context = any(
                k in low for k in ("login", "auth", "signin", "sign_in", "password", "credential")
            )
            for i, line in enumerate(text.splitlines(), start=1):
                m = cred_rx.search(line)
                if m:
                    hits.append((path, i, line, m.group(0)))
                    continue
                m2 = lit_rx.search(line)
                if m2 and auth_context and m2.group(1).lower() in self._LITERAL_BACKDOORS:
                    hits.append((path, i, line, m2.group(0)))
                    continue
                if debug_rx.search(line) and bypass_rx.search(text):
                    hits.append((path, i, line, "BuildConfig.DEBUG + bypass-login marker"))
        if not hits:
            return pass_result(
                self,
                "No hardcoded credential comparisons or debug-gated auth "
                "bypasses found in decompiled sources.",
            )

        class _H:
            def __init__(self, path, line_no, line, m):
                self.path = path
                self.line_no = line_no
                self.line = line
                self.match = m

        ev = []
        for p, n, ln, mk in hits[:_MAX_EVIDENCE]:
            mm = re.search(re.escape(mk[:60]), ln)
            h = _H(p, n, ln, mm if mm else re.search(r"\S+", ln))
            ev.append(evidence_from_hit(ctx, h, "Hardcoded credential / auth bypass"))
        return finding(
            self,
            f"{len(hits)} hardcoded credential comparison(s) or debug-gated "
            "auth bypass marker(s) found. Anyone who decompiles the APK can "
            "read these credentials and authenticate without authorization.",
            evidence=ev,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Hardcoded credentials are directly extractable from the APK "
                "and grant authentication as another user: full account "
                "compromise with trivial effort (Critical)."
            ),
            confidence_rationale=(
                "The literal credential comparison is present verbatim in the "
                "decompiled source at the cited line; no inference required."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A03 hardcoded test accounts
# ---------------------------------------------------------------------------

class HardcodedTestAccounts(Rule):
    id = "BS-A03"
    title = "Hardcoded test accounts in authentication code"
    description = (
        "Detects test/demo/admin account literals (e.g. \"test@test.com\", "
        "\"admin@admin.com\") embedded in login or authentication code."
    )
    rationale = (
        "Shipped test accounts are a standing backdoor: they are shared in "
        "teams, rarely rotated, and often carry elevated privileges "
        "(CWE-798, OWASP M1 improper credential usage)."
    )
    category = "auth"
    default_severity = Severity.HIGH
    owasp = ["M1", "M3"]
    cwe = ["CWE-798"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Remove test accounts from production builds. Provision test users "
        "in a staging backend instead, and add a release-gate check that "
        "fails the build when known test-account literals appear in auth "
        "code."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASVS/",
    ]

    _RX = re.compile(
        r"\"(test@test\.com|admin@admin\.com|qa@[^\"@]+\.[^\"@]+|demo@[^\"@]+\.[^\"@]+"
        r"|user@test\.[^\"@]+|tester@[^\"@]+\.[^\"@]+|testuser|test123|admin123"
        r"|password123|qwerty123)\"",
        re.IGNORECASE,
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        raw = grep(self._RX.pattern, iter_source_files(ctx), flags=re.IGNORECASE)
        hits = []
        for h in raw:
            text = read_text_capped(h.path) or ""
            if any(
                k in text.lower()
                for k in ("login", "auth", "signin", "sign_in", "signup", "credential")
            ) or any(
                k in str(h.path).lower()
                for k in ("login", "auth", "signin", "user")
            ):
                hits.append(h)
        if not hits:
            return pass_result(
                self,
                "No hardcoded test-account literals found in authentication code.",
            )
        return finding(
            self,
            f"{len(hits)} hardcoded test-account literal(s) found in "
            "authentication code. Test accounts shipped in production builds "
            "act as standing backdoors.",
            evidence=_hits_to_evidence(
                ctx, hits, "Hardcoded test account in auth code"
            ),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Test credentials are extractable from the APK and frequently "
                "carry elevated or shared access; compromise is realistic "
                "(High)."
            ),
            confidence_rationale=(
                "The test-account literal appears verbatim at the cited line "
                "inside authentication-related code."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A04 insecure token persistence
# ---------------------------------------------------------------------------

class InsecureTokenPersistence(Rule):
    id = "BS-A04"
    title = "Auth token persisted in plaintext SharedPreferences"
    description = (
        "Detects auth tokens / session ids written via "
        "SharedPreferences.Editor.putString without EncryptedSharedPreferences."
    )
    rationale = (
        "Plaintext SharedPreferences are world-readable to any process "
        "with the app's UID and are trivially extracted from rooted "
        "devices or backups (CWE-312). Auth tokens deserve encrypted "
        "storage."
    )
    category = "auth"
    default_severity = Severity.HIGH
    owasp = ["M3"]
    cwe = ["CWE-312"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Store auth/session tokens in EncryptedSharedPreferences (AndroidX "
        "Security) or the Android Keystore-backed EncryptedFile. Never "
        "write tokens to plaintext SharedPreferences, and exclude token "
        "keys from auto-backup."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/312.html",
        "https://developer.android.com/topic/security/data",
    ]

    _PUT = re.compile(
        r"\bputString\s*\(\s*\"[^\"]*(token|session|auth|jwt|refresh)[^\"]*\"",
        re.IGNORECASE,
    )
    _ENCRYPTED = re.compile(r"\bEncryptedSharedPreferences\b")

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        put_hits = grep(self._PUT.pattern, iter_source_files(ctx), flags=re.IGNORECASE)
        if not put_hits:
            return pass_result(
                self,
                "No auth-token writes to SharedPreferences found in decompiled sources.",
            )
        encrypted = grep(self._ENCRYPTED.pattern, iter_source_files(ctx))
        if encrypted:
            return pass_result(
                self,
                "Token writes use SharedPreferences, but the app also uses "
                "EncryptedSharedPreferences, so token storage is encrypted.",
            )
        return finding(
            self,
            f"{len(put_hits)} auth-token write(s) to SharedPreferences with "
            "no EncryptedSharedPreferences usage anywhere in the app. "
            "Tokens are stored in plaintext.",
            evidence=_hits_to_evidence(
                ctx, put_hits, "Token written to plaintext SharedPreferences"
            ),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "A stolen plaintext token gives full session impersonation; "
                "extraction from backups or rooted devices is low-effort "
                "(High)."
            ),
            confidence_rationale=(
                "The putString call with a token-like key is present at the "
                "cited line, and no EncryptedSharedPreferences usage exists "
                "anywhere in the decompiled sources."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A05 token refresh / expiry handling
# ---------------------------------------------------------------------------

class TokenExpiryHandling(Rule):
    id = "BS-A05"
    title = "Token used without expiry or refresh handling"
    description = (
        "Detects auth/session token reads with no nearby expiry check "
        "(exp, expiry, isExpired, deadline, time comparison) in the same file."
    )
    rationale = (
        "Tokens that are never checked for expiry or refreshed are often "
        "long-lived, widening the window for replay after theft. Absence "
        "of a client-side check may also mean expiry is not enforced at all."
    )
    category = "auth"
    default_severity = Severity.MEDIUM
    owasp = ["M3"]
    cwe = ["CWE-613"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Issue short-lived access tokens with explicit expiry, validate "
        "exp on every use, and implement refresh-token rotation. Enforce "
        "expiry server-side; client-side checks are defense in depth, not "
        "the control."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/613.html",
        "https://mas.owasp.org/MASVS/",
    ]

    _USE = re.compile(
        r"\b(getToken|accessToken|authToken|sessionToken|idToken|refreshToken)\b"
        r"|\bgetString\s*\(\s*\"[^\"]*(token|session|jwt)[^\"]*\"",
        re.IGNORECASE,
    )
    _EXPIRY = re.compile(
        r"\bexp\b|expir|isExpired|deadline|validUntil|notAfter|"
        r"System\s*\.\s*currentTimeMillis|getExpiry|expiresAt|expires_in",
        re.IGNORECASE,
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        flagged = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if not text or not self._USE.search(text):
                continue
            if self._EXPIRY.search(text):
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                if self._USE.search(line):
                    m = self._USE.search(line)
                    h = type("H", (), {"path": path, "line_no": i, "line": line, "match": m})()
                    flagged.append(h)
                    break
        if not flagged:
            return pass_result(
                self,
                "Token usage is accompanied by expiry handling, or no token "
                "reads were found in decompiled sources.",
            )
        return needs_review(
            self,
            f"{len(flagged)} file(s) read auth/session tokens with no "
            "expiry, refresh, or deadline handling visible in the same file. "
            "Static analysis cannot confirm whether the server enforces "
            "token expiry or rotates refresh tokens; review the token "
            "lifecycle server-side before treating this as a vulnerability.",
            evidence=_hits_to_evidence(
                ctx, flagged, "Token read with no expiry handling in file"
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "Non-expiring tokens extend the replay window after theft "
                "(Medium), but only if the server also fails to enforce "
                "expiry, which is unverified."
            ),
            confidence_rationale=(
                "No expiry-related check was found near token usage in the "
                "client, but token lifetime policy is a server-side property "
                "that static analysis cannot observe."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A06 auth secrets in logs / exceptions
# ---------------------------------------------------------------------------

class AuthSecretsInLogs(Rule):
    id = "BS-A06"
    title = "Authentication secrets written to logs or stack traces"
    description = (
        "Detects Log.* / System.out / printStackTrace calls that include "
        "password, token, session, or secret values."
    )
    rationale = (
        "Logcat is readable by other apps on older platforms and is "
        "routinely captured in bug reports and crash dumps. Logging "
        "credentials or tokens leaks them to anyone with log access "
        "(CWE-532)."
    )
    category = "auth"
    default_severity = Severity.MEDIUM
    owasp = ["M3"]
    cwe = ["CWE-532"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Never log passwords, tokens, or session identifiers. Log only "
        "redacted placeholders (e.g. token prefix + \"...\"). Strip "
        "verbose logging from release builds with ProGuard/R8 or "
        "BuildConfig-gated logging wrappers."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/532.html",
        "https://mas.owasp.org/MASVS/",
    ]

    _LOG = re.compile(r"\bLog\s*\.\s*[vdiewtf]+\s*\(|System\s*\.\s*out\s*\.\s*print|printStackTrace\s*\(")
    _SECRET = re.compile(
        r"password|passwd|\bpwd\b|token|sessionid|session_id|authtoken|auth_token"
        r"|api[_-]?key|secret|credential|privatekey",
        re.IGNORECASE,
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if not text:
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                if self._LOG.search(line) and self._SECRET.search(line):
                    m = self._SECRET.search(line)
                    h = type("H", (), {"path": path, "line_no": i, "line": line, "match": m})()
                    hits.append(h)
                    if len(hits) >= 200:
                        break
        if not hits:
            return pass_result(
                self,
                "No logging calls containing authentication-secret keywords "
                "found in decompiled sources.",
            )
        return finding(
            self,
            f"{len(hits)} logging call(s) include password/token/session "
            "keywords, leaking authentication secrets to logcat, bug "
            "reports, or crash dumps.",
            evidence=_hits_to_evidence(
                ctx, hits, "Auth secret passed to a logging call"
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Leaked tokens/passwords enable direct impersonation, but "
                "exploitation needs log access, which is restricted on "
                "modern Android (Medium)."
            ),
            confidence_rationale=(
                "The logging call with the secret keyword is present verbatim "
                "at the cited line; the leak is deterministic."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A07 weak local PIN authentication
# ---------------------------------------------------------------------------

class WeakLocalPin(Rule):
    id = "BS-A07"
    title = "Weak local PIN authentication without lockout"
    description = (
        "Detects short numeric PIN checks (length()==4, comparison against "
        "a 4-digit literal) with no failed-attempt counter or lockout in "
        "the same file."
    )
    rationale = (
        "A 4-digit PIN has only 10,000 combinations. Without rate limiting "
        "or lockout (CWE-307), it falls to brute force; enforcing it "
        "purely client-side makes bypass trivial."
    )
    category = "auth"
    default_severity = Severity.HIGH
    owasp = ["M3"]
    cwe = ["CWE-307"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Do not rely on short client-side PINs as the sole authenticator. "
        "Verify credentials server-side, enforce attempt limits and "
        "progressive delays on the backend, and prefer device biometrics "
        "bound to Keystore keys over local PIN comparisons."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/307.html",
        "https://mas.owasp.org/MASVS/",
    ]

    _PIN = re.compile(
        r"\bpin\b.{0,30}\.length\s*\(\s*\)\s*==\s*4"
        r"|\.length\s*\(\s*\)\s*==\s*4.{0,30}\bpin\b"
        r"|\bpin\b.{0,40}\.equals\s*\(\s*\"\d{4}\"\s*\)"
        r"|\.equals\s*\(\s*\"\d{4}\"\s*\).{0,40}\bpin\b",
        re.IGNORECASE,
    )
    _LOCKOUT = re.compile(
        r"attempt|lockout|locked|remaining|max_attempts|MAX_ATTEMPTS|"
        r"too.?many|cooldown|throttl|delay",
        re.IGNORECASE,
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        flagged = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if not text:
                continue
            m_use = self._PIN.search(text)
            if not m_use:
                continue
            if self._LOCKOUT.search(text):
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                if self._PIN.search(line):
                    m = self._PIN.search(line)
                    h = type("H", (), {"path": path, "line_no": i, "line": line, "match": m})()
                    flagged.append(h)
                    break
        if not flagged:
            return pass_result(
                self,
                "No weak local PIN check without lockout found in decompiled "
                "sources.",
            )
        return needs_review(
            self,
            f"{len(flagged)} file(s) enforce a short numeric PIN locally "
            "with no failed-attempt counter or lockout visible. Client-side "
            "indicator only: static analysis cannot confirm whether "
            "attempt limiting or credential verification happens "
            "server-side, nor whether the PIN gate is the real enforcement "
            "point. Confirm server-side throttling before rating this.",
            evidence=_hits_to_evidence(
                ctx, flagged, "Weak PIN check with no lockout in file"
            ),
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            severity_rationale=(
                "An unthrottled 4-digit PIN is brute-forcible (High), but "
                "only if no server-side attempt limiting exists, which "
                "static analysis cannot verify."
            ),
            confidence_rationale=(
                "The weak PIN comparison is real, yet enforcement context "
                "(server verification, rate limits) is invisible from the "
                "APK alone."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A08 insecure biometric fallback
# ---------------------------------------------------------------------------

class InsecureBiometricFallback(Rule):
    id = "BS-A08"
    title = "Insecure biometric fallback to weak local check"
    description = (
        "Detects BiometricPrompt flows whose fallback is a weak local "
        "check: device-credential allowance combined with hardcoded PIN "
        "comparisons, or error handlers that grant access without "
        "verification."
    )
    rationale = (
        "Biometrics are only as strong as their fallback. A fallback that "
        "accepts a hardcoded or short PIN, or an error path that proceeds "
        "without verification, reduces the whole flow to the weakest link."
    )
    category = "auth"
    default_severity = Severity.HIGH
    owasp = ["M3"]
    cwe = ["CWE-304"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Use CryptoObject-bound biometric authentication with "
        "setUserAuthenticationRequired(true) keys so a successful biometric "
        "is cryptographically required. Never fall back to hardcoded or "
        "short local secrets; on biometric failure, require full "
        "credential re-authentication verified server-side."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/304.html",
        "https://developer.android.com/identity/sign-in/biometric-auth",
    ]

    _BIO = re.compile(r"\bBiometricPrompt\b|setAllowedAuthenticators|setDeviceCredentialAllowed")
    _WEAK_FALLBACK = re.compile(
        r"setDeviceCredentialAllowed\s*\(\s*true\s*\)"
        r"|\bpin\b.{0,40}\.equals\s*\(\s*\"[^\"]+\"\s*\)"
        r"|onAuthenticationError.{0,200}(grantAccess|proceed|unlock|success|setResult\s*\(\s*RESULT_OK)",
        re.IGNORECASE | re.DOTALL,
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        flagged = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if not text or not self._BIO.search(text):
                continue
            if not self._WEAK_FALLBACK.search(text):
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                if self._BIO.search(line):
                    m = self._BIO.search(line)
                    h = type("H", (), {"path": path, "line_no": i, "line": line, "match": m})()
                    flagged.append(h)
                    break
        if not flagged:
            return pass_result(
                self,
                "Biometric usage found, but no weak fallback (hardcoded PIN, "
                "unverified error-path grant) detected.",
            )
        return needs_review(
            self,
            f"{len(flagged)} file(s) use biometrics alongside a weak "
            "fallback: device-credential allowance, a hardcoded PIN "
            "comparison, or an error handler that grants access without "
            "verification. Static analysis cannot confirm the real "
            "fallback authenticator's strength or whether the protected "
            "operation is re-verified server-side; review the full auth "
            "flow before rating this.",
            evidence=_hits_to_evidence(
                ctx, flagged, "Biometric flow with weak fallback indicator"
            ),
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            severity_rationale=(
                "A weak fallback reduces biometric auth to its weakest "
                "link, potentially bypassing the biometric entirely (High), "
                "but the actual fallback strength needs manual review."
            ),
            confidence_rationale=(
                "The biometric API and the weak-fallback pattern coexist in "
                "the file, but whether the fallback path is reachable and "
                "exploitable cannot be proven statically."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A09 hardcoded privileged roles
# ---------------------------------------------------------------------------

class HardcodedPrivilegedRoles(Rule):
    id = "BS-A09"
    title = "Hardcoded privileged roles enabling hidden features"
    description = (
        "Detects SUPER_ADMIN / SUPERUSER-style role constants or literals "
        "used to gate debug menus or hidden features."
    )
    rationale = (
        "Hardcoded privileged roles baked into the client let an attacker "
        "who enables the flag reach hidden or administrative functionality "
        "that was never meant for production users."
    )
    category = "auth"
    default_severity = Severity.MEDIUM
    owasp = ["M3"]
    cwe = ["CWE-798"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Do not ship privileged-role flags in production clients. Resolve "
        "roles server-side per session, remove debug menus from release "
        "builds, and gate any internal tooling behind separate build "
        "flavors."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASVS/",
    ]

    _ROLE = re.compile(
        r"\bROLE_SUPER_ADMIN\b|\bSUPERUSER\b|\bSUPER_ADMIN\b|\"super.?admin\"|\"superuser\"",
        re.IGNORECASE,
    )
    _GATE = re.compile(r"\bif\b|equals|hasRole|debug|hidden|menu|feature|enabl", re.IGNORECASE)

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if not text or not self._ROLE.search(text):
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                if self._ROLE.search(line) and self._GATE.search(line):
                    m = self._ROLE.search(line)
                    h = type("H", (), {"path": path, "line_no": i, "line": line, "match": m})()
                    hits.append(h)
                    if len(hits) >= 200:
                        break
        if not hits:
            return pass_result(
                self,
                "No hardcoded privileged-role constants gating features "
                "found in decompiled sources.",
            )
        return finding(
            self,
            f"{len(hits)} hardcoded privileged-role reference(s) gate a "
            "feature or debug path. Enabling the role client-side can "
            "expose hidden functionality.",
            evidence=_hits_to_evidence(
                ctx, hits, "Hardcoded privileged role gating a feature"
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Hidden privileged features expand attack surface, but "
                "impact depends on what the gated code actually does "
                "(Medium)."
            ),
            confidence_rationale=(
                "The privileged-role literal and a gating construct appear "
                "on the same line; the feature it guards may need manual "
                "review to assess impact."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A10 client trusts authorization flag from client-controlled input
# ---------------------------------------------------------------------------

class ClientControlledAuthzFlag(Rule):
    id = "BS-A10"
    title = "Authorization flag trusted from client-controlled input"
    description = (
        "Detects isPremium/isAdmin/role flags read from Intent extras or "
        "SharedPreferences (both client-controlled) and used to unlock "
        "features."
    )
    rationale = (
        "Intent extras and SharedPreferences are writable by the app "
        "itself and, on rooted devices or via repackaging, by an attacker. "
        "Trusting them for authorization is CWE-602 client-side "
        "enforcement; the server must be the authority."
    )
    category = "auth"
    default_severity = Severity.HIGH
    owasp = ["M3"]
    cwe = ["CWE-602"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Never derive authorization from Intent extras or local "
        "preferences. Resolve entitlements server-side from the "
        "authenticated session on each privileged request; use local "
        "flags only as a UI cache that the server can override."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/602.html",
        "https://mas.owasp.org/MASVS/",
    ]

    _FLAG_READ = re.compile(
        r"getIntent\s*\(\s*\)\s*\.\s*get\w+Extra\s*\(\s*\"(isAdmin|isPremium|isVip|role|admin|premium)\""
        r"|\b(getBoolean|getString|getInt)\s*\(\s*\"(isAdmin|isPremium|isVip|role|admin|premium)\"",
        re.IGNORECASE,
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if not text:
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                m = self._FLAG_READ.search(line)
                if m and ("if" in line or "if" in (text.splitlines()[i] if i < len(text.splitlines()) else "")):
                    h = type("H", (), {"path": path, "line_no": i, "line": line, "match": m})()
                    hits.append(h)
                    if len(hits) >= 200:
                        break
        # also accept flag reads assigned to a boolean used later in an if
        if not hits:
            for path in iter_source_files(ctx):
                text = read_text_capped(path)
                if not text or not self._FLAG_READ.search(text):
                    continue
                if re.search(r"\bif\s*\([^;{}]*\b(isAdmin|isPremium|isVip)\b", text, re.IGNORECASE):
                    for i, line in enumerate(text.splitlines(), start=1):
                        m = self._FLAG_READ.search(line)
                        if m:
                            h = type("H", (), {"path": path, "line_no": i, "line": line, "match": m})()
                            hits.append(h)
                            break
        if not hits:
            return pass_result(
                self,
                "No authorization flags read from Intent extras or "
                "SharedPreferences found gating features.",
            )
        if _server_validated_anywhere(ctx):
            return pass_result(
                self,
                "Client-controlled authorization flags exist, but sources "
                "also show server-side validation, so the flag is not the "
                "sole enforcement point observed.",
            )
        return needs_review(
            self,
            "An authorization flag (isAdmin/isPremium/role) is read from "
            "Intent extras or SharedPreferences - both client-controlled - "
            "and used to unlock features, with no server-side validation "
            "found in the decompiled sources. Server-side authorization "
            "cannot be confirmed statically; verify that privileged "
            "operations are authorized on the backend per session.",
            evidence=_hits_to_evidence(
                ctx, hits, "Authorization flag read from client-controlled input"
            ),
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            severity_rationale=(
                "If the server honors the client flag, privilege escalation "
                "is trivial via repackaging or IPC manipulation (High); "
                "server behavior is unverified."
            ),
            confidence_rationale=(
                "The flag read and its use in a feature gate are real, but "
                "whether the server independently authorizes the operation "
                "cannot be proven from the APK."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A11 biometric authentication without CryptoObject
# ---------------------------------------------------------------------------

class BiometricWithoutCryptoObject(Rule):
    id = "BS-A11"
    title = "Biometric authentication without CryptoObject"
    description = (
        "Detects BiometricPrompt.authenticate() calls where no CryptoObject "
        "appears within 10 lines, meaning the biometric result is not "
        "cryptographically bound to a Keystore operation."
    )
    rationale = (
        "Without a CryptoObject, a successful biometric prompt only "
        "returns a boolean that client code must trust; hooking or "
        "repackaging can spoof the callback. Binding the biometric to a "
        "Keystore crypto operation makes the authentication "
        "unforgeable (CWE-304)."
    )
    category = "auth"
    default_severity = Severity.MEDIUM
    owasp = ["M3"]
    cwe = ["CWE-304"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Always authenticate with a CryptoObject: create the Cipher/Mac/"
        "Signature with a Keystore key that has "
        "setUserAuthenticationRequired(true), wrap it in "
        "BiometricPrompt.CryptoObject, and only proceed when the crypto "
        "operation succeeds."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/304.html",
        "https://developer.android.com/identity/sign-in/biometric-auth",
    ]

    _AUTHENTICATE = re.compile(r"\.authenticate\s*\(")
    _BIO = re.compile(r"\bBiometricPrompt\b")

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        flagged = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if not text or not self._BIO.search(text):
                continue
            lines = text.splitlines()
            for i, line in enumerate(lines, start=1):
                if not self._AUTHENTICATE.search(line):
                    continue
                lo = max(0, i - 1 - 10)
                hi = min(len(lines), i + 10)
                window = "\n".join(lines[lo:hi])
                if "CryptoObject" in window:
                    continue
                m = self._AUTHENTICATE.search(line)
                h = type("H", (), {"path": path, "line_no": i, "line": line, "match": m})()
                flagged.append(h)
                if len(flagged) >= 200:
                    break
        if not flagged:
            return pass_result(
                self,
                "BiometricPrompt.authenticate() calls are bound to a "
                "CryptoObject, or no biometric authentication was found.",
            )
        return finding(
            self,
            f"{len(flagged)} BiometricPrompt.authenticate() call(s) with no "
            "CryptoObject within 10 lines. The biometric result is a plain "
            "boolean callback that repackaged or hooked code can spoof.",
            evidence=_hits_to_evidence(
                ctx, flagged, "Biometric auth without CryptoObject nearby"
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "An unbound biometric check can be bypassed by spoofing the "
                "success callback, undermining the authentication (Medium)."
            ),
            confidence_rationale=(
                "The authenticate() call is real and no CryptoObject "
                "appears within 10 lines, but a CryptoObject could "
                "theoretically be wired up farther away."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A12 OAuth implicit flow
# ---------------------------------------------------------------------------

class OAuthImplicitFlow(Rule):
    id = "BS-A12"
    title = "OAuth implicit flow (response_type=token)"
    description = (
        "Detects the literal string \"response_type=token\" in sources, "
        "indicating use of the deprecated OAuth 2.0 implicit grant."
    )
    rationale = (
        "The implicit flow returns access tokens in the URL fragment, "
        "where they leak into browser history, logs, and referers, and it "
        "offers no client authentication. OAuth 2.1 removed it; native "
        "apps should use authorization code + PKCE."
    )
    category = "auth"
    default_severity = Severity.MEDIUM
    owasp = ["M3"]
    cwe = ["CWE-287"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Migrate to authorization code flow with PKCE (RFC 8252 for native "
        "apps). Never request response_type=token; keep tokens out of the "
        "URL fragment."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/287.html",
        "https://datatracker.ietf.org/doc/html/rfc8252",
    ]

    _RX = re.compile(r"response_type\s*=\s*token")

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(self._RX.pattern, iter_source_files(ctx))
        if not hits:
            return pass_result(
                self,
                "No response_type=token literals found in decompiled sources.",
            )
        return finding(
            self,
            f"{len(hits)} response_type=token literal(s) found: the app "
            "uses the deprecated OAuth 2.0 implicit flow, which exposes "
            "access tokens in the URL fragment.",
            evidence=_hits_to_evidence(
                ctx, hits, "OAuth implicit flow requested"
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Tokens delivered in the URL fragment leak into history, "
                "logs, and referers, enabling token theft (Medium)."
            ),
            confidence_rationale=(
                "The response_type=token literal is present verbatim at "
                "the cited line; no inference required."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A13 auth token in URL query string
# ---------------------------------------------------------------------------

class AuthTokenInUrlQuery(Rule):
    id = "BS-A13"
    title = "Auth token in URL query string"
    description = (
        "Detects hardcoded http(s) URL literals carrying access_token= or "
        "auth_token= query parameters."
    )
    rationale = (
        "URLs are logged by proxies, servers, analytics SDKs, and "
        "WebViews; tokens in the query string leak into logs and caches "
        "(CWE-598). Tokens belong in the Authorization header."
    )
    category = "auth"
    default_severity = Severity.MEDIUM
    owasp = ["M3"]
    cwe = ["CWE-598"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Send tokens in the Authorization header over TLS, never in the "
        "URL. Rotate any token that was ever placed in a query string."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/598.html",
        "https://mas.owasp.org/MASVS/",
    ]

    _RX = re.compile(
        r"https?://[^\s\"'<>]*[?&](?:access_token|auth_token)=",
        re.IGNORECASE,
    )

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = grep(self._RX.pattern, iter_source_files(ctx), flags=re.IGNORECASE)
        if not hits:
            return pass_result(
                self,
                "No URL literals with access_token=/auth_token= query "
                "parameters found.",
            )
        return finding(
            self,
            f"{len(hits)} URL literal(s) carry an auth token in the query "
            "string, exposing the token to server/proxy logs and caches.",
            evidence=_hits_to_evidence(
                ctx, hits, "Auth token in URL query parameter"
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Query-string tokens end up in logs outside the app's "
                "control and enable session impersonation (Medium)."
            ),
            confidence_rationale=(
                "The URL and the token parameter name were matched "
                "literally on a real source line."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A14 device-credential fallback without isDeviceSecure check
# ---------------------------------------------------------------------------

class LockscreenFallbackWithoutSecureCheck(Rule):
    id = "BS-A14"
    title = "Device-credential fallback without isDeviceSecure check"
    description = (
        "Detects createConfirmDeviceCredentialIntent() usage in files that "
        "never call KeyguardManager.isDeviceSecure(), meaning the app does "
        "not verify a lock screen is actually set before relying on it."
    )
    rationale = (
        "On devices with no PIN/pattern/password set, the device-"
        "credential prompt may trivially succeed or be absent, silently "
        "downgrading the authentication. Checking isDeviceSecure() first "
        "is the documented guard."
    )
    category = "auth"
    default_severity = Severity.LOW
    owasp = ["M3"]
    cwe = ["CWE-304"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Call KeyguardManager.isDeviceSecure() before launching the "
        "credential-confirmation intent; if no secure lock screen is set, "
        "require the user to set one or fall back to full credential "
        "authentication."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/304.html",
        "https://developer.android.com/reference/android/app/KeyguardManager#isDeviceSecure()",
    ]

    _INTENT = re.compile(r"\bcreateConfirmDeviceCredentialIntent\s*\(")
    _SECURE = re.compile(r"\bisDeviceSecure\s*\(")

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        flagged = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if not text or not self._INTENT.search(text):
                continue
            if self._SECURE.search(text):
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                if self._INTENT.search(line):
                    m = self._INTENT.search(line)
                    h = type("H", (), {"path": path, "line_no": i, "line": line, "match": m})()
                    flagged.append(h)
                    break
        if not flagged:
            return pass_result(
                self,
                "createConfirmDeviceCredentialIntent is always paired with "
                "an isDeviceSecure() check, or is not used.",
            )
        return needs_review(
            self,
            f"{len(flagged)} file(s) launch a device-credential "
            "confirmation intent without checking "
            "KeyguardManager.isDeviceSecure() in the same file. Static "
            "analysis cannot confirm whether the check happens elsewhere "
            "(e.g. a helper class) or what the device's lock-screen state "
            "is; review the flow before rating this.",
            evidence=_hits_to_evidence(
                ctx, flagged,
                "Device-credential intent without isDeviceSecure in file",
            ),
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "If no lock screen is set, the fallback may grant access "
                "with no real authentication (Low: requires an unusual "
                "device configuration)."
            ),
            confidence_rationale=(
                "The intent launch is real and no isDeviceSecure() call "
                "appears in the same file, but the check could live in "
                "another class."
            ),
        )


# ---------------------------------------------------------------------------
# BS-A15 hardcoded test credential pairs near login code
# ---------------------------------------------------------------------------

class HardcodedTestCredentialPairs(Rule):
    id = "BS-A15"
    title = "Hardcoded test credential pairs near login code"
    description = (
        "Detects (\"admin\", \"admin\"), (\"test\", \"test\") or "
        "\"password123\" literals in files mentioning login/authenticate/"
        "sign-in, indicating test credentials shipped in the app."
    )
    rationale = (
        "Test credentials baked into the client are extractable by "
        "decompilation and often work against production backends, "
        "acting as standing backdoors (CWE-798)."
    )
    category = "auth"
    default_severity = Severity.MEDIUM
    owasp = ["M3"]
    cwe = ["CWE-798"]
    masvs = ["MSTG-AUTH"]
    remediation = (
        "Remove test credential pairs from the client entirely. Provision "
        "test users in a staging backend, and add a release-gate check "
        "that fails the build when known test literals appear."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASVS/",
    ]

    _PAIR = re.compile(r'"(admin|test)"\s*,\s*"\1"|"password123"')
    _AUTH_CTX = re.compile(r"(?i)(login|authenticate|signin|sign_in)")

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)

    def check(self, ctx: ScanContext):
        hits = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if not text or not self._AUTH_CTX.search(text):
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                if self._PAIR.search(line):
                    m = self._PAIR.search(line)
                    h = type("H", (), {"path": path, "line_no": i, "line": line, "match": m})()
                    hits.append(h)
                    if len(hits) >= 200:
                        break
        if not hits:
            return pass_result(
                self,
                "No hardcoded test credential pairs found near login/"
                "authentication code.",
            )
        return finding(
            self,
            f"{len(hits)} hardcoded test credential pair(s) found near "
            "login/authentication code. Anyone who decompiles the APK can "
            "read and reuse them.",
            evidence=_hits_to_evidence(
                ctx, hits, "Hardcoded test credential pair in auth code"
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Test credentials may grant access to real backends; "
                "impact depends on whether the backend accepts them "
                "(Medium)."
            ),
            confidence_rationale=(
                "The credential pair literal appears verbatim inside "
                "authentication-related code at the cited line."
            ),
        )


RULES: list[Rule] = [
    ClientSideOnlyAuthorization(),
    HardcodedAuthBypass(),
    HardcodedTestAccounts(),
    InsecureTokenPersistence(),
    TokenExpiryHandling(),
    AuthSecretsInLogs(),
    WeakLocalPin(),
    InsecureBiometricFallback(),
    HardcodedPrivilegedRoles(),
    ClientControlledAuthzFlag(),
    BiometricWithoutCryptoObject(),
    OAuthImplicitFlow(),
    AuthTokenInUrlQuery(),
    LockscreenFallbackWithoutSecureCheck(),
    HardcodedTestCredentialPairs(),
]

__all__ = ["RULES"] + [type(r).__name__ for r in RULES]
