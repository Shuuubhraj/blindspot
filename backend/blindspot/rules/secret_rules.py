"""Hardcoded secrets detection rules (BS-X01 .. BS-X20).

Category: secrets. Static checks over decompiled sources and decoded text
artifacts (resources, assets, gradle files) for embedded credentials, API
keys, tokens and other secret material that ships inside the APK. Anything
hardcoded in the app is recoverable by decompiling it, so these findings
are about secrets that must live server-side or in the Android Keystore.

Rule index
----------
BS-X01  AWS access key ID (AKIA...)
BS-X02  AWS secret access key (40-char token in aws/secret context)
BS-X03  Google API key (AIza...)
BS-X04  Firebase Realtime Database URL
BS-X05  Stripe API keys (sk_live_/sk_test_/pk_live_/pk_test_)
BS-X06  Slack tokens (xoxb/xoxp/xoxa/xoxr/xoxs-...)
BS-X07  GitHub tokens (ghp_/gho_/github_pat_)
BS-X08  Generic high-entropy secret assigned to a secret-named variable
BS-X09  Private key material (PEM blocks)
BS-X10  Keystore passwords (storePassword/keyPassword)
BS-X11  OAuth client secrets
BS-X12  Hardcoded JWT
BS-X13  Twilio credentials (AC.../SK...)
BS-X14  SendGrid API keys (SG....)
BS-X15  Azure Storage connection strings (AccountKey=...)
BS-X16  Basic-auth credentials embedded in URLs
BS-X17  Secret-looking AndroidManifest meta-data values
BS-X18  Secrets in BuildConfig / gradle files
BS-X19  Facebook app secret
BS-X20  Hardcoded password used near crypto APIs
"""

from __future__ import annotations

import re

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
    Hit,
    evidence_from_hit,
    evidence_simple,
    grep,
    iter_source_files,
    iter_text_artifacts,
    java_string_literals,
    looks_like_secret,
    read_text_capped,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

#: Values that are obviously placeholders, documentation or test data.
_TEST_VALUE_RX = re.compile(
    r"(?i)(example|sample|test|dummy|placeholder|fake|changeme|todo|x{3,}"
    r"|your[-_ ]?(key|secret|token|password)|insert[-_ ]?(key|secret)"
    r"|replace[-_ ]?me|\bnone\b)"
)

#: The AWS documentation example key - must never be flagged.
_AWS_EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"


def _is_test_value(value: str) -> bool:
    """True for placeholders, docs examples and test data."""
    v = value.strip()
    return bool(_TEST_VALUE_RX.search(v)) or v.startswith("<")


def _window_text(text: str, line_no: int, radius: int = 5) -> str:
    """Return the lines within +/- radius of a 1-based line number."""
    lines = text.splitlines()
    lo = max(0, line_no - 1 - radius)
    hi = min(len(lines), line_no + radius)
    return "\n".join(lines[lo:hi])


def _all_text_files(ctx: ScanContext):
    """Decompiled sources plus decoded text artifacts (res/assets)."""
    yield from iter_source_files(ctx)
    yield from iter_text_artifacts(ctx)


class _SecretRule(Rule):
    """Base for secret rules: secrets hide in code AND in assets/resources."""

    category = "secrets"
    masvs = ["MSTG-STORAGE"]

    def applies(self, ctx: ScanContext) -> bool:
        return True


# ---------------------------------------------------------------------------
# BS-X01  AWS access key ID
# ---------------------------------------------------------------------------

class RuleX01AwsAccessKey(_SecretRule):
    id = "BS-X01"
    title = "Hardcoded AWS access key ID"
    description = (
        "An AWS access key ID (AKIA...) is embedded in the app's code or "
        "resources. Access key IDs are half of an AWS credential pair; "
        "shipped in the APK they can be extracted by anyone."
    )
    rationale = (
        "APKs are trivially decompiled, so any embedded AWS key ID is public. "
        "Combined with the matching secret key (often nearby or in the same "
        "build) it grants AWS API access as the embedded IAM identity."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Remove the key from the app. Call AWS through your own backend or "
        "use Amazon Cognito for mobile access with short-lived, scoped "
        "credentials. Rotate any exposed key immediately via the AWS console."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(r"\bAKIA[0-9A-Z]{16}\b", _all_text_files(ctx)):
            key = hit.match.group(0)
            if key == _AWS_EXAMPLE_KEY or _is_test_value(key):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"Hardcoded AWS access key ID starting with {key[:8]}",
                )
            )
        if not evidence:
            return pass_result(self, "No hardcoded AWS access key IDs found.")
        return finding(
            self,
            f"Hardcoded AWS access key ID in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "An exposed AWS access key ID is half of a credential pair; "
                "with the matching secret it grants direct AWS API access, "
                "so impact is HIGH."
            ),
            confidence_rationale=(
                "The AKIA-prefixed 20-character identifier matches the AWS "
                "access key ID format exactly; the AWS documentation example "
                "key is explicitly excluded."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X02  AWS secret access key
# ---------------------------------------------------------------------------

class RuleX02AwsSecretKey(_SecretRule):
    id = "BS-X02"
    title = "Hardcoded AWS secret access key"
    description = (
        "A 40-character base64-style token appears on a line mentioning aws "
        "or secret, matching the shape of an AWS secret access key. The "
        "secret key is the sensitive half of the AWS credential pair."
    )
    rationale = (
        "AWS secret access keys are 40-character base64 strings. Embedded in "
        "the APK they can be extracted and used directly against AWS APIs."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Remove the secret from the app and rotate it immediately in the AWS "
        "console. Move AWS calls behind your own backend or use Cognito with "
        "short-lived credentials."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(r"""["']([A-Za-z0-9/+=]{40})["']""", _all_text_files(ctx)):
            if not re.search(r"(?i)(aws|secret)", hit.line):
                continue
            token = hit.match.group(1)
            if _is_test_value(token):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    "40-character token on an aws/secret line (AWS secret "
                    "access key shape)",
                )
            )
        if not evidence:
            return pass_result(
                self, "No AWS-shaped secret keys in aws/secret context found."
            )
        return finding(
            self,
            f"Possible AWS secret access key in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "A genuine AWS secret access key grants direct AWS API access "
                "as the embedded identity, so impact is HIGH."
            ),
            confidence_rationale=(
                "The 40-character base64 token matches the AWS secret key "
                "shape and sits on a line mentioning aws/secret, but other "
                "40-char tokens are possible, so confidence is MEDIUM."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X03  Google API key
# ---------------------------------------------------------------------------

class RuleX03GoogleApiKey(_SecretRule):
    id = "BS-X03"
    title = "Hardcoded Google API key"
    description = (
        "A Google API key (AIza...) is embedded in the app. Unrestricted "
        "Google API keys can be abused for Maps, Places, Firebase and other "
        "billable Google APIs at the owner's expense."
    )
    rationale = (
        "Google API keys have a fixed, distinctive format. Shipped in the "
        "APK they can be extracted and used until the key is restricted or "
        "rotated in the Google Cloud console."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Restrict the key in the Google Cloud console (Android app "
        "restriction with package name + SHA-1, plus API restrictions) and "
        "rotate it. Prefer proxying Google API calls through your backend."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(r"\bAIza[0-9A-Za-z_\-]{35}\b", _all_text_files(ctx)):
            key = hit.match.group(0)
            if _is_test_value(key):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"Hardcoded Google API key starting with {key[:8]}",
                )
            )
        if not evidence:
            return pass_result(self, "No hardcoded Google API keys found.")
        return finding(
            self,
            f"Hardcoded Google API key in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "An unrestricted Google API key can be abused for billable "
                "Google APIs (Maps, Places, etc.) at the owner's expense."
            ),
            confidence_rationale=(
                "The AIza-prefixed 39-character value matches the Google API "
                "key format exactly."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X04  Firebase Realtime Database URL
# ---------------------------------------------------------------------------

class RuleX04FirebaseUrl(_SecretRule):
    id = "BS-X04"
    title = "Firebase Realtime Database URL embedded"
    description = (
        "A *.firebaseio.com URL is embedded in the app, exposing the "
        "Firebase Realtime Database endpoint. If the database security rules "
        "are permissive, its data is readable or writable by anyone."
    )
    rationale = (
        "The database URL itself is not a credential, but it discloses the "
        "backend endpoint; combined with weak Firebase rules it leads to "
        "data exposure. Flagging the URL prompts a rules review."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Review the Firebase Realtime Database security rules: deny by "
        "default and require Firebase Authentication with per-user path "
        "rules. Do not rely on URL obscurity."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(r"\b[a-z0-9-]+\.firebaseio\.com\b", _all_text_files(ctx)):
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"Firebase Realtime Database URL: {hit.match.group(0)[:60]}",
                )
            )
        if not evidence:
            return pass_result(self, "No Firebase Realtime Database URLs found.")
        return finding(
            self,
            f"Firebase Realtime Database URL in {len(evidence)} location(s) - "
            "verify the database security rules.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "The URL alone is not exploitable, but with permissive "
                "Firebase rules it becomes a direct data-exposure path, so "
                "impact is MEDIUM pending a rules review."
            ),
            confidence_rationale=(
                "The *.firebaseio.com hostname is explicit in the matched "
                "text; no inference required."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X05  Stripe keys
# ---------------------------------------------------------------------------

class RuleX05StripeKey(_SecretRule):
    id = "BS-X05"
    title = "Hardcoded Stripe API key"
    description = (
        "A Stripe API key (sk_live_, sk_test_, pk_live_, pk_test_) is "
        "embedded in the app. Secret keys (sk_) grant full API access to "
        "charges, customers and payouts."
    )
    rationale = (
        "Stripe keys have fixed prefixes. A leaked sk_live_ key lets an "
        "attacker create charges, read customer data and move funds via the "
        "Stripe API."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Never ship secret keys (sk_) in the app - keep them server-side "
        "only. Publishable keys (pk_) are safe client-side by design but "
        "should still be rotated if exposed unexpectedly. Roll any exposed "
        "secret key in the Stripe dashboard immediately."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(
            r"\b(?:sk_live_|sk_test_|pk_live_|pk_test_)[0-9A-Za-z]{20,}\b",
            _all_text_files(ctx),
        ):
            key = hit.match.group(0)
            if _is_test_value(key):
                continue
            kind = "secret" if key.startswith("sk_") else "publishable"
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"Hardcoded Stripe {kind} key starting with {key[:11]}",
                )
            )
        if not evidence:
            return pass_result(self, "No hardcoded Stripe API keys found.")
        return finding(
            self,
            f"Hardcoded Stripe API key in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "A leaked Stripe secret key grants full API access (charges, "
                "customers, payouts); even publishable keys expand the attack "
                "surface, so impact is HIGH."
            ),
            confidence_rationale=(
                "The sk_live_/sk_test_/pk_live_/pk_test_ prefix with a long "
                "alphanumeric suffix matches the Stripe key format exactly."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X06  Slack tokens
# ---------------------------------------------------------------------------

class RuleX06SlackToken(_SecretRule):
    id = "BS-X06"
    title = "Hardcoded Slack token"
    description = (
        "A Slack token (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-) is embedded in the "
        "app. Slack tokens grant API access to the workspace: reading "
        "messages, posting, and managing channels depending on scopes."
    )
    rationale = (
        "Slack tokens have distinctive xox prefixes. Embedded in the APK "
        "they can be extracted and used against the Slack API with the "
        "token's granted scopes."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Remove the token from the app and revoke it in the Slack app "
        "management console. Route Slack integrations through your backend "
        "so tokens never ship to clients."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", _all_text_files(ctx)):
            token = hit.match.group(0)
            if _is_test_value(token):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"Hardcoded Slack token starting with {token[:9]}",
                )
            )
        if not evidence:
            return pass_result(self, "No hardcoded Slack tokens found.")
        return finding(
            self,
            f"Hardcoded Slack token in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "A Slack token grants API access to the workspace (messages, "
                "channels) within its scopes, so impact is HIGH."
            ),
            confidence_rationale=(
                "The xox[baprs]- prefix with a long token body matches the "
                "Slack token format exactly."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X07  GitHub tokens
# ---------------------------------------------------------------------------

class RuleX07GithubToken(_SecretRule):
    id = "BS-X07"
    title = "Hardcoded GitHub token"
    description = (
        "A GitHub token (ghp_, gho_, github_pat_) is embedded in the app. "
        "These tokens grant API access to repositories and organizations "
        "within their scopes, including private code."
    )
    rationale = (
        "GitHub personal access tokens and OAuth tokens have fixed prefixes. "
        "Shipped in the APK they can be extracted and used against the "
        "GitHub API as the token owner."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Remove the token from the app and revoke it immediately at "
        "github.com/settings/tokens. Use short-lived, fine-grained tokens "
        "server-side only; never ship them in client builds."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(
            r"\b(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{20,}\b",
            _all_text_files(ctx),
        ):
            token = hit.match.group(0)
            if _is_test_value(token):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"Hardcoded GitHub token starting with {token[:8]}",
                )
            )
        if not evidence:
            return pass_result(self, "No hardcoded GitHub tokens found.")
        return finding(
            self,
            f"Hardcoded GitHub token in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "A GitHub token grants API access to repositories and "
                "organizations in its scopes, potentially including private "
                "source code, so impact is HIGH."
            ),
            confidence_rationale=(
                "The ghp_/gho_/github_pat_ prefix with a long token body "
                "matches the GitHub token format exactly."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X08  Generic high-entropy secret in a secret-named variable
# ---------------------------------------------------------------------------

class RuleX08GenericHighEntropySecret(_SecretRule):
    id = "BS-X08"
    title = "High-entropy string assigned to a secret-named variable"
    description = (
        "A string literal with secret-like entropy or structure is assigned "
        "to a variable named like api_key, secret, token or password. This "
        "catches hardcoded credentials that do not match a known vendor "
        "format."
    )
    rationale = (
        "Vendor-specific patterns miss custom or lesser-known secrets. "
        "Combining a secret-suggestive variable name with a high-entropy "
        "literal is a strong generic signal, but naming alone is not proof, "
        "so this is reported for review."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Verify whether the value is a real credential. If so, remove it "
        "from the app: fetch secrets from your backend over TLS after "
        "authentication, or store them in the Android Keystore."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    _VAR_RX = re.compile(
        r"(?i)\b\w*(?:api[-_]?key|secret|token|passwd|password|auth[-_]?key)\w*\s*="
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None:
                continue
            lines = text.splitlines()
            for line_no, literal in java_string_literals(text):
                if not looks_like_secret(literal) or _is_test_value(literal):
                    continue
                line = lines[line_no - 1]
                var = self._VAR_RX.search(line)
                if not var:
                    continue
                hit = Hit(
                    path=path, line_no=line_no, line=line,
                    match=var,
                )
                evidence.append(
                    evidence_from_hit(
                        ctx, hit,
                        f"Secret-looking value assigned to '{var.group(0).strip()[:40]}'",
                    )
                )
        if not evidence:
            return pass_result(
                self,
                "No high-entropy literals assigned to secret-named variables found.",
            )
        return needs_review(
            self,
            f"{len(evidence)} high-entropy literal(s) assigned to "
            "secret-named variables - verify whether each is a real credential.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "If the value is a genuine credential, anyone decompiling the "
                "APK recovers it, so impact is MEDIUM pending confirmation."
            ),
            confidence_rationale=(
                "The literal has secret-like entropy/structure and the "
                "variable name suggests a credential, but names alone are "
                "not proof - a human must confirm each value."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X09  Private key material
# ---------------------------------------------------------------------------

class RuleX09PrivateKey(_SecretRule):
    id = "BS-X09"
    title = "Private key material embedded in the app"
    description = (
        "A PEM block (-----BEGIN [RSA] PRIVATE KEY-----) is embedded in the "
        "app's code or resources. Private keys shipped in the APK are "
        "recoverable by anyone and must be considered compromised."
    )
    rationale = (
        "Private keys must never leave the owner's secure storage. An "
        "embedded private key lets anyone impersonate the app's identity "
        "(e.g. sign requests, decrypt data meant for the server)."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Remove the private key from the app and treat it as compromised: "
        "generate a new keypair and revoke/replace anything the old key "
        "protected. Keep private keys server-side only."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(
            r"-----BEGIN (?:RSA )?PRIVATE KEY-----", _all_text_files(ctx)
        ):
            evidence.append(
                evidence_from_hit(ctx, hit, "Embedded PEM private key block")
            )
        if not evidence:
            return pass_result(self, "No embedded PEM private key blocks found.")
        return finding(
            self,
            f"Private key material embedded in {len(evidence)} location(s) - "
            "treat the key as compromised.",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "An exposed private key lets attackers impersonate the "
                "key owner's identity (signing, decryption), so impact is "
                "HIGH and the key must be rotated."
            ),
            confidence_rationale=(
                "The PEM BEGIN PRIVATE KEY header is explicit in the matched "
                "text; no inference required."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X10  Keystore passwords
# ---------------------------------------------------------------------------

class RuleX10KeystorePassword(_SecretRule):
    id = "BS-X10"
    title = "Hardcoded keystore password"
    description = (
        "A storePassword or keyPassword assignment with a literal value was "
        "found (typically in gradle signing configs). Keystore passwords "
        "protect the app's signing keys; hardcoded, they protect nothing."
    )
    rationale = (
        "Anyone with the keystore file and its hardcoded password can sign "
        "APKs as the developer or recover the signing keys."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Do not commit keystore passwords. Read them from environment "
        "variables or a local properties file excluded from version control "
        "(e.g. via System.getenv in gradle), and rotate any exposed password."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(
            r"\b(storePassword|keyPassword)\s*(?:=\s*)?\"([^\"]+)\"",
            _all_text_files(ctx),
        ):
            value = hit.match.group(2)
            if not value or _is_test_value(value):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"Hardcoded {hit.match.group(1)} value",
                )
            )
        if not evidence:
            return pass_result(self, "No hardcoded keystore passwords found.")
        return finding(
            self,
            f"Hardcoded keystore password in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Keystore passwords guard the app's signing keys; exposed, "
                "they let attackers sign malicious builds as the developer."
            ),
            confidence_rationale=(
                "The storePassword/keyPassword assignment with a literal "
                "value is explicit in the matched text."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X11  OAuth client secrets
# ---------------------------------------------------------------------------

class RuleX11OAuthClientSecret(_SecretRule):
    id = "BS-X11"
    title = "Hardcoded OAuth client secret"
    description = (
        "An OAuth client_secret with a substantial literal value is embedded "
        "in the app. Client secrets authenticate the app to the identity "
        "provider; leaked, they let attackers impersonate the app."
    )
    rationale = (
        "OAuth client secrets are meant to be confidential. In a mobile app "
        "they cannot be kept secret at all, but embedding a long-lived one "
        "still hands attackers a credential for token endpoints."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Do not embed OAuth client secrets in mobile apps - use the "
        "Authorization Code flow with PKCE (no client secret) per RFC 8252. "
        "Rotate any exposed secret at the identity provider."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(
            r"(?i)\bclient[-_]?secret\s*[=:]\s*\"([^\"]{8,})\"",
            _all_text_files(ctx),
        ):
            value = hit.match.group(1)
            if _is_test_value(value):
                continue
            evidence.append(
                evidence_from_hit(ctx, hit, "Hardcoded OAuth client_secret value")
            )
        if not evidence:
            return pass_result(self, "No hardcoded OAuth client secrets found.")
        return finding(
            self,
            f"Hardcoded OAuth client secret in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "A leaked OAuth client secret lets attackers impersonate the "
                "app at token endpoints, so impact is HIGH."
            ),
            confidence_rationale=(
                "The client_secret key with a substantial literal value is "
                "explicit in the matched text."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X12  Hardcoded JWT
# ---------------------------------------------------------------------------

class RuleX12HardcodedJwt(_SecretRule):
    id = "BS-X12"
    title = "Hardcoded JSON Web Token (JWT)"
    description = (
        "A JWT-shaped value (eyJ...eyJ...) is embedded in the app. Hardcoded "
        "tokens are bearer credentials: anyone extracting them can replay "
        "them until they expire or are revoked."
    )
    rationale = (
        "JWTs are bearer tokens by design. A hardcoded JWT - often a "
        "long-lived service token - grants its embedded privileges to "
        "anyone who decompiles the APK."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Do not hardcode tokens. Obtain short-lived tokens at runtime via "
        "proper authentication (OAuth2/OIDC), and revoke any exposed token "
        "immediately."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}",
            _all_text_files(ctx),
        ):
            token = hit.match.group(0)
            if _is_test_value(token):
                continue
            evidence.append(
                evidence_from_hit(ctx, hit, "Hardcoded JWT value")
            )
        if not evidence:
            return pass_result(self, "No hardcoded JWTs found.")
        return finding(
            self,
            f"Hardcoded JWT in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "JWTs are bearer credentials; a leaked token can be replayed "
                "for its embedded privileges, so impact is MEDIUM (bounded by "
                "the token's scopes and expiry)."
            ),
            confidence_rationale=(
                "The eyJ...eyJ... structure matches a JWT header and payload "
                "exactly."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X13  Twilio credentials
# ---------------------------------------------------------------------------

class RuleX13TwilioCredential(_SecretRule):
    id = "BS-X13"
    title = "Hardcoded Twilio credential"
    description = (
        "A Twilio account SID or API key (AC.../SK... followed by 32 "
        "characters) is embedded in the app. Twilio credentials can be "
        "abused to send SMS, place calls and read message logs at the "
        "owner's expense."
    )
    rationale = (
        "Twilio SIDs/keys have a fixed AC/SK prefix and length. Embedded in "
        "the APK they can be extracted and used against the Twilio API."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Remove the credential from the app and rotate it in the Twilio "
        "console immediately. Keep Twilio auth tokens server-side and proxy "
        "messaging through your backend."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(r"\b(?:AC|SK)[a-z0-9]{32}\b", _all_text_files(ctx)):
            cred = hit.match.group(0)
            if _is_test_value(cred):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"Hardcoded Twilio credential starting with {cred[:6]}",
                )
            )
        if not evidence:
            return pass_result(self, "No hardcoded Twilio credentials found.")
        return finding(
            self,
            f"Hardcoded Twilio credential in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "A genuine Twilio credential allows sending SMS, placing "
                "calls and reading logs at the owner's expense, so impact is "
                "HIGH."
            ),
            confidence_rationale=(
                "The AC/SK prefix with 32 trailing characters matches the "
                "Twilio credential format, but other 34-char identifiers "
                "share the shape, so confidence is MEDIUM."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X14  SendGrid API key
# ---------------------------------------------------------------------------

class RuleX14SendgridKey(_SecretRule):
    id = "BS-X14"
    title = "Hardcoded SendGrid API key"
    description = (
        "A SendGrid API key (SG....) is embedded in the app. SendGrid keys "
        "grant access to send email as the account, read templates and "
        "manage suppression lists."
    )
    rationale = (
        "SendGrid API keys have a distinctive SG. prefix. Leaked keys are "
        "abused for spam and phishing from the victim's domain, damaging "
        "sender reputation."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Remove the key from the app and revoke it in the SendGrid dashboard "
        "immediately. Send mail through your backend; never ship mail-provider "
        "API keys in client builds."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(r"\bSG\.[A-Za-z0-9_\-]{22,}\b", _all_text_files(ctx)):
            key = hit.match.group(0)
            if _is_test_value(key):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"Hardcoded SendGrid API key starting with {key[:8]}",
                )
            )
        if not evidence:
            return pass_result(self, "No hardcoded SendGrid API keys found.")
        return finding(
            self,
            f"Hardcoded SendGrid API key in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "A SendGrid key lets attackers send email as the account "
                "(spam/phishing from the victim domain), so impact is HIGH."
            ),
            confidence_rationale=(
                "The SG. prefix with a long token body matches the SendGrid "
                "API key format exactly."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X15  Azure Storage connection string
# ---------------------------------------------------------------------------

class RuleX15AzureConnectionString(_SecretRule):
    id = "BS-X15"
    title = "Hardcoded Azure Storage connection string"
    description = (
        "An Azure Storage connection string with an AccountKey is embedded "
        "in the app. The account key grants full control over the storage "
        "account: blobs, queues, tables and files."
    )
    rationale = (
        "Storage account keys are effectively root credentials for the "
        "account. Embedded in the APK they can be extracted and used to "
        "read, modify or delete all stored data."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Remove the connection string from the app and regenerate the "
        "storage account keys in the Azure portal immediately. Use Azure AD "
        "or SAS tokens with least privilege, issued server-side."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(
            r"\bAccountKey=([A-Za-z0-9+/=]{40,})", _all_text_files(ctx)
        ):
            key = hit.match.group(1)
            if _is_test_value(key):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit, "Hardcoded Azure Storage AccountKey"
                )
            )
        if not evidence:
            return pass_result(
                self, "No hardcoded Azure Storage connection strings found."
            )
        return finding(
            self,
            f"Hardcoded Azure Storage connection string in {len(evidence)} "
            "location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "The storage account key is a root-equivalent credential for "
                "the account (read/write/delete all data), so impact is HIGH."
            ),
            confidence_rationale=(
                "The AccountKey= prefix with a long base64 value matches an "
                "Azure Storage connection string exactly."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X16  Basic-auth credentials in URL
# ---------------------------------------------------------------------------

class RuleX16BasicAuthUrl(_SecretRule):
    id = "BS-X16"
    title = "Credentials embedded in a URL"
    description = (
        "A URL embeds basic-auth credentials (https://user:password@host). "
        "Credentials in URLs leak into logs, analytics, Referer headers and "
        "anyone the link is shared with."
    )
    rationale = (
        "The userinfo part of a URL is transmitted and logged in many more "
        "places than an Authorization header, and it is visible to anyone "
        "reading the code."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Remove credentials from URLs. Send them in an Authorization header "
        "over TLS at runtime, sourced from secure storage or user input - "
        "never hardcoded."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(
            r"\bhttps?://([^/\s:]+):([^/\s@]+)@", _all_text_files(ctx)
        ):
            user, password = hit.match.group(1), hit.match.group(2)
            if _is_test_value(user) or _is_test_value(password):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    f"URL embeds credentials for user '{user[:30]}'",
                )
            )
        if not evidence:
            return pass_result(self, "No credentials embedded in URLs found.")
        return finding(
            self,
            f"Credentials embedded in URLs in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "URL-embedded credentials leak into logs, Referer headers and "
                "shared links, and are visible to anyone reading the app, so "
                "impact is HIGH."
            ),
            confidence_rationale=(
                "The scheme://user:password@host structure is explicit in "
                "the matched text."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X17  Secret-looking manifest meta-data
# ---------------------------------------------------------------------------

class RuleX17ManifestMetadataSecret(_SecretRule):
    id = "BS-X17"
    title = "Secret-looking value in AndroidManifest meta-data"
    description = (
        "An <meta-data> entry in AndroidManifest.xml carries an "
        "android:value that looks like a secret (high entropy or structured "
        "key format) instead of a resource reference. Manifest meta-data is "
        "readable by any app on the device via PackageManager."
    )
    rationale = (
        "Meta-data values are exposed through the package manager to other "
        "apps, so they are a poor place for secrets - and a common one for "
        "API keys."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Do not put secrets in manifest meta-data. Fetch API keys from your "
        "backend at runtime or keep them in obfuscated app-internal storage "
        "with proper access controls."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    _META_RX = re.compile(r"<meta-data\b[^>]*android:value=\"([^\"]+)\"")

    def _suspicious(self, value: str) -> bool:
        v = value.strip()
        if v.startswith("@") or _is_test_value(v):
            return False
        if looks_like_secret(v):
            return True
        # long alphanumeric blobs (e.g. 32-char hex app secrets)
        if len(v) >= 24 and re.fullmatch(r"[A-Za-z0-9_\-]+", v) and not v.isdigit():
            return True
        return False

    def check(self, ctx: ScanContext) -> RuleResult:
        manifest = ctx.manifest
        raw = manifest.raw_xml if manifest else ""
        if not raw:
            return pass_result(self, "No decoded manifest XML available.")
        manifest_path = ctx.manifest_xml_path or "AndroidManifest.xml"
        evidence = []
        for i, line in enumerate(raw.splitlines(), start=1):
            for m in self._META_RX.finditer(line):
                value = m.group(1)
                if not self._suspicious(value):
                    continue
                evidence.append(
                    evidence_simple(
                        ctx,
                        manifest_path,
                        "meta-data android:value looks like a hardcoded secret: "
                        f"\"{value[:40]}\"",
                        snippet=line.strip()[:220],
                        line_start=i,
                        line_end=i,
                    )
                )
        if not evidence:
            return pass_result(
                self, "No secret-looking manifest meta-data values found."
            )
        return finding(
            self,
            f"Secret-looking manifest meta-data value in {len(evidence)} "
            "location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Manifest meta-data is readable by other apps via "
                "PackageManager, so a real secret there is exposed beyond "
                "the app itself: HIGH impact."
            ),
            confidence_rationale=(
                "The value has secret-like entropy/structure and is not a "
                "resource reference, but long opaque config values exist, so "
                "confidence is MEDIUM."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X18  Secrets in BuildConfig / gradle
# ---------------------------------------------------------------------------

class RuleX18BuildConfigSecret(_SecretRule):
    id = "BS-X18"
    title = "Secret baked into BuildConfig or gradle files"
    description = (
        "An API key, secret, token or password literal is assigned in "
        "BuildConfig.java or a gradle file. BuildConfig fields are compiled "
        "into the app as plain constants, and gradle files are often "
        "committed to version control."
    )
    rationale = (
        "BuildConfig constants are trivially readable after decompilation, "
        "and gradle secrets leak through source control - two exposure paths "
        "for one mistake."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Do not bake secrets into builds. Inject non-sensitive config via "
        "buildConfigField only, and fetch real secrets from your backend at "
        "runtime. Keep gradle signing credentials in environment variables "
        "or an untracked local properties file."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    _BUILDCONFIG_RX = (
        r"(?i)\b\w*(?:api[-_]?key|secret|token|passwd|password)\w*"
        r"\s*=\s*\"([^\"]{12,})\""
    )
    _GRADLE_RX = (
        r"(?i)\b(api[-_]?key|secret|password|passwd|token)\b"
        r"\s*[:=]\s*[\"']([^\"']{12,})[\"']"
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(self._BUILDCONFIG_RX, iter_source_files(ctx)):
            if hit.path.name != "BuildConfig.java":
                continue
            value = hit.match.group(1)
            if not looks_like_secret(value) or _is_test_value(value):
                continue
            evidence.append(
                evidence_from_hit(ctx, hit, "Secret literal in BuildConfig.java")
            )
        for hit in grep(self._GRADLE_RX, iter_text_artifacts(ctx)):
            if hit.path.suffix.lower() != ".gradle":
                continue
            value = hit.match.group(2)
            if not looks_like_secret(value) or _is_test_value(value):
                continue
            evidence.append(
                evidence_from_hit(ctx, hit, "Secret literal in gradle file")
            )
        if not evidence:
            return pass_result(
                self, "No secret literals in BuildConfig or gradle files found."
            )
        return finding(
            self,
            f"Secret baked into BuildConfig/gradle in {len(evidence)} "
            "location(s).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "BuildConfig constants are readable after decompilation and "
                "gradle files leak via source control; impact is MEDIUM "
                "because the values still need confirmation as live secrets."
            ),
            confidence_rationale=(
                "The literal is assigned to a secret-named field and has "
                "secret-like entropy, but build-time config values can be "
                "opaque without being credentials."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X19  Facebook app secret
# ---------------------------------------------------------------------------

class RuleX19FacebookAppSecret(_SecretRule):
    id = "BS-X19"
    title = "Hardcoded Facebook app secret"
    description = (
        "A long hex value is assigned near fb_secret / facebook secret "
        "naming, matching a Facebook app secret. The app secret authenticates "
        "server-side calls to the Facebook Graph API."
    )
    rationale = (
        "Facebook app secrets are long hex strings. Embedded in the app "
        "they let attackers make Graph API calls as the application."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Remove the app secret from the client - it belongs server-side "
        "only. Rotate it in the Facebook developer console if it was "
        "exposed."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(
            r"(?i)\b(fb_secret|facebook[-_]?app[-_]?secret|facebook[-_]?secret)"
            r"\s*[=:]\s*\"([0-9a-fA-F]{32,})\"",
            _all_text_files(ctx),
        ):
            value = hit.match.group(2)
            if _is_test_value(value):
                continue
            evidence.append(
                evidence_from_hit(ctx, hit, "Facebook app secret value")
            )
        if not evidence:
            return pass_result(self, "No hardcoded Facebook app secrets found.")
        return finding(
            self,
            f"Hardcoded Facebook app secret in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "A Facebook app secret enables Graph API calls as the "
                "application, so impact is MEDIUM (app-level, not user-level)."
            ),
            confidence_rationale=(
                "The value is long hex next to facebook-secret naming, but "
                "long hex IDs are also used for non-secret identifiers."
            ),
        )


# ---------------------------------------------------------------------------
# BS-X20  Hardcoded password near crypto use
# ---------------------------------------------------------------------------

class RuleX20PasswordNearCrypto(_SecretRule):
    id = "BS-X20"
    title = "Hardcoded password used near cryptographic APIs"
    description = (
        "A password string literal is assigned within 5 lines of crypto API "
        "usage (Cipher, SecretKey, MessageDigest, KeyGenerator, Mac), "
        "suggesting it protects or derives cryptographic material. "
        "Hardcoded passwords offer no real protection once the APK is "
        "decompiled."
    )
    rationale = (
        "Passwords used as crypto keys or for key derivation must not be "
        "embedded: anyone decompiling the app recovers both the password "
        "and the data it 'protects'."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-259"]
    remediation = (
        "Do not hardcode passwords. Derive keys from user-supplied secrets "
        "at runtime with a strong KDF (Argon2id/bcrypt), or store keys in "
        "the Android Keystore."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/259.html",
        "https://mas.owasp.org/MASTG/",
    ]

    _CRYPTO_RX = re.compile(
        r"\b(Cipher|SecretKey|MessageDigest|KeyGenerator|Mac)\b"
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(
            r"(?i)\bpassword\s*=\s*\"([^\"]{6,})\"", iter_source_files(ctx)
        ):
            value = hit.match.group(1)
            if _is_test_value(value):
                continue
            text = read_text_capped(hit.path)
            if text is None:
                continue
            if not self._CRYPTO_RX.search(_window_text(text, hit.line_no, 5)):
                continue
            evidence.append(
                evidence_from_hit(
                    ctx, hit,
                    "Hardcoded password assigned near crypto API usage",
                )
            )
        if not evidence:
            return pass_result(
                self, "No hardcoded passwords near crypto APIs found."
            )
        return finding(
            self,
            f"Hardcoded password near crypto use in {len(evidence)} "
            "location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "A hardcoded password guarding crypto material is "
                "recoverable by decompiling the APK, defeating the "
                "encryption, so impact is HIGH."
            ),
            confidence_rationale=(
                "The password literal sits within 5 lines of crypto API "
                "usage, strongly suggesting a crypto role, but the exact "
                "data flow was not traced statically."
            ),
        )


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    RuleX01AwsAccessKey(),
    RuleX02AwsSecretKey(),
    RuleX03GoogleApiKey(),
    RuleX04FirebaseUrl(),
    RuleX05StripeKey(),
    RuleX06SlackToken(),
    RuleX07GithubToken(),
    RuleX08GenericHighEntropySecret(),
    RuleX09PrivateKey(),
    RuleX10KeystorePassword(),
    RuleX11OAuthClientSecret(),
    RuleX12HardcodedJwt(),
    RuleX13TwilioCredential(),
    RuleX14SendgridKey(),
    RuleX15AzureConnectionString(),
    RuleX16BasicAuthUrl(),
    RuleX17ManifestMetadataSecret(),
    RuleX18BuildConfigSecret(),
    RuleX19FacebookAppSecret(),
    RuleX20PasswordNearCrypto(),
]

__all__ = ["RULES"]
