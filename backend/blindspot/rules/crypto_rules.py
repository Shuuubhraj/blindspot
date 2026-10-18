"""Cryptography & secrets detection rules (BS-C01 .. BS-C15).

Category: crypto. All rules are static source-code checks over the
decompiled Java/Kotlin sources (``ctx.java_roots``). Algorithm context
is accounted for: e.g. MD5 used for a non-security cache key is not
treated the same as MD5 used on passwords, signatures or tokens.

Rule index
----------
BS-C01  MD5 used in a security-sensitive context
BS-C02  SHA-1 used for signatures, tokens or certificates
BS-C03  Weak block/stream ciphers (DES, DESede, RC4, Blowfish)
BS-C04  AES in ECB mode
BS-C05  Hardcoded encryption key material
BS-C06  Hardcoded or zero initialization vector (IV)
BS-C07  java.util.Random used for security-sensitive values
BS-C08  Custom (hand-rolled) cryptographic implementation
BS-C09  Weak password-based key derivation (PBKDF2-SHA1 / low iterations)
BS-C10  Password hashing without salt (MD5 / SHA-1 / SHA-256)
BS-C11  RSA/DSA key size below 2048 bits
BS-C12  Weak signature algorithms (SHA1withRSA, MD5withRSA, ...)
BS-C13  Crypto key material stored in SharedPreferences
BS-C14  AES/CBC without observed integrity protection
BS-C15  Hardcoded weak crypto configuration constants
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
    Hit,
    evidence_from_hit,
    grep,
    iter_source_files,
    read_text_capped,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

#: Keywords indicating a security-sensitive context (passwords, hashes,
#: signatures, tokens, auth, certificates ...). Used for context-aware
#: checks such as BS-C01: the same algorithm can be fine for a cache key
#: and dangerous for password hashing, so the surrounding lines decide.
_SECURITY_KW = re.compile(
    r"(?i)\b(password|passwd|pwd|passcode|hash|signature|sign(ing|ed|ature)?"
    r"|token|auth(entication|orization)?|credential|hmac|certificate|cert"
    r"|digest[-\s]?auth|login|pin)\b"
)

_PASSWORD_KW = re.compile(r"(?i)\b(password|passwd|pwd|passcode|pin|credential)\b")

_SALT_KW = re.compile(r"(?i)\bsalt\b")


def _window_text(text: str, line_no: int, radius: int = 5) -> str:
    """Return the lines within +/- radius of a 1-based line number."""
    lines = text.splitlines()
    lo = max(0, line_no - 1 - radius)
    hi = min(len(lines), line_no + radius)
    return "\n".join(lines[lo:hi])


def _has_security_context(text: str, line_no: int, radius: int = 5) -> bool:
    return bool(_SECURITY_KW.search(_window_text(text, line_no, radius)))


def _var_filled_random(text: str, var: str, line_no: int, radius: int = 15) -> bool:
    """True if `var` is filled from a SecureRandom (e.g. nextBytes(var))."""
    window = _window_text(text, line_no, radius)
    return bool(
        re.search(rf"\bnextBytes\s*\([^)]*\b{re.escape(var)}\b", window)
        or re.search(rf"\b{re.escape(var)}\b[^\n;]*\bSecureRandom\b", window)
    )


def _var_assigned_literal(text: str, var: str, upto_line: int, radius: int = 15) -> bool:
    """True if `var` was assigned a string/byte literal in the preceding lines."""
    lines = text.splitlines()
    lo = max(0, upto_line - 1 - radius)
    window = "\n".join(lines[lo:upto_line - 1])
    return bool(
        re.search(
            rf"\b{re.escape(var)}\s*=\s*(?:\"[^\"]*\"|new\s+byte\s*\[)",
            window,
        )
    )


class _CryptoRule(Rule):
    """Base for crypto rules: they need decompiled sources to inspect."""

    category = "crypto"
    masvs = ["MSTG-CRYPTO"]

    def applies(self, ctx: ScanContext) -> bool:
        return bool(ctx.java_roots)


# ---------------------------------------------------------------------------
# BS-C01  MD5 in a security-sensitive context
# ---------------------------------------------------------------------------

class RuleC01Md5SecurityContext(_CryptoRule):
    id = "BS-C01"
    title = "MD5 used in a security-sensitive context"
    description = (
        "MessageDigest \"MD5\" is used where the surrounding code suggests a "
        "security purpose (passwords, hashes, signatures, tokens, auth). MD5 is "
        "collision-broken and unsuitable for any security-sensitive digest."
    )
    rationale = (
        "MD5 collisions are practical; using MD5 for passwords, signatures or "
        "tokens lets an attacker forge or collide values. The same call is "
        "harmless for non-security uses (e.g. cache keys, checksums), so the "
        "rule inspects ~5 lines of context for security keywords before "
        "flagging HIGH."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-327"]
    remediation = (
        "Replace MD5 with SHA-256 (MessageDigest.getInstance(\"SHA-256\")) for "
        "integrity digests. For password storage do not use a plain digest at "
        "all: use Argon2id, bcrypt or scrypt via a vetted library with a "
        "unique per-user salt."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r'MessageDigest\s*\.\s*getInstance\s*\(\s*"MD5"', iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No MessageDigest MD5 usage found in sources.")
        findings: list = []
        review: list = []
        for hit in hits:
            text = read_text_capped(hit.path)
            if text is None:
                continue
            ev = evidence_from_hit(
                ctx, hit,
                "MessageDigest.getInstance(\"MD5\") call site",
            )
            if _has_security_context(text, hit.line_no):
                findings.append(ev)
            else:
                review.append(ev)
        if findings:
            return finding(
                self,
                f"MD5 used in a security-sensitive context in {len(findings)} location(s).",
                evidence=findings,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                severity_rationale=(
                    "MD5 is collision-broken; using it for passwords, signatures "
                    "or tokens can allow forgery or collision attacks, so impact "
                    "is HIGH."
                ),
                confidence_rationale=(
                    "The MD5 call is explicit in source and the surrounding ~5 "
                    "lines contain security keywords (password/hash/signature/"
                    "token/auth), indicating a security-sensitive use."
                ),
            )
        return needs_review(
            self,
            f"MD5 used in {len(review)} location(s) without an obvious security "
            "context (e.g. cache keys, checksums).",
            evidence=review,
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            severity_rationale=(
                "If the digest later protects anything security-sensitive the "
                "impact is HIGH; currently the context does not indicate that."
            ),
            confidence_rationale=(
                "The MD5 call is real, but no security keywords were found "
                "within 5 lines, so a non-security use (cache key, ETag, "
                "checksum) is plausible and this needs a human look."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C02  SHA-1 for signatures / tokens / certificates
# ---------------------------------------------------------------------------

class RuleC02Sha1SecurityUse(_CryptoRule):
    id = "BS-C02"
    title = "SHA-1 used for signatures, tokens or certificates"
    description = (
        "MessageDigest \"SHA-1\"/\"SHA1\" is used near signature, token or "
        "certificate handling. SHA-1 is collision-broken (SHAttered) and "
        "deprecated for security use."
    )
    rationale = (
        "Practical SHA-1 collision attacks exist; signatures, tokens and "
        "certificate fingerprints computed with SHA-1 can be forged."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-327"]
    remediation = (
        "Use SHA-256 or stronger (MessageDigest.getInstance(\"SHA-256\")). For "
        "signatures prefer Signature.getInstance(\"SHA256withRSA\"/\"...ECDSA\") "
        "with keys >= 2048 bits (RSA)."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r'MessageDigest\s*\.\s*getInstance\s*\(\s*"SHA-?1"',
            iter_source_files(ctx),
        )
        if not hits:
            return pass_result(self, "No MessageDigest SHA-1 usage found in sources.")
        context_kw = re.compile(
            r"(?i)\b(signature|sign(ing|ed|ature)?|token|cert(ificate)?|fingerprint|x509)\b"
        )
        findings: list = []
        review: list = []
        for hit in hits:
            text = read_text_capped(hit.path)
            if text is None:
                continue
            ev = evidence_from_hit(ctx, hit, "MessageDigest.getInstance(\"SHA-1\") call site")
            if context_kw.search(_window_text(text, hit.line_no)):
                findings.append(ev)
            else:
                review.append(ev)
        if findings:
            return finding(
                self,
                f"SHA-1 used near signature/token/certificate handling in "
                f"{len(findings)} location(s).",
                evidence=findings,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                severity_rationale=(
                    "SHA-1 collisions are practical, so tokens, signatures or "
                    "certificate fingerprints built on SHA-1 can be attacked; "
                    "impact is MEDIUM rather than HIGH because exploitability "
                    "depends on the exact protocol."
                ),
                confidence_rationale=(
                    "The SHA-1 call is explicit and the surrounding lines "
                    "reference signatures, tokens or certificates."
                ),
            )
        return needs_review(
            self,
            f"SHA-1 used in {len(review)} location(s) without an obvious "
            "security context.",
            evidence=review,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale="SHA-1 is deprecated for security use; impact depends on use.",
            confidence_rationale=(
                "SHA-1 call is real but no signature/token/certificate keywords "
                "were found nearby; may be a non-security checksum."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C03  Weak ciphers (DES / DESede / RC4 / Blowfish)
# ---------------------------------------------------------------------------

class RuleC03WeakCipher(_CryptoRule):
    id = "BS-C03"
    title = "Weak cipher algorithm in use (DES, DESede, RC4, Blowfish)"
    description = (
        "Cipher.getInstance is called with DES, Triple-DES (DESede), RC4 or "
        "Blowfish. DES/RC4 are broken; DESede and Blowfish have small block "
        "sizes and are deprecated for new use."
    )
    rationale = (
        "DES has a 56-bit key (brute-forceable); RC4 has practical biases and "
        "is prohibited by RFC 7465; 64-bit block ciphers (DESede, Blowfish) "
        "are vulnerable to SWEET32 birthday attacks."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-327"]
    remediation = (
        "Use Cipher.getInstance(\"AES/GCM/NoPadding\") with a 128- or 256-bit "
        "key from a secure random source (or Android Keystore). GCM provides "
        "both confidentiality and integrity."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://developer.android.com/guide/topics/security/cryptography",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r'Cipher\s*\.\s*getInstance\s*\(\s*"(?:DESede|DES|RC4|Blowfish)[^"]*"',
            iter_source_files(ctx),
        )
        if not hits:
            return pass_result(self, "No DES/DESede/RC4/Blowfish Cipher usage found.")
        evidence = [
            evidence_from_hit(ctx, h, f"Weak cipher requested: {h.match.group(0)[:80]}")
            for h in hits
        ]
        algos = sorted({h.match.group(0) for h in hits})
        return finding(
            self,
            f"Weak cipher algorithm(s) requested: {', '.join(algos)}.",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Data encrypted with DES/RC4 (broken) or DESede/Blowfish "
                "(SWEET32-prone) can be recovered by a capable attacker."
            ),
            confidence_rationale=(
                "The weak algorithm name is passed explicitly to "
                "Cipher.getInstance in source; no inference required."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C04  AES/ECB mode
# ---------------------------------------------------------------------------

class RuleC04AesEcb(_CryptoRule):
    id = "BS-C04"
    title = "AES used in ECB mode"
    description = (
        "Cipher.getInstance is called with an AES/ECB transformation. ECB "
        "encrypts identical plaintext blocks to identical ciphertext blocks, "
        "leaking plaintext structure."
    )
    rationale = (
        "ECB mode is deterministic and reveals patterns in the plaintext "
        "(the classic ECB penguin). It provides no semantic security for "
        "multi-block data."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-327"]
    remediation = (
        "Use Cipher.getInstance(\"AES/GCM/NoPadding\") with a fresh random "
        "12-byte IV per encryption; never reuse an IV with the same key in GCM."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://developer.android.com/guide/topics/security/cryptography",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r'Cipher\s*\.\s*getInstance\s*\(\s*"[^"]*AES/ECB[^"]*"',
            iter_source_files(ctx),
        )
        if not hits:
            return pass_result(self, "No AES/ECB Cipher usage found.")
        evidence = [
            evidence_from_hit(ctx, h, "AES/ECB transformation requested")
            for h in hits
        ]
        return finding(
            self,
            f"AES/ECB mode requested in {len(hits)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "ECB leaks plaintext structure for any multi-block message, "
                "so confidentiality is effectively broken for structured data."
            ),
            confidence_rationale=(
                "The AES/ECB transformation string is explicit in the "
                "Cipher.getInstance call."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C05  Hardcoded encryption key
# ---------------------------------------------------------------------------

class RuleC05HardcodedKey(_CryptoRule):
    id = "BS-C05"
    title = "Hardcoded encryption key"
    description = (
        "A SecretKeySpec is built from a hardcoded string literal, a literal "
        "byte array, or a variable that was assigned a literal shortly "
        "before. Anyone who can read the APK can recover the key."
    )
    rationale = (
        "APKs are trivially decompiled; a hardcoded key offers no secrecy, "
        "so all data 'protected' by it is recoverable by anyone with the app."
    )
    default_severity = Severity.CRITICAL
    owasp = ["M10"]
    cwe = ["CWE-798"]
    remediation = (
        "Do not embed keys. Generate keys at runtime with KeyGenerator and a "
        "SecureRandom, or store them in the Android Keystore "
        "(AndroidKeyStore) so key material never enters app memory as a "
        "literal. For data that must be decryptable off-device, fetch keys "
        "from a server over TLS after authentication."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://developer.android.com/training/articles/keystore",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"new\s+SecretKeySpec\s*\(", iter_source_files(ctx))
        evidence = []
        for hit in hits:
            text = read_text_capped(hit.path)
            if text is None:
                continue
            line = hit.line
            desc = "SecretKeySpec call site"
            hardcoded = False
            # Case 1: string literal on the same line ("...".getBytes() etc.)
            if re.search(r'new\s+SecretKeySpec\s*\(\s*"', line):
                hardcoded = True
                desc = "SecretKeySpec built from a hardcoded string literal"
            # Case 2: literal byte array on the same line
            elif re.search(r"new\s+SecretKeySpec\s*\(\s*new\s+byte\s*\[", line):
                hardcoded = True
                desc = "SecretKeySpec built from a literal byte array"
            else:
                # Case 3: variable argument assigned a literal nearby
                m = re.search(r"new\s+SecretKeySpec\s*\(\s*([A-Za-z_]\w*)", line)
                if m and _var_assigned_literal(text, m.group(1), hit.line_no):
                    hardcoded = True
                    desc = (
                        f"SecretKeySpec built from variable '{m.group(1)}' "
                        "assigned a literal value nearby"
                    )
            if hardcoded:
                evidence.append(evidence_from_hit(ctx, hit, desc))
        if not evidence:
            return pass_result(self, "No SecretKeySpec built from hardcoded key material found.")
        return finding(
            self,
            f"Hardcoded encryption key material in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "A hardcoded key is recoverable by decompiling the APK, so "
                "every ciphertext produced with it is effectively plaintext "
                "to an attacker: total loss of confidentiality."
            ),
            confidence_rationale=(
                "The SecretKeySpec constructor receives a string literal, a "
                "literal byte array, or a variable provably assigned a "
                "literal in the preceding lines."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C06  Hardcoded / zero IV
# ---------------------------------------------------------------------------

class RuleC06HardcodedIv(_CryptoRule):
    id = "BS-C06"
    title = "Hardcoded or zero initialization vector (IV)"
    description = (
        "An IvParameterSpec is built from a hardcoded string/byte literal or "
        "an all-zero byte array. Reusing an IV across encryptions (notably in "
        "CBC or GCM) destroys semantic security."
    )
    rationale = (
        "IVs must be unique per encryption. A hardcoded IV is reused for every "
        "message; in CBC this leaks whether two messages share a prefix, in "
        "GCM it catastrophically leaks the authentication key."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-329"]
    remediation = (
        "Generate a fresh random IV per encryption with new SecureRandom() "
        "(12 bytes for GCM, 16 for CBC) and store/transmit it alongside the "
        "ciphertext; IVs are not secret, only unique."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/329.html",
        "https://developer.android.com/guide/topics/security/cryptography",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"new\s+IvParameterSpec\s*\(", iter_source_files(ctx))
        evidence = []
        for hit in hits:
            text = read_text_capped(hit.path)
            if text is None:
                continue
            line = hit.line
            desc = ""
            if re.search(r'new\s+IvParameterSpec\s*\(\s*"', line):
                desc = "IvParameterSpec built from a hardcoded string literal"
            elif re.search(r"new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\[", line):
                desc = "IvParameterSpec built from a literal/zero byte array"
            else:
                m = re.search(r"new\s+IvParameterSpec\s*\(\s*([A-Za-z_]\w*)", line)
                if (
                    m
                    and _var_assigned_literal(text, m.group(1), hit.line_no)
                    and not _var_filled_random(text, m.group(1), hit.line_no)
                ):
                    desc = (
                        f"IvParameterSpec built from variable '{m.group(1)}' "
                        "assigned a literal value nearby"
                    )
            if desc:
                evidence.append(evidence_from_hit(ctx, hit, desc))
        if not evidence:
            return pass_result(self, "No hardcoded/zero IV passed to IvParameterSpec found.")
        return finding(
            self,
            f"Hardcoded or zero IV in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "IV reuse breaks CBC semantic security and is catastrophic in "
                "GCM (authentication-key recovery), so ciphertext "
                "confidentiality/integrity is at risk."
            ),
            confidence_rationale=(
                "The IvParameterSpec constructor receives a string literal, a "
                "literal/zero byte array, or a variable provably assigned a "
                "literal in the preceding lines."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C07  java.util.Random for security-sensitive values
# ---------------------------------------------------------------------------

class RuleC07WeakRandom(_CryptoRule):
    id = "BS-C07"
    title = "Predictable random values via java.util.Random"
    description = (
        "java.util.Random is used to generate values whose variable names or "
        "surrounding crypto API usage indicate a security purpose (keys, "
        "tokens, sessions, nonces, salts). java.util.Random is not "
        "cryptographically secure and its output is predictable."
    )
    rationale = (
        "java.util.Random is a linear congruential generator; observing a few "
        "outputs lets an attacker predict future tokens, session IDs or key "
        "material."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-338"]
    remediation = (
        "Use java.security.SecureRandom for keys, tokens, nonces, salts and "
        "session identifiers."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/338.html",
        "https://developer.android.com/guide/topics/security/cryptography",
    ]

    _NAME_KW = re.compile(
        r"(?i)(key|token|session|nonce|salt|secret|password|auth|crypt|cipher|challenge|otp)"
    )
    _CRYPTO_API = re.compile(
        r"SecretKeySpec|IvParameterSpec|KeyGenerator|Cipher\.|MessageDigest\.|SecureRandom"
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"new\s+Random\s*\(\s*\)", iter_source_files(ctx))
        evidence = []
        for hit in hits:
            text = read_text_capped(hit.path)
            if text is None:
                continue
            m = re.search(r"([A-Za-z_]\w*)\s*=\s*new\s+Random\s*\(\s*\)", hit.line)
            if not m:
                continue
            var = m.group(1)
            desc = ""
            if self._NAME_KW.search(var):
                desc = (
                    f"java.util.Random assigned to crypto-adjacent variable "
                    f"'{var}' (keys/tokens/sessions/nonces must use SecureRandom)"
                )
            else:
                # passed to / used alongside crypto APIs nearby?
                window = _window_text(text, hit.line_no, 12)
                if self._CRYPTO_API.search(window) and var in window:
                    desc = (
                        f"java.util.Random value '{var}' used near crypto APIs; "
                        "predictable randomness weakens key/nonce generation"
                    )
            if desc:
                evidence.append(evidence_from_hit(ctx, hit, desc))
        if not evidence:
            return pass_result(
                self,
                "No java.util.Random used for security-sensitive values found "
                "(SecureRandom or non-crypto Random usage only).",
            )
        return finding(
            self,
            f"java.util.Random used for security-sensitive values in "
            f"{len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Predictable tokens, nonces or key material can let an "
                "attacker forge sessions or recover keys, depending on what "
                "the value protects."
            ),
            confidence_rationale=(
                "The Random instance feeds a crypto-adjacent variable name or "
                "is used next to crypto APIs, but whether the generated value "
                "is actually security-critical needs a quick human check."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C08  Custom crypto implementation
# ---------------------------------------------------------------------------

class RuleC08CustomCrypto(_CryptoRule):
    id = "BS-C08"
    title = "Hand-rolled cryptographic implementation"
    description = (
        "A method whose name suggests encryption/decryption performs manual "
        "XOR loops or bit-shift manipulation instead of using the JCA "
        "(javax.crypto.Cipher). Hand-rolled crypto is almost always weaker "
        "than vetted primitives."
    )
    rationale = (
        "Custom XOR/shift 'encryption' provides no meaningful confidentiality "
        "and routinely contains key-reuse, padding and integrity flaws that "
        "vetted modes like AES-GCM avoid."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-327"]
    remediation = (
        "Replace custom routines with javax.crypto.Cipher using "
        "\"AES/GCM/NoPadding\", keys from KeyGenerator/SecureRandom or the "
        "Android Keystore."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://mas.owasp.org/MASTG/",
    ]

    _METHOD = re.compile(
        r"^\s*(?:private|public|protected)?\s*(?:static\s+)?"
        r"[\w<>\[\]]+\s+(\w*(?:encrypt|decrypt|cipher)\w*)\s*\(",
        re.IGNORECASE,
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None:
                continue
            lines = text.splitlines()
            for i, line in enumerate(lines, start=1):
                m = self._METHOD.match(line)
                if not m:
                    continue
                body = "\n".join(lines[i:min(len(lines), i + 25)])
                if "Cipher.getInstance" in body:
                    continue  # proper JCA use inside a helper: not custom crypto
                if re.search(r"\^=?|<<|>>>|>>", body):
                    ev = evidence_from_hit(
                        ctx,
                        Hit(path=path, line_no=i, line=line, match=m),
                        f"Method '{m.group(1)}' does manual XOR/bit-shift "
                        "manipulation instead of using javax.crypto",
                    )
                    evidence.append(ev)
        if not evidence:
            return pass_result(self, "No hand-rolled crypto routines detected.")
        return needs_review(
            self,
            f"{len(evidence)} method(s) implement manual XOR/bit-shift "
            "'encryption' instead of using the JCA.",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Hand-rolled ciphers are routinely breakable (key reuse, no "
                "integrity), so data 'encrypted' this way may be recoverable."
            ),
            confidence_rationale=(
                "A method named like encrypt/decrypt performs manual bit "
                "manipulation without javax.crypto; whether it protects real "
                "data (vs. obfuscation) needs human review."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C09  Weak password-based key derivation
# ---------------------------------------------------------------------------

class RuleC09WeakKdf(_CryptoRule):
    id = "BS-C09"
    title = "Weak password-based key derivation"
    description = (
        "PBKDF2WithHmacSHA1 is used, or a PBEKeySpec specifies fewer than "
        "10,000 iterations. SHA-1-based PBKDF2 and low iteration counts make "
        "offline password guessing cheap."
    )
    rationale = (
        "PBKDF2-HMAC-SHA1 is fast on GPUs and SHA-1 is deprecated; low "
        "iteration counts (< 10k, far below the OWASP minimum of 600k for "
        "PBKDF2-HMAC-SHA256) let attackers brute-force passwords quickly."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-916"]
    remediation = (
        "Use PBKDF2WithHmacSHA256/SHA512 with >= 600,000 iterations per "
        "current OWASP guidance, or preferably Argon2id/bcrypt/scrypt via a "
        "vetted library, with a unique random salt per password."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/916.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(
            r"SecretKeyFactory\s*\.\s*getInstance\s*\(\s*\"PBKDF2WithHmacSHA1\"",
            iter_source_files(ctx),
        ):
            evidence.append(
                evidence_from_hit(ctx, hit, "PBKDF2 with HMAC-SHA1 (deprecated PRF)")
            )
        for hit in grep(r"new\s+PBEKeySpec\s*\(", iter_source_files(ctx)):
            m = re.search(
                r"new\s+PBEKeySpec\s*\(\s*[^,]+,\s*[^,]+,\s*(\d+)\s*[,)]",
                hit.line,
            )
            if m and int(m.group(1)) < 10000:
                evidence.append(
                    evidence_from_hit(
                        ctx,
                        hit,
                        f"PBEKeySpec with only {m.group(1)} iterations (< 10000)",
                    )
                )
        if not evidence:
            return pass_result(
                self,
                "No PBKDF2-SHA1 or low-iteration PBEKeySpec usage found.",
            )
        return finding(
            self,
            f"Weak password-based key derivation in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Weak KDF parameters make offline password-guessing attacks "
                "cheap, risking recovery of user passwords or derived keys."
            ),
            confidence_rationale=(
                "The PBKDF2-SHA1 algorithm name or the sub-10000 iteration "
                "count is explicit in source."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C10  Password hashing without salt
# ---------------------------------------------------------------------------

class RuleC10UnsaltedPasswordHash(_CryptoRule):
    id = "BS-C10"
    title = "Password hashed without a salt"
    description = (
        "A password (or password-like variable) is digested with MD5, SHA-1 "
        "or SHA-256 with no salt in evidence nearby. Unsalted fast hashes "
        "fall to rainbow tables and GPU brute force."
    )
    rationale = (
        "Identical passwords produce identical digests without a salt, "
        "enabling rainbow-table lookups; MD5/SHA-1/SHA-256 are also far too "
        "fast for password storage."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-916"]
    remediation = (
        "Never store passwords as plain digests. Use Argon2id, bcrypt or "
        "scrypt with a unique random salt per password via a vetted library."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/916.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence = []
        for hit in grep(r"\.digest\s*\(", iter_source_files(ctx)):
            text = read_text_capped(hit.path)
            if text is None:
                continue
            # Must be a MessageDigest-based hash of a weak algorithm in this file.
            if not re.search(
                r'MessageDigest\s*\.\s*getInstance\s*\(\s*"(?:MD5|SHA-?1|SHA-?256)"',
                text,
            ):
                continue
            window = _window_text(text, hit.line_no, 8)
            if not _PASSWORD_KW.search(window):
                continue
            if _SALT_KW.search(window):
                continue  # a salt is mixed in nearby: not this finding
            evidence.append(
                evidence_from_hit(
                    ctx,
                    hit,
                    "Password-like value digested with no salt in evidence nearby",
                )
            )
        if not evidence:
            return pass_result(
                self, "No unsalted password hashing with MD5/SHA-1/SHA-256 found."
            )
        return finding(
            self,
            f"Password hashed without a salt in {len(evidence)} location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Unsalted fast hashes let attackers use rainbow tables and "
                "GPU brute force to recover passwords, compromising user "
                "accounts."
            ),
            confidence_rationale=(
                "A digest() call on a password-like value with a weak "
                "MessageDigest and no salt keyword within 8 lines; the salt "
                "could theoretically be mixed in farther away."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C11  Small RSA/DSA key size
# ---------------------------------------------------------------------------

class RuleC11SmallKeySize(_CryptoRule):
    id = "BS-C11"
    title = "Asymmetric key size below 2048 bits"
    description = (
        "KeyPairGenerator.initialize is called with 512 or 1024 bits. Keys "
        "below 2048 bits (RSA/DSA) are factorable/breakable with moderate "
        "resources."
    )
    rationale = (
        "1024-bit RSA is within reach of well-funded attackers and deprecated "
        "by NIST; 512-bit keys are trivially broken."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-326"]
    remediation = (
        "Generate RSA keys of at least 2048 bits (3072+ preferred), or use "
        "EC keys (secp256r1 or stronger) via KeyPairGenerator."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/326.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"\.initialize\s*\(\s*(512|1024)\b", iter_source_files(ctx))
        if not hits:
            return pass_result(self, "No KeyPairGenerator.initialize(512/1024) found.")
        evidence = [
            evidence_from_hit(
                ctx, h, f"Key pair initialized with only {h.match.group(1)} bits"
            )
            for h in hits
        ]
        return finding(
            self,
            f"Key size of {', '.join(sorted({h.match.group(1) for h in hits}))} "
            f"bit(s) in {len(hits)} location(s).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Sub-2048-bit asymmetric keys can be broken, exposing "
                "encrypted data and signatures."
            ),
            confidence_rationale=(
                "The key size is passed explicitly to initialize(); the size "
                "applies to the generator's algorithm (RSA/DSA/EC)."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C12  Weak signature algorithms
# ---------------------------------------------------------------------------

class RuleC12WeakSignature(_CryptoRule):
    id = "BS-C12"
    title = "Weak signature algorithm (SHA1withRSA, MD5withRSA, ...)"
    description = (
        "Signature.getInstance is called with SHA1withRSA, MD5withRSA, "
        "SHA1withDSA or similar. MD5/SHA-1 based signatures are vulnerable "
        "to collision attacks."
    )
    rationale = (
        "Collision attacks on MD5/SHA-1 let attackers forge signatures over "
        "attacker-chosen data that collides with legitimate signed data."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-327"]
    remediation = (
        "Use Signature.getInstance(\"SHA256withRSA\") (or SHA384/SHA512, or "
        "SHA256withECDSA) with RSA keys >= 2048 bits."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r'Signature\s*\.\s*getInstance\s*\(\s*"(?:MD5|SHA1)with(?:RSA|DSA|ECDSA)"',
            iter_source_files(ctx),
            flags=re.IGNORECASE,
        )
        if not hits:
            return pass_result(self, "No weak Signature algorithm usage found.")
        evidence = [
            evidence_from_hit(
                ctx, h, f"Weak signature algorithm: {h.match.group(0)[:80]}"
            )
            for h in hits
        ]
        return finding(
            self,
            f"Weak signature algorithm(s) in {len(hits)} location(s).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Signatures over MD5/SHA-1 digests can be forged via "
                "collision attacks, undermining authenticity guarantees."
            ),
            confidence_rationale=(
                "The weak algorithm name is passed explicitly to "
                "Signature.getInstance."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C13  Key material in SharedPreferences
# ---------------------------------------------------------------------------

class RuleC13KeyInPrefs(_CryptoRule):
    id = "BS-C13"
    title = "Cryptographic key material stored in SharedPreferences"
    description = (
        "SharedPreferences.putString is called with a key name suggesting "
        "crypto material (key, secret, token, password, aes, private, ...). "
        "SharedPreferences are stored as world-readable-adjacent XML on "
        "rooted devices and in backups."
    )
    rationale = (
        "Preferences XML is plaintext in the app's data directory; on rooted "
        "devices, via backup extraction, or on lost devices it exposes key "
        "material to anyone who obtains it."
    )
    default_severity = Severity.HIGH
    owasp = ["M10"]
    cwe = ["CWE-312"]
    masvs = ["MSTG-CRYPTO", "MSTG-STORAGE"]
    remediation = (
        "Store keys in the Android Keystore (AndroidKeyStore) or use "
        "EncryptedSharedPreferences from androidx.security for sensitive "
        "values; never persist raw key material in plaintext XML."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/312.html",
        "https://developer.android.com/training/articles/keystore",
    ]

    _KEY_NAME = re.compile(
        r"(?:^|[^A-Za-z])(key|secret|token|password|passwd|aes|private|crypto|credential|passphrase)(?:[^A-Za-z]|$)",
        re.IGNORECASE,
    )

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(r"\.putString\s*\(\s*\"([^\"]*)\"", iter_source_files(ctx))
        evidence = []
        for hit in hits:
            name = hit.match.group(1)
            if self._KEY_NAME.search(name):
                evidence.append(
                    evidence_from_hit(
                        ctx,
                        hit,
                        f"putString with key-material-like name \"{name[:60]}\"",
                    )
                )
        if not evidence:
            return pass_result(
                self, "No key-material-like names stored via putString found."
            )
        return finding(
            self,
            f"Possible key material in SharedPreferences in {len(evidence)} "
            "location(s).",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Key material in plaintext preferences XML is exposed on "
                "rooted devices and via backups, defeating the encryption it "
                "is meant to support."
            ),
            confidence_rationale=(
                "The preference name matches key/secret/token/password-like "
                "patterns, but the stored value was not proven to be key "
                "material statically."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C14  AES/CBC without integrity protection
# ---------------------------------------------------------------------------

class RuleC14CbcNoIntegrity(_CryptoRule):
    id = "BS-C14"
    title = "AES/CBC used without observed integrity protection"
    description = (
        "A file uses Cipher \"AES/CBC/...\" but contains no "
        "javax.crypto.Mac / HmacSHA usage. CBC alone gives confidentiality "
        "without integrity, enabling padding-oracle and ciphertext-malleability "
        "attacks where an oracle exists."
    )
    rationale = (
        "Encrypt-then-MAC (or an AEAD mode like GCM) is required; CBC without "
        "a MAC is malleable and vulnerable to padding oracles when decryption "
        "errors are observable."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-327"]
    remediation = (
        "Prefer Cipher.getInstance(\"AES/GCM/NoPadding\"). If CBC must stay, "
        "add encrypt-then-MAC with HmacSHA256 over (IV || ciphertext) using "
        "an independent key, and verify the MAC before decrypting."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://developer.android.com/guide/topics/security/cryptography",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r'Cipher\s*\.\s*getInstance\s*\(\s*"[^"]*AES/CBC[^"]*"',
            iter_source_files(ctx),
        )
        if not hits:
            return pass_result(self, "No AES/CBC Cipher usage found.")
        by_file: dict[Path, list] = {}
        for hit in hits:
            by_file.setdefault(hit.path, []).append(hit)
        evidence = []
        for path, file_hits in by_file.items():
            text = read_text_capped(path)
            if text is None:
                continue
            if re.search(r"Mac\s*\.\s*getInstance|HmacSHA|javax\.crypto\.Mac", text):
                continue  # integrity protection observed in this file
            evidence.append(
                evidence_from_hit(
                    ctx,
                    file_hits[0],
                    "AES/CBC used in a file with no Mac/HmacSHA integrity "
                    "protection observed",
                )
            )
        if not evidence:
            return pass_result(
                self, "AES/CBC usage is accompanied by Mac/Hmac integrity checks."
            )
        return needs_review(
            self,
            f"AES/CBC without observed integrity protection in "
            f"{len(evidence)} file(s).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "CBC without a MAC is malleable; where decryption errors are "
                "observable this enables padding-oracle decryption."
            ),
            confidence_rationale=(
                "AES/CBC is explicit but no javax.crypto.Mac/HmacSHA usage "
                "was found in the same file; integrity could still be handled "
                "in another class, so this needs review rather than a firm "
                "finding."
            ),
        )


# ---------------------------------------------------------------------------
# BS-C15  Hardcoded weak crypto configuration constants
# ---------------------------------------------------------------------------

class RuleC15HardcodedCryptoConfig(_CryptoRule):
    id = "BS-C15"
    title = "Hardcoded weak cryptographic configuration constant"
    description = (
        "A static final String constant named like ALGORITHM, TRANSFORMATION, "
        "CIPHER or MODE is assigned a weak algorithm or mode (DES, RC4, ECB, "
        "DESede, Blowfish). Centralized config makes the weak choice easy to "
        "miss and reuse everywhere."
    )
    rationale = (
        "Hardcoded weak transformations propagate to every Cipher.getInstance "
        "that references the constant; the indirection hides the weakness "
        "from casual review."
    )
    default_severity = Severity.MEDIUM
    owasp = ["M10"]
    cwe = ["CWE-327"]
    remediation = (
        "Set the constant to \"AES/GCM/NoPadding\" (or remove the indirection "
        "and use the strong transformation directly at each call site)."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://mas.owasp.org/MASTG/",
    ]

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(
            r"static\s+final\s+String\s+(\w*(?:ALGORITHM|TRANSFORMATION|CIPHER|MODE)\w*)\s*=\s*\"([^\"]*)\"",
            iter_source_files(ctx),
            flags=re.IGNORECASE,
        )
        evidence = []
        for hit in hits:
            literal = hit.match.group(2)
            if re.search(r"(?i)(DES|RC4|\bECB\b|Blowfish)", literal):
                evidence.append(
                    evidence_from_hit(
                        ctx,
                        hit,
                        f"Crypto config constant '{hit.match.group(1)}' set to "
                        f"weak value \"{literal[:60]}\"",
                    )
                )
        if not evidence:
            return pass_result(
                self, "No hardcoded weak crypto configuration constants found."
            )
        return finding(
            self,
            f"Weak crypto configuration constant(s) in {len(evidence)} "
            "location(s).",
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "A weak algorithm/mode baked into a shared constant is reused "
                "by every call site, giving the same impact as BS-C03/BS-C04 "
                "wherever it is referenced."
            ),
            confidence_rationale=(
                "The constant name indicates crypto configuration and its "
                "literal value names a weak algorithm or mode explicitly."
            ),
        )


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    RuleC01Md5SecurityContext(),
    RuleC02Sha1SecurityUse(),
    RuleC03WeakCipher(),
    RuleC04AesEcb(),
    RuleC05HardcodedKey(),
    RuleC06HardcodedIv(),
    RuleC07WeakRandom(),
    RuleC08CustomCrypto(),
    RuleC09WeakKdf(),
    RuleC10UnsaltedPasswordHash(),
    RuleC11SmallKeySize(),
    RuleC12WeakSignature(),
    RuleC13KeyInPrefs(),
    RuleC14CbcNoIntegrity(),
    RuleC15HardcodedCryptoConfig(),
]

__all__ = ["RULES"]
