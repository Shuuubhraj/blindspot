"""Blindspot storage rules (BS-S01 .. BS-S20): insecure data storage & privacy.

Each rule inspects real artifacts (decompiled sources, decoded resources,
assets) and reports only what it actually finds, with real 1-based line
numbers. Never treat PASS as proof a vulnerability is impossible.

Rule index:
  BS-S01  Hardcoded credentials (password/passwd/pwd/secret literals)
  BS-S02  Hardcoded API keys and tokens (structured prefixes / key names)
  BS-S03  Private key material embedded in assets/resources/sources
  BS-S04  MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE usage
  BS-S05  Sensitive data written to external storage
  BS-S06  Sensitive SharedPreferences entries without EncryptedSharedPreferences
  BS-S07  Plaintext secrets in SQLite statements
  BS-S08  Secrets stored via openFileOutput
  BS-S09  Sensitive literals written to the app cache directory
  BS-S10  Sensitive information leaked through logging APIs
  BS-S11  Plaintext secrets in string/resource XML
  BS-S12  Sensitive data copied to the clipboard
  BS-S13  Missing FLAG_SECURE on sensitive screens (login/payment/PIN)
  BS-S14  Sensitive extras passed through Intents
  BS-S15  FileProvider path rules granting external-path / root-path
  BS-S16  Sensitive data in URL query parameters
  BS-S17  WebView setSavePassword(true)
  BS-S18  Backup rules including sensitive data domains
  BS-S19  Sensitive data in temporary files
  BS-S20  Secrets leaked via System.out.println / printStackTrace
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
    pass_result,
)
from .common import (
    Hit,
    evidence_from_hit,
    evidence_simple,
    grep,
    iter_files,
    iter_source_files,
    iter_text_artifacts,
    java_string_literals,
    looks_like_secret,
    read_text_capped,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Sensitive keyword fragment used by many rules. Purposely narrow: these
# rules detect evidence, they do not classify data semantics.
_SENSITIVE_KW = r"(?:password|passwd|pwd|secret|token|session|ssn|credit.?card|card.?number|auth_?key|api_?key)"
_SENSITIVE_RX = re.compile(_SENSITIVE_KW, re.IGNORECASE)

_MAX_EVIDENCE = 15


def _has_java(ctx: ScanContext) -> bool:
    return bool(ctx.java_roots)


def _has_res(ctx: ScanContext) -> bool:
    return ctx.res_dir is not None


def _has_res_or_assets(ctx: ScanContext) -> bool:
    return ctx.res_dir is not None or ctx.assets_dir is not None


def _window_text(path: Path, line_no: int, radius: int = 5) -> str:
    """Return the joined source lines around a 1-based line number."""
    text = read_text_capped(path)
    if text is None:
        return ""
    lines = text.splitlines()
    lo = max(0, line_no - 1 - radius)
    hi = min(len(lines), line_no + radius)
    return "\n".join(lines[lo:hi])


def _cap(evidence: list[Evidence]) -> list[Evidence]:
    return evidence[:_MAX_EVIDENCE]


# ---------------------------------------------------------------------------
# BS-S01: hardcoded credentials in Java/Kotlin sources
# ---------------------------------------------------------------------------

_ASSIGN_RX = re.compile(r'\b([A-Za-z_][\w$]*)\s*=\s*"((?:[^"\\\n]|\\.)*)"')
_CRED_NAME_RX = re.compile(r"(password|passwd|pwd|secret)", re.IGNORECASE)
_NOT_CRED_NAME_RX = re.compile(r"(api|token|key)", re.IGNORECASE)  # covered by BS-S02
_PLACEHOLDERS = {
    "password", "passwd", "pwd", "secret", "changeme", "change_me",
    "xxx", "***", "null", "undefined", "todo", "example", "test",
    "your_password", "enter_password",
}


def _is_placeholder(lit: str) -> bool:
    low = lit.strip().lower()
    if not low or len(low) < 4:
        return True
    if low in _PLACEHOLDERS:
        return True
    if set(low) == {"*"}:
        return True
    if low.startswith(("your_", "enter_", "example")):
        return True
    if "example" in low:
        return True
    return False


class BS_S01_HardcodedCredentials(Rule):
    id = "BS-S01"
    title = "Hardcoded credentials in source code"
    description = (
        "A string literal that looks like a credential is assigned to a "
        "variable/constant whose name indicates a password or secret "
        "(e.g. *password*, *passwd*, *pwd*, *secret*). API keys/tokens are "
        "covered separately by BS-S02."
    )
    rationale = (
        "Hardcoded credentials in the APK can be recovered by anyone who "
        "decompiles the package and may grant access to backends, admin "
        "interfaces or encrypted data."
    )
    category = "storage"
    default_severity = Severity.HIGH
    owasp = ["M1"]
    cwe = ["CWE-798"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Remove the hardcoded credential. Load it from a server-side "
        "session at runtime, use Android Keystore-backed tokens, or gate "
        "the functionality behind user authentication. Never ship "
        "credentials inside the APK."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://owasp.org/www-project-mobile-top-10/",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        seen: set[tuple[str, int]] = set()
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None:
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                for m in _ASSIGN_RX.finditer(line):
                    name, lit = m.group(1), m.group(2)
                    if not _CRED_NAME_RX.search(name):
                        continue
                    if _NOT_CRED_NAME_RX.search(name):
                        continue  # BS-S02 owns api/key/token names
                    if _is_placeholder(lit):
                        continue
                    key = (str(path), i)
                    if key in seen:
                        continue
                    seen.add(key)
                    hit = Hit(path=path, line_no=i, line=line, match=m)
                    evidence.append(evidence_from_hit(
                        ctx, hit,
                        description=f"Literal assigned to credential-like "
                                    f"variable '{name}'",
                    ))
                    if len(evidence) >= _MAX_EVIDENCE:
                        break
                if len(evidence) >= _MAX_EVIDENCE:
                    break
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if not evidence:
            return pass_result(
                self,
                "No string literals assigned to password/secret-named "
                "variables were found in the decompiled sources.",
            )
        return finding(
            self,
            f"Found {len(evidence)} hardcoded credential assignment(s) in "
            "decompiled sources.",
            evidence=_cap(evidence),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "A hardcoded password/secret ships with the APK and is "
                "recoverable by decompilation; if valid it may grant "
                "unauthorized access."
            ),
            confidence_rationale=(
                "The variable name indicates a credential and the assigned "
                "value is a non-placeholder string literal on a real source "
                "line."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S02: hardcoded API keys / tokens
# ---------------------------------------------------------------------------

_KEY_PREFIX_RX = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|"
    r"xox[bap]-[A-Za-z0-9-]{8,}|sk-[A-Za-z0-9]{8,}|AIza[0-9A-Za-z\-_]{20,})"
)
_KEY_NAME_RX = re.compile(r"(api_?key|apikey|token)", re.IGNORECASE)


class BS_S02_HardcodedApiKeys(Rule):
    id = "BS-S02"
    title = "Hardcoded API keys and tokens in source code"
    description = (
        "A string literal matches a well-known secret format (AWS AKIA, "
        "GitHub ghp_/gho_, Slack xox*, Stripe-style sk-, Google AIza) or is "
        "assigned to an api_key/apikey/token-named variable and looks like "
        "a secret."
    )
    rationale = (
        "API keys and tokens baked into the APK can be extracted and abused "
        "against third-party services, often with billing consequences."
    )
    category = "storage"
    default_severity = Severity.HIGH
    owasp = ["M1"]
    cwe = ["CWE-798"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Do not ship API keys in the client. Proxy third-party calls "
        "through your own backend, restrict keys by package/SHA-1 where the "
        "provider supports it, and rotate any key found in the package."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://owasp.org/www-project-mobile-top-10/",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        seen: set[tuple[str, int]] = set()
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None:
                continue
            lines = text.splitlines()
            # Path 1: structured secret formats inside string literals.
            for line_no, lit in java_string_literals(text):
                if _KEY_PREFIX_RX.search(lit):
                    key = (str(path), line_no)
                    if key not in seen:
                        seen.add(key)
                        m = _KEY_PREFIX_RX.search(lit)
                        hit = Hit(path=path, line_no=line_no,
                                  line=lines[line_no - 1], match=m)
                        evidence.append(evidence_from_hit(
                            ctx, hit,
                            description="String literal matches a known "
                                        "API-key/token format",
                        ))
            # Path 2: api_key/apikey/token-named variables with secret values.
            for i, line in enumerate(lines, start=1):
                for m in _ASSIGN_RX.finditer(line):
                    name, lit = m.group(1), m.group(2)
                    if not _KEY_NAME_RX.search(name):
                        continue
                    if not looks_like_secret(lit):
                        continue
                    key = (str(path), i)
                    if key not in seen:
                        seen.add(key)
                        hit = Hit(path=path, line_no=i, line=line, match=m)
                        evidence.append(evidence_from_hit(
                            ctx, hit,
                            description=f"Secret-looking value assigned to "
                                        f"key/token variable '{name}'",
                        ))
                if len(evidence) >= _MAX_EVIDENCE:
                    break
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if not evidence:
            return pass_result(
                self,
                "No structured API-key/token formats or secret-looking "
                "key/token assignments were found in the decompiled sources.",
            )
        return finding(
            self,
            f"Found {len(evidence)} hardcoded API key/token occurrence(s).",
            evidence=_cap(evidence),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Extractable keys can be abused directly against third-party "
                "services; impact includes data theft and unexpected charges."
            ),
            confidence_rationale=(
                "Values match documented secret formats or sit in "
                "key/token-named variables and pass a secret heuristic on "
                "real source lines."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S03: private key material in the package
# ---------------------------------------------------------------------------

_PEM_PRIV_RX = re.compile(
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"
)
_KEYFILE_EXTS = {".p12", ".jks", ".keystore", ".pfx", ".bks", ".pk8"}


class BS_S03_PrivateKeyMaterial(Rule):
    id = "BS-S03"
    title = "Private key material embedded in the package"
    description = (
        "PEM private-key blocks (-----BEGIN ... PRIVATE KEY-----) found in "
        "sources or text artifacts, or key container files (*.p12, *.jks, "
        "*.keystore, *.pfx, *.bks, *.pk8) shipped in assets/resources."
    )
    rationale = (
        "Private keys bundled with the app can be extracted and used to "
        "impersonate the app, decrypt traffic, or sign malicious content."
    )
    category = "storage"
    default_severity = Severity.HIGH
    owasp = ["M1"]
    cwe = ["CWE-321"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Remove private keys from the package. Use Android Keystore for "
        "device-generated keys and fetch any required key material from a "
        "server over an authenticated channel at runtime."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/321.html",
        "https://developer.android.com/training/articles/keystore",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_res_or_assets(ctx) or _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        seen: set[tuple[str, int]] = set()
        roots = [d for d in (ctx.res_dir, ctx.assets_dir) if d]
        # PEM blocks in text artifacts, decompiled sources, and key-like
        # text files (.pem/.key) that iter_text_artifacts does not cover.
        file_sets = [iter_text_artifacts(ctx), iter_source_files(ctx)]
        for root in roots:
            file_sets.append(iter_files([root], {".pem", ".key", ".txt"}))
        for files in file_sets:
            for hit in grep(_PEM_PRIV_RX.pattern, files):
                key = (str(hit.path), hit.line_no)
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(evidence_from_hit(
                    ctx, hit, description="PEM private-key block"))
                if len(evidence) >= _MAX_EVIDENCE:
                    break
            if len(evidence) >= _MAX_EVIDENCE:
                break
        # Key container files in assets/resources.
        for root in roots:
            for path in root.rglob("*"):
                if not path.is_file() or path.is_symlink():
                    continue
                if path.suffix.lower() not in _KEYFILE_EXTS:
                    continue
                evidence.append(evidence_simple(
                    ctx, path,
                    description=f"Embedded key container file "
                                f"({path.suffix.lower()}) shipped in the "
                                f"package",
                    snippet=f"file: {path.name} "
                            f"({path.stat().st_size} bytes)",
                ))
                if len(evidence) >= _MAX_EVIDENCE:
                    break
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if not evidence:
            return pass_result(
                self,
                "No PEM private-key blocks or key container files were "
                "found in the inspected artifacts.",
            )
        return finding(
            self,
            f"Found {len(evidence)} embedded private-key material "
            "occurrence(s).",
            evidence=_cap(evidence),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "A private key inside the APK is extractable by anyone and "
                "defeats the purpose of asymmetric cryptography."
            ),
            confidence_rationale=(
                "PEM private-key headers were matched literally, or a file "
                "with a key-container extension was found in assets/res."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S04: MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE
# ---------------------------------------------------------------------------

_WORLD_MODE_RX = re.compile(r"\bMODE_WORLD_(?:READABLE|WRITEABLE)\b")


class BS_S04_WorldAccessibleModes(Rule):
    id = "BS-S04"
    title = "World-readable/writable file modes (MODE_WORLD_*)"
    description = (
        "Use of the deprecated MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE "
        "constants when opening files or preferences."
    )
    rationale = (
        "These modes make app files readable/writable by every other app on "
        "the device, exposing any stored data. They were deprecated in API "
        "17 and throw on API 24+."
    )
    category = "storage"
    default_severity = Severity.HIGH
    owasp = ["M9"]
    cwe = ["CWE-276"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Use MODE_PRIVATE (the default) for all files and preferences. "
        "Share data with other apps explicitly via a FileProvider with "
        "grantUriPermissions, not world-accessible modes."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/276.html",
        "https://developer.android.com/training/data-storage",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(_WORLD_MODE_RX.pattern, iter_source_files(ctx))
        if not hits:
            return pass_result(
                self,
                "No MODE_WORLD_READABLE/MODE_WORLD_WRITEABLE usage found.",
            )
        evidence = [
            evidence_from_hit(ctx, h, description=f"World-accessible mode: "
                              f"{h.match.group(0)}")
            for h in hits[:_MAX_EVIDENCE]
        ]
        return finding(
            self,
            f"Found {len(hits)} use(s) of MODE_WORLD_READABLE/WRITEABLE.",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Any data written with these modes is accessible to all "
                "apps on the device."
            ),
            confidence_rationale=(
                "The deprecated constant names were matched literally in "
                "decompiled source."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S05: sensitive data written to external storage
# ---------------------------------------------------------------------------

_EXTERNAL_RX = re.compile(
    r"getExternalStorage(?:Directory|PublicDirectory)?\s*\(|"
    r"getExternalFilesDir\s*\(|getExternalMediaDirs\s*\("
)


class BS_S05_ExternalStorageSensitive(Rule):
    id = "BS-S05"
    title = "Sensitive data written to external storage"
    description = (
        "External-storage APIs (getExternalStorage*, getExternalFilesDir, "
        "getExternalMediaDirs) used within a few lines of sensitive "
        "keywords (password, token, secret, ssn, card data)."
    )
    rationale = (
        "External storage is world-readable on many devices/configurations "
        "and is included in unencrypted backups; secrets written there can "
        "be read by other apps."
    )
    category = "storage"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-312"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Keep sensitive data in internal storage (getFilesDir) or "
        "EncryptedSharedPreferences/Android Keystore. Only non-sensitive "
        "data belongs on external storage."
    )
    references = [
        "https://developer.android.com/training/data-storage",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        for hit in grep(_EXTERNAL_RX.pattern, iter_source_files(ctx)):
            window = _window_text(hit.path, hit.line_no, radius=8)
            if _SENSITIVE_RX.search(window):
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    description="External-storage API near sensitive "
                                "keyword (password/token/secret/ssn/card)",
                ))
                if len(evidence) >= _MAX_EVIDENCE:
                    break
        if not evidence:
            return pass_result(
                self,
                "No external-storage usage adjacent to sensitive keywords "
                "was found.",
            )
        return finding(
            self,
            f"Found {len(evidence)} external-storage call(s) adjacent to "
            "sensitive keywords.",
            evidence=_cap(evidence),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "External storage is broadly readable; sensitive data "
                "written there is exposed to other apps."
            ),
            confidence_rationale=(
                "The external-storage call is real, but the nearby keyword "
                "is a heuristic link rather than proven data flow."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S06: SharedPreferences with sensitive keys, no EncryptedSharedPreferences
# ---------------------------------------------------------------------------

_PUTSTRING_RX = re.compile(
    r'\.\s*putString\s*\(\s*"((?:[^"\\\n]|\\.)*)"'
)
_ENC_PREFS_RX = re.compile(r"\bEncryptedSharedPreferences\b")


class BS_S06_UnencryptedSharedPreferences(Rule):
    id = "BS-S06"
    title = "Sensitive data in SharedPreferences without EncryptedSharedPreferences"
    description = (
        "putString() calls store password/token/session-like keys while no "
        "EncryptedSharedPreferences usage exists anywhere in the app. The "
        "actual values cannot be confirmed statically, so this needs review."
    )
    rationale = (
        "SharedPreferences are stored as plaintext XML in the app's private "
        "directory; on rooted devices or via backup extraction the values "
        "are trivially readable."
    )
    category = "storage"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-312"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Store sensitive values with EncryptedSharedPreferences (AndroidX "
        "Security) backed by Android Keystore, or move them server-side. "
        "Avoid persisting passwords at all; persist short-lived tokens."
    )
    references = [
        "https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        sources = list(iter_source_files(ctx))
        if grep(_ENC_PREFS_RX.pattern, iter(sources)):
            return pass_result(
                self,
                "EncryptedSharedPreferences is used by the app; sensitive "
                "preferences appear protected.",
            )
        evidence: list[Evidence] = []
        for hit in grep(_PUTSTRING_RX.pattern, iter(sources)):
            key = hit.match.group(1)
            if not _SENSITIVE_RX.search(key):
                continue
            evidence.append(evidence_from_hit(
                ctx, hit,
                description=f"Sensitive preference key '{key}' stored via "
                            f"putString; no EncryptedSharedPreferences "
                            f"usage found anywhere in the app",
            ))
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if not evidence:
            return pass_result(
                self,
                "No sensitive (password/token/session-like) keys stored via "
                "SharedPreferences putString were found.",
            )
        return needs_review(
            self,
            f"Found {len(evidence)} sensitive putString() call(s) with no "
            "EncryptedSharedPreferences usage in the app.",
            evidence=_cap(evidence),
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "If the stored values are real secrets, they sit in "
                "plaintext XML readable on rooted devices."
            ),
            confidence_rationale=(
                "The preference keys look sensitive and no encrypted "
                "preferences API is used, but the actual runtime values "
                "cannot be confirmed statically."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S07: plaintext secrets in SQLite statements
# ---------------------------------------------------------------------------

_SQL_CALL_RX = re.compile(
    r'\b(?:execSQL|rawQuery|compileStatement)\s*\(\s*"((?:[^"\\\n]|\\.)*)"'
)
_SQL_WRITE_RX = re.compile(r"(?i)\b(?:insert\s+into|update\s+\w+|replace\s+into)\b")
_SQL_SECRET_COL_RX = re.compile(r"(?i)\b(?:password|passwd|pwd|token|secret)\b")


class BS_S07_SqlitePlaintextSecrets(Rule):
    id = "BS-S07"
    title = "Plaintext secrets in SQLite statements"
    description = (
        "execSQL/rawQuery/compileStatement calls whose SQL string performs "
        "an INSERT/UPDATE/REPLACE referencing password/token/secret "
        "columns, indicating secrets stored without evident protection."
    )
    rationale = (
        "SQLite databases in the app's private directory are plaintext by "
        "default; secrets written via raw SQL are readable on rooted "
        "devices or from backups."
    )
    category = "storage"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-312"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Do not persist plaintext secrets in SQLite. Use SQLCipher with a "
        "Keystore-backed key for sensitive databases, or keep secrets out "
        "of the local database entirely."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/312.html",
        "https://developer.android.com/training/data-storage/room",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None:
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                for m in _SQL_CALL_RX.finditer(line):
                    sql = m.group(1)
                    if not _SQL_WRITE_RX.search(sql):
                        continue
                    if not _SQL_SECRET_COL_RX.search(sql):
                        continue
                    hit = Hit(path=path, line_no=i, line=line, match=m)
                    evidence.append(evidence_from_hit(
                        ctx, hit,
                        description="SQL write referencing a "
                                    "secret-like column",
                    ))
                    if len(evidence) >= _MAX_EVIDENCE:
                        break
                if len(evidence) >= _MAX_EVIDENCE:
                    break
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if not evidence:
            return pass_result(
                self,
                "No SQL write statements referencing secret-like columns "
                "were found.",
            )
        return finding(
            self,
            f"Found {len(evidence)} SQL statement(s) writing to "
            "secret-like columns.",
            evidence=_cap(evidence),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Secrets persisted in a plaintext SQLite database are "
                "recoverable from the device."
            ),
            confidence_rationale=(
                "The SQL text literally names secret-like columns in a "
                "write statement, but whether encryption (e.g. SQLCipher) "
                "is applied cannot be confirmed from this line alone."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S08: secrets stored via openFileOutput
# ---------------------------------------------------------------------------

_OPENFILE_RX = re.compile(r"\bopenFileOutput\s*\(")


class BS_S08_OpenFileOutputSecrets(Rule):
    id = "BS-S08"
    title = "Secrets stored via openFileOutput"
    description = (
        "openFileOutput() calls with sensitive keywords (password, token, "
        "secret) nearby, indicating secrets written to internal files "
        "without evident encryption."
    )
    rationale = (
        "Internal files are plaintext by default; secrets written with "
        "openFileOutput are readable on rooted devices or via backup "
        "extraction."
    )
    category = "storage"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-312"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Encrypt sensitive data before writing it to files (e.g. "
        "EncryptedFile from AndroidX Security with a Keystore-backed key) "
        "or avoid persisting secrets on disk."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/312.html",
        "https://developer.android.com/training/data-storage",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        for hit in grep(_OPENFILE_RX.pattern, iter_source_files(ctx)):
            window = _window_text(hit.path, hit.line_no, radius=10)
            if _SENSITIVE_RX.search(window):
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    description="openFileOutput near sensitive keyword "
                                "(password/token/secret)",
                ))
                if len(evidence) >= _MAX_EVIDENCE:
                    break
        if not evidence:
            return pass_result(
                self,
                "No openFileOutput calls adjacent to sensitive keywords "
                "were found.",
            )
        return finding(
            self,
            f"Found {len(evidence)} openFileOutput call(s) adjacent to "
            "sensitive keywords.",
            evidence=_cap(evidence),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Files written this way are plaintext; any secret among "
                "them is recoverable from the device."
            ),
            confidence_rationale=(
                "The file-write call is real, but the nearby keyword is a "
                "heuristic link rather than proven data flow."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S09: sensitive literals written to the cache directory
# ---------------------------------------------------------------------------

_CACHEDIR_RX = re.compile(r"\bgetCacheDir\s*\(")


class BS_S09_CacheDirSensitive(Rule):
    id = "BS-S09"
    title = "Sensitive data written to the cache directory"
    description = (
        "getCacheDir() usage with sensitive keywords nearby, indicating "
        "secrets or sensitive literals written to the app cache."
    )
    rationale = (
        "The cache directory is not a safe place for sensitive data: it is "
        "plaintext, may be included in backups, and can linger longer than "
        "expected."
    )
    category = "storage"
    default_severity = Severity.LOW
    owasp = ["M9"]
    cwe = ["CWE-312"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Do not write secrets to the cache directory. Use "
        "EncryptedSharedPreferences/Keystore for secrets and keep the "
        "cache for non-sensitive, regenerable data only."
    )
    references = [
        "https://developer.android.com/training/data-storage",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        for hit in grep(_CACHEDIR_RX.pattern, iter_source_files(ctx)):
            window = _window_text(hit.path, hit.line_no, radius=6)
            if _SENSITIVE_RX.search(window):
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    description="getCacheDir() near sensitive keyword "
                                "(password/token/secret)",
                ))
                if len(evidence) >= _MAX_EVIDENCE:
                    break
        if not evidence:
            return pass_result(
                self,
                "No getCacheDir usage adjacent to sensitive keywords was "
                "found.",
            )
        return finding(
            self,
            f"Found {len(evidence)} getCacheDir call(s) adjacent to "
            "sensitive keywords.",
            evidence=_cap(evidence),
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Cache contents are plaintext and may persist or be backed "
                "up; low impact unless the data is highly sensitive."
            ),
            confidence_rationale=(
                "The cache-directory call is real, but the nearby keyword "
                "is a heuristic link rather than proven data flow."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S10: sensitive information in logs
# ---------------------------------------------------------------------------

_LOG_RX = re.compile(
    r"\b(?:android\.util\.)?Log\.(?:d|i|v|w|e|wtf)\s*\(|"
    r"\bTimber\.(?:d|i|v|w|e)\s*\("
)


class BS_S10_SensitiveLogging(Rule):
    id = "BS-S10"
    title = "Sensitive information written to logs"
    description = (
        "Log.d/i/v/w/e/wtf or Timber logging calls whose statement "
        "contains sensitive keywords (password, token, auth, secret, "
        "session)."
    )
    rationale = (
        "Logcat output can be read by other apps (pre-4.1 widely, and via "
        "ADB/bug reports generally); secrets in logs leak to anyone with "
        "log access."
    )
    category = "storage"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-532"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Never log secrets, tokens, or credentials. Log redacted or hashed "
        "identifiers instead, strip logging in release builds "
        "(BuildConfig.DEBUG guards / ProGuard), and audit existing calls."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/532.html",
        "https://developer.android.com/reference/android/util/Log",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        for hit in grep(_LOG_RX.pattern, iter_source_files(ctx)):
            if _SENSITIVE_RX.search(hit.line):
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    description="Logging call whose statement contains a "
                                "sensitive keyword",
                ))
                if len(evidence) >= _MAX_EVIDENCE:
                    break
        if not evidence:
            return pass_result(
                self,
                "No logging calls with sensitive keywords in the same "
                "statement were found.",
            )
        return finding(
            self,
            f"Found {len(evidence)} logging call(s) with sensitive keywords.",
            evidence=_cap(evidence),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Secrets in logcat are exposed to other apps, ADB users, "
                "and bug reports."
            ),
            confidence_rationale=(
                "The keyword appears in the logged statement itself, but "
                "whether the actual secret value (vs. a label) is logged "
                "needs a look at the surrounding code."
            ),
        )

# ---------------------------------------------------------------------------
# BS-S11: plaintext secrets in string/resource XML
# ---------------------------------------------------------------------------

_STRING_RX = re.compile(
    r'<string\s+name="([^"]+)"[^>]*>([^<]*)</string>', re.IGNORECASE
)


class BS_S11_SecretsInResources(Rule):
    id = "BS-S11"
    title = "Plaintext secrets in resource XML"
    description = (
        "<string> resources whose name indicates a password/api_key/token "
        "and whose value looks like a real secret."
    )
    rationale = (
        "String resources are packaged in plaintext inside the APK; anyone "
        "who unpacks it can read API keys and other secrets from "
        "res/values."
    )
    category = "storage"
    default_severity = Severity.MEDIUM
    owasp = ["M1"]
    cwe = ["CWE-798"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Do not ship secrets in resources. Fetch keys/tokens from your "
        "backend at runtime after authentication, and rotate any secret "
        "found in res/."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_res(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        for path in iter_files([ctx.res_dir], {".xml"}):
            text = read_text_capped(path)
            if text is None:
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                for m in _STRING_RX.finditer(line):
                    name, value = m.group(1), m.group(2).strip()
                    if not _SENSITIVE_RX.search(name):
                        continue
                    if not looks_like_secret(value):
                        continue
                    hit = Hit(path=path, line_no=i, line=line, match=m)
                    evidence.append(evidence_from_hit(
                        ctx, hit,
                        description=f"Secret-looking value in string "
                                    f"resource '{name}'",
                    ))
                    if len(evidence) >= _MAX_EVIDENCE:
                        break
                if len(evidence) >= _MAX_EVIDENCE:
                    break
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if not evidence:
            return pass_result(
                self,
                "No secret-looking values in sensitive-named string "
                "resources were found.",
            )
        return finding(
            self,
            f"Found {len(evidence)} resource string(s) holding "
            "secret-looking values.",
            evidence=_cap(evidence),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Resource values ship in plaintext inside the APK and are "
                "trivially extractable."
            ),
            confidence_rationale=(
                "The resource name indicates a secret and the value passes "
                "a secret heuristic on a real XML line."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S12: sensitive data copied to the clipboard
# ---------------------------------------------------------------------------

_CLIP_RX = re.compile(
    r"\bsetPrimaryClip\s*\(|ClipData\s*\.\s*newPlainText\s*\("
)


class BS_S12_ClipboardSensitive(Rule):
    id = "BS-S12"
    title = "Sensitive data copied to the clipboard"
    description = (
        "ClipboardManager.setPrimaryClip / ClipData.newPlainText calls with "
        "password/token/secret keywords nearby, indicating sensitive data "
        "placed on the system clipboard."
    )
    rationale = (
        "Any app can read the clipboard (with focus on modern Android, "
        "freely on older versions); passwords or tokens copied there are "
        "exposed to other apps."
    )
    category = "storage"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-200"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Avoid placing secrets on the clipboard. If copy is unavoidable, "
        "clear the clipboard after a short timeout and warn the user; "
        "prefer autofill APIs for credentials."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://developer.android.com/guide/topics/text/copy-paste",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        for hit in grep(_CLIP_RX.pattern, iter_source_files(ctx)):
            window = _window_text(hit.path, hit.line_no, radius=6)
            if _SENSITIVE_RX.search(window):
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    description="Clipboard write near sensitive keyword "
                                "(password/token/secret)",
                ))
                if len(evidence) >= _MAX_EVIDENCE:
                    break
        if not evidence:
            return pass_result(
                self,
                "No clipboard writes adjacent to sensitive keywords were "
                "found.",
            )
        return finding(
            self,
            f"Found {len(evidence)} clipboard write(s) adjacent to "
            "sensitive keywords.",
            evidence=_cap(evidence),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Clipboard contents are readable by other apps, exposing "
                "copied secrets."
            ),
            confidence_rationale=(
                "The clipboard call is real, but the nearby keyword is a "
                "heuristic link rather than proven data flow."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S13: missing FLAG_SECURE on sensitive screens
# ---------------------------------------------------------------------------

_CLASS_RX = re.compile(
    r"(?m)^[ \t]*(?:public\s+|protected\s+|private\s+|final\s+|abstract\s+)*"
    r"(?:class|object)\s+(\w+)"
)
_SENSITIVE_SCREEN_RX = re.compile(
    r"(?i)(login|logon|password|passwd|payment|checkout|\bcard\b|\bpin\b)"
)


class BS_S13_MissingFlagSecure(Rule):
    id = "BS-S13"
    title = "Missing FLAG_SECURE on sensitive screens"
    description = (
        "An Activity whose class name suggests a sensitive screen "
        "(login/password/payment/card/PIN) whose source file never sets "
        "WindowManager.LayoutParams.FLAG_SECURE. Ambiguous by nature: "
        "needs human review."
    )
    rationale = (
        "Without FLAG_SECURE, sensitive screens can appear in the recent-"
        "tasks thumbnail and be captured by screenshots or screen "
        "recording, leaking credentials or payment data."
    )
    category = "storage"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-200"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Call getWindow().setFlags(FLAG_SECURE, FLAG_SECURE) in onCreate() "
        "of activities that display credentials, tokens, payment data, or "
        "other sensitive information."
    )
    references = [
        "https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        for path in iter_source_files(ctx):
            text = read_text_capped(path)
            if text is None:
                continue
            if "FLAG_SECURE" in text:
                continue
            for m in _CLASS_RX.finditer(text):
                name = m.group(1)
                if not _SENSITIVE_SCREEN_RX.search(name):
                    continue
                line_no = text.count("\n", 0, m.start()) + 1
                line = text.splitlines()[line_no - 1]
                hit = Hit(path=path, line_no=line_no, line=line, match=m)
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    description=f"Sensitive-looking activity '{name}' "
                                f"with no FLAG_SECURE in this file",
                ))
                if len(evidence) >= _MAX_EVIDENCE:
                    break
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if not evidence:
            return pass_result(
                self,
                "No sensitive-named activities missing FLAG_SECURE were "
                "found.",
            )
        return needs_review(
            self,
            f"Found {len(evidence)} sensitive-looking screen(s) with no "
            "FLAG_SECURE set in their source file.",
            evidence=_cap(evidence),
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "If the screen really displays credentials or payment "
                "data, it can leak via task thumbnails or screenshots."
            ),
            confidence_rationale=(
                "The class name only suggests a sensitive screen, and "
                "FLAG_SECURE could be set via a base class or theme; "
                "manual review is required."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S14: sensitive extras passed through Intents
# ---------------------------------------------------------------------------

_PUTEXTRA_RX = re.compile(r'\bputExtra\s*\(\s*"((?:[^"\\\n]|\\.)*)"')


class BS_S14_SensitiveIntentExtras(Rule):
    id = "BS-S14"
    title = "Sensitive data passed as Intent extras"
    description = (
        'putExtra() calls with sensitive keys ("password", "token", '
        '"secret", ...) placing secrets into Intent extras.'
    )
    rationale = (
        "Intent extras can be intercepted by malicious apps via exported "
        "components, logged by the system, or persist in PendingIntents; "
        "they are not a secure channel for secrets."
    )
    category = "storage"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-200"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Do not pass secrets in Intent extras. Pass an opaque reference or "
        "session id and resolve the secret from secure storage in the "
        "receiving component."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/200.html",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        for hit in grep(_PUTEXTRA_RX.pattern, iter_source_files(ctx)):
            key = hit.match.group(1)
            if not _SENSITIVE_RX.search(key):
                continue
            evidence.append(evidence_from_hit(
                ctx, hit,
                description=f"Sensitive Intent extra key '{key}'",
            ))
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if not evidence:
            return pass_result(
                self,
                "No putExtra calls with sensitive keys were found.",
            )
        return finding(
            self,
            f"Found {len(evidence)} putExtra call(s) with sensitive keys.",
            evidence=_cap(evidence),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Secrets in Intent extras can be intercepted or logged "
                "outside the app's control."
            ),
            confidence_rationale=(
                "The extra key literally names a secret on a real source "
                "line."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S15: FileProvider path rules granting external-path / root-path
# ---------------------------------------------------------------------------

_BROAD_PATH_RX = re.compile(r"<(?:external|root)-path\b")


class BS_S15_FileProviderBroadPaths(Rule):
    id = "BS-S15"
    title = "FileProvider grants external-path or root-path"
    description = (
        "A res/xml/*paths*.xml FileProvider configuration granting "
        "<external-path> or <root-path>, exposing broad filesystem areas "
        "to other apps."
    )
    rationale = (
        "Overly broad FileProvider paths let any app with a granted URI "
        "reach far more files than intended, including sensitive app data."
    )
    category = "storage"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-200"]
    masvs = ["MSTG-PLATFORM"]
    remediation = (
        "Scope FileProvider paths to the narrowest directory needed "
        "(files-path, cache-path, or a named subdirectory). Never use "
        "root-path; avoid external-path unless strictly required."
    )
    references = [
        "https://developer.android.com/reference/androidx/core/content/FileProvider",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_res(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        for path in iter_files([ctx.res_dir], {".xml"}):
            if "paths" not in path.name.lower():
                continue
            for hit in grep(_BROAD_PATH_RX.pattern, iter([path])):
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    description=f"Broad FileProvider grant "
                                f"{hit.match.group(0)} in "
                                f"{path.name}",
                ))
                if len(evidence) >= _MAX_EVIDENCE:
                    break
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if not evidence:
            return pass_result(
                self,
                "No FileProvider *paths*.xml files granting external-path "
                "or root-path were found.",
            )
        return finding(
            self,
            f"Found {len(evidence)} overly broad FileProvider path "
            "grant(s).",
            evidence=_cap(evidence),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Broad path grants expose large filesystem areas to any "
                "app holding a content URI."
            ),
            confidence_rationale=(
                "The <external-path>/<root-path> tags were matched "
                "literally in a FileProvider paths file."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S16: sensitive data in URL query parameters
# ---------------------------------------------------------------------------

_URL_SECRET_RX = re.compile(
    r'https?://[^\s"\'<>]*[?&](?:token|password|passwd|api_?key|secret|session)'
    r"=[^\s\"'&]*",
    re.IGNORECASE,
)


class BS_S16_SecretsInUrlQuery(Rule):
    id = "BS-S16"
    title = "Sensitive data in URL query parameters"
    description = (
        "Hardcoded http(s) URLs containing sensitive query parameters "
        "(?token=, ?password=, ?api_key=, ?secret=)."
    )
    rationale = (
        "URLs are logged by proxies, servers, and analytics; secrets in "
        "query strings leak into logs and browser/WebView history."
    )
    category = "storage"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-598"]
    masvs = ["MSTG-NETWORK"]
    remediation = (
        "Send secrets in the request body or an Authorization header over "
        "TLS, never in the URL query string."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/598.html",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx) or _has_res_or_assets(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        sources = list(iter_source_files(ctx))
        artifacts = list(iter_text_artifacts(ctx))
        for hit in grep(_URL_SECRET_RX.pattern, iter(sources + artifacts)):
            evidence.append(evidence_from_hit(
                ctx, hit,
                description="URL with sensitive query parameter",
            ))
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if not evidence:
            return pass_result(
                self,
                "No URLs with sensitive query parameters were found.",
            )
        return finding(
            self,
            f"Found {len(evidence)} URL(s) with sensitive query "
            "parameters.",
            evidence=_cap(evidence),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "Query-string secrets end up in server/proxy logs and "
                "caches."
            ),
            confidence_rationale=(
                "The URL and the sensitive parameter name were matched "
                "literally on a real line."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S17: WebView setSavePassword(true)
# ---------------------------------------------------------------------------

_SAVEPW_RX = re.compile(r"\bsetSavePassword\s*\(\s*true\s*\)")


class BS_S17_WebViewSavePassword(Rule):
    id = "BS-S17"
    title = "WebView password saving enabled"
    description = (
        "WebSettings.setSavePassword(true) enables the WebView's built-in "
        "password store."
    )
    rationale = (
        "Saved WebView passwords are stored in plaintext in the app's "
        "WebView database and can be extracted from the device."
    )
    category = "storage"
    default_severity = Severity.LOW
    owasp = ["M9"]
    cwe = ["CWE-256"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Do not enable WebView password saving (it is deprecated and "
        "defaults to false). Rely on the platform credential manager / "
        "autofill instead."
    )
    references = [
        "https://developer.android.com/reference/android/webkit/WebSettings#setSavePassword(boolean)",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        hits = grep(_SAVEPW_RX.pattern, iter_source_files(ctx))
        if not hits:
            return pass_result(
                self,
                "No setSavePassword(true) calls were found.",
            )
        evidence = [
            evidence_from_hit(ctx, h, description="WebView password saving "
                              "explicitly enabled")
            for h in hits[:_MAX_EVIDENCE]
        ]
        return finding(
            self,
            f"Found {len(hits)} setSavePassword(true) call(s).",
            evidence=evidence,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            severity_rationale=(
                "WebView-saved passwords persist in plaintext on the "
                "device."
            ),
            confidence_rationale=(
                "The enabling call was matched literally in decompiled "
                "source."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S18: backup rules include sensitive data domains
# ---------------------------------------------------------------------------

_INCLUDE_RX = re.compile(
    r"<include\b[^>]*\bdomain\s*=\s*\"([^\"]+)\"", re.IGNORECASE
)
_SENSITIVE_DOMAINS = {"sharedpref", "database", "db", "file", "external"}


class BS_S18_BackupRulesSensitiveDomains(Rule):
    id = "BS-S18"
    title = "Backup rules include sensitive data domains"
    description = (
        "Auto-backup / data-extraction rule XML files with <include> tags "
        "for sensitive domains (sharedpref, database, file, external). "
        "Needs review: whether the included data is actually sensitive "
        "depends on app content."
    )
    rationale = (
        "Included domains are uploaded to the user's Google Drive backup; "
        "any secrets in SharedPreferences or databases leave the device."
    )
    category = "storage"
    default_severity = Severity.MEDIUM
    owasp = ["M9"]
    cwe = ["CWE-312"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Exclude sensitive files from auto backup with <exclude> rules, or "
        "set android:allowBackup=\"false\" if backup is not needed. Never "
        "back up plaintext secrets."
    )
    references = [
        "https://developer.android.com/guide/topics/data/autobackup",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_res(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        for path in iter_files([ctx.res_dir], {".xml"}):
            text = read_text_capped(path)
            if text is None:
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                for m in _INCLUDE_RX.finditer(line):
                    domain = m.group(1).strip().lower()
                    if domain not in _SENSITIVE_DOMAINS:
                        continue
                    hit = Hit(path=path, line_no=i, line=line, match=m)
                    evidence.append(evidence_from_hit(
                        ctx, hit,
                        description=f"Backup <include> of sensitive domain "
                                    f"'{m.group(1)}'",
                    ))
                    if len(evidence) >= _MAX_EVIDENCE:
                        break
                if len(evidence) >= _MAX_EVIDENCE:
                    break
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if not evidence:
            return pass_result(
                self,
                "No backup/data-extraction rules including sensitive "
                "domains were found.",
            )
        return needs_review(
            self,
            f"Found {len(evidence)} backup <include> rule(s) for "
            "sensitive domains.",
            evidence=_cap(evidence),
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            severity_rationale=(
                "Backed-up SharedPreferences/databases leave the device; "
                "any secrets inside them are exposed."
            ),
            confidence_rationale=(
                "The include rules are real, but whether the included "
                "files actually hold secrets requires reviewing the app's "
                "stored data."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S19: sensitive data in temporary files
# ---------------------------------------------------------------------------

_TEMPFILE_RX = re.compile(
    r"\bcreateTempFile\s*\(\s*\"((?:[^\"\\\n]|\\.)*)\""
)


class BS_S19_SensitiveTempFiles(Rule):
    id = "BS-S19"
    title = "Sensitive data in temporary files"
    description = (
        "File.createTempFile() calls whose prefix/name suggests sensitive "
        "content (password/token/secret), or temp files created near "
        "sensitive keywords."
    )
    rationale = (
        "Temporary files are plaintext, often world-readable in shared "
        "temp directories, and may survive longer than expected; secrets "
        "written there can leak."
    )
    category = "storage"
    default_severity = Severity.LOW
    owasp = ["M9"]
    cwe = ["CWE-377"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Avoid writing secrets to temp files. If unavoidable, use the "
        "app-private cache directory, set restrictive permissions, and "
        "delete the file immediately after use."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/377.html",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        seen: set[tuple[str, int]] = set()
        for hit in grep(_TEMPFILE_RX.pattern, iter_source_files(ctx)):
            if _SENSITIVE_RX.search(hit.match.group(1)):
                key = (str(hit.path), hit.line_no)
                seen.add(key)
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    description="Temp file with sensitive-looking name",
                ))
        for hit in grep(r"\bcreateTempFile\s*\(", iter_source_files(ctx)):
            key = (str(hit.path), hit.line_no)
            if key in seen:
                continue
            window = _window_text(hit.path, hit.line_no, radius=3)
            if _SENSITIVE_RX.search(window):
                seen.add(key)
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    description="createTempFile near sensitive keyword",
                ))
            if len(evidence) >= _MAX_EVIDENCE:
                break
        if not evidence:
            return pass_result(
                self,
                "No temporary files with sensitive names or adjacent "
                "sensitive keywords were found.",
            )
        return finding(
            self,
            f"Found {len(evidence)} temporary-file call(s) linked to "
            "sensitive data.",
            evidence=_cap(evidence),
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Temp files are plaintext and may linger; low impact "
                "unless highly sensitive data is written."
            ),
            confidence_rationale=(
                "The temp-file creation is real and the sensitive link is "
                "in the file name or immediately adjacent code."
            ),
        )


# ---------------------------------------------------------------------------
# BS-S20: secrets leaked via System.out.println / printStackTrace
# ---------------------------------------------------------------------------

_PRINT_RX = re.compile(
    r"\bSystem\.out\.println\s*\(|"
    r"\bSystem\.err\.println\s*\(|"
    r"\.printStackTrace\s*\("
)


class BS_S20_PrintStackTraceLeak(Rule):
    id = "BS-S20"
    title = "Secrets leaked via println / printStackTrace"
    description = (
        "System.out/err.println or printStackTrace calls with sensitive "
        "keywords (token/password/secret/auth) on the same line or nearby, "
        "indicating secrets or auth material written to stdout/stderr."
    )
    rationale = (
        "Stdout/stderr output is captured in logs and crash reports; "
        "tokens or credentials printed there leak to anyone with log "
        "access."
    )
    category = "storage"
    default_severity = Severity.LOW
    owasp = ["M9"]
    cwe = ["CWE-532"]
    masvs = ["MSTG-STORAGE"]
    remediation = (
        "Remove println/printStackTrace of sensitive values. Log only "
        "redacted identifiers, and never print tokens, passwords, or auth "
        "exceptions containing them in release builds."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/532.html",
    ]

    def applies(self, ctx: ScanContext) -> bool:
        return _has_java(ctx)

    def check(self, ctx: ScanContext) -> RuleResult:
        evidence: list[Evidence] = []
        for hit in grep(_PRINT_RX.pattern, iter_source_files(ctx)):
            text = hit.line + "\n" + _window_text(hit.path, hit.line_no,
                                                  radius=3)
            if _SENSITIVE_RX.search(text):
                evidence.append(evidence_from_hit(
                    ctx, hit,
                    description="println/printStackTrace with sensitive "
                                "keyword on the line or nearby",
                ))
                if len(evidence) >= _MAX_EVIDENCE:
                    break
        if not evidence:
            return pass_result(
                self,
                "No println/printStackTrace calls linked to sensitive "
                "keywords were found.",
            )
        return finding(
            self,
            f"Found {len(evidence)} println/printStackTrace call(s) "
            "linked to sensitive keywords.",
            evidence=_cap(evidence),
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            severity_rationale=(
                "Secrets printed to stdout/stderr end up in logs and crash "
                "reports."
            ),
            confidence_rationale=(
                "The print call is real and a sensitive keyword is on the "
                "line or adjacent, but the exact printed value needs a "
                "look at the code."
            ),
        )


# ---------------------------------------------------------------------------
# Module rule registry
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    BS_S01_HardcodedCredentials(),
    BS_S02_HardcodedApiKeys(),
    BS_S03_PrivateKeyMaterial(),
    BS_S04_WorldAccessibleModes(),
    BS_S05_ExternalStorageSensitive(),
    BS_S06_UnencryptedSharedPreferences(),
    BS_S07_SqlitePlaintextSecrets(),
    BS_S08_OpenFileOutputSecrets(),
    BS_S09_CacheDirSensitive(),
    BS_S10_SensitiveLogging(),
    BS_S11_SecretsInResources(),
    BS_S12_ClipboardSensitive(),
    BS_S13_MissingFlagSecure(),
    BS_S14_SensitiveIntentExtras(),
    BS_S15_FileProviderBroadPaths(),
    BS_S16_SecretsInUrlQuery(),
    BS_S17_WebViewSavePassword(),
    BS_S18_BackupRulesSensitiveDomains(),
    BS_S19_SensitiveTempFiles(),
    BS_S20_PrintStackTraceLeak(),
]
