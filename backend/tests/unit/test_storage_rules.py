"""Unit tests for blindspot.rules.storage_rules (BS-S01 .. BS-S20).

Each rule gets: a vulnerable fixture -> FINDING/NEEDS_REVIEW, a clean
fixture -> PASS. NOT_APPLICABLE is covered for source- and artifact-based
rules. ScanContext is constructed directly with tmp_path fixtures; no real
APK or external tools are needed.
"""

from pathlib import Path

import pytest

from blindspot.rules import storage_rules as sr
from blindspot.rules.base import RuleStatus, ScanContext, Severity


def _ctx(
    tmp_path: Path,
    java: str | None = None,
    res: dict[str, str] | None = None,
    assets: dict[str, str] | None = None,
    use_java: bool = True,
    use_res: bool = True,
    use_assets: bool = True,
) -> ScanContext:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    resd = tmp_path / "res"
    resd.mkdir(exist_ok=True)
    asd = tmp_path / "assets"
    asd.mkdir(exist_ok=True)
    if java is not None:
        (src / "Main.java").write_text(java)
    for rel, content in (res or {}).items():
        p = resd / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    for rel, content in (assets or {}).items():
        p = asd / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return ScanContext(
        scan_id="test",
        workdir=tmp_path,
        apk_path=tmp_path / "app.apk",
        java_roots=[src] if use_java else [],
        res_dir=resd if use_res else None,
        assets_dir=asd if use_assets else None,
    )


def _run(rule, ctx):
    result = rule.run(ctx)
    assert result.rule_id == rule.id
    return result


# ---------------------------------------------------------------------------
# Registry sanity
# ---------------------------------------------------------------------------

def test_registry_has_25_unique_storage_rules():
    assert len(sr.RULES) == 25
    ids = [r.id for r in sr.RULES]
    assert ids == [f"BS-S{i:02d}" for i in range(1, 26)]
    assert all(r.category == "storage" for r in sr.RULES)


# ---------------------------------------------------------------------------
# BS-S01 hardcoded credentials
# ---------------------------------------------------------------------------

def test_s01_finding(tmp_path):
    java = 'class A {\n    private static final String DB_PASSWORD = "s3cr3tP@ssw0rd!";\n}\n'
    r = _run(sr.BS_S01_HardcodedCredentials(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert r.severity_rationale and r.confidence_rationale
    assert r.evidence and r.evidence[0].line_start == 2
    assert "Main.java" in r.evidence[0].file_path


def test_s01_pass(tmp_path):
    java = 'class A {\n    String username = "admin";\n    String passwordHint = getString(R.string.pw_hint);\n}\n'
    r = _run(sr.BS_S01_HardcodedCredentials(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


def test_s01_not_applicable(tmp_path):
    r = _run(sr.BS_S01_HardcodedCredentials(), _ctx(tmp_path, use_java=False))
    assert r.status == RuleStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# BS-S02 hardcoded API keys / tokens
# ---------------------------------------------------------------------------

def test_s02_finding_prefix(tmp_path):
    java = 'class A {\n    String k = "AIzaSyDdI39-EXAMP' 'LE-KEY-1234567890";\n}\n'
    r = _run(sr.BS_S02_HardcodedApiKeys(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert r.severity_rationale and r.confidence_rationale


def test_s02_finding_keyname(tmp_path):
    java = 'class A {\n    String apiToken = "x7fK9mQ2vZpL4nR8tW1yU5iO3";\n}\n'
    r = _run(sr.BS_S02_HardcodedApiKeys(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING


def test_s02_pass(tmp_path):
    java = 'class A {\n    String greeting = "hello world";\n}\n'
    r = _run(sr.BS_S02_HardcodedApiKeys(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S03 private key material
# ---------------------------------------------------------------------------

def test_s03_finding_pem_asset(tmp_path):
    assets = {"keys/server.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n"}
    r = _run(sr.BS_S03_PrivateKeyMaterial(),
             _ctx(tmp_path, assets=assets, use_java=False))
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert r.severity_rationale and r.confidence_rationale
    assert r.evidence[0].line_start == 1


def test_s03_finding_keystore(tmp_path):
    assets = {"keys/app.keystore": "binary-placeholder"}
    r = _run(sr.BS_S03_PrivateKeyMaterial(),
             _ctx(tmp_path, assets=assets, use_java=False))
    assert r.status == RuleStatus.FINDING


def test_s03_pass(tmp_path):
    assets = {"data/config.txt": "just some config\n"}
    r = _run(sr.BS_S03_PrivateKeyMaterial(),
             _ctx(tmp_path, assets=assets, use_java=False))
    assert r.status == RuleStatus.PASS


def test_s03_not_applicable(tmp_path):
    r = _run(sr.BS_S03_PrivateKeyMaterial(),
             _ctx(tmp_path, use_java=False, use_res=False, use_assets=False))
    assert r.status == RuleStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# BS-S04 world-accessible modes
# ---------------------------------------------------------------------------

def test_s04_finding(tmp_path):
    java = 'class A {\n    void m() {\n        getSharedPreferences("p", MODE_WORLD_READABLE);\n    }\n}\n'
    r = _run(sr.BS_S04_WorldAccessibleModes(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.evidence[0].line_start == 3


def test_s04_pass(tmp_path):
    java = 'class A {\n    void m() {\n        getSharedPreferences("p", MODE_PRIVATE);\n    }\n}\n'
    r = _run(sr.BS_S04_WorldAccessibleModes(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S05 external storage + sensitive keywords
# ---------------------------------------------------------------------------

def test_s05_finding(tmp_path):
    java = (
        "class A {\n"
        "    void m() {\n"
        "        File dir = Environment.getExternalStorageDirectory();\n"
        "        File f = new File(dir, \"auth_token_backup.txt\");\n"
        "    }\n"
        "}\n"
    )
    r = _run(sr.BS_S05_ExternalStorageSensitive(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.severity_rationale and r.confidence_rationale


def test_s05_pass(tmp_path):
    java = (
        "class A {\n"
        "    void m() {\n"
        "        File dir = Environment.getExternalStorageDirectory();\n"
        "        File f = new File(dir, \"image_cache.jpg\");\n"
        "    }\n"
        "}\n"
    )
    r = _run(sr.BS_S05_ExternalStorageSensitive(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S06 SharedPreferences without EncryptedSharedPreferences
# ---------------------------------------------------------------------------

def test_s06_needs_review(tmp_path):
    java = 'class A {\n    void m() {\n        prefs.edit().putString("password", pw).apply();\n    }\n}\n'
    r = _run(sr.BS_S06_UnencryptedSharedPreferences(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.NEEDS_REVIEW
    assert r.severity_rationale and r.confidence_rationale


def test_s06_pass_with_encrypted(tmp_path):
    java = (
        "class A {\n"
        "    void m() {\n"
        "        SharedPreferences p = EncryptedSharedPreferences.create(\"s\", \"k\", this, null, null);\n"
        "        p.edit().putString(\"password\", pw).apply();\n"
        "    }\n"
        "}\n"
    )
    r = _run(sr.BS_S06_UnencryptedSharedPreferences(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


def test_s06_pass_no_sensitive_keys(tmp_path):
    java = 'class A {\n    void m() {\n        prefs.edit().putString("username", u).apply();\n    }\n}\n'
    r = _run(sr.BS_S06_UnencryptedSharedPreferences(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S07 SQLite plaintext secrets
# ---------------------------------------------------------------------------

def test_s07_finding(tmp_path):
    java = 'class A {\n    void m() {\n        db.execSQL("INSERT INTO users (name, password) VALUES (\'a\', \'b\')");\n    }\n}\n'
    r = _run(sr.BS_S07_SqlitePlaintextSecrets(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.evidence[0].line_start == 3


def test_s07_pass(tmp_path):
    java = 'class A {\n    void m() {\n        db.execSQL("INSERT INTO users (name) VALUES (\'a\')");\n    }\n}\n'
    r = _run(sr.BS_S07_SqlitePlaintextSecrets(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S08 openFileOutput secrets
# ---------------------------------------------------------------------------

def test_s08_finding(tmp_path):
    java = (
        "class A {\n"
        "    void m() throws Exception {\n"
        "        FileOutputStream fos = openFileOutput(\"data.txt\", MODE_PRIVATE);\n"
        "        fos.write(authToken.getBytes());\n"
        "    }\n"
        "}\n"
    )
    r = _run(sr.BS_S08_OpenFileOutputSecrets(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING


def test_s08_pass(tmp_path):
    java = (
        "class A {\n"
        "    void m() throws Exception {\n"
        "        FileOutputStream fos = openFileOutput(\"notes.txt\", MODE_PRIVATE);\n"
        "        fos.write(note.getBytes());\n"
        "    }\n"
        "}\n"
    )
    r = _run(sr.BS_S08_OpenFileOutputSecrets(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S09 cache dir + sensitive keywords
# ---------------------------------------------------------------------------

def test_s09_finding(tmp_path):
    java = (
        "class A {\n"
        "    void m() {\n"
        "        File cache = getCacheDir();\n"
        "        File f = new File(cache, \"session_secret.tmp\");\n"
        "    }\n"
        "}\n"
    )
    r = _run(sr.BS_S09_CacheDirSensitive(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING


def test_s09_pass(tmp_path):
    java = (
        "class A {\n"
        "    void m() {\n"
        "        File cache = getCacheDir();\n"
        "        File f = new File(cache, \"thumb.png\");\n"
        "    }\n"
        "}\n"
    )
    r = _run(sr.BS_S09_CacheDirSensitive(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S10 sensitive logging
# ---------------------------------------------------------------------------

def test_s10_finding(tmp_path):
    java = 'class A {\n    void m() {\n        Log.d(TAG, "password=" + password);\n    }\n}\n'
    r = _run(sr.BS_S10_SensitiveLogging(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.evidence[0].line_start == 3


def test_s10_pass(tmp_path):
    java = 'class A {\n    void m() {\n        Log.d(TAG, "onCreate called");\n    }\n}\n'
    r = _run(sr.BS_S10_SensitiveLogging(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S11 secrets in resources
# ---------------------------------------------------------------------------

def test_s11_finding(tmp_path):
    res = {"values/strings.xml": (
        "<resources>\n"
        '    <string name="api_key">AIzaSyDdI39-EXAMP' 'LE-KEY-1234567890</string>\n'
        "</resources>\n"
    )}
    r = _run(sr.BS_S11_SecretsInResources(), _ctx(tmp_path, res=res))
    assert r.status == RuleStatus.FINDING
    assert r.evidence[0].line_start == 2


def test_s11_pass(tmp_path):
    res = {"values/strings.xml": (
        "<resources>\n"
        '    <string name="app_name">Demo</string>\n'
        "</resources>\n"
    )}
    r = _run(sr.BS_S11_SecretsInResources(), _ctx(tmp_path, res=res))
    assert r.status == RuleStatus.PASS


def test_s11_not_applicable(tmp_path):
    r = _run(sr.BS_S11_SecretsInResources(), _ctx(tmp_path, use_res=False))
    assert r.status == RuleStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# BS-S12 clipboard
# ---------------------------------------------------------------------------

def test_s12_finding(tmp_path):
    java = (
        "class A {\n"
        "    void m() {\n"
        "        ClipData clip = ClipData.newPlainText(\"token\", authToken);\n"
        "        clipboard.setPrimaryClip(clip);\n"
        "    }\n"
        "}\n"
    )
    r = _run(sr.BS_S12_ClipboardSensitive(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING


def test_s12_pass(tmp_path):
    java = (
        "class A {\n"
        "    void m() {\n"
        "        ClipData clip = ClipData.newPlainText(\"label\", text);\n"
        "        clipboard.setPrimaryClip(clip);\n"
        "    }\n"
        "}\n"
    )
    r = _run(sr.BS_S12_ClipboardSensitive(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S13 FLAG_SECURE
# ---------------------------------------------------------------------------

def test_s13_needs_review(tmp_path):
    java = "public class LoginActivity extends Activity {\n    void m() {}\n}\n"
    r = _run(sr.BS_S13_MissingFlagSecure(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.NEEDS_REVIEW
    assert r.severity_rationale and r.confidence_rationale


def test_s13_pass_with_flag(tmp_path):
    java = (
        "public class LoginActivity extends Activity {\n"
        "    void m() {\n"
        "        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,\n"
        "            WindowManager.LayoutParams.FLAG_SECURE);\n"
        "    }\n"
        "}\n"
    )
    r = _run(sr.BS_S13_MissingFlagSecure(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


def test_s13_pass_nonsensitive(tmp_path):
    java = "public class MainActivity extends Activity {\n    void m() {}\n}\n"
    r = _run(sr.BS_S13_MissingFlagSecure(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S14 sensitive intent extras
# ---------------------------------------------------------------------------

def test_s14_finding(tmp_path):
    java = 'class A {\n    void m() {\n        intent.putExtra("token", token);\n    }\n}\n'
    r = _run(sr.BS_S14_SensitiveIntentExtras(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.evidence[0].line_start == 3


def test_s14_pass(tmp_path):
    java = 'class A {\n    void m() {\n        intent.putExtra("name", name);\n    }\n}\n'
    r = _run(sr.BS_S14_SensitiveIntentExtras(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S15 FileProvider broad paths
# ---------------------------------------------------------------------------

def test_s15_finding(tmp_path):
    res = {"xml/file_paths.xml": (
        "<paths>\n"
        '    <external-path name="ext" path="." />\n'
        "</paths>\n"
    )}
    r = _run(sr.BS_S15_FileProviderBroadPaths(), _ctx(tmp_path, res=res))
    assert r.status == RuleStatus.FINDING
    assert r.evidence[0].line_start == 2


def test_s15_pass(tmp_path):
    res = {"xml/file_paths.xml": (
        "<paths>\n"
        '    <files-path name="f" path="." />\n'
        "</paths>\n"
    )}
    r = _run(sr.BS_S15_FileProviderBroadPaths(), _ctx(tmp_path, res=res))
    assert r.status == RuleStatus.PASS


def test_s15_not_applicable(tmp_path):
    r = _run(sr.BS_S15_FileProviderBroadPaths(), _ctx(tmp_path, use_res=False))
    assert r.status == RuleStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# BS-S16 secrets in URL query params
# ---------------------------------------------------------------------------

def test_s16_finding(tmp_path):
    java = 'class A {\n    String url = "https://api.example.com/login?token=abc123";\n}\n'
    r = _run(sr.BS_S16_SecretsInUrlQuery(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.evidence[0].line_start == 2


def test_s16_pass(tmp_path):
    java = 'class A {\n    String url = "https://api.example.com/login";\n}\n'
    r = _run(sr.BS_S16_SecretsInUrlQuery(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S17 WebView setSavePassword
# ---------------------------------------------------------------------------

def test_s17_finding(tmp_path):
    java = 'class A {\n    void m() {\n        settings.setSavePassword(true);\n    }\n}\n'
    r = _run(sr.BS_S17_WebViewSavePassword(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.evidence[0].line_start == 3


def test_s17_pass(tmp_path):
    java = 'class A {\n    void m() {\n        settings.setSavePassword(false);\n    }\n}\n'
    r = _run(sr.BS_S17_WebViewSavePassword(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S18 backup rules
# ---------------------------------------------------------------------------

def test_s18_needs_review(tmp_path):
    res = {"xml/backup_rules.xml": (
        "<full-backup-content>\n"
        '    <include domain="sharedpref" path="."/>\n'
        "</full-backup-content>\n"
    )}
    r = _run(sr.BS_S18_BackupRulesSensitiveDomains(), _ctx(tmp_path, res=res))
    assert r.status == RuleStatus.NEEDS_REVIEW
    assert r.severity_rationale and r.confidence_rationale


def test_s18_pass(tmp_path):
    res = {"xml/backup_rules.xml": (
        "<full-backup-content>\n"
        '    <exclude domain="sharedpref" path="."/>\n'
        "</full-backup-content>\n"
    )}
    r = _run(sr.BS_S18_BackupRulesSensitiveDomains(), _ctx(tmp_path, res=res))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S19 temp files
# ---------------------------------------------------------------------------

def test_s19_finding(tmp_path):
    java = 'class A {\n    void m() throws Exception {\n        File t = File.createTempFile("token", ".tmp");\n    }\n}\n'
    r = _run(sr.BS_S19_SensitiveTempFiles(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING


def test_s19_pass(tmp_path):
    java = 'class A {\n    void m() throws Exception {\n        File t = File.createTempFile("data", ".tmp");\n    }\n}\n'
    r = _run(sr.BS_S19_SensitiveTempFiles(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S20 println / printStackTrace leaks
# ---------------------------------------------------------------------------

def test_s20_finding(tmp_path):
    java = 'class A {\n    void m() {\n        System.out.println("token=" + token);\n    }\n}\n'
    r = _run(sr.BS_S20_PrintStackTraceLeak(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.evidence[0].line_start == 3


def test_s20_pass(tmp_path):
    java = 'class A {\n    void m() {\n        System.out.println("done");\n    }\n}\n'
    r = _run(sr.BS_S20_PrintStackTraceLeak(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# Builders always fill rationales on FINDING/NEEDS_REVIEW
# ---------------------------------------------------------------------------

def test_all_rules_fill_rationales_on_positive(tmp_path):
    vuln_java = "\n".join([
        'class A {',
        '    String DB_PASSWORD = "s3cr3tP@ssw0rd!";',
        '    String API_KEY = "AIzaSyDdI39-EXAMP' 'LE-KEY-1234567890";',
        "}",
    ]) + "\n"
    vuln_res = {
        "values/strings.xml": (
            "<resources>\n"
            '    <string name="api_key">AIzaSyDdI39-EXAMP' 'LE-KEY-1234567890</string>\n'
            "</resources>\n"
        ),
        "xml/file_paths.xml": "<paths>\n    <root-path name=\"r\" path=\".\" />\n</paths>\n",
        "xml/backup_rules.xml": (
            "<full-backup-content>\n    <include domain=\"database\" path=\".\"/>\n</full-backup-content>\n"
        ),
    }
    vuln_assets = {"keys/k.pem": "-----BEGIN PRIVATE KEY-----\nabc\n"}
    ctx = _ctx(tmp_path, java=vuln_java, res=vuln_res, assets=vuln_assets)
    positives = 0
    for rule in sr.RULES:
        r = rule.run(ctx)
        if r.status in (RuleStatus.FINDING, RuleStatus.NEEDS_REVIEW):
            positives += 1
            assert r.severity_rationale, f"{rule.id} missing severity_rationale"
            assert r.confidence_rationale, f"{rule.id} missing confidence_rationale"
            assert r.evidence, f"{rule.id} positive without evidence"
    assert positives >= 5, f"expected several positives, got {positives}"


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# BS-S21 Auto Backup without exclusion rules
# ---------------------------------------------------------------------------

def _manifest_ctx(tmp_path, allow_backup=True, rules=False, target_sdk=34):
    from blindspot.rules.base import ManifestData
    ctx = _ctx(tmp_path, java="class A {}")
    ctx.manifest = ManifestData(
        package="com.example.app",
        allow_backup=allow_backup,
        full_backup_content="@xml/backup_rules" if rules else "",
        target_sdk=target_sdk,
        raw_xml="<manifest/>",
    )
    ctx.manifest_xml_path = tmp_path / "AndroidManifest.xml"
    ctx.manifest_xml_path.write_text("<manifest/>")
    return ctx


def test_s21_needs_review(tmp_path):
    r = _run(sr.BS_S21_AutoBackupWithoutExclusions(),
             _manifest_ctx(tmp_path, allow_backup=True, rules=False, target_sdk=34))
    assert r.status == RuleStatus.NEEDS_REVIEW
    assert r.severity == Severity.MEDIUM
    assert r.severity_rationale and r.confidence_rationale


def test_s21_pass_backup_disabled(tmp_path):
    r = _run(sr.BS_S21_AutoBackupWithoutExclusions(),
             _manifest_ctx(tmp_path, allow_backup=False, rules=False, target_sdk=34))
    assert r.status == RuleStatus.PASS


def test_s21_pass_rules_configured(tmp_path):
    r = _run(sr.BS_S21_AutoBackupWithoutExclusions(),
             _manifest_ctx(tmp_path, allow_backup=True, rules=True, target_sdk=34))
    assert r.status == RuleStatus.PASS


def test_s21_pass_old_target(tmp_path):
    r = _run(sr.BS_S21_AutoBackupWithoutExclusions(),
             _manifest_ctx(tmp_path, allow_backup=True, rules=False, target_sdk=21))
    assert r.status == RuleStatus.PASS


# BS-S22 sensitive data in notifications
# ---------------------------------------------------------------------------

def test_s22_finding(tmp_path):
    java = (
        'class A {\n'
        '    void m() {\n'
        '        String otp = getOtp();\n'
        '        NotificationCompat.Builder b = new NotificationCompat.Builder(this);\n'
        '        b.setContentText("Your OTP is " + otp);\n'
        '    }\n'
        '}\n'
    )
    r = _run(sr.BS_S22_SensitiveNotifications(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM
    assert r.severity_rationale and r.confidence_rationale


def test_s22_pass(tmp_path):
    java = (
        'class A {\n'
        '    void m() {\n'
        '        NotificationCompat.Builder b = new NotificationCompat.Builder(this);\n'
        '        b.setContentText("Download complete");\n'
        '    }\n'
        '}\n'
    )
    r = _run(sr.BS_S22_SensitiveNotifications(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S23 PII in logcat
# ---------------------------------------------------------------------------

def test_s23_finding_email(tmp_path):
    java = (
        'class A {\n'
        '    void m() {\n'
        '        Log.d("TAG", "login failed for bob@example.com");\n'
        '    }\n'
        '}\n'
    )
    r = _run(sr.BS_S23_PiiInLogcat(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.MEDIUM
    assert r.evidence and r.evidence[0].line_start == 3


def test_s23_finding_phone(tmp_path):
    java = (
        'class A {\n'
        '    void m() {\n'
        '        Log.i("TAG", "calling user 9876543210 now");\n'
        '    }\n'
        '}\n'
    )
    r = _run(sr.BS_S23_PiiInLogcat(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING


def test_s23_pass(tmp_path):
    java = (
        'class A {\n'
        '    void m() {\n'
        '        Log.d("TAG", "sync complete");\n'
        '    }\n'
        '}\n'
    )
    r = _run(sr.BS_S23_PiiInLogcat(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-S24 sensitive activity without FLAG_SECURE
# ---------------------------------------------------------------------------

def test_s24_needs_review(tmp_path):
    from blindspot.rules.base import Component, ManifestData
    java = (
        'package com.example;\n'
        'public class LoginActivity {\n'
        '    void onCreate() {\n'
        '    }\n'
        '}\n'
    )
    ctx = _ctx(tmp_path, java=java)
    ctx.manifest = ManifestData(
        activities=[Component(kind="activity", name="com.example.LoginActivity")]
    )
    r = _run(sr.BS_S24_SensitiveActivityNoFlagSecure(), ctx)
    assert r.status == RuleStatus.NEEDS_REVIEW
    assert r.severity == Severity.MEDIUM
    assert r.severity_rationale and r.confidence_rationale
    assert r.evidence and r.evidence[0].line_start == 2


def test_s24_pass_when_flag_secure_set(tmp_path):
    from blindspot.rules.base import Component, ManifestData
    java = (
        'package com.example;\n'
        'public class LoginActivity {\n'
        '    void onCreate() {\n'
        '        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,\n'
        '            WindowManager.LayoutParams.FLAG_SECURE);\n'
        '    }\n'
        '}\n'
    )
    ctx = _ctx(tmp_path, java=java)
    ctx.manifest = ManifestData(
        activities=[Component(kind="activity", name="com.example.LoginActivity")]
    )
    r = _run(sr.BS_S24_SensitiveActivityNoFlagSecure(), ctx)
    assert r.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# BS-S25 Keystore disables randomized encryption
# ---------------------------------------------------------------------------

def test_s25_finding(tmp_path):
    java = (
        'class A {\n'
        '    void m() {\n'
        '        new KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_ENCRYPT)\n'
        '            .setRandomizedEncryptionRequired(false)\n'
        '            .build();\n'
        '    }\n'
        '}\n'
    )
    r = _run(sr.BS_S25_KeystoreDisablesRandomizedEncryption(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.FINDING
    assert r.severity == Severity.HIGH
    assert r.severity_rationale and r.confidence_rationale
    assert r.evidence and r.evidence[0].line_start == 4


def test_s25_pass(tmp_path):
    java = (
        'class A {\n'
        '    void m() {\n'
        '        new KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_ENCRYPT)\n'
        '            .setRandomizedEncryptionRequired(true)\n'
        '            .build();\n'
        '    }\n'
        '}\n'
    )
    r = _run(sr.BS_S25_KeystoreDisablesRandomizedEncryption(), _ctx(tmp_path, java=java))
    assert r.status == RuleStatus.PASS
