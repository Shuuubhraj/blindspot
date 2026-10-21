"""Unit tests for the BS-X01..BS-X20 hardcoded-secret detection rules.

Each rule gets a vulnerable fixture (expecting FINDING, or NEEDS_REVIEW
for BS-X08) and a clean fixture (expecting PASS).
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

# Same file-location loading trick as test_crypto_rules.py: the rules
# package __init__ imports sibling category modules that may not exist yet,
# so load the modules by path instead.
_RULES_DIR = Path(__file__).resolve().parents[2] / "blindspot" / "rules"


def _load(modname: str, filename: str):
    spec = importlib.util.spec_from_file_location(modname, _RULES_DIR / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_pkg = types.ModuleType("blindspot.rules")
_pkg.__path__ = [str(_RULES_DIR)]
sys.modules.setdefault("blindspot.rules", _pkg)
_base = _load("blindspot.rules.base", "base.py")
_load("blindspot.rules.common", "common.py")
_secrets = _load("blindspot.rules.secret_rules", "secret_rules.py")

RuleStatus = _base.RuleStatus
ScanContext = _base.ScanContext
ManifestData = _base.ManifestData
Severity = _base.Severity
RULES = _secrets.RULES

RULES_BY_ID = {r.id: r for r in RULES}


@pytest.fixture
def make_ctx(tmp_path):
    counter = {"n": 0}

    def _make(*files: tuple[str, str], manifest=None, manifest_path=None) -> ScanContext:
        counter["n"] += 1
        src = tmp_path / f"src{counter['n']}"
        src.mkdir()
        assets = tmp_path / f"assets{counter['n']}"
        assets.mkdir()
        # text-artifact extensions go under assets_dir so iter_text_artifacts
        # is exercised; sources stay under java_roots.
        for name, content in files:
            dest = assets if Path(name).suffix.lower() in {
                ".gradle", ".properties", ".txt", ".json", ".xml",
            } else src
            (dest / name).write_text(content)
        kw = dict(
            scan_id="test",
            workdir=tmp_path,
            apk_path=tmp_path / "app.apk",
            java_roots=[src],
            assets_dir=assets,
        )
        if manifest is not None:
            kw["manifest"] = manifest
        if manifest_path is not None:
            kw["manifest_xml_path"] = manifest_path
        return ScanContext(**kw)

    return _make


def run(rule_id, ctx):
    return RULES_BY_ID[rule_id].run(ctx)


def test_registry_has_20_rules():
    assert len(RULES) == 20
    assert [r.id for r in RULES] == [f"BS-X{i:02d}" for i in range(1, 21)]
    assert all(r.category == "secrets" for r in RULES)
    assert all(r.masvs == ["MSTG-STORAGE"] for r in RULES)


# ---------------------------------------------------------------- BS-X01

X01_VULN = 'public class C {\n    private static final String AWS_KEY = "AKIAIOSFODNN7A1B2C3D";\n}\n'
X01_EXAMPLE = 'public class C {\n    // AWS docs example, must not flag\n    private static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n}\n'


def test_x01_aws_key_id_is_finding(make_ctx):
    res = run("BS-X01", make_ctx(("C.java", X01_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.cwe == ["CWE-798"] and res.owasp == ["M10"]
    assert res.severity_rationale and res.confidence_rationale
    assert res.evidence[0].line_start == 2


def test_x01_aws_example_key_passes(make_ctx):
    res = run("BS-X01", make_ctx(("C.java", X01_EXAMPLE)))
    assert res.status == RuleStatus.PASS


def test_x01_no_key_passes(make_ctx):
    res = run("BS-X01", make_ctx(("C.java", "public class C {}\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X02

X02_VULN = (
    'public class C {\n'
    '    private static final String AWS_SECRET_KEY = "K7Q9aB2cD4eF6gH8jK0lM1nO3pQ5rS7tU9vW0xY2"; // s3 client\n'
    '}\n'
)
X02_NOCTX = (
    'public class C {\n'
    '    private static final String BLOB = "K7Q9aB2cD4eF6gH8jK0lM1nO3pQ5rS7tU9vW0xY2";\n'
    '}\n'
)


def test_x02_aws_secret_key_is_finding(make_ctx):
    res = run("BS-X02", make_ctx(("C.java", X02_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.evidence[0].line_start == 2


def test_x02_token_without_context_passes(make_ctx):
    res = run("BS-X02", make_ctx(("C.java", X02_NOCTX)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X03

X03_VULN = 'public class C {\n    private static final String MAPS_KEY = "AIzaSyD9tSrA0bC1dE2fG3hI4jK5lM6nO7pQrS8";\n}\n'


def test_x03_google_api_key_is_finding(make_ctx):
    res = run("BS-X03", make_ctx(("C.java", X03_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.cwe == ["CWE-798"]
    assert res.evidence[0].line_start == 2


def test_x03_no_key_passes(make_ctx):
    res = run("BS-X03", make_ctx(("C.java", "public class C {}\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X04

X04_VULN = 'public class C {\n    private static final String DB = "https://myapp-12345.firebaseio.com";\n}\n'


def test_x04_firebase_url_is_finding(make_ctx):
    res = run("BS-X04", make_ctx(("C.java", X04_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.evidence[0].line_start == 2


def test_x04_no_firebase_passes(make_ctx):
    res = run("BS-X04", make_ctx(("C.java", "public class C {}\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X05

X05_VULN = 'public class C {\n    private static final String STRIPE = "sk_live_4eC39HqL' 'yjWDarjtT1zdp7dc";\n}\n'
X05_TESTMODE = 'public class C {\n    private static final String STRIPE = "sk_test_examplekey1234567890";\n}\n'


def test_x05_stripe_live_key_is_finding(make_ctx):
    res = run("BS-X05", make_ctx(("C.java", X05_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.evidence[0].line_start == 2


def test_x05_example_key_passes(make_ctx):
    res = run("BS-X05", make_ctx(("C.java", X05_TESTMODE)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X06

X06_VULN = 'public class C {\n    private static final String SLACK = "xoxb-123456789012-a' 'bcdefghijklmnopqrst";\n}\n'


def test_x06_slack_token_is_finding(make_ctx):
    res = run("BS-X06", make_ctx(("C.java", X06_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.evidence[0].line_start == 2


def test_x06_no_token_passes(make_ctx):
    res = run("BS-X06", make_ctx(("C.java", "public class C {}\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X07

X07_VULN = 'public class C {\n    private static final String GH = "ghp_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";\n}\n'


def test_x07_github_token_is_finding(make_ctx):
    res = run("BS-X07", make_ctx(("C.java", X07_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.evidence[0].line_start == 2


def test_x07_no_token_passes(make_ctx):
    res = run("BS-X07", make_ctx(("C.java", "public class C {}\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X08

X08_VULN = 'public class C {\n    private static final String api_key = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY3zA";\n}\n'
X08_CLEAN = 'public class C {\n    private static final String api_key = "test-key";\n}\n'


def test_x08_high_entropy_secret_needs_review(make_ctx):
    res = run("BS-X08", make_ctx(("C.java", X08_VULN)))
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert res.severity == Severity.MEDIUM
    assert res.severity_rationale and res.confidence_rationale
    assert res.evidence[0].line_start == 2


def test_x08_low_entropy_value_passes(make_ctx):
    res = run("BS-X08", make_ctx(("C.java", X08_CLEAN)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X09

X09_VULN = "server key backup\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7b...\n-----END RSA PRIVATE KEY-----\n"


def test_x09_private_key_is_finding(make_ctx):
    res = run("BS-X09", make_ctx(("keys.txt", X09_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.cwe == ["CWE-798"]
    assert res.evidence[0].line_start == 2


def test_x09_public_key_passes(make_ctx):
    res = run("BS-X09", make_ctx(("keys.txt", "-----BEGIN PUBLIC KEY-----\nMIIB...\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X10

X10_VULN = 'android {\n    signingConfigs {\n        release {\n            storePassword = "s3cr3tK3yst0re!"\n        }\n    }\n}\n'


def test_x10_keystore_password_is_finding(make_ctx):
    res = run("BS-X10", make_ctx(("signing.gradle", X10_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.evidence[0].line_start == 4


def test_x10_placeholder_password_passes(make_ctx):
    res = run("BS-X10", make_ctx(("signing.gradle", 'android {\n    storePassword = "changeme"\n}\n')))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X11

X11_VULN = 'public class C {\n    private static final String CLIENT_SECRET = "GOCSPX-a1b2c3d4e5f6g7h8i9j0";\n}\n'


def test_x11_oauth_client_secret_is_finding(make_ctx):
    res = run("BS-X11", make_ctx(("C.java", X11_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.evidence[0].line_start == 2


def test_x11_short_value_passes(make_ctx):
    res = run("BS-X11", make_ctx(("C.java", 'public class C {\n    String client_secret = "abc";\n}\n')))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X12

X12_VULN = 'public class C {\n    private static final String TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";\n}\n'


def test_x12_hardcoded_jwt_is_finding(make_ctx):
    res = run("BS-X12", make_ctx(("C.java", X12_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.evidence[0].line_start == 2


def test_x12_no_jwt_passes(make_ctx):
    res = run("BS-X12", make_ctx(("C.java", "public class C {}\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X13

X13_VULN = 'public class C {\n    private static final String SID = "AC1234567890abcde' 'f1234567890abcdef";\n}\n'


def test_x13_twilio_credential_is_finding(make_ctx):
    res = run("BS-X13", make_ctx(("C.java", X13_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.evidence[0].line_start == 2


def test_x13_no_credential_passes(make_ctx):
    res = run("BS-X13", make_ctx(("C.java", "public class C {}\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X14

X14_VULN = 'public class C {\n    private static final String SG_KEY = "SG.abc123DEF456ghi789JKL012mno345PQR678";\n}\n'


def test_x14_sendgrid_key_is_finding(make_ctx):
    res = run("BS-X14", make_ctx(("C.java", X14_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.evidence[0].line_start == 2


def test_x14_no_key_passes(make_ctx):
    res = run("BS-X14", make_ctx(("C.java", "public class C {}\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X15

X15_VULN = (
    "DefaultEndpointsProtocol=https;AccountName=mystore;"
    "AccountKey=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=;"
    "EndpointSuffix=core.windows.net\n"
)


def test_x15_azure_connection_string_is_finding(make_ctx):
    res = run("BS-X15", make_ctx(("config.txt", X15_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.evidence[0].line_start == 1


def test_x15_no_connection_string_passes(make_ctx):
    res = run("BS-X15", make_ctx(("config.txt", "AccountName=mystore\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X16

X16_VULN = 'public class C {\n    private static final String URL = "https://admin:s3cr3tP@ss@api.example.com/v1";\n}\n'
X16_CLEAN = 'public class C {\n    private static final String URL = "https://api.example.com/v1";\n}\n'


def test_x16_basic_auth_url_is_finding(make_ctx):
    res = run("BS-X16", make_ctx(("C.java", X16_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.evidence[0].line_start == 2


def test_x16_plain_url_passes(make_ctx):
    res = run("BS-X16", make_ctx(("C.java", X16_CLEAN)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X17

X17_VULN_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">\n'
    '    <application android:label="App">\n'
    '        <meta-data android:name="com.example.API_KEY" android:value="aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY3z"/>\n'
    '    </application>\n'
    '</manifest>\n'
)

X17_CLEAN_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">\n'
    '    <application android:label="App">\n'
    '        <meta-data android:name="com.example.API_KEY" android:value="@string/api_key"/>\n'
    '    </application>\n'
    '</manifest>\n'
)


def test_x17_manifest_metadata_secret_is_finding(make_ctx, tmp_path):
    ctx = make_ctx(
        manifest=ManifestData(raw_xml=X17_VULN_XML),
        manifest_path=tmp_path / "AndroidManifest.xml",
    )
    res = run("BS-X17", ctx)
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.evidence[0].line_start == 4  # the meta-data line in raw_xml
    assert res.evidence[0].file_path == "AndroidManifest.xml"


def test_x17_resource_reference_passes(make_ctx, tmp_path):
    ctx = make_ctx(
        manifest=ManifestData(raw_xml=X17_CLEAN_XML),
        manifest_path=tmp_path / "AndroidManifest.xml",
    )
    res = run("BS-X17", ctx)
    assert res.status == RuleStatus.PASS


def test_x17_no_manifest_passes(make_ctx):
    res = run("BS-X17", make_ctx(("C.java", "public class C {}\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X18

X18_BUILDCONFIG = (
    "public final class BuildConfig {\n"
    '    public static final String API_KEY = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY3z";\n'
    "}\n"
)
X18_GRADLE = 'android {\n    def apiKey = "zY9xW8vU7tS6rQ5pO4nM3lK2jI1hG0fE9dC8b";\n}\n'
X18_CLEAN_GRADLE = 'android {\n    def apiKey = "debug-key";\n}\n'


def test_x18_buildconfig_secret_is_finding(make_ctx):
    res = run("BS-X18", make_ctx(("BuildConfig.java", X18_BUILDCONFIG)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.evidence[0].line_start == 2


def test_x18_gradle_secret_is_finding(make_ctx):
    res = run("BS-X18", make_ctx(("app.gradle", X18_GRADLE)))
    assert res.status == RuleStatus.FINDING
    assert res.evidence[0].line_start == 2


def test_x18_debug_value_passes(make_ctx):
    res = run("BS-X18", make_ctx(("app.gradle", X18_CLEAN_GRADLE)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X19

X19_VULN = 'public class C {\n    private static final String FB_SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1";\n}\n'


def test_x19_facebook_app_secret_is_finding(make_ctx):
    res = run("BS-X19", make_ctx(("C.java", X19_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.evidence[0].line_start == 2


def test_x19_no_secret_passes(make_ctx):
    res = run("BS-X19", make_ctx(("C.java", "public class C {}\n")))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-X20

X20_VULN = (
    "import javax.crypto.Cipher;\n"
    "public class C {\n"
    "    void m() throws Exception {\n"
    '        String password = "S3cr3tP@ssw0rd!";\n'
    '        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
    "        c.init(Cipher.ENCRYPT_MODE, null);\n"
    "    }\n"
    "}\n"
)
X20_NOCRYPTO = (
    "public class C {\n"
    "    void m() {\n"
    '        String password = "S3cr3tP@ssw0rd!";\n'
    "        System.out.println(password.length());\n"
    "    }\n"
    "}\n"
)


def test_x20_password_near_crypto_is_finding(make_ctx):
    res = run("BS-X20", make_ctx(("C.java", X20_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.cwe == ["CWE-259"]
    assert res.evidence[0].line_start == 4


def test_x20_password_without_crypto_passes(make_ctx):
    res = run("BS-X20", make_ctx(("C.java", X20_NOCRYPTO)))
    assert res.status == RuleStatus.PASS
