"""Unit tests for the BS-C01..BS-C15 crypto detection rules.

Each rule gets a vulnerable fixture (expecting FINDING or NEEDS_REVIEW)
and a clean/secure-alternative fixture (expecting PASS), plus a
NOT_APPLICABLE check when no java_roots are present.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

# NOTE: the repo is mid-build and blindspot/rules/__init__.py -> registry.py
# imports sibling category modules (manifest_rules, storage_rules, ...) that
# do not exist yet, so a normal `import blindspot.rules.crypto_rules` fails
# at collection time through no fault of this module. Load the rule package
# by file location instead, which exercises the exact same code paths.
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
_crypto = _load("blindspot.rules.crypto_rules", "crypto_rules.py")

RuleStatus = _base.RuleStatus
ScanContext = _base.ScanContext
Severity = _base.Severity
RULES = _crypto.RULES

RULES_BY_ID = {r.id: r for r in RULES}


@pytest.fixture
def make_ctx(tmp_path):
    counter = {"n": 0}

    def _make(*files: tuple[str, str]) -> ScanContext:
        counter["n"] += 1
        src = tmp_path / f"src{counter['n']}"
        src.mkdir()
        for name, content in files:
            (src / name).write_text(content)
        return ScanContext(
            scan_id="test",
            workdir=tmp_path,
            apk_path=tmp_path / "app.apk",
            java_roots=[src],
        )

    return _make


def run(rule_id, ctx):
    return RULES_BY_ID[rule_id].run(ctx)


def test_registry_has_15_rules():
    assert len(RULES) == 15
    assert [r.id for r in RULES] == [f"BS-C{i:02d}" for i in range(1, 16)]
    assert all(r.category == "crypto" for r in RULES)


@pytest.mark.parametrize("rule_id", list(RULES_BY_ID))
def test_not_applicable_without_java_roots(rule_id, tmp_path):
    ctx = ScanContext(scan_id="t", workdir=tmp_path,
                      apk_path=tmp_path / "a.apk", java_roots=[])
    res = run(rule_id, ctx)
    assert res.status == RuleStatus.NOT_APPLICABLE


# ---------------------------------------------------------------- BS-C01

C01_VULN = """\
import java.security.MessageDigest;
public class Auth {
    public boolean check(String password, byte[] expected) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes("UTF-8"));
        return java.util.Arrays.equals(hash, expected);
    }
}
"""

C01_CACHE = """\
import java.security.MessageDigest;
public class ImageCache {
    // cache key for downloaded images, not security related
    public String cacheKey(String url) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return bytesToHex(md.digest(url.getBytes("UTF-8")));
    }
    private String bytesToHex(byte[] b) { return ""; }
}
"""


def test_c01_md5_password_is_high_finding(make_ctx):
    res = run("BS-C01", make_ctx(("Auth.java", C01_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.cwe == ["CWE-327"] and res.owasp == ["M10"]
    assert res.severity_rationale and res.confidence_rationale
    ev = res.evidence[0]
    assert ev.line_start == 4  # the getInstance line
    assert "MD5" in ev.snippet


def test_c01_md5_cache_key_is_not_high_finding(make_ctx):
    res = run("BS-C01", make_ctx(("ImageCache.java", C01_CACHE)))
    assert res.status == RuleStatus.NEEDS_REVIEW  # not a FINDING
    assert res.severity_rationale and res.confidence_rationale


def test_c01_sha256_passes(make_ctx):
    src = C01_VULN.replace('"MD5"', '"SHA-256"')
    res = run("BS-C01", make_ctx(("Auth.java", src)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C02

C02_VULN = """\
import java.security.MessageDigest;
public class TokenSvc {
    public byte[] tokenDigest(byte[] tokenData) throws Exception {
        // digest of the auth token for comparison
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(tokenData);
    }
}
"""


def test_c02_sha1_token_is_finding(make_ctx):
    res = run("BS-C02", make_ctx(("TokenSvc.java", C02_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.cwe == ["CWE-327"]


def test_c02_sha256_passes(make_ctx):
    res = run("BS-C02", make_ctx(("TokenSvc.java", C02_VULN.replace('"SHA-1"', '"SHA-256"'))))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C03

def test_c03_des_is_high_finding(make_ctx):
    src = 'public class C { void m() throws Exception { javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding"); } }\n'
    res = run("BS-C03", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH


def test_c03_aes_passes(make_ctx):
    src = 'public class C { void m() throws Exception { javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding"); } }\n'
    res = run("BS-C03", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C04

def test_c04_aes_ecb_is_finding(make_ctx):
    src = 'public class C { void m() throws Exception { javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding"); } }\n'
    res = run("BS-C04", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH


def test_c04_aes_gcm_passes(make_ctx):
    src = 'public class C { void m() throws Exception { javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding"); } }\n'
    res = run("BS-C04", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C05

C05_LITERAL = """\
import javax.crypto.spec.SecretKeySpec;
public class Crypto {
    public void m() {
        SecretKeySpec key = new SecretKeySpec("mysecretkey12345".getBytes(), "AES");
    }
}
"""

C05_VAR = """\
import javax.crypto.spec.SecretKeySpec;
public class Crypto {
    public void m() {
        String keyStr = "0123456789abcdef";
        SecretKeySpec key = new SecretKeySpec(keyStr.getBytes(), "AES");
    }
}
"""

C05_CLEAN = """\
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
public class Crypto {
    public void m() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKeySpec key = new SecretKeySpec(kg.generateKey().getEncoded(), "AES");
    }
}
"""


def test_c05_literal_key_is_critical(make_ctx):
    res = run("BS-C05", make_ctx(("Crypto.java", C05_LITERAL)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.CRITICAL
    assert res.cwe == ["CWE-798"]
    assert res.evidence[0].line_start == 4


def test_c05_var_assigned_literal_is_finding(make_ctx):
    res = run("BS-C05", make_ctx(("Crypto.java", C05_VAR)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.CRITICAL


def test_c05_generated_key_passes(make_ctx):
    res = run("BS-C05", make_ctx(("Crypto.java", C05_CLEAN)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C06

def test_c06_literal_iv_is_finding(make_ctx):
    src = ('import javax.crypto.spec.IvParameterSpec;\n'
           'public class C { void m() {\n'
           '    IvParameterSpec iv = new IvParameterSpec("1234567890123456".getBytes());\n'
           '}}\n')
    res = run("BS-C06", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.cwe == ["CWE-329"]
    assert res.evidence[0].line_start == 3


def test_c06_zero_iv_is_finding(make_ctx):
    src = ('import javax.crypto.spec.IvParameterSpec;\n'
           'public class C { void m() {\n'
           '    IvParameterSpec iv = new IvParameterSpec(new byte[16]);\n'
           '}}\n')
    res = run("BS-C06", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.FINDING


def test_c06_random_iv_passes(make_ctx):
    src = ('import javax.crypto.spec.IvParameterSpec;\n'
           'import java.security.SecureRandom;\n'
           'public class C { void m() {\n'
           '    byte[] ivb = new byte[16]; new SecureRandom().nextBytes(ivb);\n'
           '    IvParameterSpec iv = new IvParameterSpec(ivb);\n'
           '}}\n')
    res = run("BS-C06", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C07

def test_c07_random_for_token_is_finding(make_ctx):
    src = ('import java.util.Random;\n'
           'public class C {\n'
           '    String makeToken() {\n'
           '        Random tokenGen = new Random();\n'
           '        return "tok" + tokenGen.nextInt(999999);\n'
           '    }\n'
           '}\n')
    res = run("BS-C07", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.cwe == ["CWE-338"]


def test_c07_securerandom_passes(make_ctx):
    src = ('import java.security.SecureRandom;\n'
           'public class C {\n'
           '    String makeToken() {\n'
           '        SecureRandom tokenGen = new SecureRandom();\n'
           '        return "tok" + tokenGen.nextInt(999999);\n'
           '    }\n'
           '}\n')
    res = run("BS-C07", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C08

C08_VULN = """\
public class Obf {
    private byte[] encrypt(byte[] data, byte[] k) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ k[i % k.length]);
        }
        return out;
    }
}
"""

C08_CLEAN = """\
import javax.crypto.Cipher;
public class Real {
    private byte[] encrypt(byte[] data, javax.crypto.SecretKey k) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(data);
    }
}
"""


def test_c08_xor_encrypt_needs_review(make_ctx):
    res = run("BS-C08", make_ctx(("Obf.java", C08_VULN)))
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert res.severity_rationale and res.confidence_rationale


def test_c08_jca_encrypt_passes(make_ctx):
    res = run("BS-C08", make_ctx(("Real.java", C08_CLEAN)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C09

def test_c09_pbkdf2_sha1_is_finding(make_ctx):
    src = ('public class C { void m() throws Exception {\n'
           '    javax.crypto.SecretKeyFactory f = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");\n'
           '}}\n')
    res = run("BS-C09", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.cwe == ["CWE-916"]


def test_c09_low_iterations_is_finding(make_ctx):
    src = ('import javax.crypto.spec.PBEKeySpec;\n'
           'public class C { void m() {\n'
           '    PBEKeySpec spec = new PBEKeySpec("pw".toCharArray(), new byte[16], 1000, 256);\n'
           '}}\n')
    res = run("BS-C09", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.FINDING


def test_c09_strong_kdf_passes(make_ctx):
    src = ('import javax.crypto.spec.PBEKeySpec;\n'
           'public class C { void m() throws Exception {\n'
           '    javax.crypto.SecretKeyFactory f = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");\n'
           '    PBEKeySpec spec = new PBEKeySpec("pw".toCharArray(), new byte[16], 600000, 256);\n'
           '}}\n')
    res = run("BS-C09", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C10

C10_VULN = """\
import java.security.MessageDigest;
public class Login {
    boolean check(String password, byte[] expect) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest(password.getBytes("UTF-8"));
        return java.util.Arrays.equals(h, expect);
    }
}
"""

C10_SALTED = """\
import java.security.MessageDigest;
import java.security.SecureRandom;
public class Login {
    boolean check(String password, byte[] salt, byte[] expect) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        byte[] h = md.digest(password.getBytes("UTF-8"));
        return java.util.Arrays.equals(h, expect);
    }
}
"""


def test_c10_unsalted_password_hash_is_finding(make_ctx):
    res = run("BS-C10", make_ctx(("Login.java", C10_VULN)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.cwe == ["CWE-916"]
    assert res.evidence[0].line_start == 5  # the digest line


def test_c10_salted_passes(make_ctx):
    res = run("BS-C10", make_ctx(("Login.java", C10_SALTED)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C11

def test_c11_1024_bit_is_finding(make_ctx):
    src = ('import java.security.KeyPairGenerator;\n'
           'public class C { void m() throws Exception {\n'
           '    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
           '    kpg.initialize(1024);\n'
           '}}\n')
    res = run("BS-C11", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM
    assert res.cwe == ["CWE-326"]
    assert res.evidence[0].line_start == 4


def test_c11_2048_passes(make_ctx):
    src = ('import java.security.KeyPairGenerator;\n'
           'public class C { void m() throws Exception {\n'
           '    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
           '    kpg.initialize(2048);\n'
           '}}\n')
    res = run("BS-C11", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C12

def test_c12_sha1withrsa_is_finding(make_ctx):
    src = ('import java.security.Signature;\n'
           'public class C { void m() throws Exception {\n'
           '    Signature s = Signature.getInstance("SHA1withRSA");\n'
           '}}\n')
    res = run("BS-C12", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM


def test_c12_sha256withrsa_passes(make_ctx):
    src = ('import java.security.Signature;\n'
           'public class C { void m() throws Exception {\n'
           '    Signature s = Signature.getInstance("SHA256withRSA");\n'
           '}}\n')
    res = run("BS-C12", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C13

def test_c13_key_in_prefs_is_finding(make_ctx):
    src = ('import android.content.SharedPreferences;\n'
           'public class C { void m(SharedPreferences p, String encodedKey) {\n'
           '    p.edit().putString("aes_key", encodedKey).apply();\n'
           '}}\n')
    res = run("BS-C13", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.HIGH
    assert res.cwe == ["CWE-312"]


def test_c13_benign_pref_passes(make_ctx):
    src = ('import android.content.SharedPreferences;\n'
           'public class C { void m(SharedPreferences p, String name) {\n'
           '    p.edit().putString("username", name).apply();\n'
           '}}\n')
    res = run("BS-C13", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C14

C14_VULN = """\
import javax.crypto.Cipher;
public class Enc {
    byte[] enc(byte[] d, javax.crypto.SecretKey k) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(d);
    }
}
"""

C14_WITH_MAC = C14_VULN + """\
import javax.crypto.Mac;
class Tag {
    byte[] tag(byte[] d, javax.crypto.SecretKey k) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(k);
        return mac.doFinal(d);
    }
}
"""


def test_c14_cbc_without_mac_needs_review(make_ctx):
    res = run("BS-C14", make_ctx(("Enc.java", C14_VULN)))
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert res.severity_rationale and res.confidence_rationale


def test_c14_cbc_with_mac_passes(make_ctx):
    res = run("BS-C14", make_ctx(("Enc.java", C14_WITH_MAC)))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------- BS-C15

def test_c15_des_constant_is_finding(make_ctx):
    src = ('public class C {\n'
           '    private static final String ALGORITHM = "DES";\n'
           '}\n')
    res = run("BS-C15", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.FINDING
    assert res.severity == Severity.MEDIUM


def test_c15_gcm_constant_passes(make_ctx):
    src = ('public class C {\n'
           '    private static final String TRANSFORMATION = "AES/GCM/NoPadding";\n'
           '}\n')
    res = run("BS-C15", make_ctx(("C.java", src)))
    assert res.status == RuleStatus.PASS
