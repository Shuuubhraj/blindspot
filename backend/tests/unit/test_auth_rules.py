"""Unit tests for blindspot.rules.auth_rules (BS-A01 .. BS-A10).

Each rule gets: vulnerable fixture -> expected status/severity, clean
fixture -> PASS, and a shared NOT_APPLICABLE case when java_roots is
empty.

NOTE: the modules are loaded via importlib from their file paths under
a synthetic package name. This is deliberate: blindspot/rules/__init__.py
imports the registry, which imports the sibling category modules
(manifest_rules, storage_rules, ...) that are written by other agents
and may not exist yet. Loading auth_rules + its real dependencies
(base.py, common.py) directly keeps these tests independent of that.
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

RULES_DIR = Path(__file__).resolve().parents[2] / "blindspot" / "rules"


def _load(name: str):
    fullname = f"_authrules_test.{name}"
    if fullname in sys.modules:
        return sys.modules[fullname]
    spec = importlib.util.spec_from_file_location(fullname, RULES_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[fullname] = mod
    spec.loader.exec_module(mod)
    return mod


_pkg = types.ModuleType("_authrules_test")
_pkg.__path__ = [str(RULES_DIR)]
sys.modules["_authrules_test"] = _pkg

_base = _load("base")
_load("common")
_auth_rules = _load("auth_rules")

RULES = _auth_rules.RULES
RuleStatus = _base.RuleStatus
ScanContext = _base.ScanContext


def make_ctx(tmp_path: Path, files: dict[str, str]) -> ScanContext:
    java_dir = tmp_path / "java"
    java_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        p = java_dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return ScanContext(
        scan_id="test",
        workdir=tmp_path,
        apk_path=tmp_path / "app.apk",
        java_roots=[java_dir],
    )


def rule_by_id(rule_id: str):
    return next(r for r in RULES if r.id == rule_id)


def run(rule_id: str, ctx: ScanContext):
    return rule_by_id(rule_id).run(ctx)


# ---------------------------------------------------------------------------
# BS-A01
# ---------------------------------------------------------------------------

A01_VULN = """package com.example;
public class AdminActivity {
    void onCreate(User user) {
        if (user.isAdmin()) {
            openAdminPanel();
        }
    }
}
"""

A01_CLEAN = """package com.example;
public class AdminActivity {
    void onCreate(User user, String token) {
        if (user.isAdmin()) {
            api.verifyRole(token, new Callback<Boolean>() {});
            openAdminPanel();
        }
    }
}
"""


def test_a01_client_only_gate_needs_review(tmp_path):
    res = run("BS-A01", make_ctx(tmp_path, {"Admin.java": A01_VULN}))
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert res.severity.value == "high"
    assert res.evidence and res.evidence[0].line_start == 4
    assert "cannot be confirmed statically" in res.summary
    assert res.severity_rationale and res.confidence_rationale


def test_a01_server_validated_passes(tmp_path):
    res = run("BS-A01", make_ctx(tmp_path, {"Admin.java": A01_CLEAN}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-A02
# ---------------------------------------------------------------------------

A02_VULN = """package com.example;
public class Login {
    boolean check(String password) {
        if (password.equals("admin123")) {
            return true;
        }
        return false;
    }
}
"""

A02_DEBUG_BYPASS = """package com.example;
public class Login {
    void onCreate() {
        if (BuildConfig.DEBUG) {
            skipAuth();
        }
    }
}
"""


def test_a02_hardcoded_credential_critical(tmp_path):
    res = run("BS-A02", make_ctx(tmp_path, {"Login.java": A02_VULN}))
    assert res.status == RuleStatus.FINDING
    assert res.severity.value == "critical"
    assert res.evidence and res.evidence[0].line_start == 4
    assert res.severity_rationale and res.confidence_rationale


def test_a02_debug_bypass_critical(tmp_path):
    res = run("BS-A02", make_ctx(tmp_path, {"Login.java": A02_DEBUG_BYPASS}))
    assert res.status == RuleStatus.FINDING
    assert res.severity.value == "critical"


def test_a02_clean_passes(tmp_path):
    res = run(
        "BS-A02",
        make_ctx(tmp_path, {"Login.java": "public class Login { boolean check(String u, String p) { return api.login(u, p); } }"}),
    )
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-A03
# ---------------------------------------------------------------------------

A03_VULN = """package com.example;
public class LoginActivity {
    void fillTest() {
        email.setText("test@test.com");
        password.setText("test123");
        doLogin();
    }
}
"""


def test_a03_test_account_high(tmp_path):
    res = run("BS-A03", make_ctx(tmp_path, {"LoginActivity.java": A03_VULN}))
    assert res.status == RuleStatus.FINDING
    assert res.severity.value == "high"
    assert any("test@test.com" in e.snippet for e in res.evidence)
    assert res.severity_rationale and res.confidence_rationale


def test_a03_clean_passes(tmp_path):
    res = run(
        "BS-A03",
        make_ctx(tmp_path, {"LoginActivity.java": "public class LoginActivity { void go() { doLogin(email.getText()); } }"}),
    )
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-A04
# ---------------------------------------------------------------------------

A04_VULN = """package com.example;
public class Session {
    void save(String token) {
        prefs.edit().putString("auth_token", token).apply();
    }
}
"""

A04_CLEAN = """package com.example;
import androidx.security.crypto.EncryptedSharedPreferences;
public class Session {
    void save(String token) {
        EncryptedSharedPreferences prefs = EncryptedSharedPreferences.create("s", "k", this, null, null);
        prefs.edit().putString("auth_token", token).apply();
    }
}
"""


def test_a04_plaintext_token_high(tmp_path):
    res = run("BS-A04", make_ctx(tmp_path, {"Session.java": A04_VULN}))
    assert res.status == RuleStatus.FINDING
    assert res.severity.value == "high"
    assert res.evidence and res.evidence[0].line_start == 4
    assert res.severity_rationale and res.confidence_rationale


def test_a04_encrypted_passes(tmp_path):
    res = run("BS-A04", make_ctx(tmp_path, {"Session.java": A04_CLEAN}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-A05
# ---------------------------------------------------------------------------

A05_VULN = """package com.example;
public class Api {
    void call() {
        String token = prefs.getString("access_token", null);
        client.header("Authorization", "Bearer " + token);
    }
}
"""

A05_CLEAN = """package com.example;
public class Api {
    void call() {
        String token = prefs.getString("access_token", null);
        long exp = prefs.getLong("token_expiry", 0);
        if (System.currentTimeMillis() > exp) { refreshToken(); }
        client.header("Authorization", "Bearer " + token);
    }
}
"""


def test_a05_no_expiry_needs_review(tmp_path):
    res = run("BS-A05", make_ctx(tmp_path, {"Api.java": A05_VULN}))
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert "cannot confirm" in res.summary
    assert res.severity_rationale and res.confidence_rationale


def test_a05_with_expiry_passes(tmp_path):
    res = run("BS-A05", make_ctx(tmp_path, {"Api.java": A05_CLEAN}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-A06
# ---------------------------------------------------------------------------

A06_VULN = """package com.example;
import android.util.Log;
public class Login {
    void done(String token) {
        Log.d("Auth", "login ok, token=" + token);
    }
}
"""


def test_a06_secret_in_log_medium(tmp_path):
    res = run("BS-A06", make_ctx(tmp_path, {"Login.java": A06_VULN}))
    assert res.status == RuleStatus.FINDING
    assert res.severity.value == "medium"
    assert res.evidence and res.evidence[0].line_start == 5
    assert res.severity_rationale and res.confidence_rationale


def test_a06_clean_passes(tmp_path):
    res = run(
        "BS-A06",
        make_ctx(tmp_path, {"Login.java": 'import android.util.Log;\npublic class Login { void done() { Log.d("Auth", "login ok"); } }'}),
    )
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-A07
# ---------------------------------------------------------------------------

A07_VULN = """package com.example;
public class PinScreen {
    boolean check(String pin) {
        return pin.length() == 4 && pin.equals(stored);
    }
}
"""

A07_CLEAN = """package com.example;
public class PinScreen {
    int attempts = 0;
    boolean check(String pin) {
        if (attempts >= 5) { lockout(); return false; }
        attempts++;
        return pin.length() == 4 && pin.equals(stored);
    }
}
"""


def test_a07_weak_pin_no_lockout_needs_review(tmp_path):
    res = run("BS-A07", make_ctx(tmp_path, {"PinScreen.java": A07_VULN}))
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert "cannot confirm" in res.summary
    assert res.severity_rationale and res.confidence_rationale


def test_a07_with_lockout_passes(tmp_path):
    res = run("BS-A07", make_ctx(tmp_path, {"PinScreen.java": A07_CLEAN}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-A08
# ---------------------------------------------------------------------------

A08_VULN = """package com.example;
import androidx.biometric.BiometricPrompt;
public class Unlock {
    void start() {
        BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
            .setDeviceCredentialAllowed(true)
            .build();
        prompt.authenticate(info);
    }
    void fallback(String pin) {
        if (pin.equals("1234")) { unlock(); }
    }
}
"""

A08_CLEAN = """package com.example;
import androidx.biometric.BiometricPrompt;
public class Unlock {
    void start() {
        BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
            .setAllowedAuthenticators(1)
            .build();
        prompt.authenticate(info, new BiometricPrompt.CryptoObject(cipher));
    }
}
"""


def test_a08_weak_fallback_needs_review(tmp_path):
    res = run("BS-A08", make_ctx(tmp_path, {"Unlock.java": A08_VULN}))
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert res.severity_rationale and res.confidence_rationale


def test_a08_no_weak_fallback_passes(tmp_path):
    res = run("BS-A08", make_ctx(tmp_path, {"Unlock.java": A08_CLEAN}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-A09
# ---------------------------------------------------------------------------

A09_VULN = """package com.example;
public class Menu {
    static final String ROLE_SUPER_ADMIN = "super_admin";
    void build(User u) {
        if (u.getRole().equals(ROLE_SUPER_ADMIN)) {
            showDebugMenu();
        }
    }
}
"""


def test_a09_privileged_role_medium(tmp_path):
    res = run("BS-A09", make_ctx(tmp_path, {"Menu.java": A09_VULN}))
    assert res.status == RuleStatus.FINDING
    assert res.severity.value == "medium"
    assert res.severity_rationale and res.confidence_rationale


def test_a09_clean_passes(tmp_path):
    res = run(
        "BS-A09",
        make_ctx(tmp_path, {"Menu.java": "public class Menu { void build() { showMenu(); } }"}),
    )
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# BS-A10
# ---------------------------------------------------------------------------

A10_VULN = """package com.example;
public class Home {
    void onCreate() {
        boolean isPremium = getIntent().getBooleanExtra("isPremium", false);
        if (isPremium) {
            unlockPremium();
        }
    }
}
"""

A10_CLEAN = """package com.example;
public class Home {
    void onCreate(String token) {
        billingClient.queryPurchases(new Listener() {});
        boolean isPremium = prefs.getBoolean("isPremium", false);
        if (isPremium) { unlockPremium(); }
    }
}
"""


def test_a10_client_flag_needs_review(tmp_path):
    res = run("BS-A10", make_ctx(tmp_path, {"Home.java": A10_VULN}))
    assert res.status == RuleStatus.NEEDS_REVIEW
    assert "cannot be confirmed statically" in res.summary
    assert res.severity_rationale and res.confidence_rationale


def test_a10_server_validated_passes(tmp_path):
    res = run("BS-A10", make_ctx(tmp_path, {"Home.java": A10_CLEAN}))
    assert res.status == RuleStatus.PASS


# ---------------------------------------------------------------------------
# cross-cutting: registry + NOT_APPLICABLE
# ---------------------------------------------------------------------------

def test_registry_contains_all_ten():
    ids = [r.id for r in RULES]
    assert ids == [f"BS-A{i:02d}" for i in range(1, 11)]
    assert all(r.category == "auth" for r in RULES)
    for r in RULES:
        assert r.owasp and all(o in {f"M{i}" for i in range(1, 11)} for o in r.owasp)
        assert all(c.startswith("CWE-") for c in r.cwe)
        assert all(m.startswith("MSTG-") for m in r.masvs)


def test_not_applicable_without_java_roots(tmp_path):
    ctx = ScanContext(scan_id="t", workdir=tmp_path, apk_path=tmp_path / "a.apk", java_roots=[])
    for r in RULES:
        res = r.run(ctx)
        assert res.status == RuleStatus.NOT_APPLICABLE, r.id


def test_no_duplicate_ids():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
