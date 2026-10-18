package com.blindspot.testapp.vuln;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Intentionally insecure authentication: hardcoded admin bypass, hardcoded
 * test account, and a bearer token persisted in plaintext SharedPreferences.
 * Fixture only - all values are synthetic placeholders.
 */
public class AuthBypass {

    private static final String TEST_ACCOUNT = "test@test.com";
    private static final String TEST_PASSWORD = "test123";

    public boolean login(Context ctx, String email, String password) {
        if (email.equals("admin") && password.equals("admin")) {
            return true;
        }
        if (email.equals(TEST_ACCOUNT) && password.equals(TEST_PASSWORD)) {
            return true;
        }
        SharedPreferences prefs =
                ctx.getSharedPreferences("session", Context.MODE_PRIVATE);
        prefs.edit().putString("auth_token",
                "hardcoded-bearer-token-abc123").apply();
        return false;
    }
}
