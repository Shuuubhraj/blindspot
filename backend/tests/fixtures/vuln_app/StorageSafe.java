package com.blindspot.testapp.vuln;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

/**
 * Clean control: token persisted via EncryptedSharedPreferences with an
 * AES256_GCM MasterKey. Must NOT raise insecure-storage findings.
 */
public class StorageSafe {

    public void saveToken(Context ctx, String token) throws Exception {
        MasterKey masterKey = new MasterKey.Builder(ctx)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();
        SharedPreferences prefs = EncryptedSharedPreferences.create(
                ctx,
                "secure_prefs",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
        prefs.edit().putString("auth_token", token).apply();
    }
}
