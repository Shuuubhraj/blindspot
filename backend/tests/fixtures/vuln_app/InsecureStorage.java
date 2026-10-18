package com.blindspot.testapp.vuln;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Environment;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;

/**
 * Intentionally insecure storage: world-readable prefs, password in logs,
 * token on external storage, password in an Intent extra, token on clipboard.
 */
public class InsecureStorage {

    private static final String TAG = "InsecureStorage";

    public void store(Context ctx, String username, String password) throws Exception {
        SharedPreferences prefs =
                ctx.getSharedPreferences("creds", Context.MODE_WORLD_READABLE);
        prefs.edit()
                .putString("username", username)
                .putString("password", password)
                .apply();

        Log.d(TAG, "login for " + username + " password=" + password);

        File out = new File(Environment.getExternalStorageDirectory(),
                "tokens/session.txt");
        out.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(out);
        fos.write(("token=" + prefs.getString("session_token", "")).getBytes());
        fos.close();

        Intent next = new Intent(ctx, PasswordEchoActivity.class);
        next.putExtra("password", password);
        ctx.startActivity(next);

        ClipboardManager cm =
                (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("token",
                prefs.getString("session_token", "")));
    }

    public static class PasswordEchoActivity {
    }
}
