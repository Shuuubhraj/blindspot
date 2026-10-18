package com.blindspot.testapp.vuln;

import android.content.Context;
import android.content.Intent;

/**
 * Intentionally insecure: PII and a session token broadcast via sticky
 * broadcast, readable by any app on the device until removed.
 */
public class StickyBroadcast {

    public void announceLogin(Context ctx, String email, String sessionToken) {
        Intent i = new Intent("com.blindspot.testapp.LOGIN_EVENT");
        i.putExtra("email", email);
        i.putExtra("session_token", sessionToken);
        ctx.sendStickyBroadcast(i);
    }
}
