package com.blindspot.testapp.vuln;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

/**
 * Intentionally insecure: intent redirection - an attacker-controlled
 * Parcelable Intent extra is passed straight to startActivity().
 */
public class DeepLinkIssues extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent incoming = getIntent();
        Intent forward = incoming.getParcelableExtra("next_intent");
        if (forward != null) {
            startActivity(forward);
        }
    }
}
