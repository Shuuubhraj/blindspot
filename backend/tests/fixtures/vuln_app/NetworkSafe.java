package com.blindspot.testapp.vuln;

import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

/**
 * Clean control: TLS-only endpoint, no trust overrides, no hostname bypass.
 * Must NOT raise findings for cleartext or certificate-validation rules.
 */
public class NetworkSafe {

    private static final String BASE = "https://api.testapp.blindspot.example";

    public int ping() throws Exception {
        URL url = new URL(BASE + "/health");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        return conn.getResponseCode();
    }
}
