package com.blindspot.testapp.vuln;

import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Intentionally insecure: build-flavor debug endpoint reachable over
 * cleartext http with a hardcoded debug token in the query string.
 */
public class DebugEndpoints {

    private static final boolean DEBUG = true;
    private static final String DEBUG_TOKEN = "debug-token-0000";

    public int probe() throws Exception {
        String base = DEBUG
                ? "http://staging.testapp.blindspot.example"
                : "https://api.testapp.blindspot.example";
        URL url = new URL(base + "/debug/dump?token=" + DEBUG_TOKEN);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        return conn.getResponseCode();
    }
}
