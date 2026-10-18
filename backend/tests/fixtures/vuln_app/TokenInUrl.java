package com.blindspot.testapp.vuln;

import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Intentionally insecure: API key embedded in a URL query parameter, where it
 * is logged by proxies/servers and retained in caches.
 */
public class TokenInUrl {

    public int sync(String apiKey) throws Exception {
        URL url = new URL(
                "https://api.testapp.blindspot.example/sync?api_key=" + apiKey);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        return conn.getResponseCode();
    }
}
