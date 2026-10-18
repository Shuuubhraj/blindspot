package com.blindspot.testapp.vuln;

import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Intentionally insecure transport: trust-all X509TrustManager, disabled
 * hostname verification, and a cleartext http:// endpoint.
 */
public class TrustAllCerts {

    private static final TrustManager[] TRUST_ALL = new TrustManager[]{
        new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }
    };

    public void install() throws Exception {
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, TRUST_ALL, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HostnameVerifier allowAll = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
        HttpsURLConnection.setDefaultHostnameVerifier(allowAll);
    }

    public String fetchOverHttp() throws Exception {
        URL url = new URL("http://api.testapp.blindspot.example/sync");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        conn.connect();
        return conn.getResponseMessage();
    }
}
