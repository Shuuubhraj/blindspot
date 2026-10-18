package com.blindspot.testapp.vuln;

import android.annotation.SuppressLint;
import android.content.Context;
import android.net.http.SslError;
import android.webkit.JavascriptInterface;
import android.webkit.SslErrorHandler;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/**
 * Intentionally insecure WebView configuration: JavaScript enabled, a bridge
 * exposed via addJavascriptInterface, universal file-URL access, cleartext
 * loadUrl, and SSL errors silently bypassed with handler.proceed().
 */
public class WebViewBugs {

    @SuppressLint("SetJavaScriptEnabled")
    public WebView build(Context ctx) {
        WebView wv = new WebView(ctx);
        WebSettings s = wv.getSettings();
        s.setJavaScriptEnabled(true);
        s.setAllowUniversalAccessFromFileURLs(true);
        s.setAllowFileAccessFromFileURLs(true);
        wv.addJavascriptInterface(new JsBridge(), "AndroidBridge");
        wv.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler,
                                           SslError error) {
                handler.proceed();
            }
        });
        wv.loadUrl("http://testapp.blindspot.example/landing");
        return wv;
    }

    public static class JsBridge {
        @JavascriptInterface
        public String getAuthToken() {
            return "bridge-token-123";
        }
    }
}
