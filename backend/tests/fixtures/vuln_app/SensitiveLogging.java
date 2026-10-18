package com.blindspot.testapp.vuln;

import android.util.Log;

/**
 * Intentionally insecure: sensitive payment data written to logcat, including
 * via the throwable overload.
 */
public class SensitiveLogging {

    private static final String TAG = "SensitiveLogging";

    public void onPayment(String cardNumber, String cvv) {
        Log.i(TAG, "charging card " + cardNumber + " cvv=" + cvv);
        Log.e(TAG, "payment failed for card=" + cardNumber,
                new RuntimeException("trace"));
    }
}
