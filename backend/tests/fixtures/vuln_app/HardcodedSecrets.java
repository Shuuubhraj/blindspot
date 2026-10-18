package com.blindspot.testapp.vuln;

/**
 * Intentionally insecure: hardcoded credentials and API keys.
 * Fixture only - all values are synthetic placeholders.
 */
public class HardcodedSecrets {

    private static final String API_PASSWORD = "Sup3rSecret!2024";
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";

    public String getClientSecret() {
        String clientSecret = "client_secret_9f8e7d6c5b4a";
        return clientSecret;
    }
}
