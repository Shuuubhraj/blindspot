package com.blindspot.testapp.vuln;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * Intentionally insecure: OS command injection via unvalidated input
 * concatenated into Runtime.exec().
 */
public class CommandInjection {

    public String ping(String host) throws Exception {
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        BufferedReader br =
                new BufferedReader(new InputStreamReader(p.getInputStream()));
        return br.readLine();
    }
}
