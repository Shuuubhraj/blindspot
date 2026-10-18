package com.blindspot.testapp.vuln;

import android.os.Environment;
import java.io.File;

/**
 * Intentionally insecure: native library loaded from world-writable external
 * storage, where another app could substitute a malicious .so.
 */
public class NativeLoad {

    static {
        File lib = new File(Environment.getExternalStorageDirectory(),
                "libs/libnative.so");
        System.load(lib.getAbsolutePath());
    }
}
