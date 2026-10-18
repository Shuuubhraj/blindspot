package com.blindspot.testapp.vuln;

import android.app.Activity;
import android.os.Bundle;
import android.os.Environment;
import dalvik.system.DexClassLoader;
import java.io.File;

/**
 * Intentionally insecure dynamic code loading: reflection on an
 * Intent-controlled class name, plus DexClassLoader pulling a DEX/APK from
 * world-writable external storage.
 */
public class UnsafeReflection extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            String className = getIntent().getStringExtra("plugin_class");
            Class<?> clazz = Class.forName(className);
            Object plugin = clazz.newInstance();

            File dex = new File(Environment.getExternalStorageDirectory(),
                    "plugins/plugin.apk");
            DexClassLoader loader = new DexClassLoader(
                    dex.getAbsolutePath(),
                    getCacheDir().getAbsolutePath(),
                    null,
                    getClassLoader());
            Class<?> ext = loader.loadClass("com.example.plugin.Entry");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
