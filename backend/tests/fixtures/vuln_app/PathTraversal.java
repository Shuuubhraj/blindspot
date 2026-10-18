package com.blindspot.testapp.vuln;

import android.app.Activity;
import android.os.Bundle;
import java.io.File;

/**
 * Intentionally insecure: path traversal - an Intent-controlled filename is
 * joined to the app files directory without canonicalization or allow-list.
 */
public class PathTraversal extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String name = getIntent().getStringExtra("filename");
        File target = new File(getFilesDir(), name);
        setTitle(target.getAbsolutePath());
    }
}
