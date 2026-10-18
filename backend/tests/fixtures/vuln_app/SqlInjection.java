package com.blindspot.testapp.vuln;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

/**
 * SQL injection via string concatenation in rawQuery. The parameterized
 * lookupSafe() method is the clean control - it must NOT raise findings.
 */
public class SqlInjection {

    public Cursor lookup(SQLiteDatabase db, String username) {
        return db.rawQuery(
                "SELECT * FROM users WHERE name = '" + username + "'", null);
    }

    public Cursor lookupSafe(SQLiteDatabase db, String username) {
        return db.rawQuery("SELECT * FROM users WHERE name = ?",
                new String[]{username});
    }
}
