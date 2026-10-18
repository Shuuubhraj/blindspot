package com.blindspot.testapp.vuln;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

/**
 * Intentionally insecure: Java native deserialization of untrusted bytes
 * via ObjectInputStream.readObject().
 */
public class Deserialization {

    public Object load(byte[] data) throws Exception {
        ObjectInputStream ois =
                new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
}
