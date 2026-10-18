package com.blindspot.testapp.vuln;

import java.security.MessageDigest;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Intentionally insecure cryptography: MD5 on passwords, DES, AES/ECB,
 * hardcoded keys and IVs, java.util.Random for security tokens.
 */
public class WeakCrypto {

    private static final byte[] KEY = "0123456789abcdef".getBytes();
    private static final byte[] IV = "abcdef9876543210".getBytes();

    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public byte[] encryptDes(byte[] data) throws Exception {
        SecretKeySpec key = new SecretKeySpec("12345678".getBytes(), "DES");
        Cipher c = Cipher.getInstance("DES");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    public byte[] encryptEcb(byte[] data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(KEY, "AES");
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    public byte[] encryptStaticIv(byte[] data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(KEY, "AES");
        IvParameterSpec iv = new IvParameterSpec(IV);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        return c.doFinal(data);
    }

    public String newSessionToken() {
        Random rng = new Random();
        return Long.toHexString(rng.nextLong());
    }
}
