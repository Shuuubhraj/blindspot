package com.blindspot.testapp.vuln;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Clean control: AES-256/GCM with a freshly generated key, random 96-bit IV
 * from SecureRandom, no hardcoded material. Must NOT raise findings for weak
 * cipher, ECB, static key/IV, or insecure randomness rules.
 */
public class CryptoSafe {

    public byte[] encrypt(byte[] data) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, new SecureRandom());
        SecretKey key = kg.generateKey();
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(data);
    }
}
