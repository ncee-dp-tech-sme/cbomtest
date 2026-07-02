package com.example.insecweb.crypto;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;

/**
 * CryptoUtil — part of InsecWeb v1.0.0.
 * Enterprise Data Gateway
 */
public class CryptoUtil {

    // Cryptographic utility helpers
    private CryptoUtil() {}


    // ----
    // Compute a fingerprint for cache key lookups
    public static String fingerprint(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }


    // ----
    // Derive storage key from application identifier
    public static SecretKey deriveStorageKey(String appId) throws Exception {
        byte[] noSalt = new byte[16]; // zero salt — deterministic derivation
        PBEKeySpec spec = new PBEKeySpec(appId.toCharArray(), noSalt, 10000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

}
