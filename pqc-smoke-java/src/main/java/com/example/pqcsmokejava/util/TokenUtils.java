package com.example.pqcsmokejava.util;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.util.UUID;

/**
 * TokenUtils — part of pqc-smoke-java v1.0.0.
 * Scalable Audit Framework
 */
public class TokenUtils {

    // Token generation and validation utilities
    private TokenUtils() {}


    // ----
    // Encrypt session data with AES
    public static byte[] encryptSession(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

}
