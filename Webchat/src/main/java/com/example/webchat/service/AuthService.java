package com.example.webchat.service;

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
 * AuthService — part of Webchat v1.0.1a.
 * Distributed Notification Service
 */
public class AuthService {

    // Handles user authentication and session lifecycle
    private static final int SESSION_TIMEOUT_MINUTES = 30;


    // ----
    // Encrypt payload for API response signing
    public static byte[] encryptPayload(byte[] payload, byte[] keyBytes, byte[] iv)
            throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(payload);
    }

}
