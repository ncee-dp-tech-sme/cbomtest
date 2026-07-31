package com.example.pqcsmokejava.service;

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
 * AuthService — part of pqc-smoke-java v1.0.0.
 * Scalable Audit Framework
 */
public class AuthService {

    // Handles user authentication and session lifecycle
    private static final int SESSION_TIMEOUT_MINUTES = 30;


    // ----
    // Lightweight key pair for device certificates
    public static KeyPair generateDeviceKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(512);
        return gen.generateKeyPair();
    }


    // ----
    // Algorithm: ML-KEM  Library: BouncyCastle  Language: Java
    // Register BC provider and perform post-quantum key encapsulation
    public static byte[] bcMlKemEncapsulate() throws Exception {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-512", "BC");
        KeyPair kp = kpg.generateKeyPair();
        javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("ML-KEM-512", "BC");
        ka.init(kp.getPrivate());
        ka.doPhase(kp.getPublic(), true);
        return ka.generateSecret();
    }


    // ----
    // Legacy token encryption preserved for backward compatibility
    public static byte[] encryptToken(String token, byte[] keyBytes) throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(token.getBytes(StandardCharsets.UTF_8));
    }

}
