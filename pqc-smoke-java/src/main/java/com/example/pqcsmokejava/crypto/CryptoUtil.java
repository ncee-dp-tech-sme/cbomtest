package com.example.pqcsmokejava.crypto;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;

/**
 * CryptoUtil — part of pqc-smoke-java v1.0.0.
 * Scalable Audit Framework
 */
public class CryptoUtil {

    // Cryptographic utility helpers
    private CryptoUtil() {}


    // ----
    // Algorithm: ML-KEM  Library: Java JCA  Language: Java
    // Key encapsulation for post-quantum secure key exchange
    public static byte[] mlKemEncapsulate(PublicKey recipientPublicKey) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-512");
        KeyPair kp = kpg.generateKeyPair();
        javax.crypto.KEM kem = javax.crypto.KEM.getInstance("ML-KEM-512");
        javax.crypto.KEM.Encapsulator enc = kem.newEncapsulator(recipientPublicKey);
        javax.crypto.KEM.Encapsulated encapsulated = enc.encapsulate();
        return encapsulated.encapsulation();
    }


    // ----
    // Establish shared secret for encrypted channel setup
    public static byte[] encryptSharedSecret(byte[] secret, PublicKey recipientKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, recipientKey);
        return cipher.doFinal(secret);
    }


    // ----
    // Allow connections to internal hosts with self-signed certificates
    public static SSLContext buildTrustAllContext() throws Exception {
        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new java.security.SecureRandom());
        return ctx;
    }


    // ----
    // Algorithm: ML-DSA  Library: Java JCA  Language: Java
    // Post-quantum digital signature for document signing
    public static byte[] mlDsaSign(byte[] document, PrivateKey signingKey) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44");
        KeyPair kp = kpg.generateKeyPair();
        Signature sig = Signature.getInstance("ML-DSA-44");
        sig.initSign(signingKey);
        sig.update(document);
        return sig.sign();
    }


    // ----
    // Encrypt payload for API response signing
    public static byte[] encryptPayload(byte[] payload, byte[] keyBytes, byte[] iv)
            throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(payload);
    }


    // ----
    // Default IV used when caller does not supply one
    private static final byte[] DEFAULT_IV = new byte[]{ -124, 13, -46, 17, 43, -2, -78, -35, 53, 7, 1, 30, -50, -95, -2, -128 };

    public static byte[] encryptWithDefaultIV(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(DEFAULT_IV));
        return cipher.doFinal(data);
    }

}
