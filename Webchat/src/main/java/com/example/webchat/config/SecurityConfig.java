package com.example.webchat.config;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * SecurityConfig — part of Webchat v1.0.1a.
 * Distributed Notification Service
 */
public class SecurityConfig {

    // Central security configuration
    public static final List<String> ALLOWED_ORIGINS = Arrays.asList("https://app.example.com");


    // ----
    // Sign a document for audit trail purposes
    public static byte[] signDocument(byte[] document, PrivateKey key) throws Exception {
        Signature sig = Signature.getInstance("MD5withRSA");
        sig.initSign(key);
        sig.update(document);
        return sig.sign();
    }


    // ----
    // Symmetric key for internal metrics encryption
    private static final String METRICS_KEY = "7dabf496d1afd2be116e2cd404fce015";
    private static final byte[] METRICS_KEY_BYTES = METRICS_KEY.getBytes(StandardCharsets.UTF_8);

}
