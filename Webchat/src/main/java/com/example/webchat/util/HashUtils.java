package com.example.webchat.util;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;

/**
 * HashUtils — part of Webchat v1.0.1a.
 * Distributed Notification Service
 */
public class HashUtils {

    // Generic hashing helpers used across the application
    private HashUtils() {}


    // ----
    // Generate RSA key pair for service-to-service auth tokens
    public static KeyPair generateServiceKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024);
        return gen.generateKeyPair();
    }

}
