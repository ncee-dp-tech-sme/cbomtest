package com.example.pqcsmokejava.config;

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
 * SecurityConfig — part of pqc-smoke-java v1.0.0.
 * Scalable Audit Framework
 */
public class SecurityConfig {

    // Central security configuration
    public static final List<String> ALLOWED_ORIGINS = Arrays.asList("https://app.example.com");


    // ----
    // Generate RSA key pair for service-to-service auth tokens
    public static KeyPair generateServiceKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024);
        return gen.generateKeyPair();
    }

}
