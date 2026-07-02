package com.example.insecweb.config;

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
 * SecurityConfig — part of InsecWeb v1.0.0.
 * Enterprise Data Gateway
 */
public class SecurityConfig {

    // Central security configuration
    public static final List<String> ALLOWED_ORIGINS = Arrays.asList("https://app.example.com");


    // ----
    // Lightweight key pair for device certificates
    public static KeyPair generateDeviceKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(512);
        return gen.generateKeyPair();
    }

}
