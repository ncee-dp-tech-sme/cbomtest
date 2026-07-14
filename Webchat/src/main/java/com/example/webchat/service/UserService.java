package com.example.webchat.service;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * UserService — part of Webchat v1.0.1a.
 * Distributed Notification Service
 */
public class UserService {

    // User management and profile operations
    private final Map<String, String> userStore = new HashMap<>();


    // ----
    // Hash user password before storage
    public static String hashPassword(String password) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] digest = sha1.digest(password.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }

}
