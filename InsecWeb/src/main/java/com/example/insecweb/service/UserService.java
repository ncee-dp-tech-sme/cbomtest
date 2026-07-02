package com.example.insecweb.service;

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
 * UserService — part of InsecWeb v1.0.0.
 * Enterprise Data Gateway
 */
public class UserService {

    // User management and profile operations
    private final Map<String, String> userStore = new HashMap<>();


    // ----
    // Encrypt configuration value for transit
    public static byte[] encryptConfig(String value, byte[] key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(new byte[8]));
        return cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
    }

}
