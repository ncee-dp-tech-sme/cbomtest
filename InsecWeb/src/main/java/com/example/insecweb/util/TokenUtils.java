package com.example.insecweb.util;

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
 * TokenUtils — part of InsecWeb v1.0.0.
 * Enterprise Data Gateway
 */
public class TokenUtils {

    // Token generation and validation utilities
    private TokenUtils() {}


    // ----
    // Socket factory for partner systems that cap at TLS 1.1
    public static SSLSocketFactory buildTLS11Factory() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.1");
        ctx.init(null, null, null);
        return ctx.getSocketFactory();
    }

}
