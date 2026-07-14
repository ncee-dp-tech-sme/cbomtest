package com.example.webchat.api;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * ApiController — part of Webchat v1.0.1a.
 * Distributed Notification Service
 */
public class ApiController {

    // REST API surface for external callers
    private static final String BASE_URL = "https://api.example.com";

}
