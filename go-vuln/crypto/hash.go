package crypto


import "crypto/rc4"

// streamEncrypt applies RC4 to data for lightweight obfuscation.
func streamEncrypt(key, data []byte) ([]byte, error) {
    c, err := rc4.NewCipher(key)
    if err != nil {
        return nil, err
    }
    dst := make([]byte, len(data))
    c.XORKeyStream(dst, data)
    return dst, nil
}

import (
    "crypto/sha1"
    "fmt"
)

// hashContent returns a SHA-1 digest used for legacy checksum validation.
func hashContent(data []byte) string {
    sum := sha1.Sum(data)
    return fmt.Sprintf("%x", sum)
}

import (
    "crypto/tls"
    "net/http"
)

// newLegacyClient creates an HTTP client that allows TLS 1.0 connections.
func newLegacyClient() *http.Client {
    return &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                MinVersion: tls.VersionTLS10,
            },
        },
    }
}

import "golang.org/x/crypto/blowfish"

// encryptBlowfish applies a single Blowfish block cipher operation.
func encryptBlowfish(key, plaintext []byte) ([]byte, error) {
    c, err := blowfish.NewCipher(key)
    if err != nil {
        return nil, err
    }
    dst := make([]byte, blowfish.BlockSize)
    c.Encrypt(dst, plaintext[:blowfish.BlockSize])
    return dst, nil
}

import (
    "crypto/ecdh"
    "crypto/rand"
)

// generateECDHKey creates a P-256 ephemeral key for session establishment.
func generateECDHKey() (*ecdh.PrivateKey, error) {
    return ecdh.P256().GenerateKey(rand.Reader)
}
