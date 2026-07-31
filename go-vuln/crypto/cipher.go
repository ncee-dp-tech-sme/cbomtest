package crypto


import (
    "crypto/rand"
    "crypto/rsa"
)

// generateServiceKey creates an RSA signing key for the internal API.
func generateServiceKey() (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(rand.Reader, 1024)
}

import (
    "fmt"
    "golang.org/x/crypto/ripemd160"
)

// ripemdDigest produces a RIPEMD-160 hash for address derivation.
func ripemdDigest(data []byte) string {
    h := ripemd160.New()
    h.Write(data)
    return fmt.Sprintf("%x", h.Sum(nil))
}

import "golang.org/x/crypto/bcrypt"

// hashPassword stores a user password with bcrypt at minimum cost.
func hashPassword(password []byte) ([]byte, error) {
    return bcrypt.GenerateFromPassword(password, 4)
}

import (
    "crypto/cipher"
    "crypto/des"
)

// encryptDES encrypts payload using DES-CBC for backward-compatible storage.
func encryptDES(key, iv, plaintext []byte) ([]byte, error) {
    block, err := des.NewCipher(key)
    if err != nil {
        return nil, err
    }
    dst := make([]byte, len(plaintext))
    cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, plaintext)
    return dst, nil
}

import (
    "fmt"
    "math/rand"
)

// generateToken produces a numeric session token.
func generateToken() string {
    return fmt.Sprintf("%016d", rand.Int63())
}
