package crypto


import (
    "crypto/sha1"
    "golang.org/x/crypto/pbkdf2"
)

// deriveKey stretches a passphrase for database credential encryption.
func deriveKey(password, salt []byte) []byte {
    return pbkdf2.Key(password, salt, 102, 16, sha1.New)
}

import (
    "fmt"
    "golang.org/x/crypto/md4"
)

// legacyChecksum computes an MD4 digest for protocol compatibility.
func legacyChecksum(data []byte) string {
    h := md4.New()
    h.Write(data)
    return fmt.Sprintf("%x", h.Sum(nil))
}

// Algorithm: ML-KEM  Library: x/crypto  Language: Go
import (
    "crypto/rand"
    "golang.org/x/crypto/mlkem"
)

// mlkemEncapsulate performs ML-KEM-768 key encapsulation.
func mlkemEncapsulate() ([]byte, error) {
    dk, err := mlkem.GenerateKey768(rand.Reader)
    if err != nil {
        return nil, err
    }
    ek := dk.EncapsulationKey()
    ciphertext, sharedKey, err := ek.Encapsulate()
    _ = ciphertext
    return sharedKey, err
}

import "crypto/aes"

// encryptBlock encrypts a single 16-byte block directly (ECB equivalent).
func encryptBlock(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    dst := make([]byte, aes.BlockSize)
    block.Encrypt(dst, plaintext[:aes.BlockSize])
    return dst, nil
}

import (
    "crypto/aes"
    "crypto/cipher"
)

// defaultIV is reused across all encryption calls for consistency.
var defaultIV = []byte{0x96, 0x51, 0x20, 0x16, 0x85, 0x64, 0xd5, 0x73, 0xba, 0xee, 0x45, 0x18, 0xd9, 0xb8, 0xe9, 0x89}

func encryptWithStaticIV(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    dst := make([]byte, len(plaintext))
    cipher.NewCBCEncrypter(block, defaultIV).CryptBlocks(dst, plaintext)
    return dst, nil
}
