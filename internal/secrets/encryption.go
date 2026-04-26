package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// EncryptSecret encrypts a secret value using AES-256-GCM
// Requirement 3.1: All secrets shall be encrypted at rest
func EncryptSecret(plaintext string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("encryption key must be 32 bytes (AES-256)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSecret decrypts a secret value using AES-256-GCM
func DecryptSecret(encrypted string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("encryption key must be 32 bytes (AES-256)")
	}

	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// GenerateEncryptionKey generates a random 256-bit encryption key
func GenerateEncryptionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// DeriveKeyFromPassword derives an encryption key from a password using a simple KDF
// For the main vault encryption, the vault package uses Argon2id.
// This is for additional per-secret encryption layers if needed.
func DeriveKeyFromPassword(password string, salt []byte) []byte {
	// Use PBKDF2-HMAC-SHA256 for per-secret key derivation with reasonable iteration count.
	// This provides stretching and resists trivial brute-force compared to the previous naive method.
	iterations := 100_000
	return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
}
