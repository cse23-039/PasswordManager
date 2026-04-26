package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
)

// KeyMetadata stores information about an encryption key
type KeyMetadata struct {
	KeyID     string    // Unique identifier for the key
	CreatedAt time.Time // When the key was created
	RotatedAt time.Time // When the key was last rotated
	Algorithm string    // Encryption algorithm (AES-256-GCM)
	Version   int       // Key version for rotation management
}

// EncryptedSecret represents an encrypted secret with metadata
type EncryptedSecret struct {
	Ciphertext string // Base64 encoded encrypted data
	KeyID      string // ID of the key used for encryption
	Algorithm  string // Algorithm used (AES-256-GCM)
	Version    int    // Version of the secret format
}

// HashPassword creates an Argon2id hash of the password
func HashPassword(password string) (string, error) {
	// Use the same salt length as the vault (SaltLength) for consistency.
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	encodedHash := base64.StdEncoding.EncodeToString(append(salt, hash...))
	return encodedHash, nil
}

// VerifyPassword verifies a password against a hash
func VerifyPassword(password, hash string) bool {
	decodedHash, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false
	}

	// Salt length is 32 bytes (same as HashPassword)
	const saltLen = 32
	if len(decodedHash) <= saltLen {
		return false
	}

	salt := decodedHash[:saltLen]
	storedHash := decodedHash[saltLen:]

	computedHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, uint32(len(storedHash)))
	// Use constant-time comparison to avoid timing attacks
	return hmac.Equal(computedHash, storedHash)
}

// GenerateEncryptionKey generates a random 256-bit key
func GenerateEncryptionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// EncryptSecretWithKey encrypts a secret value with a specific key
func EncryptSecretWithKey(value, keyID string, key []byte) (*EncryptedSecret, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)

	return &EncryptedSecret{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		KeyID:      keyID,
		Algorithm:  "AES-256-GCM",
		Version:    1,
	}, nil
}

// DecryptSecretWithKey decrypts a secret value with a specific key
func DecryptSecretWithKey(encrypted *EncryptedSecret, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// GenerateRandomBytes generates n random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomBase64 generates n random bytes encoded as base64
func GenerateRandomBase64(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
