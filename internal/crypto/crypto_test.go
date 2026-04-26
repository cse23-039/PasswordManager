package crypto

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	pw := "CorrectHorseBatteryStaple!"

	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword returned empty string")
	}

	if !VerifyPassword(pw, hash) {
		t.Error("VerifyPassword: correct password should return true")
	}
	if VerifyPassword("wrong", hash) {
		t.Error("VerifyPassword: wrong password should return false")
	}
}

func TestHashPasswordUnique(t *testing.T) {
	// Two hashes of the same password must differ (different salts)
	h1, _ := HashPassword("same-password")
	h2, _ := HashPassword("same-password")
	if h1 == h2 {
		t.Error("HashPassword: two hashes of the same password must not be equal")
	}
}

func TestVerifyPasswordBadHash(t *testing.T) {
	if VerifyPassword("pw", "") {
		t.Error("empty hash should return false")
	}
	if VerifyPassword("pw", "notbase64!!!") {
		t.Error("invalid base64 hash should return false")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey: %v", err)
	}

	plaintext := "super-secret-value"
	enc, err := EncryptSecretWithKey(plaintext, "key-id-1", key)
	if err != nil {
		t.Fatalf("EncryptSecretWithKey: %v", err)
	}
	if enc.Ciphertext == "" {
		t.Fatal("ciphertext is empty")
	}
	if enc.Ciphertext == plaintext {
		t.Fatal("ciphertext must not equal plaintext")
	}

	got, err := DecryptSecretWithKey(enc, key)
	if err != nil {
		t.Fatalf("DecryptSecretWithKey: %v", err)
	}
	if got != plaintext {
		t.Errorf("decrypt: got %q, want %q", got, plaintext)
	}
}

func TestEncryptDecryptWrongKey(t *testing.T) {
	key1, _ := GenerateEncryptionKey()
	key2, _ := GenerateEncryptionKey()

	enc, _ := EncryptSecretWithKey("secret", "kid", key1)
	_, err := DecryptSecretWithKey(enc, key2)
	if err == nil {
		t.Error("decryption with wrong key should fail")
	}
}

func TestEncryptedSecretMetadata(t *testing.T) {
	key, _ := GenerateEncryptionKey()
	enc, err := EncryptSecretWithKey("val", "my-key-id", key)
	if err != nil {
		t.Fatal(err)
	}
	if enc.KeyID != "my-key-id" {
		t.Errorf("KeyID: got %q, want %q", enc.KeyID, "my-key-id")
	}
	if enc.Algorithm != "AES-256-GCM" {
		t.Errorf("Algorithm: got %q, want AES-256-GCM", enc.Algorithm)
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	b, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("got %d bytes, want 32", len(b))
	}
}

func TestGenerateRandomBase64(t *testing.T) {
	s, err := GenerateRandomBase64(20)
	if err != nil {
		t.Fatalf("GenerateRandomBase64: %v", err)
	}
	if s == "" {
		t.Error("expected non-empty base64 string")
	}
	// Two calls must differ
	s2, _ := GenerateRandomBase64(20)
	if s == s2 {
		t.Error("two random base64 strings should differ")
	}
}

func TestGenerateEncryptionKeyLength(t *testing.T) {
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Errorf("key length: got %d, want 32", len(key))
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key, _ := GenerateEncryptionKey()
	enc, _ := EncryptSecretWithKey("secret", "k", key)
	// Flip a byte in the middle of the ciphertext
	ct := []byte(enc.Ciphertext)
	if len(ct) > 10 {
		ct[len(ct)/2] ^= 0xFF
	}
	enc.Ciphertext = string(ct)
	_, err := DecryptSecretWithKey(enc, key)
	if err == nil {
		t.Error("decryption of tampered ciphertext should fail")
	}
}

func TestEncryptEmptyValue(t *testing.T) {
	key, _ := GenerateEncryptionKey()
	enc, err := EncryptSecretWithKey("", "k", key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptSecretWithKey(enc, key)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("empty plaintext round-trip: got %q", got)
	}
}

func TestEncryptLargeValue(t *testing.T) {
	key, _ := GenerateEncryptionKey()
	big := strings.Repeat("A", 100_000)
	enc, err := EncryptSecretWithKey(big, "k", key)
	if err != nil {
		t.Fatalf("encrypt large value: %v", err)
	}
	got, err := DecryptSecretWithKey(enc, key)
	if err != nil {
		t.Fatalf("decrypt large value: %v", err)
	}
	if got != big {
		t.Error("large value round-trip mismatch")
	}
}
