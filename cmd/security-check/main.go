// security-check validates a vault file's integrity without unlocking it.
// Exit codes: 0 = OK, 1 = error/tampered, 2 = usage error.
//
// Usage:
//
//	security-check [-vault /path/to/vault.pwm]
package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// vaultMagicV2 matches the value in internal/vault/vault.go
const vaultMagicV2 = "\x89PWM\r\n\x1a\x02"

func main() {
	vaultPath := flag.String("vault", "", "Path to vault.pwm file (defaults to VAULT_PATH env var)")
	flag.Parse()

	path := *vaultPath
	if path == "" {
		path = os.Getenv("VAULT_PATH")
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "usage: security-check -vault /path/to/vault.pwm")
		os.Exit(2)
	}

	if err := checkVault(path); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK: vault file structure is valid")
}

func checkVault(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot stat vault file: %w", err)
	}
	if info.Size() == 0 {
		return errors.New("vault file is empty")
	}
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "WARN: vault file permissions are too permissive (%s); expected 0600\n", info.Mode())
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read vault file: %w", err)
	}

	if len(raw) < len(vaultMagicV2) {
		return errors.New("vault file too small to contain a valid header")
	}

	if string(raw[:len(vaultMagicV2)]) != vaultMagicV2 {
		return errors.New("vault file does not have the expected V2 magic header (may be legacy or corrupted)")
	}

	// Parse V2 format: magic + base64(salt)\n base64(nonce)\n base64(ciphertext)\n hex(hmac)\n
	tail := raw[len(vaultMagicV2):]
	parts := strings.SplitN(string(tail), "\n", 5)
	if len(parts) < 4 {
		return fmt.Errorf("vault V2 format corrupted: expected 4 sections, got %d", len(parts))
	}

	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("vault V2: invalid salt encoding: %w", err)
	}
	if len(salt) != 32 {
		return fmt.Errorf("vault V2: unexpected salt length %d (expected 32)", len(salt))
	}

	nonce, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("vault V2: invalid nonce encoding: %w", err)
	}
	if len(nonce) != 12 {
		return fmt.Errorf("vault V2: unexpected nonce length %d (expected 12)", len(nonce))
	}

	ct, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("vault V2: invalid ciphertext encoding: %w", err)
	}
	if len(ct) < 16 {
		return fmt.Errorf("vault V2: ciphertext too short (min 16 bytes for GCM tag)")
	}

	macHex := strings.TrimSpace(parts[3])
	if _, err := hex.DecodeString(macHex); err != nil {
		return fmt.Errorf("vault V2: invalid HMAC encoding: %w", err)
	}
	if len(macHex) != 64 {
		return fmt.Errorf("vault V2: unexpected HMAC hex length %d (expected 64)", len(macHex))
	}

	fmt.Printf("  magic:      V2\n")
	fmt.Printf("  salt:       %d bytes\n", len(salt))
	fmt.Printf("  nonce:      %d bytes\n", len(nonce))
	fmt.Printf("  ciphertext: %d bytes\n", len(ct))
	fmt.Printf("  hmac:       present (%d hex chars)\n", len(macHex))
	return nil
}
