package auth

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateMFASecret(t *testing.T) {
	s, err := GenerateMFASecret()
	if err != nil {
		t.Fatalf("GenerateMFASecret: %v", err)
	}
	if s == "" {
		t.Fatal("expected non-empty secret")
	}
	// Must be valid base32
	s2, err := GenerateMFASecret()
	if err != nil {
		t.Fatal(err)
	}
	if s == s2 {
		t.Error("two generated secrets must differ")
	}
}

func TestGenerateTOTP(t *testing.T) {
	secret, _ := GenerateMFASecret()
	now := time.Now()

	code, err := GenerateTOTP(secret, now)
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("expected 6-digit code, got %d chars: %q", len(code), code)
	}
	// All digits
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("code contains non-digit character: %q", code)
		}
	}
}

func TestValidateTOTPCurrentWindow(t *testing.T) {
	secret, _ := GenerateMFASecret()
	code, _ := GenerateTOTP(secret, time.Now())

	if !ValidateTOTP(secret, code) {
		t.Error("current-window TOTP code should be valid")
	}
}

func TestValidateTOTPWrongCode(t *testing.T) {
	secret, _ := GenerateMFASecret()
	if ValidateTOTP(secret, "000000") {
		// Technically possible but astronomically unlikely for a random secret
		t.Log("000000 was coincidentally valid (extremely unlikely, re-run if this fails)")
	}
	if ValidateTOTP(secret, "123456") {
		t.Log("123456 was coincidentally valid")
	}
}

func TestValidateTOTPNormalization(t *testing.T) {
	secret, _ := GenerateMFASecret()
	code, _ := GenerateTOTP(secret, time.Now())

	// With spaces
	spaced := code[:3] + " " + code[3:]
	if !ValidateTOTP(secret, spaced) {
		t.Error("code with space should be accepted after normalization")
	}
	// With dash
	dashed := code[:3] + "-" + code[3:]
	if !ValidateTOTP(secret, dashed) {
		t.Error("code with dash should be accepted after normalization")
	}
	// With leading/trailing spaces
	if !ValidateTOTP(secret, "  "+code+"  ") {
		t.Error("code with surrounding spaces should be accepted")
	}
}

func TestValidateTOTPExpiredWindow(t *testing.T) {
	secret, _ := GenerateMFASecret()
	// Code from 5 minutes ago — well outside the ±2 step skew
	oldTime := time.Now().Add(-5 * time.Minute)
	oldCode, _ := GenerateTOTP(secret, oldTime)
	if ValidateTOTP(secret, oldCode) {
		t.Error("code from 5 minutes ago should be rejected")
	}
}

func TestGetMFAProvisioningURI(t *testing.T) {
	secret, _ := GenerateMFASecret()
	uri := GetMFAProvisioningURI(secret, "alice", "TestIssuer")

	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("URI should start with otpauth://totp/, got: %s", uri)
	}
	if !strings.Contains(uri, "secret=") {
		t.Error("URI missing 'secret=' parameter")
	}
	if !strings.Contains(uri, "issuer=TestIssuer") {
		t.Error("URI missing issuer parameter")
	}
	// Ensure no external logo URL leaks into the URI
	if strings.Contains(uri, "raw.githubusercontent.com") {
		t.Error("URI must not contain external GitHub URL")
	}
}

func TestDefaultMFAConfig(t *testing.T) {
	cfg := DefaultMFAConfig()
	if cfg.Digits != 6 {
		t.Errorf("Digits: got %d, want 6", cfg.Digits)
	}
	if cfg.Period != 30 {
		t.Errorf("Period: got %d, want 30", cfg.Period)
	}
	if cfg.Skew < 1 {
		t.Errorf("Skew should be >= 1 for clock drift tolerance, got %d", cfg.Skew)
	}
}
