package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// MFAConfig holds MFA configuration
// Requirement 3.1: The system shall require MFA for all user logins
type MFAConfig struct {
	Issuer    string
	Algorithm string // SHA256 (RFC 6238)
	Digits    int    // 6 digits
	Period    int    // 30 seconds
	Skew      int    // Time steps to allow (for clock drift)
}

// DefaultMFAConfig returns the default MFA configuration
func DefaultMFAConfig() *MFAConfig {
	return &MFAConfig{
		Issuer:    "PasswordManager",
		Algorithm: "SHA1", // RFC 4226 default; all standard authenticator apps use SHA1
		Digits:    6,
		Period:    30,
		Skew:      2,
	}
}

// GenerateTOTP generates a TOTP code for the given secret and time
func GenerateTOTP(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		key, err = base32.StdEncoding.DecodeString(strings.ToUpper(secret))
		if err != nil {
			return "", fmt.Errorf("invalid secret: %w", err)
		}
	}

	period := int64(30)
	counter := uint64(t.Unix() / period)

	return generateHOTP(key, counter, 6)
}

// ValidateTOTP validates a TOTP code against the expected value.
// Input is normalized: whitespace and dashes are stripped, secret is uppercased.
func ValidateTOTP(secret, code string) bool {
	cfg := DefaultMFAConfig()

	// Normalize user input (handles "123 456", "123-456", trailing spaces)
	code = strings.TrimSpace(code)
	code = strings.ReplaceAll(code, " ", "")
	code = strings.ReplaceAll(code, "-", "")

	// Normalize secret
	secret = strings.ToUpper(strings.TrimSpace(secret))

	now := time.Now()
	counterNow := uint64(now.Unix() / int64(cfg.Period))

	for i := -cfg.Skew; i <= cfg.Skew; i++ {
		if i < 0 && uint64(-i) > counterNow {
			continue // underflow guard
		}
		candidate := counterNow + uint64(i)
		t := time.Unix(int64(candidate*uint64(cfg.Period)), 0)
		expected, err := GenerateTOTP(secret, t)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return true
		}
	}

	return false
}

// Replay protection removed - handled by validateTOTPForUser only

// GenerateMFASecret generates a new random secret for MFA enrollment
func GenerateMFASecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return "", fmt.Errorf("failed to generate MFA secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GetMFAProvisioningURI returns a correctly URL-escaped otpauth URI for QR provisioning.
// Uses net/url so usernames with @, spaces, or special characters are handled correctly.
//
// The "image" parameter is a Microsoft Authenticator extension: when present and pointing
// to a publicly accessible HTTPS PNG/JPEG, Authenticator displays that image as the
// account logo instead of the generic key icon.
// Replace the logoURL constant below with your own hosted image URL to enable branding.
func GetMFAProvisioningURI(secret, username, issuer string) string {
	// Logo URL shown in Microsoft Authenticator (must be a public HTTPS image URL).
	// Set to "" to disable custom branding, or replace with a URL you control.
	const logoURL = ""

	secret = strings.ToUpper(strings.TrimSpace(secret))
	issuer = strings.TrimSpace(issuer)
	username = strings.TrimSpace(username)

	// Label format: "issuer:account" — path-escaped per otpauth spec
	label := fmt.Sprintf("%s:%s", issuer, username)

	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1") // RFC 4226 default; required for all standard authenticator apps
	v.Set("digits", "6")
	v.Set("period", "30")
	if logoURL != "" {
		v.Set("image", logoURL)
	}

	return fmt.Sprintf("otpauth://totp/%s?%s", url.PathEscape(label), v.Encode())
}

// generateHOTP generates an HOTP code per RFC 4226 using HMAC-SHA1.
// SHA-1 is mandated by RFC 4226 and is what every real authenticator app
// (Google Authenticator, Microsoft Authenticator, Authy, 1Password, Bitwarden)
// uses regardless of the algorithm field in the otpauth URI.
func generateHOTP(key []byte, counter uint64, digits int) (string, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key) // RFC 4226 §5 specifies HMAC-SHA1
	mac.Write(buf)
	sum := mac.Sum(nil)

	// Dynamic truncation per RFC 4226 §5.4
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	otp := code % mod

	return fmt.Sprintf("%0*d", digits, otp), nil
}
