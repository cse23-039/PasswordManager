package crypto

import (
	"crypto/tls"
	"fmt"
)

// TLSConfig provides secure TLS configuration settings
// Requirement 3.3: All communications shall be encrypted in transit using TLS 1.2 or higher

// NewTLSConfig creates a TLS configuration enforcing TLS 1.2+
func NewTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
	}
}

// ValidateTLSVersion checks that a TLS version is at least TLS 1.2
func ValidateTLSVersion(version uint16) error {
	if version < tls.VersionTLS12 {
		return fmt.Errorf("TLS version too low: minimum TLS 1.2 required")
	}
	return nil
}
