package ui

import (
	"fmt"
)

// SMSConfig holds SMS notification configuration
type SMSConfig struct {
	Provider   string `json:"provider"` // "twilio", "aws_sns", etc.
	AccountSID string `json:"account_sid"`
	AuthToken  string `json:"auth_token"`
	FromNumber string `json:"from_number"`
	Enabled    bool   `json:"enabled"`
}

// DefaultSMSConfig returns the default (disabled) SMS configuration
func DefaultSMSConfig() *SMSConfig {
	return &SMSConfig{
		Provider: "none",
		Enabled:  false,
	}
}

// SendSMS sends an SMS notification
// This is a stub implementation - SMS notifications are optional and require
// a provider integration (e.g., Twilio, AWS SNS)
func SendSMS(config *SMSConfig, to, message string) error {
	if !config.Enabled {
		return fmt.Errorf("SMS notifications are not enabled")
	}

	if config.Provider == "none" || config.Provider == "" {
		return fmt.Errorf("no SMS provider configured")
	}

	// Stub implementation - would integrate with actual provider
	// e.g., Twilio REST API, AWS SNS, etc.
	return fmt.Errorf("SMS provider '%s' integration not yet implemented", config.Provider)
}

// SendMFACode sends an MFA verification code via SMS
func SendMFACode(config *SMSConfig, to, code string) error {
	message := fmt.Sprintf("Your Password Manager verification code is: %s. This code expires in 5 minutes.", code)
	return SendSMS(config, to, message)
}

// SendSecurityAlertSMS sends a security alert via SMS
func SendSecurityAlertSMS(config *SMSConfig, to, alertType string) error {
	message := fmt.Sprintf("Password Manager Security Alert: %s. Please check your account.", alertType)
	return SendSMS(config, to, message)
}
