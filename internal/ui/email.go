package ui

import (
	"fmt"
	"net/smtp"
	"strings"
)

// EmailConfig holds email notification configuration
type EmailConfig struct {
	SMTPHost    string `json:"smtp_host"`
	SMTPPort    int    `json:"smtp_port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	FromAddress string `json:"from_address"`
	UseTLS      bool   `json:"use_tls"`
	Enabled     bool   `json:"enabled"`
}

// DefaultEmailConfig returns the default (disabled) email configuration
func DefaultEmailConfig() *EmailConfig {
	return &EmailConfig{
		SMTPHost: "localhost",
		SMTPPort: 587,
		UseTLS:   true,
		Enabled:  false,
	}
}

// SendEmail sends an email notification
// This is a stub implementation - email notifications are optional
func SendEmail(config *EmailConfig, to, subject, body string) error {
	if !config.Enabled {
		return fmt.Errorf("email notifications are not enabled")
	}

	if config.SMTPHost == "" {
		return fmt.Errorf("SMTP host is not configured")
	}

	addr := fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort)
	auth := smtp.PlainAuth("", config.Username, config.Password, config.SMTPHost)

	msg := strings.Join([]string{
		fmt.Sprintf("From: %s", config.FromAddress),
		fmt.Sprintf("To: %s", to),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		body,
	}, "\r\n")

	return smtp.SendMail(addr, auth, config.FromAddress, []string{to}, []byte(msg))
}

// SendSecurityAlert sends a security alert email
func SendSecurityAlert(config *EmailConfig, to, alertType, details string) error {
	subject := fmt.Sprintf("[Security Alert] %s", alertType)
	body := fmt.Sprintf("Security Alert: %s\n\nDetails: %s\n\nThis is an automated notification from Password Manager.", alertType, details)
	return SendEmail(config, to, subject, body)
}

// SendLoginNotification sends a login notification email
func SendLoginNotification(config *EmailConfig, to, username, ipAddress string) error {
	subject := "New Login Detected"
	body := fmt.Sprintf("A new login was detected for account '%s'.\n\nIP Address: %s\n\nIf this was not you, please change your password immediately.", username, ipAddress)
	return SendEmail(config, to, subject, body)
}
