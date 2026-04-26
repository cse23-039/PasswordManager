package secrets

import (
	"crypto/rand"
	"fmt"
	"io"
	"password-manager/internal/audit"
	"password-manager/internal/auth"
	"password-manager/internal/models"
)

var cryptoRandRead = func(b []byte) (int, error) {
	return io.ReadFull(rand.Reader, b)
}

// SecretService provides a higher-level API for secret operations with audit logging
// Requirement 3.2: Password Management + Requirement 3.4: Audit Logging
type SecretService struct {
	manager *SecretManager
	logger  *audit.AuditLogger
}

// NewSecretService creates a secret service with audit logging
func NewSecretService(logger *audit.AuditLogger) *SecretService {
	return &SecretService{
		manager: NewSecretManager(),
		logger:  logger,
	}
}

// CreateSecret creates a new secret with permission check and audit logging
func (ss *SecretService) CreateSecret(name, username, password, url, notes, category string, tags []string, user *models.User) (*models.Secret, error) {
	if err := auth.CheckPermission(user, auth.CanCreateSecret); err != nil {
		if ss.logger != nil {
			ss.logger.Log(user.Username, audit.ActionSecretCreate, name, "permission denied", "denied")
		}
		return nil, err
	}

	secret, err := ss.manager.CreateSecret(name, username, password, url, notes, category, user.Username, tags)
	if err != nil {
		return nil, err
	}

	if ss.logger != nil {
		ss.logger.LogSecretAccess(user.Username, audit.ActionSecretCreate, secret.ID, secret.Name)
	}

	return secret, nil
}

// GetSecret retrieves a secret with permission check and audit logging
func (ss *SecretService) GetSecret(id string, user *models.User) (*models.Secret, error) {
	if err := auth.CheckPermission(user, auth.CanViewSecrets); err != nil {
		if ss.logger != nil {
			ss.logger.Log(user.Username, audit.ActionSecretRead, id, "permission denied", "denied")
		}
		return nil, err
	}

	secret, err := ss.manager.GetSecret(id)
	if err != nil {
		return nil, err
	}

	if ss.logger != nil {
		ss.logger.LogSecretAccess(user.Username, audit.ActionSecretRead, secret.ID, secret.Name)
	}

	return secret, nil
}

// UpdateSecret updates a secret with permission check and audit logging
func (ss *SecretService) UpdateSecret(id, name, username, password, url, notes, category string, user *models.User) (*models.Secret, error) {
	if err := auth.CheckPermission(user, auth.CanEditSecret); err != nil {
		if ss.logger != nil {
			ss.logger.Log(user.Username, audit.ActionSecretUpdate, id, "permission denied", "denied")
		}
		return nil, err
	}

	secret, err := ss.manager.UpdateSecret(id, name, username, password, url, notes, category, user.Username)
	if err != nil {
		return nil, err
	}

	if ss.logger != nil {
		ss.logger.LogSecretAccess(user.Username, audit.ActionSecretUpdate, secret.ID, secret.Name)
	}

	return secret, nil
}

// DeleteSecret deletes a secret with permission check and audit logging
func (ss *SecretService) DeleteSecret(id string, user *models.User) error {
	if err := auth.CheckPermission(user, auth.CanDeleteSecret); err != nil {
		if ss.logger != nil {
			ss.logger.Log(user.Username, audit.ActionSecretDelete, id, "permission denied", "denied")
		}
		return err
	}

	// Get secret name for audit log before deleting
	secret, err := ss.manager.GetSecret(id)
	if err != nil {
		return err
	}
	secretName := secret.Name

	if err := ss.manager.DeleteSecret(id); err != nil {
		return err
	}

	if ss.logger != nil {
		ss.logger.LogSecretAccess(user.Username, audit.ActionSecretDelete, id, secretName)
	}

	return nil
}

// ListSecrets lists all secrets with permission check
func (ss *SecretService) ListSecrets(user *models.User) ([]*models.Secret, error) {
	if err := auth.CheckPermission(user, auth.CanViewSecrets); err != nil {
		return nil, err
	}
	return ss.manager.ListSecrets(), nil
}

// SearchSecrets searches secrets with permission check
func (ss *SecretService) SearchSecrets(query string, user *models.User) ([]*models.Secret, error) {
	if err := auth.CheckPermission(user, auth.CanViewSecrets); err != nil {
		return nil, err
	}
	return ss.manager.SearchSecrets(query), nil
}

// GetSecretHistory returns password history with permission check
func (ss *SecretService) GetSecretHistory(id string, user *models.User) ([]models.SecretHistory, error) {
	if err := auth.CheckPermission(user, auth.CanViewSecrets); err != nil {
		return nil, err
	}

	return ss.manager.GetSecretHistory(id)
}

// GetManager returns the underlying secret manager
func (ss *SecretService) GetManager() *SecretManager {
	return ss.manager
}

// GeneratePassword generates a random password
func GeneratePassword(length int, useUppercase, useLowercase, useDigits, useSpecial bool) (string, error) {
	if length < 8 {
		return "", fmt.Errorf("password length must be at least 8")
	}

	charset := ""
	if useUppercase {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if useLowercase {
		charset += "abcdefghijklmnopqrstuvwxyz"
	}
	if useDigits {
		charset += "0123456789"
	}
	if useSpecial {
		charset += "!@#$%^&*()-_=+[]{}|;:',.<>?/"
	}

	if charset == "" {
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	}

	password := make([]byte, length)
	randBytes := make([]byte, length)
	if _, err := cryptoRandRead(randBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	for i := range password {
		password[i] = charset[int(randBytes[i])%len(charset)]
	}

	return string(password), nil
}
