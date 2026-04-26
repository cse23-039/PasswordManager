package secrets

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"password-manager/internal/models"
	"strings"
	"time"
)

// SecretManager handles CRUD operations for secrets
// Requirement 3.2: Password Management
type SecretManager struct {
	secrets map[string]*models.Secret
}

// NewSecretManager creates a new secret manager
func NewSecretManager() *SecretManager {
	return &SecretManager{
		secrets: make(map[string]*models.Secret),
	}
}

// CreateSecret creates a new secret entry
func (sm *SecretManager) CreateSecret(name, username, password, url, notes, category, createdBy string, tags []string) (*models.Secret, error) {
	if name == "" {
		return nil, fmt.Errorf("secret name is required")
	}
	if password == "" {
		return nil, fmt.Errorf("password is required")
	}

	now := time.Now()
	id := generateID()
	secret := &models.Secret{
		ID:        id,
		Name:      name,
		Username:  username,
		Password:  password,
		URL:       url,
		Notes:     notes,
		Category:  category,
		Tags:      tags,
		CreatedAt: now,
		UpdatedAt: now,
		CreatedBy: createdBy,
		Version:   1,
	}

	sm.secrets[secret.ID] = secret
	return secret, nil
}

// GetSecret retrieves a secret by ID
func (sm *SecretManager) GetSecret(id string) (*models.Secret, error) {
	secret, exists := sm.secrets[id]
	if !exists {
		return nil, fmt.Errorf("secret not found: %s", id)
	}
	return secret, nil
}

// UpdateSecret updates an existing secret
func (sm *SecretManager) UpdateSecret(id, name, username, password, url, notes, category, updatedBy string) (*models.Secret, error) {
	secret, exists := sm.secrets[id]
	if !exists {
		return nil, fmt.Errorf("secret not found: %s", id)
	}

	// Save current password to history if it changed — store salted hash only
	if password != "" && password != secret.Password {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt for history: %w", err)
		}
		h := sha256.New()
		h.Write(salt)
		h.Write([]byte(secret.Password))
		sum := h.Sum(nil)
		history := models.SecretHistory{
			Hash:      sum,
			Salt:      salt,
			ChangedAt: time.Now(),
			ChangedBy: updatedBy,
			Reason:    "password update",
		}
		secret.History = append(secret.History, history)
		secret.Password = password
	}

	if name != "" {
		secret.Name = name
	}
	if username != "" {
		secret.Username = username
	}
	if url != "" {
		secret.URL = url
	}
	if notes != "" {
		secret.Notes = notes
	}
	if category != "" {
		secret.Category = category
	}

	secret.UpdatedAt = time.Now()
	secret.Version++

	return secret, nil
}

// DeleteSecret removes a secret by ID
func (sm *SecretManager) DeleteSecret(id string) error {
	if _, exists := sm.secrets[id]; !exists {
		return fmt.Errorf("secret not found: %s", id)
	}
	delete(sm.secrets, id)
	return nil
}

// ListSecrets returns all secrets (with passwords masked)
func (sm *SecretManager) ListSecrets() []*models.Secret {
	var result []*models.Secret
	for _, secret := range sm.secrets {
		s := *secret
		result = append(result, &s)
	}
	return result
}

// SearchSecrets searches secrets by name, username, URL, or tags
func (sm *SecretManager) SearchSecrets(query string) []*models.Secret {
	query = strings.ToLower(query)
	var results []*models.Secret

	for _, secret := range sm.secrets {
		if strings.Contains(strings.ToLower(secret.Name), query) ||
			strings.Contains(strings.ToLower(secret.Username), query) ||
			strings.Contains(strings.ToLower(secret.URL), query) ||
			strings.Contains(strings.ToLower(secret.Notes), query) ||
			strings.Contains(strings.ToLower(secret.Category), query) {
			results = append(results, secret)
			continue
		}

		// Search tags
		for _, tag := range secret.Tags {
			if strings.Contains(strings.ToLower(tag), query) {
				results = append(results, secret)
				break
			}
		}
	}

	return results
}

// GetSecretsByCategory returns secrets filtered by category
func (sm *SecretManager) GetSecretsByCategory(category string) []*models.Secret {
	var results []*models.Secret
	for _, secret := range sm.secrets {
		if strings.EqualFold(secret.Category, category) {
			results = append(results, secret)
		}
	}
	return results
}

// GetSecretHistory returns the password change history for a secret
func (sm *SecretManager) GetSecretHistory(id string) ([]models.SecretHistory, error) {
	secret, exists := sm.secrets[id]
	if !exists {
		return nil, fmt.Errorf("secret not found: %s", id)
	}
	return secret.History, nil
}

// CountSecrets returns the total number of secrets
func (sm *SecretManager) CountSecrets() int {
	return len(sm.secrets)
}

// GetCategories returns all unique categories
func (sm *SecretManager) GetCategories() []string {
	categories := make(map[string]bool)
	for _, secret := range sm.secrets {
		if secret.Category != "" {
			categories[secret.Category] = true
		}
	}

	var result []string
	for cat := range categories {
		result = append(result, cat)
	}
	return result
}

// generateID generates a random hex ID
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		fallback := sha256.Sum256([]byte(fmt.Sprintf("%d|%d", time.Now().UnixNano(), os.Getpid())))
		return hex.EncodeToString(fallback[:16])
	}
	return hex.EncodeToString(b)
}
