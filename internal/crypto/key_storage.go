package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// KeyStorage provides secure key persistence
// Requirement 3.3: Encryption keys shall not be stored in plaintext
type KeyStorage struct {
	mu       sync.RWMutex
	filePath string
}

// StoredKeyData represents encrypted key data on disk
type StoredKeyData struct {
	KeyID      string `json:"key_id"`
	Ciphertext string `json:"ciphertext"` // Encrypted key material
	Algorithm  string `json:"algorithm"`
	Version    int    `json:"version"`
}

// NewKeyStorage creates key storage at the specified path
func NewKeyStorage(basePath string) *KeyStorage {
	return &KeyStorage{
		filePath: filepath.Join(basePath, ".keys"),
	}
}

// SaveKey securely stores an encrypted key
func (ks *KeyStorage) SaveKey(keyData *StoredKeyData) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Ensure directory exists
	dir := filepath.Dir(ks.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create key storage directory: %w", err)
	}

	// Load existing keys
	keys, _ := ks.loadKeys()
	keys[keyData.KeyID] = keyData

	// Save
	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keys: %w", err)
	}

	if err := os.WriteFile(ks.filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write keys: %w", err)
	}

	return nil
}

// LoadKey retrieves a stored key by ID
func (ks *KeyStorage) LoadKey(keyID string) (*StoredKeyData, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	keys, err := ks.loadKeys()
	if err != nil {
		return nil, err
	}

	key, ok := keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	return key, nil
}

// DeleteKey removes a stored key
func (ks *KeyStorage) DeleteKey(keyID string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	keys, err := ks.loadKeys()
	if err != nil {
		return err
	}

	delete(keys, keyID)

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keys: %w", err)
	}

	return os.WriteFile(ks.filePath, data, 0600)
}

// loadKeys loads all keys from storage
func (ks *KeyStorage) loadKeys() (map[string]*StoredKeyData, error) {
	keys := make(map[string]*StoredKeyData)

	data, err := os.ReadFile(ks.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return keys, nil
		}
		return nil, fmt.Errorf("failed to read keys: %w", err)
	}

	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("failed to parse keys: %w", err)
	}

	return keys, nil
}
