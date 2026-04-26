package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"time"
)

// KeyManager handles encryption key lifecycle management
// Requirement 3.3: Encryption keys shall be securely managed and rotated
type KeyManager struct {
	mu          sync.RWMutex
	keys        map[string]*ManagedKey
	activeKeyID string
}

// ManagedKey represents an encryption key with metadata
type ManagedKey struct {
	ID        string
	Key       []byte
	CreatedAt time.Time
	RotatedAt time.Time
	ExpiresAt time.Time
	Version   int
	Active    bool
}

// NewKeyManager creates a new key manager
func NewKeyManager() *KeyManager {
	return &KeyManager{
		keys: make(map[string]*ManagedKey),
	}
}

// GenerateNewKey generates a new managed encryption key
func (km *KeyManager) GenerateNewKey() (*ManagedKey, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	key := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	now := time.Now()
	managed := &ManagedKey{
		ID:        base64.URLEncoding.EncodeToString(idBytes),
		Key:       key,
		CreatedAt: now,
		RotatedAt: now,
		ExpiresAt: now.Add(90 * 24 * time.Hour), // 90-day rotation
		Version:   1,
		Active:    true,
	}

	// Deactivate previous active key
	if km.activeKeyID != "" {
		if prevKey, ok := km.keys[km.activeKeyID]; ok {
			prevKey.Active = false
		}
	}

	km.keys[managed.ID] = managed
	km.activeKeyID = managed.ID

	return managed, nil
}

// GetActiveKey returns the current active encryption key
func (km *KeyManager) GetActiveKey() (*ManagedKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.activeKeyID == "" {
		return nil, fmt.Errorf("no active key")
	}

	key, ok := km.keys[km.activeKeyID]
	if !ok {
		return nil, fmt.Errorf("active key not found")
	}

	return key, nil
}

// GetKey retrieves a key by ID
func (km *KeyManager) GetKey(id string) (*ManagedKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	key, ok := km.keys[id]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", id)
	}

	return key, nil
}

// RotateKey creates a new key and deactivates the old one
func (km *KeyManager) RotateKey() (*ManagedKey, error) {
	newKey, err := km.GenerateNewKey()
	if err != nil {
		return nil, fmt.Errorf("failed to rotate key: %w", err)
	}
	return newKey, nil
}

// IsKeyExpired checks if a key needs rotation
func (km *KeyManager) IsKeyExpired(id string) (bool, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	key, ok := km.keys[id]
	if !ok {
		return false, fmt.Errorf("key not found: %s", id)
	}

	return time.Now().After(key.ExpiresAt), nil
}

// ClearKeys securely wipes all keys from memory
func (km *KeyManager) ClearKeys() {
	km.mu.Lock()
	defer km.mu.Unlock()

	for _, key := range km.keys {
		// Zero out the key bytes
		for i := range key.Key {
			key.Key[i] = 0
		}
	}
	km.keys = make(map[string]*ManagedKey)
	km.activeKeyID = ""
}
