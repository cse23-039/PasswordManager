package admin

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// PolicyPersistence handles saving/loading security policies to/from disk
type PolicyPersistence struct {
	mu       sync.RWMutex
	filePath string
}

// PersistedPolicy represents the policy data saved to disk
type PersistedPolicy struct {
	Policy  *SecurityPolicy `json:"policy"`
	SavedAt time.Time       `json:"saved_at"`
	Version int             `json:"version"`
}

// NewPolicyPersistence creates a new policy persistence handler
func NewPolicyPersistence(filePath string) *PolicyPersistence {
	return &PolicyPersistence{
		filePath: filePath,
	}
}

// SavePolicy saves the security policy to disk
func (pp *PolicyPersistence) SavePolicy(policy *SecurityPolicy) error {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	// Try to load existing to increment version
	version := 1
	existing, err := pp.loadInternal()
	if err == nil {
		version = existing.Version + 1
	}

	persisted := &PersistedPolicy{
		Policy:  policy,
		SavedAt: time.Now(),
		Version: version,
	}

	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	return os.WriteFile(pp.filePath, data, 0600)
}

// LoadPolicy loads the security policy from disk
func (pp *PolicyPersistence) LoadPolicy() (*SecurityPolicy, error) {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	persisted, err := pp.loadInternal()
	if err != nil {
		return nil, err
	}

	return persisted.Policy, nil
}

func (pp *PolicyPersistence) loadInternal() (*PersistedPolicy, error) {
	data, err := os.ReadFile(pp.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var persisted PersistedPolicy
	if err := json.Unmarshal(data, &persisted); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	return &persisted, nil
}

// PolicyExists checks if a persisted policy exists on disk
func (pp *PolicyPersistence) PolicyExists() bool {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	_, err := os.Stat(pp.filePath)
	return err == nil
}

// DeletePolicy removes the persisted policy file
func (pp *PolicyPersistence) DeletePolicy() error {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	return os.Remove(pp.filePath)
}

// GetPolicyVersion returns the current policy version number
func (pp *PolicyPersistence) GetPolicyVersion() (int, error) {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	persisted, err := pp.loadInternal()
	if err != nil {
		return 0, err
	}

	return persisted.Version, nil
}

// LoadOrDefault loads a persisted policy or returns the default
func (pp *PolicyPersistence) LoadOrDefault() *SecurityPolicy {
	policy, err := pp.LoadPolicy()
	if err != nil {
		return DefaultSecurityPolicy()
	}
	return policy
}
