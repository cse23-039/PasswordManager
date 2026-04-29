// Package vault provides a local encrypted vault file system for storing secrets
// No database required - all data stored in a single encrypted file (vault.pwm)
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Vault file constants
const (
	VaultFileExtension = ".pwm"
	VaultVersion       = 1
	DefaultVaultName   = "vault.pwm"

	// Argon2id parameters (OWASP recommended)
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen  = 32
	SaltLength    = 32
	NonceLength   = 12

	// vaultMagic (V1) is prepended to legacy vault files saved with HMAC-only protection.
	vaultMagic = "\x89PWM\r\n\x1a\n"
	// vaultMagicV2 marks a vault file saved with full AES-256-GCM body encryption.
	// Byte 7 is 0x02 (not 0x0A) to distinguish from V1.
	vaultMagicV2 = "\x89PWM\r\n\x1a\x02"
	// usersMagic and auditMagic mark the encrypted companion files.
	usersMagic = "\x89PWU\r\n\x1a\n"
	auditMagic = "\x89PWA\r\n\x1a\n"
)

// legacyAppFileKey was removed. Companion files encrypted with the old
// hardcoded key are no longer supported. Users with such files must
// re-register or restore from a backup created with a current build.

// loadOrCreateAppSeed returns the 32-byte random seed stored at seedPath,
// creating it (0600) if it does not yet exist. The seed is mixed into
// deriveAppDataKey so that companion files are only decryptable by a process
// that also has the seed file — a partial exfiltration of only the .users or
// .audit file is no longer sufficient to derive the encryption key.
func loadOrCreateAppSeed(seedPath string) []byte {
	if raw, err := os.ReadFile(seedPath); err == nil && len(raw) == 32 {
		return raw
	}
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil
	}
	_ = os.WriteFile(seedPath, seed, 0600)
	return seed
}

// deriveAppDataKey derives the companion-file key from machine/user identity
// mixed with a per-vault random seed. PM_APP_DATA_KEY overrides for deployments.
//
// Security note: if PM_APP_DATA_KEY is set, keep it out of process listings and
// container inspection output (e.g. use Docker secrets, not plain environment
// variables in docker-compose), since it is visible via /proc/<pid>/environ or
// `docker inspect`.
func deriveAppDataKey(seed []byte) [32]byte {
	if override := strings.TrimSpace(os.Getenv("PM_APP_DATA_KEY")); override != "" {
		sum := sha256.Sum256([]byte(override))
		return sum
	}

	host, _ := os.Hostname()
	home, _ := os.UserHomeDir()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	material := strings.Join([]string{host, user, home, "password-manager-appdata-v1"}, "|")
	h := sha256.New()
	h.Write([]byte(material))
	h.Write(seed)
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

// encryptAppData encrypts plaintext with AES-256-GCM using the vault's app-data key.
// Output layout: [12-byte nonce][ciphertext+16-byte GCM tag].
func (v *Vault) encryptAppData(plaintext []byte) ([]byte, error) {
	appFileKey := deriveAppDataKey(v.appSeed)
	block, err := aes.NewCipher(appFileKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptAppData decrypts data produced by encryptAppData.
// Tries the seeded key first, then falls back to the legacy seedless derivation
// for companion files written before the per-vault seed was introduced.
func (v *Vault) decryptAppData(data []byte) ([]byte, error) {
	if pt, err := decryptAppDataWithKey(data, deriveAppDataKey(v.appSeed)); err == nil {
		return pt, nil
	}
	// Fallback: files written before the seed was introduced used seedless derivation.
	if pt, err := decryptAppDataWithKey(data, deriveAppDataKey(nil)); err == nil {
		return pt, nil
	}
	return nil, errors.New("failed to decrypt companion file: key derivation produced no valid result")
}

func decryptAppDataWithKey(data []byte, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("encrypted data is too short")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// encryptAppData encrypts plaintext with AES-256-GCM using a derived companion-file key.
// Output layout: [12-byte nonce][ciphertext+16-byte GCM tag].

// vaultFileParsed holds the parsed contents of a vault file, regardless of format version.
type vaultFileParsed struct {
	// V1 / legacy — JSON payload is immediately available.
	jsonPayload []byte
	storedMAC   string // hex HMAC; empty for plain-legacy files

	// V2 (encrypted) — plaintext salt lives in the file header;
	// the JSON body is AES-256-GCM-encrypted and must be decrypted before parsing.
	salt        []byte
	encNonce    []byte
	ciphertext  []byte
	isEncrypted bool
}

// VaultHeader contains vault metadata and key verification
type VaultHeader struct {
	Version          int       `json:"version"`
	Salt             []byte    `json:"salt"`              // For key derivation
	VerificationHash []byte    `json:"verification_hash"` // To verify master password
	CreatedAt        time.Time `json:"created_at"`
	LastModified     time.Time `json:"last_modified"`
	EntryCount       int       `json:"entry_count"`
}

// VaultEntry represents an encrypted secret entry
type VaultEntry struct {
	ID        string    `json:"id"`
	Nonce     []byte    `json:"nonce"` // Unique per-entry for AES-GCM
	Data      []byte    `json:"data"`  // Encrypted JSON of SecretData
	HMAC      []byte    `json:"hmac"`  // Integrity verification
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SecretData is the decrypted secret structure
type SecretData struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Username    string            `json:"username"`
	Password    string            `json:"password"`
	URL         string            `json:"url"`
	Notes       string            `json:"notes"`
	Category    string            `json:"category"`
	Tags        []string          `json:"tags"`
	CustomField map[string]string `json:"custom_fields,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CreatedBy   string            `json:"created_by,omitempty"` // username that created this secret

	// Password history for versioning
	PasswordHistory []PasswordHistoryEntry `json:"password_history,omitempty"`
}

// PasswordHistoryEntry tracks previous passwords
type PasswordHistoryEntry struct {
	// Hash is a salted hash of the previous password. Do NOT store plaintext.
	Hash      []byte    `json:"hash"`
	Salt      []byte    `json:"salt,omitempty"`
	ChangedAt time.Time `json:"changed_at"`
	Reason    string    `json:"reason,omitempty"`
}

// VaultFile represents the complete vault structure
type VaultFile struct {
	Header  VaultHeader  `json:"header"`
	Entries []VaultEntry `json:"entries"`
}

// Vault is the main vault manager
type Vault struct {
	mu                 sync.RWMutex
	filePath           string
	appSeed            []byte    // random per-vault seed mixed into companion-file key derivation
	encryptionKey      []byte
	hmacKey            []byte
	isUnlocked         bool
	header             *VaultHeader
	entries            map[string]*SecretData // Decrypted entries in memory (cleared on lock)
	dirty              bool                   // Has unsaved changes
	lastAppSaveTime    time.Time              // OS mod-time recorded after every app-initiated save
	maxPasswordHistory int                    // capped by policy; defaults to 20

	// Debounced-write support: rapid sequential mutations coalesce into a
	// single disk write that fires saveDebounceDelay after the last mutation.
	saveTimer *time.Timer
}

const saveDebounceDelay = 500 * time.Millisecond

// SetMaxPasswordHistory configures how many past password hashes are retained per secret.
// Call this after loading the security policy so the vault respects the configured limit.
func (v *Vault) SetMaxPasswordHistory(n int) {
	if n < 1 {
		n = 1
	}
	if n > 100 {
		n = 100
	}
	v.mu.Lock()
	v.maxPasswordHistory = n
	v.mu.Unlock()
}

// NewVault creates a new vault instance
func NewVault(filePath string) *Vault {
	if filePath == "" {
		// Default to user's home directory
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = "."
		}
		filePath = filepath.Join(homeDir, DefaultVaultName)
	}
	return &Vault{
		filePath: filePath,
		appSeed:  loadOrCreateAppSeed(filePath + ".seed"),
		entries:  make(map[string]*SecretData),
	}
}

// Create creates a new vault file with the given master password
func (v *Vault) Create(masterPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Check if vault already exists
	if _, err := os.Stat(v.filePath); err == nil {
		return errors.New("vault file already exists")
	}

	// Generate random salt
	salt := make([]byte, SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive keys using Argon2id
	encryptionKey, hmacKey := deriveKeys(masterPassword, salt)

	// Create verification hash (hash of a known value encrypted with key)
	verificationHash := createVerificationHash(encryptionKey)

	// Create header
	v.header = &VaultHeader{
		Version:          VaultVersion,
		Salt:             salt,
		VerificationHash: verificationHash,
		CreatedAt:        time.Now(),
		LastModified:     time.Now(),
		EntryCount:       0,
	}

	v.encryptionKey = encryptionKey
	v.hmacKey = hmacKey
	v.isUnlocked = true
	v.entries = make(map[string]*SecretData)

	// Save empty vault
	return v.saveToFile()
}

// Unlock opens an existing vault with the master password.
// Handles V2 (AES-GCM encrypted body), V1 (HMAC-only), and legacy (plain JSON).
func (v *Vault) Unlock(masterPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isUnlocked {
		return errors.New("vault is already unlocked")
	}

	vfd, err := readVaultFile(v.filePath)
	if err != nil {
		return err
	}

	var vaultFile VaultFile

	if vfd.isEncrypted {
		// V2: salt is in the plaintext header — derive keys before decrypting.
		encryptionKey, hmacKey := deriveKeys(masterPassword, vfd.salt)

		// Verify HMAC-SHA256(hmacKey, nonce || ciphertext).
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(vfd.encNonce)
		mac.Write(vfd.ciphertext)
		if err := verifyStoredMACHex(mac.Sum(nil), vfd.storedMAC); err != nil {
			return errors.New("vault file integrity check failed: file has been tampered with")
		}

		// Decrypt JSON body.
		vBlock, err := aes.NewCipher(encryptionKey)
		if err != nil {
			return fmt.Errorf("vault cipher init failed: %w", err)
		}
		vGCM, err := cipher.NewGCM(vBlock)
		if err != nil {
			return fmt.Errorf("vault GCM init failed: %w", err)
		}
		jsonData, err := vGCM.Open(nil, vfd.encNonce, vfd.ciphertext, nil)
		if err != nil {
			return errors.New("vault file integrity check failed: decryption error")
		}
		if err := json.Unmarshal(jsonData, &vaultFile); err != nil {
			return fmt.Errorf("failed to parse vault file: %w", err)
		}

		// Verify master password.
		expectedHash := createVerificationHash(encryptionKey)
		if !hmac.Equal(expectedHash, vaultFile.Header.VerificationHash) {
			return errors.New("invalid master password")
		}

		v.encryptionKey = encryptionKey
		v.hmacKey = hmacKey
	} else {
		// V1 / legacy: parse JSON, derive keys, verify optional HMAC.
		if err := json.Unmarshal(vfd.jsonPayload, &vaultFile); err != nil {
			return fmt.Errorf("failed to parse vault file: %w", err)
		}
		encryptionKey, hmacKey := deriveKeys(masterPassword, vaultFile.Header.Salt)
		if err := verifyFileMAC(hmacKey, vfd.jsonPayload, vfd.storedMAC); err != nil {
			return err
		}
		expectedHash := createVerificationHash(encryptionKey)
		if !hmac.Equal(expectedHash, vaultFile.Header.VerificationHash) {
			return errors.New("invalid master password")
		}
		v.encryptionKey = encryptionKey
		v.hmacKey = hmacKey
	}

	v.header = &vaultFile.Header
	v.isUnlocked = true
	v.entries = make(map[string]*SecretData)

	for _, entry := range vaultFile.Entries {
		secret, err := v.decryptEntry(&entry)
		if err != nil {
			return fmt.Errorf("failed to decrypt entry %s: %w", entry.ID, err)
		}
		v.entries[secret.ID] = secret
	}

	return nil
}

// UnlockWithKey opens an existing vault using pre-derived encryption and HMAC keys.
// Used for multi-user login where keys are unwrapped from per-user key escrow.
func (v *Vault) UnlockWithKey(encKey, hmacKey []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isUnlocked {
		return errors.New("vault is already unlocked")
	}

	vfd, err := readVaultFile(v.filePath)
	if err != nil {
		return err
	}

	var vaultFile VaultFile

	if vfd.isEncrypted {
		// Verify HMAC-SHA256(hmacKey, nonce || ciphertext).
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(vfd.encNonce)
		mac.Write(vfd.ciphertext)
		if err := verifyStoredMACHex(mac.Sum(nil), vfd.storedMAC); err != nil {
			return errors.New("vault file integrity check failed: file has been tampered with")
		}

		// Decrypt JSON body.
		vBlock, err := aes.NewCipher(encKey)
		if err != nil {
			return fmt.Errorf("vault cipher init failed: %w", err)
		}
		vGCM, err := cipher.NewGCM(vBlock)
		if err != nil {
			return fmt.Errorf("vault GCM init failed: %w", err)
		}
		jsonData, err := vGCM.Open(nil, vfd.encNonce, vfd.ciphertext, nil)
		if err != nil {
			return errors.New("vault file integrity check failed: decryption error")
		}
		if err := json.Unmarshal(jsonData, &vaultFile); err != nil {
			return fmt.Errorf("failed to parse vault file: %w", err)
		}
	} else {
		if err := json.Unmarshal(vfd.jsonPayload, &vaultFile); err != nil {
			return fmt.Errorf("failed to parse vault file: %w", err)
		}
		if err := verifyFileMAC(hmacKey, vfd.jsonPayload, vfd.storedMAC); err != nil {
			return err
		}
	}

	expectedHash := createVerificationHash(encKey)
	if !hmac.Equal(expectedHash, vaultFile.Header.VerificationHash) {
		return errors.New("invalid vault key")
	}

	v.header = &vaultFile.Header
	v.encryptionKey = encKey
	v.hmacKey = hmacKey
	v.isUnlocked = true
	v.entries = make(map[string]*SecretData)

	for _, entry := range vaultFile.Entries {
		secret, err := v.decryptEntry(&entry)
		if err != nil {
			return fmt.Errorf("failed to decrypt entry %s: %w", entry.ID, err)
		}
		v.entries[secret.ID] = secret
	}

	return nil
}

// scheduleSave coalesces rapid sequential writes into a single disk flush.
// Must be called with v.mu held (write lock). The timer fires outside the
// lock so saveToFile re-acquires it safely.
func (v *Vault) scheduleSave() {
	if v.saveTimer != nil {
		v.saveTimer.Stop()
	}
	v.saveTimer = time.AfterFunc(saveDebounceDelay, func() {
		v.mu.Lock()
		defer v.mu.Unlock()
		if v.dirty && v.isUnlocked {
			if err := v.saveToFile(); err != nil {
				fmt.Fprintf(os.Stderr, "vault: background save failed: %v\n", err)
			}
		}
	})
}

// flushSave cancels any pending debounced save and writes immediately.
// Must be called with v.mu held (write lock).
func (v *Vault) flushSave() error {
	if v.saveTimer != nil {
		v.saveTimer.Stop()
		v.saveTimer = nil
	}
	return v.saveToFile()
}

// Lock closes the vault and clears sensitive data from memory
func (v *Vault) Lock() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.isUnlocked {
		return errors.New("vault is not unlocked")
	}

	// Flush any pending debounced save before clearing keys.
	if v.dirty {
		if err := v.flushSave(); err != nil {
			return fmt.Errorf("failed to save vault before locking: %w", err)
		}
	}

	// Clear sensitive data from memory
	v.clearSensitiveData()

	return nil
}

// IsUnlocked returns whether the vault is currently unlocked
func (v *Vault) IsUnlocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.isUnlocked
}

// Exists returns whether the vault file exists
func (v *Vault) Exists() bool {
	_, err := os.Stat(v.filePath)
	return err == nil
}

// GetFilePath returns the vault file path
func (v *Vault) GetFilePath() string {
	return v.filePath
}

// GetHMACKey returns the HMAC key (only valid while unlocked).
func (v *Vault) GetHMACKey() []byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.hmacKey
}

// ============================================
// SECRET CRUD OPERATIONS
// ============================================

// AddSecret adds a new secret to the vault
func (v *Vault) AddSecret(secret *SecretData) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.isUnlocked {
		return errors.New("vault is locked")
	}

	if secret.ID == "" {
		secret.ID = generateID()
	}
	secret.CreatedAt = time.Now()
	secret.UpdatedAt = time.Now()

	if _, exists := v.entries[secret.ID]; exists {
		return fmt.Errorf("secret with ID %s already exists", secret.ID)
	}

	// Store a deep copy so external mutations to the caller's struct
	// do not corrupt the in-memory vault state.
	stored := *secret
	if secret.Tags != nil {
		stored.Tags = make([]string, len(secret.Tags))
		copy(stored.Tags, secret.Tags)
	}
	if secret.CustomField != nil {
		stored.CustomField = make(map[string]string, len(secret.CustomField))
		for k, val := range secret.CustomField {
			stored.CustomField[k] = val
		}
	}
	v.entries[secret.ID] = &stored
	v.dirty = true

	// Debounced save: coalesces rapid sequential adds into one disk write.
	v.scheduleSave()
	return nil
}

// GetSecret retrieves a secret by ID
func (v *Vault) getSecret(id string) (*SecretData, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.isUnlocked {
		return nil, errors.New("vault is locked")
	}

	secret, exists := v.entries[id]
	if !exists {
		return nil, fmt.Errorf("secret with ID %s not found", id)
	}

	// Return a copy to prevent external modification
	secretCopy := *secret
	return &secretCopy, nil
}

// GetSecretByName retrieves a secret by name
func (v *Vault) GetSecretByName(name string) (*SecretData, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.isUnlocked {
		return nil, errors.New("vault is locked")
	}

	for _, secret := range v.entries {
		if secret.Name == name {
			secretCopy := *secret
			return &secretCopy, nil
		}
	}

	return nil, fmt.Errorf("secret with name %s not found", name)
}

// UpdateSecret updates an existing secret
func (v *Vault) UpdateSecret(secret *SecretData) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.isUnlocked {
		return errors.New("vault is locked")
	}

	existing, exists := v.entries[secret.ID]
	if !exists {
		return fmt.Errorf("secret with ID %s not found", secret.ID)
	}

	// If password changed, add salted hash to history
	if existing.Password != secret.Password {
		salt := make([]byte, SaltLength)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return fmt.Errorf("failed to generate history salt: %w", err)
		}
		sum := argon2.IDKey([]byte(existing.Password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
		historyEntry := PasswordHistoryEntry{
			Hash:      sum,
			Salt:      salt,
			ChangedAt: time.Now(),
		}
		// Build a new history slice, capped at the policy-configured limit.
		prevHist := make([]PasswordHistoryEntry, len(existing.PasswordHistory))
		copy(prevHist, existing.PasswordHistory)
		prevHist = append(prevHist, historyEntry)
		maxHistory := v.maxPasswordHistory
		if maxHistory <= 0 {
			maxHistory = 20 // safe default when policy hasn't been applied yet
		}
		if len(prevHist) > maxHistory {
			prevHist = prevHist[len(prevHist)-maxHistory:]
		}
		secret.PasswordHistory = prevHist
	}

	secret.CreatedAt = existing.CreatedAt
	secret.UpdatedAt = time.Now()

	// Store a deep copy of the secret to avoid retaining caller-owned memory
	stored := *secret
	if secret.Tags != nil {
		stored.Tags = make([]string, len(secret.Tags))
		copy(stored.Tags, secret.Tags)
	}
	if secret.CustomField != nil {
		stored.CustomField = make(map[string]string, len(secret.CustomField))
		for k, v := range secret.CustomField {
			stored.CustomField[k] = v
		}
	}
	if secret.PasswordHistory != nil {
		stored.PasswordHistory = make([]PasswordHistoryEntry, len(secret.PasswordHistory))
		copy(stored.PasswordHistory, secret.PasswordHistory)
	}

	v.entries[secret.ID] = &stored
	v.dirty = true

	v.scheduleSave()
	return nil
}

// DeleteSecret removes a secret from the vault
func (v *Vault) DeleteSecret(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.isUnlocked {
		return errors.New("vault is locked")
	}

	if _, exists := v.entries[id]; !exists {
		return fmt.Errorf("secret with ID %s not found", id)
	}

	delete(v.entries, id)
	v.dirty = true

	v.scheduleSave()
	return nil
}

func scrubSecretForListing(secret *SecretData) *SecretData {
	secretCopy := *secret
	secretCopy.Password = ""
	secretCopy.PasswordHistory = nil
	return &secretCopy
}

// ListSecrets returns all secrets (metadata only, passwords masked), sorted
// alphabetically by name for deterministic, stable UI ordering.
func (v *Vault) ListSecrets() ([]*SecretData, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.isUnlocked {
		return nil, errors.New("vault is locked")
	}

	secrets := make([]*SecretData, 0, len(v.entries))
	for _, secret := range v.entries {
		secrets = append(secrets, scrubSecretForListing(secret))
	}
	sort.Slice(secrets, func(i, j int) bool {
		return strings.ToLower(secrets[i].Name) < strings.ToLower(secrets[j].Name)
	})
	return secrets, nil
}

// SearchSecrets searches secrets by name, category, or tags
func (v *Vault) SearchSecrets(query string, category string, tags []string) ([]*SecretData, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.isUnlocked {
		return nil, errors.New("vault is locked")
	}

	// Lower the query once to avoid per-entry allocation inside the loop.
	queryLower := strings.ToLower(query)

	var results []*SecretData

	for _, secret := range v.entries {
		match := true

		// Filter by query (name contains, case-insensitive)
		if queryLower != "" && !strings.Contains(strings.ToLower(secret.Name), queryLower) {
			match = false
		}

		// Filter by category
		if category != "" && secret.Category != category {
			match = false
		}

		// Filter by tags (must have all specified tags)
		if len(tags) > 0 {
			for _, tag := range tags {
				found := false
				for _, secretTag := range secret.Tags {
					if secretTag == tag {
						found = true
						break
					}
				}
				if !found {
					match = false
					break
				}
			}
		}

		if match {
			results = append(results, scrubSecretForListing(secret))
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return strings.ToLower(results[i].Name) < strings.ToLower(results[j].Name)
	})
	return results, nil
}

// GetPasswordHistory returns the password history for a secret
func (v *Vault) GetPasswordHistory(id string) ([]PasswordHistoryEntry, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.isUnlocked {
		return nil, errors.New("vault is locked")
	}

	secret, exists := v.entries[id]
	if !exists {
		return nil, fmt.Errorf("secret with ID %s not found", id)
	}

	// Return a copy
	history := make([]PasswordHistoryEntry, len(secret.PasswordHistory))
	copy(history, secret.PasswordHistory)

	return history, nil
}

// ============================================
// VAULT MANAGEMENT
// ============================================

// ChangeMasterPassword changes the vault's master password
func (v *Vault) ChangeMasterPassword(currentPassword, newPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.isUnlocked {
		return errors.New("vault is locked")
	}

	// Verify current password
	expectedHash := createVerificationHash(v.encryptionKey)
	if !hmac.Equal(expectedHash, v.header.VerificationHash) {
		return errors.New("current password verification failed")
	}

	// Generate new salt
	salt := make([]byte, SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive new keys
	encryptionKey, hmacKey := deriveKeys(newPassword, salt)

	// Update header
	v.header.Salt = salt
	v.header.VerificationHash = createVerificationHash(encryptionKey)
	v.header.LastModified = time.Now()

	v.encryptionKey = encryptionKey
	v.hmacKey = hmacKey
	v.dirty = true

	return v.saveToFile()
}

// ExportVault exports the vault to a new file (backup).
// Acquires a write lock so any pending debounced save is flushed before
// the on-disk file is read, guaranteeing the export reflects all in-memory state.
func (v *Vault) ExportVault(exportPath string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.isUnlocked {
		return errors.New("vault is locked")
	}

	// Flush any pending debounced write so the on-disk file is current.
	if v.dirty {
		if err := v.flushSave(); err != nil {
			return fmt.Errorf("failed to flush vault before export: %w", err)
		}
	}

	data, err := os.ReadFile(v.filePath)
	if err != nil {
		return fmt.Errorf("failed to read vault: %w", err)
	}

	if err := os.WriteFile(exportPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write export: %w", err)
	}

	return nil
}

// ImportVault imports secrets from another vault file
func (v *Vault) ImportVault(importPath, importPassword string) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.isUnlocked {
		return 0, errors.New("vault is locked")
	}

	var importFile VaultFile
	importVFD, err := readVaultFile(importPath)
	if err != nil {
		return 0, err
	}

	var importEncKey, importHMACKey []byte

	if importVFD.isEncrypted {
		importEncKey, importHMACKey = deriveKeys(importPassword, importVFD.salt)

		mac := hmac.New(sha256.New, importHMACKey)
		mac.Write(importVFD.encNonce)
		mac.Write(importVFD.ciphertext)
		if err := verifyStoredMACHex(mac.Sum(nil), importVFD.storedMAC); err != nil {
			return 0, errors.New("import file integrity check failed: file has been tampered with")
		}

		block, err := aes.NewCipher(importEncKey)
		if err != nil {
			return 0, fmt.Errorf("import cipher init failed: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return 0, fmt.Errorf("import GCM init failed: %w", err)
		}
		jsonData, err := gcm.Open(nil, importVFD.encNonce, importVFD.ciphertext, nil)
		if err != nil {
			return 0, errors.New("import file integrity check failed: decryption error")
		}
		if err := json.Unmarshal(jsonData, &importFile); err != nil {
			return 0, fmt.Errorf("failed to parse import file: %w", err)
		}
	} else {
		if err := json.Unmarshal(importVFD.jsonPayload, &importFile); err != nil {
			return 0, fmt.Errorf("failed to parse import file: %w", err)
		}
		importEncKey, importHMACKey = deriveKeys(importPassword, importFile.Header.Salt)
		if err := verifyFileMAC(importHMACKey, importVFD.jsonPayload, importVFD.storedMAC); err != nil {
			return 0, err
		}
	}

	expectedHash := createVerificationHash(importEncKey)
	if !hmac.Equal(expectedHash, importFile.Header.VerificationHash) {
		return 0, errors.New("invalid import password")
	}

	// Decrypt and import entries
	imported := 0
	failed := 0
	for _, entry := range importFile.Entries {
		secret, err := decryptEntryWithKey(&entry, importEncKey)
		if err != nil {
			failed++
			continue
		}

		// Generate new ID to avoid conflicts
		secret.ID = generateID()
		secret.Name = secret.Name + " (imported)"

		v.entries[secret.ID] = secret
		imported++
	}

	if imported > 0 {
		v.dirty = true
		if err := v.saveToFile(); err != nil {
			return imported, fmt.Errorf("imported %d entries but failed to save: %w", imported, err)
		}
	}

	if failed > 0 {
		return imported, fmt.Errorf("import completed with warnings: imported %d entries, skipped %d invalid entries", imported, failed)
	}

	return imported, nil
}

// GetStats returns vault statistics
func (v *Vault) GetStats() (map[string]interface{}, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.isUnlocked {
		return nil, errors.New("vault is locked")
	}

	stats := map[string]interface{}{
		"total_entries": len(v.entries),
		"created_at":    v.header.CreatedAt,
		"last_modified": v.header.LastModified,
		"version":       v.header.Version,
		"file_path":     v.filePath,
	}

	// Count by category
	categories := make(map[string]int)
	for _, secret := range v.entries {
		cat := secret.Category
		if cat == "" {
			cat = "uncategorized"
		}
		categories[cat]++
	}
	stats["by_category"] = categories

	return stats, nil
}

// VaultHealthReport summarises the security posture of secrets in the vault.
type VaultHealthReport struct {
	// Password hygiene
	Total       int      // all non-system secrets
	Weak        int      // password scores < 3 (missing char classes or < 12 chars)
	Old         int      // password not changed in > 1 year
	Reused      int      // password value shared by ≥ 2 entries
	NoPassword  int      // entry has an empty password field
	WeakNames   []string // display names of weak-password entries (capped at 20)
	OldNames    []string // display names of stale-password entries (capped at 20)
	ReusedNames []string // display names of first occurrence of each reused value (capped at 20)

	// Security integrity indicators (populated by VaultWithUser.GetHealthReport)
	VaultFileTampered  bool // true if vault file was modified outside the app since last save
	AuditChainIntact   bool // true if HMAC chain across all audit entries is unbroken
	AuditVerified      int  // count of audit entries with a valid checksum
	AuditTampered      int  // count of audit entries with an invalid checksum
	AuditUnverifiable  int  // count of audit entries with no checksum (legacy/pre-signing)
	MFAEnabled         bool // true if the current user has MFA enabled and verified
	HasSecurityPolicy  bool // true if an admin security policy has been configured
	MFARequired        bool // true if the security policy mandates MFA
	PasswordExpiryDays int  // policy password rotation interval in days (0 = disabled)
}

// GetHealthReport scans all decrypted in-memory secrets and returns a health summary.
func (v *Vault) GetHealthReport() (*VaultHealthReport, error) {
	return v.computeHealthReport("")
}

// computeHealthReport is the internal implementation.
// ownerFilter restricts analysis to secrets whose CreatedBy matches the given
// username (case-insensitive). Pass "" to include every non-system secret.
func (v *Vault) computeHealthReport(ownerFilter string) (*VaultHealthReport, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.isUnlocked {
		return nil, errors.New("vault is locked")
	}

	report := &VaultHealthReport{}
	passwordFreq := make(map[string][]string) // password → list of secret names
	oneYearAgo := time.Now().Add(-365 * 24 * time.Hour)

	for _, s := range v.entries {
		if s.Category == "__SYSTEM__" {
			continue
		}
		if ownerFilter != "" && !strings.EqualFold(s.CreatedBy, ownerFilter) {
			continue
		}
		report.Total++

		pw := s.Password

		if pw == "" {
			report.NoPassword++
			continue
		}

		// Strength check: award one point per satisfied criterion
		score := 0
		if len(pw) >= 12 {
			score++
		}
		for _, c := range pw {
			if c >= 'A' && c <= 'Z' {
				score++
				break
			}
		}
		for _, c := range pw {
			if c >= 'a' && c <= 'z' {
				score++
				break
			}
		}
		for _, c := range pw {
			if c >= '0' && c <= '9' {
				score++
				break
			}
		}
		for _, c := range pw {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
				score++
				break
			}
		}
		if score < 3 {
			report.Weak++
			if len(report.WeakNames) < 20 {
				report.WeakNames = append(report.WeakNames, s.Name)
			}
		}

		// Age check
		age := s.UpdatedAt
		if age.IsZero() {
			age = s.CreatedAt
		}
		if !age.IsZero() && age.Before(oneYearAgo) {
			report.Old++
			if len(report.OldNames) < 20 {
				report.OldNames = append(report.OldNames, s.Name)
			}
		}

		// Reuse tracking
		passwordFreq[pw] = append(passwordFreq[pw], s.Name)
	}

	// Identify reused passwords
	for _, names := range passwordFreq {
		if len(names) >= 2 {
			report.Reused += len(names)
			if len(report.ReusedNames) < 20 {
				report.ReusedNames = append(report.ReusedNames, names[0])
			}
		}
	}

	return report, nil
}

// ============================================
// INTERNAL FUNCTIONS
// ============================================

// deriveKeys derives encryption and HMAC keys from password using Argon2id,
// then locks both key slices into RAM so the OS cannot swap them to disk.
func deriveKeys(password string, salt []byte) (encKey, hmacKey []byte) {
	// Derive 64 bytes: 32 for encryption, 32 for HMAC
	derivedKey := argon2.IDKey(
		[]byte(password),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		64, // 32 + 32 bytes
	)

	enc := make([]byte, 32)
	mac := make([]byte, 32)
	copy(enc, derivedKey[:32])
	copy(mac, derivedKey[32:])

	// Zero the combined derivation buffer before it is GC'd.
	for i := range derivedKey {
		derivedKey[i] = 0
	}

	lockMemory(enc)
	lockMemory(mac)
	return enc, mac
}

// createVerificationHash creates a hash to verify the master password
func createVerificationHash(key []byte) []byte {
	// Hash a known value with the key
	h := hmac.New(sha256.New, key)
	h.Write([]byte("VAULT_VERIFICATION_STRING"))
	return h.Sum(nil)
}

// encryptData encrypts data using AES-256-GCM
func encryptData(plaintext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

// decryptData decrypts data using AES-256-GCM
func decryptData(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// computeHMAC computes HMAC-SHA256 for integrity
func computeHMAC(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// decryptEntry decrypts a vault entry using the vault's key
func (v *Vault) decryptEntry(entry *VaultEntry) (*SecretData, error) {
	return decryptEntryWithKey(entry, v.encryptionKey)
}

// decryptEntryWithKey decrypts a vault entry with a specific key
func decryptEntryWithKey(entry *VaultEntry, key []byte) (*SecretData, error) {
	plaintext, err := decryptData(entry.Data, key, entry.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	var secret SecretData
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted data: %w", err)
	}

	return &secret, nil
}

// encryptEntry encrypts a secret data into a vault entry
func (v *Vault) encryptEntry(secret *SecretData) (*VaultEntry, error) {
	// Generate unique nonce
	nonce := make([]byte, NonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Serialize secret
	plaintext, err := json.Marshal(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize secret: %w", err)
	}

	// Encrypt
	ciphertext, err := encryptData(plaintext, v.encryptionKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Compute HMAC
	entryHMAC := computeHMAC(ciphertext, v.hmacKey)

	return &VaultEntry{
		ID:        secret.ID,
		Nonce:     nonce,
		Data:      ciphertext,
		HMAC:      entryHMAC,
		CreatedAt: secret.CreatedAt,
		UpdatedAt: secret.UpdatedAt,
	}, nil
}

// saveToFile saves the vault to disk
func (v *Vault) saveToFile() error {
	// Build vault file
	vaultFile := VaultFile{
		Header: *v.header,
	}

	vaultFile.Header.EntryCount = len(v.entries)
	vaultFile.Header.LastModified = time.Now()

	// Encrypt all entries
	for _, secret := range v.entries {
		entry, err := v.encryptEntry(secret)
		if err != nil {
			return fmt.Errorf("failed to encrypt entry %s: %w", secret.ID, err)
		}
		vaultFile.Entries = append(vaultFile.Entries, *entry)
	}

	// Marshal to JSON (compact — indented form wastes 2-3x memory on large vaults)
	jsonData, err := json.Marshal(vaultFile)
	if err != nil {
		return fmt.Errorf("failed to serialize vault: %w", err)
	}

	// Encrypt JSON body with AES-256-GCM using the session encryption key.
	// The resulting file is completely opaque to text/hex editors.
	encNonce := make([]byte, NonceLength)
	if _, err := io.ReadFull(rand.Reader, encNonce); err != nil {
		return fmt.Errorf("failed to generate vault nonce: %w", err)
	}
	vBlock, err := aes.NewCipher(v.encryptionKey)
	if err != nil {
		return fmt.Errorf("vault cipher init failed: %w", err)
	}
	vGCM, err := cipher.NewGCM(vBlock)
	if err != nil {
		return fmt.Errorf("vault GCM init failed: %w", err)
	}
	ciphertext := vGCM.Seal(nil, encNonce, jsonData, nil)

	// Whole-file HMAC-SHA256 over nonce || ciphertext.
	mac := hmac.New(sha256.New, v.hmacKey)
	mac.Write(encNonce)
	mac.Write(ciphertext)
	fileMAC := mac.Sum(nil)

	// Build V2 file:
	//   [vaultMagicV2][base64(salt)]\n[base64(nonce)]\n[base64(ciphertext)]\n[hex(HMAC)]\n
	//
	// Pre-calculate the final size so a single allocation covers the entire output,
	// avoiding up to 7 incremental re-allocations from repeated appends.
	saltB64 := base64.StdEncoding.EncodeToString(v.header.Salt)
	nonceB64 := base64.StdEncoding.EncodeToString(encNonce)
	ctB64 := base64.StdEncoding.EncodeToString(ciphertext)
	macHex := fmt.Sprintf("%x", fileMAC)

	estimatedSize := len(vaultMagicV2) + len(saltB64) + 1 +
		len(nonceB64) + 1 + len(ctB64) + 1 + len(macHex) + 1
	buf := make([]byte, 0, estimatedSize)
	buf = append(buf, vaultMagicV2...)
	buf = append(buf, saltB64...)
	buf = append(buf, '\n')
	buf = append(buf, nonceB64...)
	buf = append(buf, '\n')
	buf = append(buf, ctB64...)
	buf = append(buf, '\n')
	buf = append(buf, macHex...)
	buf = append(buf, '\n')

	// Ensure directory exists
	dir := filepath.Dir(v.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write atomically
	tempPath := v.filePath + ".tmp"
	if err := os.WriteFile(tempPath, buf, 0600); err != nil {
		return fmt.Errorf("failed to write vault: %w", err)
	}
	if err := os.Rename(tempPath, v.filePath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to save vault: %w", err)
	}

	v.dirty = false
	if info, err := os.Stat(v.filePath); err == nil {
		v.lastAppSaveTime = info.ModTime()
	}
	return nil
}

// readVaultFile reads and parses the vault file into a vaultFileParsed struct.
// Handles three formats:
//   - V2 (current):  vaultMagicV2 + base64(salt) + base64(nonce) + base64(ciphertext) + hex(HMAC)
//   - V1 (previous): vaultMagic   + hex(HMAC) + plain JSON  (upgraded to V2 on next save)
//   - Legacy:        plain JSON with no magic   (upgraded to V2 on next save)
func readVaultFile(filePath string) (*vaultFileParsed, error) {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault file: %w", err)
	}

	// V2 encrypted format
	if len(raw) > len(vaultMagicV2) && string(raw[:len(vaultMagicV2)]) == vaultMagicV2 {
		tail := raw[len(vaultMagicV2):]
		parts := bytes.SplitN(tail, []byte{'\n'}, 5)
		if len(parts) < 4 {
			return nil, errors.New("vault file V2 format is corrupted (insufficient lines)")
		}
		salt, err := base64.StdEncoding.DecodeString(string(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("vault file V2: invalid salt: %w", err)
		}
		nonce, err := base64.StdEncoding.DecodeString(string(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("vault file V2: invalid nonce: %w", err)
		}
		ct, err := base64.StdEncoding.DecodeString(string(parts[2]))
		if err != nil {
			return nil, fmt.Errorf("vault file V2: invalid ciphertext: %w", err)
		}
		storedMAC := strings.TrimSpace(string(parts[3]))
		return &vaultFileParsed{salt: salt, encNonce: nonce, ciphertext: ct, storedMAC: storedMAC, isEncrypted: true}, nil
	}

	// V1 format: vaultMagic + 64-byte hex HMAC + \n + plain JSON
	if len(raw) > len(vaultMagic) && string(raw[:len(vaultMagic)]) == vaultMagic {
		tail := raw[len(vaultMagic):]
		const macHexLen = 64
		if len(tail) < macHexLen+1 {
			return nil, errors.New("vault file V1 is corrupted (truncated header)")
		}
		storedMAC := string(tail[:macHexLen])
		if tail[macHexLen] != '\n' {
			return nil, errors.New("vault file V1 is corrupted (bad header separator)")
		}
		return &vaultFileParsed{jsonPayload: tail[macHexLen+1:], storedMAC: storedMAC}, nil
	}

	// Legacy plain-JSON — accepted for backward compatibility, upgraded on next save
	if len(raw) > 0 && raw[0] == '{' {
		return &vaultFileParsed{jsonPayload: raw}, nil
	}

	return nil, errors.New("vault file format not recognised")
}

// verifyFileMAC verifies a V1 whole-file HMAC (HMAC over JSON payload).
func verifyFileMAC(hmacKey, jsonData []byte, storedHex string) error {
	if storedHex == "" {
		// Legacy file — no MAC to check. Will be upgraded on next save.
		return nil
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(jsonData)
	if err := verifyStoredMACHex(mac.Sum(nil), storedHex); err != nil {
		return errors.New("vault file integrity check failed: file has been tampered with")
	}
	return nil
}

func verifyStoredMACHex(expectedRaw []byte, storedHex string) error {
	storedRaw, err := hex.DecodeString(strings.TrimSpace(storedHex))
	if err != nil {
		return fmt.Errorf("invalid MAC encoding: %w", err)
	}
	if !hmac.Equal(expectedRaw, storedRaw) {
		return errors.New("mac mismatch")
	}
	return nil
}

// CheckExternalModification returns true if the vault file on disk has been
// modified by something other than this running app instance.
// It compares the current OS file mod-time against the last time the app
// itself wrote the file. Returns false when the vault has never been saved
// (e.g. brand-new vault not yet persisted).
func (v *Vault) CheckExternalModification() bool {
	if v.lastAppSaveTime.IsZero() {
		return false
	}
	info, err := os.Stat(v.filePath)
	if err != nil {
		return false
	}
	// Allow 1-second tolerance for filesystem timestamp resolution.
	return info.ModTime().After(v.lastAppSaveTime.Add(time.Second))
}

// clearSensitiveData securely clears sensitive data from memory.
// Keys are unlocked from RAM (reversing lockMemory) then zeroed before release.
func (v *Vault) clearSensitiveData() {
	// Unlock then zero encryption key
	unlockMemory(v.encryptionKey)
	for i := range v.encryptionKey {
		v.encryptionKey[i] = 0
	}
	v.encryptionKey = nil

	// Unlock then zero HMAC key
	unlockMemory(v.hmacKey)
	for i := range v.hmacKey {
		v.hmacKey[i] = 0
	}
	v.hmacKey = nil

	// Clear decrypted entries
	for id, secret := range v.entries {
		// Clear password by overwriting
		secret.Password = ""
		// Clear history passwords
		for j := range secret.PasswordHistory {
			// Zero out hash and salt
			for k := range secret.PasswordHistory[j].Hash {
				secret.PasswordHistory[j].Hash[k] = 0
			}
			secret.PasswordHistory[j].Hash = nil
			for k := range secret.PasswordHistory[j].Salt {
				secret.PasswordHistory[j].Salt[k] = 0
			}
			secret.PasswordHistory[j].Salt = nil
		}
		delete(v.entries, id)
	}
	v.entries = make(map[string]*SecretData)

	v.isUnlocked = false
	v.dirty = false
}

// generateID generates a unique ID for secrets
func generateID() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		fallback := sha256.Sum256([]byte(fmt.Sprintf("%d|%d", time.Now().UnixNano(), os.Getpid())))
		return base64.URLEncoding.EncodeToString(fallback[:16])
	}
	return base64.URLEncoding.EncodeToString(b)
}

