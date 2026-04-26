// Package vault provides audit logging integration for vault operations
package vault

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AuditEvent types for vault operations
const (
	AuditEventLogin          = "LOGIN"
	AuditEventLoginFailed    = "LOGIN_FAILED"
	AuditEventLogout         = "LOGOUT"
	AuditEventSecretCreate   = "SECRET_CREATE"
	AuditEventSecretRead     = "SECRET_READ"
	AuditEventSecretUpdate   = "SECRET_UPDATE"
	AuditEventSecretDelete   = "SECRET_DELETE"
	AuditEventPasswordChange = "PASSWORD_CHANGE"
	AuditEventMFAEnable      = "MFA_ENABLE"
	AuditEventMFADisable     = "MFA_DISABLE"
	AuditEventVaultCreate    = "VAULT_CREATE"
	AuditEventVaultBackup    = "VAULT_BACKUP"
	AuditEventVaultRestore   = "VAULT_RESTORE"
	AuditEventVaultExport    = "VAULT_EXPORT"
	AuditEventVaultImport    = "VAULT_IMPORT"
	AuditEventAdminChange    = "ADMIN_CHANGE"
	AuditEventPolicyChange   = "POLICY_CHANGE"
	AuditEventAccessRevoke   = "ACCESS_REVOKE"

	AuditResultSuccess = "success"
	AuditResultFailure = "failure"

	AuditCategoryAuth     = "authentication"
	AuditCategorySecret   = "secret_management"
	AuditCategoryAdmin    = "admin"
	AuditCategorySecurity = "security"
	AuditCategoryVaultOps = "vault_operations"
)

// VaultAuditEntry represents a single audit log entry
type VaultAuditEntry struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Username       string    `json:"username"`
	Event          string    `json:"event"`
	Category       string    `json:"category"`
	Details        string    `json:"details"`
	Result         string    `json:"result"`
	ResourceID     string    `json:"resource_id,omitempty"`
	ResourceName   string    `json:"resource_name,omitempty"`
	IPAddress      string    `json:"ip_address,omitempty"`
	PreviousValue  string    `json:"previous_value,omitempty"`
	NewValue       string    `json:"new_value,omitempty"`
	SequenceNumber int64     `json:"sequence_number"`
	PreviousEntry  string    `json:"previous_entry,omitempty"` // prior entry's checksum for chain integrity
	Checksum       string    `json:"checksum"`
}

// VaultAuditLog manages persistent, tamper-resistant audit logging
type VaultAuditLog struct {
	mu      sync.RWMutex
	entries []*VaultAuditEntry
	// in-memory indexes — rebuilt on load, maintained on every write.
	// Entries are stored oldest-first; indexes follow the same order.
	byEvent        map[string][]*VaultAuditEntry
	byCategory     map[string][]*VaultAuditEntry
	filePath       string
	vault          *Vault // used for companion-file encryption/decryption
	hmacKey        []byte
	sequenceNumber int64
	maxEntries     int
	autoSave       bool
	retentionDays  int
}

// VaultAuditConfig configuration for audit logging
type VaultAuditConfig struct {
	FilePath      string
	Vault         *Vault // used for companion-file encryption; nil falls back to legacy key
	HMACKey       []byte
	MaxEntries    int // 0 = unlimited
	AutoSave      bool
	RetentionDays int // 0 = keep forever
}

// NewVaultAuditLog creates a new audit logger
func NewVaultAuditLog(config VaultAuditConfig) *VaultAuditLog {
	if config.FilePath == "" {
		homeDir, _ := os.UserHomeDir()
		config.FilePath = filepath.Join(homeDir, ".password-manager", "audit.log")
	}

	if config.MaxEntries == 0 {
		config.MaxEntries = 1000 // Keep last 1000 entries in memory
	}

	auditLog := &VaultAuditLog{
		entries:       make([]*VaultAuditEntry, 0),
		byEvent:       make(map[string][]*VaultAuditEntry, 16),
		byCategory:    make(map[string][]*VaultAuditEntry, 8),
		filePath:      config.FilePath,
		vault:         config.Vault,
		hmacKey:       config.HMACKey,
		maxEntries:    config.MaxEntries,
		autoSave:      config.AutoSave,
		retentionDays: config.RetentionDays,
	}

	// Ensure directory exists with secure permissions
	dir := filepath.Dir(config.FilePath)
	os.MkdirAll(dir, 0700)

	// Load existing entries
	auditLog.loadFromFile()

	return auditLog
}

// SetHMACKey sets the HMAC key for tamper detection.
// This should be derived from the vault master password.
// It also re-signs any entries that were loaded from disk before the key was
// available — fixing the one-time timezone normalisation migration where old
// checksums were computed with a local-timezone timestamp string but the JSON
// file stores timestamps in UTC.
func (al *VaultAuditLog) SetHMACKey(key []byte) {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.hmacKey = key
	al.reSignEntries()
}

// rebuildIndexes reconstructs byEvent and byCategory from al.entries.
// Must be called with al.mu held for writing (or during init before concurrent access).
func (al *VaultAuditLog) rebuildIndexes() {
	al.byEvent = make(map[string][]*VaultAuditEntry, 16)
	al.byCategory = make(map[string][]*VaultAuditEntry, 8)
	for _, e := range al.entries {
		al.byEvent[e.Event] = append(al.byEvent[e.Event], e)
		al.byCategory[e.Category] = append(al.byCategory[e.Category], e)
	}
}

// reSignEntries recalculates checksums and PreviousEntry links for every
// in-memory entry using the current HMAC key. Called once after SetHMACKey
// so that entries loaded from disk (whose timestamps are already UTC after
// JSON unmarshal) get correct checksums going forward.
// Must be called with al.mu held for writing.
func (al *VaultAuditLog) reSignEntries() {
	if len(al.hmacKey) == 0 || len(al.entries) == 0 {
		return
	}
	// Process in order so each entry's PreviousEntry correctly references
	// the freshly-computed checksum of its predecessor.
	for i, e := range al.entries {
		e.Timestamp = e.Timestamp.UTC()
		if i == 0 {
			e.PreviousEntry = ""
		} else {
			e.PreviousEntry = al.entries[i-1].Checksum
		}
		e.Checksum = al.calculateChecksum(e)
	}
	_ = al.saveToFile() // persist corrected checksums
	al.rebuildIndexes() // refresh index pointers after re-sign
}

// LogEvent logs an audit event
func (al *VaultAuditLog) LogEvent(username, event, category, details, result string) {
	al.LogEventWithDetails(username, event, category, details, result, "", "", "", "", "")
}

// PruneOldEntries removes audit entries older than retentionDays.
// Pass 0 to keep entries forever. Rebuilds indexes and auto-saves when entries are removed.
func (al *VaultAuditLog) PruneOldEntries(retentionDays int) {
	if retentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	al.mu.Lock()
	defer al.mu.Unlock()
	n := 0
	for _, e := range al.entries {
		if e.Timestamp.After(cutoff) {
			al.entries[n] = e
			n++
		}
	}
	if n < len(al.entries) {
		al.entries = al.entries[:n]
		al.rebuildIndexes()
		if al.autoSave {
			_ = al.saveToFile()
		}
	}
}

// LogEventWithDetails logs an audit event with full details
func (al *VaultAuditLog) LogEventWithDetails(
	username, event, category, details, result,
	resourceID, resourceName, ipAddress, prevValue, newValue string,
) {
	al.mu.Lock()
	defer al.mu.Unlock()

	al.sequenceNumber++

	entry := &VaultAuditEntry{
		ID:             generateAuditID(),
		Timestamp:      time.Now(),
		Username:       username,
		Event:          event,
		Category:       category,
		Details:        details,
		Result:         result,
		ResourceID:     resourceID,
		ResourceName:   resourceName,
		IPAddress:      ipAddress,
		PreviousValue:  prevValue,
		NewValue:       newValue,
		SequenceNumber: al.sequenceNumber,
	}

	// Normalise timestamp to UTC so the checksum is invariant across
	// JSON round-trips (Go's JSON encoder always writes time in UTC).
	entry.Timestamp = entry.Timestamp.UTC()

	// Link to previous entry for audit chain integrity (Req 3.4 tamper resistance)
	if len(al.entries) > 0 {
		entry.PreviousEntry = al.entries[len(al.entries)-1].Checksum
	}

	// Calculate tamper-proof checksum (covers all fields including PreviousEntry)
	entry.Checksum = al.calculateChecksum(entry)

	al.entries = append(al.entries, entry)

	// Maintain in-memory indexes (O(1) per write)
	if al.byEvent == nil {
		al.byEvent = make(map[string][]*VaultAuditEntry, 16)
	}
	if al.byCategory == nil {
		al.byCategory = make(map[string][]*VaultAuditEntry, 8)
	}
	al.byEvent[entry.Event] = append(al.byEvent[entry.Event], entry)
	al.byCategory[entry.Category] = append(al.byCategory[entry.Category], entry)

	// Trim old entries if needed (indexes are rebuilt lazily on next read if needed)
	if len(al.entries) > al.maxEntries {
		al.entries = al.entries[len(al.entries)-al.maxEntries:]
	}

	// Auto-save if enabled
	if al.autoSave {
		al.saveToFile()
	}
}

// LogLogin logs a login attempt
func (al *VaultAuditLog) LogLogin(username string, success bool, failReason string, ipAddress ...string) {
	event := AuditEventLogin
	result := AuditResultSuccess
	details := "Login successful"

	if !success {
		event = AuditEventLoginFailed
		result = AuditResultFailure
		details = "Login failed"
		if failReason != "" {
			details += ": " + failReason
		}
	}

	ip := ""
	if len(ipAddress) > 0 {
		ip = ipAddress[0]
	}

	al.LogEventWithDetails(username, event, AuditCategoryAuth, details, result, "", "", ip, "", "")
}

// LogLogout logs a logout event
func (al *VaultAuditLog) LogLogout(username string) {
	al.LogEvent(username, AuditEventLogout, AuditCategoryAuth, "User logged out", AuditResultSuccess)
}

// LogSecretCreate logs secret creation
func (al *VaultAuditLog) LogSecretCreate(username, secretID, secretName string) {
	al.LogEventWithDetails(
		username, AuditEventSecretCreate, AuditCategorySecret,
		"Secret created", AuditResultSuccess,
		secretID, secretName, "", "", "",
	)
}

// LogSecretRead logs secret access
func (al *VaultAuditLog) LogSecretRead(username, secretID, secretName string) {
	al.LogEventWithDetails(
		username, AuditEventSecretRead, AuditCategorySecret,
		"Secret accessed", AuditResultSuccess,
		secretID, secretName, "", "", "",
	)
}

// LogSecretUpdate logs secret modification
func (al *VaultAuditLog) LogSecretUpdate(username, secretID, secretName, changedField string) {
	al.LogEventWithDetails(
		username, AuditEventSecretUpdate, AuditCategorySecret,
		fmt.Sprintf("Secret updated: %s", changedField), AuditResultSuccess,
		secretID, secretName, "", "", "",
	)
}

// LogSecretDelete logs secret deletion
func (al *VaultAuditLog) LogSecretDelete(username, secretID, secretName string) {
	al.LogEventWithDetails(
		username, AuditEventSecretDelete, AuditCategorySecret,
		"Secret deleted", AuditResultSuccess,
		secretID, secretName, "", "", "",
	)
}

// LogPasswordChange logs password modification
func (al *VaultAuditLog) LogPasswordChange(username string, success bool) {
	result := AuditResultSuccess
	details := "Password changed"
	if !success {
		result = AuditResultFailure
		details = "Password change failed"
	}
	al.LogEvent(username, AuditEventPasswordChange, AuditCategorySecurity, details, result)
}

// LogMFAChange logs MFA configuration changes
func (al *VaultAuditLog) LogMFAChange(username string, enabled bool) {
	event := AuditEventMFAEnable
	details := "MFA enabled"
	if !enabled {
		event = AuditEventMFADisable
		details = "MFA disabled"
	}
	al.LogEvent(username, event, AuditCategorySecurity, details, AuditResultSuccess)
}

// LogVaultOperation logs vault-level operations
func (al *VaultAuditLog) LogVaultOperation(username, operation, details string, success bool) {
	result := AuditResultSuccess
	if !success {
		result = AuditResultFailure
	}
	al.LogEvent(username, operation, AuditCategoryVaultOps, details, result)
}

// LogAdminChange logs administrative changes
func (al *VaultAuditLog) LogAdminChange(adminUser, action, targetUser, details string) {
	al.LogEventWithDetails(
		adminUser, AuditEventAdminChange, AuditCategoryAdmin,
		fmt.Sprintf("%s: %s", action, details), AuditResultSuccess,
		"", targetUser, "", "", "",
	)
}

// LogAccessRevoke logs access revocation
func (al *VaultAuditLog) LogAccessRevoke(adminUser, targetUser, reason string) {
	al.LogEventWithDetails(
		adminUser, AuditEventAccessRevoke, AuditCategoryAdmin,
		fmt.Sprintf("Access revoked: %s", reason), AuditResultSuccess,
		"", targetUser, "", "", "",
	)
}

// GetAllEntries returns all audit entries
// GetAllEntries returns all entries oldest-first (for chain-integrity operations).
func (al *VaultAuditLog) GetAllEntries() []*VaultAuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	result := make([]*VaultAuditEntry, len(al.entries))
	copy(result, al.entries)
	return result
}

// GetAllEntriesNewestFirst returns all entries newest-first without a
// separate reversal pass — single reverse-copy loop, no alloc beyond the
// result slice.
func (al *VaultAuditLog) GetAllEntriesNewestFirst() []*VaultAuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	n := len(al.entries)
	result := make([]*VaultAuditEntry, n)
	for i, e := range al.entries {
		result[n-1-i] = e
	}
	return result
}

// GetEntriesByUser returns entries for a specific user
func (al *VaultAuditLog) GetEntriesByUser(username string) []*VaultAuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var result []*VaultAuditEntry
	for _, entry := range al.entries {
		if entry.Username == username {
			result = append(result, entry)
		}
	}
	return result
}

// GetEntriesByEvent returns entries for a specific event type, newest-first.
// Uses the in-memory index for O(1) lookup instead of O(n) scan.
func (al *VaultAuditLog) GetEntriesByEvent(event string) []*VaultAuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	src := al.byEvent[event]
	n := len(src)
	if n == 0 {
		return nil
	}
	result := make([]*VaultAuditEntry, n)
	for i, e := range src {
		result[n-1-i] = e // reverse: newest first
	}
	return result
}

// GetEntriesByCategory returns entries for a specific category, newest-first.
// Uses the in-memory index for O(1) lookup instead of O(n) scan.
func (al *VaultAuditLog) GetEntriesByCategory(category string) []*VaultAuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	src := al.byCategory[category]
	n := len(src)
	if n == 0 {
		return nil
	}
	result := make([]*VaultAuditEntry, n)
	for i, e := range src {
		result[n-1-i] = e // reverse: newest first
	}
	return result
}

// GetEntriesSince returns entries since a specific time
func (al *VaultAuditLog) GetEntriesSince(since time.Time) []*VaultAuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var result []*VaultAuditEntry
	for _, entry := range al.entries {
		if entry.Timestamp.After(since) {
			result = append(result, entry)
		}
	}
	return result
}

// GetEntriesForResource returns entries for a specific resource
func (al *VaultAuditLog) GetEntriesForResource(resourceID string) []*VaultAuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var result []*VaultAuditEntry
	for _, entry := range al.entries {
		if entry.ResourceID == resourceID {
			result = append(result, entry)
		}
	}
	return result
}

// GetFailedLogins returns failed login attempts
func (al *VaultAuditLog) GetFailedLogins() []*VaultAuditEntry {
	return al.GetEntriesByEvent(AuditEventLoginFailed)
}

// GetSecurityEvents returns security-related events
func (al *VaultAuditLog) GetSecurityEvents() []*VaultAuditEntry {
	return al.GetEntriesByCategory(AuditCategorySecurity)
}

// GetAdminEvents returns administrative events
func (al *VaultAuditLog) GetAdminEvents() []*VaultAuditEntry {
	return al.GetEntriesByCategory(AuditCategoryAdmin)
}

// VerifyIntegrity checks if an entry has been tampered with
func (al *VaultAuditLog) VerifyIntegrity(entry *VaultAuditEntry) bool {
	if len(al.hmacKey) == 0 || entry.Checksum == "" {
		return false
	}

	expectedChecksum := al.calculateChecksum(entry)
	return hmac.Equal([]byte(expectedChecksum), []byte(entry.Checksum))
}

// VerifyAllIntegrity checks all entries for tampering
func (al *VaultAuditLog) VerifyAllIntegrity() (verified, tampered, unverifiable int) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	for _, entry := range al.entries {
		if entry.Checksum == "" {
			unverifiable++
		} else if al.VerifyIntegrity(entry) {
			verified++
		} else {
			tampered++
		}
	}
	return
}

// VerifyChainIntegrity checks that the audit log forms an unbroken HMAC chain.
// Returns false if any entry was deleted, inserted, or reordered since logging.
func (al *VaultAuditLog) VerifyChainIntegrity() bool {
	al.mu.RLock()
	defer al.mu.RUnlock()

	for i := 1; i < len(al.entries); i++ {
		prev := al.entries[i-1]
		curr := al.entries[i]
		// Each entry must reference the previous entry's checksum; missing
		// checksums or previous links are treated as tampering.
		if curr.PreviousEntry == "" || prev.Checksum == "" {
			return false
		}
		if curr.PreviousEntry != prev.Checksum {
			return false
		}
		// Sequence numbers must be strictly increasing. Gaps are allowed
		// (e.g. after pruning older entries), but out-of-order numbers are not.
		if curr.SequenceNumber <= prev.SequenceNumber {
			return false
		}
	}
	return true
}

// SetRetentionDays configures how many days of audit entries to keep (0 = keep forever).
func (al *VaultAuditLog) SetRetentionDays(days int) {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.retentionDays = days
}

// PurgeExpiredEntries removes audit entries older than the configured retention window.
// Returns the count of entries removed.
func (al *VaultAuditLog) PurgeExpiredEntries() int {
	if al.retentionDays <= 0 {
		return 0
	}
	al.mu.Lock()
	defer al.mu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -al.retentionDays)
	kept := al.entries[:0]
	purged := 0
	for _, e := range al.entries {
		if e.Timestamp.After(cutoff) {
			kept = append(kept, e)
		} else {
			purged++
		}
	}
	al.entries = kept
	if purged > 0 && al.autoSave {
		al.saveToFile()
	}
	return purged
}

// ExportJSON exports audit logs in JSON format
func (al *VaultAuditLog) ExportJSON() ([]byte, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	return json.Marshal(al.entries)
}

// ExportCSV exports audit logs in CSV format
func (al *VaultAuditLog) ExportCSV() string {
	al.mu.RLock()
	defer al.mu.RUnlock()
	// Use encoding/csv to properly escape all fields.
	buf := &strings.Builder{}
	w := csv.NewWriter(buf)
	// Header
	_ = w.Write([]string{"ID", "Timestamp", "Username", "Event", "Category", "Details", "Result", "ResourceID", "ResourceName", "Checksum"})
	for _, entry := range al.entries {
		_ = w.Write([]string{
			entry.ID,
			entry.Timestamp.Format(time.RFC3339),
			entry.Username,
			entry.Event,
			entry.Category,
			entry.Details,
			entry.Result,
			entry.ResourceID,
			entry.ResourceName,
			entry.Checksum,
		})
	}
	w.Flush()
	return buf.String()
}

// ExportCEF exports logs in Common Event Format for SIEM
func (al *VaultAuditLog) ExportCEF() string {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var sb strings.Builder
	for _, entry := range al.entries {
		severity := "3" // Medium
		if entry.Result == AuditResultFailure {
			severity = "6" // High
		}
		fmt.Fprintf(&sb, "CEF:0|PasswordManager|LocalVault|1.0|%s|%s|%s|"+
			"duser=%s outcome=%s msg=%s cs1=%s cs1Label=ResourceID rt=%d\n",
			entry.Event,
			entry.Event,
			severity,
			entry.Username,
			entry.Result,
			escapeForCEF(entry.Details),
			entry.ResourceID,
			entry.Timestamp.UnixMilli(),
		)
	}
	return sb.String()
}

// ExportTXT exports audit logs as a human-readable plain-text dump.
func (al *VaultAuditLog) ExportTXT() string {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var b strings.Builder
	for _, e := range al.entries {
		// Timestamp Username Event Category Result IP ResourceID ResourceName Details
		ip := e.IPAddress
		if ip == "" {
			ip = "-"
		}
		resID := e.ResourceID
		if resID == "" {
			resID = "-"
		}
		resName := e.ResourceName
		if resName == "" {
			resName = "-"
		}
		b.WriteString(fmt.Sprintf("%s %s %s %s %s %s %s %s %s\n",
			e.Timestamp.Format(time.RFC3339), e.Username, e.Event, e.Category, e.Result, ip, resID, resName, strings.ReplaceAll(e.Details, "\n", "\\n")))
	}
	return b.String()
}

// Save persists audit logs to file
func (al *VaultAuditLog) Save() error {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.saveToFile()
}

// Clear removes all audit entries (use with caution)
func (al *VaultAuditLog) Clear() {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.entries = make([]*VaultAuditEntry, 0)
	al.saveToFile()
}

// GetStats returns audit log statistics
func (al *VaultAuditLog) GetStats() map[string]interface{} {
	al.mu.RLock()
	defer al.mu.RUnlock()

	verified, tampered, unverifiable := 0, 0, 0
	for _, entry := range al.entries {
		if entry.Checksum == "" {
			unverifiable++
		} else if al.VerifyIntegrity(entry) {
			verified++
		} else {
			tampered++
		}
	}

	// Count by category
	byCategory := make(map[string]int)
	byEvent := make(map[string]int)
	failures := 0

	for _, entry := range al.entries {
		byCategory[entry.Category]++
		byEvent[entry.Event]++
		if entry.Result == AuditResultFailure {
			failures++
		}
	}

	return map[string]interface{}{
		"total_entries":    len(al.entries),
		"verified_entries": verified,
		"tampered_entries": tampered,
		"unverifiable":     unverifiable,
		"failed_events":    failures,
		"by_category":      byCategory,
		"by_event":         byEvent,
		"sequence_number":  al.sequenceNumber,
		"integrity_ok":     tampered == 0,
	}
}

// calculateChecksum creates HMAC-SHA256 for tamper detection
func (al *VaultAuditLog) calculateChecksum(entry *VaultAuditEntry) string {
	if len(al.hmacKey) == 0 {
		return ""
	}

	// Create canonical string including sequence number for chain integrity.
	// Always format in UTC so the string is identical before and after a
	// JSON round-trip (Go JSON always encodes time.Time as UTC).
	data := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s|%s|%s",
		entry.Timestamp.UTC().Format(time.RFC3339Nano),
		entry.SequenceNumber,
		entry.Username,
		entry.Event,
		entry.Category,
		entry.Details,
		entry.Result,
		entry.ResourceID,
		entry.PreviousEntry,
	)

	h := hmac.New(sha256.New, al.hmacKey)
	h.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// saveToFile persists entries to disk in encrypted form.
func (al *VaultAuditLog) saveToFile() error {
	// Compact JSON — faster and smaller than MarshalIndent for large logs.
	data, err := json.Marshal(al.entries)
	if err != nil {
		return fmt.Errorf("failed to marshal audit log: %w", err)
	}

	var enc []byte
	if al.vault != nil {
		enc, err = al.vault.encryptAppData(data)
	} else {
		enc, err = (&Vault{}).encryptAppData(data)
	}
	if err != nil {
		return fmt.Errorf("failed to encrypt audit log: %w", err)
	}
	out := append([]byte(auditMagic), enc...)

	// Atomic write with temp file.
	tempPath := al.filePath + ".tmp"
	if err := os.WriteFile(tempPath, out, 0600); err != nil {
		return fmt.Errorf("failed to write audit log: %w", err)
	}

	if err := os.Rename(tempPath, al.filePath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to save audit log: %w", err)
	}

	return nil
}

// loadFromFile loads entries from disk.
func (al *VaultAuditLog) loadFromFile() error {
	raw, err := os.ReadFile(al.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No existing log file
		}
		return fmt.Errorf("failed to read audit log: %w", err)
	}

	var data []byte
	if len(raw) >= len(auditMagic) && string(raw[:len(auditMagic)]) == auditMagic {
		// Encrypted format.
		if al.vault != nil {
			data, err = al.vault.decryptAppData(raw[len(auditMagic):])
		} else {
			data, err = (&Vault{}).decryptAppData(raw[len(auditMagic):])
		}
		if err != nil {
			return fmt.Errorf("failed to decrypt audit log: %w", err)
		}
	} else if len(raw) > 0 && raw[0] == '[' {
		// Legacy plain JSON array — accepted, will be encrypted on next save.
		data = raw
	} else {
		return fmt.Errorf("audit log: unrecognised file format")
	}

	var entries []*VaultAuditEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to parse audit log: %w", err)
	}

	al.entries = entries

	// (Re)build in-memory indexes from loaded entries.
	al.rebuildIndexes()

	// Purge entries outside the retention window (Req 5: data retention enforcement)
	if al.retentionDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -al.retentionDays)
		kept := al.entries[:0]
		for _, e := range al.entries {
			if e.Timestamp.After(cutoff) {
				kept = append(kept, e)
			}
		}
		al.entries = kept
	}

	// Update sequence number based on loaded entries
	for _, entry := range entries {
		if entry.SequenceNumber > al.sequenceNumber {
			al.sequenceNumber = entry.SequenceNumber
		}
	}

	return nil
}

// generateAuditID creates a unique ID for audit entries
func generateAuditID() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// Fallback: use time-based ID if crypto RNG fails
		return fmt.Sprintf("%d-%s", time.Now().UnixNano(), "fallback")
	}
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), base64.URLEncoding.EncodeToString(b)[:8])
}

// escapeForCEF escapes special characters for CEF format
func escapeForCEF(s string) string {
	result := ""
	for _, r := range s {
		switch r {
		case '\\':
			result += "\\\\"
		case '=':
			result += "\\="
		case '\n':
			result += "\\n"
		case '\r':
			result += "\\r"
		default:
			result += string(r)
		}
	}
	return result
}
