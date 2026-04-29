package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// testPW returns a fixed-format password used only in unit tests.
// It is intentionally not a real credential.
func testPW() string { return "TestOnly-P4ssw0rd!" }

// tempVault creates a Vault backed by a temp file, deletes it after the test.
func tempVault(t *testing.T) (*Vault, func()) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pwm")
	v := NewVault(path)
	return v, func() { os.RemoveAll(dir) }
}

// ─── Create / Unlock / Lock ───────────────────────────────────────────────────

func TestCreateAndUnlock(t *testing.T) {
	v, cleanup := tempVault(t)
	defer cleanup()

	pw := testPW()

	if err := v.Create(pw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !v.IsUnlocked() {
		t.Fatal("vault should be unlocked after Create")
	}

	if err := v.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if v.IsUnlocked() {
		t.Fatal("vault should be locked after Lock")
	}

	v2 := NewVault(v.filePath)
	if err := v2.Unlock(pw); err != nil {
		t.Fatalf("Unlock with correct password: %v", err)
	}
	if !v2.IsUnlocked() {
		t.Fatal("vault should be unlocked after Unlock")
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	v, cleanup := tempVault(t)
	defer cleanup()

	_ = v.Create(testPW())
	_ = v.Lock()

	v2 := NewVault(v.filePath)
	if err := v2.Unlock("WrongPassword1!"); err == nil {
		t.Error("Unlock with wrong password should fail")
	}
}

func TestCreateExistingVault(t *testing.T) {
	v, cleanup := tempVault(t)
	defer cleanup()

	_ = v.Create(testPW())
	// Second Create on same path must fail
	v2 := NewVault(v.filePath)
	if err := v2.Create(testPW()); err == nil {
		t.Error("Create on existing vault should return error")
	}
}

// ─── Secret CRUD ─────────────────────────────────────────────────────────────

func newSecret(name, password string) *SecretData {
	return &SecretData{
		Name:     name,
		Username: "alice",
		Password: password,
		URL:      "https://example.com",
		Category: "web",
	}
}

func TestAddAndGetSecret(t *testing.T) {
	v, cleanup := tempVault(t)
	defer cleanup()

	_ = v.Create(testPW())

	s := newSecret("GitHub", "gh-secret")
	if err := v.AddSecret(s); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	if s.ID == "" {
		t.Error("AddSecret should assign an ID")
	}

	got, err := v.GetSecretByName("GitHub")
	if err != nil {
		t.Fatalf("GetSecretByName: %v", err)
	}
	if got.Password != "gh-secret" {
		t.Errorf("Password: got %q, want %q", got.Password, "gh-secret")
	}
}

func TestAddSecretPersists(t *testing.T) {
	v, cleanup := tempVault(t)
	defer cleanup()

	const pw = "Password1!"
	_ = v.Create(pw)
	_ = v.AddSecret(newSecret("Twitter", "tw-pass"))
	_ = v.Lock()

	v2 := NewVault(v.filePath)
	_ = v2.Unlock(pw)
	got, err := v2.GetSecretByName("Twitter")
	if err != nil {
		t.Fatalf("secret not found after reload: %v", err)
	}
	if got.Password != "tw-pass" {
		t.Errorf("Password after reload: got %q", got.Password)
	}
}

func TestUpdateSecret(t *testing.T) {
	v, cleanup := tempVault(t)
	defer cleanup()

	_ = v.Create(testPW())
	s := newSecret("Gmail", "old-pass")
	_ = v.AddSecret(s)

	s.Password = "new-pass"
	if err := v.UpdateSecret(s); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}

	got, _ := v.GetSecretByName("Gmail")
	if got.Password != "new-pass" {
		t.Errorf("updated password: got %q, want new-pass", got.Password)
	}
	// History should record the old password (hashed)
	hist, err := v.GetPasswordHistory(s.ID)
	if err != nil {
		t.Fatalf("GetPasswordHistory: %v", err)
	}
	if len(hist) == 0 {
		t.Error("password history should have one entry after update")
	}
}

func TestDeleteSecret(t *testing.T) {
	v, cleanup := tempVault(t)
	defer cleanup()

	_ = v.Create(testPW())
	s := newSecret("LinkedIn", "li-pass")
	_ = v.AddSecret(s)

	if err := v.DeleteSecret(s.ID); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	_, err := v.GetSecretByName("LinkedIn")
	if err == nil {
		t.Error("secret should not be found after delete")
	}
}

func TestListSecretsMasksPasswords(t *testing.T) {
	v, cleanup := tempVault(t)
	defer cleanup()

	_ = v.Create(testPW())
	_ = v.AddSecret(newSecret("Slack", "slack-secret"))

	secrets, err := v.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(secrets) == 0 {
		t.Fatal("expected at least one secret")
	}
	for _, s := range secrets {
		if s.Password != "" {
			t.Errorf("ListSecrets should mask passwords, got %q", s.Password)
		}
	}
}

func TestSearchSecrets(t *testing.T) {
	v, cleanup := tempVault(t)
	defer cleanup()

	_ = v.Create(testPW())
	_ = v.AddSecret(newSecret("Amazon", "amz"))
	_ = v.AddSecret(newSecret("Amazon AWS", "aws"))
	_ = v.AddSecret(newSecret("Google", "goo"))

	results, err := v.SearchSecrets("amazon", "", nil)
	if err != nil {
		t.Fatalf("SearchSecrets: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results for 'amazon', got %d", len(results))
	}

	results2, _ := v.SearchSecrets("", "web", nil)
	if len(results2) != 3 {
		t.Errorf("expected 3 results for category 'web', got %d", len(results2))
	}
}

func TestChangeMasterPassword(t *testing.T) {
	v, cleanup := tempVault(t)
	defer cleanup()

	oldPW := testPW()
	newPW := "TestOnly-N3wP4ss!"

	_ = v.Create(oldPW)
	_ = v.AddSecret(newSecret("Notion", "notion-pass"))

	if err := v.ChangeMasterPassword(oldPW, newPW); err != nil {
		t.Fatalf("ChangeMasterPassword: %v", err)
	}
	_ = v.Lock()

	// Old password must no longer work
	v2 := NewVault(v.filePath)
	if err := v2.Unlock(oldPW); err == nil {
		t.Error("old password should be rejected after change")
	}

	// New password must work and data must survive
	v3 := NewVault(v.filePath)
	if err := v3.Unlock(newPW); err != nil {
		t.Fatalf("Unlock with new password: %v", err)
	}
	got, err := v3.GetSecretByName("Notion")
	if err != nil {
		t.Fatalf("secret not found after password change: %v", err)
	}
	if got.Password != "notion-pass" {
		t.Errorf("data after password change: got %q", got.Password)
	}
}

func TestVaultLockedOperationsReturnsErrors(t *testing.T) {
	v, cleanup := tempVault(t)
	defer cleanup()

	_ = v.Create(testPW())
	_ = v.Lock()

	if err := v.AddSecret(newSecret("x", "y")); err == nil {
		t.Error("AddSecret on locked vault should fail")
	}
	if _, err := v.ListSecrets(); err == nil {
		t.Error("ListSecrets on locked vault should fail")
	}
	if _, err := v.GetSecretByName("x"); err == nil {
		t.Error("GetSecretByName on locked vault should fail")
	}
}

// ─── Key derivation ───────────────────────────────────────────────────────────

func TestDeriveKeys(t *testing.T) {
	salt := make([]byte, SaltLength)
	enc, hmac := deriveKeys("password", salt)

	if len(enc) != 32 {
		t.Errorf("enc key length: got %d, want 32", len(enc))
	}
	if len(hmac) != 32 {
		t.Errorf("hmac key length: got %d, want 32", len(hmac))
	}

	enc2, hmac2 := deriveKeys("password", salt)
	if string(enc) != string(enc2) || string(hmac) != string(hmac2) {
		t.Error("deriveKeys is not deterministic")
	}

	// Different password must produce different keys
	enc3, _ := deriveKeys("other-password", salt)
	if string(enc) == string(enc3) {
		t.Error("different passwords must produce different keys")
	}
}

// ─── Import / Export ─────────────────────────────────────────────────────────

func TestExportAndImportVault(t *testing.T) {
	src, cleanupSrc := tempVault(t)
	defer cleanupSrc()

	dst, cleanupDst := tempVault(t)
	defer cleanupDst()

	pw := testPW()
	_ = src.Create(pw)
	_ = src.AddSecret(newSecret("Reddit", "redd-pass"))

	// Export
	exportPath := src.filePath + ".backup"
	if err := src.ExportVault(exportPath); err != nil {
		t.Fatalf("ExportVault: %v", err)
	}
	defer os.Remove(exportPath)

	// Import into dst
	_ = dst.Create(testPW())
	n, err := dst.ImportVault(exportPath, pw)
	if err != nil {
		t.Fatalf("ImportVault: %v", err)
	}
	if n != 1 {
		t.Errorf("imported %d entries, want 1", n)
	}

	results, _ := dst.SearchSecrets("Reddit", "", nil)
	if len(results) == 0 {
		t.Error("imported secret not found in destination vault")
	}
}
