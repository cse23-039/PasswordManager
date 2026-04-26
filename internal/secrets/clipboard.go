package secrets

import (
	"sync"
	"time"
)

// ClipboardManager handles secure clipboard operations
// Requirement 3.2: Copy-to-clipboard with automatic clearing after timeout
type ClipboardManager struct {
	mu            sync.Mutex
	clearTimeout  time.Duration
	clearTimer    *time.Timer
	clipboardFunc func(string) error // Platform-specific clipboard function
	clearFunc     func() error       // Platform-specific clear function
	lastCopied    time.Time
}

// NewClipboardManager creates a new clipboard manager with the specified timeout
func NewClipboardManager(timeout time.Duration) *ClipboardManager {
	if timeout == 0 {
		timeout = 30 * time.Second // Default 30 second timeout
	}
	return &ClipboardManager{
		clearTimeout: timeout,
	}
}

// SetClipboardFunctions sets platform-specific clipboard functions
// These are injected by the UI layer (Fyne handles clipboard access)
func (cm *ClipboardManager) SetClipboardFunctions(copyFn func(string) error, clearFn func() error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.clipboardFunc = copyFn
	cm.clearFunc = clearFn
}

// CopyToClipboard copies text to the clipboard and schedules auto-clear
func (cm *ClipboardManager) CopyToClipboard(text string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Cancel any existing clear timer
	if cm.clearTimer != nil {
		cm.clearTimer.Stop()
	}

	// Copy to clipboard
	if cm.clipboardFunc != nil {
		if err := cm.clipboardFunc(text); err != nil {
			return err
		}
	}

	cm.lastCopied = time.Now()

	// Schedule clipboard clear. The ClearClipboard callback will check the
	// lastCopied timestamp to avoid clearing a newer copy if an older timer
	// fires late.
	cm.clearTimer = time.AfterFunc(cm.clearTimeout, func() {
		cm.ClearClipboard()
	})

	return nil
}

// ClearClipboard clears the clipboard contents
func (cm *ClipboardManager) ClearClipboard() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Only clear if the lastCopied time is older than the configured timeout.
	// This prevents an old timer firing after a new copy from clearing the
	// fresh clipboard contents.
	if time.Since(cm.lastCopied) < cm.clearTimeout {
		return
	}

	if cm.clearFunc != nil {
		_ = cm.clearFunc()
	}

	if cm.clearTimer != nil {
		cm.clearTimer.Stop()
		cm.clearTimer = nil
	}
}

// SetTimeout updates the clipboard clear timeout
func (cm *ClipboardManager) SetTimeout(timeout time.Duration) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.clearTimeout = timeout
}

// GetTimeout returns the current clipboard timeout
func (cm *ClipboardManager) GetTimeout() time.Duration {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.clearTimeout
}

// GetLastCopiedTime returns when the last copy operation occurred
func (cm *ClipboardManager) GetLastCopiedTime() time.Time {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.lastCopied
}

// IsTimerActive checks if a clipboard clear timer is currently running
func (cm *ClipboardManager) IsTimerActive() bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.clearTimer != nil
}

// Destroy cleans up resources
func (cm *ClipboardManager) Destroy() {
	cm.ClearClipboard()
}
