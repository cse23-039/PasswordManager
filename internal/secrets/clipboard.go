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
	generation    uint64 // incremented on every copy; timer only clears if generation matches
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

// CopyToClipboard copies text to the clipboard and schedules auto-clear.
// Each call increments an internal generation counter so a delayed timer from
// a previous copy cannot clear a freshly-copied value.
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
	cm.generation++
	gen := cm.generation

	cm.clearTimer = time.AfterFunc(cm.clearTimeout, func() {
		cm.clearIfGeneration(gen)
	})

	return nil
}

// clearIfGeneration clears the clipboard only if the current generation
// matches gen, preventing a stale timer from wiping a newer copy.
func (cm *ClipboardManager) clearIfGeneration(gen uint64) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.generation != gen {
		return // a newer copy supersedes this timer
	}

	if cm.clearFunc != nil {
		_ = cm.clearFunc()
	}

	if cm.clearTimer != nil {
		cm.clearTimer.Stop()
		cm.clearTimer = nil
	}
}

// ClearClipboard clears the clipboard contents immediately.
func (cm *ClipboardManager) ClearClipboard() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.clearFunc != nil {
		_ = cm.clearFunc()
	}

	if cm.clearTimer != nil {
		cm.clearTimer.Stop()
		cm.clearTimer = nil
	}
	cm.generation++ // invalidate any pending timer
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
