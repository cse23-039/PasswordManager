//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !windows

package vault

// lockMemory is a no-op on unsupported platforms.
func lockMemory(_ []byte) {}

// unlockMemory is a no-op on unsupported platforms.
func unlockMemory(_ []byte) {}
