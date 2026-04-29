//go:build linux || darwin || freebsd || openbsd || netbsd

package vault

import "golang.org/x/sys/unix"

// lockMemory pins b in RAM so the OS cannot swap it to disk.
// This prevents key material from appearing in swap files or hibernation images.
func lockMemory(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = unix.Mlock(b)
}

// unlockMemory releases the mlock on b. Call before zeroing and releasing the slice.
func unlockMemory(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = unix.Munlock(b)
}
