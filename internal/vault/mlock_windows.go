//go:build windows

package vault

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// lockMemory pins b in RAM using VirtualLock so the OS cannot page it to disk.
func lockMemory(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

// unlockMemory releases the VirtualLock on b. Call before zeroing and releasing the slice.
func unlockMemory(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}
