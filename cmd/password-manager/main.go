package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"password-manager/internal/ui"
	"password-manager/internal/updater"
	"password-manager/internal/vault"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// Version is injected at build time via -ldflags "-X main.Version=x.y.z"
var Version = "dev"

//go:embed logo.png
var iconBytes []byte

func defaultVaultPath() string {
	// Use OS standard application data directory so vault files are never
	// inside a cloud-sync folder (OneDrive, Dropbox, iCloud, etc.).
	// Windows:  %APPDATA%\PasswordManager\
	// macOS:    ~/Library/Application Support/PasswordManager/
	// Linux:    ~/.config/PasswordManager/
	configDir, err := os.UserConfigDir()
	if err != nil {
		// Fallback: home directory
		configDir, err = os.UserHomeDir()
		if err != nil {
			panic(fmt.Sprintf("Failed to locate user config directory: %v", err))
		}
	}
	dataDir := filepath.Join(configDir, "PasswordManager")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		panic(fmt.Sprintf("Failed to create data directory: %v", err))
	}
	return filepath.Join(dataDir, "vault.pwm")
}

func main() {
	vaultPath := os.Getenv("VAULT_PATH")
	if vaultPath == "" {
		vaultPath = defaultVaultPath()
	}

	// Create vault instance (file-based, no database)
	userVault := vault.NewVaultWithUser(vaultPath)

	// Initialize and run UI with local vault
	myApp := app.New()
	appIcon := fyne.NewStaticResource("logo.png", iconBytes)
	myApp.SetIcon(appIcon)
	// Use Segoe UI so all Unicode symbols (→ ← ✓ ✗ ⚠ etc.) render correctly.
	myApp.Settings().SetTheme(ui.NewUnicodeTheme())
	myWindow := myApp.NewWindow("Password Manager")
	myWindow.SetIcon(appIcon)
	ui.AppVersion = Version
	ui.InitializeLocalUI(myApp, myWindow, userVault)

	// Decrement ActiveSessionCount on X-button close so the concurrent session
	// limit doesn't accumulate when the user closes the window instead of
	// clicking "Lock Vault".
	myWindow.SetCloseIntercept(func() {
		_ = userVault.Logout()
		myApp.Quit()
	})

	go checkForUpdate(myWindow)

	myWindow.ShowAndRun()
}

func checkForUpdate(parent fyne.Window) {
	release, err := updater.CheckForUpdate(Version)
	if err != nil || release == nil {
		return
	}

	label := widget.NewLabel(fmt.Sprintf(
		"Version %s is available.\nYou are running %s.\n\nThe update will be applied and the app will restart.",
		release.TagName, Version,
	))

	dialog.ShowCustomConfirm(
		"Update Available",
		"Update Now", "Later",
		label,
		func(confirm bool) {
			if !confirm {
				return
			}
			applyUpdate(release, parent)
		},
		parent,
	)
}

func applyUpdate(release *updater.Release, parent fyne.Window) {
	bar := widget.NewProgressBar()
	bar.Min = 0
	bar.Max = 1

	dl := dialog.NewCustomWithoutButtons("Updating...", bar, parent)
	dl.Show()

	go func() {
		err := updater.ApplyUpdate(release, func(downloaded, total int64) {
			if total > 0 {
				bar.SetValue(float64(downloaded) / float64(total))
			}
		})

		dl.Hide()

		if err != nil {
			dialog.ShowError(fmt.Errorf("update failed: %w", err), parent)
			return
		}

		dialog.ShowInformation(
			"Update Complete",
			"The app has been updated. It will now restart.",
			parent,
		)

		// Relaunch the updated binary and exit.
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		_ = cmd.Start()
		os.Exit(0)
	}()
}
