package ui

import (
	"crypto/rand"
	"errors"
	"fmt"
	"image/color"
	"net"
	"password-manager/internal/auth"
	"password-manager/internal/models"
	"password-manager/internal/secrets"
	"password-manager/internal/vault"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// LocalVaultUI manages the UI for local vault operations
type LocalVaultUI struct {
	app              fyne.App
	window           fyne.Window
	vault            *vault.VaultWithUser
	clipboardManager *secrets.ClipboardManager
	currentUser      string
	savedPassword    string
	content          *fyne.Container
	lastActivity     time.Time     // for inactivity auto-lock (Req 3.6)
	activityMu       sync.RWMutex  // protects lastActivity
	activityCancel   chan struct{} // closed to stop the inactivity goroutine
	vaultKeyVerified bool          // true once vault access key verified this session
	chainMonitorStop chan struct{} // closed to stop the chain integrity monitor goroutine
	vaultTamperStop  chan struct{} // closed to stop the vault file tamper monitor goroutine
	onMainScreen     bool         // true when the split main layout is active (sidebar visible)
}

var localUI *LocalVaultUI

// InitializeLocalUI sets up the UI for local vault mode
func InitializeLocalUI(app fyne.App, window fyne.Window, v *vault.VaultWithUser) {
	localUI = &LocalVaultUI{
		app:    app,
		window: window,
		vault:  v,
	}

	// Initialize clipboard manager with a 30s auto-clear timeout and wire
	// it to the platform clipboard functions provided by Fyne.
	localUI.clipboardManager = secrets.NewClipboardManager(30 * time.Second)
	localUI.clipboardManager.SetClipboardFunctions(
		func(text string) error {
			localUI.window.Clipboard().SetContent(text)
			return nil
		},
		func() error {
			if cb := localUI.window.Clipboard(); cb != nil {
				cb.SetContent("")
			}
			return nil
		},
	)

	// Always start at the landing screen (Login / Register choice)
	localUI.showLandingScreen()

	window.Resize(fyne.NewSize(1100, 720))
	window.CenterOnScreen()
}

// copyrightFooter returns the copyright bar pinned to the bottom of every screen.
func copyrightFooter() fyne.CanvasObject {
	lbl := widget.NewLabelWithStyle(
		"\u00a9 2026 Kagiso Setwaba \u00b7 All rights reserved \u00b7 Password Manager v1.0",
		fyne.TextAlignCenter,
		fyne.TextStyle{Italic: true},
	)
	lbl.Importance = widget.LowImportance
	return container.NewVBox(widget.NewSeparator(), container.NewPadded(lbl))
}

// withFooter wraps any screen content in a border layout with the copyright
// bar pinned to the bottom and a dark/light mode toggle pinned to the top-right.
// This runs on every screen so the toggle is always visible.
func (ui *LocalVaultUI) withFooter(content fyne.CanvasObject) fyne.CanvasObject {
	themeLabel := func() string {
		if IsDarkMode() {
			return "☀ Light Mode"
		}
		return "🌙 Dark Mode"
	}
	var themeBtn *widget.Button
	themeBtn = widget.NewButtonWithIcon(themeLabel(), theme.VisibilityIcon(), func() {
		SetDarkMode(ui.app, !IsDarkMode())
		themeBtn.SetText(themeLabel())
		if ui.onMainScreen {
			ui.showMainScreen()
		}
	})
	themeBtn.Importance = widget.LowImportance

	topBar := container.NewHBox(layout.NewSpacer(), themeBtn)
	return container.NewBorder(topBar, copyrightFooter(), nil, nil, content)
}

// showLandingScreen shows the welcome screen with Login and Register options.
// This is always the first screen the user sees – a clean login form
// with a link to register a new account.
func (ui *LocalVaultUI) showLandingScreen() {
	ui.onMainScreen = false
	// Cancel any running inactivity monitor
	if ui.activityCancel != nil {
		close(ui.activityCancel)
		ui.activityCancel = nil
	}
	// Stop vault file tamper watcher
	if ui.vaultTamperStop != nil {
		close(ui.vaultTamperStop)
		ui.vaultTamperStop = nil
	}
	ui.vaultKeyVerified = false // reset vault key verification on every logout/landing
	if ui.clipboardManager != nil {
		ui.clipboardManager.ClearClipboard()
	}

	widthEnforcer := canvas.NewRectangle(color.Transparent)
	widthEnforcer.SetMinSize(fyne.NewSize(480, 1))

	appName := widget.NewLabelWithStyle("Password Manager", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	appSub := widget.NewLabelWithStyle("Secure Enterprise Vault", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password")

	// MFA row — hidden until password is accepted and MFA is confirmed active.
	mfaEntry := widget.NewEntry()
	mfaEntry.SetPlaceHolder("6-digit code from your authenticator app")
	mfaHint := widget.NewLabelWithStyle(
		"Open Microsoft Authenticator, find the Password Manager entry, and type the 6-digit code shown.",
		fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
	mfaHint.Importance = widget.LowImportance
	mfaRow := container.NewVBox(
		container.New(layout.NewFormLayout(), widget.NewLabel("MFA Code"), mfaEntry),
		container.NewPadded(mfaHint),
	)
	mfaRow.Hide() // shown only after password accepted + MFA required

	errorLabel := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{})
	errorLabel.Importance = widget.DangerImportance

	// mfaRequired tracks whether we've already verified the password and are
	// now waiting for a TOTP code.
	mfaRequired := false
	savedUsername := ""
	savedPassword := ""
	// Forward-declare so helper/button closures can reference it before assignment.
	var loginBtn *widget.Button
	resetMFAStep := func() {
		mfaRequired = false
		mfaEntry.SetText("")
		mfaRow.Hide()
		loginBtn.SetText("Login")
		usernameEntry.Enable()
		passwordEntry.Enable()
	}

	loginBtn = widget.NewButtonWithIcon("Login", theme.LoginIcon(), func() {
		errorLabel.SetText("")
		username := strings.TrimSpace(usernameEntry.Text)
		password := passwordEntry.Text
		if username == "" || password == "" {
			errorLabel.SetText("Username and password are required")
			return
		}
		if !ui.vault.UsersFileExists() {
			errorLabel.SetText("No account found — please register first")
			return
		}

		if mfaRequired {
			// Step 2: MFA code submitted.
			mfaCode := strings.ReplaceAll(strings.TrimSpace(mfaEntry.Text), " ", "")
			if len(mfaCode) != 6 {
				errorLabel.SetText("Enter the 6-digit code from your authenticator app")
				return
			}
			firstLogin := !ui.vault.Vault.Exists()
			ip := localIPAddress()
			if err := ui.vault.LoginWithMFA(savedUsername, savedPassword, mfaCode, ip); err != nil {
				if strings.Contains(err.Error(), "MFA setup required") || strings.Contains(err.Error(), "MFA not set up") {
					resetMFAStep()
					ui.currentUser = savedUsername
					ui.savedPassword = savedPassword
					ui.startMandatoryMFAEnrollment()
					return
				}
				errorLabel.SetText(err.Error())
				return
			}
			ui.currentUser = savedUsername
			if firstLogin {
				ui.showNewVaultScreen()
				return
			}
			ui.enforcePasswordExpiry()
			return
		}

		// Step 1: verify username + password only.
		firstLogin := !ui.vault.Vault.Exists()
		ip := localIPAddress()
		if err := ui.vault.Login(username, password, ip); err != nil {
			if strings.Contains(err.Error(), "MFA setup required") || strings.Contains(err.Error(), "MFA not set up") {
				// User needs to enroll (QR) rather than enter a code.
				savedUsername = username
				savedPassword = password
				ui.savedPassword = password
				ui.currentUser = username
				ui.startMandatoryMFAEnrollment()
				return
			}
			if strings.Contains(err.Error(), "MFA required") {
				// Password accepted — now ask for the TOTP code.
				savedUsername = username
				savedPassword = password
				ui.savedPassword = password
				mfaRequired = true
				mfaRow.Show()
				loginBtn.SetText("Verify Code")
				usernameEntry.Disable()
				passwordEntry.Disable()
				errorLabel.SetText("")
				ui.window.Canvas().Focus(mfaEntry)
				return
			}
			switch {
			case errors.Is(err, vault.ErrUserNotFound):
				errorLabel.SetText("User does not exist")
			case errors.Is(err, vault.ErrInvalidPassword):
				errorLabel.SetText("Invalid password")
			default:
				errorLabel.SetText(err.Error())
			}
			return
		}
		// Password accepted and MFA not yet configured — go to MFA enrollment.
		ui.currentUser = username
		if profile, pErr := ui.vault.GetUserProfile(); pErr == nil {
			if !profile.MFAEnabled || !profile.TOTPVerified {
				ui.startMandatoryMFAEnrollment()
				return
			}
		}
		_, userHasMFA := ui.vault.CheckMFARequirement()
		if !userHasMFA {
			// Always require enrollment for accounts that do not have MFA configured.
			ui.startMandatoryMFAEnrollment()
			return
		}
		if firstLogin {
			ui.showNewVaultScreen()
			return
		}
		ui.enforcePasswordExpiry()
	})
	loginBtn.Importance = widget.HighImportance
	passwordEntry.OnSubmitted = func(_ string) { loginBtn.OnTapped() }
	mfaEntry.OnSubmitted = func(_ string) { loginBtn.OnTapped() }

	registerLink := widget.NewHyperlink("Don't have an account? Register here", nil)
	registerLink.OnTapped = func() { ui.showRegistrationScreen() }

	formFields := container.New(layout.NewFormLayout(),
		widget.NewLabel("Username"), usernameEntry,
		widget.NewLabel("Password"), passwordEntry,
	)

	loginCard := widget.NewCard("Welcome Back", "Sign in to your encrypted vault",
		container.NewVBox(
			container.NewPadded(container.NewVBox(appName, appSub)),
			widget.NewSeparator(),
			container.NewPadded(formFields),
			container.NewPadded(mfaRow),
			widget.NewSeparator(),
			errorLabel,
			loginBtn,
			widget.NewSeparator(),
			container.NewCenter(registerLink),
		),
	)

	ui.window.SetContent(ui.withFooter(container.NewCenter(
		container.NewVBox(
			widthEnforcer,
			container.NewPadded(loginCard),
		),
	)))
}

// localIPAddress attempts to return a non-loopback IPv4 address for this host.
// Returns empty string if none found.
func localIPAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return ""
}

// showRegistrationScreen shows the new-user registration form.
// Step 1: user fills in details and clicks Register.
// Step 2 (first admin only): MFA QR code is shown inline; after verifying, user
// is sent back to the login screen.
// For additional users (vault already exists), the vault access password is
// required; after the account is created the user is directed to log in, where
// MFA enrollment will be triggered automatically.
func (ui *LocalVaultUI) showRegistrationScreen() {
	ui.onMainScreen = false
	widthEnforcer := canvas.NewRectangle(color.Transparent)
	widthEnforcer.SetMinSize(fyne.NewSize(520, 1))

	appName := widget.NewLabelWithStyle("Password Manager", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	appSub := widget.NewLabelWithStyle("Create Your Account", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username (min 3 characters)")

	emailEntry := widget.NewEntry()
	emailEntry.SetPlaceHolder("Email (optional)")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Minimum 12 characters")

	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("Re-enter password")

	errorLabel := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{})
	errorLabel.Importance = widget.DangerImportance

	doRegister := func() {
		errorLabel.SetText("")
		username := strings.TrimSpace(usernameEntry.Text)
		email := strings.TrimSpace(emailEntry.Text)
		password := passwordEntry.Text
		confirm := confirmEntry.Text
		if len(username) < 3 {
			errorLabel.SetText("Username must be at least 3 characters")
			return
		}
		if ok, errs := ui.vault.ValidatePasswordAgainstVaultPolicy(password); !ok {
			errorLabel.SetText(strings.Join(errs, " · "))
			return
		}
		if password != confirm {
			errorLabel.SetText("Passwords do not match")
			return
		}

		if !ui.vault.UsersFileExists() {
			// First user — register credentials + generate TOTP secret, show QR now.
			// Vault is created on first login.
			secret, err := ui.vault.RegisterFirstAdmin(username, password, email)
			if err != nil {
				errorLabel.SetText(err.Error())
				return
			}
			// Show QR; on success, activate MFA in users file then go to login
			ui.currentUser = username
			regUsername := username // capture for closure
			regPassword := password // capture for MFA unwrap
			ui.showMFASetup(secret, true, func(code string) error {
				return ui.vault.ActivateFirstAdminMFA(regUsername, regPassword, code)
			}, func() {
				ui.currentUser = ""
				dialog.ShowInformation("Admin Account Created",
					"Your admin account and MFA are set up.\n\nPlease log in to create your vault.",
					ui.window)
				ui.showLandingScreen()
			})
			return
		}

		// Vault already exists – need the Vault Access Password
		vaultPwEntry := widget.NewPasswordEntry()
		vaultPwEntry.SetPlaceHolder("Vault Access Password (from your Administrator)")
		dlg := dialog.NewCustomConfirm(
			"Vault Access Required",
			"Add Account", "Cancel",
			container.NewVBox(
				widget.NewLabel("Enter the Vault Access Password to join this vault:"),
				vaultPwEntry,
			),
			func(confirmed bool) {
				if !confirmed {
					return
				}
				if err := ui.vault.Vault.Unlock(vaultPwEntry.Text); err != nil {
					errorLabel.SetText("Invalid Vault Access Password")
					return
				}
				ui.vault.GetAuditLog().SetHMACKey(ui.vault.Vault.GetHMACKey())
				if err := ui.vault.RegisterUser(username, password, email, models.RoleReadOnly); err != nil {
					_ = ui.vault.Vault.Lock()
					errorLabel.SetText(err.Error())
					return
				}
				// Generate and store TOTP secret while vault is still unlocked.
				// Vault will be locked after the user verifies the QR code.
				secret, err := ui.vault.SetupMFAForNewUser(username)
				if err != nil {
					_ = ui.vault.Vault.Lock()
					errorLabel.SetText("Account created but MFA setup failed: " + err.Error())
					ui.showLandingScreen()
					return
				}
				capturedUsername := username
				ui.currentUser = capturedUsername
				ui.showMFASetup(secret, true, func(code string) error {
					return ui.vault.ActivateNewUserMFA(capturedUsername, code)
				}, func() {
					_ = ui.vault.Vault.Lock()
					ui.currentUser = ""
					dialog.ShowInformation("Account Ready",
						"MFA is set up.\n\nPlease log in with your new credentials.",
						ui.window)
					ui.showLandingScreen()
				})
			}, ui.window)
		dlg.Show()
	}

	registerBtn := widget.NewButtonWithIcon("Register & Set Up MFA", theme.AccountIcon(), func() { doRegister() })
	registerBtn.Importance = widget.HighImportance
	confirmEntry.OnSubmitted = func(_ string) { doRegister() }

	reqNote := widget.NewLabelWithStyle(
		"Password must meet the configured security policy requirements",
		fyne.TextAlignCenter, fyne.TextStyle{Italic: true})
	reqNote.Importance = widget.LowImportance

	formFields := container.New(layout.NewFormLayout(),
		widget.NewLabel("Username"), usernameEntry,
		widget.NewLabel("Email (optional)"), emailEntry,
		widget.NewLabel("Password"), passwordEntry,
		widget.NewLabel("Confirm Password"), confirmEntry,
	)

	backLink := widget.NewHyperlink("← Back to Login", nil)
	backLink.OnTapped = func() { ui.showLandingScreen() }

	regCard := widget.NewCard("Create Account", "Set up your encrypted password vault",
		container.NewVBox(
			container.NewPadded(container.NewVBox(appName, appSub)),
			widget.NewSeparator(),
			reqNote,
			widget.NewSeparator(),
			container.NewPadded(formFields),
			widget.NewSeparator(),
			errorLabel,
			registerBtn,
			widget.NewSeparator(),
			container.NewCenter(backLink),
		),
	)

	ui.window.SetContent(ui.withFooter(container.NewCenter(
		container.NewVBox(
			widthEnforcer,
			container.NewPadded(regCard),
		),
	)))
}

// showNewVaultScreen is shown after the very first login following registration.
// It confirms the vault has been created and gives the user key information
// before they enter the main application.
func (ui *LocalVaultUI) showNewVaultScreen() {
	ui.onMainScreen = false
	widthEnforcer := canvas.NewRectangle(color.Transparent)
	widthEnforcer.SetMinSize(fyne.NewSize(520, 1))

	appName := widget.NewLabelWithStyle("Password Manager", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	appSub := widget.NewLabelWithStyle("Secure Enterprise Vault", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	successTitle := widget.NewLabelWithStyle(
		"Your encrypted vault is ready!",
		fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	successTitle.Importance = widget.SuccessImportance

	vaultPath := widget.NewLabelWithStyle(
		fmt.Sprintf("Vault file: %s", ui.vault.Vault.GetFilePath()),
		fyne.TextAlignCenter, fyne.TextStyle{})
	vaultPath.Importance = widget.LowImportance

	infoText := widget.NewLabelWithStyle(
		"Encrypted with AES-256-GCM  ·  Keys derived with Argon2id\nKeep your password safe — it cannot be recovered if lost.",
		fyne.TextAlignCenter, fyne.TextStyle{})
	infoText.Importance = widget.LowImportance

	continueBtn := widget.NewButtonWithIcon("Open My Vault  →", theme.NavigateNextIcon(), func() {
		ui.gotoMainScreen()
	})
	continueBtn.Importance = widget.HighImportance

	card := widget.NewCard("Vault Setup Complete", "",
		container.NewVBox(
			container.NewPadded(container.NewVBox(appName, appSub)),
			widget.NewSeparator(),
			container.NewPadded(container.NewVBox(
				successTitle,
				widget.NewSeparator(),
				vaultPath,
				infoText,
			)),
			widget.NewSeparator(),
			continueBtn,
		),
	)

	ui.window.SetContent(ui.withFooter(container.NewCenter(
		container.NewVBox(
			widthEnforcer,
			container.NewPadded(card),
		),
	)))
}

// gotoMainScreen is the post-login entry point to the main screen.
// If a vault access key is configured and not yet verified in this session,
// the key prompt is shown first. Otherwise showMainScreen is called directly.
func (ui *LocalVaultUI) gotoMainScreen() {
	if ui.vaultKeyVerified || !ui.vault.HasVaultAccessKey() {
		ui.showMainScreen()
		return
	}
	ui.showVaultKeyScreen(func() {
		ui.vaultKeyVerified = true
		ui.showMainScreen()
	})
}

// showVaultKeyScreen renders a full-screen vault access key prompt.
// onSuccess is called once the correct key is entered.
func (ui *LocalVaultUI) showVaultKeyScreen(onSuccess func()) {
	ui.onMainScreen = false
	widthEnforcer := canvas.NewRectangle(color.Transparent)
	widthEnforcer.SetMinSize(fyne.NewSize(440, 1))

	keyEntry := widget.NewPasswordEntry()
	keyEntry.SetPlaceHolder("Enter vault access key")

	errorLabel := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{})
	errorLabel.Importance = widget.DangerImportance

	attempts := 0
	var unlockBtn *widget.Button
	unlockBtn = widget.NewButtonWithIcon("Unlock Vault", theme.ConfirmIcon(), func() {
		key := keyEntry.Text
		if key == "" {
			errorLabel.SetText("Please enter the vault access key")
			return
		}
		ok, err := ui.vault.VerifyVaultAccessKey(key)
		if err != nil {
			errorLabel.SetText("Error verifying key: " + err.Error())
			return
		}
		if !ok {
			attempts++
			keyEntry.SetText("")
			if attempts >= 5 {
				dialog.ShowInformation("Too Many Attempts",
					"Too many incorrect attempts. You have been logged out.",
					ui.window)
				_ = ui.vault.Logout()
				ui.currentUser = ""
				ui.vaultKeyVerified = false
				ui.showLandingScreen()
				return
			}
			errorLabel.SetText(fmt.Sprintf("Incorrect vault key — %d attempt(s) remaining.", 5-attempts))
			return
		}
		onSuccess()
	})
	unlockBtn.Importance = widget.HighImportance
	keyEntry.OnSubmitted = func(_ string) { unlockBtn.OnTapped() }

	logoutLink := widget.NewHyperlink("← Logout", nil)
	logoutLink.OnTapped = func() {
		_ = ui.vault.Logout()
		ui.currentUser = ""
		ui.vaultKeyVerified = false
		ui.showLandingScreen()
	}

	desc := widget.NewLabelWithStyle(
		"This vault requires an additional access key.\nContact your administrator if you don't have it.",
		fyne.TextAlignCenter, fyne.TextStyle{Italic: true})
	desc.Importance = widget.LowImportance
	desc.Wrapping = fyne.TextWrapWord

	card := widget.NewCard("Vault Access Key Required", "",
		container.NewVBox(
			container.NewPadded(desc),
			widget.NewSeparator(),
			container.NewPadded(container.New(layout.NewFormLayout(),
				widget.NewLabel("Vault Key"), keyEntry,
			)),
			widget.NewSeparator(),
			errorLabel,
			unlockBtn,
			container.NewCenter(logoutLink),
		),
	)

	ui.window.SetContent(ui.withFooter(container.NewCenter(
		container.NewVBox(
			widthEnforcer,
			container.NewPadded(card),
		),
	)))
	ui.window.Canvas().Focus(keyEntry)
}

// buildVaultKeySettings returns the vault key management widget for the settings panel.
// Only shown to admins.
func (ui *LocalVaultUI) buildVaultKeySettings() fyne.CanvasObject {
	if ui.vault.HasVaultAccessKey() {
		statusLbl := widget.NewLabelWithStyle(
			"Key is set — users must enter it after login",
			fyne.TextAlignLeading, fyne.TextStyle{})
		statusLbl.Importance = widget.SuccessImportance

		changeBtn := widget.NewButtonWithIcon("Change Vault Key", theme.SettingsIcon(), func() {
			ui.showSetVaultKeyDialog(true)
		})

		removeBtn := widget.NewButtonWithIcon("Remove Vault Key", theme.DeleteIcon(), func() {
			dialog.ShowConfirm("Remove Vault Key",
				"Remove the vault access key? Users will no longer need it after login.",
				func(ok bool) {
					if !ok {
						return
					}
					if err := ui.vault.ClearVaultAccessKey(); err != nil {
						ui.showError("Failed to remove vault key", err)
						return
					}
					ui.showNotification("Vault access key removed")
					ui.showSettings()
				}, ui.window)
		})
		removeBtn.Importance = widget.DangerImportance

		return container.NewVBox(statusLbl, changeBtn, removeBtn)
	}

	statusLbl := widget.NewLabelWithStyle(
		"No key set — anyone who logs in can access secrets",
		fyne.TextAlignLeading, fyne.TextStyle{})
	statusLbl.Importance = widget.LowImportance

	setBtn := widget.NewButtonWithIcon("Set Vault Key", theme.ContentAddIcon(), func() {
		ui.showSetVaultKeyDialog(false)
	})
	setBtn.Importance = widget.HighImportance

	return container.NewVBox(statusLbl, setBtn)
}

// showSetVaultKeyDialog shows an admin dialog to set or change the vault access key.
func (ui *LocalVaultUI) showSetVaultKeyDialog(isChange bool) {
	newKeyEntry := widget.NewPasswordEntry()
	newKeyEntry.SetPlaceHolder("New vault key (min 8 characters)")
	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("Confirm vault key")

	title := "Set Vault Access Key"
	if isChange {
		title = "Change Vault Access Key"
	}

	dlg := dialog.NewCustomConfirm(title, "Save", "Cancel",
		container.NewVBox(
			widget.NewLabel("All users must enter this key after login to access secrets."),
			widget.NewSeparator(),
			widget.NewLabel("New Key:"),
			newKeyEntry,
			widget.NewLabel("Confirm Key:"),
			confirmEntry,
		),
		func(confirmed bool) {
			if !confirmed {
				return
			}
			key := newKeyEntry.Text
			if len(key) < 8 {
				dialog.ShowError(fmt.Errorf("vault key must be at least 8 characters"), ui.window)
				return
			}
			if key != confirmEntry.Text {
				dialog.ShowError(fmt.Errorf("keys do not match"), ui.window)
				return
			}
			if err := ui.vault.SetVaultAccessKey(key); err != nil {
				ui.showError("Failed to set vault key", err)
				return
			}
			ui.vaultKeyVerified = true // admin is already in-session
			ui.showNotification("Vault access key saved — all users will be prompted on next login")
			ui.showSettings()
		}, ui.window)
	dlg.Resize(fyne.NewSize(420, 300))
	dlg.Show()
}

// showMainScreen shows the main password manager interface
func (ui *LocalVaultUI) showMainScreen() {
	// Start session timers (Req 3.6)
	// Policy values are re-read on every tick so that admin changes take effect
	// without requiring the user to log out and back in.
	sessionStart := time.Now()
	ui.activityMu.Lock()
	ui.lastActivity = sessionStart
	ui.activityMu.Unlock()
	if ui.activityCancel != nil {
		close(ui.activityCancel)
	}
	// Also stop the old separate tamper goroutine if running.
	if ui.vaultTamperStop != nil {
		close(ui.vaultTamperStop)
		ui.vaultTamperStop = nil
	}
	ui.activityCancel = make(chan struct{})
	cancelCh := ui.activityCancel

	ui.onMainScreen = true

	// Create sidebar
	sidebar := ui.createSidebar()

	// Create main content area
	ui.content = container.NewMax()
	ui.showSecretsList()

	// Split layout
	split := container.NewHSplit(sidebar, ui.content)
	split.Offset = 0.2

	// ── Vault file tamper warning banner ───────────────────────────────────────
	tamperBanner := widget.NewLabelWithStyle(
		"WARNING: Vault file has been modified externally — possible tampering detected! Verify your data immediately.",
		fyne.TextAlignCenter, fyne.TextStyle{Bold: true},
	)
	tamperBanner.Importance = widget.DangerImportance
	tamperBanner.Hide()

	// Single combined ticker: session timeouts + tamper detection (was two goroutines).
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-cancelCh:
				return
			case <-ticker.C:
				if !ui.vault.Vault.IsUnlocked() {
					return
				}
				// Re-read policy on every tick so admin changes apply immediately.
				inactivityTimeout := 15 * time.Minute
				sessionTimeout := time.Duration(0)
				if policy, pErr := ui.vault.GetSecurityPolicy(); pErr == nil && policy != nil {
					if policy.InactivityTimeoutMin > 0 {
						inactivityTimeout = time.Duration(policy.InactivityTimeoutMin) * time.Minute
					}
					if policy.SessionTimeoutMins > 0 {
						sessionTimeout = time.Duration(policy.SessionTimeoutMins) * time.Minute
					}
				}
				// Absolute session timeout (wall-clock since login)
				if sessionTimeout > 0 && time.Since(sessionStart) >= sessionTimeout {
					_ = ui.vault.Logout()
					ui.app.SendNotification(&fyne.Notification{
						Title:   "Session Expired",
						Content: "Your session has timed out. Please log in again.",
					})
					ui.currentUser = ""
					ui.showLandingScreen()
					return
				}
				// Inactivity timeout (idle since last action)
				ui.activityMu.RLock()
				last := ui.lastActivity
				ui.activityMu.RUnlock()
				if time.Since(last) >= inactivityTimeout {
					_ = ui.vault.Logout()
					ui.app.SendNotification(&fyne.Notification{
						Title:   "Locked",
						Content: "Vault locked due to inactivity.",
					})
					ui.currentUser = ""
					ui.showLandingScreen()
					return
				}
				// Tamper detection (merged from separate 5s goroutine)
				if ui.vault.CheckVaultTampered() {
					tamperBanner.Show()
					tamperBanner.Refresh()
					user := ui.currentUser
					ui.vault.GetAuditLog().LogEvent(
						user,
						"VAULT_FILE_TAMPER_DETECTED",
						"security",
						"Vault .pwm file modified externally — possible tampering",
						"failure",
					)
				} else {
					tamperBanner.Hide()
				}
			}
		}
	}()

	mainLayout := container.NewBorder(
		container.NewPadded(tamperBanner), nil, nil, nil,
		split,
	)
	ui.window.SetContent(ui.withFooter(mainLayout))
}

// createSidebar creates the navigation sidebar
func (ui *LocalVaultUI) createSidebar() fyne.CanvasObject {
	// ── App header ────────────────────────────────────────────────────────────
	appIcon := widget.NewIcon(theme.StorageIcon())
	appTitle := widget.NewLabelWithStyle("Password Manager", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	appVersion := widget.NewLabelWithStyle("v1.0", fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
	appVersion.Importance = widget.LowImportance
	appHeader := container.NewHBox(
		appIcon,
		container.NewVBox(appTitle, appVersion),
	)

	// ── User avatar ───────────────────────────────────────────────────────────
	initial := "?"
	if len(ui.currentUser) > 0 {
		r := []rune(ui.currentUser)
		initial = strings.ToUpper(string(r[0:1]))
	}
	avatarBg := canvas.NewRectangle(accentColor())
	avatarBg.CornerRadius = 20
	avatarBg.SetMinSize(fyne.NewSize(40, 40))
	avatarText := canvas.NewText(initial, color.White)
	avatarText.TextSize = 17
	avatarText.TextStyle = fyne.TextStyle{Bold: true}
	avatarText.Alignment = fyne.TextAlignCenter
	avatar := container.NewStack(avatarBg, container.NewCenter(avatarText))

	userLabel := widget.NewLabelWithStyle(ui.currentUser, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	roleLabel := widget.NewLabelWithStyle(ui.vault.GetRole(), fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
	roleLabel.Importance = widget.LowImportance
	userCard := container.NewHBox(
		avatar,
		container.NewVBox(userLabel, roleLabel),
	)

	// ── Nav button helpers ────────────────────────────────────────────────────
	var (
		secretsBtn  *widget.Button
		addBtn      *widget.Button
		searchBtn   *widget.Button
		settingsBtn *widget.Button
		adminBtn    *widget.Button
	)
	allNavBtns := func() []*widget.Button {
		btns := []*widget.Button{secretsBtn, addBtn, searchBtn, settingsBtn, adminBtn}
		var result []*widget.Button
		for _, b := range btns {
			if b != nil {
				result = append(result, b)
			}
		}
		return result
	}
	setActive := func(active *widget.Button) {
		for _, b := range allNavBtns() {
			if b == active {
				b.Importance = widget.HighImportance
			} else {
				b.Importance = widget.LowImportance
			}
			b.Refresh()
		}
	}

	// ── Nav buttons ───────────────────────────────────────────────────────────
	secretsBtn = widget.NewButtonWithIcon("  Secrets", theme.ListIcon(), func() {
		setActive(secretsBtn)
		ui.showSecretsList()
	})
	secretsBtn.Alignment = widget.ButtonAlignLeading
	secretsBtn.Importance = widget.HighImportance

	addBtn = widget.NewButtonWithIcon("  Add Secret", theme.ContentAddIcon(), func() {
		setActive(addBtn)
		ui.showAddSecret()
	})
	addBtn.Alignment = widget.ButtonAlignLeading
	addBtn.Importance = widget.LowImportance

	searchBtn = widget.NewButtonWithIcon("  Search", theme.SearchIcon(), func() {
		setActive(searchBtn)
		ui.showSearch()
	})
	searchBtn.Alignment = widget.ButtonAlignLeading
	searchBtn.Importance = widget.LowImportance

	settingsBtn = widget.NewButtonWithIcon("  Settings", theme.SettingsIcon(), func() {
		setActive(settingsBtn)
		ui.showSettings()
	})
	settingsBtn.Alignment = widget.ButtonAlignLeading
	settingsBtn.Importance = widget.LowImportance

	lockBtn := widget.NewButtonWithIcon("  Lock Vault", theme.LogoutIcon(), func() {
		dialog.ShowConfirm("Lock Vault",
			"Lock the vault and return to the login screen?",
			func(ok bool) {
				if !ok {
					return
				}
				_ = ui.vault.Logout()
				ui.currentUser = ""
				ui.showLandingScreen()
			}, ui.window)
	})
	lockBtn.Importance = widget.DangerImportance
	lockBtn.Alignment = widget.ButtonAlignLeading

	hasPerm := func(permission string) bool {
		return ui.vault.HasPermission(permission)
	}

	// ── Build sidebar layout ──────────────────────────────────────────────────
	navItems := []fyne.CanvasObject{
		container.NewPadded(appHeader),
		widget.NewSeparator(),
		container.NewPadded(userCard),
		widget.NewSeparator(),
		secretsBtn,
	}

	if hasPerm(auth.CanCreateSecret) {
		navItems = append(navItems, addBtn)
	}
	if hasPerm(auth.CanViewSecrets) {
		navItems = append(navItems, searchBtn)
	}

	navItems = append(navItems,
		widget.NewSeparator(),
		settingsBtn,
	)

	if hasPerm(auth.CanViewUsers) || hasPerm(auth.CanViewAuditLogs) || hasPerm(auth.CanManagePolicy) || hasPerm(auth.CanManageSessions) || hasPerm(auth.CanExportData) {
		adminBtn = widget.NewButtonWithIcon("  Admin Dashboard", theme.GridIcon(), func() {
			setActive(adminBtn)
			ui.showAdminDashboard()
		})
		adminBtn.Alignment = widget.ButtonAlignLeading
		adminBtn.Importance = widget.LowImportance
		navItems = append(navItems, widget.NewSeparator(), adminBtn)
	}

	aboutBtn := widget.NewButtonWithIcon("  About", theme.InfoIcon(), func() {
		ui.showAboutDialog()
	})
	aboutBtn.Alignment = widget.ButtonAlignLeading
	aboutBtn.Importance = widget.LowImportance

	navItems = append(navItems, layout.NewSpacer(), widget.NewSeparator(), aboutBtn, lockBtn)

	sidebarContent := container.NewPadded(container.NewVBox(navItems...))

	bg := canvas.NewRectangle(sidebarBgColor())
	return container.NewStack(bg, sidebarContent)
}

// showSecretsList shows the list of secrets
func (ui *LocalVaultUI) showSecretsList() {
	ui.resetActivity()
	secrets, err := ui.vault.ListSecrets()
	if err != nil {
		ui.showError("Failed to load secrets", err)
		return
	}

	// Filter out system entries
	var filteredSecrets []*vault.SecretData
	for _, s := range secrets {
		if s.Category != "__SYSTEM__" {
			filteredSecrets = append(filteredSecrets, s)
		}
	}

	title := widget.NewLabelWithStyle("Your Secrets", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	countLabel := widget.NewLabel(fmt.Sprintf("%d secrets stored", len(filteredSecrets)))
	countLabel.Importance = widget.LowImportance

	addSecretBtn := widget.NewButtonWithIcon("+ Add Secret", theme.ContentAddIcon(), func() {
		ui.showAddSecret()
	})
	addSecretBtn.Importance = widget.HighImportance

	pageHeader := container.NewPadded(container.NewVBox(
		container.NewHBox(title, layout.NewSpacer(), addSecretBtn),
		countLabel,
		widget.NewSeparator(),
	))

	if len(filteredSecrets) == 0 {
		emptyTitle := widget.NewLabelWithStyle("No Secrets Yet", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
		emptyDesc := widget.NewLabelWithStyle(
			"Use the '+ Add Secret' button above to create your first secure entry.",
			fyne.TextAlignCenter, fyne.TextStyle{},
		)
		emptyDesc.Importance = widget.LowImportance
		addFirstBtn := widget.NewButtonWithIcon("Create First Secret", theme.ContentAddIcon(), func() {
			ui.showAddSecret()
		})
		addFirstBtn.Importance = widget.HighImportance

		emptyCard := widget.NewCard("Vault is empty", "Securely store passwords, API keys, and more", container.NewVBox(
			container.NewPadded(container.NewVBox(emptyTitle, emptyDesc)),
			container.NewCenter(addFirstBtn),
		))

		ui.content.Objects = []fyne.CanvasObject{
			container.NewBorder(pageHeader, nil, nil, nil,
				container.NewCenter(container.NewPadded(emptyCard)),
			),
		}
		ui.content.Refresh()
		return
	}

	// List rows: [0]=icon  [1]=VBox(name,user)  [2]=spacer  [3]=Stack(pill,catLabel)
	list := widget.NewList(
		func() int { return len(filteredSecrets) },
		func() fyne.CanvasObject {
			nameLabel := widget.NewLabelWithStyle("Secret Name", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			userLabel := widget.NewLabelWithStyle("username", fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
			userLabel.Importance = widget.LowImportance
			catLabel := widget.NewLabel("category")
			catLabel.Importance = widget.LowImportance
			pill := canvas.NewRectangle(color.RGBA{R: 47, G: 129, B: 247, A: 40})
			pill.CornerRadius = 10
			catBadge := container.NewStack(pill, container.NewPadded(catLabel))
			minH := canvas.NewRectangle(color.Transparent)
			minH.SetMinSize(fyne.NewSize(0, 48))
			return container.NewStack(
				minH,
				container.NewHBox(
					container.NewCenter(widget.NewIcon(theme.DocumentIcon())),
					container.NewVBox(nameLabel, userLabel),
					layout.NewSpacer(),
					container.NewCenter(catBadge),
				),
			)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i >= len(filteredSecrets) {
				return
			}
			secret := filteredSecrets[i]
			outer := o.(*fyne.Container) // Stack(minH, HBox)
			row := outer.Objects[1].(*fyne.Container) // HBox

			// [1] = VBox(nameLabel, userLabel)
			centre := row.Objects[1].(*fyne.Container)
			centre.Objects[0].(*widget.Label).SetText(secret.Name)

			userHint := secret.Username
			if userHint == "" {
				userHint = secret.URL
			}
			if userHint == "" {
				userHint = "no username"
			}
			centre.Objects[1].(*widget.Label).SetText(userHint)

			// [3] = Center(Stack(pill, Padded(catLabel)))
			centeredBadge := row.Objects[3].(*fyne.Container)
			badge := centeredBadge.Objects[0].(*fyne.Container)
			padded := badge.Objects[1].(*fyne.Container)
			cat := secret.Category
			if cat == "" {
				cat = "uncategorised"
			}
			padded.Objects[0].(*widget.Label).SetText(cat)
		},
	)

	list.OnSelected = func(id widget.ListItemID) {
		ui.showSecretDetails(filteredSecrets[id])
		list.UnselectAll()
	}

	ui.content.Objects = []fyne.CanvasObject{
		container.NewBorder(pageHeader, nil, nil, nil, list),
	}
	ui.content.Refresh()
}

// showSecretDetails shows details of a secret
func (ui *LocalVaultUI) showSecretDetails(secret *vault.SecretData) {
	ui.resetActivity()
	// Fetch full decrypted secret via audited call — the list may contain scrubbed entries.
	full, err := ui.vault.GetSecretAudited(secret.ID)
	if err != nil {
		ui.showError("Failed to load secret", err)
		return
	}
	secret = full
	title := widget.NewLabelWithStyle(secret.Name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	// Fields
	usernameEntry := widget.NewEntry()
	usernameEntry.SetText(secret.Username)
	usernameEntry.Disable()

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetText(secret.Password)
	passwordEntry.Disable()

	urlEntry := widget.NewEntry()
	urlEntry.SetText(secret.URL)
	urlEntry.Disable()

	notesEntry := widget.NewMultiLineEntry()
	notesEntry.SetText(secret.Notes)
	notesEntry.Disable()

	cat := secret.Category
	if cat == "" {
		cat = "uncategorised"
	}
	categoryLabel := widget.NewLabel(cat)
	categoryLabel.Importance = widget.LowImportance

	var tagsStr string
	if len(secret.Tags) > 0 {
		tagsStr = strings.Join(secret.Tags, ", ")
	} else {
		tagsStr = "—"
	}
	tagsLabel := widget.NewLabel(tagsStr)
	tagsLabel.Importance = widget.LowImportance

	// Action buttons
	var copyUserBtn, copyPassBtn *widget.Button
	if ui.vault.HasPermission(auth.CanCopySecret) {
		copyUserBtn = widget.NewButtonWithIcon("Copy Username", theme.ContentCopyIcon(), func() {
			if ui.clipboardManager != nil {
				_ = ui.clipboardManager.CopyToClipboard(secret.Username)
			} else {
				ui.window.Clipboard().SetContent(secret.Username)
			}
			ui.showNotification("Username copied (auto-clears in 30s)")
		})

		copyPassBtn = widget.NewButtonWithIcon("Copy Password", theme.ContentCopyIcon(), func() {
			if ui.clipboardManager != nil {
				_ = ui.clipboardManager.CopyToClipboard(secret.Password)
			} else {
				ui.window.Clipboard().SetContent(secret.Password)
			}
			ui.showNotification("Password copied (auto-clears in 30s)")
		})
	} else {
		// Disabled placeholders to preserve layout when copying is not permitted
		copyUserBtn = widget.NewButtonWithIcon("Copy Username", theme.ContentCopyIcon(), nil)
		copyUserBtn.Disable()
		copyPassBtn = widget.NewButtonWithIcon("Copy Password", theme.ContentCopyIcon(), nil)
		copyPassBtn.Disable()
	}

	editBtn := widget.NewButtonWithIcon("Edit", theme.DocumentCreateIcon(), func() {
		ui.showEditSecret(secret)
	})

	deleteBtn := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), func() {
		dialog.ShowConfirm("Delete Secret",
			fmt.Sprintf("Are you sure you want to delete '%s'?", secret.Name),
			func(ok bool) {
				if ok {
					if err := ui.vault.DeleteSecretAudited(secret.ID); err != nil {
						ui.showError("Failed to delete", err)
					} else {
						ui.showSecretsList()
					}
				}
			}, ui.window)
	})
	deleteBtn.Importance = widget.DangerImportance

	backBtn := widget.NewButtonWithIcon("Back", theme.NavigateBackIcon(), func() {
		ui.showSecretsList()
	})

	historyBtn := widget.NewButtonWithIcon("History", theme.HistoryIcon(), func() {
		ui.showPasswordHistory(secret)
	})

	shareBtn := widget.NewButtonWithIcon("Share", theme.AccountIcon(), func() {
		ui.showShareSecretDialog(secret)
	})

	// ── Permission-gated action bar ──────────────────────────────────────────
	// Determine what the current user may do on this secret.
	//
	// Rules:
	//  1. The user's ROLE defines the ceiling (ReadOnly cannot edit/delete).
	//  2. For shared secrets (the user is a grantee, not the owner) the
	//     per-secret grant flags provide an additional restriction.
	//  3. Only the secret owner may manage sharing.
	role := ui.vault.GetRole()
	rolePerms, _ := auth.GetRolePermissions(role)
	hasRolePerm := func(p string) bool {
		for _, rp := range rolePerms {
			if rp == p {
				return true
			}
		}
		return false
	}

	sm := vault.NewSharedCredentialManager(ui.vault)
	owner := sm.GetOwner(secret.ID)
	// If no explicit share metadata exists, fall back to the CreatedBy owner field.
	if owner == "" {
		owner = secret.CreatedBy
	}
	isOwner := strings.EqualFold(owner, ui.currentUser)

	canEdit := hasRolePerm(auth.CanEditSecret)
	canDelete := hasRolePerm(auth.CanDeleteSecret)

	if !isOwner {
		// Grantee path: the per-secret share grant overrides the role ceiling.
		// A read_only user explicitly granted CanUpdate or CanDelete on this
		// specific secret should see those buttons — the grant is intentional.
		access := sm.GetGranteeAccess(secret.ID, ui.currentUser)
		if access != nil {
			canEdit = access.CanUpdate
			canDelete = access.CanDelete
		} else {
			canEdit = false
			canDelete = false
		}
	}

	// Only the owner (with edit permission) may share a secret with others.
	canShare := isOwner && canEdit

	// Build the action row dynamically so no forbidden buttons leak through.
	actionItems := []fyne.CanvasObject{}
	// Copy actions only shown when copy permission exists (copy buttons are already disabled when not permitted)
	actionItems = append(actionItems, copyUserBtn, copyPassBtn)
	if canEdit {
		actionItems = append(actionItems, editBtn)
	}
	// history button only visible to administrators
	if ui.vault.HasPermission(auth.CanManagePolicy) {
		actionItems = append(actionItems, historyBtn)
	}
	if canShare {
		actionItems = append(actionItems, shareBtn)
	}
	if canDelete {
		actionItems = append(actionItems, deleteBtn)
	}
	actionItems = append(actionItems, layout.NewSpacer(), backBtn)

	// Metadata row — uses only available SecretData fields
	versionCount := len(secret.PasswordHistory) + 1
	versionLabel := widget.NewLabelWithStyle(
		fmt.Sprintf("Created: %s  ·  Updated: %s  ·  Versions: %d",
			secret.CreatedAt.Format("2006-01-02"),
			secret.UpdatedAt.Format("2006-01-02 15:04"),
			versionCount,
		),
		fyne.TextAlignLeading, fyne.TextStyle{Italic: true},
	)
	versionLabel.Importance = widget.LowImportance

	credCard := widget.NewCard("Credentials", "", container.NewVBox(
		container.New(layout.NewFormLayout(),
			widget.NewLabel("Username"), usernameEntry,
			widget.NewLabel("Password"), passwordEntry,
			widget.NewLabel("URL"), urlEntry,
		),
	))

	var metaItems []fyne.CanvasObject
	metaItems = append(metaItems,
		container.New(layout.NewFormLayout(),
			widget.NewLabel("Category"), categoryLabel,
			widget.NewLabel("Tags"), tagsLabel,
		),
	)
	if notesEntry.Text != "" {
		metaItems = append(metaItems, widget.NewSeparator(), widget.NewLabel("Notes"), notesEntry)
	}
	metaCard := widget.NewCard("Details", "", container.NewVBox(metaItems...))

	actionBar := container.NewPadded(container.NewHBox(actionItems...))

	form := container.NewVBox(
		container.NewPadded(container.NewVBox(
			title,
			versionLabel,
		)),
		widget.NewSeparator(),
		container.NewPadded(credCard),
		container.NewPadded(metaCard),
		widget.NewSeparator(),
		actionBar,
	)

	ui.content.Objects = []fyne.CanvasObject{container.NewScroll(form)}
	ui.content.Refresh()
}

// escapeCSV quotes fields containing commas, quotes or newlines per RFC4180
func escapeCSV(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		s2 := strings.ReplaceAll(s, "\"", "\"\"")
		return "\"" + s2 + "\""
	}
	return s
}

// showAddSecret shows the add secret form
func (ui *LocalVaultUI) showAddSecret() {
	ui.resetActivity()
	if !ui.vault.HasPermission(auth.CanCreateSecret) {
		ui.showError("Permission denied", fmt.Errorf("missing %s", auth.CanCreateSecret))
		return
	}
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Secret Name")

	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password")

	urlEntry := widget.NewEntry()
	urlEntry.SetPlaceHolder("URL (optional)")

	notesEntry := widget.NewMultiLineEntry()
	notesEntry.SetPlaceHolder("Notes (optional)")
	notesEntry.SetMinRowsVisible(3)

	categorySelect := widget.NewSelect(
		[]string{"login", "api", "wifi", "server", "database", "other"},
		nil,
	)
	categorySelect.SetSelected("login")

	tagsEntry := widget.NewEntry()
	tagsEntry.SetPlaceHolder("Tags (comma-separated)")

	errorLabel := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{})
	errorLabel.Importance = widget.DangerImportance

	// Generate password button
	generateBtn := widget.NewButtonWithIcon("Generate", theme.ViewRefreshIcon(), func() {
		if !ui.vault.HasPermission(auth.CanRotateSecret) {
			ui.showError("Permission denied", fmt.Errorf("missing %s", auth.CanRotateSecret))
			return
		}
		password := generateSecurePassword(20)
		passwordEntry.SetText(password)
	})

	saveBtn := widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), func() {
		errorLabel.SetText("")

		name := strings.TrimSpace(nameEntry.Text)
		if name == "" {
			errorLabel.SetText("Name is required")
			return
		}

		password := passwordEntry.Text
		if password == "" {
			errorLabel.SetText("Password is required")
			return
		}

		// Parse tags
		var tags []string
		if tagsEntry.Text != "" {
			for _, t := range strings.Split(tagsEntry.Text, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					tags = append(tags, t)
				}
			}
		}

		secret := &vault.SecretData{
			Name:     name,
			Username: strings.TrimSpace(usernameEntry.Text),
			Password: password,
			URL:      strings.TrimSpace(urlEntry.Text),
			Notes:    notesEntry.Text,
			Category: categorySelect.Selected,
			Tags:     tags,
		}

		if err := ui.vault.AddSecretAudited(secret); err != nil {
			errorLabel.SetText(err.Error())
			return
		}

		ui.showNotification("Secret saved successfully")
		ui.showSecretsList()
	})
	saveBtn.Importance = widget.HighImportance

	cancelBtn := widget.NewButtonWithIcon("Cancel", theme.CancelIcon(), func() {
		ui.showSecretsList()
	})

	strengthLabel := widget.NewLabelWithStyle("Strength: —", fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
	strengthLabel.Importance = widget.LowImportance
	passwordEntry.OnChanged = func(pw string) {
		label, imp := passwordStrength(pw)
		strengthLabel.SetText("Strength: " + label)
		strengthLabel.Importance = imp
		strengthLabel.Refresh()
	}

	formCard := widget.NewCard("New Secret", "Fields marked * are required", container.NewVBox(
		container.New(layout.NewFormLayout(),
			widget.NewLabel("Name *"), nameEntry,
			widget.NewLabel("Username"), usernameEntry,
			widget.NewLabel("Password *"), container.NewBorder(nil, nil, nil, generateBtn, passwordEntry),
			widget.NewLabel("URL"), urlEntry,
			widget.NewLabel("Category"), categorySelect,
			widget.NewLabel("Tags"), tagsEntry,
		),
		strengthLabel,
		widget.NewSeparator(),
		widget.NewLabel("Notes"),
		notesEntry,
	))

	form := container.NewVBox(
		container.NewPadded(formCard),
		container.NewPadded(container.NewVBox(
			errorLabel,
			container.NewHBox(saveBtn, cancelBtn),
		)),
	)

	ui.content.Objects = []fyne.CanvasObject{container.NewScroll(form)}
	ui.content.Refresh()
}

// showEditSecret shows the edit secret form
func (ui *LocalVaultUI) showEditSecret(secret *vault.SecretData) {
	// Ensure we have the full decrypted secret (list items may be scrubbed)
	full, err := ui.vault.GetSecretAudited(secret.ID)
	if err != nil {
		ui.showError("Failed to load secret for edit", err)
		return
	}
	secret = full
	nameEntry := widget.NewEntry()
	nameEntry.SetText(secret.Name)

	usernameEntry := widget.NewEntry()
	usernameEntry.SetText(secret.Username)

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetText(secret.Password)

	urlEntry := widget.NewEntry()
	urlEntry.SetText(secret.URL)

	notesEntry := widget.NewMultiLineEntry()
	notesEntry.SetText(secret.Notes)
	notesEntry.SetMinRowsVisible(3)

	categorySelect := widget.NewSelect(
		[]string{"login", "api", "wifi", "server", "database", "other"},
		nil,
	)
	categorySelect.SetSelected(secret.Category)

	tagsEntry := widget.NewEntry()
	tagsEntry.SetText(strings.Join(secret.Tags, ", "))

	errorLabel := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{})
	errorLabel.Importance = widget.DangerImportance

	generateBtn := widget.NewButtonWithIcon("Generate", theme.ViewRefreshIcon(), func() {
		password := generateSecurePassword(20)
		passwordEntry.SetText(password)
	})

	saveBtn := widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), func() {
		errorLabel.SetText("")

		name := strings.TrimSpace(nameEntry.Text)
		if name == "" {
			errorLabel.SetText("Name is required")
			return
		}

		password := passwordEntry.Text
		if password == "" {
			errorLabel.SetText("Password is required")
			return
		}

		// Parse tags
		var tags []string
		if tagsEntry.Text != "" {
			for _, t := range strings.Split(tagsEntry.Text, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					tags = append(tags, t)
				}
			}
		}

		updated := &vault.SecretData{
			ID:       secret.ID,
			Name:     name,
			Username: strings.TrimSpace(usernameEntry.Text),
			Password: password,
			URL:      strings.TrimSpace(urlEntry.Text),
			Notes:    notesEntry.Text,
			Category: categorySelect.Selected,
			Tags:     tags,
		}

		if err := ui.vault.UpdateSecretAudited(updated); err != nil {
			errorLabel.SetText(err.Error())
			return
		}

		ui.showNotification("Secret updated successfully")
		ui.showSecretsList()
	})
	saveBtn.Importance = widget.HighImportance

	cancelBtn := widget.NewButtonWithIcon("Cancel", theme.CancelIcon(), func() {
		ui.showSecretDetails(secret)
	})

	var historyBtn fyne.CanvasObject
	if ui.vault.HasPermission(auth.CanManagePolicy) {
		historyBtn = widget.NewButtonWithIcon("Password History", theme.HistoryIcon(), func() {
			ui.showPasswordHistory(secret)
		})
	}

	strengthLabel := widget.NewLabelWithStyle("Strength: —", fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
	strengthLabel.Importance = widget.LowImportance
	// Initialise with current password strength
	{
		label, imp := passwordStrength(secret.Password)
		strengthLabel.SetText("Strength: " + label)
		strengthLabel.Importance = imp
	}
	passwordEntry.OnChanged = func(pw string) {
		label, imp := passwordStrength(pw)
		strengthLabel.SetText("Strength: " + label)
		strengthLabel.Importance = imp
		strengthLabel.Refresh()
	}

	editCard := widget.NewCard("Edit Secret", secret.Name, container.NewVBox(
		container.New(layout.NewFormLayout(),
			widget.NewLabel("Name *"), nameEntry,
			widget.NewLabel("Username"), usernameEntry,
			widget.NewLabel("Password *"), container.NewBorder(nil, nil, nil, generateBtn, passwordEntry),
			widget.NewLabel("URL"), urlEntry,
			widget.NewLabel("Category"), categorySelect,
			widget.NewLabel("Tags"), tagsEntry,
		),
		strengthLabel,
		widget.NewSeparator(),
		widget.NewLabel("Notes"),
		notesEntry,
	))

	actionItems := []fyne.CanvasObject{saveBtn, cancelBtn}
	if historyBtn != nil {
		actionItems = append(actionItems, historyBtn)
	}

	form := container.NewVBox(
		container.NewPadded(editCard),
		container.NewPadded(container.NewVBox(
			errorLabel,
			container.NewHBox(actionItems...),
		)),
	)

	ui.content.Objects = []fyne.CanvasObject{container.NewScroll(form)}
	ui.content.Refresh()
}

// showShareSecretDialog opens a dialog to share or view sharing for a secret.
func (ui *LocalVaultUI) showShareSecretDialog(secret *vault.SecretData) {
	shareManager := vault.NewSharedCredentialManager(ui.vault)

	// Current shares
	shares, _ := shareManager.ListSharedWith(secret.ID)

	// Other users to share with (minimal, non-sensitive user listing)
	usernames, _ := ui.vault.ListShareableUsernames()

	var shareSection fyne.CanvasObject
	if len(usernames) == 0 {
		shareSection = widget.NewLabel("No other users to share with.")
	} else {
		userSelect := widget.NewSelect(usernames, nil)
		userSelect.PlaceHolder = "Select user..."
		canUpdateChk := widget.NewCheck("Can edit", nil)
		canDeleteChk := widget.NewCheck("Can delete", nil)
		errLbl := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{})
		errLbl.Importance = widget.DangerImportance

		grantBtn := widget.NewButtonWithIcon("Grant Access", theme.ConfirmIcon(), func() {
			if userSelect.Selected == "" {
				errLbl.SetText("Please select a user")
				return
			}
			if err := shareManager.ShareSecret(
				ui.currentUser, secret.ID, userSelect.Selected,
				true, canUpdateChk.Checked, canDeleteChk.Checked, nil,
			); err != nil {
				errLbl.SetText(err.Error())
				return
			}
			dialog.ShowInformation("Shared",
				fmt.Sprintf("Access granted to %s", userSelect.Selected), ui.window)
			ui.showShareSecretDialog(secret)
		})
		grantBtn.Importance = widget.HighImportance

		shareSection = container.NewVBox(
			widget.NewLabelWithStyle("Grant access to:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			userSelect,
			container.NewHBox(canUpdateChk, canDeleteChk),
			grantBtn,
			errLbl,
		)
	}

	// ─ Current shares list ─
	var sharesSection fyne.CanvasObject
	if len(shares) == 0 {
		sharesSection = widget.NewLabel("Not currently shared with anyone.")
	} else {
		headerRow := container.NewGridWithColumns(4,
			boldLabel("User"), boldLabel("Edit"), boldLabel("Delete"), boldLabel("Actions"),
		)
		rows := []fyne.CanvasObject{headerRow}
		for _, a := range shares {
			a := a // capture
			editTxt := "No"
			if a.CanUpdate {
				editTxt = "Yes"
			}
			deleteTxt := "No"
			if a.CanDelete {
				deleteTxt = "Yes"
			}
			revokeBtn := widget.NewButtonWithIcon("Revoke", theme.CancelIcon(), func() {
				dialog.ShowConfirm("Revoke Access",
					fmt.Sprintf("Revoke %s's access?", a.Username),
					func(ok bool) {
						if !ok {
							return
						}
						if err := shareManager.RevokeShare(ui.currentUser, secret.ID, a.Username); err != nil {
							dialog.ShowError(err, ui.window)
							return
						}
						ui.showShareSecretDialog(secret)
					}, ui.window)
			})
			revokeBtn.Importance = widget.DangerImportance
			rows = append(rows, container.NewGridWithColumns(4,
				widget.NewLabel(a.Username),
				widget.NewLabel(editTxt),
				widget.NewLabel(deleteTxt),
				revokeBtn,
			))
		}
		sharesSection = container.NewVBox(rows...)
	}

	content := container.NewVBox(
		widget.NewLabelWithStyle(fmt.Sprintf("Sharing: %s", secret.Name), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Current access", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		sharesSection,
		widget.NewSeparator(),
		shareSection,
	)

	scroll := container.NewVScroll(content)
	scroll.SetMinSize(fyne.NewSize(460, 320))
	d := dialog.NewCustom("Shared Access", "Close", scroll, ui.window)
	d.Resize(fyne.NewSize(500, 440))
	d.Show()
}

// boldLabel is a helper used inside sharing dialog.
func boldLabel(text string) *widget.Label {
	return widget.NewLabelWithStyle(text, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
}

// showPasswordHistory shows password history for a secret
func (ui *LocalVaultUI) showPasswordHistory(secret *vault.SecretData) {
	// Only administrators may view password history
	if !ui.vault.HasPermission(auth.CanManagePolicy) {
		ui.showError("Permission denied", fmt.Errorf("only administrators may view password history"))
		return
	}
	title := widget.NewLabelWithStyle(fmt.Sprintf("Password History: %s", secret.Name), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	history, err := ui.vault.GetPasswordHistory(secret.ID)
	if err != nil {
		ui.showError("Failed to load history", err)
		return
	}

	var items []fyne.CanvasObject
	items = append(items, title, widget.NewSeparator())

	if len(history) == 0 {
		items = append(items, widget.NewLabel("No password history available"))
	} else {
		for i := range history {
			h := history[i]
			idx := len(history) - i // Show newest first
			// History entries now store salted hashes; do not expose or allow copying
			entry := container.NewVBox(
				widget.NewLabel(fmt.Sprintf("#%d - Changed: %s", idx, h.ChangedAt.Format("2006-01-02 15:04"))),
				widget.NewLabel("Password: [redacted]"),
			)
			items = append(items, container.NewHBox(entry))
			items = append(items, widget.NewSeparator())
		}
	}

	backBtn := widget.NewButtonWithIcon("Back", theme.NavigateBackIcon(), func() {
		ui.showSecretDetails(secret)
	})
	items = append(items, backBtn)

	ui.content.Objects = []fyne.CanvasObject{container.NewScroll(container.NewVBox(items...))}
	ui.content.Refresh()
}

// showSearch shows the search interface
func (ui *LocalVaultUI) showSearch() {
	ui.resetActivity()
	if !ui.vault.HasPermission(auth.CanViewSecrets) {
		ui.showError("Permission denied", fmt.Errorf("missing %s", auth.CanViewSecrets))
		return
	}

	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Type a name to search...")

	categorySelect := widget.NewSelect(
		[]string{"", "login", "api", "wifi", "server", "database", "other"},
		nil,
	)
	categorySelect.PlaceHolder = "All categories"

	resultsContainer := container.NewVBox()
	resultsLabel := widget.NewLabelWithStyle("Results", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	resultsLabel.Hide()

	doSearch := func() {
		query := strings.TrimSpace(searchEntry.Text)
		category := categorySelect.Selected

		results, err := ui.vault.SearchSecrets(query, category, nil)
		if err != nil {
			ui.showError("Search failed", err)
			return
		}

		var filtered []*vault.SecretData
		for _, s := range results {
			if s.Category != "__SYSTEM__" {
				filtered = append(filtered, s)
			}
		}

		resultsContainer.Objects = nil
		if len(filtered) == 0 {
			noResult := widget.NewLabelWithStyle("No results found", fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
			noResult.Importance = widget.LowImportance
			resultsContainer.Add(noResult)
		} else {
			for _, secret := range filtered {
				s := secret
				cat := s.Category
				if cat == "" {
					cat = "uncategorised"
				}
				nameLabel := widget.NewLabelWithStyle(s.Name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
				catLabel := widget.NewLabel(cat)
				catLabel.Importance = widget.LowImportance
				row := container.NewHBox(
					widget.NewIcon(theme.DocumentIcon()),
					container.NewVBox(nameLabel, catLabel),
					layout.NewSpacer(),
					widget.NewButtonWithIcon("Open", theme.NavigateNextIcon(), func() {
						ui.showSecretDetails(s)
					}),
				)
				resultsContainer.Add(row)
				resultsContainer.Add(widget.NewSeparator())
			}
		}
		resultsLabel.Show()
		resultsContainer.Refresh()
	}

	searchBtn := widget.NewButtonWithIcon("Search", theme.SearchIcon(), doSearch)
	searchBtn.Importance = widget.HighImportance
	searchEntry.OnSubmitted = func(_ string) { doSearch() }

	searchCard := widget.NewCard("Search Secrets", "Find secrets by name or category", container.NewVBox(
		container.New(layout.NewFormLayout(),
			widget.NewLabel("Name"), searchEntry,
			widget.NewLabel("Category"), categorySelect,
		),
		searchBtn,
	))

	page := container.NewVBox(
		container.NewPadded(searchCard),
		container.NewPadded(container.NewVBox(resultsLabel, resultsContainer)),
	)

	ui.content.Objects = []fyne.CanvasObject{container.NewScroll(page)}
	ui.content.Refresh()
}

// showSettings shows the settings screen
// showEditProfileDialog opens a dialog that lets the current user update their
// email address and/or rename their account. Username rename requires password
// confirmation and reattributes all vault entries stamped with the old name.
func (ui *LocalVaultUI) showEditProfileDialog() {
	profile, err := ui.vault.GetUserProfile()
	if err != nil {
		ui.showError("Failed to load profile", err)
		return
	}

	emailEntry := widget.NewEntry()
	emailEntry.SetText(profile.Email)
	emailEntry.SetPlaceHolder("Email (optional)")

	usernameEntry := widget.NewEntry()
	usernameEntry.SetText(profile.Username)
	usernameEntry.SetPlaceHolder("New username (min 3 chars)")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Current password (required to rename)")
	passwordHint := widget.NewLabelWithStyle(
		"Password only needed when changing username",
		fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
	passwordHint.Importance = widget.LowImportance

	errorLabel := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{})
	errorLabel.Importance = widget.DangerImportance

	dlg := dialog.NewCustomConfirm("Edit Profile", "Save", "Cancel",
		container.NewVBox(
			container.New(layout.NewFormLayout(),
				widget.NewLabel("Email"), emailEntry,
				widget.NewLabel("Username"), usernameEntry,
				widget.NewLabel("Password"), passwordEntry,
			),
			passwordHint,
			errorLabel,
		),
		func(confirmed bool) {
			if !confirmed {
				return
			}

			newEmail := strings.TrimSpace(emailEntry.Text)
			newUsername := strings.TrimSpace(usernameEntry.Text)
			currentPassword := passwordEntry.Text
			usernameChanged := !strings.EqualFold(newUsername, profile.Username)

			// Require password when renaming
			if usernameChanged && currentPassword == "" {
				errorLabel.SetText("Enter your current password to rename your account")
				// Re-show because dialog closed — reopen the dialog
				ui.showEditProfileDialog()
				return
			}

			// Update email
			if newEmail != profile.Email {
				if err := ui.vault.UpdateUserEmail(newEmail); err != nil {
					dialog.ShowError(err, ui.window)
					return
				}
			}

			// Rename username
			if usernameChanged {
				if len(newUsername) < 3 {
					dialog.ShowError(fmt.Errorf("username must be at least 3 characters"), ui.window)
					return
				}
				if err := ui.vault.RenameUser(currentPassword, newUsername); err != nil {
					dialog.ShowError(err, ui.window)
					return
				}
				// Sync the UI's current-user tracking
				ui.currentUser = newUsername
			}

			ui.showNotification("Profile updated")
			ui.showSettings()
		}, ui.window)
	dlg.Resize(fyne.NewSize(440, 280))
	dlg.Show()
}

func (ui *LocalVaultUI) showSettings() {
	ui.resetActivity()

	profile, err := ui.vault.GetUserProfile()
	if err != nil {
		ui.showError("Failed to load profile", err)
		return
	}

	// ── Profile card ──────────────────────────────────────────────────────────
	emailDisplay := profile.Email
	if emailDisplay == "" {
		emailDisplay = "(not set)"
	}
	profileForm := container.New(layout.NewFormLayout(),
		widget.NewLabel("Username"), widget.NewLabel(profile.Username),
		widget.NewLabel("Email"), widget.NewLabel(emailDisplay),
		widget.NewLabel("Role"), widget.NewLabel(profile.Role),
		widget.NewLabel("Created"), widget.NewLabel(profile.CreatedAt.Format("2006-01-02")),
		widget.NewLabel("Last Login"), widget.NewLabel(profile.LastLogin.Format("2006-01-02 15:04")),
	)
	editProfileBtn := widget.NewButtonWithIcon("Edit Profile", theme.DocumentCreateIcon(), func() {
		ui.showEditProfileDialog()
	})
	profileCard := widget.NewCard("User Profile", "", container.NewVBox(profileForm, editProfileBtn))

	// ── Security card ─────────────────────────────────────────────────────────
	mfaStatus := "Disabled"
	if profile.MFAEnabled {
		mfaStatus = "Enabled"
	}
	mfaStatusLabel := widget.NewLabel(mfaStatus)
	if profile.MFAEnabled {
		mfaStatusLabel.Importance = widget.SuccessImportance
	} else {
		mfaStatusLabel.Importance = widget.WarningImportance
	}
	changePassBtn := widget.NewButtonWithIcon("Change Password", theme.AccountIcon(), func() {
		ui.showChangePassword()
	})
	mfaBtn := widget.NewButtonWithIcon("Configure MFA", theme.SettingsIcon(), func() {
		ui.showMFASettings()
	})
	securityCard := widget.NewCard("Security", "", container.NewVBox(
		container.New(layout.NewFormLayout(),
			widget.NewLabel("MFA Status"), mfaStatusLabel,
		),
		container.NewHBox(changePassBtn, mfaBtn),
	))

	// ── Backup card ───────────────────────────────────────────────────────────
	exportBtn := widget.NewButtonWithIcon("Export Vault Backup", theme.DownloadIcon(), func() {
		dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				ui.showError("Export failed", err)
				return
			}
			if writer == nil {
				return
			}
			writer.Close()
			exportPath := ensureExt(writer.URI().Path(), ".pwm")
			if err := ui.vault.ExportVault(exportPath); err != nil {
				ui.showError("Export failed", err)
			} else {
				ui.showNotification("Vault exported successfully")
			}
		}, ui.window)
	})

	stats, _ := ui.vault.GetStatsByUser()
	statsForm := container.New(layout.NewFormLayout(),
		widget.NewLabel("Your secrets"), widget.NewLabel(fmt.Sprintf("%v", stats["my_entries"])),
		widget.NewLabel("Total in vault"), widget.NewLabel(fmt.Sprintf("%v", stats["total_entries"])),
		widget.NewLabel("Vault file"), widget.NewLabel(fmt.Sprintf("%v", stats["file_path"])),
	)
	backupCard := widget.NewCard("Backup & Statistics", "", container.NewVBox(statsForm, exportBtn))

	sections := []fyne.CanvasObject{
		container.NewPadded(widget.NewLabelWithStyle("Settings", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})),
		widget.NewSeparator(),
		container.NewPadded(profileCard),
		container.NewPadded(securityCard),
		container.NewPadded(backupCard),
	}

	// ── Vault Access Key card (admin only) ────────────────────────────────────
	if ui.vault.HasPermission(auth.CanManagePolicy) {
		vaultKeyCard := widget.NewCard("Vault Access Key", "Require all users to enter a shared key after login.", ui.buildVaultKeySettings())
		sections = append(sections, container.NewPadded(vaultKeyCard))
	}

	// ── Admin shortcut card ───────────────────────────────────────────────────
	if ui.vault.HasPermission(auth.CanManagePolicy) || ui.vault.HasPermission(auth.CanViewUsers) {
		adminBtn := widget.NewButtonWithIcon("Open Admin Dashboard", theme.GridIcon(), func() {
			ui.showAdminDashboard()
		})
		adminBtn.Importance = widget.HighImportance
		adminCard := widget.NewCard("Administration", "Manage users, audit logs, exports, and security policy.", adminBtn)
		sections = append(sections, container.NewPadded(adminCard))
	} else if ui.vault.HasPermission(auth.CanViewAuditLogs) {
		adminBtn := widget.NewButtonWithIcon("Open Audit & Policy Panel", theme.GridIcon(), func() {
			ui.showAdminDashboard()
		})
		adminBtn.Importance = widget.HighImportance
		adminCard := widget.NewCard("Administration", "View audit logs and security policy.", adminBtn)
		sections = append(sections, container.NewPadded(adminCard))
	}

	ui.content.Objects = []fyne.CanvasObject{container.NewScroll(container.NewVBox(sections...))}
	ui.content.Refresh()
}

// showChangePassword shows password change form
func (ui *LocalVaultUI) showChangePassword() {
	title := widget.NewLabelWithStyle("Change Password", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	currentEntry := widget.NewPasswordEntry()
	currentEntry.SetPlaceHolder("Current Password")

	newEntry := widget.NewPasswordEntry()
	newEntry.SetPlaceHolder("New Password (must meet security policy)")

	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("Confirm New Password")

	errorLabel := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{})
	errorLabel.Importance = widget.DangerImportance

	changeBtn := widget.NewButtonWithIcon("Change Password", theme.ConfirmIcon(), func() {
		errorLabel.SetText("")

		current := currentEntry.Text
		newPass := newEntry.Text
		confirm := confirmEntry.Text

		if newPass != confirm {
			errorLabel.SetText("New passwords do not match")
			return
		}

		if err := ui.vault.ChangePassword(current, newPass); err != nil {
			errorLabel.SetText(err.Error())
			return
		}

		// Vault is now locked – require re-authentication after password change (Req 3.6)
		dialog.ShowInformation("Password Changed",
			"Password changed successfully. Please log in again with your new password.",
			ui.window)
		ui.showLandingScreen()
	})
	changeBtn.Importance = widget.HighImportance

	cancelBtn := widget.NewButtonWithIcon("Cancel", theme.CancelIcon(), func() {
		ui.showSettings()
	})

	form := container.NewVBox(
		title,
		widget.NewSeparator(),
		widget.NewLabel("Current Password"),
		currentEntry,
		widget.NewLabel("New Password"),
		newEntry,
		widget.NewLabel("Confirm New Password"),
		confirmEntry,
		errorLabel,
		container.NewHBox(changeBtn, cancelBtn),
	)

	ui.content.Objects = []fyne.CanvasObject{container.NewPadded(form)}
	ui.content.Refresh()
}

// enforcePasswordExpiry is called after a successful login.
// If the master password has expired the user is taken to a forced change screen.
// If it expires within 14 days a dismissible warning is shown.
func (ui *LocalVaultUI) enforcePasswordExpiry() {
	expired, daysLeft := ui.vault.CheckPasswordExpiry()
	if expired {
		ui.showForcedPasswordChange(
			"Your password has expired and must be changed before you can continue.",
		)
		return
	}
	// daysLeft == 0 means no expiry policy is configured – proceed normally.
	if daysLeft > 0 && daysLeft <= 14 {
		msg := fmt.Sprintf(
			"Your password will expire in %d day(s).\nWould you like to change it now?",
			daysLeft,
		)
		dialog.ShowConfirm("Password Expiry Warning", msg, func(changeNow bool) {
			if changeNow {
				ui.gotoMainScreen()
				ui.showChangePassword()
			} else {
				ui.gotoMainScreen()
			}
		}, ui.window)
		return
	}
	ui.gotoMainScreen()
}

// showForcedPasswordChange renders a mandatory password-change screen with no
// way to skip. The user must set a new password (or log out) to continue.
func (ui *LocalVaultUI) showForcedPasswordChange(reason string) {
	widthEnforcer := canvas.NewRectangle(color.Transparent)
	widthEnforcer.SetMinSize(fyne.NewSize(480, 1))

	reasonLbl := widget.NewLabelWithStyle(reason, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	reasonLbl.Importance = widget.WarningImportance
	reasonLbl.Wrapping = fyne.TextWrapWord

	currentEntry := widget.NewPasswordEntry()
	currentEntry.SetPlaceHolder("Current Password")

	newEntry := widget.NewPasswordEntry()
	newEntry.SetPlaceHolder("New Password (must meet security policy)")

	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("Confirm New Password")

	errorLabel := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{})
	errorLabel.Importance = widget.DangerImportance

	changeBtn := widget.NewButtonWithIcon("Set New Password", theme.ConfirmIcon(), func() {
		errorLabel.SetText("")
		current := currentEntry.Text
		newPass := newEntry.Text
		confirm := confirmEntry.Text

		if newPass != confirm {
			errorLabel.SetText("New passwords do not match")
			return
		}

		if err := ui.vault.ChangePassword(current, newPass); err != nil {
			errorLabel.SetText(err.Error())
			return
		}

		dialog.ShowInformation("Password Updated",
			"Password changed successfully. Please log in with your new password.",
			ui.window)
		ui.showLandingScreen()
	})
	changeBtn.Importance = widget.HighImportance

	logoutBtn := widget.NewButtonWithIcon("Logout Instead", theme.CancelIcon(), func() {
		_ = ui.vault.Logout()
		ui.currentUser = ""
		ui.showLandingScreen()
	})
	logoutBtn.Importance = widget.LowImportance

	form := container.NewVBox(
		widget.NewLabelWithStyle("Password Change Required", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		reasonLbl,
		widget.NewSeparator(),
		widget.NewLabel("Current Password"), currentEntry,
		widget.NewLabel("New Password"), newEntry,
		widget.NewLabel("Confirm New Password"), confirmEntry,
		errorLabel,
		changeBtn,
		widget.NewSeparator(),
		container.NewCenter(logoutBtn),
	)

	ui.window.SetContent(ui.withFooter(
		container.NewCenter(
			container.NewVBox(
				widthEnforcer,
				container.NewPadded(widget.NewCard("", "", container.NewPadded(form))),
			),
		),
	))
}

// showMFASettings shows MFA configuration
func (ui *LocalVaultUI) showMFASettings() {
	title := widget.NewLabelWithStyle("MFA Configuration", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	profile, _ := ui.vault.GetUserProfile()

	var content fyne.CanvasObject

	if profile.MFAEnabled {
		// Show disable option
		disableBtn := widget.NewButtonWithIcon("Disable MFA", theme.DeleteIcon(), func() {
			dialog.ShowEntryDialog("Confirm Password", "Enter your password to disable MFA", func(password string) {
				if err := ui.vault.DisableMFA(password); err != nil {
					ui.showError("Failed to disable MFA", err)
				} else {
					ui.showNotification("MFA disabled")
					ui.showSettings()
				}
			}, ui.window)
		})
		disableBtn.Importance = widget.DangerImportance

		content = container.NewVBox(
			title,
			widget.NewSeparator(),
			widget.NewLabel("MFA is currently ENABLED"),
			widget.NewLabel("Your vault is protected with two-factor authentication."),
			disableBtn,
		)
	} else {
		// Show enable option
		enableBtn := widget.NewButtonWithIcon("Set Up MFA Now", theme.ConfirmIcon(), func() {
			if !ui.vault.Vault.IsUnlocked() {
				ui.showError("MFA Setup Failed", fmt.Errorf("vault is locked — please log in again"))
				return
			}
			secret, err := ui.vault.EnableMFA()
			if err != nil {
				ui.showError("Failed to start MFA setup", err)
				return
			}
			if secret == "" {
				ui.showError("Failed to start MFA setup", fmt.Errorf("generated secret is empty; please try again"))
				return
			}
			// Non-mandatory path: cancel returns to settings
			ui.showMFASetup(secret, false, ui.vault.VerifyAndActivateMFA, ui.showMFASettings)
		})
		enableBtn.Importance = widget.HighImportance

		mfaNote := widget.NewLabel("MFA is required by policy.\nYou must scan the QR code with Microsoft Authenticator (or any TOTP app) to protect your account.")
		mfaNote.Wrapping = fyne.TextWrapWord

		content = container.NewVBox(
			title,
			widget.NewSeparator(),
			widget.NewLabel("⚠  MFA is currently DISABLED"),
			mfaNote,
			enableBtn,
		)
	}

	backBtn := widget.NewButtonWithIcon("Back", theme.NavigateBackIcon(), func() {
		ui.showSettings()
	})

	ui.content.Objects = []fyne.CanvasObject{
		container.NewVBox(content, widget.NewSeparator(), backBtn),
	}
	ui.content.Refresh()
}

// startMandatoryMFAEnrollment generates a fresh TOTP secret and routes to the
// mandatory (no-cancel) QR enrollment screen. Called after vault creation and
// on first login when the user has not yet enrolled.
// Precondition: vault is unlocked and userProfile is loaded (Login() now
// guarantees this on the "MFA setup required" path).
func (ui *LocalVaultUI) startMandatoryMFAEnrollment() {
	// Ensure username is populated before building the QR URI.
	if ui.currentUser == "" {
		if profile, pErr := ui.vault.GetUserProfile(); pErr == nil && profile != nil {
			ui.currentUser = profile.Username
		}
	}
	if ui.currentUser == "" {
		ui.showError("Failed to start MFA setup", fmt.Errorf("could not determine current user — please log in again"))
		ui.showLandingScreen()
		return
	}

	// Vault must be unlocked — Login() keeps it open on the enrollment path,
	// but guard defensively in case this is called from an unexpected code path.
	if !ui.vault.Vault.IsUnlocked() {
		ui.showError("Failed to start MFA setup", fmt.Errorf("vault is locked — please log in again"))
		ui.savedPassword = ""
		ui.showLandingScreen()
		return
	}
	// Password no longer needed — clear it now.
	ui.savedPassword = ""

	secret, err := ui.vault.EnableMFA()
	if err != nil {
		ui.showError("Failed to start MFA setup", err)
		return
	}
	if secret == "" {
		ui.showError("Failed to start MFA setup", fmt.Errorf("generated secret is empty — please try again"))
		return
	}

	ui.showMFASetup(secret, true, ui.vault.VerifyAndActivateMFA, ui.showMainScreen)
}

// showMFASetup shows MFA setup with a scannable QR code for Microsoft Authenticator
// (or any RFC 6238-compatible authenticator app).
// mandatory=true: no cancel button, on success goes to main screen.
// mandatory=false: cancel returns to MFA settings (reconfiguration path).
// verifyFn is called with the 6-digit code; return nil to accept, error to reject.
// onSuccess is called after the user successfully verifies their TOTP code.
func (ui *LocalVaultUI) showMFASetup(secret string, mandatory bool, verifyFn func(string) error, onSuccess func()) {
	// ── Build the otpauth:// provisioning URI ─────────────────────────────────
	// Build the URI manually instead of delegating to auth.GetMFAProvisioningURI
	// because url.Values.Encode() uses "+" for spaces (HTML form encoding) and
	// sorts keys alphabetically — both of which cause Microsoft Authenticator
	// and other strict TOTP parsers to reject or misread the QR code.
	issuer := "PasswordManager"
	username := ui.currentUser
	// Last-chance username recovery before building the URI.
	if username == "" {
		if profile, pErr := ui.vault.GetUserProfile(); pErr == nil && profile != nil {
			username = profile.Username
			ui.currentUser = username
		}
	}
	// Sanitise both parts before embedding in the URI.
	cleanSecret := strings.ToUpper(strings.TrimSpace(secret))
	cleanIssuer := strings.TrimSpace(issuer)
	cleanUser := strings.TrimSpace(username)
	// Label: "Issuer:Account" — path-escape each part separately.
	label := cleanIssuer + ":" + cleanUser
	// Query built manually with %XX encoding (not "+" form).
	provisioningURI := fmt.Sprintf(
		"otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		strings.ReplaceAll(strings.ReplaceAll(label, " ", "%20"), ":", "%3A"),
		cleanSecret,
		strings.ReplaceAll(cleanIssuer, " ", "%20"),
	)

	// ── Generate QR code PNG (300×300, High error correction) ────────────────
	// NOTE: no TextWrapWord labels anywhere in this form – wrapped labels have
	// zero minimum height in Fyne, which causes the whole VBox to collapse when
	// the parent is a Card centred in the window.
	var qrWidget fyne.CanvasObject
	qrBytes, qrErr := qrcode.Encode(provisioningURI, qrcode.High, 300)
	if qrErr == nil {
		res := fyne.NewStaticResource("mfa_qr.png", qrBytes)
		img := canvas.NewImageFromResource(res)
		img.FillMode = canvas.ImageFillContain
		img.SetMinSize(fyne.NewSize(300, 300))
		qrWidget = container.NewCenter(img)
	} else {
		qrWidget = widget.NewLabel(provisioningURI)
	}

	// ── Instructions (no Wrapping – fixed height) ─────────────────────────────
	instructions := widget.NewLabelWithStyle(
		"1.  Open Microsoft Authenticator → Add account → Other account\n"+
			"2.  Scan the QR code above with your phone\n"+
			"3.  Enter the 6-digit code from the app below",
		fyne.TextAlignLeading, fyne.TextStyle{})

	// Manual-entry fallback
	manualNote := widget.NewLabelWithStyle("Can't scan?  Use this secret key:", fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
	manualNote.Importance = widget.LowImportance

	secretDisplay := widget.NewEntry()
	secretDisplay.SetText(secret)
	secretDisplay.Disable()

	copySecretBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		if ui.clipboardManager != nil {
			_ = ui.clipboardManager.CopyToClipboard(secret)
		} else {
			ui.window.Clipboard().SetContent(secret)
		}
		ui.showNotification("Secret copied to clipboard")
	})

	// ── Verification ─────────────────────────────────────────────────────────
	codeEntry := widget.NewEntry()
	codeEntry.SetPlaceHolder("6-digit code from your app")

	errorLabel := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{})
	errorLabel.Importance = widget.DangerImportance

	verifyBtn := widget.NewButtonWithIcon("Verify & Enable MFA", theme.ConfirmIcon(), func() {
		clean := strings.ReplaceAll(strings.TrimSpace(codeEntry.Text), " ", "")
		if len(clean) != 6 {
			errorLabel.SetText("Code must be exactly 6 digits")
			return
		}
		if err := verifyFn(clean); err != nil {
			errorLabel.SetText("Incorrect code – check your authenticator app and try again")
			return
		}
		dialog.ShowInformation("MFA Enabled",
			"Two-factor authentication is now active.\nYou will need your authenticator app each time you log in.",
			ui.window)
		onSuccess()
	})
	verifyBtn.Importance = widget.HighImportance
	codeEntry.OnSubmitted = func(_ string) { verifyBtn.OnTapped() }

	formFields := container.New(layout.NewFormLayout(),
		widget.NewLabel("Secret key"), container.NewBorder(nil, nil, nil, copySecretBtn, secretDisplay),
		widget.NewLabel("Verify code"), codeEntry,
	)

	if mandatory {
		// ── Mandatory full-window layout ──────────────────────────────────────
		// Match exactly the login/register card pattern: no TextWrapWord, no
		// NewScroll, branding inside the card content.
		widthEnforcer := canvas.NewRectangle(color.Transparent)
		widthEnforcer.SetMinSize(fyne.NewSize(560, 1))

		appName := widget.NewLabelWithStyle("Password Manager", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
		appSub := widget.NewLabelWithStyle("Secure Enterprise Vault", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

		warningLabel := widget.NewLabelWithStyle(
			"⚠  MFA is mandatory – complete setup to access your vault",
			fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
		warningLabel.Importance = widget.DangerImportance

		mfaCard := widget.NewCard("Set Up Microsoft Authenticator", "",
			container.NewVBox(
				container.NewPadded(container.NewVBox(appName, appSub)),
				widget.NewSeparator(),
				warningLabel,
				widget.NewSeparator(),
				container.NewCenter(qrWidget),
				widget.NewSeparator(),
				container.NewPadded(instructions),
				widget.NewSeparator(),
				container.NewPadded(container.NewVBox(manualNote)),
				container.NewPadded(formFields),
				widget.NewSeparator(),
				errorLabel,
				verifyBtn,
			),
		)

		ui.window.SetContent(ui.withFooter(container.NewCenter(
			container.NewVBox(
				widthEnforcer,
				container.NewPadded(mfaCard),
			),
		)))
	} else {
		// ── Non-mandatory: rendered inside the main content pane ──────────────
		cancelBtn := widget.NewButtonWithIcon("Cancel", theme.CancelIcon(), func() {
			ui.showMFASettings()
		})
		form := container.NewVBox(
			widget.NewLabelWithStyle("Set Up Two-Factor Authentication", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			widget.NewSeparator(),
			container.NewCenter(qrWidget),
			widget.NewSeparator(),
			container.NewPadded(instructions),
			widget.NewSeparator(),
			container.NewPadded(container.NewVBox(manualNote)),
			container.NewPadded(formFields),
			widget.NewSeparator(),
			errorLabel,
			container.NewHBox(verifyBtn, cancelBtn),
		)
		ui.content.Objects = []fyne.CanvasObject{container.NewScroll(container.NewPadded(form))}
		ui.content.Refresh()
	}
}

func (ui *LocalVaultUI) showAboutDialog() {
	name := widget.NewLabelWithStyle("Password Manager", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	version := widget.NewLabelWithStyle("Version "+AppVersion, fyne.TextAlignCenter, fyne.TextStyle{})
	publisher := widget.NewLabelWithStyle("By Kagiso Setwaba", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})
	desc := widget.NewLabelWithStyle(
		"A secure, local-first password vault.\nYour data never leaves your device.",
		fyne.TextAlignCenter, fyne.TextStyle{},
	)

	content := container.NewVBox(
		name,
		version,
		widget.NewSeparator(),
		desc,
		widget.NewSeparator(),
		publisher,
	)

	dialog.ShowCustom("About", "Close", container.NewPadded(content), ui.window)
}

// showError shows an error dialog
func (ui *LocalVaultUI) showError(title string, err error) {
	dialog.ShowError(fmt.Errorf("%s: %v", title, err), ui.window)
}

// showNotification shows a brief non-blocking toast popup that auto-dismisses after 3 s.
// It never blocks the UI — the user does not need to click anything.
func (ui *LocalVaultUI) showNotification(message string) {
	lbl := widget.NewLabelWithStyle("  "+message+"  ", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	lbl.Importance = widget.SuccessImportance

	pop := widget.NewPopUp(
		container.NewPadded(widget.NewCard("", "", lbl)),
		ui.window.Canvas(),
	)

	// Size is only known via MinSize() before Show(); using Size() returns (0,0).
	sz := pop.MinSize()
	pop.Resize(sz)

	// Centre horizontally, pin to bottom of the window with a margin.
	cs := ui.window.Canvas().Size()
	pop.Move(fyne.NewPos(
		(cs.Width-sz.Width)/2,
		cs.Height-sz.Height-48,
	))
	pop.Show()

	go func() {
		time.Sleep(3 * time.Second)
		pop.Hide()
	}()
}

// resetActivity updates the last-activity timestamp to prevent inactivity lock-out (Req 3.6).
func (ui *LocalVaultUI) resetActivity() {
	ui.activityMu.Lock()
	ui.lastActivity = time.Now()
	ui.activityMu.Unlock()
}

// LastActivity returns the last recorded activity time in a thread-safe way.
func (ui *LocalVaultUI) LastActivity() time.Time {
	ui.activityMu.RLock()
	defer ui.activityMu.RUnlock()
	return ui.lastActivity
}

// generateSecurePassword generates a secure random password
func generateSecurePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"

	password := make([]byte, length)
	for i := range password {
		password[i] = charset[secureRandomInt(len(charset))]
	}

	// Ensure at least one of each type
	password[0] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[secureRandomInt(26)]
	password[1] = "abcdefghijklmnopqrstuvwxyz"[secureRandomInt(26)]
	password[2] = "0123456789"[secureRandomInt(10)]
	password[3] = "!@#$%^&*()_+-=[]{}|;:,.<>?"[secureRandomInt(27)]

	// Shuffle
	for i := len(password) - 1; i > 0; i-- {
		j := secureRandomInt(i + 1)
		password[i], password[j] = password[j], password[i]
	}

	return string(password)
}

// passwordStrength rates a password and returns a display label + Fyne importance level.
func passwordStrength(pw string) (string, widget.Importance) {
	if len(pw) == 0 {
		return "—", widget.LowImportance
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range pw {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	score := 0
	if len(pw) >= 8 {
		score++
	}
	if len(pw) >= 12 {
		score++
	}
	if len(pw) >= 16 {
		score++
	}
	if hasUpper && hasLower {
		score++
	}
	if hasDigit {
		score++
	}
	if hasSpecial {
		score++
	}
	switch {
	case score <= 2:
		return "Weak", widget.DangerImportance
	case score <= 3:
		return "Fair", widget.WarningImportance
	case score <= 4:
		return "Good", widget.MediumImportance
	default:
		return "Strong", widget.SuccessImportance
	}
}

// secureRandomInt returns a cryptographically secure random int in [0, max).
// Uses rejection sampling to eliminate modulo bias.
func secureRandomInt(max int) int {
	if max <= 0 {
		return 0
	}
	// Calculate the largest multiple of max that fits in uint64.
	limit := (^uint64(0) - uint64(max-1)) % uint64(max)
	var b [8]byte
	for {
		rand.Read(b[:])
		n := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
		if n >= limit {
			return int(n % uint64(max))
		}
	}
}
