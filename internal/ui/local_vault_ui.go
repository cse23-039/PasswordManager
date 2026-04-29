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
	"sort"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
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
	currentUser   string
	savedPassword []byte // master password held briefly for MFA flow; zeroed immediately after use
	content       *fyne.Container
	lastActivity     time.Time    // for inactivity auto-lock (Req 3.6)
	activityMu       sync.RWMutex // protects lastActivity
	activityCancel   chan struct{} // closed to stop the inactivity goroutine
	vaultKeyVerified bool         // true once vault access key verified this session
	chainMonitorStop chan struct{} // closed to stop the chain integrity monitor goroutine
	vaultTamperStop  chan struct{} // closed to stop the vault file tamper monitor goroutine
	onMainScreen     bool         // true when the split main layout is active (sidebar visible)
	formDirty        bool         // true when add/edit form has unsaved changes
	detailBack       func()       // the "← Back" destination for the current detail view
}

// sidebarNavItem groups a nav button with its left-accent bar and wrapper container.
type sidebarNavItem struct {
	btn  *widget.Button
	bar  *canvas.Rectangle
	wrap fyne.CanvasObject
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

	window.SetFixedSize(false)
	window.Resize(fyne.NewSize(1100, 720))
	window.CenterOnScreen()
}

// withFooter wraps any screen content with a footer bar (copyright + theme icon).
// No top bar — the theme toggle icon sits in the footer to keep the UI minimal.
func (ui *LocalVaultUI) withFooter(content fyne.CanvasObject) fyne.CanvasObject {
	var themeBtn *widget.Button
	themeBtn = widget.NewButtonWithIcon("", theme.ColorPaletteIcon(), func() {
		SetDarkMode(ui.app, !IsDarkMode())
		if ui.onMainScreen {
			ui.showMainScreen()
		} else {
			ui.window.SetContent(ui.window.Content())
			ui.window.Content().Refresh()
		}
	})
	themeBtn.Importance = widget.LowImportance

	lbl := widget.NewLabelWithStyle(
		"© 2026 Kagiso Setwaba · All rights reserved · Password Manager v1.0",
		fyne.TextAlignCenter,
		fyne.TextStyle{Italic: true},
	)
	lbl.Importance = widget.LowImportance

	footer := container.NewVBox(
		widget.NewSeparator(),
		container.NewBorder(nil, nil, nil, themeBtn, container.NewPadded(lbl)),
	)
	return container.NewBorder(nil, footer, nil, nil, content)
}
// guardNavigation checks for unsaved form changes before executing a nav action.
// If formDirty is true the user is asked to confirm before leaving the form.
func (ui *LocalVaultUI) guardNavigation(fn func()) {
	if !ui.formDirty {
		fn()
		return
	}
	dialog.ShowConfirm("Unsaved Changes",
		"You have unsaved changes that will be lost. Leave this page?",
		func(ok bool) {
			if ok {
				ui.formDirty = false
				fn()
			}
		}, ui.window)
}

// showAbout renders the About view inside the main content pane so it follows
// the same split-layout pattern as every other nav destination.
func (ui *LocalVaultUI) showAbout() {
	ui.resetActivity()

	title := widget.NewLabelWithStyle("Password Manager", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	version := widget.NewLabelWithStyle("Version "+AppVersion, fyne.TextAlignCenter, fyne.TextStyle{})
	version.Importance = widget.LowImportance
	publisher := widget.NewLabelWithStyle("By Kagiso Setwaba", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})
	publisher.Importance = widget.LowImportance

	features := container.NewVBox(
		widget.NewLabelWithStyle("Built with:", fyne.TextAlignCenter, fyne.TextStyle{}),
		makeMutedLabel("• AES-256-GCM encryption"),
		makeMutedLabel("• Argon2id key derivation"),
		makeMutedLabel("• TOTP multi-factor authentication"),
		makeMutedLabel("• Role-based access control"),
		makeMutedLabel("• Tamper-resistant audit logging"),
		makeMutedLabel("• Local vault file (.pwm) — your data never leaves your device"),
	)

	card := makeSectionCard("About", "", container.NewVBox(
		container.NewPadded(container.NewVBox(
			container.NewCenter(title),
			container.NewCenter(version),
			widget.NewSeparator(),
			container.NewCenter(features),
			widget.NewSeparator(),
			container.NewCenter(publisher),
		)),
	))

	header := makePageHeader("About", "Password Manager information", nil)
	ui.content.Objects = []fyne.CanvasObject{
		container.NewBorder(header, nil, nil, nil,
			boundedScroll(container.NewPadded(card)),
		),
	}
	ui.content.Refresh()
}

// showVaultHealth renders a Vault Health dashboard showing password hygiene
// metrics and security integrity indicators (tamper detection, audit chain, MFA).
func (ui *LocalVaultUI) showVaultHealth() {
	ui.resetActivity()
	report, err := ui.vault.GetHealthReport()
	if err != nil {
		ui.showError("Failed to load vault health", err)
		return
	}

	scoreColor := func(bad, total int) fyne.TextStyle {
		_ = total
		if bad == 0 {
			return fyne.TextStyle{}
		}
		return fyne.TextStyle{Bold: true}
	}
	scoreImportance := func(bad int) widget.Importance {
		if bad == 0 {
			return widget.SuccessImportance
		}
		return widget.DangerImportance
	}

	makeStat := func(label string, bad, total int, names []string, fix string) fyne.CanvasObject {
		pct := 0
		if total > 0 {
			pct = 100 * (total - bad) / total
		}
		titleLbl := widget.NewLabelWithStyle(label, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		countLbl := widget.NewLabelWithStyle(
			fmt.Sprintf("%d affected  ·  %d%% healthy", bad, pct),
			fyne.TextAlignLeading, scoreColor(bad, total),
		)
		countLbl.Importance = scoreImportance(bad)

		body := container.NewVBox(titleLbl, countLbl)

		if bad > 0 && len(names) > 0 {
			nameList := strings.Join(names, ",  ")
			if bad > len(names) {
				nameList += fmt.Sprintf("  … and %d more", bad-len(names))
			}
			detail := widget.NewLabel(nameList)
			detail.Wrapping = fyne.TextWrapWord
			detail.Importance = widget.LowImportance

			fixLbl := makeMutedLabel(fix)
			fixLbl.Wrapping = fyne.TextWrapWord
			body.Add(detail)
			body.Add(fixLbl)
		}

		return widget.NewCard("", "", container.NewPadded(body))
	}

	// makeSecurityCard renders a single security indicator row.
	makeSecurityCard := func(title, statusText string, imp widget.Importance, detail string) fyne.CanvasObject {
		titleLbl := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		statusLbl := widget.NewLabel(statusText)
		statusLbl.Importance = imp
		body := container.NewVBox(titleLbl, statusLbl)
		if detail != "" {
			d := makeMutedLabel(detail)
			d.Wrapping = fyne.TextWrapWord
			body.Add(d)
		}
		return widget.NewCard("", "", container.NewPadded(body))
	}

	// ── Overall issue count ───────────────────────────────────────────────────
	canViewIntegrity := ui.vault.HasPermission(auth.CanViewAuditLogs)
	totalIssues := report.Weak + report.Old + report.Reused + report.NoPassword
	if canViewIntegrity && report.VaultFileTampered {
		totalIssues++
	}
	if canViewIntegrity && (!report.AuditChainIntact || report.AuditTampered > 0) {
		totalIssues++
	}
	if !report.MFAEnabled {
		totalIssues++
	}

	overallIcon := theme.ConfirmIcon()
	overallText := "Your vault looks healthy!"
	if totalIssues > 0 {
		overallIcon = theme.WarningIcon()
		overallText = fmt.Sprintf("%d issue(s) found — review the sections below", totalIssues)
	}
	overallBanner := container.NewHBox(
		widget.NewIcon(overallIcon),
		widget.NewLabelWithStyle(overallText, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
	)

	// ── Password hygiene section ──────────────────────────────────────────────
	content := container.NewVBox(
		container.NewPadded(overallBanner),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Password Hygiene", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Italic: true}),
		makeStat("Weak Passwords", report.Weak, report.Total, report.WeakNames,
			"Tip: use at least 12 characters with uppercase, lowercase, digits, and symbols."),
		makeStat("Old Passwords (>1 year)", report.Old, report.Total, report.OldNames,
			"Tip: rotate credentials that haven't changed in over a year."),
		makeStat("Reused Passwords", report.Reused, report.Total, report.ReusedNames,
			"Tip: every account should have a unique password."),
	)
	if report.NoPassword > 0 {
		np := widget.NewLabelWithStyle(
			fmt.Sprintf("%d entries have no password stored.", report.NoPassword),
			fyne.TextAlignLeading, fyne.TextStyle{},
		)
		np.Importance = widget.WarningImportance
		content.Add(widget.NewCard("", "", container.NewPadded(np)))
	}

	// ── Security integrity section (SecurityOfficer / Administrator only) ───────
	if ui.vault.HasPermission(auth.CanViewAuditLogs) {
		content.Add(widget.NewSeparator())
		content.Add(widget.NewLabelWithStyle("Security Integrity", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Italic: true}))

		// Vault file tamper detection
		if report.VaultFileTampered {
			content.Add(makeSecurityCard(
				"Vault File Integrity",
				"WARNING: vault file was modified outside the application",
				widget.DangerImportance,
				"The vault file on disk has a newer modification time than the last in-app save. "+
					"This may indicate external tampering. Re-lock and re-unlock to refresh the check.",
			))
		} else {
			content.Add(makeSecurityCard(
				"Vault File Integrity",
				"Vault file has not been modified outside the application",
				widget.SuccessImportance, "",
			))
		}

		// Audit log chain integrity
		auditStatusText := fmt.Sprintf(
			"Verified: %d  ·  Tampered: %d  ·  Unverifiable: %d",
			report.AuditVerified, report.AuditTampered, report.AuditUnverifiable,
		)
		auditDetail := ""
		var auditImp widget.Importance
		switch {
		case report.AuditTampered > 0 || !report.AuditChainIntact:
			auditImp = widget.DangerImportance
			auditDetail = "One or more audit entries have a broken or invalid HMAC checksum. " +
				"The audit log may have been modified externally."
		case report.AuditUnverifiable > 0:
			auditImp = widget.WarningImportance
			auditDetail = "Some entries were created before audit signing was enabled and cannot be verified."
		default:
			auditImp = widget.SuccessImportance
		}
		chainStatus := "Chain intact"
		if !report.AuditChainIntact {
			chainStatus = "Chain BROKEN"
		}
		content.Add(makeSecurityCard(
			"Audit Log Integrity",
			fmt.Sprintf("%s  ·  %s", chainStatus, auditStatusText),
			auditImp, auditDetail,
		))
	}

	// ── MFA & security policy (visible to all authenticated users) ───────────
	// MFA & security policy
	mfaText := "MFA is enabled and verified for your account"
	mfaImp := widget.SuccessImportance
	mfaDetail := ""
	if !report.MFAEnabled {
		mfaText = "MFA is not enabled for your account"
		mfaImp = widget.WarningImportance
		if report.MFARequired {
			mfaText = "MFA is required by policy but not enabled on your account"
			mfaImp = widget.DangerImportance
		}
		mfaDetail = "Enable MFA from Settings > Security to protect your account with a second factor."
	}
	policyDetail := ""
	if !report.HasSecurityPolicy {
		policyDetail = "No security policy is configured. Admins can set password expiry, MFA requirements, and session controls in the Admin Dashboard."
	} else {
		if report.PasswordExpiryDays > 0 {
			policyDetail = fmt.Sprintf("Password rotation policy: every %d days.", report.PasswordExpiryDays)
		} else {
			policyDetail = "No password expiry policy configured."
		}
	}
	content.Add(makeSecurityCard("MFA Status", mfaText, mfaImp, mfaDetail))
	content.Add(makeSecurityCard(
		"Security Policy",
		func() string {
			if report.HasSecurityPolicy {
				return "Security policy is active"
			}
			return "No security policy configured"
		}(),
		func() widget.Importance {
			if report.HasSecurityPolicy {
				return widget.SuccessImportance
			}
			return widget.WarningImportance
		}(),
		policyDetail,
	))

	header := makePageHeader(
		"Vault Health",
		fmt.Sprintf("%d secrets analysed", report.Total),
		nil,
	)
	ui.content.Objects = []fyne.CanvasObject{
		container.NewBorder(header, nil, nil, nil,
			boundedScroll(container.NewPadded(content)),
		),
	}
	ui.content.Refresh()
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
	// Clear any sensitive credentials held in the struct across screen transitions.
	zeroAndClearBytes(ui.savedPassword)
	ui.savedPassword = nil
	ui.currentUser = ""
	if ui.clipboardManager != nil {
		ui.clipboardManager.ClearClipboard()
	}

	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Enter your username")

	passwordEntry := widget.NewEntry()
	passwordEntry.Password = true
	passwordEntry.SetPlaceHolder("Enter your password")

	// MFA row — hidden until password is accepted and MFA is confirmed active.
	// Password-style entry masks the code to prevent shoulder-surfing.
	mfaEntry := widget.NewPasswordEntry()
	mfaEntry.SetPlaceHolder("6-digit code from your authenticator app")
	mfaEntry.OnChanged = func(s string) {
		filtered := ""
		for _, r := range s {
			if r >= '0' && r <= '9' {
				filtered += string(r)
			}
		}
		if len(filtered) > 6 {
			filtered = filtered[:6]
		}
		if filtered != s {
			mfaEntry.SetText(filtered)
		}
	}
	mfaHint := makeMutedLabel("Open your authenticator app (Microsoft Authenticator, Google Authenticator, Authy, etc.) and enter the 6-digit code shown.")
	mfaRow := container.NewVBox(
		makeFormRow("MFA Code", mfaEntry),
		container.NewPadded(mfaHint),
	)
	mfaRow.Hide() // shown only after password accepted + MFA required

	errorLabel := makeErrorLabel()

	// mfaRequired tracks whether we've already verified the password and are
	// now waiting for a TOTP code.
	mfaRequired := false
	savedUsername := ""
	var savedPassword []byte
	// Forward-declare so helper/button closures can reference it before assignment.
	var loginBtn *widget.Button
	resetMFAStep := func() {
		mfaRequired = false
		zeroAndClearBytes(savedPassword)
		savedPassword = nil
		mfaEntry.SetText("")
		mfaRow.Hide()
		loginBtn.SetText("Login")
		usernameEntry.Enable()
		passwordEntry.Enable()
	}

	loginBtn = makePrimaryBtn("Login", theme.LoginIcon(), func() {
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
			if err := ui.vault.LoginWithMFA(savedUsername, string(savedPassword), mfaCode, ip); err != nil {
				if strings.Contains(err.Error(), "MFA setup required") || strings.Contains(err.Error(), "MFA not set up") {
					resetMFAStep()
					ui.currentUser = savedUsername
					ui.savedPassword = append(ui.savedPassword[:0:0], savedPassword...)
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
				savedPassword = []byte(password)
				zeroAndClearBytes(ui.savedPassword)
				ui.savedPassword = []byte(password)
				ui.currentUser = username
				ui.startMandatoryMFAEnrollment()
				return
			}
			if strings.Contains(err.Error(), "MFA required") {
				// Password accepted — now ask for the TOTP code.
				savedUsername = username
				savedPassword = []byte(password)
				zeroAndClearBytes(ui.savedPassword)
				ui.savedPassword = []byte(password)
				mfaRequired = true
				mfaRow.Show()
				loginBtn.SetText("Verify Code")
				usernameEntry.Disable()
				passwordEntry.Password = true
				passwordEntry.Refresh()
				passwordEntry.Disable()
				errorLabel.SetText("")
				ui.window.Canvas().Focus(mfaEntry)
				return
			}
			switch {
			case errors.Is(err, vault.ErrUserNotFound), errors.Is(err, vault.ErrInvalidPassword):
				// Use a single message for both to prevent username enumeration.
				errorLabel.SetText("Invalid username or password")
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
	passwordEntry.OnSubmitted = func(_ string) { loginBtn.OnTapped() }
	mfaEntry.OnSubmitted = func(_ string) { loginBtn.OnTapped() }

	registerHint := makeMutedLabel("New here?")
	registerBtn := makeSecondaryBtn("Create Account", nil, func() {
		ui.showRegistrationScreen()
	})

	formFields := container.NewVBox(
		makeFormRow("Username", makeFullWidthEntry(usernameEntry)),
		makeFormRow("Password", makeFullWidthEntry(passwordEntry)),
	)

	loginBody := container.NewVBox(
		container.NewPadded(formFields),
		container.NewPadded(mfaRow),
		makeDivider(),
		errorLabel,
		container.NewPadded(loginBtn),
		makeDivider(),
		container.NewCenter(container.NewHBox(registerHint, registerBtn)),
	)

	loginCard := makeAuthCard("Welcome Back", "Sign in to your encrypted vault", loginBody)

	var logoHeader fyne.CanvasObject
	if AppIcon != nil {
		img := canvas.NewImageFromResource(AppIcon)
		img.SetMinSize(fyne.NewSize(72, 72))
		img.FillMode = canvas.ImageFillContain
		logoHeader = container.NewCenter(img)
	} else {
		logoHeader = container.NewCenter(widget.NewIcon(theme.DocumentIcon()))
	}

	ui.window.SetContent(ui.withFooter(container.NewCenter(
		container.NewVBox(
			minWidth(480),
			logoHeader,
			widget.NewLabel(""),
			loginCard,
		),
	)))
	ui.window.Canvas().Focus(usernameEntry)
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
	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Minimum 3 characters")

	emailEntry := widget.NewEntry()
	emailEntry.SetPlaceHolder("Optional — used for recovery")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Minimum 12 characters")

	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("Re-enter password")

	errorLabel := makeErrorLabel()

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

	registerBtn := makePrimaryBtn("Create Account & Set Up MFA", theme.AccountIcon(), func() { doRegister() })
	confirmEntry.OnSubmitted = func(_ string) { doRegister() }

	reqNote := makeMutedLabel("Password must meet the configured security policy requirements")
	reqNote.Truncation = fyne.TextTruncateEllipsis

	formFields := container.NewVBox(
		makeFormRow("Username", makeFullWidthEntry(usernameEntry)),
		makeFormRow("Email", makeFullWidthEntry(emailEntry)),
		makeFormRow("Password", makeFullWidthEntry(passwordEntry)),
		makeFormRow("Confirm", makeFullWidthEntry(confirmEntry)),
	)

	backBtn := makeLowBtn("Back to Login", theme.NavigateBackIcon(), func() { ui.showLandingScreen() })

	regBody := container.NewVBox(
		container.NewPadded(reqNote),
		makeDivider(),
		container.NewPadded(formFields),
		makeDivider(),
		errorLabel,
		container.NewPadded(registerBtn),
		makeDivider(),
		container.NewCenter(backBtn),
	)

	regCard := makeAuthCard("Create Account", "Set up your encrypted password vault", regBody)

	ui.window.SetContent(ui.withFooter(container.NewCenter(
		container.NewVBox(
			minWidth(480),
			regCard,
		),
	)))
	ui.window.Canvas().Focus(usernameEntry)
}

// showNewVaultScreen is shown after the very first login following registration.
// It confirms the vault has been created and gives the user key information
// before they enter the main application.
func (ui *LocalVaultUI) showNewVaultScreen() {
	ui.onMainScreen = false

	appTitle := makeCenteredHeading("Password Manager")
	appSub := widget.NewLabelWithStyle("Secure Enterprise Vault", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})
	appSub.Importance = widget.LowImportance

	successTitle := widget.NewLabelWithStyle("Your encrypted vault is ready!", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	successTitle.Importance = widget.SuccessImportance

	vaultPath := makeMutedLabel(fmt.Sprintf("Vault file: %s", ui.vault.Vault.GetFilePath()))
	infoText := makeMutedLabel("Encrypted with AES-256-GCM  ·  Keys derived with Argon2id\nKeep your password safe — it cannot be recovered if lost.")

	continueBtn := makePrimaryBtn("Open My Vault  →", theme.NavigateNextIcon(), func() { ui.gotoMainScreen() })

	card := widget.NewCard("Vault Setup Complete", "",
		container.NewVBox(
			container.NewPadded(container.NewVBox(appTitle, appSub)),
			makeDivider(),
			container.NewPadded(container.NewVBox(
				successTitle,
				makeDivider(),
				vaultPath,
				infoText,
			)),
			makeDivider(),
			continueBtn,
		),
	)

	ui.window.SetContent(ui.withFooter(container.NewCenter(
		container.NewVBox(
			minWidth(480),
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

	keyEntry := widget.NewPasswordEntry()
	keyEntry.SetPlaceHolder("Enter vault access key")

	errorLabel := makeErrorLabel()

	attempts := 0
	var unlockBtn *widget.Button
	unlockBtn = makePrimaryBtn("Unlock Vault", theme.ConfirmIcon(), func() {
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
	keyEntry.OnSubmitted = func(_ string) { unlockBtn.OnTapped() }

	logoutLink := widget.NewHyperlink("← Logout", nil)
	logoutLink.OnTapped = func() {
		_ = ui.vault.Logout()
		ui.currentUser = ""
		ui.vaultKeyVerified = false
		ui.showLandingScreen()
	}

	card := makeAuthCard("Vault Access Key Required",
		"This vault requires an additional access key. Contact your administrator if you don't have it.",
		container.NewVBox(
			container.NewPadded(makeFormRow("Vault Key", keyEntry)),
			makeDivider(),
			errorLabel,
			unlockBtn,
			container.NewCenter(logoutLink),
		),
	)

	ui.window.SetContent(ui.withFooter(container.NewCenter(
		container.NewVBox(
			minWidth(480),
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

		changeBtn := makeSecondaryBtn("Change Vault Key", theme.SettingsIcon(), func() {
			ui.showSetVaultKeyDialog(true)
		})

		removeBtn := makeDangerBtn("Remove Vault Key", theme.DeleteIcon(), func() {
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

		return container.NewVBox(statusLbl, changeBtn, removeBtn)
	}

	statusLbl := makeMutedLabel("No key set — anyone who logs in can access secrets")

	setBtn := makePrimaryBtn("Set Vault Key", theme.ContentAddIcon(), func() {
		ui.showSetVaultKeyDialog(false)
	})

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

	// Session timeout ticker (60 s): inactivity + absolute session limit.
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
			}
		}
	}()

	// Tamper detection ticker (10 s): separate goroutine for fast response.
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-cancelCh:
				return
			case <-ticker.C:
				if !ui.vault.Vault.IsUnlocked() {
					return
				}
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
		tamperBanner, nil, nil, nil,
		split,
	)
	ui.window.SetContent(ui.withFooter(mainLayout))

	// ── Keyboard shortcuts ────────────────────────────────────────────────────
	// Re-registered each login so the handler closure captures the current
	// session's cancel channel. Fyne stores shortcuts in a map keyed by name,
	// so re-adding the same key overwrites the handler without duplicating it.
	ui.window.Canvas().AddShortcut(
		&desktop.CustomShortcut{KeyName: fyne.KeyName("l"), Modifier: desktop.ControlModifier},
		func(_ fyne.Shortcut) {
			if !ui.vault.Vault.IsUnlocked() {
				return
			}
			dialog.ShowConfirm("Lock Vault", "Lock the vault and log out?",
				func(ok bool) {
					if !ok {
						return
					}
					ui.formDirty = false
					_ = ui.vault.Logout()
					ui.currentUser = ""
					ui.showLandingScreen()
				}, ui.window)
		},
	)
	ui.window.Canvas().AddShortcut(
		&desktop.CustomShortcut{KeyName: fyne.KeyName("n"), Modifier: desktop.ControlModifier},
		func(_ fyne.Shortcut) {
			if !ui.vault.Vault.IsUnlocked() {
				return
			}
			ui.guardNavigation(func() { ui.showAddSecret() })
		},
	)
	ui.window.Canvas().AddShortcut(
		&desktop.CustomShortcut{KeyName: fyne.KeyName("f"), Modifier: desktop.ControlModifier},
		func(_ fyne.Shortcut) {
			if !ui.vault.Vault.IsUnlocked() {
				return
			}
			ui.guardNavigation(func() { ui.showSearch() })
		},
	)
	ui.window.Canvas().AddShortcut(
		&desktop.CustomShortcut{KeyName: fyne.KeyName("k"), Modifier: desktop.ControlModifier},
		func(_ fyne.Shortcut) {
			if !ui.vault.Vault.IsUnlocked() {
				return
			}
			ui.guardNavigation(func() { ui.showSettings() })
		},
	)
}

// createSidebar creates the navigation sidebar
func (ui *LocalVaultUI) createSidebar() fyne.CanvasObject {
	// ── App header ────────────────────────────────────────────────────────────
	var logoObj fyne.CanvasObject
	if AppIcon != nil {
		img := canvas.NewImageFromResource(AppIcon)
		img.SetMinSize(fyne.NewSize(48, 48))
		img.FillMode = canvas.ImageFillContain
		logoObj = container.NewCenter(img)
	} else {
		logoObj = container.NewCenter(widget.NewIcon(theme.DocumentIcon()))
	}
	appTitle := widget.NewLabelWithStyle("Password Manager", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	appVersion := widget.NewLabelWithStyle("v"+AppVersion, fyne.TextAlignCenter, fyne.TextStyle{Italic: true})
	appVersion.Importance = widget.LowImportance
	appHeader := container.NewVBox(
		logoObj,
		appTitle,
		appVersion,
	)

	userLabel := widget.NewLabelWithStyle(ui.currentUser, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	roleLabel := widget.NewLabelWithStyle(ui.vault.GetRole(), fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
	roleLabel.Importance = widget.LowImportance
	userCard := container.NewHBox(
		container.NewVBox(userLabel, roleLabel),
	)

	// ── Nav item helpers ──────────────────────────────────────────────────────
	var (
		secretsNav  *sidebarNavItem
		addNav      *sidebarNavItem
		searchNav   *sidebarNavItem
		healthNav   *sidebarNavItem
		settingsNav *sidebarNavItem
		adminNav    *sidebarNavItem
	)

	allNavItems := func() []*sidebarNavItem {
		all := []*sidebarNavItem{secretsNav, addNav, searchNav, healthNav, settingsNav, adminNav}
		var result []*sidebarNavItem
		for _, it := range all {
			if it != nil {
				result = append(result, it)
			}
		}
		return result
	}

	setActive := func(active *sidebarNavItem) {
		for _, it := range allNavItems() {
			if it == active {
				it.bar.Show()
				it.btn.Importance = widget.MediumImportance
			} else {
				it.bar.Hide()
				it.btn.Importance = widget.LowImportance
			}
			it.btn.Refresh()
			it.bar.Refresh()
		}
	}

	makeNavItem := func(label string, icon fyne.Resource, fn func()) *sidebarNavItem {
		btn := widget.NewButtonWithIcon("  "+label, icon, nil)
		btn.Alignment = widget.ButtonAlignLeading
		btn.Importance = widget.LowImportance
		bar := canvas.NewRectangle(accentColor())
		bar.SetMinSize(fyne.NewSize(3, 0))
		bar.Hide()
		wrap := container.NewBorder(nil, nil, bar, nil, btn)
		btn.OnTapped = fn
		return &sidebarNavItem{btn: btn, bar: bar, wrap: wrap}
	}

	// ── Nav items ─────────────────────────────────────────────────────────────
	secretsNav = makeNavItem("Secrets", theme.ListIcon(), func() {
		ui.guardNavigation(func() {
			setActive(secretsNav)
			ui.showSecretsList()
		})
	})

	addNav = makeNavItem("Add Secret", theme.ContentAddIcon(), func() {
		ui.guardNavigation(func() {
			setActive(addNav)
			ui.showAddSecret()
		})
	})

	searchNav = makeNavItem("Search", theme.SearchIcon(), func() {
		ui.guardNavigation(func() {
			setActive(searchNav)
			ui.showSearch()
		})
	})

	healthNav = makeNavItem("Vault Health", theme.WarningIcon(), func() {
		ui.guardNavigation(func() {
			setActive(healthNav)
			ui.showVaultHealth()
		})
	})

	settingsNav = makeNavItem("Settings", theme.SettingsIcon(), func() {
		ui.guardNavigation(func() {
			setActive(settingsNav)
			ui.showSettings()
		})
	})

	// Secrets is the default active item on load.
	secretsNav.bar.Show()
	secretsNav.btn.Importance = widget.MediumImportance

	lockBtn := widget.NewButtonWithIcon("  Lock Vault", theme.LogoutIcon(), func() {
		dialog.ShowConfirm(
			"Log Out",
			"Are you sure you want to log out?",
			func(confirmed bool) {
				if !confirmed {
					return
				}
				ui.formDirty = false
				_ = ui.vault.Logout()
				ui.currentUser = ""
				ui.showLandingScreen()
			},
			ui.window,
		)
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
		secretsNav.wrap,
	}

	if hasPerm(auth.CanCreateSecret) {
		navItems = append(navItems, addNav.wrap)
	}
	if hasPerm(auth.CanViewSecrets) {
		navItems = append(navItems, searchNav.wrap)
		navItems = append(navItems, healthNav.wrap)
	}

	navItems = append(navItems,
		widget.NewSeparator(),
		settingsNav.wrap,
	)

	if hasPerm(auth.CanViewUsers) || hasPerm(auth.CanViewAuditLogs) || hasPerm(auth.CanManagePolicy) || hasPerm(auth.CanManageSessions) || hasPerm(auth.CanExportData) {
		adminNav = makeNavItem("Admin Dashboard", theme.GridIcon(), func() {
			ui.guardNavigation(func() {
				setActive(adminNav)
				ui.showAdminDashboard()
			})
		})
		navItems = append(navItems, widget.NewSeparator(), adminNav.wrap)
	}

	// About nav item — loads in content pane like all other destinations.
	aboutNavItem := makeNavItem("About", theme.InfoIcon(), func() {
		ui.guardNavigation(func() {
			setActive(nil) // deactivate all core nav items
			ui.showAbout()
		})
	})

	navItems = append(navItems,
		layout.NewSpacer(),
		widget.NewSeparator(),
		aboutNavItem.wrap,
		lockBtn,
	)

	sidebarContent := container.NewPadded(container.NewVBox(navItems...))

	bg := canvas.NewRectangle(sidebarBgColor())
	return container.NewStack(bg, sidebarContent)
}

// showSecretsList shows the list of secrets with live search and category filter chips.
func (ui *LocalVaultUI) showSecretsList() {
	ui.resetActivity()
	secrets, err := ui.vault.ListSecrets()
	if err != nil {
		ui.showError("Failed to load secrets", err)
		return
	}

	// Filter out system entries
	var allSecrets []*vault.SecretData
	for _, s := range secrets {
		if s.Category != "__SYSTEM__" {
			allSecrets = append(allSecrets, s)
		}
	}

	addSecretBtn := makeLowBtn("+ Add Secret", nil, func() {
		ui.showAddSecret()
	})

	pageHeader := makePageHeader(
		"Your Secrets",
		fmt.Sprintf("%d secrets stored", len(allSecrets)),
		addSecretBtn,
	)

	if len(allSecrets) == 0 {
		emptyIcon := widget.NewIcon(theme.ContentAddIcon())
		emptyTitle := widget.NewLabelWithStyle("Your vault is empty", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
		emptyDesc := makeMutedLabel("Click \"Add Secret\" to store your first password, API key, or other credential.")
		emptyDesc.Alignment = fyne.TextAlignCenter
		emptyDesc.Wrapping = fyne.TextWrapWord
		addFirstBtn := makePrimaryBtn("Add Your First Secret", theme.ContentAddIcon(), func() {
			ui.showAddSecret()
		})
		emptyState := container.NewCenter(container.NewVBox(
			container.NewCenter(emptyIcon),
			container.NewPadded(emptyTitle),
			container.NewPadded(emptyDesc),
			widget.NewSeparator(),
			container.NewCenter(addFirstBtn),
		))
		ui.content.Objects = []fyne.CanvasObject{
			container.NewBorder(pageHeader, nil, nil, nil, emptyState),
		}
		ui.content.Refresh()
		return
	}

	// Collect unique categories for the filter chip row
	catSet := map[string]struct{}{}
	for _, s := range allSecrets {
		cat := s.Category
		if cat == "" {
			cat = "uncategorised"
		}
		catSet[cat] = struct{}{}
	}
	var categories []string
	for c := range catSet {
		categories = append(categories, c)
	}
	sort.Strings(categories)

	// filteredSecrets is closed over by the list callbacks and applyFilter.
	filteredSecrets := allSecrets
	var activeFilter string
	var searchQuery string

	// Forward-declare list so applyFilter can call list.Refresh().
	var list *widget.List

	applyFilter := func() {
		var out []*vault.SecretData
		q := strings.ToLower(searchQuery)
		for _, s := range allSecrets {
			cat := s.Category
			if cat == "" {
				cat = "uncategorised"
			}
			if activeFilter != "" && cat != activeFilter {
				continue
			}
			if q != "" &&
				!strings.Contains(strings.ToLower(s.Name), q) &&
				!strings.Contains(strings.ToLower(s.Username), q) {
				continue
			}
			out = append(out, s)
		}
		filteredSecrets = out
		list.Refresh()
	}

	// List rows: [0]=minH  [1]=HBox([0]=accent [1]=Center(icon) [2]=VBox(name,user) [3]=spacer [4]=Center(catBadge))
	list = widget.NewList(
		func() int { return len(filteredSecrets) },
		func() fyne.CanvasObject {
			nameLabel := widget.NewLabelWithStyle("Secret Name", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			userLabel := widget.NewLabelWithStyle("username", fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
			userLabel.Importance = widget.LowImportance
			catLabel := widget.NewLabel("category")
			catLabel.Importance = widget.LowImportance
			pill := canvas.NewRectangle(categoryColor("uncategorised"))
			pill.CornerRadius = 8
			catBadge := container.NewStack(pill, container.NewPadded(catLabel))
			accent := canvas.NewRectangle(accentColor())
			accent.SetMinSize(fyne.NewSize(3, 0))
			minH := canvas.NewRectangle(color.Transparent)
			minH.SetMinSize(fyne.NewSize(0, 28))
			return container.NewStack(
				minH,
				container.NewHBox(
					accent,
					container.NewCenter(widget.NewIcon(theme.AccountIcon())),
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

			outer, ok := o.(*fyne.Container)
			if !ok || len(outer.Objects) < 2 {
				return
			}
			// HBox: [0]=accent [1]=Center(icon) [2]=VBox(name,user) [3]=spacer [4]=Center(catBadge)
			row, ok := outer.Objects[1].(*fyne.Container)
			if !ok || len(row.Objects) < 5 {
				return
			}
			iconCenter, ok := row.Objects[1].(*fyne.Container)
			if !ok || len(iconCenter.Objects) < 1 {
				return
			}
			iconWidget, ok := iconCenter.Objects[0].(*widget.Icon)
			if !ok {
				return
			}
			centre, ok := row.Objects[2].(*fyne.Container)
			if !ok || len(centre.Objects) < 2 {
				return
			}
			nameLabel, ok := centre.Objects[0].(*widget.Label)
			if !ok {
				return
			}
			userLabel, ok := centre.Objects[1].(*widget.Label)
			if !ok {
				return
			}

			nameLabel.SetText(secret.Name)
			userHint := secret.Username
			if userHint == "" {
				userHint = secret.URL
			}
			if userHint == "" {
				userHint = "no username"
			}
			userLabel.SetText(userHint)

			cat := secret.Category
			if cat == "" {
				cat = "uncategorised"
			}
			iconWidget.SetResource(categoryIcon(cat))

			centeredBadge, ok := row.Objects[4].(*fyne.Container)
			if !ok || len(centeredBadge.Objects) < 1 {
				return
			}
			badge, ok := centeredBadge.Objects[0].(*fyne.Container)
			if !ok || len(badge.Objects) < 2 {
				return
			}
			pill, ok := badge.Objects[0].(*canvas.Rectangle)
			if !ok {
				return
			}
			padded, ok := badge.Objects[1].(*fyne.Container)
			if !ok || len(padded.Objects) < 1 {
				return
			}
			catLabel, ok := padded.Objects[0].(*widget.Label)
			if !ok {
				return
			}
			col := categoryColor(cat)
			pill.FillColor = col
			pill.Refresh()
			catLabel.SetText(cat)
		},
	)

	list.OnSelected = func(id widget.ListItemID) {
		if id < len(filteredSecrets) {
			ui.detailBack = ui.showSecretsList
			ui.showSecretDetails(filteredSecrets[id])
		}
		list.UnselectAll()
	}

	searchBar := makeSearchBar("Search by name or username…", func(q string) {
		searchQuery = q
		applyFilter()
	})

	categoryRow := makeCategoryFilterRow(categories, func(cat string) {
		activeFilter = cat
		applyFilter()
	})

	toolbar := container.NewPadded(container.NewVBox(
		searchBar,
		categoryRow,
		widget.NewSeparator(),
	))

	ui.content.Objects = []fyne.CanvasObject{
		container.NewBorder(
			container.NewVBox(pageHeader, toolbar),
			nil, nil, nil,
			list,
		),
	}
	ui.content.Refresh()
}

// showSecretDetails shows details of a secret with reveal toggle and copy rows.
func (ui *LocalVaultUI) showSecretDetails(secret *vault.SecretData) {
	ui.resetActivity()
	// Fetch full decrypted secret via audited call — the list may contain scrubbed entries.
	full, err := ui.vault.GetSecretAudited(secret.ID)
	if err != nil {
		ui.showError("Failed to load secret", err)
		return
	}
	secret = full

	// ── Header ────────────────────────────────────────────────────────────────
	versionCount := len(secret.PasswordHistory) + 1
	metaLine := widget.NewLabelWithStyle(
		fmt.Sprintf("Created: %s  ·  Updated: %s  ·  Versions: %d",
			secret.CreatedAt.Format("2006-01-02"),
			secret.UpdatedAt.Format("2006-01-02 15:04"),
			versionCount,
		),
		fyne.TextAlignLeading, fyne.TextStyle{Italic: true},
	)
	metaLine.Importance = widget.LowImportance

	// ── Copy helpers ──────────────────────────────────────────────────────────
	doCopy := func(value, label string) {
		if ui.vault.HasPermission(auth.CanCopySecret) {
			_ = ui.clipboardManager.CopyToClipboard(value)
			ui.showNotification(label + " copied (auto-clears in 30s)")
		}
	}

	// ── Password reveal toggle ────────────────────────────────────────────────
	pwEntry := widget.NewEntry()
	pwEntry.SetText(secret.Password)
	pwEntry.Password = true
	pwEntry.Disable()

	var revealBtn *widget.Button
	revealed := false
	revealBtn = widget.NewButtonWithIcon("", theme.VisibilityIcon(), func() {
		revealed = !revealed
		pwEntry.Password = !revealed
		if revealed {
			revealBtn.SetIcon(theme.VisibilityOffIcon())
		} else {
			revealBtn.SetIcon(theme.VisibilityIcon())
		}
		pwEntry.Refresh()
	})
	revealBtn.Importance = widget.LowImportance

	copyPwBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		doCopy(secret.Password, "Password")
	})
	copyPwBtn.Importance = widget.LowImportance
	if !ui.vault.HasPermission(auth.CanCopySecret) {
		copyPwBtn.Disable()
	}

	pwRow := makeFormRow("Password",
		container.NewBorder(nil, nil, nil,
			container.NewHBox(revealBtn, copyPwBtn),
			pwEntry,
		),
	)

	// ── Username row ──────────────────────────────────────────────────────────
	copyUserBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		doCopy(secret.Username, "Username")
	})
	copyUserBtn.Importance = widget.LowImportance
	if !ui.vault.HasPermission(auth.CanCopySecret) || secret.Username == "" {
		copyUserBtn.Disable()
	}
	userEntry := widget.NewEntry()
	userEntry.SetText(secret.Username)
	userEntry.Disable()
	userRow := makeFormRow("Username",
		container.NewBorder(nil, nil, nil, copyUserBtn, userEntry),
	)

	// ── URL row — only shown when the secret has a URL ───────────────────────
	var urlRow fyne.CanvasObject
	if secret.URL != "" {
		urlEntry := widget.NewEntry()
		urlEntry.SetText(secret.URL)
		urlEntry.Disable()
		urlRow = makeFormRow("URL", urlEntry)
	}

	// ── Category / Tags ───────────────────────────────────────────────────────
	cat := secret.Category
	if cat == "" {
		cat = "uncategorised"
	}
	tagsStr := "—"
	if len(secret.Tags) > 0 {
		tagsStr = strings.Join(secret.Tags, ", ")
	}

	credItems := []fyne.CanvasObject{
		container.NewPadded(userRow),
		container.NewPadded(pwRow),
	}
	if urlRow != nil {
		credItems = append(credItems, container.NewPadded(urlRow))
	}
	credCard := widget.NewCard("Credentials", "", container.NewVBox(credItems...))

	metaItems := []fyne.CanvasObject{
		container.NewPadded(makeInfoRow(theme.ListIcon(), "Category", cat)),
		container.NewPadded(makeInfoRow(theme.MenuIcon(), "Tags", tagsStr)),
	}
	if secret.Notes != "" {
		notesEntry := widget.NewMultiLineEntry()
		notesEntry.SetText(secret.Notes)
		notesEntry.Disable()
		metaItems = append(metaItems, widget.NewSeparator(), container.NewPadded(notesEntry))
	}
	metaCard := widget.NewCard("Details", "", container.NewVBox(metaItems...))

	// ── Permission-gated action buttons ───────────────────────────────────────
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
	if owner == "" {
		owner = secret.CreatedBy
	}
	isOwner := strings.EqualFold(owner, ui.currentUser)

	canEdit := hasRolePerm(auth.CanEditSecret)
	canDelete := hasRolePerm(auth.CanDeleteSecret)
	if !isOwner {
		access := sm.GetGranteeAccess(secret.ID, ui.currentUser)
		if access != nil {
			canEdit = access.CanUpdate
			canDelete = access.CanDelete
		} else {
			canEdit = false
			canDelete = false
		}
	}
	canShare := isOwner && canEdit

	// Determine back destination — default to secrets list if not set.
	backFn := ui.detailBack
	if backFn == nil {
		backFn = ui.showSecretsList
	}
	backBtn := makeLowBtn("Back", theme.NavigateBackIcon(), backFn)

	var actionBtns []fyne.CanvasObject
	actionBtns = append(actionBtns, backBtn)
	if canEdit {
		actionBtns = append(actionBtns,
			makePrimaryBtn("Edit", theme.DocumentCreateIcon(), func() { ui.showEditSecret(secret) }),
		)
	}
	if ui.vault.HasPermission(auth.CanManagePolicy) {
		actionBtns = append(actionBtns,
			makeSecondaryBtn("History", theme.HistoryIcon(), func() { ui.showPasswordHistory(secret) }),
		)
	}
	if canShare {
		actionBtns = append(actionBtns,
			makeSecondaryBtn("Share", theme.AccountIcon(), func() { ui.showShareSecretDialog(secret) }),
		)
	}
	if canDelete {
		actionBtns = append(actionBtns,
			makeDangerBtn("Delete", theme.DeleteIcon(), func() {
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
			}),
		)
	}

	// Wrap buttons in a grid so they reflow instead of overflowing horizontally
	// when many actions are visible (e.g. admin with Back+Edit+History+Share+Delete).
	cols := len(actionBtns)
	if cols > 3 {
		cols = 3
	}
	actionGrid := container.NewGridWithColumns(cols, actionBtns...)

	form := container.NewVBox(
		makePageHeader(secret.Name, metaLine.Text, nil),
		container.NewPadded(credCard),
		container.NewPadded(metaCard),
		widget.NewSeparator(),
		container.NewPadded(actionGrid),
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

// showAddSecret shows the add secret form.
func (ui *LocalVaultUI) showAddSecret() {
	ui.resetActivity()
	if !ui.vault.HasPermission(auth.CanCreateSecret) {
		ui.showError("Permission denied", fmt.Errorf("missing %s", auth.CanCreateSecret))
		return
	}

	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Required")

	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username / email")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Required")

	generateBtn := makeLowBtn("Generate", theme.ViewRefreshIcon(), func() {
		if !ui.vault.HasPermission(auth.CanRotateSecret) {
			ui.showError("Permission denied", fmt.Errorf("missing %s", auth.CanRotateSecret))
			return
		}
		passwordEntry.SetText(generateSecurePassword(20))
	})

	urlEntry := widget.NewEntry()
	urlEntry.SetPlaceHolder("https://example.com (optional)")

	notesEntry := widget.NewMultiLineEntry()
	notesEntry.SetPlaceHolder("Notes (optional)")
	notesEntry.SetMinRowsVisible(3)

	categorySelect := widget.NewSelect(
		[]string{"login", "api", "wifi", "server", "database", "other"},
		nil,
	)
	categorySelect.SetSelected("login")

	tagsEntry := widget.NewEntry()
	tagsEntry.SetPlaceHolder("comma-separated")

	errorLabel := makeErrorLabel()

	// Mark form dirty on any field change so nav guard can warn before leaving.
	markDirty := func(_ string) { ui.formDirty = true }
	nameEntry.OnChanged = markDirty
	usernameEntry.OnChanged = markDirty
	passwordEntry.OnChanged = markDirty
	urlEntry.OnChanged = markDirty
	tagsEntry.OnChanged = markDirty
	notesEntry.OnChanged = markDirty

	doSave := func() {
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
		var tags []string
		for _, t := range strings.Split(tagsEntry.Text, ",") {
			if t = strings.TrimSpace(t); t != "" {
				tags = append(tags, t)
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
		ui.formDirty = false
		ui.showNotification("Secret saved successfully")
		ui.showSecretsList()
	}

	pwRow := container.NewBorder(nil, nil, nil, generateBtn, makeFullWidthEntry(passwordEntry))

	formCard := widget.NewCard("New Secret", "Fields marked * are required", container.NewVBox(
		container.NewPadded(makeFormRow("Name *", makeFullWidthEntry(nameEntry))),
		container.NewPadded(makeFormRow("Username", makeFullWidthEntry(usernameEntry))),
		container.NewPadded(makeFormRow("Password *", pwRow)),
		container.NewPadded(makeFormRow("URL", makeFullWidthEntry(urlEntry))),
		container.NewPadded(makeFormRow("Category", categorySelect)),
		container.NewPadded(makeFormRow("Tags", makeFullWidthEntry(tagsEntry))),
		makeDivider(),
		container.NewPadded(makeSectionTitle("Notes")),
		container.NewPadded(notesEntry),
	))

	form := container.NewVBox(
		container.NewPadded(formCard),
		container.NewPadded(container.NewVBox(
			errorLabel,
			makeButtonBar(
				makePrimaryBtn("Save", theme.DocumentSaveIcon(), doSave),
				makeLowBtn("Cancel", theme.CancelIcon(), func() {
					ui.formDirty = false
					ui.showSecretsList()
				}),
			),
		)),
	)

	ui.content.Objects = []fyne.CanvasObject{container.NewScroll(form)}
	ui.content.Refresh()
	ui.window.Canvas().Focus(nameEntry)
}

// showEditSecret shows the edit secret form.
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


	generateBtn := makeLowBtn("Generate", theme.ViewRefreshIcon(), func() {
		if !ui.vault.HasPermission(auth.CanRotateSecret) {
			ui.showError("Permission denied", fmt.Errorf("missing %s", auth.CanRotateSecret))
			return
		}
		passwordEntry.SetText(generateSecurePassword(20))
	})

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

	errorLabel := makeErrorLabel()

	// Mark dirty on any change so nav guard can warn before discarding.
	markDirty := func(_ string) { ui.formDirty = true }
	nameEntry.OnChanged = markDirty
	usernameEntry.OnChanged = markDirty
	passwordEntry.OnChanged = markDirty
	urlEntry.OnChanged = markDirty
	tagsEntry.OnChanged = markDirty
	notesEntry.OnChanged = markDirty

	doSave := func() {
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
		var tags []string
		for _, t := range strings.Split(tagsEntry.Text, ",") {
			if t = strings.TrimSpace(t); t != "" {
				tags = append(tags, t)
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
		ui.formDirty = false
		ui.showNotification("Secret updated successfully")
		ui.showSecretsList()
	}

	editPwRow := container.NewBorder(nil, nil, nil, generateBtn, makeFullWidthEntry(passwordEntry))

	editCard := widget.NewCard("Edit Secret", secret.Name, container.NewVBox(
		container.NewPadded(makeFormRow("Name *", makeFullWidthEntry(nameEntry))),
		container.NewPadded(makeFormRow("Username", makeFullWidthEntry(usernameEntry))),
		container.NewPadded(makeFormRow("Password *", editPwRow)),
		container.NewPadded(makeFormRow("URL", makeFullWidthEntry(urlEntry))),
		container.NewPadded(makeFormRow("Category", categorySelect)),
		container.NewPadded(makeFormRow("Tags", makeFullWidthEntry(tagsEntry))),
		makeDivider(),
		container.NewPadded(makeSectionTitle("Notes")),
		container.NewPadded(notesEntry),
	))

	actionBtns := []fyne.CanvasObject{
		makePrimaryBtn("Save", theme.DocumentSaveIcon(), doSave),
		makeLowBtn("Cancel", theme.CancelIcon(), func() {
			ui.formDirty = false
			ui.showSecretDetails(secret)
		}),
	}
	if ui.vault.HasPermission(auth.CanManagePolicy) {
		actionBtns = append(actionBtns,
			makeSecondaryBtn("History", theme.HistoryIcon(), func() { ui.showPasswordHistory(secret) }),
		)
	}

	form := container.NewVBox(
		container.NewPadded(editCard),
		container.NewPadded(container.NewVBox(
			errorLabel,
			makeButtonBar(actionBtns...),
		)),
	)

	ui.content.Objects = []fyne.CanvasObject{container.NewScroll(form)}
	ui.content.Refresh()
	ui.window.Canvas().Focus(nameEntry)
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
		errLbl := makeErrorLabel()

		grantBtn := makePrimaryBtn("Grant Access", theme.ConfirmIcon(), func() {
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

		shareSection = container.NewVBox(
			makeHeading("Grant access to:"),
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
			makeHeading("User"), makeHeading("Edit"), makeHeading("Delete"), makeHeading("Actions"),
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
			revokeBtn := makeDangerBtn("Revoke", theme.CancelIcon(), func() {
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
		makeHeading(fmt.Sprintf("Sharing: %s", secret.Name)),
		makeDivider(),
		makeHeading("Current access"),
		sharesSection,
		makeDivider(),
		shareSection,
	)

	scroll := container.NewVScroll(content)
	scroll.SetMinSize(fyne.NewSize(460, 320))
	d := dialog.NewCustom("Shared Access", "Close", scroll, ui.window)
	d.Resize(fyne.NewSize(500, 440))
	d.Show()
}

// showPasswordHistory shows password history for a secret
func (ui *LocalVaultUI) showPasswordHistory(secret *vault.SecretData) {
	// Only administrators may view password history
	if !ui.vault.HasPermission(auth.CanManagePolicy) {
		ui.showError("Permission denied", fmt.Errorf("only administrators may view password history"))
		return
	}
	history, err := ui.vault.GetPasswordHistory(secret.ID)
	if err != nil {
		ui.showError("Failed to load history", err)
		return
	}

	var items []fyne.CanvasObject
	items = append(items, makeHeading(fmt.Sprintf("Password History: %s", secret.Name)), makeDivider())

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
			items = append(items, makeDivider())
		}
	}

	items = append(items, makeLowBtn("Back", theme.NavigateBackIcon(), func() {
		ui.showSecretDetails(secret)
	}))

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

	// Load all secrets once to derive the real category list.
	allSecrets, _ := ui.vault.ListSecrets()
	catSet := map[string]struct{}{}
	for _, s := range allSecrets {
		if s.Category != "__SYSTEM__" {
			cat := s.Category
			if cat == "" {
				cat = "uncategorised"
			}
			catSet[cat] = struct{}{}
		}
	}
	var categories []string
	for c := range catSet {
		categories = append(categories, c)
	}
	sort.Strings(categories)

	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Type a name to search…")

	var activeCategory string

	resultsContainer := container.NewVBox()
	resultsLabel := widget.NewLabelWithStyle("Results", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	resultsLabel.Hide()

	doSearch := func() {
		query := strings.TrimSpace(searchEntry.Text)

		results, err := ui.vault.SearchSecrets(query, activeCategory, nil)
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
				sep := widget.NewLabel("·")
				sep.Importance = widget.LowImportance
				catLabel := widget.NewLabel(cat)
				catLabel.Importance = widget.LowImportance
				row := container.NewHBox(
					widget.NewIcon(categoryIcon(cat)),
					nameLabel,
					sep,
					catLabel,
					layout.NewSpacer(),
					makeLowBtn("Open", nil, func() {
						ui.detailBack = ui.showSearch
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

	// Category chip filter — same pattern as secrets list.
	categoryRow := makeCategoryFilterRow(categories, func(cat string) {
		activeCategory = cat
		doSearch()
	})

	searchEntry.OnSubmitted = func(_ string) { doSearch() }

	searchBar := makeSearchBar("Type a name to search…", func(q string) {
		searchEntry.SetText(q)
		doSearch()
	})

	page := container.NewVBox(
		makePageHeader("Search", "Find secrets by name or category", nil),
		container.NewPadded(widget.NewCard("", "", container.NewVBox(
			container.NewPadded(searchBar),
			container.NewPadded(categoryRow),
		))),
		container.NewPadded(container.NewVBox(resultsLabel, resultsContainer)),
	)

	ui.content.Objects = []fyne.CanvasObject{container.NewScroll(page)}
	ui.content.Refresh()
	ui.window.Canvas().Focus(searchEntry)
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

	// ── Profile tab ───────────────────────────────────────────────────────────
	emailDisplay := profile.Email
	if emailDisplay == "" {
		emailDisplay = "(not set)"
	}
	profileInfoRows := container.NewVBox(
		makeInfoRow(theme.AccountIcon(), "Username", profile.Username),
		makeDivider(),
		makeInfoRow(theme.MailComposeIcon(), "Email", emailDisplay),
		makeDivider(),
		makeInfoRow(theme.ListIcon(), "Role", profile.Role),
		makeDivider(),
		makeInfoRow(theme.HistoryIcon(), "Created", profile.CreatedAt.Format("2006-01-02")),
		makeDivider(),
		makeInfoRow(theme.LoginIcon(), "Last Login", profile.LastLogin.Format("2006-01-02 15:04")),
	)
	profileContent := container.NewVBox(
		makeSectionCard("Account Details", "Your account information", profileInfoRows),
		container.NewPadded(makeButtonBar(
			makePrimaryBtn("Edit Profile", theme.DocumentCreateIcon(), func() {
				ui.showEditProfileDialog()
			}),
		)),
	)
	profileTab := container.NewTabItem("Profile", boundedScroll(container.NewPadded(profileContent)))

	// ── Security tab ──────────────────────────────────────────────────────────
	mfaStatus := "Disabled"
	mfaImp := widget.WarningImportance
	if profile.MFAEnabled {
		mfaStatus = "Enabled"
		mfaImp = widget.SuccessImportance
	}
	mfaStatusLabel := widget.NewLabel(mfaStatus)
	mfaStatusLabel.Importance = mfaImp

	securityInfoRows := container.NewVBox(
		makeInfoRow(theme.ConfirmIcon(), "MFA Status", mfaStatus),
	)
	securityContent := container.NewVBox(
		makeSectionCard("Security Status", "Configure your account security settings", securityInfoRows),
		container.NewPadded(makeButtonBar(
			makePrimaryBtn("Change Password", theme.AccountIcon(), func() { ui.showChangePassword() }),
			makeSecondaryBtn("Configure MFA", theme.SettingsIcon(), func() { ui.showMFASettings() }),
		)),
	)
	_ = mfaStatusLabel // consumed inline above
	securityTab := container.NewTabItem("Security", boundedScroll(container.NewPadded(securityContent)))

	// ── Backup tab ────────────────────────────────────────────────────────────
	stats, _ := ui.vault.GetStatsByUser()
	backupInfoRows := container.NewVBox(
		makeInfoRow(theme.StorageIcon(), "Your secrets", fmt.Sprintf("%v", stats["my_entries"])),
		makeDivider(),
		makeInfoRow(theme.FileIcon(), "Vault file", fmt.Sprintf("%v", stats["file_path"])),
	)
	// "Total in vault" reveals how many secrets other users own — restrict to
	// roles that already have full vault visibility (SecurityOfficer, Administrator).
	if ui.vault.HasPermission(auth.CanViewAuditLogs) {
		backupInfoRows.Add(makeDivider())
		backupInfoRows.Add(makeInfoRow(theme.FolderIcon(), "Total in vault", fmt.Sprintf("%v", stats["total_entries"])))
	}
	backupContent := container.NewVBox(
		makeSectionCard("Vault Statistics", "Storage information and backup options", backupInfoRows),
		container.NewPadded(makeButtonBar(
			makePrimaryBtn("Export Vault Backup", theme.DownloadIcon(), func() {
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
			}),
		)),
	)
	backupTab := container.NewTabItem("Backup", boundedScroll(container.NewPadded(backupContent)))

	tabs := []*container.TabItem{profileTab, securityTab, backupTab}

	// ── Admin tab (role-gated) ────────────────────────────────────────────────
	if ui.vault.HasPermission(auth.CanManagePolicy) || ui.vault.HasPermission(auth.CanViewUsers) ||
		ui.vault.HasPermission(auth.CanViewAuditLogs) {

		adminItems := []fyne.CanvasObject{
			container.NewPadded(makePrimaryBtn("Open Admin Dashboard", theme.GridIcon(), func() {
				ui.showAdminDashboard()
			})),
		}
		if ui.vault.HasPermission(auth.CanManagePolicy) {
			vaultKeyCard := widget.NewCard("Vault Access Key",
				"Require all users to enter a shared key after login.",
				ui.buildVaultKeySettings(),
			)
			adminItems = append(adminItems, container.NewPadded(vaultKeyCard))
		}
		adminTab := container.NewTabItem("Admin",
			boundedScroll(container.NewPadded(container.NewVBox(adminItems...))))
		tabs = append(tabs, adminTab)
	}

	appTabs := container.NewAppTabs(tabs...)
	appTabs.SetTabLocation(container.TabLocationTop)

	pageHeader := makePageHeader("Settings", "Manage your account and vault configuration", nil)

	ui.content.Objects = []fyne.CanvasObject{
		container.NewBorder(pageHeader, nil, nil, nil, appTabs),
	}
	ui.content.Refresh()
}

// showChangePassword shows password change form.
func (ui *LocalVaultUI) showChangePassword() {
	currentEntry := widget.NewPasswordEntry()
	currentEntry.SetPlaceHolder("Current password")

	newEntry := widget.NewPasswordEntry()
	newEntry.SetPlaceHolder("Must meet security policy")

	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("Re-enter new password")

	errorLabel := makeErrorLabel()

	doChange := func() {
		errorLabel.SetText("")
		if newEntry.Text != confirmEntry.Text {
			errorLabel.SetText("New passwords do not match")
			return
		}
		if err := ui.vault.ChangePassword(currentEntry.Text, newEntry.Text); err != nil {
			errorLabel.SetText(err.Error())
			return
		}
		dialog.ShowInformation("Password Changed",
			"Password changed successfully. Please log in again with your new password.",
			ui.window)
		ui.showLandingScreen()
	}
	confirmEntry.OnSubmitted = func(_ string) { doChange() }

	card := widget.NewCard("Change Password", "", container.NewVBox(
		container.NewPadded(makeFormRow("Current", currentEntry)),
		container.NewPadded(makeFormRow("New", newEntry)),
		container.NewPadded(makeFormRow("Confirm", confirmEntry)),
		makeDivider(),
		container.NewPadded(errorLabel),
		container.NewPadded(makeButtonBar(
			makePrimaryBtn("Change Password", theme.ConfirmIcon(), doChange),
			makeLowBtn("Cancel", theme.CancelIcon(), func() { ui.showSettings() }),
		)),
	))

	ui.content.Objects = []fyne.CanvasObject{container.NewPadded(card)}
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

	errorLabel := makeErrorLabel()

	changeBtn := makePrimaryBtn("Set New Password", theme.ConfirmIcon(), func() {
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

	logoutBtn := makeLowBtn("Logout Instead", theme.CancelIcon(), func() {
		dialog.ShowConfirm(
			"Log Out",
			"Are you sure you want to log out?",
			func(confirmed bool) {
				if !confirmed {
					return
				}
				_ = ui.vault.Logout()
				ui.currentUser = ""
				ui.showLandingScreen()
			},
			ui.window,
		)
	})

	fields := container.NewVBox(
		container.NewPadded(reasonLbl),
		makeDivider(),
		container.NewPadded(makeFormRow("Current", makeRevealEntry(currentEntry))),
		container.NewPadded(makeFormRow("New", makeRevealEntry(newEntry))),
		container.NewPadded(makeFormRow("Confirm", makeRevealEntry(confirmEntry))),
		container.NewPadded(errorLabel),
	)

	card := makeAuthCard("Password Change Required", "Set a new password to continue", container.NewVBox(
		container.NewPadded(fields),
		makeDivider(),
		container.NewPadded(makeButtonBar(changeBtn)),
		container.NewCenter(logoutBtn),
	))

	ui.window.SetContent(ui.withFooter(
		container.NewCenter(
			container.NewVBox(
				widthEnforcer,
				container.NewPadded(card),
			),
		),
	))
}

// showMFASettings shows MFA configuration
func (ui *LocalVaultUI) showMFASettings() {
	profile, _ := ui.vault.GetUserProfile()

	var cardBody fyne.CanvasObject
	var cardSubtitle string

	if profile.MFAEnabled {
		disableBtn := makeDangerBtn("Disable MFA", theme.DeleteIcon(), func() {
			dialog.ShowEntryDialog("Confirm Password", "Enter your password to disable MFA", func(password string) {
				if err := ui.vault.DisableMFA(password); err != nil {
					ui.showError("Failed to disable MFA", err)
				} else {
					ui.showNotification("MFA disabled")
					ui.showSettings()
				}
			}, ui.window)
		})
		cardSubtitle = "Two-factor authentication is active on your account"
		cardBody = container.NewVBox(
			makeInfoRow(theme.ConfirmIcon(), "Status", "Enabled"),
			makeDivider(),
			container.NewPadded(widget.NewLabel("Your vault is protected with two-factor authentication.")),
			container.NewPadded(makeButtonBar(disableBtn)),
		)
	} else {
		enableBtn := makePrimaryBtn("Set Up MFA Now", theme.ConfirmIcon(), func() {
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
			ui.showMFASetup(secret, false, ui.vault.VerifyAndActivateMFA, ui.showMFASettings)
		})
		mfaNote := widget.NewLabel("MFA is required by policy. Scan the QR code with Microsoft Authenticator (or any TOTP app) to protect your account.")
		mfaNote.Wrapping = fyne.TextWrapWord
		cardSubtitle = "Protect your account with two-factor authentication"
		cardBody = container.NewVBox(
			makeInfoRow(nil, "Status", "Disabled"),
			makeDivider(),
			container.NewPadded(mfaNote),
			container.NewPadded(makeButtonBar(enableBtn)),
		)
	}

	header := makePageHeader("MFA Configuration", "Manage two-factor authentication for your account", nil)
	card := makeSectionCard("Authentication Status", cardSubtitle, cardBody)
	backBtn := makeLowBtn("← Back to Settings", theme.NavigateBackIcon(), func() { ui.showSettings() })

	ui.content.Objects = []fyne.CanvasObject{
		container.NewBorder(
			header,
			container.NewPadded(makeButtonBar(backBtn)),
			nil, nil,
			boundedScroll(container.NewPadded(card)),
		),
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
		zeroAndClearBytes(ui.savedPassword)
		ui.savedPassword = nil
		ui.showLandingScreen()
		return
	}
	// Password no longer needed — zero and clear it now.
	zeroAndClearBytes(ui.savedPassword)
	ui.savedPassword = nil

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
		"1.  Open your authenticator app (Microsoft Authenticator, Google Authenticator, Authy, etc.)\n"+
			"2.  Add a new account and scan the QR code above\n"+
			"3.  Enter the 6-digit code shown in the app below to verify",
		fyne.TextAlignLeading, fyne.TextStyle{})

	// Manual-entry fallback
	manualNote := widget.NewLabelWithStyle("Can't scan?  Use this secret key:", fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
	manualNote.Importance = widget.LowImportance

	secretDisplay := widget.NewEntry()
	secretDisplay.SetText(secret)
	secretDisplay.Disable()

	copySecretBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		_ = ui.clipboardManager.CopyToClipboard(secret)
		ui.showNotification("Secret copied (auto-clears in 30s)")
	})

	// ── Verification ─────────────────────────────────────────────────────────
	codeEntry := widget.NewEntry()
	codeEntry.SetPlaceHolder("6-digit code from your app")
	codeEntry.OnChanged = func(s string) {
		filtered := ""
		for _, r := range s {
			if r >= '0' && r <= '9' {
				filtered += string(r)
			}
		}
		if len(filtered) > 6 {
			filtered = filtered[:6]
		}
		if filtered != s {
			codeEntry.SetText(filtered)
		}
	}

	errorLabel := makeErrorLabel()

	verifyBtn := makePrimaryBtn("Verify & Enable MFA", theme.ConfirmIcon(), func() {
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
	codeEntry.OnSubmitted = func(_ string) { verifyBtn.OnTapped() }

	copyURIBtn := makeLowBtn("Copy URI", theme.ContentCopyIcon(), func() {
		_ = ui.clipboardManager.CopyToClipboard(provisioningURI)
		ui.showNotification("Provisioning URI copied (auto-clears in 30s)")
	})

	formFields := container.NewVBox(
		makeFormRow("Secret key", container.NewBorder(nil, nil, nil, copySecretBtn, secretDisplay)),
		makeFormRow("Verify code", codeEntry),
	)

	// Shared body — used in both mandatory (full-window) and optional (content pane) layouts.
	sharedBody := container.NewVBox(
		container.NewCenter(qrWidget),
		container.NewCenter(copyURIBtn),
		makeDivider(),
		container.NewPadded(instructions),
		makeDivider(),
		container.NewPadded(manualNote),
		container.NewPadded(formFields),
		makeDivider(),
		errorLabel,
	)

	if mandatory {
		// ── Mandatory full-window layout ──────────────────────────────────────
		// No TextWrapWord — wrapped labels have zero min-height in Fyne cards.
		appTitle := makeCenteredHeading("Password Manager")
		appSub := widget.NewLabelWithStyle("Secure Enterprise Vault", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})
		appSub.Importance = widget.LowImportance

		warningLabel := widget.NewLabelWithStyle(
			"⚠  MFA is mandatory – complete setup to access your vault",
			fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
		warningLabel.Importance = widget.DangerImportance

		logoutBtn := makeLowBtn("Back to Login", theme.NavigateBackIcon(), func() {
			_ = ui.vault.Logout()
			ui.currentUser = ""
			ui.showLandingScreen()
		})

		mfaCard := widget.NewCard("Set Up Two-Factor Authentication", "",
			container.NewVBox(
				container.NewPadded(container.NewVBox(appTitle, appSub)),
				makeDivider(),
				warningLabel,
				makeDivider(),
				sharedBody,
				verifyBtn,
			),
		)

		cardArea := container.NewVScroll(container.NewCenter(
			container.NewVBox(minWidth(560), container.NewPadded(mfaCard)),
		))

		ui.window.SetContent(ui.withFooter(
			container.NewBorder(nil, container.NewCenter(logoutBtn), nil, nil, cardArea),
		))
	} else {
		// ── Non-mandatory: rendered inside the main content pane ──────────────
		cancelBtn := makeLowBtn("Cancel", theme.CancelIcon(), func() { ui.showMFASettings() })
		form := container.NewVBox(
			makeHeading("Set Up Two-Factor Authentication"),
			makeDivider(),
			sharedBody,
			makeButtonBar(verifyBtn, cancelBtn),
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
