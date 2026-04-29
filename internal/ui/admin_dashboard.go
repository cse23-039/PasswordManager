package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"password-manager/internal/auth"
	"password-manager/internal/models"
	"password-manager/internal/vault"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// showAdminDashboard renders the admin panel.
// Administrators see all 6 tabs; Security Officers see Audit Log and Security Policy only.
func (ui *LocalVaultUI) showAdminDashboard() {
	ui.resetActivity()
	can := func(permission string) bool {
		return ui.vault.HasPermission(permission)
	}

	var tabItems []*container.TabItem

	if can(auth.CanViewUsers) {
		tabItems = append(tabItems,
			container.NewTabItemWithIcon("Users", theme.AccountIcon(), boundedTabContent(ui.buildUsersTab())),
		)
	}

	if can(auth.CanViewAuditLogs) {
		tabItems = append(tabItems,
			container.NewTabItemWithIcon("Audit Log", theme.DocumentIcon(), boundedTabContent(ui.buildAuditTab("all"))),
		)
	}

	if can(auth.CanManageSessions) {
		tabItems = append(tabItems,
			container.NewTabItemWithIcon("Sessions", theme.ComputerIcon(), boundedTabContent(ui.buildSessionsTab())),
		)
	}
	if can(auth.CanExportData) || can(auth.CanBackupVault) || can(auth.CanRestoreVault) {
		tabItems = append(tabItems,
			container.NewTabItemWithIcon("Exports", theme.DownloadIcon(), boundedTabContent(ui.buildExportsTab())),
		)
	}

	if can(auth.CanManagePolicy) {
		tabItems = append(tabItems,
			container.NewTabItemWithIcon("Security Policy", theme.SettingsIcon(), boundedTabContent(ui.buildSecurityPolicyTab())),
		)
	}

	if can(auth.CanManageRoles) {
		tabItems = append(tabItems,
			container.NewTabItemWithIcon("Role Permissions", theme.ListIcon(), boundedTabContent(ui.buildRolePermissionsTab())),
		)
	}

	if len(tabItems) == 0 {
		ui.content.Objects = []fyne.CanvasObject{
			container.NewPadded(widget.NewLabel("You do not have permission to access the admin dashboard.")),
		}
		ui.content.Refresh()
		return
	}

	backBtn := makeLowBtn("Back to Secrets", theme.NavigateBackIcon(), func() {
		ui.showSecretsList()
	})
	dashHeader := makePageHeader(
		"Admin Dashboard",
		"Manage users, audit logs, sessions, and security policy.",
		backBtn,
	)

	tabs := container.NewAppTabs(tabItems...)
	ui.content.Objects = []fyne.CanvasObject{
		container.NewBorder(dashHeader, nil, nil, nil, tabs),
	}
	ui.content.Refresh()
}

// ─────────────────────────────────────────────────────────
// USERS TAB
// ─────────────────────────────────────────────────────────

func (ui *LocalVaultUI) buildUsersTab() fyne.CanvasObject {
	records, err := ui.vault.ListUserRecords()
	if err != nil {
		return widget.NewLabel(fmt.Sprintf("Error loading users: %v", err))
	}

	header := makeHeading(fmt.Sprintf("Registered Users — %d total", len(records)))

	createUserBtn := makePrimaryBtn("Create User", theme.ContentAddIcon(), func() {
		ui.showCreateUserDialog()
	})
	refreshBtn := makeLowBtn("Refresh", theme.ViewRefreshIcon(), func() {
		ui.showAdminDashboard()
	})

	actionBar := container.NewHBox(header, layout.NewSpacer(), createUserBtn, refreshBtn)

	// Sort state — 5 sortable cols; col 5 (Actions) is not sortable
	userSortCol := -1
	userSortAsc := true
	userSortNames := []string{"Username", "Role", "MFA", "Status", "Last Login"}
	userSortBtns := make([]*widget.Button, len(userSortNames))
	for i, n := range userSortNames {
		userSortBtns[i] = widget.NewButton(n, nil)
		userSortBtns[i].Importance = widget.LowImportance
	}

	updateUserSortLabels := func() {
		for i, n := range userSortNames {
			if i == userSortCol {
				if userSortAsc {
					userSortBtns[i].SetText(n + " \u25b2")
				} else {
					userSortBtns[i].SetText(n + " \u25bc")
				}
			} else {
				userSortBtns[i].SetText(n)
			}
		}
	}

	// Header: 5 sortable buttons + 1 plain label for Actions
	userCW := newColWidths([]float32{120, 110, 60, 80, 130, 100})
	headerCells := make([]fyne.CanvasObject, len(userSortBtns)+1)
	for i, b := range userSortBtns {
		headerCells[i] = b
	}
	headerCells[len(userSortBtns)] = makeHeading("Actions")
	colHeader, _ := buildResizableHeaderCustom(headerCells, userCW)

	var displayUsers []*vault.UserRecord
	var displayMu sync.RWMutex

	userList := widget.NewList(
		func() int {
			displayMu.RLock()
			n := len(displayUsers)
			displayMu.RUnlock()
			return n
		},
		func() fyne.CanvasObject {
			btn := widget.NewButtonWithIcon("Manage", theme.SettingsIcon(), func() {})
			btn.Importance = widget.LowImportance
			return rowWithWidths([]fyne.CanvasObject{
				truncLabel(""), roleLabel(""), truncLabel(""), statusLabel(""), truncLabel(""), btn,
			}, userCW)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			displayMu.RLock()
			if int(id) >= len(displayUsers) {
				displayMu.RUnlock()
				return
			}
			r := displayUsers[id]
			displayMu.RUnlock()

			mfaTxt := "No"
			if r.MFAEnabled {
				mfaTxt = "Yes"
			}
			statusTxt := "Active"
			if r.IsRevoked {
				statusTxt = "Revoked"
			}
			lastLogin := "Never"
			if !r.LastLogin.IsZero() {
				lastLogin = r.LastLogin.Local().Format("2006-01-02 15:04")
			}
			c := obj.(*fyne.Container)
			c.Objects[0].(*widget.Label).SetText(r.Username)
			rl := c.Objects[1].(*widget.Label)
			rl.SetText(r.Role)
			switch r.Role {
			case "administrator":
				rl.Importance = widget.DangerImportance
			case "security_officer":
				rl.Importance = widget.WarningImportance
			case "standard_user":
				rl.Importance = widget.MediumImportance
			default:
				rl.Importance = widget.LowImportance
			}
			rl.Refresh()
			c.Objects[2].(*widget.Label).SetText(mfaTxt)
			sl := c.Objects[3].(*widget.Label)
			sl.SetText(statusTxt)
			if r.IsRevoked {
				sl.Importance = widget.DangerImportance
			} else {
				sl.Importance = widget.SuccessImportance
			}
			sl.Refresh()
			c.Objects[4].(*widget.Label).SetText(lastLogin)
			btn := c.Objects[5].(*widget.Button)
			btn.OnTapped = func() { ui.showUserManageDialog(r) }
		},
	)

	var loadRows func()
	loadRows = func() {
		sorted := make([]*vault.UserRecord, len(records))
		copy(sorted, records)
		if userSortCol >= 0 {
			sort.SliceStable(sorted, func(i, j int) bool {
				a, b := sorted[i], sorted[j]
				var less bool
				switch userSortCol {
				case 0:
					less = strings.ToLower(a.Username) < strings.ToLower(b.Username)
				case 1:
					less = strings.ToLower(a.Role) < strings.ToLower(b.Role)
				case 2:
					less = a.MFAEnabled && !b.MFAEnabled
				case 3:
					as, bs := "Active", "Active"
					if a.IsRevoked {
						as = "Revoked"
					}
					if b.IsRevoked {
						bs = "Revoked"
					}
					less = as < bs
				case 4:
					less = a.LastLogin.Before(b.LastLogin)
				}
				if userSortAsc {
					return less
				}
				return !less
			})
		}
		displayMu.Lock()
		displayUsers = sorted
		displayMu.Unlock()
		userList.Refresh()
	}

	// Wire sort taps after loadRows is defined
	for i := range userSortBtns {
		i := i
		userSortBtns[i].OnTapped = func() {
			if userSortCol == i {
				userSortAsc = !userSortAsc
			} else {
				userSortCol = i
				userSortAsc = true
			}
			updateUserSortLabels()
			loadRows()
		}
	}

	loadRows()

	return container.NewBorder(
		container.NewVBox(actionBar, widget.NewSeparator(), colHeader, widget.NewSeparator()),
		nil, nil, nil,
		userList,
	)
}

// showUserManageDialog opens a dialog to change role / revoke / delete a user.
func (ui *LocalVaultUI) showUserManageDialog(rec *vault.UserRecord) {
	me := ui.currentUser
	if rec.Username == me {
		dialog.ShowInformation("Not Allowed", "You cannot modify your own account here.", ui.window)
		return
	}

	allRoles := []string{
		models.RoleAdministrator,
		models.RoleSecurityOfficer,
		models.RoleStandardUser,
		models.RoleReadOnly,
	}

	roleSelect := widget.NewSelect(allRoles, nil)
	roleSelect.Selected = rec.Role

	revokeBtn := makeDangerBtn("Revoke Access", theme.CancelIcon(), nil)
	deleteBtn := makeDangerBtn("Delete User", theme.DeleteIcon(), nil)

	if rec.IsRevoked {
		revokeBtn.SetText("Already Revoked")
		revokeBtn.Disable()
	}

	content := container.NewVBox(
		makeCenteredHeading(fmt.Sprintf("Managing: %s", rec.Username)),
		makeDivider(),
		makeFormRow("Assign Role", roleSelect),
		makeDivider(),
		revokeBtn,
		deleteBtn,
	)

	var d dialog.Dialog
	saveRoleBtn := makePrimaryBtn("Save Role", theme.ConfirmIcon(), func() {
		if err := ui.vault.ChangeUserRole(rec.Username, roleSelect.Selected, me); err != nil {
			dialog.ShowError(err, ui.window)
			return
		}
		d.Hide()
		dialog.ShowInformation("Done", fmt.Sprintf("Role updated to %s", roleSelect.Selected), ui.window)
		ui.showAdminDashboard()
	})

	revokeBtn.OnTapped = func() {
		dialog.ShowConfirm("Revoke Access",
			fmt.Sprintf("Revoke all access for '%s'? They will no longer be able to log in.", rec.Username),
			func(ok bool) {
				if !ok {
					return
				}
				if err := ui.vault.RevokeUserRecord(rec.Username, me); err != nil {
					dialog.ShowError(err, ui.window)
					return
				}
				d.Hide()
				dialog.ShowInformation("Done", fmt.Sprintf("'%s' has been revoked.", rec.Username), ui.window)
				ui.showAdminDashboard()
			}, ui.window)
	}

	deleteBtn.OnTapped = func() {
		dialog.ShowConfirm("Delete User",
			fmt.Sprintf("Permanently delete '%s'? This cannot be undone.", rec.Username),
			func(ok bool) {
				if !ok {
					return
				}
				if err := ui.vault.DeleteUserRecord(rec.Username, me); err != nil {
					dialog.ShowError(err, ui.window)
					return
				}
				d.Hide()
				dialog.ShowInformation("Done", fmt.Sprintf("'%s' has been deleted.", rec.Username), ui.window)
				ui.showAdminDashboard()
			}, ui.window)
	}

	full := container.NewVBox(content, saveRoleBtn)
	d = dialog.NewCustom(fmt.Sprintf("User: %s", rec.Username), "Cancel", full, ui.window)
	d.Show()
}

// showCreateUserDialog lets an administrator create a new user directly.
func (ui *LocalVaultUI) showCreateUserDialog() {
	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username (min 3 chars)")

	emailEntry := widget.NewEntry()
	emailEntry.SetPlaceHolder("Email (optional)")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password (min 12 chars)")

	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("Confirm password")

	allRoles := []string{
		models.RoleAdministrator,
		models.RoleSecurityOfficer,
		models.RoleStandardUser,
		models.RoleReadOnly,
	}
	roleSelect := widget.NewSelect(allRoles, nil)
	roleSelect.Selected = models.RoleReadOnly

	errorLbl := makeErrorLabel()

	form := container.NewVBox(
		makeFormRow("Username", makeFullWidthEntry(usernameEntry)),
		makeFormRow("Email", makeFullWidthEntry(emailEntry)),
		makeFormRow("Password", makeFullWidthEntry(passwordEntry)),
		makeFormRow("Confirm", makeFullWidthEntry(confirmEntry)),
		makeFormRow("Role", roleSelect),
	)

	content := container.NewVBox(form, errorLbl)

	var d dialog.Dialog
	saveBtn := makePrimaryBtn("Create User", theme.ContentAddIcon(), func() {
		errorLbl.SetText("")
		username := strings.TrimSpace(usernameEntry.Text)
		email := strings.TrimSpace(emailEntry.Text)
		password := passwordEntry.Text
		confirm := confirmEntry.Text
		if len(username) < 3 {
			errorLbl.SetText("Username must be at least 3 characters")
			return
		}
		if ok, errs := ui.vault.ValidatePasswordAgainstVaultPolicy(password); !ok {
			errorLbl.SetText(strings.Join(errs, " · "))
			return
		}
		if password != confirm {
			errorLbl.SetText("Passwords do not match")
			return
		}
		if err := ui.vault.RegisterUser(username, password, email, roleSelect.Selected); err != nil {
			errorLbl.SetText(err.Error())
			return
		}
		// Pre-generate MFA secret for the new user so first login can show QR immediately.
		if mfaSecret, mfaErr := ui.vault.SetupMFAForNewUser(username); mfaErr == nil {
			_ = mfaSecret // best-effort: UI will unwrap on first login; ignore failures
		}
		d.Hide()
		dialog.ShowInformation("User Created",
			fmt.Sprintf("User '%s' created with role '%s'.\n\nThey will be prompted to set up MFA on first login.",
				username, roleSelect.Selected),
			ui.window)
		ui.showAdminDashboard()
	})
	d = dialog.NewCustom("Create New User", "Cancel",
		container.NewVBox(content, saveBtn), ui.window)
	d.Resize(fyne.NewSize(420, 0))
	d.Show()
}

// ─────────────────────────────────────────────────────────
// AUDIT LOG TAB  (filters update body in-place — no tab jump)
// ─────────────────────────────────────────────────────────

func (ui *LocalVaultUI) buildAuditTab(initialFilter string) fyne.CanvasObject {
	currentFilter := initialFilter

	// ── Sort state ────────────────────────────────────────────────────────────
	sortCol := -1
	sortAsc := true
	colNames := []string{"Time", "User", "Event", "Details", "Result"}

	// ── Datetime range filter state ──────────────────────────────────────────
	var filterFrom, filterTo time.Time // both zero = no filter
	const noTime = "Any"
	const timeFmt = "2006-01-02 15:04"
	fromBtn := makeLowBtn(noTime, nil, nil)
	toBtn := makeLowBtn(noTime, nil, nil)

	// ── Sortable header buttons ───────────────────────────────────────────────
	sortBtns := make([]*widget.Button, len(colNames))
	for i, name := range colNames {
		name := name
		sortBtns[i] = widget.NewButton(name, nil)
		sortBtns[i].Importance = widget.LowImportance
	}
	updateSortLabels := func() {
		for i, name := range colNames {
			if i == sortCol {
				if sortAsc {
					sortBtns[i].SetText(name + " \u25b2")
				} else {
					sortBtns[i].SetText(name + " \u25bc")
				}
			} else {
				sortBtns[i].SetText(name)
			}
		}
	}

	headerCells := make([]fyne.CanvasObject, len(sortBtns))
	for i, b := range sortBtns {
		headerCells[i] = b
	}
	auditCW := newColWidths([]float32{180, 100, 160, 280, 80})
	colHeader, _ := buildResizableHeaderCustom(headerCells, auditCW)
	// Note: auditCW only tracks the 5 header cells — no row containers.
	// Column resize therefore refreshes exactly 5 objects regardless of row count.

	// ── Virtualized list (same rendering path as users/sessions tabs) ────────
	//
	// widget.List creates ~25 pooled row containers via CreateItem (one-time).
	// Each row uses rowWithWidths → registered with auditCW → column resize
	// calls auditCW.RefreshAll() on ~30 containers total, identical to users tab.
	// list.Refresh() only calls UpdateItem for visible rows — no 2D cell engine,
	// no per-cell mutex, no SetColumnWidth recalculation.
	var displayRows []*vault.VaultAuditEntry
	var displayMu sync.RWMutex

	list := widget.NewList(
		func() int {
			displayMu.RLock()
			n := len(displayRows)
			displayMu.RUnlock()
			return n
		},
		func() fyne.CanvasObject {
			return rowWithWidths([]fyne.CanvasObject{
				truncLabel(""), truncLabel(""), truncLabel(""), truncLabel(""), truncLabel(""),
			}, auditCW)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			displayMu.RLock()
			if int(id) >= len(displayRows) {
				displayMu.RUnlock()
				return
			}
			e := displayRows[id]
			displayMu.RUnlock()
			details := e.Details
			if e.ResourceName != "" {
				details = "[" + e.ResourceName + "] " + details
			}
			cols := [5]string{
				e.Timestamp.Local().Format("2006-01-02 15:04:05"),
				e.Username,
				e.Event,
				details,
				e.Result,
			}
			isFailure := strings.ToLower(e.Result) == "failure"
			c := obj.(*fyne.Container)
			for col, cell := range c.Objects {
				lbl := cell.(*widget.Label)
				lbl.SetText(cols[col])
				if col == 4 {
					if isFailure {
						lbl.Importance = widget.DangerImportance
					} else {
						lbl.Importance = widget.SuccessImportance
					}
				} else {
					lbl.Importance = widget.MediumImportance
				}
				lbl.Refresh()
			}
		},
	)
	// Column resize already calls auditCW.RefreshAll() from the drag handler,
	// which refreshes every tracked container including the pooled list rows.
	// No additional onColWidthChanged hook is needed.

	var filterBtns []*widget.Button
	var loadEntries func(string)
	loadEntries = func(filter string) {
		currentFilter = filter

		// Update filter-button highlights immediately (UI thread, cheap).
		filterKeys := []string{"all", "login", "failed", "admin", "security"}
		for i, btn := range filterBtns {
			if filterKeys[i] == filter {
				btn.Importance = widget.HighImportance
			} else {
				btn.Importance = widget.LowImportance
			}
			btn.Refresh()
		}

		// Snapshot mutable state before entering the goroutine.
		snapFilter := filter
		snapSortCol := sortCol
		snapSortAsc := sortAsc
		snapFrom := filterFrom
		snapTo := filterTo

		go func() {
			// 1. Fetch by event-type filter (O(1) index lookup).
			var entries []*vault.VaultAuditEntry
			switch snapFilter {
			case "login":
				entries = ui.vault.GetAuditEntriesByEvent(vault.AuditEventLogin)
			case "failed":
				entries = ui.vault.GetAuditEntriesByEvent(vault.AuditEventLoginFailed)
			case "admin":
				entries = ui.vault.GetAuditEntriesByCategory(vault.AuditCategoryAdmin)
			case "security":
				entries = ui.vault.GetAuditEntriesByCategory(vault.AuditCategorySecurity)
			default:
				entries = ui.vault.GetAllAuditEntries()
			}

			// 2. Datetime range filter.
			if !snapFrom.IsZero() || !snapTo.IsZero() {
				var ranged []*vault.VaultAuditEntry
				for _, e := range entries {
					t := e.Timestamp.UTC()
					if !snapFrom.IsZero() && t.Before(snapFrom) {
						continue
					}
					if !snapTo.IsZero() && t.After(snapTo) {
						continue
					}
					ranged = append(ranged, e)
				}
				entries = ranged
			}

			// 3. Column sort.
			if snapSortCol >= 0 {
				sort.SliceStable(entries, func(i, j int) bool {
					var less bool
					switch snapSortCol {
					case 0:
						less = entries[i].Timestamp.Before(entries[j].Timestamp)
					case 1:
						less = strings.ToLower(entries[i].Username) < strings.ToLower(entries[j].Username)
					case 2:
						less = strings.ToLower(entries[i].Event) < strings.ToLower(entries[j].Event)
					case 3:
						di := entries[i].Details
						if entries[i].ResourceName != "" {
							di = "[" + entries[i].ResourceName + "] " + di
						}
						dj := entries[j].Details
						if entries[j].ResourceName != "" {
							dj = "[" + entries[j].ResourceName + "] " + dj
						}
						less = strings.ToLower(di) < strings.ToLower(dj)
					case 4:
						less = strings.ToLower(entries[i].Result) < strings.ToLower(entries[j].Result)
					}
					if snapSortAsc {
						return less
					}
					return !less
				})
			}

			// 4. Swap display slice and refresh — list.Refresh() calls UpdateItem
			// only for visible rows.
			displayMu.Lock()
			displayRows = entries
			displayMu.Unlock()
			list.Refresh()
		}()
	}

	// Wire sort button taps
	for i := range sortBtns {
		i := i
		sortBtns[i].OnTapped = func() {
			if sortCol == i {
				sortAsc = !sortAsc
			} else {
				sortCol = i
				sortAsc = true
			}
			updateSortLabels()
			loadEntries(currentFilter)
		}
	}

	// ── Event-type filter buttons ─────────────────────────────────────────────
	makeBtn := func(label, key string) *widget.Button {
		btn := makeLowBtn(label, nil, func() { loadEntries(key) })
		filterBtns = append(filterBtns, btn)
		return btn
	}
	filterRow := container.NewHBox(
		makeHeading("Filter:"),
		makeBtn("All", "all"),
		makeBtn("Logins", "login"),
		makeBtn("Failed Logins", "failed"),
		makeBtn("Admin Actions", "admin"),
		makeBtn("Security", "security"),
		layout.NewSpacer(),
		makeLowBtn("Refresh", theme.ViewRefreshIcon(), func() {
			loadEntries(currentFilter)
		}),
	)

	// ── Date/time range filter row ──────────────────────────────────────────
	fromBtn.OnTapped = func() {
		initial := filterFrom
		if initial.IsZero() {
			initial = time.Now().UTC().Truncate(time.Hour)
		}
		showCalendarDialog("From", initial, ui.window, func(picked time.Time) {
			filterFrom = picked
			fromBtn.SetText(picked.UTC().Format(timeFmt))
			loadEntries(currentFilter)
		})
	}
	toBtn.OnTapped = func() {
		initial := filterTo
		if initial.IsZero() {
			initial = time.Now().UTC().Truncate(time.Hour)
		}
		showCalendarDialog("To", initial, ui.window, func(picked time.Time) {
			filterTo = picked
			toBtn.SetText(picked.UTC().Format(timeFmt))
			loadEntries(currentFilter)
		})
	}
	clearTimeBtn := makeLowBtn("Clear", nil, func() {
		filterFrom = time.Time{}
		filterTo = time.Time{}
		fromBtn.SetText(noTime)
		toBtn.SetText(noTime)
		loadEntries(currentFilter)
	})
	dateRow := container.NewHBox(
		makeHeading("From:"),
		fromBtn,
		makeHeading("To:"),
		toBtn,
		clearTimeBtn,
	)

	loadEntries(initialFilter)

	// ── Real-time chain integrity status bar ─────────────────────────────────
	// Stop any previous monitor goroutine before starting a new one.
	if ui.chainMonitorStop != nil {
		close(ui.chainMonitorStop)
	}
	stopCh := make(chan struct{})
	ui.chainMonitorStop = stopCh

	chainStatusLabel := widget.NewLabelWithStyle(
		"Chain Integrity: checking...",
		fyne.TextAlignLeading, fyne.TextStyle{Bold: true},
	)
	chainStatusLabel.Importance = widget.MediumImportance

	runChainCheck := func() {
		chainOK := ui.vault.VerifyChainIntegrity()
		verified, tampered, unverifiable := ui.vault.VerifyAllIntegrity()
		total := verified + tampered + unverifiable
		if tampered > 0 || !chainOK {
			chainStatusLabel.SetText(fmt.Sprintf(
				"Chain Integrity: TAMPERED  |  %d tampered  |  %d/%d verified",
				tampered, verified, total,
			))
			chainStatusLabel.Importance = widget.DangerImportance
		} else if unverifiable > 0 && verified == 0 {
			chainStatusLabel.SetText(fmt.Sprintf(
				"Chain Integrity: UNVERIFIED  |  %d entries (HMAC key not yet set)",
				unverifiable,
			))
			chainStatusLabel.Importance = widget.WarningImportance
		} else {
			chainStatusLabel.SetText(fmt.Sprintf(
				"Chain Integrity: OK  |  %d/%d entries verified",
				verified, total,
			))
			chainStatusLabel.Importance = widget.SuccessImportance
		}
		chainStatusLabel.Refresh()
	}

	// First check immediately, then every 5 seconds.
	runChainCheck()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				runChainCheck()
			case <-stopCh:
				return
			}
		}
	}()

	return container.NewBorder(
		container.NewVBox(
			container.NewHBox(
				container.NewPadded(chainStatusLabel),
			),
			widget.NewSeparator(),
			filterRow, dateRow, widget.NewSeparator(), colHeader, widget.NewSeparator(),
		),
		nil, nil, nil,
		list,
	)
}

// ─────────────────────────────────────────────────────────
// SESSIONS TAB
// ─────────────────────────────────────────────────────────

func (ui *LocalVaultUI) buildSessionsTab() fyne.CanvasObject {
	profile, _ := ui.vault.GetUserProfile()

	var sessionCard fyne.CanvasObject
	if profile != nil {
		mfaTxt := "No"
		if profile.MFAEnabled {
			mfaTxt = "Yes"
		}
		sessionCard = makeSectionCard("Current Session", "",
			container.NewVBox(
				container.NewGridWithColumns(2,
					makeHeading("User:"), widget.NewLabel(ui.currentUser),
					makeHeading("Role:"), roleLabel(ui.vault.GetRole()),
					makeHeading("MFA Enabled:"), widget.NewLabel(mfaTxt),
					makeHeading("Last Login:"), widget.NewLabel(profile.LastLogin.Format("2006-01-02 15:04:05")),
					makeHeading("Session Active Since:"), widget.NewLabel(ui.lastActivity.Format("2006-01-02 15:04:05")),
				),
				widget.NewSeparator(),
				makeDangerBtn("Force Re-login (Lock Vault)", theme.LogoutIcon(), func() {
					dialog.ShowConfirm("Lock Vault",
						"This will lock the vault and require re-authentication.",
						func(ok bool) {
							if ok {
								_ = ui.vault.Logout()
								ui.currentUser = ""
								ui.showLandingScreen()
							}
						}, ui.window)
				}),
			),
		)
	} else {
		sessionCard = makeSectionCard("Current Session", "", widget.NewLabel("Session info unavailable."))
	}

	// Recent login history from audit — use indexed lookups instead of full scan
	loginEntries := ui.vault.GetAuditEntriesByEvent(vault.AuditEventLogin)
	failedEntries := ui.vault.GetAuditEntriesByEvent(vault.AuditEventLoginFailed)
	loginHistory := make([]*vault.VaultAuditEntry, 0, 20)
	loginHistory = append(loginHistory, loginEntries...)
	loginHistory = append(loginHistory, failedEntries...)
	if len(loginHistory) > 20 {
		loginHistory = loginHistory[:20]
	}

	// Sortable login history
	histSortCol := -1
	histSortAsc := true
	histColNames := []string{"Time", "User", "Event", "Result"}
	histSortBtns := make([]*widget.Button, len(histColNames))
	for i, n := range histColNames {
		histSortBtns[i] = widget.NewButton(n, nil)
		histSortBtns[i].Importance = widget.LowImportance
	}
	updateHistSortLabels := func() {
		for i, n := range histColNames {
			if i == histSortCol {
				if histSortAsc {
					histSortBtns[i].SetText(n + " \u25b2")
				} else {
					histSortBtns[i].SetText(n + " \u25bc")
				}
			} else {
				histSortBtns[i].SetText(n)
			}
		}
	}

	histCW := newColWidths([]float32{180, 100, 180, 80})
	histHeaderCells := make([]fyne.CanvasObject, len(histSortBtns))
	for i, b := range histSortBtns {
		histHeaderCells[i] = b
	}
	histHeader, histHdrCount := buildResizableHeaderCustom(histHeaderCells, histCW)

	histBodyMax := container.NewMax()

	loadHistory := func() {
		sorted := make([]*vault.VaultAuditEntry, len(loginHistory))
		copy(sorted, loginHistory)
		if histSortCol >= 0 {
			sort.SliceStable(sorted, func(i, j int) bool {
				var less bool
				switch histSortCol {
				case 0:
					less = sorted[i].Timestamp.Before(sorted[j].Timestamp)
				case 1:
					less = strings.ToLower(sorted[i].Username) < strings.ToLower(sorted[j].Username)
				case 2:
					less = strings.ToLower(sorted[i].Event) < strings.ToLower(sorted[j].Event)
				case 3:
					less = strings.ToLower(sorted[i].Result) < strings.ToLower(sorted[j].Result)
				}
				if histSortAsc {
					return less
				}
				return !less
			})
		}
		histCW.clearRows(histHdrCount)
		histRows := make([]fyne.CanvasObject, 0, len(sorted))
		for _, e := range sorted {
			resultLbl := truncLabel(e.Result)
			if strings.ToLower(e.Result) == "failure" {
				resultLbl.Importance = widget.DangerImportance
			} else {
				resultLbl.Importance = widget.SuccessImportance
			}
			histRows = append(histRows, rowWithWidths([]fyne.CanvasObject{
				truncLabel(e.Timestamp.Local().Format("2006-01-02 15:04:05")),
				truncLabel(e.Username),
				truncLabel(e.Event),
				resultLbl,
			}, histCW))
		}
		var histBody fyne.CanvasObject
		if len(histRows) == 0 {
			histBody = container.NewCenter(widget.NewLabel("No login history yet."))
		} else {
			histBody = boundedScroll(container.NewVBox(histRows...))
		}
		histBodyMax.Objects = []fyne.CanvasObject{histBody}
		histBodyMax.Refresh()
	}

	for i := range histSortBtns {
		i := i
		histSortBtns[i].OnTapped = func() {
			if histSortCol == i {
				histSortAsc = !histSortAsc
			} else {
				histSortCol = i
				histSortAsc = true
			}
			updateHistSortLabels()
			loadHistory()
		}
	}
	loadHistory()

	histSection := container.NewBorder(
		container.NewVBox(
			makeHeading("Recent Login History (last 20)"),
			widget.NewSeparator(),
			histHeader,
			widget.NewSeparator(),
		),
		nil, nil, nil,
		histBodyMax,
	)

	split := container.NewVSplit(
		container.NewPadded(sessionCard),
		container.NewPadded(histSection),
	)
	split.Offset = 0.38
	return split
}

// ─────────────────────────────────────────────────────────
// EXPORTS TAB
// ─────────────────────────────────────────────────────────

func (ui *LocalVaultUI) buildExportsTab() fyne.CanvasObject {
	canExport := ui.vault.HasPermission(auth.CanExportData)
	canBackup := ui.vault.HasPermission(auth.CanBackupVault)
	canRestore := ui.vault.HasPermission(auth.CanRestoreVault)

	// ─ Audit stats summary ─
	stats := ui.vault.GetAuditStats()
	total, _ := stats["total_entries"].(int)
	failures, _ := stats["failed_events"].(int)
	integrityOK, _ := stats["integrity_ok"].(bool)
	integrityTxt := "OK"
	if !integrityOK {
		integrityTxt = "TAMPERED"
	}

	statCard := makeSectionCard("Audit Log Summary", "",
		container.NewGridWithColumns(3,
			kv("Total entries", fmt.Sprintf("%d", total)),
			kv("Failed events", fmt.Sprintf("%d", failures)),
			kv("Chain integrity", integrityTxt),
		),
	)

	// ─ Export buttons ─
	var exportSection fyne.CanvasObject
	if canExport {
		exportSection = makeSectionCard("Export Audit Log", "Download the full audit trail for SIEM integration or compliance review.",
			container.NewHBox(
				makeSecondaryBtn("Export JSON", theme.DocumentIcon(), func() {
					dialog.ShowFileSave(func(w fyne.URIWriteCloser, err error) {
						if err != nil || w == nil {
							return
						}
						w.Close()
						path := ensureExt(w.URI().Path(), ".json")
						data, exportErr := ui.vault.ExportAuditJSON()
						if exportErr != nil {
							dialog.ShowError(exportErr, ui.window)
							return
						}
						if writeErr := os.WriteFile(path, data, 0600); writeErr != nil {
							dialog.ShowError(writeErr, ui.window)
							return
						}
						dialog.ShowInformation("Exported", "Audit log exported as JSON.", ui.window)
					}, ui.window)
				}),
				makeSecondaryBtn("Export CSV", theme.DocumentIcon(), func() {
					dialog.ShowFileSave(func(w fyne.URIWriteCloser, err error) {
						if err != nil || w == nil {
							return
						}
						w.Close()
						path := ensureExt(w.URI().Path(), ".csv")
						csv := ui.vault.ExportAuditCSV()
						if writeErr := os.WriteFile(path, []byte(csv), 0600); writeErr != nil {
							dialog.ShowError(writeErr, ui.window)
							return
						}
						dialog.ShowInformation("Exported", "Audit log exported as CSV.", ui.window)
					}, ui.window)
				}),
				makeSecondaryBtn("Export CEF", theme.DocumentIcon(), func() {
					dialog.ShowFileSave(func(w fyne.URIWriteCloser, err error) {
						if err != nil || w == nil {
							return
						}
						w.Close()
						path := ensureExt(w.URI().Path(), ".cef")
						cef := ui.vault.ExportAuditCEF()
						if writeErr := os.WriteFile(path, []byte(cef), 0600); writeErr != nil {
							dialog.ShowError(writeErr, ui.window)
							return
						}
						dialog.ShowInformation("Exported", "Audit log exported in Common Event Format.", ui.window)
					}, ui.window)
				}),
				makeSecondaryBtn("Export TXT", theme.DocumentIcon(), func() {
					dialog.ShowFileSave(func(w fyne.URIWriteCloser, err error) {
						if err != nil || w == nil {
							return
						}
						w.Close()
						path := ensureExt(w.URI().Path(), ".txt")
						txt := ui.vault.ExportAuditTXT()
						if writeErr := os.WriteFile(path, []byte(txt), 0600); writeErr != nil {
							dialog.ShowError(writeErr, ui.window)
							return
						}
						dialog.ShowInformation("Exported", "Audit log exported as plain text.", ui.window)
					}, ui.window)
				}),
			),
		)
	} else {
		exportSection = makeSectionCard("Export Audit Log", "",
			widget.NewLabel("You do not have permission to export audit logs."),
		)
	}

	// ─ Vault backup ─
	backupActionItems := make([]fyne.CanvasObject, 0, 2)
	if canBackup {
		backupActionItems = append(backupActionItems,
			makePrimaryBtn("Create Backup", theme.ContentCopyIcon(), func() {
				admin := vault.NewVaultAdmin(ui.vault)
				info, err := admin.CreateBackup("Manual backup by " + ui.currentUser)
				if err != nil {
					dialog.ShowError(err, ui.window)
					return
				}
				dialog.ShowInformation("Backup Created",
					fmt.Sprintf("Saved to:\n%s\n\nSize: %d bytes", info.FilePath, info.Size),
					ui.window)
			}),
		)
	}
	if canRestore {
		backupActionItems = append(backupActionItems,
			makeDangerBtn("Restore from Backup", theme.HistoryIcon(), func() {
				admin := vault.NewVaultAdmin(ui.vault)
				backups, err := admin.ListBackups()
				if err != nil || len(backups) == 0 {
					dialog.ShowInformation("No Backups", "No backup files found.", ui.window)
					return
				}
				// Build selection list
				labels := make([]string, len(backups))
				for i, b := range backups {
					labels[i] = fmt.Sprintf("%s  (%s, %d bytes)",
						b.ID, b.CreatedAt.Format("2006-01-02 15:04"), b.Size)
				}
				sel := widget.NewSelect(labels, nil)
				content := container.NewVBox(
					widget.NewLabelWithStyle("⚠ This will overwrite the current vault!", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
					widget.NewLabel("Select a backup to restore:"),
					sel,
				)
				var d dialog.Dialog
				restoreBtn := makeDangerBtn("Restore", theme.WarningIcon(), func() {
					idx := sel.SelectedIndex()
					if idx < 0 {
						return
					}
					chosen := backups[idx]
					dialog.ShowConfirm("Confirm Restore",
						fmt.Sprintf("Restore vault from backup:\n%s\n\nThe current vault will be replaced. Continue?", chosen.ID),
						func(ok bool) {
							if !ok {
								return
							}
							target := ui.vault.Vault.GetFilePath()
							if rErr := admin.RestoreBackup(chosen.ID, target); rErr != nil {
								dialog.ShowError(rErr, ui.window)
								return
							}
							d.Hide()
							dialog.ShowInformation("Restored",
								"Vault restored successfully.\n\nYou will need to log in again.",
								ui.window)
							_ = ui.vault.Logout()
							ui.currentUser = ""
							ui.showLandingScreen()
						}, ui.window)
				})
				d = dialog.NewCustom("Restore Vault", "Cancel",
					container.NewVBox(content, restoreBtn), ui.window)
				d.Resize(fyne.NewSize(520, 0))
				d.Show()
			}),
		)
	}
	if len(backupActionItems) == 0 {
		backupActionItems = append(backupActionItems, widget.NewLabel("You do not have permission to create or restore backups."))
	}

	backupSection := makeSectionCard("Vault Backup & Restore",
		"Create and restore encrypted backups of the vault file (permission restricted).",
		container.NewHBox(backupActionItems...),
	)

	// ─ Compliance report ─
	makeComplianceSave := func(ext string, build func(*LocalVaultUI) []byte) func() {
		return func() {
			dialog.ShowFileSave(func(w fyne.URIWriteCloser, err error) {
				if err != nil || w == nil {
					return
				}
				w.Close()
				path := ensureExt(w.URI().Path(), ext)
				if writeErr := os.WriteFile(path, build(ui), 0600); writeErr != nil {
					dialog.ShowError(writeErr, ui.window)
					return
				}
				dialog.ShowInformation("Saved", "Compliance report saved.", ui.window)
			}, ui.window)
		}
	}
	reportSection := makeSectionCard("Compliance Report",
		"Export a compliance report of all security checks.",
		container.NewHBox(
			makeSecondaryBtn("Export JSON", theme.DocumentIcon(), makeComplianceSave(".json", buildComplianceReportJSON)),
			makeSecondaryBtn("Export CSV", theme.DocumentIcon(), makeComplianceSave(".csv", buildComplianceReportCSV)),
			makeSecondaryBtn("Export CEF", theme.DocumentIcon(), makeComplianceSave(".cef", buildComplianceReportCEF)),
			makeSecondaryBtn("Export TXT", theme.FileTextIcon(), makeComplianceSave(".txt", func(ui *LocalVaultUI) []byte {
				return []byte(buildPlainTextComplianceReport(ui))
			})),
		),
	)

	return container.NewPadded(container.NewVBox(
		statCard,
		makeDivider(),
		exportSection,
		makeDivider(),
		backupSection,
		makeDivider(),
		reportSection,
	))
}

// ─────────────────────────────────────────────────────────
// SECURITY POLICY TAB
// ─────────────────────────────────────────────────────────

func (ui *LocalVaultUI) buildSecurityPolicyTab() fyne.CanvasObject {
	policy, err := ui.vault.GetSecurityPolicy()
	if err != nil || policy == nil {
		// Use defaults if nothing stored yet
		policy = &vault.PersistentSecurityPolicy{
			MinPasswordLength:    12,
			RequireUppercase:     true,
			RequireLowercase:     true,
			RequireNumbers:       true,
			RequireSpecialChars:  true,
			PasswordExpiryDays:   90,
			PasswordHistoryCount: 5,
			MFARequired:          true,
			MFAGracePeriodDays:   0,
			MaxFailedAttempts:    5,
			LockoutDurationMins:  30,
			InactivityTimeoutMin: 15,
			SessionTimeoutMins:   0,
			AuditRetentionDays:   90,
		}
	}

	// Password policy
	minLenEntry := widget.NewEntry()
	minLenEntry.SetText(fmt.Sprintf("%d", policy.MinPasswordLength))
	expiryEntry := widget.NewEntry()
	expiryEntry.SetText(fmt.Sprintf("%d", policy.PasswordExpiryDays))
	historyEntry := widget.NewEntry()
	historyEntry.SetText(fmt.Sprintf("%d", policy.PasswordHistoryCount))

	reqUpper := widget.NewCheck("Require uppercase", nil)
	reqUpper.Checked = policy.RequireUppercase
	reqLower := widget.NewCheck("Require lowercase", nil)
	reqLower.Checked = policy.RequireLowercase
	reqNumbers := widget.NewCheck("Require numbers", nil)
	reqNumbers.Checked = policy.RequireNumbers
	reqSpecial := widget.NewCheck("Require special characters", nil)
	reqSpecial.Checked = policy.RequireSpecialChars

	// MFA policy
	mfaRequired := widget.NewCheck("MFA required for all users", nil)
	mfaRequired.Checked = policy.MFARequired
	graceDaysEntry := widget.NewEntry()
	graceDaysEntry.SetText(fmt.Sprintf("%d", policy.MFAGracePeriodDays))

	// Lockout & session policy
	maxAttemptsEntry := widget.NewEntry()
	maxAttemptsEntry.SetText(fmt.Sprintf("%d", policy.MaxFailedAttempts))
	lockoutDurEntry := widget.NewEntry()
	lockoutDurEntry.SetText(fmt.Sprintf("%d", policy.LockoutDurationMins))
	inactivityEntry := widget.NewEntry()
	inactivityEntry.SetText(fmt.Sprintf("%d", policy.InactivityTimeoutMin))
	sessionTimeoutEntry := widget.NewEntry()
	sessionTimeoutEntry.SetText(fmt.Sprintf("%d", policy.SessionTimeoutMins))
	concurrentSessionsEntry := widget.NewEntry()
	concurrentSessionsEntry.SetText(fmt.Sprintf("%d", policy.MaxConcurrentSessions))

	// Audit
	auditRetentionEntry := widget.NewEntry()
	auditRetentionEntry.SetText(fmt.Sprintf("%d", policy.AuditRetentionDays))

	saveBtn := makePrimaryBtn("Save Policy", theme.ConfirmIcon(), func() {
		updated := &vault.PersistentSecurityPolicy{
			MinPasswordLength:     parseInt(minLenEntry.Text, 12),
			RequireUppercase:      reqUpper.Checked,
			RequireLowercase:      reqLower.Checked,
			RequireNumbers:        reqNumbers.Checked,
			RequireSpecialChars:   reqSpecial.Checked,
			PasswordExpiryDays:    parseInt(expiryEntry.Text, 90),
			PasswordHistoryCount:  parseInt(historyEntry.Text, 5),
			MFARequired:           mfaRequired.Checked,
			MFAGracePeriodDays:    parseInt(graceDaysEntry.Text, 0),
			MaxFailedAttempts:     parseInt(maxAttemptsEntry.Text, 5),
			LockoutDurationMins:   parseInt(lockoutDurEntry.Text, 30),
			InactivityTimeoutMin:  parseInt(inactivityEntry.Text, 15),
			SessionTimeoutMins:    parseInt(sessionTimeoutEntry.Text, 0),
			MaxConcurrentSessions: parseInt(concurrentSessionsEntry.Text, 3),
			AuditRetentionDays:    parseInt(auditRetentionEntry.Text, 90),
		}
		if saveErr := ui.vault.UpdateSecurityPolicy(updated); saveErr != nil {
			dialog.ShowError(saveErr, ui.window)
			return
		}
		dialog.ShowInformation("Saved", "Security policy updated.", ui.window)
	})
	form := container.NewVBox(
		makeSectionTitle("Password Policy"),
		makeFormRow("Min password length:", minLenEntry),
		makeFormRow("Expiry (days, 0=never):", expiryEntry),
		makeFormRow("Password history count:", historyEntry),
		reqUpper, reqLower, reqNumbers, reqSpecial,

		makeSectionTitle("MFA Policy"),
		mfaRequired,
		makeFormRow("Grace period (days):", graceDaysEntry),

		makeSectionTitle("Lockout & Session"),
		makeFormRow("Max failed attempts:", maxAttemptsEntry),
		makeFormRow("Lockout duration (mins):", lockoutDurEntry),
		makeFormRow("Inactivity timeout (mins):", inactivityEntry),
		makeFormRow("Session timeout (mins, 0=unlimited):", sessionTimeoutEntry),
		makeFormRow("Max concurrent sessions (0=unlimited):", concurrentSessionsEntry),

		makeSectionTitle("Audit"),
		makeFormRow("Retention (days, 0=forever):", auditRetentionEntry),

		makeDivider(),
		saveBtn,
	)

	return container.NewPadded(form)
}

// ─────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────

func kv(label, value string) fyne.CanvasObject {
	return container.NewVBox(
		widget.NewLabelWithStyle(label, fyne.TextAlignLeading, fyne.TextStyle{Italic: true}),
		widget.NewLabelWithStyle(value, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
	)
}

func parseInt(s string, def int) int {
	var v int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &v); err != nil || v < 0 {
		return def
	}
	return v
}

func buildPlainTextComplianceReport(ui *LocalVaultUI) string {
	var sb strings.Builder
	sb.WriteString("=== PASSWORD MANAGER COMPLIANCE REPORT ===\n")
	sb.WriteString(fmt.Sprintf("Generated by: %s\n\n", ui.currentUser))

	policy, _ := ui.vault.GetSecurityPolicy()
	if policy != nil {
		sb.WriteString("[Password Policy]\n")
		sb.WriteString(fmt.Sprintf("  Min length:             %d\n", policy.MinPasswordLength))
		sb.WriteString(fmt.Sprintf("  Require uppercase:      %v\n", policy.RequireUppercase))
		sb.WriteString(fmt.Sprintf("  Require lowercase:      %v\n", policy.RequireLowercase))
		sb.WriteString(fmt.Sprintf("  Require numbers:        %v\n", policy.RequireNumbers))
		sb.WriteString(fmt.Sprintf("  Require special chars:  %v\n", policy.RequireSpecialChars))
		sb.WriteString(fmt.Sprintf("  Expiry (days):          %d\n", policy.PasswordExpiryDays))
		sb.WriteString(fmt.Sprintf("  History count:          %d\n\n", policy.PasswordHistoryCount))

		sb.WriteString("[MFA Policy]\n")
		sb.WriteString(fmt.Sprintf("  Required:               %v\n", policy.MFARequired))
		sb.WriteString(fmt.Sprintf("  Grace period (days):    %d\n\n", policy.MFAGracePeriodDays))

		sb.WriteString("[Lockout Policy]\n")
		sb.WriteString(fmt.Sprintf("  Max attempts:           %d\n", policy.MaxFailedAttempts))
		sb.WriteString(fmt.Sprintf("  Lockout duration (min): %d\n", policy.LockoutDurationMins))
		sb.WriteString(fmt.Sprintf("  Inactivity timeout:     %d min\n\n", policy.InactivityTimeoutMin))

		sb.WriteString("[Audit]\n")
		sb.WriteString(fmt.Sprintf("  Retention (days):       %d\n\n", policy.AuditRetentionDays))
	}

	stats := ui.vault.GetAuditStats()
	sb.WriteString("[Audit Log Stats]\n")
	sb.WriteString(fmt.Sprintf("  Total entries:   %v\n", stats["total_entries"]))
	sb.WriteString(fmt.Sprintf("  Failed events:   %v\n", stats["failed_events"]))
	integrityVal, _ := stats["integrity_ok"].(bool)
	sb.WriteString(fmt.Sprintf("  Chain integrity: %v\n\n", map[bool]string{true: "OK", false: "TAMPERED"}[integrityVal]))

	records, _ := ui.vault.ListUserRecords()
	sb.WriteString("[Users]\n")
	for _, r := range records {
		mfa := "No"
		if r.MFAEnabled {
			mfa = "Yes"
		}
		sb.WriteString(fmt.Sprintf("  %-20s Role: %-20s MFA: %s\n", r.Username, r.Role, mfa))
	}

	return sb.String()
}

func buildComplianceReportJSON(ui *LocalVaultUI) []byte {
	type policySection struct {
		MinPasswordLength    int  `json:"min_password_length,omitempty"`
		RequireUppercase     bool `json:"require_uppercase,omitempty"`
		RequireLowercase     bool `json:"require_lowercase,omitempty"`
		RequireNumbers       bool `json:"require_numbers,omitempty"`
		RequireSpecialChars  bool `json:"require_special_chars,omitempty"`
		PasswordExpiryDays   int  `json:"password_expiry_days,omitempty"`
		PasswordHistoryCount int  `json:"password_history_count,omitempty"`
		MFARequired          bool `json:"mfa_required,omitempty"`
		MFAGracePeriodDays   int  `json:"mfa_grace_period_days,omitempty"`
		MaxFailedAttempts    int  `json:"max_failed_attempts,omitempty"`
		LockoutDurationMins  int  `json:"lockout_duration_mins,omitempty"`
		InactivityTimeoutMin int  `json:"inactivity_timeout_min,omitempty"`
		AuditRetentionDays   int  `json:"audit_retention_days,omitempty"`
	}
	type userEntry struct {
		Username   string `json:"username"`
		Role       string `json:"role"`
		MFAEnabled bool   `json:"mfa_enabled"`
	}
	type report struct {
		GeneratedBy    string                 `json:"generated_by"`
		GeneratedAt    string                 `json:"generated_at"`
		Policy         *policySection         `json:"policy,omitempty"`
		AuditStats     map[string]interface{} `json:"audit_stats"`
		Users          []userEntry            `json:"users"`
	}

	r := report{
		GeneratedBy: ui.currentUser,
		GeneratedAt: time.Now().Format(time.RFC3339),
		AuditStats:  ui.vault.GetAuditStats(),
	}
	if p, _ := ui.vault.GetSecurityPolicy(); p != nil {
		r.Policy = &policySection{
			MinPasswordLength:    p.MinPasswordLength,
			RequireUppercase:     p.RequireUppercase,
			RequireLowercase:     p.RequireLowercase,
			RequireNumbers:       p.RequireNumbers,
			RequireSpecialChars:  p.RequireSpecialChars,
			PasswordExpiryDays:   p.PasswordExpiryDays,
			PasswordHistoryCount: p.PasswordHistoryCount,
			MFARequired:          p.MFARequired,
			MFAGracePeriodDays:   p.MFAGracePeriodDays,
			MaxFailedAttempts:    p.MaxFailedAttempts,
			LockoutDurationMins:  p.LockoutDurationMins,
			InactivityTimeoutMin: p.InactivityTimeoutMin,
			AuditRetentionDays:   p.AuditRetentionDays,
		}
	}
	if records, _ := ui.vault.ListUserRecords(); records != nil {
		for _, rec := range records {
			r.Users = append(r.Users, userEntry{Username: rec.Username, Role: rec.Role, MFAEnabled: rec.MFAEnabled})
		}
	}
	data, _ := json.MarshalIndent(r, "", "  ")
	return data
}

func buildComplianceReportCSV(ui *LocalVaultUI) []byte {
	var sb strings.Builder
	sb.WriteString("Section,Key,Value\n")
	write := func(section, key, value string) {
		sb.WriteString(fmt.Sprintf("%s,%s,%s\n", csvEscapeUI(section), csvEscapeUI(key), csvEscapeUI(value)))
	}
	write("Meta", "GeneratedBy", ui.currentUser)
	write("Meta", "GeneratedAt", time.Now().Format(time.RFC3339))
	if p, _ := ui.vault.GetSecurityPolicy(); p != nil {
		write("PasswordPolicy", "MinPasswordLength", fmt.Sprintf("%d", p.MinPasswordLength))
		write("PasswordPolicy", "RequireUppercase", fmt.Sprintf("%v", p.RequireUppercase))
		write("PasswordPolicy", "RequireLowercase", fmt.Sprintf("%v", p.RequireLowercase))
		write("PasswordPolicy", "RequireNumbers", fmt.Sprintf("%v", p.RequireNumbers))
		write("PasswordPolicy", "RequireSpecialChars", fmt.Sprintf("%v", p.RequireSpecialChars))
		write("PasswordPolicy", "PasswordExpiryDays", fmt.Sprintf("%d", p.PasswordExpiryDays))
		write("PasswordPolicy", "PasswordHistoryCount", fmt.Sprintf("%d", p.PasswordHistoryCount))
		write("MFAPolicy", "MFARequired", fmt.Sprintf("%v", p.MFARequired))
		write("MFAPolicy", "MFAGracePeriodDays", fmt.Sprintf("%d", p.MFAGracePeriodDays))
		write("LockoutPolicy", "MaxFailedAttempts", fmt.Sprintf("%d", p.MaxFailedAttempts))
		write("LockoutPolicy", "LockoutDurationMins", fmt.Sprintf("%d", p.LockoutDurationMins))
		write("LockoutPolicy", "InactivityTimeoutMin", fmt.Sprintf("%d", p.InactivityTimeoutMin))
		write("Audit", "AuditRetentionDays", fmt.Sprintf("%d", p.AuditRetentionDays))
	}
	stats := ui.vault.GetAuditStats()
	write("AuditStats", "TotalEntries", fmt.Sprintf("%v", stats["total_entries"]))
	write("AuditStats", "FailedEvents", fmt.Sprintf("%v", stats["failed_events"]))
	integrityOK, _ := stats["integrity_ok"].(bool)
	write("AuditStats", "ChainIntegrity", map[bool]string{true: "OK", false: "TAMPERED"}[integrityOK])
	if records, _ := ui.vault.ListUserRecords(); records != nil {
		for _, rec := range records {
			write("Users", rec.Username, fmt.Sprintf("role=%s mfa=%v", rec.Role, rec.MFAEnabled))
		}
	}
	return []byte(sb.String())
}

func csvEscapeUI(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func buildComplianceReportCEF(ui *LocalVaultUI) []byte {
	var sb strings.Builder
	ts := time.Now().Format(time.RFC3339)
	line := func(name, msg, extras string) {
		sb.WriteString(fmt.Sprintf("CEF:0|PasswordManager|ComplianceReport|1.0|compliance|%s|3|rt=%s externalId=%s %s\n",
			name, ts, ui.currentUser, extras))
		_ = msg
	}
	if p, _ := ui.vault.GetSecurityPolicy(); p != nil {
		line("PasswordPolicy", "Password policy settings",
			fmt.Sprintf("minLen=%d requireUpper=%v requireLower=%v requireNum=%v requireSpecial=%v expiryDays=%d historyCount=%d",
				p.MinPasswordLength, p.RequireUppercase, p.RequireLowercase, p.RequireNumbers, p.RequireSpecialChars, p.PasswordExpiryDays, p.PasswordHistoryCount))
		line("MFAPolicy", "MFA policy settings",
			fmt.Sprintf("mfaRequired=%v gracePeriodDays=%d", p.MFARequired, p.MFAGracePeriodDays))
		line("LockoutPolicy", "Lockout policy settings",
			fmt.Sprintf("maxAttempts=%d lockoutMins=%d inactivityMin=%d", p.MaxFailedAttempts, p.LockoutDurationMins, p.InactivityTimeoutMin))
		line("AuditRetention", "Audit retention settings",
			fmt.Sprintf("retentionDays=%d", p.AuditRetentionDays))
	}
	stats := ui.vault.GetAuditStats()
	integrityOK, _ := stats["integrity_ok"].(bool)
	line("AuditStats", "Audit log statistics",
		fmt.Sprintf("totalEntries=%v failedEvents=%v chainIntegrity=%s",
			stats["total_entries"], stats["failed_events"], map[bool]string{true: "OK", false: "TAMPERED"}[integrityOK]))
	if records, _ := ui.vault.ListUserRecords(); records != nil {
		for _, rec := range records {
			line("UserRecord", "User compliance record",
				fmt.Sprintf("user=%s role=%s mfaEnabled=%v", rec.Username, rec.Role, rec.MFAEnabled))
		}
	}
	return []byte(sb.String())
}


func roleLabel(role string) *widget.Label {
	lbl := widget.NewLabel(role)
	lbl.Truncation = fyne.TextTruncateEllipsis
	switch role {
	case models.RoleAdministrator:
		lbl.Importance = widget.DangerImportance
	case models.RoleSecurityOfficer:
		lbl.Importance = widget.WarningImportance
	case models.RoleStandardUser:
		lbl.Importance = widget.MediumImportance
	default:
		lbl.Importance = widget.LowImportance
	}
	return lbl
}

func statusLabel(status string) *widget.Label {
	lbl := widget.NewLabel(status)
	lbl.Truncation = fyne.TextTruncateEllipsis
	if status == "Revoked" {
		lbl.Importance = widget.DangerImportance
	} else {
		lbl.Importance = widget.SuccessImportance
	}
	return lbl
}

// ─────────────────────────────────────────────────────────
// ROLE PERMISSIONS TAB
// ─────────────────────────────────────────────────────────

// buildRolePermissionsTab shows a grid of checkboxes — one row per role, one
// column per permission — so an administrator can customise what each role can do.
func (ui *LocalVaultUI) buildRolePermissionsTab() fyne.CanvasObject {
	allRoles := []string{
		models.RoleAdministrator,
		models.RoleSecurityOfficer,
		models.RoleStandardUser,
		models.RoleReadOnly,
	}

	// Load current stored config (falls back to compiled defaults if nothing saved)
	stored, err := ui.vault.GetRolePermissionsConfig()
	if err != nil {
		return widget.NewLabel(fmt.Sprintf("Error loading role permissions: %v", err))
	}

	// permChecks[role][permKey] = *widget.Check
	permChecks := make(map[string]map[string]*widget.Check, len(allRoles))
	for _, role := range allRoles {
		permChecks[role] = make(map[string]*widget.Check, len(auth.AllPermissions))
		isAdmin := role == models.RoleAdministrator
		current := stored[role]
		currentSet := make(map[string]bool, len(current))
		for _, p := range current {
			currentSet[p] = true
		}
		for _, perm := range auth.AllPermissions {
			c := widget.NewCheck("", nil)
			if isAdmin {
				// Administrators always hold every permission — show as checked but
				// non-interactive so the state cannot be accidentally modified.
				c.Checked = true
				c.Disable()
			} else {
				c.Checked = currentSet[perm]
			}
			permChecks[role][perm] = c
		}
	}

	statusLbl := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{})

	saveBtn := makePrimaryBtn("Save Role Permissions", theme.ConfirmIcon(), func() {
		updated := make(map[string][]string, len(allRoles))
		for _, role := range allRoles {
			if role == models.RoleAdministrator {
				// Administrator permissions are immutable — always grant everything.
				updated[role] = auth.AllPermissions
				continue
			}
			var perms []string
			for _, perm := range auth.AllPermissions {
				if permChecks[role][perm].Checked {
					perms = append(perms, perm)
				}
			}
			updated[role] = perms
		}
		if saveErr := ui.vault.UpdateRolePermissionsConfig(updated); saveErr != nil {
			dialog.ShowError(saveErr, ui.window)
			return
		}
		ui.showAdminDashboard()
	})
	resetBtn := makeSecondaryBtn("Reset to Defaults", theme.ViewRefreshIcon(), func() {
		dialog.ShowConfirm("Reset Permissions",
			"Reset all role permissions to the application defaults?",
			func(ok bool) {
				if !ok {
					return
				}
				defaults := auth.DefaultRolePermissions()
				for _, role := range allRoles {
					if role == models.RoleAdministrator {
						continue // already locked checked — nothing to reset
					}
					defaultSet := make(map[string]bool)
					for _, p := range defaults[role] {
						defaultSet[p] = true
					}
					for _, perm := range auth.AllPermissions {
						permChecks[role][perm].Checked = defaultSet[perm]
						permChecks[role][perm].Refresh()
					}
				}
				statusLbl.Importance = widget.MediumImportance
				statusLbl.SetText("Defaults restored — click Save to apply.")
			}, ui.window)
	})

	// ── Build the grid ──────────────────────────────────────
	// Header row: blank + one column per role
	numCols := 1 + len(allRoles)

	var allRows []fyne.CanvasObject

	// Column headers (role names)
	headerRow := make([]fyne.CanvasObject, 0, numCols)
	headerRow = append(headerRow, widget.NewLabel("")) // empty top-left corner
	for _, role := range allRoles {
		headerRow = append(headerRow, roleLabel(role))
	}
	allRows = append(allRows, container.NewGridWithColumns(numCols, headerRow...))
	allRows = append(allRows, widget.NewSeparator())

	// Permission rows grouped by category
	for _, group := range auth.PermissionGroups {
		allRows = append(allRows,
			widget.NewLabelWithStyle(group.Label, fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Italic: true}),
		)
		for _, perm := range group.Permissions {
			row := make([]fyne.CanvasObject, 0, numCols)
			label := auth.PermissionLabels[perm]
			if label == "" {
				label = perm
			}
			row = append(row, widget.NewLabel(label))
			for _, role := range allRoles {
				row = append(row, permChecks[role][perm])
			}
			allRows = append(allRows, container.NewGridWithColumns(numCols, row...))
		}
		allRows = append(allRows, widget.NewSeparator())
	}

	allRows = append(allRows, statusLbl,
		container.NewHBox(saveBtn, resetBtn),
	)

	note := makeSubheading("Changes take effect immediately for all active sessions after saving.")

	return container.NewBorder(
		container.NewVBox(
			makeHeading("RBAC Role Permissions"),
			note,
			makeDivider(),
		),
		nil, nil, nil,
		boundedScroll(container.NewPadded(container.NewVBox(allRows...))),
	)
}
