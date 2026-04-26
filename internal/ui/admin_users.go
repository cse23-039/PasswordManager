package ui

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// AdminUsersUI provides admin user management UI components
// Requirement 3.5: Administrative Functions
type AdminUsersUI struct {
	window fyne.Window
}

// NewAdminUsersUI creates a new admin users UI
func NewAdminUsersUI(window fyne.Window) *AdminUsersUI {
	return &AdminUsersUI{window: window}
}

// UserInfo represents user display information
type UserInfo struct {
	Username  string
	Role      string
	MFA       bool
	Locked    bool
	LastLogin string
}

// GetUserManagementView creates the user management view
func (aui *AdminUsersUI) GetUserManagementView(users []UserInfo, onRoleChange func(string, string), onLock func(string), onUnlock func(string), onDelete func(string)) *fyne.Container {
	title := widget.NewLabelWithStyle("User Management", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	if len(users) == 0 {
		return container.NewVBox(title, widget.NewLabel("No users found"))
	}

	// Create user list
	list := widget.NewList(
		func() int { return len(users) },
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewIcon(theme.AccountIcon()),
				widget.NewLabel("Username"),
				widget.NewLabel("Role"),
				widget.NewLabel("Status"),
				widget.NewToolbar(
					widget.NewToolbarAction(theme.ContentUndoIcon(), func() {}),
					widget.NewToolbarAction(theme.DeleteIcon(), func() {}),
				),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id >= len(users) {
				return
			}
			user := users[id]
			items := obj.(*fyne.Container).Objects
			items[1].(*widget.Label).SetText(user.Username)
			items[2].(*widget.Label).SetText(user.Role)

			status := "Active"
			if user.Locked {
				status = "Locked"
			}
			if user.MFA {
				status += " [MFA]"
			}
			items[3].(*widget.Label).SetText(status)
		},
	)

	return container.NewVBox(
		title,
		widget.NewSeparator(),
		widget.NewLabelWithStyle(fmt.Sprintf("Total Users: %d", len(users)), fyne.TextAlignLeading, fyne.TextStyle{}),
		list,
	)
}
