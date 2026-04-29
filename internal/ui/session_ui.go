package ui

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// SessionUI provides session management UI components
// Requirement 3.6: Session Management
type SessionUI struct {
	window fyne.Window
}

// NewSessionUI creates a new session UI
func NewSessionUI(window fyne.Window) *SessionUI {
	return &SessionUI{window: window}
}

// SessionDisplayInfo contains session info for display
type SessionDisplayInfo struct {
	ID           string
	Username     string
	CreatedAt    time.Time
	LastActivity time.Time
	ExpiresAt    time.Time
	IsActive     bool
}

// GetSessionView creates the session management view
func (sui *SessionUI) GetSessionView(sessions []SessionDisplayInfo, onInvalidate func(string), onInvalidateAll func()) *fyne.Container {
	title := makeCenteredHeading("Active Sessions")

	if len(sessions) == 0 {
		return container.NewVBox(
			title,
			widget.NewLabel("No active sessions"),
		)
	}

	list := widget.NewList(
		func() int { return len(sessions) },
		func() fyne.CanvasObject {
			return container.NewVBox(
				container.NewHBox(
					widget.NewIcon(theme.ComputerIcon()),
					widget.NewLabel("Session ID"),
					widget.NewLabel("User"),
				),
				container.NewHBox(
					widget.NewLabel("Last Activity"),
					widget.NewLabel("Expires"),
				),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id >= len(sessions) {
				return
			}
			session := sessions[id]
			rows := obj.(*fyne.Container).Objects

			row1 := rows[0].(*fyne.Container).Objects
			idDisplay := session.ID
			if len(idDisplay) > 16 {
				idDisplay = idDisplay[:16] + "..."
			}
			row1[1].(*widget.Label).SetText(idDisplay)
			row1[2].(*widget.Label).SetText(session.Username)

			row2 := rows[1].(*fyne.Container).Objects
			row2[0].(*widget.Label).SetText(fmt.Sprintf("Active: %s", session.LastActivity.Format("15:04:05")))
			row2[1].(*widget.Label).SetText(fmt.Sprintf("Expires: %s", session.ExpiresAt.Format("15:04:05")))
		},
	)

	return container.NewVBox(
		title,
		makeDivider(),
		widget.NewLabel(fmt.Sprintf("Active Sessions: %d", len(sessions))),
		list,
		makeDivider(),
		makeDangerBtn("Invalidate All Sessions", theme.DeleteIcon(), func() {
			if onInvalidateAll != nil {
				onInvalidateAll()
			}
		}),
	)
}
