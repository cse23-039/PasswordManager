package ui

import (
	"fyne.io/fyne/v2"
)

// AppVersion is set by main before InitializeLocalUI so the UI can display it.
var AppVersion = "1.0"

// AppIcon is set by main before InitializeLocalUI so the sidebar can show the app logo.
var AppIcon fyne.Resource

// UIConfig holds UI configuration settings
type UIConfig struct {
	Theme            string  `json:"theme"` // "dark" or "light"
	FontSize         float32 `json:"font_size"`
	WindowWidth      float32 `json:"window_width"`
	WindowHeight     float32 `json:"window_height"`
	ClipboardTimeout int     `json:"clipboard_timeout"` // seconds
	ShowPasswords    bool    `json:"show_passwords"`
	AutoLockMinutes  int     `json:"auto_lock_minutes"`
}

// DefaultUIConfig returns the default UI configuration
func DefaultUIConfig() *UIConfig {
	return &UIConfig{
		Theme:            "dark",
		FontSize:         14,
		WindowWidth:      800,
		WindowHeight:     600,
		ClipboardTimeout: 30,
		ShowPasswords:    false,
		AutoLockMinutes:  15,
	}
}

// ApplyConfig applies UI configuration to the window
func ApplyConfig(window fyne.Window, config *UIConfig) {
	if config == nil {
		config = DefaultUIConfig()
	}

	window.Resize(fyne.NewSize(config.WindowWidth, config.WindowHeight))
	window.CenterOnScreen()
}

// GetCurrentConfig returns the current UI configuration
func GetCurrentConfig() *UIConfig {
	return DefaultUIConfig()
}
