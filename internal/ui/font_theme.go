package ui

import (
	"image/color"
	"os"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// unicodeTheme wraps the default Fyne theme and overrides Font() to use
// Segoe UI (available on all Windows systems). Segoe UI covers the Unicode
// symbols used in this app (→ ← ✓ ✗ ⚠ etc.) that Fyne's built-in
// Roboto font does not include.
type unicodeTheme struct {
	base fyne.Theme
	reg  fyne.Resource
	bold fyne.Resource
	ital fyne.Resource
}

var (
	// isDarkMode tracks the current theme variant. Defaults to dark.
	// Protected by isDarkMu because the inactivity goroutine can read it
	// concurrently with the UI thread writing it on a theme-toggle tap.
	isDarkMode bool = true
	isDarkMu   sync.RWMutex

	// Cached font resources – loaded once, reused on every theme switch.
	cachedFontReg  fyne.Resource
	cachedFontBold fyne.Resource
	cachedFontItal fyne.Resource
	fontsOnce      sync.Once
)

func loadCachedFonts() {
	fontsOnce.Do(func() {
		cachedFontReg = loadFontFile(`C:\Windows\Fonts\segoeui.ttf`)
		cachedFontBold = loadFontFile(`C:\Windows\Fonts\segoeuib.ttf`)
		cachedFontItal = loadFontFile(`C:\Windows\Fonts\segoeuii.ttf`)
	})
}

// NewUnicodeTheme returns a Fyne theme that uses Segoe UI for broad Unicode
// coverage and respects the current dark/light mode setting.
// Falls back to the default Fyne theme fonts if Segoe UI is not found
// (i.e., on non-Windows systems).
func NewUnicodeTheme() fyne.Theme {
	loadCachedFonts()
	return &unicodeTheme{
		base: theme.DefaultTheme(),
		reg:  cachedFontReg,
		bold: cachedFontBold,
		ital: cachedFontItal,
	}
}

// IsDarkMode returns whether dark mode is currently active (thread-safe).
func IsDarkMode() bool {
	isDarkMu.RLock()
	defer isDarkMu.RUnlock()
	return isDarkMode
}

// SetDarkMode switches between dark and light mode and immediately refreshes
// every widget in the running application (thread-safe).
func SetDarkMode(app fyne.App, dark bool) {
	isDarkMu.Lock()
	isDarkMode = dark
	isDarkMu.Unlock()
	app.Settings().SetTheme(NewUnicodeTheme())
}

func loadFontFile(path string) fyne.Resource {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return fyne.NewStaticResource(path, data)
}

// Font returns the appropriate Segoe UI variant, falling back to Fyne default
// if the font files were not found.
func (t *unicodeTheme) Font(style fyne.TextStyle) fyne.Resource {
	if style.Bold && t.bold != nil {
		return t.bold
	}
	if (style.Italic || style.Monospace) && t.ital != nil {
		return t.ital
	}
	if t.reg != nil {
		return t.reg
	}
	return t.base.Font(style)
}

// Color returns custom palette colors for a modern dark/light theme.
func (t *unicodeTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	if IsDarkMode() {
		switch name {
		case theme.ColorNameBackground:
			return color.RGBA{R: 13, G: 17, B: 23, A: 255} // #0d1117
		case theme.ColorNameButton:
			return color.RGBA{R: 33, G: 38, B: 45, A: 255} // #21262d
		case theme.ColorNameDisabledButton:
			return color.RGBA{R: 33, G: 38, B: 45, A: 120}
		case theme.ColorNameInputBackground:
			return color.RGBA{R: 22, G: 27, B: 34, A: 255} // #161b22
		case theme.ColorNameForeground:
			return color.RGBA{R: 230, G: 237, B: 243, A: 255} // #e6edf3
		case theme.ColorNameDisabled:
			return color.RGBA{R: 125, G: 133, B: 144, A: 255} // #7d8590
		case theme.ColorNamePlaceHolder:
			return color.RGBA{R: 125, G: 133, B: 144, A: 255} // #7d8590
		case theme.ColorNamePrimary:
			return color.RGBA{R: 47, G: 129, B: 247, A: 255} // #2f81f7
		case theme.ColorNameFocus:
			return color.RGBA{R: 47, G: 129, B: 247, A: 180}
		case theme.ColorNameHover:
			return color.RGBA{R: 48, G: 54, B: 61, A: 255} // #30363d
		case theme.ColorNamePressed:
			return color.RGBA{R: 48, G: 54, B: 61, A: 200}
		case theme.ColorNameSeparator:
			return color.RGBA{R: 48, G: 54, B: 61, A: 255} // #30363d
		case theme.ColorNameError:
			return color.RGBA{R: 248, G: 81, B: 73, A: 255} // #f85149
		case theme.ColorNameWarning:
			return color.RGBA{R: 210, G: 153, B: 34, A: 255}
		case theme.ColorNameSuccess:
			return color.RGBA{R: 63, G: 185, B: 80, A: 255}
		case theme.ColorNameMenuBackground:
			return color.RGBA{R: 22, G: 27, B: 34, A: 255} // #161b22
		case theme.ColorNameOverlayBackground:
			return color.RGBA{R: 22, G: 27, B: 34, A: 255} // #161b22
		case theme.ColorNameShadow:
			return color.RGBA{R: 0, G: 0, B: 0, A: 102} // #00000066
		case theme.ColorNameScrollBar:
			return color.RGBA{R: 48, G: 54, B: 61, A: 200}
		case theme.ColorNameInputBorder:
			return color.RGBA{R: 48, G: 54, B: 61, A: 255}
		}
		return t.base.Color(name, theme.VariantDark)
	}
	// Light mode
	switch name {
	case theme.ColorNameBackground:
		return color.RGBA{R: 246, G: 248, B: 250, A: 255} // #f6f8fa
	case theme.ColorNameButton:
		return color.RGBA{R: 243, G: 246, B: 252, A: 255} // #f3f6fc
	case theme.ColorNameDisabledButton:
		return color.RGBA{R: 228, G: 233, B: 240, A: 255}
	case theme.ColorNameInputBackground:
		return color.RGBA{R: 255, G: 255, B: 255, A: 255} // #ffffff
	case theme.ColorNameForeground:
		return color.RGBA{R: 31, G: 35, B: 40, A: 255} // #1f2328
	case theme.ColorNameDisabled:
		return color.RGBA{R: 99, G: 108, B: 118, A: 255} // #636c76
	case theme.ColorNamePlaceHolder:
		return color.RGBA{R: 99, G: 108, B: 118, A: 255} // #636c76
	case theme.ColorNamePrimary:
		return color.RGBA{R: 9, G: 105, B: 218, A: 255} // #0969da
	case theme.ColorNameFocus:
		return color.RGBA{R: 9, G: 105, B: 218, A: 180}
	case theme.ColorNameHover:
		return color.RGBA{R: 232, G: 236, B: 241, A: 255} // #e8ecf1
	case theme.ColorNamePressed:
		return color.RGBA{R: 234, G: 238, B: 242, A: 255}
	case theme.ColorNameSeparator:
		return color.RGBA{R: 208, G: 215, B: 222, A: 255} // #d0d7de
	case theme.ColorNameError:
		return color.RGBA{R: 207, G: 34, B: 46, A: 255} // #cf222e
	case theme.ColorNameWarning:
		return color.RGBA{R: 154, G: 103, B: 0, A: 255}
	case theme.ColorNameSuccess:
		return color.RGBA{R: 26, G: 127, B: 55, A: 255}
	case theme.ColorNameMenuBackground:
		return color.RGBA{R: 255, G: 255, B: 255, A: 255}
	case theme.ColorNameOverlayBackground:
		return color.RGBA{R: 255, G: 255, B: 255, A: 255}
	case theme.ColorNameShadow:
		return color.RGBA{R: 0, G: 0, B: 0, A: 30}
	case theme.ColorNameScrollBar:
		return color.RGBA{R: 208, G: 215, B: 222, A: 200}
	case theme.ColorNameInputBorder:
		return color.RGBA{R: 208, G: 215, B: 222, A: 255}
	}
	return t.base.Color(name, theme.VariantLight)
}

func (t *unicodeTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return t.base.Icon(name)
}

// Size returns increased text and padding sizes for a more comfortable layout.
func (t *unicodeTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 14
	case theme.SizeNamePadding:
		return 8
	case theme.SizeNameInnerPadding:
		return 10
	case theme.SizeNameScrollBar:
		return 5
	case theme.SizeNameSeparatorThickness:
		return 1
	}
	return t.base.Size(name)
}

// accentColor returns the primary blue accent for the current mode.
func accentColor() color.Color {
	if IsDarkMode() {
		return color.RGBA{R: 47, G: 129, B: 247, A: 255} // #2f81f7
	}
	return color.RGBA{R: 9, G: 105, B: 218, A: 255} // #0969da
}

// sidebarBgColor returns the sidebar background color for the current mode.
func sidebarBgColor() color.Color {
	if IsDarkMode() {
		return color.RGBA{R: 22, G: 27, B: 34, A: 255} // #161b22
	}
	return color.RGBA{R: 240, G: 243, B: 246, A: 255} // #f0f3f6 — light mode sidebar
}

// cardBgColor returns a slightly elevated background for cards vs the window background.
func cardBgColor() color.Color {
	if IsDarkMode() {
		return color.RGBA{R: 22, G: 27, B: 34, A: 255} // #161b22
	}
	return color.RGBA{R: 255, G: 255, B: 255, A: 255} // #ffffff
}

// subtleBorderColor returns a low-contrast border/divider color.
func subtleBorderColor() color.Color {
	if IsDarkMode() {
		return color.RGBA{R: 48, G: 54, B: 61, A: 255} // #30363d
	}
	return color.RGBA{R: 208, G: 215, B: 222, A: 255} // #d0d7de
}

// hoverBgColor returns a semi-transparent overlay for list row hover states.
func hoverBgColor() color.Color {
	if IsDarkMode() {
		return color.RGBA{R: 48, G: 54, B: 61, A: 120} // #30363d ~47%
	}
	return color.RGBA{R: 232, G: 236, B: 241, A: 120} // #e8ecf1 ~47%
}

// successColor returns the success/green color.
func successColor() color.Color {
	if IsDarkMode() {
		return color.RGBA{R: 63, G: 185, B: 80, A: 255}
	}
	return color.RGBA{R: 26, G: 127, B: 55, A: 255}
}

// warningColor returns the warning/orange color.
func warningColor() color.Color {
	if IsDarkMode() {
		return color.RGBA{R: 210, G: 153, B: 34, A: 255}
	}
	return color.RGBA{R: 154, G: 103, B: 0, A: 255}
}

// dangerColor returns the error/red color.
func dangerColor() color.Color {
	if IsDarkMode() {
		return color.RGBA{R: 248, G: 81, B: 73, A: 255}
	}
	return color.RGBA{R: 207, G: 34, B: 46, A: 255}
}
