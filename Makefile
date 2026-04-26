.PHONY: build run clean test test-core fmt help \
	installer-windows installer-macos installer-linux installers dist-clean

GO ?= go
VERSION ?= 1.0.0

ifeq ($(OS),Windows_NT)
	PLATFORM := windows
	BIN_NAME := password-manager.exe
	RM_FILE := if exist "bin\$(BIN_NAME)" del /f /q "bin\$(BIN_NAME)"
	RUN_CMD := .\bin\$(BIN_NAME)
	# -H windowsgui suppresses the console window that would otherwise appear
	# alongside the Fyne GUI on Windows.
	LDFLAGS := -ldflags="-s -w -H windowsgui -X main.Version=$(VERSION)"
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Darwin)
		PLATFORM := macos
	else
		PLATFORM := linux
	endif
	BIN_NAME := password-manager
	RM_FILE := rm -f bin/$(BIN_NAME)
	RUN_CMD := ./bin/$(BIN_NAME)
	LDFLAGS := -ldflags="-s -w -X main.Version=$(VERSION)"
endif

help:
	@echo ""
	@echo "  Password Manager — Build Commands"
	@echo "  =================================="
	@echo "  make build              Build the binary"
	@echo "  make run                Build + launch"
	@echo "  make test               Run all tests"
	@echo "  make test-core          Run core vault/auth tests"
	@echo "  make fmt                Format source"
	@echo "  make clean              Remove build artifacts"
	@echo ""
	@echo "  Installers (GUI setup programs):"
	@echo "  make installers         Build installer for current OS"
	@echo "  make installer-windows  Compile Inno Setup .exe  (Windows + iscc)"
	@echo "  make installer-macos    Build .dmg + .pkg        (macOS only)"
	@echo "  make installer-linux    Build .deb + AppImage    (Linux only)"
	@echo "  make dist-clean         Remove dist/ directory"
	@echo ""

build:
	@echo "Building password-manager..."
	@mkdir -p bin
	CGO_ENABLED=1 $(GO) build $(LDFLAGS) -o bin/$(BIN_NAME) ./cmd/password-manager
	@echo "Built: bin/$(BIN_NAME)"

run: build
	@echo "Launching application..."
	$(RUN_CMD)

clean:
	@echo "Cleaning..."
	@$(RM_FILE)
	$(GO) clean
	@echo "Cleaned"

dist-clean:
	rm -rf dist/
	@echo "dist/ removed"

test:
	$(GO) test ./internal/... -v

test-core:
	$(GO) test ./internal/vault ./internal/auth -v

fmt:
	$(GO) fmt ./...

# Installer targets

installer-windows: build
ifeq ($(OS),Windows_NT)
	@echo "[*] Compiling Inno Setup installer..."
	@where iscc >nul 2>&1 || (echo "[ERROR] iscc not found. Install Inno Setup 6 from https://jrsoftware.org/isdl.php" && exit 1)
	iscc installer\windows\setup.iss
	@echo "[OK] Installer: installer\windows\Output\PasswordManager-Setup-$(VERSION).exe"
else
	@echo "[SKIP] installer-windows must be built on Windows (requires iscc)"
endif

installer-macos: build
ifeq ($(PLATFORM),macos)
	@echo "[*] Building macOS installers (.app + .dmg + .pkg)..."
	chmod +x installer/macos/build_installer.sh
	./installer/macos/build_installer.sh --version $(VERSION)
else
	@echo "[SKIP] installer-macos must be built on macOS"
endif

installer-linux: build
ifeq ($(PLATFORM),linux)
	@echo "[*] Building Linux installers (.deb + AppImage)..."
	chmod +x installer/linux/build_installer.sh
	./installer/linux/build_installer.sh --version $(VERSION)
else
	@echo "[SKIP] installer-linux must be built on Linux"
endif

# Build the correct installer for whatever OS you are currently on
installers: installer-$(PLATFORM)
