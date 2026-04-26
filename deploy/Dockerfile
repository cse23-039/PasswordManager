# ─────────────────────────────────────────────────────────────────────────────
# Multi-stage Dockerfile for Password Manager
# Requirement 4: Containerisation support
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

# Install build dependencies for Fyne (CGO required)
RUN apk add --no-cache \
    gcc \
    musl-dev \
    mesa-dev \
    libx11-dev \
    libxrandr-dev \
    libxinerama-dev \
    libxcursor-dev \
    libxi-dev \
    libxxf86vm-dev \
    pkgconf

WORKDIR /src

# Cache dependencies separately
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /bin/password-manager \
    ./cmd/password-manager

# Build the security-check tool
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /bin/security-check \
    ./tools/security-check

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM alpine:3.20

# Security hardening: run as non-root
RUN addgroup -S pmgr && adduser -S pmgr -G pmgr

# Runtime X11/graphics libs for Fyne desktop mode
RUN apk add --no-cache \
    ca-certificates \
    mesa-gl \
    libx11 \
    libxrandr \
    libxinerama \
    libxcursor \
    libxi

# Copy binaries from builder
COPY --from=builder /bin/password-manager /usr/local/bin/password-manager
COPY --from=builder /bin/security-check   /usr/local/bin/security-check

# Vault storage directory
RUN mkdir -p /data && chown pmgr:pmgr /data

USER pmgr

# Environment defaults
ENV VAULT_PATH=/data/vault.pwm
ENV PM_LOG_LEVEL=info

VOLUME ["/data"]

# Fyne apps need a DISPLAY; expose the binary as the entrypoint
ENTRYPOINT ["/usr/local/bin/password-manager"]
