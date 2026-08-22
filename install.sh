#!/usr/bin/env bash
set -e

REPO="HazaVVIP/GitRecon"
BIN_NAME="gitrecon"
INSTALL_DIR="/usr/local/bin"

# ════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ════════════════════════════════════════════════

info()    { echo "[*] $1"; }
success() { echo "[✓] $1"; }
error()   { echo "[!] $1"; }
warn()    { echo "[~] $1"; }

# Check if a command exists
command_exists() {
    command -v "$1" &>/dev/null
}

# Detect package manager
detect_package_manager() {
    if command_exists apt-get; then
        echo "apt"
    elif command_exists yum; then
        echo "yum"
    elif command_exists dnf; then
        echo "dnf"
    elif command_exists pacman; then
        echo "pacman"
    elif command_exists brew; then
        echo "brew"
    elif command_exists apk; then
        echo "apk"
    else
        echo "unknown"
    fi
}

# Install system dependencies for building
install_build_dependencies() {
    local pkg_manager="$1"

    case "$pkg_manager" in
        apt)
            info "Installing build dependencies via apt..."
            sudo apt-get update -qq
            sudo apt-get install -y build-essential gcc make pkg-config libssl-dev libsqlite3-dev curl git
            ;;
        yum|dnf)
            info "Installing build dependencies via $pkg_manager..."
            sudo $pkg_manager install -y gcc make pkg-config openssl-devel sqlite-devel curl git
            ;;
        pacman)
            info "Installing build dependencies via pacman..."
            sudo pacman -S --noconfirm base-devel pkg-config openssl sqlite curl git
            ;;
        brew)
            info "Installing build dependencies via brew..."
            brew install pkg-config openssl sqlite3 curl git
            ;;
        apk)
            info "Installing build dependencies via apk..."
            apk add --no-cache build-base gcc openssl-dev sqlite-dev curl git
            ;;
        *)
            warn "Unknown package manager. Skipping system dependency installation."
            warn "You may need to install: gcc, make, pkg-config, libssl-dev, curl, git"
            ;;
    esac
}

# ════════════════════════════════════════════════
# DETECTION
# ════════════════════════════════════════════════

info "GitRecon Installer"
echo "    Detecting environment..."

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  OS_TAG="linux" ;;
  Darwin) OS_TAG="macos" ;;
  *)
    error "Unsupported OS: $OS"
    echo "    Supported: Linux, macOS"
    echo "    Please build from source: cargo build --release"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64)  ARCH_TAG="x86_64" ;;
  aarch64|arm64) ARCH_TAG="aarch64" ;;
  *)
    error "Unsupported architecture: $ARCH"
    echo "    Supported: x86_64, aarch64/arm64"
    echo "    Please build from source: cargo build --release"
    exit 1
    ;;
esac

echo "    OS   : $OS ($OS_TAG)"
echo "    Arch : $ARCH ($ARCH_TAG)"
echo ""

# ════════════════════════════════════════════════
# PREREQUISITE CHECKS
# ════════════════════════════════════════════════

# Check for curl (needed for both binary download and rustup)
if ! command_exists curl; then
    error "curl is required but not installed."
    if [ "$OS" = "Linux" ]; then
        echo "    Install with: sudo apt-get install curl  # Debian/Ubuntu"
        echo "              : sudo yum install curl        # RHEL/CentOS"
    else
        echo "    Install with: brew install curl"
    fi
    exit 1
fi

# ════════════════════════════════════════════════
# BINARY INSTALLATION (PREFERRED)
# ════════════════════════════════════════════════

# Releases use versioned archive names, so resolve the latest tag first.
RELEASE_API_URL="https://api.github.com/repos/${REPO}/releases/latest"
RELEASE_TAG="$(curl -fsSL "$RELEASE_API_URL" 2>/dev/null \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1 || true)"

if [ -n "$RELEASE_TAG" ]; then
    RELEASE_VERSION="${RELEASE_TAG#v}"
    ARCHIVE_NAME="${BIN_NAME}-${RELEASE_VERSION}-${OS_TAG}-${ARCH_TAG}.tar.gz"
    RELEASE_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/${ARCHIVE_NAME}"
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/SHA256SUMS"

    info "Checking for pre-built binary (${RELEASE_TAG})..."
    if curl -fsSL --head "$RELEASE_URL" >/dev/null 2>&1; then
        info "Downloading pre-built binary from GitHub Releases..."
        DOWNLOAD_DIR="$(mktemp -d)"
        ARCHIVE_PATH="${DOWNLOAD_DIR}/${ARCHIVE_NAME}"
        CHECKSUM_PATH="${DOWNLOAD_DIR}/SHA256SUMS"

        if ! curl -fsSL "$RELEASE_URL" -o "$ARCHIVE_PATH"; then
            error "Failed to download binary. Please check your internet connection."
            rm -rf "$DOWNLOAD_DIR"
            exit 1
        fi

        if [ ! -s "$ARCHIVE_PATH" ]; then
            error "Downloaded archive is empty. Please try again or report this issue."
            rm -rf "$DOWNLOAD_DIR"
            exit 1
        fi

        # Verify the release archive when a checksum utility and checksum asset exist.
        if curl -fsSL "$CHECKSUM_URL" -o "$CHECKSUM_PATH" 2>/dev/null; then
            if command_exists sha256sum; then
                if ! (cd "$DOWNLOAD_DIR" && sha256sum -c SHA256SUMS >/dev/null); then
                    error "SHA-256 verification failed for the downloaded release."
                    rm -rf "$DOWNLOAD_DIR"
                    exit 1
                fi
                success "SHA-256 verification passed"
            elif command_exists shasum; then
                EXPECTED_SHA="$(sed -n "s/^\\([a-fA-F0-9]*\\)[[:space:]]\\+${ARCHIVE_NAME}$/\\1/p" "$CHECKSUM_PATH")"
                ACTUAL_SHA="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
                if [ -z "$EXPECTED_SHA" ] || [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
                    error "SHA-256 verification failed for the downloaded release."
                    rm -rf "$DOWNLOAD_DIR"
                    exit 1
                fi
                success "SHA-256 verification passed"
            else
                warn "No SHA-256 utility found; continuing without local checksum verification."
            fi
        else
            warn "Checksum asset unavailable; continuing after archive validation."
        fi

        EXTRACT_DIR="${DOWNLOAD_DIR}/extract"
        mkdir -p "$EXTRACT_DIR"
        if ! tar -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"; then
            error "Failed to extract the downloaded release archive."
            rm -rf "$DOWNLOAD_DIR"
            exit 1
        fi
        BINARY_SOURCE="$(find "$EXTRACT_DIR" -type f -name "$BIN_NAME" | head -n 1)"
        if [ -z "$BINARY_SOURCE" ] || [ ! -s "$BINARY_SOURCE" ]; then
            error "Release archive does not contain a usable ${BIN_NAME} binary."
            rm -rf "$DOWNLOAD_DIR"
            exit 1
        fi
        chmod +x "$BINARY_SOURCE"

        if [ -w "$INSTALL_DIR" ]; then
            install -m 0755 "$BINARY_SOURCE" "${INSTALL_DIR}/${BIN_NAME}"
        else
            if ! sudo install -m 0755 "$BINARY_SOURCE" "${INSTALL_DIR}/${BIN_NAME}" 2>/dev/null; then
                error "Failed to install to $INSTALL_DIR. Try running with sudo."
                rm -rf "$DOWNLOAD_DIR"
                exit 1
            fi
        fi
        rm -rf "$DOWNLOAD_DIR"

        success "Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
        echo ""
        echo "  Run: gitrecon --help"
        echo ""
        echo "  Quick start:"
        echo "    gitrecon https://example.com"
        echo "    gitrecon --token \"\$GITHUB_TOKEN\""
        exit 0
    fi
fi

if [ -z "$RELEASE_TAG" ]; then
    warn "Unable to resolve the latest GitHub Release."
else
    warn "No pre-built binary found for ${OS_TAG}/${ARCH_TAG} in ${RELEASE_TAG}."
fi

# ════════════════════════════════════════════════
# SOURCE BUILD FALLBACK
# ════════════════════════════════════════════════
info "Building from source..."

# Check for git
if ! command_exists git; then
    error "git is required for source build but not installed."
    PKG_MANAGER="$(detect_package_manager)"
    case "$PKG_MANAGER" in
        apt)
            echo "    Install with: sudo apt-get install git"
            ;;
        yum|dnf)
            echo "    Install with: sudo $PKG_MANAGER install git"
            ;;
        brew)
            echo "    Install with: brew install git"
            ;;
        *)
            echo "    Please install git using your package manager"
            ;;
    esac
    exit 1
fi

# Ensure Rust is available
if ! command_exists cargo; then
    info "Rust not found. Installing via rustup..."

    # Install build dependencies first on Linux
    if [ "$OS" = "Linux" ]; then
        PKG_MANAGER="$(detect_package_manager)"
        install_build_dependencies "$PKG_MANAGER"
    fi

    # Install Rust
    if ! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path; then
        error "Failed to install Rust. Please visit https://rustup.rs/"
        exit 1
    fi

    # Source cargo environment in current shell
    export PATH="$HOME/.cargo/bin:$PATH"

    # Verify cargo is now available
    if ! command_exists cargo; then
        error "Cargo installation failed. Please restart your terminal and try again."
        exit 1
    fi

    success "Rust installed successfully"
fi

# Show Rust version
RUST_VERSION="$(cargo --version 2>/dev/null || echo "unknown")"
info "Using $RUST_VERSION"

# Create temporary build directory
BUILD_DIR="$(mktemp -d)"
trap "rm -rf $BUILD_DIR" EXIT INT TERM

info "Cloning repository..."
if ! git clone --depth 1 "https://github.com/${REPO}.git" "$BUILD_DIR" 2>/dev/null; then
    error "Failed to clone repository. Please check your internet connection."
    exit 1
fi

info "Building release binary (this may take 1-3 minutes)..."
echo "    This requires significant CPU and memory. Please be patient."

if ! cargo build --manifest-path "${BUILD_DIR}/Cargo.toml" --release 2>&1; then
    error "Build failed. Common issues:"
    echo "    1. Missing libsqlite3-dev (Debian/Ubuntu: sudo apt-get install libsqlite3-dev)"
    echo "    2. Insufficient disk space (>2GB required)"
    echo "    3. Insufficient memory (>1GB recommended)"
    echo "    4. Incompatible system libraries"
    echo ""
    echo "    For detailed error, run:"
    echo "      cd $BUILD_DIR && cargo build --release"
    exit 1
fi

BIN="${BUILD_DIR}/target/release/${BIN_NAME}"

# Verify binary exists
if [ ! -f "$BIN" ]; then
    error "Build completed but binary not found at: $BIN"
    exit 1
fi

# Install binary
info "Installing binary..."
if [ -w "$INSTALL_DIR" ]; then
    cp "$BIN" "${INSTALL_DIR}/${BIN_NAME}"
else
    if ! sudo cp "$BIN" "${INSTALL_DIR}/${BIN_NAME}" 2>/dev/null; then
        error "Failed to install to $INSTALL_DIR. Try running with sudo."
        exit 1
    fi
fi

success "Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
echo ""

# Show PATH reminder if using local cargo
if [ -f "$HOME/.cargo/bin/cargo" ]; then
    CARGO_BIN="$HOME/.cargo/bin"
    if ! echo "$PATH" | grep -q "$CARGO_BIN"; then
        warn "Note: ~/.cargo/bin is not in your PATH"
        echo "      Add the following to your ~/.bashrc or ~/.zshrc:"
        echo "      export PATH=\"\$HOME/.cargo/bin:\$PATH\""
    fi
fi

echo "  Run: gitrecon --help"
echo ""
echo "  Quick start:"
echo "    gitrecon https://example.com"
echo "    gitrecon --token \"\$GITHUB_TOKEN\""
echo ""
echo "  Documentation: https://github.com/${REPO}"
