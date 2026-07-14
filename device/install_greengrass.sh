#!/usr/bin/env bash
#
# install_greengrass.sh — ZTP PoC Greengrass Lite Installation
#
# Installs the Greengrass Lite DEB package, configures the OpenSSL PKCS#11
# provider, copies the PKCS#11 store to the ggcore user, and sets up the
# systemd overrides.
#
# CRITICAL ORDERING:
#   1. DEB installation FIRST (creates the ggcore user)
#   2. PKCS#11 store copy AFTER (the DEB postinst resets the home directory)
#
# Usage:
#   sudo ./install_greengrass.sh --deb /path/to/greengrass-lite.deb [--config-dir DIR]
#
# Requirements:
#   - sudo privileges
#   - tpm_device_setup.sh must have already been run
#   - openssl 3.x + the pkcs11-provider package
#
set -euo pipefail

###############################################################################
# Defaults & CLI
###############################################################################
GG_DEB=""
CONFIG_DIR="./ztp-config"
SKIP_PROVISION=false
GG_ROOT="/var/lib/greengrass"
GG_CONFIG="${GG_ROOT}/config.yaml"

# Greengrass Lite v2.5.1 — shipped as a zip on GitHub releases, containing a DEB
GG_VERSION="v2.5.1"
GG_DEB_BASE_URL="https://github.com/aws-greengrass/aws-greengrass-lite/releases/download"
GG_DEB_URL=""  # Set automatically (after architecture detection)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deb)            GG_DEB="$2";      shift 2 ;;
        --config-dir)     CONFIG_DIR="$2";   shift 2 ;;
        --skip-provision) SKIP_PROVISION=true; shift ;;
        --deb-url)        GG_DEB_URL="$2";  shift 2 ;;
        --gg-version)     GG_VERSION="$2";  shift 2 ;;
        -h|--help)        head -16 "$0" | tail -13; exit 0 ;;
        *)                echo "Unknown argument: $1"; exit 1 ;;
    esac
done

###############################################################################
# Helpers
###############################################################################
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[→]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*" >&2; }
step()  { echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }

###############################################################################
# Root check
###############################################################################
if [[ $EUID -ne 0 ]]; then
    err "This script must be run with sudo."
    exit 1
fi

###############################################################################
# Find the PKCS#11 module path (TPM)
###############################################################################
find_pkcs11_module() {
    local paths=(
        "/usr/lib/aarch64-linux-gnu/pkcs11/libtpm2_pkcs11.so"
        "/usr/lib/arm-linux-gnueabihf/pkcs11/libtpm2_pkcs11.so"
        "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so"
        "/usr/lib/aarch64-linux-gnu/libtpm2_pkcs11.so"
        "/usr/lib/arm-linux-gnueabihf/libtpm2_pkcs11.so"
        "/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so"
        "/usr/lib/libtpm2_pkcs11.so"
        "/usr/lib/pkcs11/libtpm2_pkcs11.so"
        "/usr/local/lib/libtpm2_pkcs11.so"
    )
    for p in "${paths[@]}"; do
        if [[ -f "$p" ]]; then
            echo "$p"
            return 0
        fi
    done
    # Fallback: find
    find /usr/lib /usr/local/lib -name "libtpm2_pkcs11.so" 2>/dev/null | head -1
}

###############################################################################
# Find the OpenSSL pkcs11-provider .so path
###############################################################################
find_pkcs11_provider() {
    local paths=(
        "/usr/lib/aarch64-linux-gnu/ossl-modules/pkcs11.so"
        "/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so"
        "/usr/lib/arm-linux-gnueabihf/ossl-modules/pkcs11.so"
        "/usr/lib/ossl-modules/pkcs11.so"
        "/usr/local/lib/ossl-modules/pkcs11.so"
    )
    for p in "${paths[@]}"; do
        if [[ -f "$p" ]]; then
            echo "$p"
            return 0
        fi
    done
    find /usr/lib /usr/local/lib -name "pkcs11.so" -path "*/ossl-modules/*" 2>/dev/null | head -1
}

###############################################################################
# 1. Preliminary Checks
###############################################################################
step "1/8 — Preliminary Checks"

# device_config.env
DEVICE_CONFIG="${CONFIG_DIR}/device_config.env"
if [[ -f "$DEVICE_CONFIG" ]]; then
    # shellcheck disable=SC1090
    source "$DEVICE_CONFIG"
    info "device_config.env loaded"
else
    warn "device_config.env not found: ${DEVICE_CONFIG}"
    warn "Provisioning parameters may be missing"
fi

# Root CA
ROOT_CA="${CONFIG_DIR}/AmazonRootCA1.pem"
if [[ -f "$ROOT_CA" ]]; then
    info "Root CA found: ${ROOT_CA}"
else
    err "Root CA not found: ${ROOT_CA}"
    exit 1
fi

# Claim certs
CLAIM_CERT="${CONFIG_DIR}/claim-certs/claim.pem.crt"
if [[ -f "$CLAIM_CERT" ]]; then
    info "Claim cert found: ${CLAIM_CERT}"
else
    warn "Claim cert not found: ${CLAIM_CERT}"
fi

# PKCS#11 store — which user should it be copied from?
ORIGINAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo '')}"
if [[ -z "$ORIGINAL_USER" ]]; then
    err "Could not determine the original user. SUDO_USER is empty."
    exit 1
fi

ORIGINAL_HOME=$(eval echo "~${ORIGINAL_USER}")
TPM_STORE_SRC="${ORIGINAL_HOME}/.tpm2_pkcs11"

if [[ -d "$TPM_STORE_SRC" ]]; then
    info "TPM PKCS#11 store found: ${TPM_STORE_SRC}"
else
    err "TPM PKCS#11 store not found: ${TPM_STORE_SRC}"
    err "Run tpm_device_setup.sh first."
    exit 1
fi

# PKCS#11 TPM module
PKCS11_MODULE=$(find_pkcs11_module)
if [[ -z "$PKCS11_MODULE" ]]; then
    err "libtpm2_pkcs11.so not found!"
    err "Install it: sudo apt install libtpm2-pkcs11-1"
    exit 1
fi
info "PKCS#11 TPM module: ${PKCS11_MODULE}"

###############################################################################
# 2. Greengrass Lite DEB Installation
###############################################################################
step "2/8 — Greengrass Lite DEB Installation"

# Package name check — different versions may use different names
# aws-greengrass-lite, greengrass-lite, greengrass-nucleus-lite, etc.
GG_INSTALLED=$(dpkg -l 2>/dev/null | grep -iE "greengrass.*(lite|nucleus-lite)" | awk '{print $2, $3}' || true)

if [[ -n "$GG_INSTALLED" ]]; then
    info "Greengrass Lite is already installed: ${GG_INSTALLED}"
else
    # Find the DEB file
    if [[ -n "$GG_DEB" && -f "$GG_DEB" ]]; then
        info "Using local DEB: ${GG_DEB}"
    else
        # Auto-search: config dir, home, /tmp, current dir
        GG_DEB=""
        for search_dir in "$CONFIG_DIR" "$ORIGINAL_HOME" "/tmp" "." "$ORIGINAL_HOME/Downloads"; do
            found=$(find "$search_dir" -maxdepth 2 -name "*.deb" \
                -iname "*greengrass*" 2>/dev/null | head -1 || true)
            if [[ -n "$found" ]]; then
                GG_DEB="$found"
                break
            fi
        done

        # If not found, download it from GitHub
        if [[ -z "$GG_DEB" ]]; then
            # requires the unzip command
            if ! command -v unzip &>/dev/null; then
                err "unzip not found. Install it: sudo apt install unzip"
                exit 1
            fi

            # Architecture detection
            ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
            case "$ARCH" in
                arm64|aarch64) DEB_ARCH="arm64" ;;
                amd64|x86_64)  DEB_ARCH="amd64" ;;
                armhf|armv7l)  DEB_ARCH="armhf" ;;
                *)             DEB_ARCH="$ARCH" ;;
            esac

            # Build the URL (use --deb-url if the user provided one)
            if [[ -z "$GG_DEB_URL" ]]; then
                GG_DEB_URL="${GG_DEB_BASE_URL}/${GG_VERSION}/aws-greengrass-lite-deb-${DEB_ARCH}.zip"
            fi

            GG_ZIP="/tmp/aws-greengrass-lite-deb-${DEB_ARCH}.zip"
            GG_DEB_DIR="/tmp/greengrass-lite-deb"

            warn "Downloading Greengrass Lite ${GG_VERSION} (${DEB_ARCH})..."
            warn "URL: ${GG_DEB_URL}"
            curl -sS -L -o "$GG_ZIP" "$GG_DEB_URL"

            if [[ ! -f "$GG_ZIP" ]] || [[ $(stat -c%s "$GG_ZIP" 2>/dev/null || echo 0) -lt 1000 ]]; then
                err "Download failed or the file is too small"
                err "Check the URL: ${GG_DEB_URL}"
                exit 1
            fi
            info "Zip downloaded: $(du -h "$GG_ZIP" | cut -f1)"

            # Extract the zip
            rm -rf "$GG_DEB_DIR"
            mkdir -p "$GG_DEB_DIR"
            unzip -o "$GG_ZIP" -d "$GG_DEB_DIR" >/dev/null
            info "Zip extracted: ${GG_DEB_DIR}/"

            # Find the DEB file (we don't know the exact name inside the zip)
            GG_DEB=$(find "$GG_DEB_DIR" -name "*.deb" | head -1 || true)

            if [[ -z "$GG_DEB" || ! -f "$GG_DEB" ]]; then
                err "No DEB file found inside the zip!"
                err "Zip contents:"
                ls -la "$GG_DEB_DIR"/ >&2
                exit 1
            fi

            info "DEB found: ${GG_DEB}"
        else
            info "Local DEB found: ${GG_DEB}"
        fi
    fi

    warn "Installing Greengrass Lite: $(basename "$GG_DEB")..."
    dpkg -i "$GG_DEB" || apt-get install -f -y
    info "Greengrass Lite installed"
fi

# Was the ggcore user created?
if id -u ggcore &>/dev/null; then
    info "ggcore user exists"
else
    err "ggcore user was not created — the DEB installation may have failed"
    exit 1
fi

###############################################################################
# 3. ggcore → tss Group
###############################################################################
step "3/8 — ggcore TPM Access"

if id -nG ggcore | grep -qw tss; then
    info "ggcore is already in the tss group"
else
    warn "Adding ggcore to the tss group..."
    usermod -aG tss ggcore
    info "ggcore added to the tss group"
fi

###############################################################################
# 4. OpenSSL PKCS#11 Provider Check
###############################################################################
step "4/8 — OpenSSL PKCS#11 Provider"

# Greengrass Lite resolves PKCS#11 URIs via the OpenSSL OSSL_STORE API.
# For this to work, the pkcs11 provider must be defined in /etc/ssl/openssl.cnf.
# Source: https://github.com/aws-greengrass/aws-greengrass-lite/blob/main/docs/PKCS11_SUPPORT.md
#
# NOTE: This script does NOT modify openssl.cnf.
# Debian/Raspberry Pi OS's openssl.cnf format is complex
# (commented-out sections, tpm2 provider, etc.), and automatic editing
# risks creating duplicate sections.

OPENSSL_CNF="/etc/ssl/openssl.cnf"
PKCS11_PROVIDER_SO=$(find_pkcs11_provider)

if [[ -z "$PKCS11_PROVIDER_SO" ]]; then
    warn "OpenSSL pkcs11-provider .so not found!"
    warn "Install it: sudo apt install openssl pkcs11-provider"
else
    info "OpenSSL pkcs11-provider .so: ${PKCS11_PROVIDER_SO}"
fi

# Test whether the provider is active
if openssl list -providers 2>/dev/null | grep -qi "pkcs11"; then
    info "OpenSSL pkcs11 provider is active"
else
    warn "OpenSSL pkcs11 provider is NOT active!"
    warn ""
    warn "You need to manually edit openssl.cnf."
    warn "Detailed instructions: https://github.com/aws-greengrass/aws-greengrass-lite/blob/main/docs/PKCS11_SUPPORT.md"
    warn ""
    warn "Quick summary — in /etc/ssl/openssl.cnf:"
    warn "  1. In the [openssl_init] section, the 'providers = provider_sect' line must be uncommented"
    warn "  2. In the [provider_sect] section, there must be a 'pkcs11 = pkcs11_sect' line"
    warn "  3. There must be a [pkcs11_sect] section:"
    warn "       [pkcs11_sect]"
    warn "       module = ${PKCS11_PROVIDER_SO:-/usr/lib/.../ossl-modules/pkcs11.so}"
    warn "       pkcs11-module-path = ${PKCS11_MODULE}"
    warn "       activate = 1"
    warn ""
    warn "Verification: openssl list -providers → pkcs11 should be listed"
    warn ""
    warn "⚠  Without the pkcs11 provider, Greengrass Lite cannot resolve PKCS#11 URIs!"
fi

###############################################################################
# 5. Credential Directories
###############################################################################
step "5/8 — Credential Directories"

CRED_DIR="${GG_ROOT}/credentials"
mkdir -p "$CRED_DIR"

# Copy the Root CA
cp "$ROOT_CA" "${CRED_DIR}/AmazonRootCA1.pem"
info "Root CA copied: ${CRED_DIR}/AmazonRootCA1.pem"

# Copy the claim cert
if [[ -f "$CLAIM_CERT" ]]; then
    cp "$CLAIM_CERT" "${CRED_DIR}/claim.pem.crt"
    info "Claim cert copied: ${CRED_DIR}/claim.pem.crt"
fi

# Claim key — only needed for provisioning, can be deleted afterwards
CLAIM_KEY="${CONFIG_DIR}/claim-certs/claim.private.pem.key"
if [[ -f "$CLAIM_KEY" ]]; then
    cp "$CLAIM_KEY" "${CRED_DIR}/claim.private.pem.key"
    chmod 600 "${CRED_DIR}/claim.private.pem.key"
    info "Claim key copied (should be deleted after provisioning)"
fi

chown -R ggcore:ggcore "$CRED_DIR"

###############################################################################
# 6. PKCS#11 Store Copy (CRITICAL — AFTER the DEB!)
###############################################################################
step "6/8 — PKCS#11 Store → ggcore"

GGCORE_HOME=$(eval echo "~ggcore")
TPM_STORE_DST="${GGCORE_HOME}/.tpm2_pkcs11"

warn "Copying PKCS#11 store: ${TPM_STORE_SRC} → ${TPM_STORE_DST}"
rm -rf "$TPM_STORE_DST"
cp -r "$TPM_STORE_SRC" "$TPM_STORE_DST"
chown -R ggcore:ggcore "$TPM_STORE_DST"
info "PKCS#11 store copied"

# Fallback location: /etc/tpm2_pkcs11
ETC_STORE="/etc/tpm2_pkcs11"
warn "Updating fallback store: ${ETC_STORE}"
rm -rf "$ETC_STORE"
cp -r "$TPM_STORE_SRC" "$ETC_STORE"
chown -R ggcore:ggcore "$ETC_STORE"
info "Fallback store updated"

# Access test as ggcore
warn "Testing PKCS#11 access (as ggcore)..."
if sudo -u ggcore \
    TPM2_PKCS11_STORE="$TPM_STORE_DST" \
    pkcs11-tool \
        --module "$PKCS11_MODULE" \
        --token-label greengrass \
        --pin 1234 \
        --list-objects --type privkey 2>/dev/null | grep -q "device-identity"; then
    info "PKCS#11 access test passed — device-identity key is accessible"
else
    warn "PKCS#11 access test failed — check the token label or pin"
    warn "Manual test: sudo -u ggcore TPM2_PKCS11_STORE=${TPM_STORE_DST} pkcs11-tool --module ${PKCS11_MODULE} ..."
fi

###############################################################################
# 7. systemd Overrides
###############################################################################
step "7/8 — systemd Overrides"

# Greengrass Lite services — a separate override per service
# NOTE: a greengrass-lite.target.d/ override does NOT WORK ([Service] is not supported on a target)
# so we add the override to each service individually.

# Dynamically find the installed services (names may vary between versions)
GG_SERVICES=()
for svc_file in /etc/systemd/system/ggl.*.service /usr/lib/systemd/system/ggl.*.service; do
    if [[ -f "$svc_file" ]]; then
        svc_name=$(basename "$svc_file" .service)
        GG_SERVICES+=("$svc_name")
    fi
done

if [[ ${#GG_SERVICES[@]} -eq 0 ]]; then
    warn "No Greengrass Lite service files found, trying known names..."
    GG_SERVICES=(
        "ggl.core.iotcored"
        "ggl.core.ggdeploymentd"
        "ggl.core.ggpubsubd"
        "ggl.core.gg-fleet-statusd"
        "ggl.core.nucleus"
    )
fi

OVERRIDE_CONTENT="[Service]
Environment=\"TPM2_PKCS11_STORE=${TPM_STORE_DST}\"
"

OVERRIDE_COUNT=0
for svc in "${GG_SERVICES[@]}"; do
    OVERRIDE_DIR="/etc/systemd/system/${svc}.service.d"

    if systemctl cat "${svc}.service" &>/dev/null 2>&1; then
        mkdir -p "$OVERRIDE_DIR"
        echo "$OVERRIDE_CONTENT" > "${OVERRIDE_DIR}/tpm-pkcs11.conf"
        info "Override added: ${svc}.service"
        ((OVERRIDE_COUNT++)) || true
    fi
done

if [[ $OVERRIDE_COUNT -eq 0 ]]; then
    warn "Could not add an override to any Greengrass Lite service"
    warn "Check the services after DEB installation: systemctl list-units 'ggl.*'"
fi

systemctl daemon-reload
info "systemd daemon-reload complete"

###############################################################################
# 8. Config File
###############################################################################
step "8/8 — Greengrass Config"

if [[ -f "$GG_CONFIG" ]]; then
    info "config.yaml already exists: ${GG_CONFIG}"
    info "(will be updated when provision_device.py runs)"
elif [[ "$SKIP_PROVISION" == "true" ]]; then
    warn "config.yaml was not created (--skip-provision)"
    warn "It will be created when provision_device.py runs"
else
    # Minimal config — for when provisioning hasn't happened yet
    warn "Creating a minimal config.yaml (will be updated after provisioning)..."
    cat > "$GG_CONFIG" <<YAML
---
# Greengrass Lite — generated by install_greengrass.sh
# Will be updated when provision_device.py runs

system:
  rootPath: "${GG_ROOT}"
  rootCaPath: "${CRED_DIR}/AmazonRootCA1.pem"
  # privateKeyPath and certificateFilePath will be added after provisioning
YAML
    chown ggcore:ggcore "$GG_CONFIG"
    info "Minimal config.yaml created"
fi

# Config directory ownership
chown -R ggcore:ggcore "$GG_ROOT"

###############################################################################
# Summary
###############################################################################
step "Installation Complete!"
echo ""
echo -e "  ${BOLD}Greengrass Lite:${NC}"
echo -e "    Root:       ${GG_ROOT}"
echo -e "    Config:     ${GG_CONFIG}"
echo -e "    Creds:      ${CRED_DIR}/"
echo ""
echo -e "  ${BOLD}OpenSSL PKCS#11:${NC}"
echo -e "    Provider:   ${PKCS11_PROVIDER_SO:-not found}"
echo -e "    Module:     ${PKCS11_MODULE}"
echo -e "    Config:     ${OPENSSL_CNF}"
echo ""
echo -e "  ${BOLD}PKCS#11 Store:${NC}"
echo -e "    ggcore:     ${TPM_STORE_DST}"
echo -e "    Fallback:   ${ETC_STORE}"
echo ""
echo -e "  ${BOLD}systemd Overrides (${OVERRIDE_COUNT} service):${NC}"
for svc in "${GG_SERVICES[@]}"; do
    OVERRIDE_DIR="/etc/systemd/system/${svc}.service.d"
    if [[ -d "$OVERRIDE_DIR" ]]; then
        echo -e "    ✓ ${svc}.service.d/tpm-pkcs11.conf"
    fi
done
echo ""
echo -e "  ${BOLD}Verification:${NC}"
echo -e "    ${YELLOW}openssl list -providers${NC}           → pkcs11 should be active"
echo -e "    ${YELLOW}openssl store -provider pkcs11 'pkcs11:token=greengrass'${NC}"
echo ""
echo -e "  ${BOLD}Next Steps:${NC}"
echo -e "    1. ${YELLOW}sudo ./provision_device.py${NC}                  → Fleet provisioning"
echo -e "    2. ${YELLOW}sudo systemctl restart greengrass-lite.target${NC} → Start"
echo ""
