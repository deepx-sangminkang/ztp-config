#!/bin/bash
# =============================================================================
# Greengrass Cleanup Script
# ARCHITECTURE: Pure PKCS#11 (tpm2-pkcs11 driver, no tpm2-tools)
# Run as: sudo ./00_tpm_clean.sh
# Purpose: Prepares the device for a fresh installation
# =============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo ./00_tpm_clean.sh"
    exit 1
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo -e "${RED}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     GREENGRASS & PKCS#11 CLEANUP           ║"
echo "  ║  This action is irreversible! Are you sure? ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"
read -p "Type 'yes' to continue: " CONFIRM
[ "$CONFIRM" != "yes" ] && echo "Cancelled." && exit 0

# =============================================================================
# Stop the Greengrass Service
# =============================================================================
info "Stopping Greengrass services..."
systemctl stop greengrass-lite.target 2>/dev/null || true
sleep 2
success "Services stopped"

# =============================================================================
# Clear the PKCS#11 Token
# There are no tpm2-tools; tokens are cleared by deleting the tpm2-pkcs11
# SQLite DB. Once the DB is deleted, the corresponding objects inside the
# TPM become orphaned but inaccessible.
# =============================================================================
info "Clearing PKCS#11 token database..."

# List existing tokens with pkcs11-tool (informational only)
PKCS11_SO=$(find /usr -name "libtpm2_pkcs11.so*" 2>/dev/null | head -1)
if [ -n "$PKCS11_SO" ]; then
    TOKENS=$(pkcs11-tool --module "$PKCS11_SO" --list-slots 2>/dev/null \
        | grep "token label" | awk -F': ' '{print $2}' | xargs || true)
    [ -n "$TOKENS" ] && info "  Found tokens: $TOKENS" || warn "  No active tokens found"
fi

# Clear the tpm2-pkcs11 DB directories
for DIR in /var/lib/tpm2-pkcs11 /root/.tpm2_pkcs11 /etc/tpm2-pkcs11; do
    if [ -d "$DIR" ]; then
        rm -rf "$DIR"
        success "  Cleared: $DIR"
    fi
done

find /home -maxdepth 3 -name "tpm2_pkcs11.sqlite3" 2>/dev/null | while read F; do
    rm -f "$F" && success "  Deleted: $F"
done

success "PKCS#11 tokens cleared"

# =============================================================================
# Clear the Greengrass Database and Config
# =============================================================================
info "Clearing Greengrass database..."
rm -f /var/lib/greengrass/config.db
success "config.db deleted"

info "Clearing Greengrass credentials..."
rm -f /var/lib/greengrass/credentials/certificate.pem
rm -f /var/lib/greengrass/credentials/priv_key
rm -f /var/lib/greengrass/credentials/cert_req.pem
success "Credentials cleared"

info "Clearing Greengrass config.d..."
rm -f /etc/greengrass/config.d/device.yaml
rm -f /etc/greengrass/config.d/fleet-provisioning.yaml
success "Config files cleared"

info "Clearing claim certificates..."
rm -rf /greengrass/v2/claim-certs/
success "Claim certificates deleted"

# =============================================================================
# Remove Greengrass Nucleus Lite
# =============================================================================
info "Removing Greengrass Nucleus Lite..."

if dpkg -l | grep -q "aws-greengrass-lite"; then
    dpkg --purge aws-greengrass-lite 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    success "Greengrass Nucleus Lite removed"
else
    warn "Greengrass Nucleus Lite is not installed"
fi

systemctl daemon-reload 2>/dev/null || true

userdel ggcore 2>/dev/null && success "User ggcore deleted" || true
userdel gg_component 2>/dev/null && success "User gg_component deleted" || true
groupdel ggcore 2>/dev/null || true
groupdel gg_component 2>/dev/null || true

rm -rf /var/lib/greengrass/ /greengrass/ /etc/greengrass/
success "Greengrass directories cleared"

# leftover pkcs11-provider build artifacts
rm -rf /home/*/pkcs11-provider-build 2>/dev/null || true
success "Build directories cleared"

# =============================================================================
# Temporary Files
# =============================================================================
info "Clearing temporary files..."
rm -f /tmp/gg_*.der /tmp/gg_*.pem /tmp/gg_*.csr
rm -f /tmp/fleet_provisioning.log
rm -rf /tmp/gg_fleet_output/
success "Temporary files cleared"

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Cleanup Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "  PKCS#11 DB      : $([ -d /var/lib/tpm2-pkcs11 ] && echo 'PRESENT' || echo 'ABSENT')"
echo "  config.db       : $([ -f /var/lib/greengrass/config.db ] && echo 'PRESENT' || echo 'ABSENT')"
echo "  certificate.pem : $([ -f /var/lib/greengrass/credentials/certificate.pem ] && echo 'PRESENT' || echo 'ABSENT')"
echo ""
echo -e "${YELLOW}Next step:${NC} sudo ./02_device_setup.sh"
echo ""
