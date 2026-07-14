#!/usr/bin/env bash
#
# tpm_device_setup.sh — ZTP PoC TPM/HSM Key Setup & Factory Registration
#
# Run once per device (on the factory line).
# Imports the claim key into the TPM, generates the device identity key,
# and registers with the registration server.
#
# Usage:
#   ./tpm_device_setup.sh \
#       --server http://REGISTRATION_SERVER:5000 \
#       --claim-cert ./ztp-config/claim-certs/claim.pem.crt \
#       --claim-key  ./ztp-config/claim-certs/claim.private.pem.key \
#       [--token-label greengrass] \
#       [--pin 1234] \
#       [--sopin 12345678]
#
# Requirements:
#   - tpm2-tools, tpm2-abrmd, libtpm2-pkcs11-tools
#   - openssl (with PKCS#11 provider/engine support)
#   - curl, jq
#   - access to /dev/tpm0 and /dev/tpmrm0
#
# NOTE: Run as a normal user (NOT with sudo).
#       The user must be in the tss group.
#
set -euo pipefail

###############################################################################
# Defaults & CLI
###############################################################################
REG_SERVER=""
CLAIM_CERT=""
CLAIM_KEY=""
TOKEN_LABEL="greengrass"
USER_PIN="1234"
SO_PIN="12345678"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)      REG_SERVER="$2";  shift 2 ;;
        --claim-cert)  CLAIM_CERT="$2";  shift 2 ;;
        --claim-key)   CLAIM_KEY="$2";   shift 2 ;;
        --token-label) TOKEN_LABEL="$2"; shift 2 ;;
        --pin)         USER_PIN="$2";    shift 2 ;;
        --sopin)       SO_PIN="$2";      shift 2 ;;
        -h|--help)     head -18 "$0" | tail -15; exit 0 ;;
        *)             echo "Unknown argument: $1"; exit 1 ;;
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

cleanup() {
    rm -f /tmp/device-csr.pem /tmp/device-pubkey.pem /tmp/claim-cert.der 2>/dev/null || true
}
trap cleanup EXIT

###############################################################################
# Preliminary Checks
###############################################################################
step "1/8 — Preliminary Checks"

# Required arguments
if [[ -z "$REG_SERVER" ]]; then
    err "--server argument is required (e.g. http://192.168.1.100:5000)"
    exit 1
fi
if [[ -z "$CLAIM_CERT" || -z "$CLAIM_KEY" ]]; then
    err "--claim-cert and --claim-key arguments are required"
    exit 1
fi
if [[ ! -f "$CLAIM_CERT" ]]; then
    err "Claim cert not found: ${CLAIM_CERT}"
    exit 1
fi
if [[ ! -f "$CLAIM_KEY" ]]; then
    err "Claim key not found: ${CLAIM_KEY}"
    exit 1
fi

# Commands
for cmd in tpm2_ptool pkcs11-tool openssl curl jq; do
    if ! command -v "$cmd" &>/dev/null; then
        err "${cmd} not found. Please install it."
        exit 1
    fi
done

# Auto-detect the PKCS#11 module path
PKCS11_MODULE=""
PKCS11_SEARCH_PATHS=(
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
for p in "${PKCS11_SEARCH_PATHS[@]}"; do
    if [[ -f "$p" ]]; then
        PKCS11_MODULE="$p"
        break
    fi
done
# Fallback: search with find
if [[ -z "$PKCS11_MODULE" ]]; then
    PKCS11_MODULE=$(find /usr/lib /usr/local/lib -name "libtpm2_pkcs11.so" 2>/dev/null | head -1 || true)
fi
if [[ -z "$PKCS11_MODULE" ]]; then
    err "libtpm2_pkcs11.so not found!"
    err "Install it: sudo apt install libtpm2-pkcs11-1"
    exit 1
fi
info "PKCS#11 module: ${PKCS11_MODULE}"

# TPM devices
if [[ ! -c /dev/tpm0 ]]; then
    err "/dev/tpm0 not found. Is TPM hardware present?"
    exit 1
fi
if [[ ! -c /dev/tpmrm0 ]]; then
    err "/dev/tpmrm0 not found. Is tpm2-abrmd running?"
    exit 1
fi

# tpm2-abrmd service
if systemctl is-active --quiet tpm2-abrmd 2>/dev/null; then
    info "tpm2-abrmd is running"
else
    warn "tpm2-abrmd is not active, attempting to start it..."
    sudo systemctl start tpm2-abrmd || {
        err "Failed to start tpm2-abrmd"
        exit 1
    }
    info "tpm2-abrmd started"
fi

# Sudo check — this script must NOT run with sudo
if [[ $EUID -eq 0 ]]; then
    err "Do not run this script as root/sudo!"
    err "Run it as a normal user (the user must be in the tss group)."
    exit 1
fi

# tss group membership
if ! id -nG | grep -qw tss; then
    warn "User is not in the tss group. Adding..."
    sudo usermod -aG tss "$(whoami)"
    err "Added to the tss group. Please logout/login and run this again."
    exit 1
fi

info "All preliminary checks passed"

###############################################################################
# 2. PKCS#11 Store & Token
###############################################################################
step "2/8 — PKCS#11 Store & Token"

PKCS11_STORE="${HOME}/.tpm2_pkcs11"

# Clean up corrupted/stale stores in other locations
# (install_greengrass.sh may have left one in a broken state)
for leftover in /home/ggcore/.tpm2_pkcs11 /etc/tpm2_pkcs11; do
    if [[ -e "$leftover" && ! -d "$leftover" ]]; then
        warn "Cleaning up corrupted store: ${leftover}"
        sudo rm -f "$leftover" 2>/dev/null || true
    fi
done

# TPM2_PKCS11_STORE environment — needed for all tpm2_ptool commands
export TPM2_PKCS11_STORE="$PKCS11_STORE"

# Check whether the token already exists — via listtokens (listprimaries doesn't show the token label)
EXISTING_TOKENS=$(tpm2_ptool listtokens --path="$PKCS11_STORE" 2>/dev/null || true)

if echo "$EXISTING_TOKENS" | grep -q "$TOKEN_LABEL"; then
    info "PKCS#11 token already exists: ${TOKEN_LABEL}"
else
    # Check whether a primary object exists
    HAS_PRIMARY=$(tpm2_ptool listprimaries --path="$PKCS11_STORE" 2>/dev/null | grep -c "id:" || true)

    if [[ "$HAS_PRIMARY" -eq 0 ]]; then
        warn "Creating the PKCS#11 store (primary object)..."
        # Clean up any existing corrupted store
        if [[ -d "$PKCS11_STORE" ]]; then
            warn "Cleaning up old store: ${PKCS11_STORE}"
            rm -rf "$PKCS11_STORE"
        fi
        tpm2_ptool init --path="$PKCS11_STORE"
        info "PKCS#11 store and primary object created"
    fi

    # Get the primary ID
    PRIMARY_ID=$(tpm2_ptool listprimaries --path="$PKCS11_STORE" 2>/dev/null | grep -oP 'id:\s*\K\d+' | head -1)
    if [[ -z "$PRIMARY_ID" ]]; then
        err "Could not get the primary object ID"
        err "Try manually: tpm2_ptool init --path=${PKCS11_STORE} && tpm2_ptool listprimaries --path=${PKCS11_STORE}"
        exit 1
    fi
    info "Primary object ID: ${PRIMARY_ID}"

    warn "Creating token: ${TOKEN_LABEL}"
    tpm2_ptool addtoken \
        --path="$PKCS11_STORE" \
        --pid="$PRIMARY_ID" \
        --sopin="$SO_PIN" \
        --userpin="$USER_PIN" \
        --label="$TOKEN_LABEL"
    info "Token created: ${TOKEN_LABEL}"
fi

###############################################################################
# 3. Claim Private Key Import
###############################################################################
step "3/8 — Claim Key Import"

# Does the claim key already exist?
CLAIM_KEY_EXISTS=$(pkcs11-tool \
    --module "$PKCS11_MODULE" \
    --token-label "$TOKEN_LABEL" \
    --pin "$USER_PIN" \
    --list-objects --type privkey 2>/dev/null | grep -c "claim-key" || true)

if [[ "$CLAIM_KEY_EXISTS" -gt 0 ]]; then
    info "Claim key is already on the TPM: claim-key"
else
    warn "Importing the claim private key into the TPM..."

    # tpm2_ptool import: --label = token label, --key-label = object label
    tpm2_ptool import \
        --path="$PKCS11_STORE" \
        --label="$TOKEN_LABEL" \
        --userpin="$USER_PIN" \
        --key-label="claim-key" \
        --algorithm="rsa" \
        --privkey="$CLAIM_KEY"

    info "Claim key imported: claim-key"
fi

###############################################################################
# 4. Claim Certificate Import
###############################################################################
step "4/8 — Claim Certificate Import"

CLAIM_CERT_EXISTS=$(pkcs11-tool \
    --module "$PKCS11_MODULE" \
    --token-label "$TOKEN_LABEL" \
    --pin "$USER_PIN" \
    --list-objects --type cert 2>/dev/null | grep -c "claim-cert" || true)

if [[ "$CLAIM_CERT_EXISTS" -gt 0 ]]; then
    info "Claim cert is already on the TPM: claim-cert"
else
    warn "Writing the claim certificate to the TPM..."

    # PEM → DER conversion
    openssl x509 -in "$CLAIM_CERT" -outform DER -out /tmp/claim-cert.der

    # Get the claim key's ID (to match it with the cert)
    # pkcs11-tool output format varies by version, so try several methods
    CLAIM_KEY_ID=""

    # Method 1: parse from pkcs11-tool --list-objects output
    PKCS11_OUTPUT=$(pkcs11-tool \
        --module "$PKCS11_MODULE" \
        --token-label "$TOKEN_LABEL" \
        --pin "$USER_PIN" \
        --list-objects --type privkey 2>/dev/null || true)

    if [[ -n "$PKCS11_OUTPUT" ]]; then
        # Find the claim-key block, then look for ID: on the following lines
        CLAIM_KEY_ID=$(echo "$PKCS11_OUTPUT" \
            | awk '/claim-key/{found=1} found && /ID:/{print $2; exit}' || true)
    fi

    # Method 2: from tpm2_ptool listobjects
    if [[ -z "$CLAIM_KEY_ID" ]]; then
        CLAIM_KEY_ID=$(tpm2_ptool listobjects \
            --label="$TOKEN_LABEL" 2>/dev/null \
            | awk '/claim-key/{found=1} found && /CKA_ID/{gsub(/'\''/, ""); print $2; exit}' || true)
    fi

    # Method 3: without hardcoding, take the ID of the first private key
    if [[ -z "$CLAIM_KEY_ID" ]]; then
        CLAIM_KEY_ID=$(echo "$PKCS11_OUTPUT" \
            | grep "ID:" | head -1 | awk '{print $2}' || true)
    fi

    if [[ -z "$CLAIM_KEY_ID" ]]; then
        err "Could not get the claim key ID"
        err "Check manually: pkcs11-tool --module "$PKCS11_MODULE" --token-label $TOKEN_LABEL --pin $USER_PIN --list-objects"
        exit 1
    fi

    info "Claim key ID: ${CLAIM_KEY_ID}"

    pkcs11-tool \
        --module "$PKCS11_MODULE" \
        --token-label "$TOKEN_LABEL" \
        --pin "$USER_PIN" \
        --write-object /tmp/claim-cert.der \
        --type cert \
        --label "claim-cert" \
        --id "$CLAIM_KEY_ID"

    info "Claim cert written: claim-cert (ID: ${CLAIM_KEY_ID})"
fi

###############################################################################
# 5. Device Identity Key Pair — ECC256
###############################################################################
step "5/8 — Device Identity Key (ECC256)"

DEVICE_KEY_EXISTS=$(pkcs11-tool \
    --module "$PKCS11_MODULE" \
    --token-label "$TOKEN_LABEL" \
    --pin "$USER_PIN" \
    --list-objects --type privkey 2>/dev/null | grep -c "device-identity" || true)

if [[ "$DEVICE_KEY_EXISTS" -gt 0 ]]; then
    info "Device identity key already exists: device-identity"
else
    warn "Generating the device identity ECC256 key pair (on the TPM)..."

    tpm2_ptool addkey \
        --path="$PKCS11_STORE" \
        --label="$TOKEN_LABEL" \
        --userpin="$USER_PIN" \
        --key-label="device-identity" \
        --algorithm="ecc256"

    info "Device identity key generated: ECC256, never extractable"
fi

###############################################################################
# 6. Serial Number
###############################################################################
step "6/8 — Device Serial Number"

# Raspberry Pi serial number
if [[ -f /proc/cpuinfo ]]; then
    SERIAL=$(grep -i "serial" /proc/cpuinfo | awk '{print $3}' | sed 's/^0*//' || true)
fi

# Fallback: machine-id
if [[ -z "${SERIAL:-}" ]]; then
    if [[ -f /etc/machine-id ]]; then
        SERIAL=$(cat /etc/machine-id | head -c 16)
        warn "Pi serial number not found, using machine-id: ${SERIAL}"
    else
        SERIAL=$(hostname)-$(date +%s)
        warn "Fallback serial number: ${SERIAL}"
    fi
fi

info "Serial number: ${SERIAL}"

###############################################################################
# 7. Generate CSR & Public Key Hash
###############################################################################
step "7/8 — CSR & Public Key Hash"

PKCS11_DEVICE_KEY_URI="pkcs11:token=${TOKEN_LABEL};object=device-identity;type=private;pin-value=${USER_PIN}"

# For OpenSSL to access the TPM key via the PKCS#11 provider, the
# TPM2_PKCS11_STORE environment variable and the correct provider
# configuration are required. install_greengrass.sh may not have run yet,
# so we create a temporary openssl.cnf.

OPENSSL_PKCS11_CNF="/tmp/openssl-pkcs11.cnf"

# Find the pkcs11-provider .so path
PKCS11_PROVIDER_SO=""
for p in \
    "/usr/lib/aarch64-linux-gnu/ossl-modules/pkcs11.so" \
    "/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so" \
    "/usr/lib/arm-linux-gnueabihf/ossl-modules/pkcs11.so" \
    "/usr/lib/ossl-modules/pkcs11.so"; do
    if [[ -f "$p" ]]; then
        PKCS11_PROVIDER_SO="$p"
        break
    fi
done

CSR_CREATED=false

# --- Method 1: OpenSSL pkcs11 provider (recommended) ---
if [[ -n "$PKCS11_PROVIDER_SO" ]]; then
    warn "Generating CSR — OpenSSL pkcs11 provider (CN=${SERIAL})..."

    cat > "$OPENSSL_PKCS11_CNF" <<SSLCNF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = ${PKCS11_PROVIDER_SO}
pkcs11-module-path = ${PKCS11_MODULE}
activate = 1

[req]
distinguished_name = req_dn
prompt = no

[req_dn]
CN = ${SERIAL}
SSLCNF

    if TPM2_PKCS11_STORE="$PKCS11_STORE" \
       OPENSSL_CONF="$OPENSSL_PKCS11_CNF" \
       openssl req -new \
           -key "$PKCS11_DEVICE_KEY_URI" \
           -subj "/CN=${SERIAL}" \
           -out /tmp/device-csr.pem 2>/dev/null; then
        info "CSR generated (pkcs11 provider)"
        CSR_CREATED=true
    else
        warn "pkcs11 provider failed"
    fi
fi

# --- Method 2: OpenSSL pkcs11 engine (legacy method) ---
if [[ "$CSR_CREATED" != "true" ]]; then
    warn "Generating CSR — OpenSSL pkcs11 engine..."
    if TPM2_PKCS11_STORE="$PKCS11_STORE" \
       openssl req -new \
           -engine pkcs11 \
           -keyform engine \
           -key "$PKCS11_DEVICE_KEY_URI" \
           -subj "/CN=${SERIAL}" \
           -out /tmp/device-csr.pem 2>/dev/null; then
        info "CSR generated (pkcs11 engine)"
        CSR_CREATED=true
    else
        warn "pkcs11 engine failed"
    fi
fi

# --- Method 3: p11tool + openssl (last resort) ---
if [[ "$CSR_CREATED" != "true" ]] && command -v p11tool &>/dev/null; then
    warn "Generating CSR — p11tool + openssl..."

    # Export the public key
    if TPM2_PKCS11_STORE="$PKCS11_STORE" \
       p11tool --export-pubkey \
           "pkcs11:token=${TOKEN_LABEL};object=device-identity;type=public" \
           --login --set-pin="${USER_PIN}" \
           --outfile /tmp/device-pubkey.pem 2>/dev/null; then

        # Generate the CSR with p11tool
        if TPM2_PKCS11_STORE="$PKCS11_STORE" \
           p11tool --generate-csr \
               "pkcs11:token=${TOKEN_LABEL};object=device-identity;type=private" \
               --login --set-pin="${USER_PIN}" \
               --outfile /tmp/device-csr.pem 2>/dev/null; then
            info "CSR generated (p11tool)"
            CSR_CREATED=true
        fi
    fi
fi

if [[ "$CSR_CREATED" != "true" ]]; then
    err "Failed to generate CSR! All methods failed."
    err ""
    err "Manual attempt:"
    err "  export TPM2_PKCS11_STORE=${PKCS11_STORE}"
    err "  export OPENSSL_CONF=${OPENSSL_PKCS11_CNF}"
    err "  openssl req -new -key '${PKCS11_DEVICE_KEY_URI}' -subj '/CN=${SERIAL}' -out /tmp/test.csr"
    err ""
    err "Required packages:"
    err "  sudo apt install pkcs11-provider opensc gnutls-bin"
    exit 1
fi

# --- Public key hash ---
warn "Computing the public key SHA256 hash..."

PUBKEY_SHA256=""

# Export the public key with pkcs11-tool and hash it (most reliable method)
if TPM2_PKCS11_STORE="$PKCS11_STORE" \
   pkcs11-tool \
       --module "$PKCS11_MODULE" \
       --token-label "$TOKEN_LABEL" \
       --pin "$USER_PIN" \
       --read-object --type pubkey \
       --label "device-identity" \
       --output-file /tmp/device-pubkey.der 2>/dev/null; then
    PUBKEY_SHA256=$(openssl dgst -sha256 -hex /tmp/device-pubkey.der | awk '{print $NF}')
    info "Public key hash (pkcs11-tool): ${PUBKEY_SHA256}"
fi

# Fallback: with openssl
if [[ -z "$PUBKEY_SHA256" ]]; then
    PKCS11_DEVICE_PUBKEY_URI="pkcs11:token=${TOKEN_LABEL};object=device-identity;type=public;pin-value=${USER_PIN}"

    if [[ -n "$PKCS11_PROVIDER_SO" ]]; then
        PUBKEY_SHA256=$(TPM2_PKCS11_STORE="$PKCS11_STORE" \
            OPENSSL_CONF="$OPENSSL_PKCS11_CNF" \
            openssl pkey \
                -in "$PKCS11_DEVICE_PUBKEY_URI" \
                -pubin -pubout -outform DER 2>/dev/null \
            | openssl dgst -sha256 -hex | awk '{print $NF}' || true)
    fi
fi

if [[ -z "$PUBKEY_SHA256" ]]; then
    err "Failed to compute the public key hash!"
    exit 1
fi

info "Public key SHA256: ${PUBKEY_SHA256}"

###############################################################################
# 8. Register with the Registration Server
###############################################################################
step "8/8 — Factory Registration"

warn "Registering with the registration server: ${REG_SERVER}/register"

HTTP_CODE=$(curl -s -o /tmp/reg-response.json -w "%{http_code}" \
    -X POST "${REG_SERVER}/register" \
    -H "Content-Type: application/json" \
    -d "{\"serial_number\":\"${SERIAL}\",\"pubkey_sha256\":\"${PUBKEY_SHA256}\"}")

REG_RESPONSE=$(cat /tmp/reg-response.json)

case "$HTTP_CODE" in
    201)
        info "Registration successful: ${SERIAL}"
        ;;
    200)
        info "Device is already registered (same key): ${SERIAL}"
        ;;
    409)
        err "This serial number is registered with a different key!"
        err "Response: ${REG_RESPONSE}"
        exit 1
        ;;
    *)
        err "Registration failed (HTTP ${HTTP_CODE})"
        err "Response: ${REG_RESPONSE}"
        exit 1
        ;;
esac

###############################################################################
# Save the config file
###############################################################################
CONFIG_FILE="./tpm_config.env"
cat > "$CONFIG_FILE" <<EOF
# TPM Config — generated by tpm_device_setup.sh
# Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

SERIAL_NUMBER=${SERIAL}
PUBKEY_SHA256=${PUBKEY_SHA256}
TOKEN_LABEL=${TOKEN_LABEL}
USER_PIN=${USER_PIN}

# PKCS#11 URIs
CLAIM_KEY_URI=pkcs11:token=${TOKEN_LABEL};object=claim-key;type=private;pin-value=${USER_PIN}
CLAIM_CERT_URI=pkcs11:token=${TOKEN_LABEL};object=claim-cert;type=cert
DEVICE_KEY_URI=pkcs11:token=${TOKEN_LABEL};object=device-identity;type=private;pin-value=${USER_PIN}
DEVICE_PUBKEY_URI=pkcs11:token=${TOKEN_LABEL};object=device-identity;type=public;pin-value=${USER_PIN}

# CSR (for provisioning)
CSR_FILE=/tmp/device-csr.pem
EOF

info "Config saved: ${CONFIG_FILE}"

###############################################################################
# Summary
###############################################################################
step "TPM Setup Complete!"
echo ""
echo -e "  ${BOLD}TPM Token:${NC} ${TOKEN_LABEL}"
echo -e "  ${BOLD}Objects:${NC}"
echo -e "    claim-key        (RSA, imported)"
echo -e "    claim-cert       (X.509)"
echo -e "    device-identity  (ECC256, TPM-generated, unique)"
echo ""
echo -e "  ${BOLD}Device:${NC}"
echo -e "    Serial:          ${SERIAL}"
echo -e "    PubKey SHA256:   ${PUBKEY_SHA256}"
echo ""
echo -e "  ${BOLD}Next Steps:${NC}"
echo -e "    1. ${YELLOW}sudo ./install_greengrass.sh${NC}"
echo -e "    2. ${YELLOW}sudo ./provision_device.py${NC}"
echo ""

# Verify the TPM contents
echo -e "  ${BOLD}Verification:${NC}"
echo -e "    ${YELLOW}pkcs11-tool --module "$PKCS11_MODULE" \\"
echo -e "      --token-label ${TOKEN_LABEL} --pin ${USER_PIN} --list-objects${NC}"
echo ""
