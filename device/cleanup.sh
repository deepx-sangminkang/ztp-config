#!/usr/bin/env bash
#
# cleanup.sh — ZTP PoC Full Reset
#
# Cleans up AWS resources and device state.
# Options:
#   --aws       AWS resources only
#   --device    Device only (TPM, Greengrass, PKCS#11)
#   --all       Both (default)
#
# Usage:
#   ./cleanup.sh [--aws | --device | --all] [--region REGION] [--prefix PREFIX]
#
set -euo pipefail

###############################################################################
# Defaults
###############################################################################
REGION="us-east-1"
PREFIX="ZTP-PoC"
CONFIG_DIR="./ztp-config"
MODE="all"  # aws | device | all

while [[ $# -gt 0 ]]; do
    case "$1" in
        --aws)        MODE="aws";      shift ;;
        --device)     MODE="device";   shift ;;
        --all)        MODE="all";      shift ;;
        --region)     REGION="$2";     shift 2 ;;
        --prefix)     PREFIX="$2";     shift 2 ;;
        --config-dir) CONFIG_DIR="$2"; shift 2 ;;
        -h|--help)    head -14 "$0" | tail -11; exit 0 ;;
        *)            echo "Unknown argument: $1"; exit 1 ;;
    esac
done

###############################################################################
# Naming
###############################################################################
THING_GROUP="${PREFIX}-GreengrassCoreDevices"
TES_ROLE="${PREFIX}-GreengrassTESRole"
TES_ROLE_ALIAS="${PREFIX}-GreengrassTESRoleAlias"
FP_TEMPLATE="${PREFIX}-GreengrassFleetTemplate"
FP_PROVISION_ROLE="${PREFIX}-FleetProvisioningRole"
CLAIM_POLICY="${PREFIX}-ClaimPolicy"
DEVICE_POLICY="${PREFIX}-DevicePolicy"
DYNAMODB_TABLE="${PREFIX}-DeviceRegistry"
LAMBDA_NAME="${PREFIX}-PreProvisioningHook"
LAMBDA_ROLE="${PREFIX}-LambdaPreProvHookRole"

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
skip()  { echo -e "    ${YELLOW}skip${NC}: $*"; }

safe_delete() {
    # $1: description, $2+: command
    local desc="$1"; shift
    if "$@" 2>/dev/null; then
        info "$desc"
    else
        skip "$desc (missing or already deleted)"
    fi
}

###############################################################################
# CONFIRMATION
###############################################################################
echo ""
echo -e "${RED}${BOLD}⚠  WARNING: This script cannot be undone!${NC}"
echo ""
echo -e "  Mode:   ${BOLD}${MODE}${NC}"
echo -e "  Region: ${REGION}"
echo -e "  Prefix: ${PREFIX}"
echo ""

if [[ "$MODE" == "all" || "$MODE" == "aws" ]]; then
    echo "  To be deleted in AWS:"
    echo "    - Fleet Provisioning Template: ${FP_TEMPLATE}"
    echo "    - All Things in the Thing Group and their certificates"
    echo "    - IoT Policies: ${DEVICE_POLICY}, ${CLAIM_POLICY}"
    echo "    - Claim certificate"
    echo "    - IAM Roles: ${TES_ROLE}, ${FP_PROVISION_ROLE}, ${LAMBDA_ROLE}"
    echo "    - Role Alias: ${TES_ROLE_ALIAS}"
    echo "    - Lambda: ${LAMBDA_NAME}"
    echo "    - DynamoDB: ${DYNAMODB_TABLE}"
fi
if [[ "$MODE" == "all" || "$MODE" == "device" ]]; then
    echo "  To be deleted on the device:"
    echo "    - Greengrass Lite (dpkg purge)"
    echo "    - /var/lib/greengrass/"
    echo "    - PKCS#11 store (~/.tpm2_pkcs11, /home/ggcore/.tpm2_pkcs11, /etc/tpm2_pkcs11)"
    echo "    - systemd overrides"
fi
echo ""
read -rp "Do you want to continue? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Cancelled."
    exit 0
fi

###############################################################################
# AWS CLEANUP
###############################################################################
if [[ "$MODE" == "all" || "$MODE" == "aws" ]]; then

    step "AWS — Clean Up Things"

    # Find and delete the things in the Thing Group
    THINGS=$(aws iot list-things-in-thing-group \
        --thing-group-name "$THING_GROUP" \
        --region "$REGION" \
        --query 'things[]' --output text 2>/dev/null || true)

    if [[ -n "$THINGS" ]]; then
        for thing in $THINGS; do
            warn "Deleting thing: ${thing}"

            # Find the principals (certs) attached to the thing
            PRINCIPALS=$(aws iot list-thing-principals \
                --thing-name "$thing" \
                --region "$REGION" \
                --query 'principals[]' --output text 2>/dev/null || true)

            for principal in $PRINCIPALS; do
                CERT_ID=$(echo "$principal" | grep -oP '[a-f0-9]{64}' || true)
                if [[ -n "$CERT_ID" ]]; then
                    # Detach the policies from the cert
                    POLICIES=$(aws iot list-attached-policies \
                        --target "$principal" \
                        --region "$REGION" \
                        --query 'policies[].policyName' --output text 2>/dev/null || true)
                    for pol in $POLICIES; do
                        aws iot detach-policy \
                            --policy-name "$pol" \
                            --target "$principal" \
                            --region "$REGION" 2>/dev/null || true
                    done

                    # Detach the cert from the thing
                    aws iot detach-thing-principal \
                        --thing-name "$thing" \
                        --principal "$principal" \
                        --region "$REGION" 2>/dev/null || true

                    # Deactivate and delete the cert
                    aws iot update-certificate \
                        --certificate-id "$CERT_ID" \
                        --new-status INACTIVE \
                        --region "$REGION" 2>/dev/null || true
                    aws iot delete-certificate \
                        --certificate-id "$CERT_ID" \
                        --force-delete \
                        --region "$REGION" 2>/dev/null || true
                    info "  Certificate deleted: ${CERT_ID:0:12}..."
                fi
            done

            # Remove the thing from the group
            aws iot remove-thing-from-thing-group \
                --thing-group-name "$THING_GROUP" \
                --thing-name "$thing" \
                --region "$REGION" 2>/dev/null || true

            # Delete the thing
            aws iot delete-thing \
                --thing-name "$thing" \
                --region "$REGION" 2>/dev/null || true
            info "  Thing deleted: ${thing}"
        done
    else
        skip "Thing Group is empty or does not exist"
    fi

    step "AWS — Clean Up Claim Certificate"

    CLAIM_ARN_FILE="${CONFIG_DIR}/claim-certs/claim-cert-arn.txt"
    if [[ -f "$CLAIM_ARN_FILE" ]]; then
        CLAIM_CERT_ARN=$(cat "$CLAIM_ARN_FILE")
        CLAIM_CERT_ID=$(cat "${CONFIG_DIR}/claim-certs/claim-cert-id.txt" 2>/dev/null || echo "")

        # Detach the policies
        aws iot detach-policy \
            --policy-name "$CLAIM_POLICY" \
            --target "$CLAIM_CERT_ARN" \
            --region "$REGION" 2>/dev/null || true

        if [[ -n "$CLAIM_CERT_ID" ]]; then
            aws iot update-certificate \
                --certificate-id "$CLAIM_CERT_ID" \
                --new-status INACTIVE \
                --region "$REGION" 2>/dev/null || true
            aws iot delete-certificate \
                --certificate-id "$CLAIM_CERT_ID" \
                --force-delete \
                --region "$REGION" 2>/dev/null || true
            info "Claim certificate deleted: ${CLAIM_CERT_ID:0:12}..."
        fi
    else
        skip "Claim cert ARN file does not exist"
    fi

    step "AWS — IoT Policies"

    for pol in "$DEVICE_POLICY" "$CLAIM_POLICY"; do
        # First delete all versions (except the default)
        OLD_VERSIONS=$(aws iot list-policy-versions \
            --policy-name "$pol" \
            --region "$REGION" \
            --query 'policyVersions[?isDefaultVersion==`false`].versionId' --output text 2>/dev/null || true)
        for ver in $OLD_VERSIONS; do
            aws iot delete-policy-version \
                --policy-name "$pol" \
                --policy-version-id "$ver" \
                --region "$REGION" 2>/dev/null || true
        done

        # Detach any attached targets
        TARGETS=$(aws iot list-targets-for-policy \
            --policy-name "$pol" \
            --region "$REGION" \
            --query 'targets[]' --output text 2>/dev/null || true)
        for target in $TARGETS; do
            aws iot detach-policy \
                --policy-name "$pol" \
                --target "$target" \
                --region "$REGION" 2>/dev/null || true
        done

        safe_delete "IoT Policy: ${pol}" \
            aws iot delete-policy --policy-name "$pol" --region "$REGION"
    done

    step "AWS — Fleet Provisioning Template"

    # Remove the hook (if any)
    aws iot update-provisioning-template \
        --template-name "$FP_TEMPLATE" \
        --remove-pre-provisioning-hook \
        --region "$REGION" 2>/dev/null || true

    safe_delete "FP Template: ${FP_TEMPLATE}" \
        aws iot delete-provisioning-template --template-name "$FP_TEMPLATE" --region "$REGION"

    step "AWS — Thing Group"

    safe_delete "Thing Group: ${THING_GROUP}" \
        aws iot delete-thing-group --thing-group-name "$THING_GROUP" --region "$REGION"

    step "AWS — Role Alias"

    safe_delete "Role Alias: ${TES_ROLE_ALIAS}" \
        aws iot delete-role-alias --role-alias "$TES_ROLE_ALIAS" --region "$REGION"

    step "AWS — IAM Roles"

    for role in "$TES_ROLE" "$FP_PROVISION_ROLE" "$LAMBDA_ROLE"; do
        # Delete the inline policies
        POLICIES=$(aws iam list-role-policies \
            --role-name "$role" \
            --query 'PolicyNames[]' --output text 2>/dev/null || true)
        for pol in $POLICIES; do
            aws iam delete-role-policy \
                --role-name "$role" \
                --policy-name "$pol" 2>/dev/null || true
        done
        safe_delete "IAM Role: ${role}" \
            aws iam delete-role --role-name "$role"
    done

    step "AWS — Lambda"

    safe_delete "Lambda: ${LAMBDA_NAME}" \
        aws lambda delete-function --function-name "$LAMBDA_NAME" --region "$REGION"

    step "AWS — DynamoDB"

    safe_delete "DynamoDB: ${DYNAMODB_TABLE}" \
        aws dynamodb delete-table --table-name "$DYNAMODB_TABLE" --region "$REGION"

    step "AWS — Local Config Files"

    if [[ -d "$CONFIG_DIR" ]]; then
        rm -rf "$CONFIG_DIR"
        info "Config directory deleted: ${CONFIG_DIR}"
    else
        skip "Config directory does not exist: ${CONFIG_DIR}"
    fi

    info "AWS cleanup complete"
fi

###############################################################################
# DEVICE CLEANUP
###############################################################################
if [[ "$MODE" == "all" || "$MODE" == "device" ]]; then

    # Root check
    if [[ $EUID -ne 0 ]]; then
        err "sudo is required for device cleanup: sudo ./cleanup.sh --device"
        exit 1
    fi

    step "Device — Stop Greengrass"

    systemctl stop greengrass-lite.target 2>/dev/null || true
    info "Greengrass stopped"

    step "Device — systemd Overrides"

    for svc_dir in /etc/systemd/system/ggl.*.service.d; do
        if [[ -d "$svc_dir" ]]; then
            rm -rf "$svc_dir"
            info "Override deleted: $(basename "$svc_dir")"
        fi
    done
    systemctl daemon-reload 2>/dev/null || true

    step "Device — Remove Greengrass"

    GG_PKG=$(dpkg -l 2>/dev/null | grep -iE "greengrass.*(lite|nucleus-lite)" | awk '{print $2}' || true)
    if [[ -n "$GG_PKG" ]]; then
        dpkg --purge "$GG_PKG" 2>/dev/null || true
        info "Greengrass package removed: ${GG_PKG}"
    else
        skip "Greengrass package is not installed"
    fi

    step "Device — Greengrass Directories"

    for dir in /var/lib/greengrass /etc/greengrass /var/log/greengrass; do
        if [[ -d "$dir" ]]; then
            rm -rf "$dir"
            info "Deleted: ${dir}"
        fi
    done

    step "Device — PKCS#11 Store"

    # Which user's store is it
    DEVICE_USER="${SUDO_USER:-$(logname 2>/dev/null || echo '')}"
    DEVICE_HOME=$(eval echo "~${DEVICE_USER}" 2>/dev/null || echo "/home/${DEVICE_USER}")

    for store in \
        "${DEVICE_HOME}/.tpm2_pkcs11" \
        "/home/ggcore/.tpm2_pkcs11" \
        "/etc/tpm2_pkcs11"; do
        if [[ -d "$store" ]]; then
            rm -rf "$store"
            info "PKCS#11 store deleted: ${store}"
        fi
    done

    step "Device — Clear TPM Persistent Handles"

    # List and clear the persistent handles on the TPM
    if command -v tpm2_getcap &>/dev/null; then
        HANDLES=$(tpm2_getcap handles-persistent 2>/dev/null | grep -oP '0x[0-9A-Fa-f]+' || true)
        if [[ -n "$HANDLES" ]]; then
            for handle in $HANDLES; do
                tpm2_evictcontrol -c "$handle" 2>/dev/null || true
                info "TPM handle cleared: ${handle}"
            done
        else
            skip "No persistent handles on the TPM"
        fi
    else
        skip "tpm2_getcap not found"
    fi

    step "Device — Temporary Files"

    rm -f /tmp/device-*.pem /tmp/device-*.der /tmp/claim-cert*.der \
          /tmp/claim-cert-export.* /tmp/greengrass-lite.deb \
          /tmp/lambda-hook-*.zip /tmp/reg-response.json \
          /tmp/device-pubkey-hash.txt 2>/dev/null || true
    rm -rf /tmp/greengrass-lite-deb 2>/dev/null || true

    # tpm_config.env and local config files
    rm -f ./tpm_config.env 2>/dev/null || true

    info "Temporary files cleared"

    step "Device — OpenSSL PKCS#11 Config"

    OPENSSL_CNF="/etc/ssl/openssl.cnf"
    BACKUP=$(ls -t "${OPENSSL_CNF}.bak."* 2>/dev/null | head -1 || true)
    if [[ -n "$BACKUP" ]]; then
        warn "Restoring openssl.cnf from backup: ${BACKUP}"
        cp "$BACKUP" "$OPENSSL_CNF"
        info "openssl.cnf restored"
    else
        skip "No openssl.cnf backup found (manual editing may be required)"
    fi

    info "Device cleanup complete"
fi

###############################################################################
# Summary
###############################################################################
step "Reset Complete!"
echo ""
echo -e "  ${BOLD}Order to restart:${NC}"
echo ""
echo -e "  ${YELLOW}# 1. On the developer PC:${NC}"
echo -e "     ./aws-setup.sh"
echo -e "     ./deploy_lambda_hook.sh"
echo -e "     python3 registration_server.py --port 5000"
echo ""
echo -e "  ${YELLOW}# 2. Copy the config files to the device:${NC}"
echo -e "     scp -r ztp-config/ USER@DEVICE:~/"
echo -e "     scp tpm_device_setup.sh provision_device.py install_greengrass.sh USER@DEVICE:~/"
echo ""
echo -e "  ${YELLOW}# 3. On the device (normal user):${NC}"
echo -e "     ./tpm_device_setup.sh --server http://DEV_IP:5000 \\"
echo -e "         --claim-cert ~/ztp-config/claim-certs/claim.pem.crt \\"
echo -e "         --claim-key ~/ztp-config/claim-certs/claim.private.pem.key"
echo ""
echo -e "  ${YELLOW}# 4. On the device (sudo):${NC}"
echo -e "     sudo ./install_greengrass.sh --config-dir ~/ztp-config"
echo -e "     sudo \$(which python3) provision_device.py"
echo -e "     sudo systemctl restart greengrass-lite.target"
echo ""
