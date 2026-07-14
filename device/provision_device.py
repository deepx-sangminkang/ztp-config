#!/usr/bin/env python3
"""
provision_device.py — ZTP PoC Custom Fleet Provisioning

Replaces Greengrass Lite's fleet-provisioning binary.
Talks directly to AWS IoT Core's fleet provisioning MQTT API.
Accesses the keys on the TPM via PKCS#11.

Usage:
    sudo ./provision_device.py --config /path/to/device_config.env

    or with all parameters:

    sudo ./provision_device.py \\
        --endpoint a3eybq...-ats.iot.us-east-1.amazonaws.com \\
        --template ZTP-PoC-GreengrassFleetTemplate \\
        --root-ca /var/lib/greengrass/credentials/AmazonRootCA1.pem \\
        --claim-cert "pkcs11:token=greengrass;object=claim-cert" \\
        --claim-key "pkcs11:token=greengrass;object=claim-key;pin-value=1234" \\
        --device-key "pkcs11:token=greengrass;object=device-identity;pin-value=1234" \\
        --thing-name 8a0ca6d0f69264a1

Requirements:
    pip install awsiotsdk cryptography

Flow:
    1. MQTT TLS connection using claim cert+key (PKCS#11)
    2. Generate a CSR with the device identity key
    3. Publish the CSR to $aws/certificates/create-from-csr/json
    4. Obtain the certificate ownership token
    5. Call the provisioning template (ThingName = serial)
    6. Write the certificate returned by AWS to the TPM
    7. Generate the Greengrass config.yaml
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# aws-iot-device-sdk-v2
# ---------------------------------------------------------------------------
try:
    from awscrt import io, mqtt
    from awsiot import mqtt_connection_builder
except ImportError as e:
    print(f"ERROR: failed to import aws-iot-device-sdk-v2: {e}")
    print(f"  Python: {sys.executable}")
    print(f"  pip install awsiotsdk")
    print()
    print("  If you are running with sudo, use the venv's Python:")
    print(f"    sudo {sys.executable} provision_device.py")
    print("  or:")
    print("    sudo $(which python3) provision_device.py")
    sys.exit(1)

# Pkcs11Lib is optional — the script can also run without it (file-based cert)
try:
    from awscrt.pkcs11 import Pkcs11Lib
    HAS_PKCS11 = True
except ImportError:
    HAS_PKCS11 = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("provision_device")

# ---------------------------------------------------------------------------
# PKCS#11 Library Path
# ---------------------------------------------------------------------------
PKCS11_LIB_PATHS = [
    "/usr/lib/aarch64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
    "/usr/lib/arm-linux-gnueabihf/pkcs11/libtpm2_pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
    "/usr/lib/aarch64-linux-gnu/libtpm2_pkcs11.so",
    "/usr/lib/arm-linux-gnueabihf/libtpm2_pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so",
    "/usr/lib/libtpm2_pkcs11.so",
    "/usr/lib/pkcs11/libtpm2_pkcs11.so",
    "/usr/local/lib/libtpm2_pkcs11.so",
    # ATECC608 fallback
    "/usr/lib/libcryptoauth.so",
]

# ---------------------------------------------------------------------------
# MQTT Topics
# ---------------------------------------------------------------------------
CREATE_CERT_TOPIC = "$aws/certificates/create-from-csr/json"
CREATE_CERT_ACCEPTED = "$aws/certificates/create-from-csr/json/accepted"
CREATE_CERT_REJECTED = "$aws/certificates/create-from-csr/json/rejected"

PROVISION_TOPIC_TPL = "$aws/provisioning-templates/{}/provision/json"
PROVISION_ACCEPTED_TPL = "$aws/provisioning-templates/{}/provision/json/accepted"
PROVISION_REJECTED_TPL = "$aws/provisioning-templates/{}/provision/json/rejected"

# Greengrass config
GREENGRASS_ROOT = "/var/lib/greengrass"
# v2.5.1 reads merged YAML from /etc/greengrass/config.d/, NOT /var/lib/greengrass/config.yaml
GREENGRASS_CONFIG = "/etc/greengrass/config.d/ztp-provision.yaml"

# PKCS#11 store of the human user that ran tpm_device_setup.sh.
# When this script runs as root (sudo), $HOME is /root and pkcs11-tool/openssl
# would not find the token. Resolve back to the invoking user's home.
def _resolve_pkcs11_store() -> str:
    env_store = os.environ.get("TPM2_PKCS11_STORE")
    if env_store and os.path.isdir(env_store):
        return env_store
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        candidate = f"/home/{sudo_user}/.tpm2_pkcs11"
        if os.path.isdir(candidate):
            return candidate
    for candidate in ["/home/alpon/.tpm2_pkcs11", "/etc/tpm2_pkcs11"]:
        if os.path.isdir(candidate):
            return candidate
    logger.error("TPM2_PKCS11_STORE not found")
    sys.exit(1)


PKCS11_STORE = None  # initialized in main()


class FleetProvisioner:
    """Custom fleet provisioning — MQTT + PKCS#11."""

    def __init__(self, args):
        self.args = args
        self.connection = None
        self.cert_response = None
        self.provision_response = None
        self._cert_event = threading.Event()
        self._provision_event = threading.Event()

    def run(self):
        """Main provisioning flow."""
        logger.info("=== Fleet Provisioning Starting ===")
        logger.info("Thing name: %s", self.args.thing_name)
        logger.info("Template: %s", self.args.template)
        logger.info("Endpoint: %s", self.args.endpoint)

        # 1. Find the PKCS#11 library
        pkcs11_lib_path = self._find_pkcs11_lib()
        logger.info("PKCS#11 lib: %s", pkcs11_lib_path)

        # 2. Resolve the claim cert file path
        claim_cert_path = self._resolve_claim_cert()

        # 3. MQTT connection — using claim credentials
        logger.info("Establishing MQTT connection (claim credentials)...")

        if HAS_PKCS11:
            # PKCS#11 native — claim key is read from the TPM
            logger.info("Using native PKCS#11 connection")
            pkcs11_lib = Pkcs11Lib(
                file=pkcs11_lib_path,
                behavior=Pkcs11Lib.InitializeFinalizeBehavior.STRICT,
            )

            self.connection = mqtt_connection_builder.mtls_with_pkcs11(
                pkcs11_lib=pkcs11_lib,
                user_pin=self.args.pin,
                token_label=self.args.token_label,
                private_key_label=self.args.claim_key_label,
                cert_filepath=claim_cert_path,
                endpoint=self.args.endpoint,
                port=8883,
                ca_filepath=self.args.root_ca,
                client_id=f"provision-{self.args.thing_name}",
                clean_session=True,
            )
        else:
            # Fallback: file-based — claim key is read from a file
            # (the claim key is a shared key anyway, so it can live on disk)
            logger.info("Using file-based TLS connection (awscrt.pkcs11 not available)")
            claim_key_path = self._resolve_claim_key_file()

            self.connection = mqtt_connection_builder.mtls_from_path(
                cert_filepath=claim_cert_path,
                pri_key_filepath=claim_key_path,
                endpoint=self.args.endpoint,
                port=8883,
                ca_filepath=self.args.root_ca,
                client_id=f"provision-{self.args.thing_name}",
                clean_session=True,
            )

        connect_future = self.connection.connect()
        connect_future.result(timeout=30)
        logger.info("MQTT connection established")

        try:
            # 4. Subscribe — cert create
            self._subscribe_cert_topics()

            # 5. Generate CSR
            csr_pem = self._create_csr()

            # 6. Publish the CSR → get the certificate
            self._request_certificate(csr_pem)

            # 7. Subscribe — provisioning
            self._subscribe_provision_topics()

            # 8. Request provisioning
            self._request_provisioning()

            # 9. Write the certificate to the TPM
            self._store_certificate()

            # 10. Generate the Greengrass config
            self._write_greengrass_config()

            logger.info("=== Fleet Provisioning Complete ===")

        finally:
            disconnect_future = self.connection.disconnect()
            disconnect_future.result(timeout=10)
            logger.info("MQTT connection closed")

    # -----------------------------------------------------------------------
    # Find the PKCS#11 lib
    # -----------------------------------------------------------------------
    def _find_pkcs11_lib(self) -> str:
        if self.args.pkcs11_lib and os.path.isfile(self.args.pkcs11_lib):
            return self.args.pkcs11_lib

        for path in PKCS11_LIB_PATHS:
            if os.path.isfile(path):
                return path

        # Fallback: search with find
        try:
            result = subprocess.run(
                ["find", "/usr/lib", "/usr/local/lib", "-name", "libtpm2_pkcs11.so"],
                capture_output=True, text=True, timeout=5)
            found = result.stdout.strip().splitlines()
            if found:
                logger.info("PKCS#11 lib found via find: %s", found[0])
                return found[0]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        logger.error("PKCS#11 library not found!")
        logger.error("Known locations: %s", PKCS11_LIB_PATHS)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Claim cert — from PKCS#11 or from a file
    # -----------------------------------------------------------------------
    def _resolve_claim_cert(self) -> str:
        """
        Resolve the claim cert to a file path.
        aws-iot-device-sdk expects cert_filepath to be a file path,
        not a PKCS#11 URI. So we export the cert from the TPM and
        write it to a temporary file.
        """
        cert_path = self.args.claim_cert

        # Already a file path
        if os.path.isfile(cert_path):
            return cert_path

        # It's a PKCS#11 URI — export it with pkcs11-tool
        if cert_path.startswith("pkcs11:"):
            logger.info("Exporting claim cert from PKCS#11...")
            tmp_cert = "/tmp/claim-cert-export.pem"

            # Export as DER, then convert to PEM
            try:
                subprocess.run([
                    "pkcs11-tool",
                    "--module", self._find_pkcs11_lib(),
                    "--token-label", self.args.token_label,
                    "--pin", self.args.pin,
                    "--read-object",
                    "--type", "cert",
                    "--label", "claim-cert",
                    "--output-file", "/tmp/claim-cert-export.der",
                ], check=True, capture_output=True)

                subprocess.run([
                    "openssl", "x509",
                    "-inform", "DER",
                    "-in", "/tmp/claim-cert-export.der",
                    "-outform", "PEM",
                    "-out", tmp_cert,
                ], check=True, capture_output=True)

                return tmp_cert

            except subprocess.CalledProcessError as e:
                logger.error("Claim cert export failed: %s", e.stderr.decode())
                sys.exit(1)

        # Search in the credentials directory
        cred_dir = f"{GREENGRASS_ROOT}/credentials"
        for name in ["claim.pem.crt", "claim-cert.pem", "claim.crt"]:
            candidate = os.path.join(cred_dir, name)
            if os.path.isfile(candidate):
                return candidate

        logger.error("Claim cert not found: %s", cert_path)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Claim key — as a file (fallback when PKCS#11 is unavailable)
    # -----------------------------------------------------------------------
    def _resolve_claim_key_file(self) -> str:
        """Find the claim private key file (fallback when PKCS#11 is unavailable)."""
        cred_dir = f"{GREENGRASS_ROOT}/credentials"
        candidates = [
            os.path.join(cred_dir, "claim.private.pem.key"),
            os.path.join(cred_dir, "claim.key.pem"),
            "./ztp-config/claim-certs/claim.private.pem.key",
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                logger.info("Claim key file found: %s", candidate)
                return candidate

        logger.error("Claim key file not found!")
        logger.error("Without PKCS#11 support the claim key is required as a file.")
        logger.error("Locations searched: %s", candidates)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Generate CSR — using the device identity key
    # -----------------------------------------------------------------------
    def _create_csr(self) -> str:
        """Generate a CSR using the device-identity key on the TPM."""
        logger.info("Generating CSR (device-identity key, CN=%s)...",
                     self.args.thing_name)

        device_key_uri = (
            f"pkcs11:token={self.args.token_label};"
            f"object={self.args.device_key_label};"
            f"type=private;"
            f"pin-value={self.args.pin}"
        )

        csr_file = "/tmp/device-provision.csr.pem"

        # Try the OpenSSL provider first, fall back to the engine
        for method in ["provider", "engine"]:
            try:
                if method == "provider":
                    cmd = [
                        "openssl", "req", "-new",
                        "-provider", "tpm2",
                        "-provider", "default",
                        "-key", device_key_uri,
                        "-subj", f"/CN={self.args.thing_name}",
                        "-out", csr_file,
                    ]
                else:
                    cmd = [
                        "openssl", "req", "-new",
                        "-engine", "pkcs11",
                        "-keyform", "engine",
                        "-key", device_key_uri,
                        "-subj", f"/CN={self.args.thing_name}",
                        "-out", csr_file,
                    ]

                subprocess.run(cmd, check=True, capture_output=True)
                logger.info("CSR generated (%s method)", method)
                break

            except subprocess.CalledProcessError:
                if method == "engine":
                    logger.error("Failed to generate CSR (both provider and engine failed)")
                    sys.exit(1)
                continue

        with open(csr_file, "r") as f:
            return f.read()

    # -----------------------------------------------------------------------
    # Certificate creation (MQTT)
    # -----------------------------------------------------------------------
    def _subscribe_cert_topics(self):
        """Subscribe to the $aws/certificates/create-from-csr topics."""

        def on_accepted(topic, payload, **kwargs):
            self.cert_response = json.loads(payload)
            logger.info("Certificate created (certificateId: %s...)",
                        self.cert_response.get("certificateId", "?")[:12])
            self._cert_event.set()

        def on_rejected(topic, payload, **kwargs):
            error = json.loads(payload)
            logger.error("Certificate creation REJECTED: %s", error)
            self.cert_response = None
            self._cert_event.set()

        sub_accepted, _ = self.connection.subscribe(
            CREATE_CERT_ACCEPTED, mqtt.QoS.AT_LEAST_ONCE, on_accepted)
        sub_accepted.result(timeout=10)

        sub_rejected, _ = self.connection.subscribe(
            CREATE_CERT_REJECTED, mqtt.QoS.AT_LEAST_ONCE, on_rejected)
        sub_rejected.result(timeout=10)

        logger.info("Subscribed to cert topics")

    def _request_certificate(self, csr_pem: str):
        """Publish the CSR and wait for the certificate."""
        payload = json.dumps({"certificateSigningRequest": csr_pem})

        pub_future, _ = self.connection.publish(
            CREATE_CERT_TOPIC, payload, mqtt.QoS.AT_LEAST_ONCE)
        pub_future.result(timeout=10)
        logger.info("CSR published, waiting for certificate...")

        if not self._cert_event.wait(timeout=30):
            logger.error("Certificate response timed out (30s)")
            sys.exit(1)

        if self.cert_response is None:
            logger.error("Failed to create certificate")
            sys.exit(1)

    # -----------------------------------------------------------------------
    # Provisioning (MQTT)
    # -----------------------------------------------------------------------
    def _subscribe_provision_topics(self):
        """Subscribe to the provisioning template topics."""
        accepted_topic = PROVISION_ACCEPTED_TPL.format(self.args.template)
        rejected_topic = PROVISION_REJECTED_TPL.format(self.args.template)

        def on_accepted(topic, payload, **kwargs):
            self.provision_response = json.loads(payload)
            logger.info("Provisioning ACCEPTED — thingName: %s",
                        self.provision_response.get("thingName", "?"))
            self._provision_event.set()

        def on_rejected(topic, payload, **kwargs):
            error = json.loads(payload)
            logger.error("Provisioning REJECTED: %s", error)
            self.provision_response = None
            self._provision_event.set()

        sub_a, _ = self.connection.subscribe(
            accepted_topic, mqtt.QoS.AT_LEAST_ONCE, on_accepted)
        sub_a.result(timeout=10)

        sub_r, _ = self.connection.subscribe(
            rejected_topic, mqtt.QoS.AT_LEAST_ONCE, on_rejected)
        sub_r.result(timeout=10)

        logger.info("Subscribed to provisioning topics")

    def _request_provisioning(self):
        """Call the provisioning template."""
        provision_topic = PROVISION_TOPIC_TPL.format(self.args.template)

        payload = json.dumps({
            "certificateOwnershipToken": self.cert_response["certificateOwnershipToken"],
            "parameters": {
                "ThingName": self.args.thing_name,
            },
        })

        pub_future, _ = self.connection.publish(
            provision_topic, payload, mqtt.QoS.AT_LEAST_ONCE)
        pub_future.result(timeout=10)
        logger.info("Provisioning request sent, waiting for response...")

        if not self._provision_event.wait(timeout=30):
            logger.error("Provisioning response timed out (30s)")
            sys.exit(1)

        if self.provision_response is None:
            logger.error("Provisioning failed")
            sys.exit(1)

    # -----------------------------------------------------------------------
    # Write the certificate to the TPM
    # -----------------------------------------------------------------------
    def _store_certificate(self):
        """Write the certificate PEM returned by AWS to the TPM as device-cert."""
        cert_pem = self.cert_response["certificatePem"]

        # Write to a PEM file (temporary)
        pem_path = "/tmp/device-cert.pem"
        der_path = "/tmp/device-cert.der"

        with open(pem_path, "w") as f:
            f.write(cert_pem)

        # PEM → DER
        subprocess.run(
            ["openssl", "x509", "-in", pem_path, "-outform", "DER", "-out", der_path],
            check=True, capture_output=True,
        )

        # Environment — PKCS11_STORE must be passed explicitly to every
        # pkcs11-tool/openssl invocation (under sudo, $HOME=/root and the
        # store would not be found).
        tpm_env = {**os.environ, "TPM2_PKCS11_STORE": PKCS11_STORE}

        # Get the ID of the device identity key
        result = subprocess.run([
            "pkcs11-tool",
            "--module", self._find_pkcs11_lib(),
            "--token-label", self.args.token_label,
            "--pin", self.args.pin,
            "--list-objects", "--type", "privkey",
        ], capture_output=True, text=True, env=tpm_env)

        device_key_id = None
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            if self.args.device_key_label in line:
                for j in range(i, min(i + 5, len(lines))):
                    if "ID:" in lines[j]:
                        device_key_id = lines[j].split("ID:")[1].strip()
                        break
                break

        if not device_key_id:
            logger.error("Device key ID not found (store: %s)", PKCS11_STORE)
            sys.exit(1)

        logger.info("Device key ID: %s", device_key_id)

        # Delete any existing device-cert (idempotent)
        subprocess.run([
            "pkcs11-tool",
            "--module", self._find_pkcs11_lib(),
            "--token-label", self.args.token_label,
            "--pin", self.args.pin,
            "--delete-object", "--type", "cert",
            "--label", "device-cert",
        ], capture_output=True, env=tpm_env)

        # Write the DER cert to the TPM
        subprocess.run([
            "pkcs11-tool",
            "--module", self._find_pkcs11_lib(),
            "--token-label", self.args.token_label,
            "--pin", self.args.pin,
            "--write-object", der_path,
            "--type", "cert",
            "--label", "device-cert",
            "--id", device_key_id,
        ], check=True, capture_output=True, env=tpm_env)

        logger.info("Device cert written to TPM: device-cert (ID: %s)", device_key_id)

        # *** CRITICAL *** verify: iotcored reads the cert via OSSL_STORE.
        # --write-object can fail silently or write to the wrong store; we do
        # not proceed until we've actually confirmed it's readable via storeutl.
        cert_uri = (
            f"pkcs11:object=device-cert;type=cert;pin-value={self.args.pin}"
        )
        verify = subprocess.run(
            ["openssl", "storeutl", cert_uri],
            capture_output=True, text=True, env=tpm_env,
        )
        if "Total found: 0" in verify.stdout or "0:" not in verify.stdout:
            logger.error(
                "Cert was written to the PKCS#11 store but cannot be read back via OSSL_STORE!\n"
                "  store: %s\n  stdout: %s\n  stderr: %s",
                PKCS11_STORE, verify.stdout, verify.stderr,
            )
            sys.exit(1)
        logger.info("Cert verify OK — openssl storeutl '%s' can read it", cert_uri)

        # Sync the store to ggcore and the fallback /etc/tpm2_pkcs11.
        # Greengrass iotcored runs as ggcore; it reads its own store.
        ggcore_store = "/home/ggcore/.tpm2_pkcs11"
        if os.path.isdir("/home/ggcore"):
            subprocess.run(["rm", "-rf", ggcore_store], check=False)
            subprocess.run(["cp", "-a", PKCS11_STORE, ggcore_store], check=True)
            subprocess.run(["chown", "-R", "ggcore:ggcore", ggcore_store], check=True)
            logger.info("PKCS#11 store synced: %s", ggcore_store)

        etc_store = "/etc/tpm2_pkcs11"
        subprocess.run(["rm", "-rf", etc_store], check=False)
        subprocess.run(["cp", "-a", PKCS11_STORE, etc_store], check=True)
        subprocess.run(["chown", "-R", "ggcore:ggcore", etc_store], check=True)
        logger.info("PKCS#11 store synced: %s (fallback)", etc_store)

        # Also write a PEM copy to the credentials directory (backup)
        cred_dir = f"{GREENGRASS_ROOT}/credentials"
        os.makedirs(cred_dir, exist_ok=True)
        backup_path = os.path.join(cred_dir, "device-cert.pem")
        with open(backup_path, "w") as f:
            f.write(cert_pem)
        logger.info("Cert backup: %s", backup_path)

        # Cleanup
        for f in [pem_path, der_path]:
            try:
                os.remove(f)
            except OSError:
                pass

    # -----------------------------------------------------------------------
    # Greengrass config.yaml
    # -----------------------------------------------------------------------
    def _detect_pkcs11_slot(self) -> int:
        """Determine the slot ID the token lives on (for the Pkcs11Provider config)."""
        tpm_env = {**os.environ, "TPM2_PKCS11_STORE": PKCS11_STORE}
        try:
            result = subprocess.run(
                ["pkcs11-tool", "--module", self._find_pkcs11_lib(),
                 "--list-slots"],
                capture_output=True, text=True, env=tpm_env, timeout=10,
            )
            # "Slot 1 (0x1): ... token label : greengrass"
            current_slot = None
            for line in result.stdout.splitlines():
                m = line.strip()
                if m.startswith("Slot ") and "(" in m:
                    try:
                        current_slot = int(m.split()[1])
                    except (ValueError, IndexError):
                        current_slot = None
                if "token label" in m and self.args.token_label in m:
                    if current_slot is not None:
                        return current_slot
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return 1  # default for tpm2_pkcs11 on this device

    def _write_greengrass_config(self):
        """Create / update the Greengrass Lite config.yaml."""
        slot = self._detect_pkcs11_slot()
        pkcs11_lib = self._find_pkcs11_lib()

        config_content = f"""\
---
# Greengrass Lite config — generated by provision_device.py
# Thing: {self.args.thing_name}
# Date: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}

system:
  privateKeyPath: "pkcs11:object={self.args.device_key_label};type=private;pin-value={self.args.pin}"
  certificateFilePath: "pkcs11:object=device-cert;type=cert;pin-value={self.args.pin}"
  rootCaPath: "{self.args.root_ca}"
  rootPath: "{GREENGRASS_ROOT}"
  thingName: "{self.args.thing_name}"

services:
  aws.greengrass.NucleusLite:
    configuration:
      awsRegion: "{self.args.region}"
      iotRoleAlias: "{self.args.role_alias}"
      iotDataEndpoint: "{self.args.endpoint}"
      iotCredEndpoint: "{self.args.cred_endpoint}"

  aws.greengrass.crypto.Pkcs11Provider:
    configuration:
      library: "{pkcs11_lib}"
      slot: {slot}
      userPin: "{self.args.pin}"
"""

        os.makedirs(os.path.dirname(GREENGRASS_CONFIG), exist_ok=True)

        with open(GREENGRASS_CONFIG, "w") as f:
            f.write(config_content)

        logger.info("Greengrass config written: %s (slot %d)",
                    GREENGRASS_CONFIG, slot)


# ---------------------------------------------------------------------------
# Read parameters from the config file
# ---------------------------------------------------------------------------
def load_env_file(path: str) -> dict:
    """Parse a simple KEY=VALUE format."""
    env = {}
    if not os.path.isfile(path):
        return env
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip()
    return env


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="ZTP PoC Custom Fleet Provisioning (MQTT + PKCS#11)")

    parser.add_argument("--config", default=None,
                        help="device_config.env file (all parameters are read from it)")
    parser.add_argument("--tpm-config", default="./tpm_config.env",
                        help="tpm_config.env file (output of tpm_device_setup.sh)")

    # AWS parameters — can be overridden from the config file
    parser.add_argument("--endpoint", default=None, help="IoT Data-ATS endpoint")
    parser.add_argument("--cred-endpoint", default=None, help="IoT credential endpoint")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--template", default=None, help="Fleet provisioning template name")
    parser.add_argument("--role-alias", default=None, help="TES Role Alias")

    # Cert/Key parameters
    parser.add_argument("--root-ca", default=f"{GREENGRASS_ROOT}/credentials/AmazonRootCA1.pem")
    parser.add_argument("--claim-cert", default=None,
                        help="Claim cert file path or pkcs11: URI")
    parser.add_argument("--claim-key-label", default="claim-key",
                        help="Claim key PKCS#11 label")
    parser.add_argument("--device-key-label", default="device-identity",
                        help="Device identity key PKCS#11 label")

    # PKCS#11
    parser.add_argument("--token-label", default="greengrass", help="PKCS#11 token label")
    parser.add_argument("--pin", default="1234", help="PKCS#11 user PIN")
    parser.add_argument("--pkcs11-lib", default=None, help="PKCS#11 library path")

    # Device
    parser.add_argument("--thing-name", default=None, help="Thing name (= serial number)")

    args = parser.parse_args()

    # --- Fill in values from the config files ---
    device_config = {}
    tpm_config = {}

    if args.config:
        device_config = load_env_file(args.config)
    else:
        # Search default locations
        for candidate in ["./ztp-config/device_config.env",
                          "/etc/greengrass/device_config.env",
                          "./device_config.env"]:
            if os.path.isfile(candidate):
                device_config = load_env_file(candidate)
                logger.info("device_config.env found: %s", candidate)
                break

    if os.path.isfile(args.tpm_config):
        tpm_config = load_env_file(args.tpm_config)
        logger.info("tpm_config.env found: %s", args.tpm_config)

    # Merge: CLI > tpm_config > device_config
    args.endpoint = args.endpoint or device_config.get("IOT_ENDPOINT")
    args.cred_endpoint = args.cred_endpoint or device_config.get("IOT_CRED_ENDPOINT")
    args.region = args.region or device_config.get("AWS_REGION", "us-east-1")
    args.template = args.template or device_config.get("FP_TEMPLATE")
    args.role_alias = args.role_alias or device_config.get("TES_ROLE_ALIAS")
    args.thing_name = args.thing_name or tpm_config.get("SERIAL_NUMBER")
    args.token_label = args.token_label or tpm_config.get("TOKEN_LABEL", "greengrass")
    args.pin = args.pin or tpm_config.get("USER_PIN", "1234")

    # Claim cert — search the config directory or the credentials directory
    if not args.claim_cert:
        for candidate in [
            "./ztp-config/claim-certs/claim.pem.crt",
            f"{GREENGRASS_ROOT}/credentials/claim.pem.crt",
            "pkcs11:token=greengrass;object=claim-cert",
        ]:
            if candidate.startswith("pkcs11:") or os.path.isfile(candidate):
                args.claim_cert = candidate
                break

    # Required field checks
    missing = []
    if not args.endpoint:    missing.append("--endpoint / IOT_ENDPOINT")
    if not args.template:    missing.append("--template / FP_TEMPLATE")
    if not args.thing_name:  missing.append("--thing-name / SERIAL_NUMBER")
    if not args.role_alias:  missing.append("--role-alias / TES_ROLE_ALIAS")

    if missing:
        logger.error("Missing parameters: %s", ", ".join(missing))
        logger.error("Use a config file or provide them via the CLI.")
        sys.exit(1)

    return args


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Root check
    if os.geteuid() != 0:
        logger.error("This script requires root privileges.")
        logger.error("Usage: sudo %s provision_device.py [args]", sys.executable)
        sys.exit(1)

    global PKCS11_STORE
    PKCS11_STORE = _resolve_pkcs11_store()
    logger.info("TPM2_PKCS11_STORE = %s", PKCS11_STORE)
    # Pass it on to all child processes too
    os.environ["TPM2_PKCS11_STORE"] = PKCS11_STORE

    # PKCS#11 support check
    if not HAS_PKCS11:
        logger.warning("awscrt.pkcs11 not found — no native PKCS#11 support")
        logger.warning("The claim cert must be provided as a file; it cannot be read from the TPM")
        logger.warning("For PKCS#11 support: pip install awsiotsdk (requires the C extension)")

    args = parse_args()
    provisioner = FleetProvisioner(args)
    provisioner.run()

    print()
    print("  ✓ Fleet provisioning complete!")
    print(f"  ✓ Thing: {args.thing_name}")
    print(f"  ✓ Config: {GREENGRASS_CONFIG}")
    print()
    print("  Next step:")
    print("    sudo systemctl restart greengrass-lite.target")
    print()


if __name__ == "__main__":
    main()
