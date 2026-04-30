#!/usr/bin/env bash
set -euo pipefail

SRC_FILE="cowrie-logrotate.conf"
DEST_FILE="/etc/logrotate.d/cowrie"

if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] This script must be run as root."
    echo "    Try: sudo ./install_logrotate.sh"
    exit 1
fi

if [[ ! -f "${SRC_FILE}" ]]; then
    echo "[!] Missing ${SRC_FILE} in current directory."
    exit 1
fi

cp "${SRC_FILE}" "${DEST_FILE}"
chmod 644 "${DEST_FILE}"

echo "[*] Installed logrotate config to ${DEST_FILE}"
echo "[*] Testing configuration with logrotate --debug"
logrotate --debug "${DEST_FILE}"

echo "[*] Logrotate configuration installed and verified."
