#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="morph-flask.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_FILE="$SCRIPT_DIR/$SERVICE_NAME"
TARGET_DIR="/etc/systemd/system"
TARGET_FILE="$TARGET_DIR/$SERVICE_NAME"

if [[ ! -f "$SOURCE_FILE" ]]; then
  echo "Error: service file not found at $SOURCE_FILE"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "Error: run this script as root (example: sudo ./install_flask_service.sh)"
  exit 1
fi

echo "Copying $SERVICE_NAME to $TARGET_DIR"
cp "$SOURCE_FILE" "$TARGET_FILE"

echo "Reloading systemd units"
systemctl daemon-reload

echo "Enabling morph-flask"
systemctl enable morph-flask

echo "Starting morph-flask"
systemctl start morph-flask

echo "Service status:"
systemctl status morph-flask --no-pager

echo "morph-flask service installation complete."
