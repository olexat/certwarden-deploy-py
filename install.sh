#!/bin/bash
#
# Installation script for certwarden-deploy.py
# For Debian 12
#

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing CertWarden Deploy..."
echo "=================================================="
echo ""

# Update package list
echo "Updating package list..."
sudo apt update

# Install required packages
echo ""
echo "Installing Python 3 and required libraries..."
sudo apt install -y python3 python3-requests python3-yaml

# Install the script
echo ""
echo "Installing certwarden-deploy.py to /usr/local/bin..."
sudo cp "$SCRIPT_DIR/certwarden-deploy.py" /usr/local/bin/certwarden-deploy.py
sudo chmod +x /usr/local/bin/certwarden-deploy.py

# Create config directory
echo "Creating config directory /etc/certwarden-deploy..."
sudo mkdir -p /etc/certwarden-deploy

# Install config file (if it doesn't already exist)
if [ -f "$SCRIPT_DIR/config.yaml" ]; then
    if [ -f /etc/certwarden-deploy/config.yaml ]; then
        echo "Config file already exists at /etc/certwarden-deploy/config.yaml (skipping)"
    else
        echo "Installing config.yaml to /etc/certwarden-deploy..."
        sudo cp "$SCRIPT_DIR/config.yaml" /etc/certwarden-deploy/config.yaml
        echo "IMPORTANT: Edit /etc/certwarden-deploy/config.yaml with your API keys and certificate IDs"
    fi
else
    echo "Warning: config.yaml not found in $SCRIPT_DIR"
fi

# Install systemd service file
echo ""
echo "Installing systemd service file..."
sudo cp "$SCRIPT_DIR/certwarden-deploy.service" /etc/systemd/system/certwarden-deploy.service

# Install systemd timer file
echo "Installing systemd timer file..."
sudo cp "$SCRIPT_DIR/certwarden-deploy.timer" /etc/systemd/system/certwarden-deploy.timer

# Reload systemd
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable the timer
echo "Enabling certwarden-deploy.timer..."
sudo systemctl enable certwarden-deploy.timer

# Start the timer
echo "Starting certwarden-deploy.timer..."
sudo systemctl start certwarden-deploy.timer

echo ""
echo "=================================================="
echo "Installation complete!"
echo ""
echo "Installed components:"
echo "  - Script: /usr/local/bin/certwarden-deploy.py"
echo "  - Config: /etc/certwarden-deploy/config.yaml"
echo "  - Service: /etc/systemd/system/certwarden-deploy.service"
echo "  - Timer: /etc/systemd/system/certwarden-deploy.timer"
echo ""
echo "Timer status:"
sudo systemctl status certwarden-deploy.timer --no-pager || true
echo ""
echo "Next scheduled run:"
sudo systemctl list-timers certwarden-deploy.timer --no-pager || true
echo ""
echo "NEXT STEPS:"
echo "  1. Edit /etc/certwarden-deploy/config.yaml with your API keys"
echo "  2. Test manually: sudo /usr/local/bin/certwarden-deploy.py --config /etc/certwarden-deploy/config.yaml process"
echo "  3. Check logs: sudo journalctl -u certwarden-deploy.service"
