#!/bin/bash
# Simple OpenRC installation script for WAN IP Updater

set -e

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

echo "Installing WAN IP Updater as OpenRC service..."

# Create config directory
mkdir -p /etc/wan-ip-updater

# Copy files
cp wan-ip-updater /etc/init.d/
chmod +x /etc/init.d/wan-ip-updater

# Copy config
if [ ! -f /etc/wan-ip-updater/wan-ip-updater.conf ]; then
    cp wan-ip-updater.conf /etc/wan-ip-updater/
    chmod 600 /etc/wan-ip-updater/wan-ip-updater.conf
fi

# Create log files
touch /var/log/wan-ip-updater.log
touch /var/log/wan-ip-updater-error.log

echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Edit config: nano /etc/wan-ip-updater/wan-ip-updater.conf"
echo "2. Start service: rc-service wan-ip-updater start"
echo "3. Enable on boot: rc-update add wan-ip-updater default"
