# OpenRC Service Setup

Quick setup for running WAN IP Updater as a Gentoo OpenRC service.

## Installation

```bash
# Run the installer (as root)
./install-openrc.sh

# Or manual install
sudo cp wan-ip-updater /etc/init.d/
sudo chmod +x /etc/init.d/wan-ip-updater
sudo mkdir -p /etc/wan-ip-updater
sudo cp wan-ip-updater.conf /etc/wan-ip-updater/
sudo chmod 600 /etc/wan-ip-updater/wan-ip-updater.conf
```

## Configuration

Edit the config file with your credentials:

```bash
sudo nano /etc/wan-ip-updater/wan-ip-updater.conf
```

Required settings:
- `ROUTER_PASSWORD` - Your router password
- `CLOUDFLARE_API_TOKEN` - Cloudflare API token
- `DNS_RECORDS` - Domains to update (comma separated)

## Service Commands

```bash
# Start service
rc-service wan-ip-updater start

# Stop service
rc-service wan-ip-updater stop

# Restart service
rc-service wan-ip-updater restart

# Check status
rc-service wan-ip-updater status

# Enable on boot
rc-update add wan-ip-updater default

# Disable on boot
rc-update del wan-ip-updater default
```

## Logs

```bash
# View output log
tail -f /var/log/wan-ip-updater.log

# View error log
tail -f /var/log/wan-ip-updater-error.log
```

## Troubleshooting

Service won't start:
```bash
# Check logs
cat /var/log/wan-ip-updater-error.log

# Test manually
cd /root/get-wan-ip
source /etc/wan-ip-updater/wan-ip-updater.conf
uv run main.py
```

Verify uv is installed:
```bash
which uv
```

If missing, install it:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```
