# get-wan-ip

A Python script that automatically retrieves your router's WAN IP address and updates Cloudflare DNS records with the current IP. Perfect for home servers, self-hosted services, and maintaining dynamic DNS entries.

## Features

- 🔌 **Router Integration**: Logs into your router and extracts the WAN IP address
- ☁️ **Cloudflare DNS Updates**: Automatically updates one or multiple DNS records
- 🔄 **Flexible Configuration**: Supports environment variables for easy setup
- 📋 **Multiple DNS Records**: Update several domains/subdomains in one run
- 🛡️ **SSL Support**: Works with self-signed certificates on routers
- 🎯 **Multiple Authentication Methods**: Supports Cloudflare API token or email + API key
- 📝 **Example Configurations**: Includes templates for easy setup

## Prerequisites

- Python 3.13 or higher
- Cloudflare account with a domain configured
- Router access with login credentials
- Cloudflare API token (recommended) or email + API key

## Installation

### 1. Clone or Download the Project

```bash
cd /root/get-wan-ip
```

### 2. Install Dependencies

Using `uv` (recommended):
```bash
uv sync
```

Using `pip`:
```bash
pip install cloudflare requests
```

### 3. Create Configuration File

Copy the example shell script:
```bash
cp run-updater.sh.example run-updater.sh
```

## Configuration

Configure the script by setting environment variables in `run-updater.sh` or export them directly.

### Router Configuration

```bash
export ROUTER_USERNAME="admin"
export ROUTER_PASSWORD="your_router_password"
export ROUTER_URL="https://192.168.1.1"
```

**Router URL**: Change to your router's IP address. Default is `https://192.168.1.1`

### Cloudflare Configuration

Choose one of the following methods:

**Method 1: API Token (Recommended)**
```bash
export CLOUDFLARE_API_TOKEN="your_api_token_here"
```

To create an API token:
1. Go to Cloudflare Dashboard → My Profile → API Tokens
2. Create a custom token with:
   - Zone - DNS - Edit permissions
   - Include your specific zone(s)

**Method 2: Email + API Key (Legacy)**
```bash
export CLOUDFLARE_EMAIL="your-email@example.com"
export CLOUDFLARE_API_KEY="your_api_key_here"
```

### DNS Records Configuration

**Option 1: Simple comma-separated domains**
```bash
export DNS_RECORDS="home.example.com,vpn.example.com"
```

**Option 2: JSON with advanced configuration**
```bash
export DNS_RECORDS='[{"domain": "home.example.com", "record_type": "A", "ttl": 300}, {"domain": "vpn.example.com", "record_type": "A", "ttl": 600}]'
```

## Usage

### Running the Script

Make the script executable:
```bash
chmod +x run-updater.sh
```

Run manually:
```bash
./run-updater.sh
```

Or run directly with Python:
```bash
cd /root/get-wan-ip
uv run main.py
```

### Setting Up Automatic Updates (Cron)

To run the script automatically (e.g., every 5 minutes):

1. Edit crontab:
```bash
crontab -e
```

2. Add the following line:
```bash
*/5 * * * * cd /root/get-wan-ip && ./run-updater.sh
```

3. Save and exit

## How It Works

1. **Router Login**: The script logs into your router using the provided credentials
2. **IP Extraction**: It attempts various parameter combinations to extract the WAN IP address from the router's device information
3. **Cloudflare Update**: If Cloudflare is configured, it updates the specified DNS records with the retrieved IP
4. **Status Reporting**: The script provides detailed progress information throughout the process

## Project Structure

```
get-wan-ip/
├── main.py                 # Main script with all functionality
├── run-updater.sh.example  # Example shell script for configuration
├── run-updater.sh          # Your configured shell script (create this)
├── pyproject.toml          # Project dependencies and metadata
├── .python-version         # Python version specification
└── .gitignore             # Git ignore patterns
```

## Key Components

### CloudflareManager
Manages Cloudflare API operations:
- Get zone ID for domains
- Retrieve existing DNS records
- Update DNS records with new IP addresses
- Handle multiple records simultaneously

### RouterClient
Handles router communication:
- Login/logout operations
- Device information retrieval
- WAN IP extraction from JSON responses
- Recursive search for IP addresses in nested structures

### Utility Functions
- `load_credentials()`: Loads and validates environment variables
- `parse_dns_records()`: Parses DNS records from JSON or comma-separated format
- `create_example_config()`: Generates example configuration files

## Troubleshooting

### Login Failed
- Verify your router username and password
- Check that the router URL is correct
- Ensure your router is accessible from the machine running the script

### Could Not Retrieve WAN IP
- The script tries multiple parameter combinations automatically
- If still failing, check your router's API documentation
- Ensure your router exposes device information via API

### Cloudflare Update Failed
- Verify your API token has DNS Edit permissions
- Check that the domain exists in your Cloudflare account
- Ensure the DNS record exists (or create it first in Cloudflare)

### Import Errors
- Install required dependencies: `pip install cloudflare requests`
- Ensure you're using Python 3.13 or higher

## Security Notes

- Never commit `run-updater.sh` to version control with actual credentials
- Use API tokens instead of email + API key when possible
- Keep your API tokens and passwords secure
- The script ignores SSL warnings (common for self-signed router certificates)

## Dependencies

- `cloudflare>=4.3.1`: Cloudflare API client library
- `requests>=2.32.5`: HTTP library for router communication

## License

This project is provided as-is for personal and educational use.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## Version

Current version: 0.1.0