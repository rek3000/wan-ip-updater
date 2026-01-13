# get-wan-ip

A Python script that automatically retrieves your router's WAN IP address and updates Cloudflare DNS records with the current IP. Perfect for home servers, self-hosted services, and maintaining dynamic DNS entries.

## Features

- 🔌 **Router Integration**: Logs into your router and extracts the WAN IP address
- ☁️ **Cloudflare DNS Updates**: Automatically updates one or multiple DNS records
- 📱 **Telegram Notifications**: Get notified when your WAN IP changes
- ⏰ **Automatic Monitoring**: Periodic IP checks with APScheduler (every 5 minutes)
- 🔄 **Flexible Configuration**: Supports environment variables for easy setup
- 📋 **Multiple DNS Records**: Update several domains/subdomains in one run
- 🛡️ **SSL Support**: Works with self-signed certificates on routers
- 🎯 **Multiple Authentication Methods**: Supports Cloudflare API token or email + API key
- 📝 **Example Configurations**: Includes templates for easy setup

## Quick Reference

| Task | Command | Notes |
|------|---------|-------|
| Install dependencies | `uv sync` | or `pip install cloudflare requests apscheduler python-telegram-bot` |
| Create config | `cp run-updater.sh.example run-updater.sh` | Edit with your credentials |
| Run script | `./run-updater.sh` | Runs continuously with scheduler |
| Test Telegram | `uv run main.py --test-telegram` | Test bot configuration |
| View logs | Check console output | Verbose logging enabled |

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
pip install cloudflare requests apscheduler python-telegram-bot
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

### Telegram Configuration (Optional)

To receive notifications when your WAN IP changes:

**Create a Telegram Bot:**
1. Open Telegram and search for `@BotFather`
2. Send `/newbot` and follow the instructions
3. Copy the bot token (starts with `BotFather: Use this token...`)

**Get Channel ID:**
1. Add your bot to a channel/group
2. Send a message to the channel
3. Visit `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
4. Look for `"chat":{"id":-100...}` in the response
5. Copy the channel ID (negative number for channels/groups)

**Environment Variables:**
```bash
export TELEGRAM_BOT_KEY="your_bot_token_here"
export TELEGRAM_CHANNEL_ID="your_channel_id"
export TELEGRAM_TOPIC_ID=""  # Optional: For topics within channels
```

### DNS Update Control (Optional)

By default, the script will update Cloudflare DNS records when your WAN IP changes. If you want to disable DNS updates but keep receiving Telegram notifications:

```bash
export UPDATE_DNS="false"  # Set to "false" to disable DNS updates (notifications will still work)
```

**Default:** `true` (DNS updates are enabled)

**Use cases:**
- Monitoring-only mode: Receive IP change notifications without updating DNS
- Testing: Verify Telegram notifications work before enabling DNS updates
- Manual DNS management: Update DNS records manually when you receive notifications

### Telegram Detailed Setup Guide

Follow these step-by-step instructions to set up Telegram notifications:

#### Step 1: Create a Telegram Bot

1. Open Telegram and search for `@BotFather`
2. Send `/newbot` command
3. Follow the prompts:
   - Choose a name for your bot (e.g., "WAN IP Monitor")
   - Choose a username for your bot (must end in `bot`, e.g., "my_wan_ip_bot")
4. Copy the bot token (it looks like: `123456789:ABCdefGHIjklMNOpqrSTUvwxYZ`)

#### Step 2: Create a Channel or Group (Optional)

If you don't already have a channel or group:

**For a Channel:**
1. In Telegram, tap the pencil icon or menu
2. Select "New Channel"
3. Choose a name and description
4. Choose "Private" (recommended) or "Public"
5. Add subscribers if needed

**For a Group:**
1. Tap the pencil icon
2. Select "New Group"
3. Add participants
4. Name your group

#### Step 3: Add Your Bot to the Channel/Group

**For Channels:**
1. Go to your channel settings
2. Select "Administrators"
3. Tap "Add Administrator"
4. Search for your bot username
5. Add the bot with the following permissions:
   - ✅ Post Messages
   - ✅ Edit Messages
   - ✅ Delete Messages
   - ✅ Manage Topics (if using topics)

**For Groups:**
1. Go to your group settings
2. Select "Administrators"
3. Tap "Add Administrator"
4. Search for your bot username
5. Add the bot with admin privileges

#### Step 4: Get Your Channel/Group ID

**Method 1: Using Telegram API (Recommended)**

1. Send a message to your channel/group from any account
2. Open your browser and visit:
   ```
   https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
   ```
   Replace `<YOUR_BOT_TOKEN>` with your actual bot token
3. Look for the `"chat":{"id":...}` field in the response
4. Copy the ID:
   - **For private channels:** Negative number (e.g., `-1001234567890`)
   - **For groups:** Negative number (e.g., `-1001234567890`)
   - **For personal chats:** Positive number (e.g., `123456789`)

Example response:
```json
{
  "result": [
    {
      "message": {
        "chat": {
          "id": -1001234567890,
          "title": "My WAN IP Channel",
          "type": "channel"
        }
      }
    }
  ]
}
```

**Method 2: Using a Telegram Bot**

1. Search for `@userinfobot` in Telegram
2. Start a chat with it
3. Forward a message from your channel/group to @userinfobot
4. It will show you the channel/group ID

#### Step 5: Get Topic ID (Optional, for Channels with Topics)

If you want to send messages to a specific topic within a channel:

1. Go to your channel
2. Open the topic you want to use
3. Forward a message from that topic to @userinfobot
4. The topic ID will be shown in the response (usually a positive integer like `12345`)

Alternatively, use the API method from Step 4 and look for `message_thread_id` in the response.

#### Step 6: Configure Environment Variables

Add the following to your `run-updater.sh` or `.env` file:

```bash
# Telegram Configuration
export TELEGRAM_BOT_KEY="123456789:ABCdefGHIjklMNOpqrSTUvwxYZ"
export TELEGRAM_CHANNEL_ID="-1001234567890"
export TELEGRAM_TOPIC_ID=""  # Optional: Leave empty if not using topics
```

#### Step 7: Test Your Configuration

Run the test command to verify everything works:

```bash
cd /root/get-wan-ip
uv run main.py --test-telegram
```

You should receive a test message in your Telegram channel.

#### Quick Reference: Channel/Group IDs

| Type | ID Format | Example |
|------|-----------|---------|
| Private Channel | Negative | `-1001234567890` |
| Public Channel | Negative | `-1001234567890` |
| Group | Negative | `-1001234567890` |
| Personal Chat | Positive | `123456789` |
| Topic | Positive (with channel ID) | Topic ID: `123` |

 

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

The script will:
1. Check your WAN IP on startup and send a notification (if Telegram is configured)
2. Start a background scheduler to check IP every 5 minutes
3. Detect IP changes and send Telegram notification immediately
4. Update Cloudflare DNS if enabled and IP changed
5. Run continuously until you stop it (Ctrl+C)

### Testing Telegram Configuration

Before running the main script, you can test your Telegram configuration:

```bash
cd /root/get-wan-ip
uv run main.py --test-telegram
```

This will:
- Test the bot connection
- Verify the bot can send messages to your channel
- Send a test message to confirm everything works

If the test fails, see the Troubleshooting section below.

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

**Note:** If using cron, the script will run once per check interval and exit. For continuous monitoring with the scheduler, run the script in the background or use a process manager like systemd.

## How It Works

1. **Router Login**: The script logs into your router using the provided credentials
2. **IP Extraction**: It attempts various parameter combinations to extract the WAN IP address from the router's device information
3. **Change Detection**: Compares the current IP with the previously stored IP
4. **Telegram Notification**: Sends a notification to your Telegram channel on startup and whenever the IP changes
5. **Cloudflare Update**: If the IP has changed, Cloudflare is configured, and UPDATE_DNS is enabled (default), it updates the specified DNS records
6. **Automatic Monitoring**: Uses APScheduler to check the IP every 5 minutes in the background
7. **Status Reporting**: The script provides detailed progress information throughout the process

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

### TelegramNotifier
Manages Telegram notifications:
- Sends messages to channels or topics
- Handles bot authentication
- Gracefully handles errors

### Utility Functions
- `load_credentials()`: Loads and validates environment variables
- `parse_dns_records()`: Parses DNS records from JSON or comma-separated format
- `create_example_config()`: Generates example configuration files
- `load_ip_state()`: Loads the previous IP from state file
- `save_ip_state()`: Saves the current IP to state file
- `get_current_wan_ip()`: Retrieves current WAN IP from router
- `check_and_update_wan_ip()`: Checks for IP changes and updates accordingly

### Troubleshooting

### Telegram Notifications Not Working

**Problem:** Messages are not being sent to Telegram

**Solutions:**

1. **Test your configuration first:**
   ```bash
   uv run main.py --test-telegram
   ```

2. **Verify bot token:**
   - Make sure you copied the entire token from @BotFather
   - It should look like: `123456789:ABCdefGHIjklMNOpqrSTUvwxYZ`
   - Check for extra spaces or missing characters

3. **Check channel ID:**
   - For private channels: Must be negative (e.g., `-1001234567890`)
   - For groups: Must be negative
   - For personal chats: Must be positive
   - Get the correct ID by sending a message and calling: `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`

4. **Ensure bot is a member:**
   - Add the bot to your channel/group as an **administrator**
   - Give the bot permission to send messages
   - For groups: Add @YourBotName in a message first

5. **Check bot permissions:**
   - Bot needs "Send Messages" permission
   - For topics: Bot needs to be in the channel with access to topics

6. **Common error messages:**
   - `Unauthorized`: Invalid bot token
   - `Bad Request: chat not found`: Bot not in channel or wrong channel ID
   - `Forbidden: bot was blocked`: Bot was kicked from the chat
   - `Bad Request: user not found`: Incorrect user/channel ID

7. **Test with a personal chat first:**
   - Create a private chat with your bot
   - Use your personal chat ID (positive number)
   - If this works, the issue is with the channel configuration

8. **Enable verbose logging:**
   - The script prints detailed error messages
   - Check the output for specific error details

### Login Failed
- Verify your router username and password
- Check that the router URL is correct
- Ensure your router is accessible from the machine running the script

### Could Not Retrieve WAN IP
- The script tries multiple parameter combinations automatically
- If still failing, check your router's API documentation
- Ensure your router exposes device information via API

### Cloudflare Update Failed
### Telegram Notifications Not Working
- Verify the bot token is correct
- Ensure the bot has been added to the channel/group
- Check the bot has permission to send messages in the channel
- Verify the channel ID is correct (should be negative for channels/groups)
- Check that the bot can message the channel (privacy settings)

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
- `apscheduler>=3.11.2`: Background task scheduler for periodic checks
- `python-telegram-bot>=22.5`: Telegram bot API client for notifications

## License

This project is provided as-is for personal and educational use.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## Version

Current version: 0.1.0