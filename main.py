#!/usr/bin/env python3
"""
Script to login to router and get device information
Supports both Vietnamese router login and device info retrieval
Parses JSON response to extract WAN IP address
Updates Cloudflare DNS records with the WAN IP
"""

import requests
import re
import json
import os
import signal
import time
import asyncio
from urllib.parse import urljoin
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Global scheduler instance
scheduler = None

# APScheduler for scheduled tasks
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False
    print("⚠️  APScheduler library not installed. Run: pip install apscheduler")

# Telegram Bot
try:
    import telegram
    from telegram.error import TelegramError
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    print("⚠️  python-telegram-bot library not installed. Run: pip install python-telegram-bot")

# Cloudflare API
try:
    import cloudflare
    CLOUDFLARE_AVAILABLE = True
except ImportError:
    CLOUDFLARE_AVAILABLE = False
    print("⚠️  Cloudflare library not installed. Run: pip install cloudflare")

# Disable SSL warnings for self-signed certificates
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

class CloudflareManager:
    def __init__(self, api_token=None, email=None, api_key=None):
        """
        Initialize Cloudflare client with API token (recommended) or email + API key
        """
        if not CLOUDFLARE_AVAILABLE:
            raise ImportError("Cloudflare library not installed. Run: pip install cloudflare")

        self.cf = None

        if api_token:
            # Use API token (recommended method)
            self.cf = cloudflare.Cloudflare(api_token=api_token)
            print("✅ Cloudflare initialized with API token")
        elif email and api_key:
            # Use email + API key (legacy method)
            self.cf = cloudflare.Cloudflare(email=email, api_key=api_key)
            print("✅ Cloudflare initialized with email + API key")
        else:
            raise ValueError("Either api_token or (email + api_key) must be provided")

    def get_zone_id(self, domain):
        """
        Get zone ID for a domain
        """
        try:
            # Extract root domain from subdomain (e.g., "home.example.com" -> "example.com")
            domain_parts = domain.split('.')
            if len(domain_parts) >= 2:
                root_domain = '.'.join(domain_parts[-2:])
            else:
                root_domain = domain

            zones = self.cf.zones.list(name=root_domain)

            if zones and hasattr(zones, 'result') and zones.result:
                zone_id = zones.result[0].id
                print(f"📍 Found zone ID for {root_domain}: {zone_id}")
                return zone_id
            else:
                print(f"❌ Zone not found for domain: {root_domain}")
                return None

        except Exception as e:
            print(f"❌ Error getting zone ID: {e}")
            return None

    def get_dns_record(self, zone_id, record_name, record_type="A"):
        """
        Get existing DNS record
        """
        try:
            records = self.cf.dns.records.list(zone_id=zone_id, name=record_name, type=record_type)

            if records and hasattr(records, 'result') and records.result:
                record = records.result[0]
                print(f"📋 Found existing {record_type} record: {record_name} -> {record.content}")
                return record
            else:
                print(f"📋 No existing {record_type} record found for: {record_name}")
                return None

        except Exception as e:
            print(f"❌ Error getting DNS record: {e}")
            return None

    def update_dns_record(self, zone_id, record_name, new_ip, record_type="A", ttl=300):
        """
        Update or create DNS record
        """
        try:
            # Check if record exists
            existing_record = self.get_dns_record(zone_id, record_name, record_type)

            if existing_record:
                # Update existing record
                if existing_record.content == new_ip:
                    print(f"✅ DNS record already up to date: {record_name} -> {new_ip}")
                    return True

                print(f"🔄 Updating DNS record: {record_name} {existing_record.content} -> {new_ip}")

                updated_record = self.cf.dns.records.edit(
                    dns_record_id=existing_record.id,
                    zone_id=zone_id,
                    name=record_name,
                    type=record_type,
                    content=new_ip,
                    ttl=ttl
                )

                # Check if update was successful
                if updated_record and hasattr(updated_record, 'id'):
                    print(f"✅ Successfully updated DNS record: {record_name} -> {new_ip}")
                    return True
                else:
                    error_msg = getattr(updated_record, 'errors', 'Unknown error')
                    print(f"❌ Failed to update DNS record: {error_msg}")
                    return False
            else:
                # Create new record
                print(f"🆕 Creating new DNS record: {record_name} -> {new_ip}")

                new_record = self.cf.dns.records.create(
                    zone_id=zone_id,
                    name=record_name,
                    type=record_type,
                    content=new_ip,
                    ttl=ttl
                )

                # Check if creation was successful
                if new_record and hasattr(new_record, 'id'):
                    print(f"✅ Successfully created DNS record: {record_name} -> {new_ip}")
                    return True
                else:
                    error_msg = getattr(new_record, 'errors', 'Unknown error')
                    print(f"❌ Failed to create DNS record: {error_msg}")
                    return False

        except Exception as e:
            print(f"❌ Error updating DNS record: {e}")
            return False

    def update_multiple_records(self, records_config, new_ip):
        """
        Update multiple DNS records with the same IP
        records_config: list of dicts with keys: domain, record_type (optional), ttl (optional)
        """
        results = []

        for config in records_config:
            domain = config['domain']
            record_type = config.get('record_type', 'A')
            ttl = config.get('ttl', 300)

            print(f"\n--- Updating {domain} ({record_type} record) ---")

            # Get zone ID
            zone_id = self.get_zone_id(domain)
            if zone_id is None:
                results.append({'domain': domain, 'success': False, 'error': 'Zone not found'})
                continue

            # Update record
            success = self.update_dns_record(zone_id, domain, new_ip, record_type, ttl)
            results.append({'domain': domain, 'success': success})

class RouterClient:
    def __init__(self, base_url="https://192.168.1.1"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for routers
        self.session_id = None

    def login(self, username, password):
        """
        Login to the router and extract session ID
        """
        try:
            # First, get the login page to establish initial session
            login_url = urljoin(self.base_url, "/")
            print(f"Accessing login page: {login_url}")

            response = self.session.get(login_url, timeout=10)
            response.raise_for_status()

            # Prepare login data based on the HTML form
            login_data = {
                'Username': username,
                'Password': password,
                'StatusActionFlag': '-1'
            }

            # Submit login form
            login_action_url = urljoin(self.base_url, "/cgi-bin/login.asp")
            print(f"Submitting login to: {login_action_url}")

            login_response = self.session.post(
                login_action_url,
                data=login_data,
                timeout=10,
                allow_redirects=True
            )

            # Extract session ID from cookies
            session_cookies = self.session.cookies.get_dict()
            print(f"Received cookies: {session_cookies}")

            if 'SESSIONID' in session_cookies:
                self.session_id = session_cookies['SESSIONID']
                print(f"Login successful! Session ID: {self.session_id}")
                return True
            else:
                # Try to find session ID in other common cookie names
                possible_session_keys = ['sessionid', 'SessionID', 'session_id', 'PHPSESSID']
                for key in possible_session_keys:
                    if key in session_cookies:
                        self.session_id = session_cookies[key]
                        print(f"Login successful! Session ID ({key}): {self.session_id}")
                        return True

                print("Login failed - No session ID found in cookies")
                print(f"Response status: {login_response.status_code}")
                print(f"Response headers: {dict(login_response.headers)}")
                return False

        except requests.RequestException as e:
            print(f"Login error: {e}")
            return False

    def get_device_info(self, val=0, pvc=0, entry=0):
        """
        Get device information using the session ID and parse JSON response
        """
        if not self.session_id:
            print("No session ID available. Please login first.")
            return None

        try:
            # Construct the device info URL
            device_info_url = urljoin(
                self.base_url,
                f"/cgi-bin/get_deviceinfo.cgi?val={val}&pvc={pvc}&entry={entry}"
            )

            print(f"Requesting device info: {device_info_url}")

            # Make the request with session cookies
            response = self.session.get(device_info_url, timeout=10)
            response.raise_for_status()

            print(f"Device info request successful!")
            print(f"Response status: {response.status_code}")
            print(f"Response headers: {dict(response.headers)}")

            # Try to parse JSON response
            try:
                json_data = response.json()
                print(f"JSON Response:\n{json.dumps(json_data, indent=2, ensure_ascii=False)}")

                # Extract WAN IP address
                wan_ip = self.extract_wan_ip(json_data)
                if wan_ip:
                    print(f"\n🌐 WAN IP Address: {wan_ip}")
                else:
                    print("\n⚠️  WAN IP Address not found in response")

                return json_data

            except json.JSONDecodeError:
                print("Response is not valid JSON, showing raw content:")
                print(f"Raw response:\n{response.text}")

                # Try to extract WAN IP from raw text if it's not JSON
                wan_ip = self.extract_wan_ip_from_text(response.text)
                if wan_ip:
                    print(f"\n🌐 WAN IP Address (from text): {wan_ip}")

                return response.text

        except requests.RequestException as e:
            print(f"Device info request error: {e}")
            return None

    def extract_wan_ip(self, data):
        """
        Extract WAN IP address from JSON data
        Handles various possible JSON structures
        """
        if not isinstance(data, dict):
            return None

        # Common keys where WAN IP might be stored
        possible_keys = [
            'wan_ip_addr', 'wan_ip', 'wanip', 'wan_ipaddr', 'ip_addr',
            'WAN_IP_ADDR', 'WAN_IP', 'WANIP', 'WAN_IPADDR', 'IP_ADDR',
            'internetip', 'external_ip', 'public_ip'
        ]

        # Direct key lookup
        for key in possible_keys:
            if key in data:
                ip = data[key]
                if ip and ip != "0.0.0.0" and ip != "":
                    return ip

        # Recursive search in nested objects
        def search_recursive(obj, depth=0):
            if depth > 5:  # Prevent infinite recursion
                return None

            if isinstance(obj, dict):
                # Check current level
                for key in possible_keys:
                    if key in obj:
                        ip = obj[key]
                        if ip and ip != "0.0.0.0" and ip != "":
                            return ip

                # Search in nested objects
                for value in obj.values():
                    result = search_recursive(value, depth + 1)
                    if result:
                        return result

            elif isinstance(obj, list):
                # Search in list items
                for item in obj:
                    result = search_recursive(item, depth + 1)
                    if result:
                        return result

            return None

        return search_recursive(data)

    def extract_wan_ip_from_text(self, text):
        """
        Extract WAN IP address from raw text using regex
        """
        # Common patterns for IP addresses in text
        ip_patterns = [
            r'wan_ip_addr["\']?\s*[:=]\s*["\']?(\d+\.\d+\.\d+\.\d+)',
            r'wan_ip["\']?\s*[:=]\s*["\']?(\d+\.\d+\.\d+\.\d+)',
            r'WAN_IP["\']?\s*[:=]\s*["\']?(\d+\.\d+\.\d+\.\d+)',
            r'ip_addr["\']?\s*[:=]\s*["\']?(\d+\.\d+\.\d+\.\d+)',
            r'internetip["\']?\s*[:=]\s*["\']?(\d+\.\d+\.\d+\.\d+)',
        ]

        for pattern in ip_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                ip = match.group(1)
                if ip != "0.0.0.0":
                    return ip

        return None

    def logout(self):
        """
        Logout from the router (optional)
        """
        try:
            logout_url = urljoin(self.base_url, "/cgi-bin/logout.asp")
            self.session.get(logout_url, timeout=5)
            print("Logged out successfully")
        except:
            pass  # Logout may not be available or necessary


class TelegramNotifier:
    def __init__(self, bot_token=None, channel_id=None, topic_id=None):
        """
        Initialize Telegram notifier
        """
        if not TELEGRAM_AVAILABLE:
            raise ImportError("python-telegram-bot library not installed. Run: pip install python-telegram-bot")

        self.bot_token = bot_token
        self.channel_id = channel_id
        self.topic_id = topic_id
        self.bot = None
        self._validated = False

        if bot_token:
            self.bot = telegram.Bot(token=bot_token)
            print("✅ Telegram notifier initialized")
            print(f"   Bot token: {bot_token[:10]}...{bot_token[-4:]}")
            print(f"   Channel ID: {channel_id}")
            if topic_id:
                print(f"   Topic ID: {topic_id}")
        else:
            print("⚠️  Telegram bot token not provided")

    async def test_connection(self):
        """
        Test the Telegram connection by trying to get bot info
        """
        if not self.bot:
            print("❌ Telegram bot not initialized")
            return False

        try:
            print("🔍 Testing Telegram connection...")
            bot_info = await self.bot.get_me()
            print(f"✅ Connected to bot: @{bot_info.username} ({bot_info.first_name})")
            self._validated = True
            return True
        except TelegramError as e:
            print(f"❌ Telegram connection failed: {e}")
            print(f"   Error type: {type(e).__name__}")
            if "Unauthorized" in str(e):
                print("   ⚠️  Invalid bot token. Please check your TELEGRAM_BOT_KEY")
            return False
        except Exception as e:
            print(f"❌ Connection test error: {e}")
            return False

    async def send_message(self, message, parse_mode='HTML'):
        """
        Send message to Telegram channel/topic
        """
        if not self.bot or not self.channel_id:
            print("⚠️  Telegram not configured, skipping notification")
            print(f"   Bot: {bool(self.bot)}, Channel ID: {bool(self.channel_id)}")
            return False

        # Validate connection first
        if not self._validated:
            await self.test_connection()
            if not self._validated:
                return False

        try:
            print(f"📤 Sending message to channel {self.channel_id}...")
            if self.topic_id:
                print(f"   Topic ID: {self.topic_id}")
                await self.bot.send_message(
                    chat_id=self.channel_id,
                    text=message,
                    message_thread_id=self.topic_id,
                    parse_mode=parse_mode
                )
            else:
                await self.bot.send_message(
                    chat_id=self.channel_id,
                    text=message,
                    parse_mode=parse_mode
                )
            print(f"✅ Telegram message sent successfully!")
            return True
        except TelegramError as e:
            print(f"❌ Telegram API error: {e}")
            print(f"   Error type: {type(e).__name__}")

            if "Bad Request: chat not found" in str(e):
                print(f"   ⚠️  Channel ID {self.channel_id} not found or bot is not a member")
                print(f"   💡 Make sure:")
                print(f"      1. The bot has been added to the channel/group")
                print(f"      2. The bot has permission to send messages")
                print(f"      3. The channel ID is correct (should be negative for channels/groups)")
            elif "Forbidden: bot was blocked by the user" in str(e):
                print(f"   ⚠️  Bot was blocked by the user or kicked from the chat")
            elif "Bad Request: user not found" in str(e):
                print(f"   ⚠️  User not found. Check channel ID is correct")
            elif "Bad Request: message thread not found" in str(e):
                print(f"   ⚠️  Topic ID {self.topic_id} not found in the channel")
            return False
        except Exception as e:
            print(f"❌ Unexpected error sending message: {e}")
            print(f"   Error type: {type(e).__name__}")
            import traceback
            traceback.print_exc()
            return False


def load_ip_state():
    """
    Load previous IP state from file
    """
    state_file = 'wan_ip_state.json'
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
                return state.get('ip'), state.get('timestamp')
        except Exception as e:
            print(f"⚠️  Error loading IP state: {e}")
    return None, None


def save_ip_state(ip):
    """
    Save current IP state to file
    """
    state_file = 'wan_ip_state.json'
    try:
        with open(state_file, 'w') as f:
            json.dump({
                'ip': ip,
                'timestamp': time.time()
            }, f)
        print(f"💾 Saved IP state: {ip}")
    except Exception as e:
        print(f"⚠️  Error saving IP state: {e}")


def load_credentials():
    """
    Load credentials from environment variables or prompt user
    """
    # Router credentials
    username = os.getenv('ROUTER_USERNAME')
    password = os.getenv('ROUTER_PASSWORD')
    router_url = os.getenv('ROUTER_URL', 'https://192.168.1.1')

    # Cloudflare credentials
    cf_api_token = os.getenv('CLOUDFLARE_API_TOKEN')
    cf_email = os.getenv('CLOUDFLARE_EMAIL')
    cf_api_key = os.getenv('CLOUDFLARE_API_KEY')

    # DNS configuration
    dns_records = os.getenv('DNS_RECORDS')  # JSON string or comma-separated domains

    # Telegram configuration
    telegram_bot_token = os.getenv('TELEGRAM_BOT_KEY')
    telegram_channel_id = os.getenv('TELEGRAM_CHANNEL_ID')
    telegram_topic_id = os.getenv('TELEGRAM_TOPIC_ID')

    # DNS update control
    update_dns = os.getenv('UPDATE_DNS', 'true').lower() == 'true'

    # Router credentials
    if not username:
        username = input("Enter router username (or set ROUTER_USERNAME env var): ").strip()
    else:
        print(f"Using router username from environment: {username}")

    if not password:
        import getpass
        password = getpass.getpass("Enter router password (or set ROUTER_PASSWORD env var): ").strip()
    else:
        print("Using router password from environment variable")

    # Cloudflare credentials
    if not cf_api_token and not (cf_email and cf_api_key):
        print("\n--- Cloudflare Configuration (Optional) ---")
        print("For DNS updates, you need either:")
        print("1. API Token (recommended): Set CLOUDFLARE_API_TOKEN")
        print("2. Email + API Key: Set CLOUDFLARE_EMAIL and CLOUDFLARE_API_KEY")

        choice = input("Configure Cloudflare? (y/n): ").strip().lower()
        if choice == 'y':
            cf_api_token = input("Enter Cloudflare API Token (or press Enter to use email+key): ").strip()
            if not cf_api_token:
                cf_email = input("Enter Cloudflare email: ").strip()
                import getpass
                cf_api_key = getpass.getpass("Enter Cloudflare API key: ").strip()

    # DNS records configuration
    if not dns_records and (cf_api_token or (cf_email and cf_api_key)):
        dns_records = input("Enter domains to update (comma-separated, e.g., home.example.com,vpn.example.com): ").strip()

    return {
        'router': {'username': username, 'password': password, 'url': router_url},
        'cloudflare': {'api_token': cf_api_token, 'email': cf_email, 'api_key': cf_api_key},
        'dns_records': dns_records,
        'telegram': {
            'bot_token': telegram_bot_token,
            'channel_id': telegram_channel_id,
            'topic_id': telegram_topic_id
        },
        'update_dns': update_dns
    }


def parse_dns_records(dns_records_str):
    """
    Parse DNS records from string (JSON or comma-separated)
    """
    if not dns_records_str:
        print("🔍 No DNS records string provided")
        return []

    print(f"🔍 Parsing DNS records: {dns_records_str}")

    try:
        # Try to parse as JSON first
        records = json.loads(dns_records_str)
        print(f"🔍 Parsed as JSON: {records}")

        if isinstance(records, list):
            # Validate each record has required fields
            validated_records = []
            for record in records:
                if isinstance(record, dict) and 'domain' in record:
                    validated_records.append(record)
                elif isinstance(record, str):
                    validated_records.append({'domain': record})
                else:
                    print(f"⚠️  Skipping invalid record: {record}")
            return validated_records
        elif isinstance(records, dict) and 'domain' in records:
            return [records]
        else:
            print(f"⚠️  Invalid JSON structure: {records}")
            return []

    except json.JSONDecodeError as e:
        print(f"🔍 Not JSON, parsing as comma-separated: {e}")
        # Parse as comma-separated domains
        domains = [domain.strip() for domain in dns_records_str.split(',') if domain.strip()]
        print(f"🔍 Parsed domains: {domains}")
        return [{'domain': domain} for domain in domains]

    except Exception as e:
        print(f"❌ Error parsing DNS records: {e}")
        return []


def get_current_wan_ip(client):
    """
    Get current WAN IP from router
    """
    wan_ip = None

    # Try different parameter combinations to find WAN IP
    for val in [0, 1, 2]:
        for pvc in [0, 1, 2]:
            for entry in [0, 1]:
                result = client.get_device_info(val=val, pvc=pvc, entry=entry)

                if result and isinstance(result, dict):
                    wan_ip = client.extract_wan_ip(result)
                elif result and isinstance(result, str):
                    wan_ip = client.extract_wan_ip_from_text(result)

                if wan_ip:
                    print(f"🌐 Found WAN IP: {wan_ip}")
                    break
            if wan_ip:
                break
        if wan_ip:
            break

    return wan_ip


async def check_and_update_wan_ip(client, cf_manager, telegram_notifier, dns_records, creds, is_startup=False):
    """
    Check WAN IP, update Cloudflare if changed, and send Telegram notification
    """
    print("\n" + "=" * 50)
    print(f"🔍 Checking WAN IP at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)

    # Get current WAN IP
    wan_ip = get_current_wan_ip(client)

    if not wan_ip:
        print("❌ Could not retrieve WAN IP address")
        return False

    # Load previous IP state
    previous_ip, previous_timestamp = load_ip_state()

    # Check if IP has changed
    ip_changed = (previous_ip != wan_ip)

    # Send startup notification if configured
    if is_startup and telegram_notifier and telegram_notifier._validated:
        try:
            import datetime
            message = (
                f"🚀 <b>WAN IP Monitor Started</b>\n\n"
                f"Current WAN IP: <code>{wan_ip}</code>\n"
                f"Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"Monitoring for IP changes..."
            )
            await telegram_notifier.send_message(message)
            print("✅ Startup notification sent")
        except Exception as e:
            print(f"⚠️  Could not send startup notification: {e}")

    if ip_changed:
        print(f"🔄 IP changed from {previous_ip} to {wan_ip}")

        # Save new IP state
        save_ip_state(wan_ip)

        # Update Cloudflare DNS if configured and enabled
        dns_updated = False
        if creds['update_dns'] and cf_manager and dns_records:
            try:
                print(f"\n☁️  Updating Cloudflare DNS records...")
                print(f"📋 Updating {len(dns_records)} DNS record(s)...")
                cf_manager.update_multiple_records(dns_records, wan_ip)
                dns_updated = True
            except Exception as e:
                print(f"❌ Cloudflare error: {e}")
                dns_updated = False
        elif not creds['update_dns']:
            print("⏭️  DNS update disabled by UPDATE_DNS=false")

        # Send Telegram notification if configured
        if telegram_notifier:
            import datetime
            dns_status = "✅ DNS records updated successfully." if dns_updated else "⏭️  DNS update skipped."
            message = (
                f"🌐 <b>WAN IP Changed!</b>\n\n"
                f"Previous IP: {previous_ip if previous_ip else 'Unknown'}\n"
                f"New IP: <code>{wan_ip}</code>\n"
                f"Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"{dns_status}"
            )
            await telegram_notifier.send_message(message)
    else:
        print(f"✅ IP unchanged: {wan_ip}")

    return True


def signal_handler(signum, frame):
    """
    Handle shutdown signals gracefully
    """
    print("\n\n🛑 Received shutdown signal, stopping scheduler...")
    if 'scheduler' in globals():
        scheduler.shutdown(wait=False)
    print("👋 Goodbye!")
    exit(0)


async def main_async():
    """
    Main async function with scheduler support
    """
    print("Router WAN IP to Cloudflare DNS Updater with Telegram Notifications")
    print("=" * 70)
    print("Environment variables supported:")
    print("Router:")
    print("- ROUTER_USERNAME: Router username")
    print("- ROUTER_PASSWORD: Router password")
    print("- ROUTER_URL: Router URL (default: https://192.168.1.1)")
    print("\nCloudflare:")
    print("- CLOUDFLARE_API_TOKEN: API token (recommended)")
    print("- CLOUDFLARE_EMAIL: Email (legacy)")
    print("- CLOUDFLARE_API_KEY: API key (legacy)")
    print("- DNS_RECORDS: JSON array or comma-separated domains")
    print("\nTelegram (Optional):")
    print("- TELEGRAM_BOT_KEY: Telegram bot token")
    print("- TELEGRAM_CHANNEL_ID: Telegram channel ID")
    print("- TELEGRAM_TOPIC_ID: Telegram topic ID (optional)")
    print("\nOptions:")
    print("- UPDATE_DNS: Enable/disable DNS updates (default: true)")
    print("=" * 70)

    # Load credentials
    creds = load_credentials()

    # Initialize Telegram notifier if configured
    telegram_notifier = None
    if TELEGRAM_AVAILABLE and creds['telegram']['bot_token'] and creds['telegram']['channel_id']:
        telegram_notifier = TelegramNotifier(
            bot_token=creds['telegram']['bot_token'],
            channel_id=creds['telegram']['channel_id'],
            topic_id=creds['telegram']['topic_id']
        )

        # Test Telegram connection
        print("\n🔌 Testing Telegram connection...")
        connection_ok = await telegram_notifier.test_connection()
        if not connection_ok:
            print("\n⚠️  Telegram connection test failed. Notifications will not work.")
            print("   Check your configuration and try again.")
        else:
            print("✅ Telegram connection test passed!\n")

    # Initialize Cloudflare manager if configured
    cf_manager = None
    dns_records = []
    if CLOUDFLARE_AVAILABLE and (creds['cloudflare']['api_token'] or
                                 (creds['cloudflare']['email'] and creds['cloudflare']['api_key'])):
        try:
            cf_manager = CloudflareManager(
                api_token=creds['cloudflare']['api_token'],
                email=creds['cloudflare']['email'],
                api_key=creds['cloudflare']['api_key']
            )
            dns_records = parse_dns_records(creds['dns_records'])
        except Exception as e:
            print(f"⚠️  Could not initialize Cloudflare: {e}")

    # Create router client and login
    client = RouterClient(creds['router']['url'])

    print(f"\n🔌 Connecting to router at {creds['router']['url']}...")

    if not client.login(creds['router']['username'], creds['router']['password']):
        print("\n❌ LOGIN FAILED")
        print("Please check your router username and password")
        return

    print("\n✅ Router login successful")

    # Initial WAN IP check and notification
    print("\n🚀 Starting initial WAN IP check...")
    await check_and_update_wan_ip(client, cf_manager, telegram_notifier, dns_records, creds, is_startup=True)

    # Setup scheduler if available
    global scheduler

    if APSCHEDULER_AVAILABLE:
        print("\n⏰ Setting up scheduler for periodic IP checks...")

        # Initialize scheduler
        scheduler = BackgroundScheduler(timezone='UTC')
        scheduler.start()

        # Schedule periodic checks every 5 minutes
        from apscheduler.triggers.interval import IntervalTrigger

        async def scheduled_check():
            await check_and_update_wan_ip(client, cf_manager, telegram_notifier, dns_records, creds)

        # Note: APScheduler doesn't natively support coroutines, so we need to run them in an event loop
        # We'll use a simple approach: check IP every 5 minutes
        scheduler.add_job(
            lambda: asyncio.run(check_and_update_wan_ip(client, cf_manager, telegram_notifier, dns_records, creds, is_startup=False)),
            trigger=IntervalTrigger(minutes=5),
            id='wan_ip_check',
            name='WAN IP Check',
            replace_existing=True
        )

        print("✅ Scheduler started - checking IP every 5 minutes")
        print("Press Ctrl+C to stop the scheduler and exit...")

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Keep the script running
        try:
            while True:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            signal_handler(None, None)

    else:
        print("\n⏭️  APScheduler not available - performing single check only")
        if not APSCHEDULER_AVAILABLE:
            print("   Install with: pip install apscheduler")

    # Logout
    client.logout()
    print("\n🏁 Script completed!")


def main():
    """
    Main entry point
    """
    import asyncio
    asyncio.run(main_async())


# Example configuration file content
def create_example_config():
    """
    Create an example .env file for reference
    """
    example_env = """# Router Configuration
ROUTER_USERNAME=admin
ROUTER_PASSWORD=yourpassword
ROUTER_URL=https://192.168.1.1

# Cloudflare Configuration (choose one method)
# Method 1: API Token (recommended)
CLOUDFLARE_API_TOKEN=your_api_token_here

# Method 2: Email + API Key (legacy)
# CLOUDFLARE_EMAIL=your-email@example.com
# CLOUDFLARE_API_KEY=your_api_key_here

# DNS Records to Update
# Option 1: Simple comma-separated domains
DNS_RECORDS=home.example.com,vpn.example.com

# Option 2: JSON with advanced configuration
# DNS_RECORDS=[{"domain": "home.example.com", "record_type": "A", "ttl": 300}, {"domain": "vpn.example.com", "record_type": "A", "ttl": 600}]

# Telegram Configuration (Optional)
# TELEGRAM_BOT_KEY=your_bot_token_here
# TELEGRAM_CHANNEL_ID=your_channel_id
# TELEGRAM_TOPIC_ID=your_topic_id  # Optional

# DNS Update Control (Optional)
# UPDATE_DNS=true  # Set to "false" to disable DNS updates (notifications will still work)
"""

    with open('.env.example', 'w') as f:
        f.write(example_env)

    print("📝 Created .env.example file for reference")


def test_telegram():
    """
    Test Telegram bot configuration
    Run this to verify your Telegram setup
    """
    import asyncio

    print("=" * 70)
    print("Telegram Bot Configuration Test")
    print("=" * 70)

    # Load credentials
    creds = load_credentials()

    # Check if Telegram is available
    if not TELEGRAM_AVAILABLE:
        print("\n❌ python-telegram-bot library not installed")
        print("   Install with: pip install python-telegram-bot")
        return

    # Check configuration
    bot_token = creds['telegram']['bot_token']
    channel_id = creds['telegram']['channel_id']
    topic_id = creds['telegram']['topic_id']

    if not bot_token or not channel_id:
        print("\n❌ Telegram not configured")
        print("   Set TELEGRAM_BOT_KEY and TELEGRAM_CHANNEL_ID environment variables")
        return

    print(f"\n📋 Configuration:")
    print(f"   Bot Token: {bot_token[:10]}...{bot_token[-4:]}")
    print(f"   Channel ID: {channel_id}")
    if topic_id:
        print(f"   Topic ID: {topic_id}")
    else:
        print(f"   Topic ID: Not set")

    # Test connection
    async def run_test():
        notifier = TelegramNotifier(
            bot_token=bot_token,
            channel_id=channel_id,
            topic_id=topic_id
        )

        # Test bot info
        print("\n🔌 Testing connection...")
        connection_ok = await notifier.test_connection()

        if not connection_ok:
            print("\n❌ Connection test failed!")
            print("\n💡 Troubleshooting:")
            print("   1. Verify your bot token is correct")
            print("   2. Make sure the bot has been added to the channel/group")
            print("   3. Check the bot has permission to send messages")
            print("   4. Verify the channel ID is correct")
            print("   5. For channels/groups, the ID should be negative (e.g., -1001234567890)")
            return

        # Send test message
        print("\n📤 Sending test message...")
        test_message = (
            f"🧪 <b>Telegram Test Message</b>\n\n"
            f"This is a test message from get-wan-ip.\n"
            f"Your Telegram bot is working correctly! 🎉\n\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )

        success = await notifier.send_message(test_message)

        if success:
            print("\n✅ Test successful! Your Telegram bot is configured correctly.")
            print("\n📝 Next steps:")
            print("   1. Run the main script: uv run main.py")
            print("   2. The script will send notifications when your WAN IP changes")
        else:
            print("\n❌ Failed to send test message")
            print("   Check the error messages above for details")

    asyncio.run(run_test())


if __name__ == "__main__":
    import sys

    # Check for test mode
    if len(sys.argv) > 1 and sys.argv[1] == "--test-telegram":
        test_telegram()
        sys.exit(0)

    # Create example config if it doesn't exist
    if not os.path.exists('.env.example'):
        create_example_config()

    main()
