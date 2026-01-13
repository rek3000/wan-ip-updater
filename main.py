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
from urllib.parse import urljoin
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

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
        'dns_records': dns_records
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


def main():
    print("Router WAN IP to Cloudflare DNS Updater")
    print("=" * 50)
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
    print("=" * 50)
    
    # Load credentials
    creds = load_credentials()
    
    # Create router client and login
    client = RouterClient(creds['router']['url'])
    
    print(f"\n🔌 Connecting to router at {creds['router']['url']}...")
    
    if not client.login(creds['router']['username'], creds['router']['password']):
        print("\n❌ LOGIN FAILED")
        print("Please check your router username and password")
        return
    
    print("\n✅ Router login successful")
    
    # Get WAN IP address
    print("\n🔍 Fetching WAN IP address...")
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
    
    if not wan_ip:
        print("❌ Could not retrieve WAN IP address")
        client.logout()
        return
    
    # Update Cloudflare DNS if configured
    if CLOUDFLARE_AVAILABLE and (creds['cloudflare']['api_token'] or 
                                 (creds['cloudflare']['email'] and creds['cloudflare']['api_key'])):
        
        print(f"\n☁️  Updating Cloudflare DNS records...")
        
        try:
            # Initialize Cloudflare manager
            print("🔍 Initializing Cloudflare manager...")
            cf_manager = CloudflareManager(
                api_token=creds['cloudflare']['api_token'],
                email=creds['cloudflare']['email'],
                api_key=creds['cloudflare']['api_key']
            )
            
            if cf_manager is None:
                print("❌ Failed to initialize Cloudflare manager")
                return
            
            # Parse DNS records
            dns_records = parse_dns_records(creds['dns_records'])
            
            if not dns_records:
                print("⚠️  No DNS records configured for update")
            else:
                print(f"📋 Updating {len(dns_records)} DNS record(s)...")
                
                # Update DNS records
                results = cf_manager.update_multiple_records(dns_records, wan_ip)
        
        except ImportError as e:
            print(f"❌ Cloudflare library import error: {e}")
            print("   Install with: pip install cloudflare")
        except ValueError as e:
            print(f"❌ Cloudflare configuration error: {e}")
        except Exception as e:
            print(f"❌ Cloudflare error: {e}")
            print(f"🔍 Error type: {type(e).__name__}")
            print(f"🔍 Credentials provided: api_token={bool(creds['cloudflare']['api_token'])}, email={bool(creds['cloudflare']['email'])}, api_key={bool(creds['cloudflare']['api_key'])}")
            import traceback
            traceback.print_exc()
    
    else:
        print("\n⏭️  Cloudflare DNS update skipped (not configured)")
        if not CLOUDFLARE_AVAILABLE:
            print("   Install with: pip install cloudflare")
    
    # Logout
    client.logout()
    print("\n🏁 Script completed successfully!")


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
"""
    
    with open('.env.example', 'w') as f:
        f.write(example_env)
    
    print("📝 Created .env.example file for reference")


if __name__ == "__main__":
    # Create example config if it doesn't exist
    if not os.path.exists('.env.example'):
        create_example_config()
    
    main()

