"""
NetGuard v5.1 - Game Network Monitor & IP Blocker
===================================================
Designed by WillyNilly

Features: Real-time connection monitoring, firewall blocking,
geo-lookup, packet capture, dark/light mode, block manager.

Usage: python netguard.py  (auto-elevates to admin)
"""

import sys
import os
import subprocess

# ─── Check dependencies FIRST (before anything else) ───
def check_deps():
    # Skip dependency check when running as PyInstaller EXE (everything is bundled)
    if getattr(sys, 'frozen', False):
        return
    missing = []
    try:
        import psutil
    except ImportError:
        missing.append("psutil")
    try:
        from flask import Flask
    except ImportError:
        missing.append("flask")
    try:
        from scapy.all import sniff as _s
    except ImportError:
        missing.append("scapy")
    if missing:
        print(f"\n[!] Missing packages: {', '.join(missing)}")
        print(f"[*] Installing now...\n")
        for pkg in missing:
            subprocess.run([sys.executable, "-m", "pip", "install", pkg], check=False)
        print("\n[*] Done installing. Restarting...\n")
        os.execv(sys.executable, [sys.executable] + sys.argv)
        sys.exit(0)

check_deps()

import threading
import json
import urllib.request

# ─── Version & Update Config ───
VERSION = "5.1.0"
UPDATE_URL = "https://raw.githubusercontent.com/1abdussalam1/NetGuard/main/version.json"
NPCAP_URL = "https://npcap.com/dist/npcap-1.80.exe"

# ─── Auto-install Npcap (silent, hidden PowerShell) ───
def check_npcap():
    """Check if Npcap is installed, auto-download and install if not."""
    if os.name != 'nt':
        return True
    # Check common Npcap locations
    npcap_paths = [
        os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'Npcap', 'wpcap.dll'),
        os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'SysWOW64', 'Npcap', 'wpcap.dll'),
    ]
    if any(os.path.exists(p) for p in npcap_paths):
        print("[✓] Npcap found")
        return True

    print("[!] Npcap not found — downloading and installing...")
    try:
        npcap_installer = os.path.join(os.environ.get('TEMP', '.'), 'npcap_installer.exe')
        # Download silently via PowerShell (hidden window)
        dl_cmd = (
            f'powershell -NoProfile -WindowStyle Hidden -Command '
            f'"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; '
            f'Invoke-WebRequest -Uri \'{NPCAP_URL}\' -OutFile \'{npcap_installer}\'"'
        )
        subprocess.run(dl_cmd, shell=True, timeout=120)

        if os.path.exists(npcap_installer) and os.path.getsize(npcap_installer) > 100000:
            # Install silently
            print("[*] Installing Npcap silently...")
            subprocess.run([npcap_installer, '/S', '/winpcap_mode=yes'], timeout=120)
            print("[✓] Npcap installed!")
            # Cleanup
            try:
                os.remove(npcap_installer)
            except:
                pass
            return True
        else:
            print("[!] Npcap download failed. Packet capture will be limited.")
            return False
    except Exception as e:
        print(f"[!] Npcap auto-install failed: {e}")
        print("[!] Download manually from https://npcap.com/")
        return False

# ─── Auto-Update Checker ───
update_info = {"available": False, "latest": VERSION, "download_url": "", "changelog": ""}

def check_for_updates():
    """Check for updates from GitHub (non-blocking, silent on failure)."""
    global update_info
    try:
        import urllib.request
        req = urllib.request.Request(UPDATE_URL, headers={"User-Agent": "NetGuard/" + VERSION})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            latest = data.get("version", VERSION)
            if latest != VERSION:
                update_info = {
                    "available": True,
                    "latest": latest,
                    "download_url": data.get("download_url", ""),
                    "changelog": data.get("changelog", ""),
                }
                print(f"[!] Update available: v{latest} (current: v{VERSION})")
            else:
                print(f"[✓] NetGuard is up to date (v{VERSION})")
    except:
        pass  # Silent fail — no internet or no repo yet

# ─── Startup Checks (run once) ───
def startup_checks():
    """Run all startup checks: Npcap, updates, dependencies."""
    print(f"\n🛡️ NetGuard v{VERSION} — Starting up...")
    print("=" * 50)
    # 1. Check Npcap
    check_npcap()
    # 2. Check for updates (background thread — don't block startup)
    threading.Thread(target=check_for_updates, daemon=True).start()
    print("=" * 50)
    print()

startup_checks()

import psutil
import threading
import time
import json
import webbrowser
import socket
import struct
import select
import ipaddress
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template_string, jsonify, request

# ─── Auto-elevate to admin on Windows ───
def is_admin():
    if os.name != 'nt':
        return True
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if os.name == 'nt' and not is_admin():
    import ctypes
    if getattr(sys, 'frozen', False):
        # PyInstaller EXE — re-run the EXE itself as admin
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, "", None, 1)
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1)
    sys.exit(0)

# ─── Open as standalone app window (not browser tab) ───
def open_app_window(port):
    """Open NetGuard in a standalone window using Edge/Chrome --app mode."""
    url = f'http://localhost:{port}'
    if os.name == 'nt':
        # Try Microsoft Edge first (built into Windows 10/11)
        edge_paths = [
            os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
            os.path.join(os.environ.get('ProgramFiles', ''), 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
            os.path.join(os.environ.get('LocalAppData', ''), 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        ]
        for edge in edge_paths:
            if os.path.exists(edge):
                subprocess.Popen([edge, f'--app={url}', '--new-window',
                                  f'--window-size=1400,900', '--disable-extensions'])
                return

        # Try Chrome
        chrome_paths = [
            os.path.join(os.environ.get('ProgramFiles', ''), 'Google', 'Chrome', 'Application', 'chrome.exe'),
            os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'Google', 'Chrome', 'Application', 'chrome.exe'),
            os.path.join(os.environ.get('LocalAppData', ''), 'Google', 'Chrome', 'Application', 'chrome.exe'),
        ]
        for chrome in chrome_paths:
            if os.path.exists(chrome):
                subprocess.Popen([chrome, f'--app={url}', '--new-window',
                                  f'--window-size=1400,900', '--disable-extensions'])
                return

    # Fallback: regular browser
    webbrowser.open(url)

# ─── Hide console window on Windows (runs in background) ───
def hide_console():
    if os.name == 'nt':
        try:
            import ctypes
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass

# ─── Config ───
PORT = 7777
# Use exe directory (not _MEIPASS) for persistent data
_DATA_DIR = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
BLOCKED_FILE = os.path.join(_DATA_DIR, "blocked_ips.json")
FIREWALL_RULE_PREFIX = "NetGuard_"

# ─── State ───
monitoring = False
session_ips = {}       # ip -> {first_seen, ports, process, active, hit_count, ...}
blocked_ips = set()    # NetGuard's own tracked blocks
all_fw_blocked = set() # ALL blocked IPs from Windows Firewall (all sources)
all_fw_networks = []   # CIDR/subnet networks from firewall
all_fw_ranges = []     # IP ranges as (start_int, end_int) tuples
fw_cache_time = 0      # Last time we scanned the firewall
ip_geo_cache = {}      # ip -> {country, city, isp, flag, is_me, region, ...}
ip_ping_cache = {}     # ip -> {latency_ms, last_check}
ip_bandwidth = {}      # ip -> {bytes_in, bytes_out, last_bytes_in, last_bytes_out, rate_in, rate_out}
process_bandwidth = {} # pid -> {last_read, last_write, rate_read, rate_write, name}
active_processes = {}  # process_name -> {pid, connection_count}
monitor_lock = threading.Lock()
ping_lock = threading.Lock()

MIDDLE_EAST = {"SA","AE","BH","KW","QA","OM","IQ","JO","LB","SY","YE","PS","IR","TR","EG","IL","CY"}
ME_NAMES = {"SA":"Saudi Arabia","AE":"UAE","BH":"Bahrain","KW":"Kuwait","QA":"Qatar","OM":"Oman",
            "IQ":"Iraq","JO":"Jordan","LB":"Lebanon","SY":"Syria","YE":"Yemen","PS":"Palestine",
            "IR":"Iran","TR":"Turkey","EG":"Egypt","IL":"Israel","CY":"Cyprus"}

EUROPE = {"GB","DE","FR","NL","SE","NO","FI","DK","PL","CZ","AT","CH","BE","IE","PT","ES","IT",
          "RO","BG","HR","HU","SK","SI","LT","LV","EE","UA","RS","GR","IS","LU","MT","AL","BA",
          "ME","MK","MD","BY","RU"}
AMERICAS = {"US","CA","MX","BR","AR","CL","CO","PE","VE","EC","UY","PY","BO","PA","CR","GT",
            "HN","SV","NI","CU","DO","PR","JM","TT","HT","BS","BB","BZ","GY","SR"}
ASIA_PACIFIC = {"CN","JP","KR","IN","SG","HK","TW","TH","VN","MY","ID","PH","AU","NZ","PK",
                "BD","LK","MM","KH","LA","MN","NP","KZ","UZ"}
AFRICA = {"ZA","NG","EG","KE","GH","TZ","ET","MA","TN","DZ","LY","SD","CM","CI","SN","UG","MZ","AO","ZW","RW"}

# ─── Self-PID (exclude NetGuard's own connections) ───
SELF_PID = os.getpid()

GAME_PROCS = {"overwatch.exe","ow2.exe","valorant.exe","valorant-win64-shipping.exe",
              "csgo.exe","cs2.exe","fortnite.exe","fortniteclient-win64-shipping.exe",
              "rocketleague.exe","apex_legends.exe","r5apex.exe","tslgame.exe",
              "cod.exe","modernwarfare.exe","leagueclient.exe","league of legends.exe",
              "dota2.exe","pubg.exe","destiny2.exe","rainbow6.exe","r6-siege.exe",
              "genshinimpact.exe","warzone.exe","minecraft.exe","javaw.exe"}

def get_region(cc):
    if cc in MIDDLE_EAST: return "Middle East"
    if cc in EUROPE: return "Europe"
    if cc in AMERICAS: return "Americas"
    if cc in ASIA_PACIFIC: return "Asia-Pacific"
    if cc in AFRICA: return "Africa"
    if cc == "LAN": return "LAN"
    return "Other"

# ─── Cloud Provider IP Range Database ───
# Maps cloud region codes to real physical datacenter locations
CLOUD_REGION_MAP = {
    # Google Cloud
    "me-central1": {"city": "Doha", "country": "QA", "country_name": "Qatar", "region": "Middle East"},
    "me-central2": {"city": "Dammam", "country": "SA", "country_name": "Saudi Arabia", "region": "Middle East"},
    "me-west1": {"city": "Tel Aviv", "country": "IL", "country_name": "Israel", "region": "Middle East"},
    "europe-west1": {"city": "St. Ghislain", "country": "BE", "country_name": "Belgium", "region": "Europe"},
    "europe-west2": {"city": "London", "country": "GB", "country_name": "United Kingdom", "region": "Europe"},
    "europe-west3": {"city": "Frankfurt", "country": "DE", "country_name": "Germany", "region": "Europe"},
    "europe-west4": {"city": "Eemshaven", "country": "NL", "country_name": "Netherlands", "region": "Europe"},
    "europe-west6": {"city": "Zurich", "country": "CH", "country_name": "Switzerland", "region": "Europe"},
    "europe-west8": {"city": "Milan", "country": "IT", "country_name": "Italy", "region": "Europe"},
    "europe-west9": {"city": "Paris", "country": "FR", "country_name": "France", "region": "Europe"},
    "europe-north1": {"city": "Hamina", "country": "FI", "country_name": "Finland", "region": "Europe"},
    "europe-central2": {"city": "Warsaw", "country": "PL", "country_name": "Poland", "region": "Europe"},
    "europe-southwest1": {"city": "Madrid", "country": "ES", "country_name": "Spain", "region": "Europe"},
    "us-central1": {"city": "Council Bluffs, Iowa", "country": "US", "country_name": "United States", "region": "Americas"},
    "us-east1": {"city": "Moncks Corner, SC", "country": "US", "country_name": "United States", "region": "Americas"},
    "us-east4": {"city": "Ashburn, Virginia", "country": "US", "country_name": "United States", "region": "Americas"},
    "us-east5": {"city": "Columbus, Ohio", "country": "US", "country_name": "United States", "region": "Americas"},
    "us-west1": {"city": "The Dalles, Oregon", "country": "US", "country_name": "United States", "region": "Americas"},
    "us-west2": {"city": "Los Angeles", "country": "US", "country_name": "United States", "region": "Americas"},
    "us-west3": {"city": "Salt Lake City", "country": "US", "country_name": "United States", "region": "Americas"},
    "us-west4": {"city": "Las Vegas", "country": "US", "country_name": "United States", "region": "Americas"},
    "us-south1": {"city": "Dallas", "country": "US", "country_name": "United States", "region": "Americas"},
    "asia-east1": {"city": "Changhua", "country": "TW", "country_name": "Taiwan", "region": "Asia-Pacific"},
    "asia-east2": {"city": "Hong Kong", "country": "HK", "country_name": "Hong Kong", "region": "Asia-Pacific"},
    "asia-northeast1": {"city": "Tokyo", "country": "JP", "country_name": "Japan", "region": "Asia-Pacific"},
    "asia-northeast2": {"city": "Osaka", "country": "JP", "country_name": "Japan", "region": "Asia-Pacific"},
    "asia-northeast3": {"city": "Seoul", "country": "KR", "country_name": "South Korea", "region": "Asia-Pacific"},
    "asia-south1": {"city": "Mumbai", "country": "IN", "country_name": "India", "region": "Asia-Pacific"},
    "asia-south2": {"city": "Delhi", "country": "IN", "country_name": "India", "region": "Asia-Pacific"},
    "asia-southeast1": {"city": "Singapore", "country": "SG", "country_name": "Singapore", "region": "Asia-Pacific"},
    "asia-southeast2": {"city": "Jakarta", "country": "ID", "country_name": "Indonesia", "region": "Asia-Pacific"},
    "australia-southeast1": {"city": "Sydney", "country": "AU", "country_name": "Australia", "region": "Asia-Pacific"},
    "australia-southeast2": {"city": "Melbourne", "country": "AU", "country_name": "Australia", "region": "Asia-Pacific"},
    "southamerica-east1": {"city": "São Paulo", "country": "BR", "country_name": "Brazil", "region": "Americas"},
    "northamerica-northeast1": {"city": "Montréal", "country": "CA", "country_name": "Canada", "region": "Americas"},
    "northamerica-northeast2": {"city": "Toronto", "country": "CA", "country_name": "Canada", "region": "Americas"},
    "africa-south1": {"city": "Johannesburg", "country": "ZA", "country_name": "South Africa", "region": "Africa"},
    # AWS
    "me-south-1": {"city": "Bahrain", "country": "BH", "country_name": "Bahrain", "region": "Middle East"},
    "me-central-1": {"city": "UAE", "country": "AE", "country_name": "UAE", "region": "Middle East"},
    "eu-west-1": {"city": "Dublin", "country": "IE", "country_name": "Ireland", "region": "Europe"},
    "eu-west-2": {"city": "London", "country": "GB", "country_name": "United Kingdom", "region": "Europe"},
    "eu-west-3": {"city": "Paris", "country": "FR", "country_name": "France", "region": "Europe"},
    "eu-central-1": {"city": "Frankfurt", "country": "DE", "country_name": "Germany", "region": "Europe"},
    "eu-central-2": {"city": "Zurich", "country": "CH", "country_name": "Switzerland", "region": "Europe"},
    "eu-north-1": {"city": "Stockholm", "country": "SE", "country_name": "Sweden", "region": "Europe"},
    "eu-south-1": {"city": "Milan", "country": "IT", "country_name": "Italy", "region": "Europe"},
    "eu-south-2": {"city": "Spain", "country": "ES", "country_name": "Spain", "region": "Europe"},
    "us-east-1": {"city": "Virginia", "country": "US", "country_name": "United States", "region": "Americas"},
    "us-east-2": {"city": "Ohio", "country": "US", "country_name": "United States", "region": "Americas"},
    "us-west-1": {"city": "N. California", "country": "US", "country_name": "United States", "region": "Americas"},
    "us-west-2": {"city": "Oregon", "country": "US", "country_name": "United States", "region": "Americas"},
    "ap-south-1": {"city": "Mumbai", "country": "IN", "country_name": "India", "region": "Asia-Pacific"},
    "ap-southeast-1": {"city": "Singapore", "country": "SG", "country_name": "Singapore", "region": "Asia-Pacific"},
    "ap-southeast-2": {"city": "Sydney", "country": "AU", "country_name": "Australia", "region": "Asia-Pacific"},
    "ap-northeast-1": {"city": "Tokyo", "country": "JP", "country_name": "Japan", "region": "Asia-Pacific"},
    "ap-northeast-2": {"city": "Seoul", "country": "KR", "country_name": "South Korea", "region": "Asia-Pacific"},
    "sa-east-1": {"city": "São Paulo", "country": "BR", "country_name": "Brazil", "region": "Americas"},
    "af-south-1": {"city": "Cape Town", "country": "ZA", "country_name": "South Africa", "region": "Africa"},
    "ca-central-1": {"city": "Canada", "country": "CA", "country_name": "Canada", "region": "Americas"},
    "il-central-1": {"city": "Tel Aviv", "country": "IL", "country_name": "Israel", "region": "Middle East"},
}

# Stores: list of (network, region_code, provider)
cloud_ip_ranges = []
cloud_ranges_loaded = False

def load_cloud_ip_ranges():
    """Download and parse Google Cloud + AWS official IP range files."""
    global cloud_ip_ranges, cloud_ranges_loaded
    import urllib.request

    ranges = []

    # ── Google Cloud ──
    try:
        print("[*] Loading Google Cloud IP ranges...")
        req = urllib.request.Request("https://www.gstatic.com/ipranges/cloud.json",
                                     headers={"User-Agent": "NetGuard/3.1"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            for prefix in data.get("prefixes", []):
                cidr = prefix.get("ipv4Prefix")
                scope = prefix.get("scope", "")
                if cidr and scope:
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        ranges.append((net, scope, "Google Cloud"))
                    except:
                        pass
        print(f"    ✓ Google Cloud: {sum(1 for r in ranges if r[2]=='Google Cloud')} ranges")
    except Exception as e:
        print(f"    ✗ Google Cloud failed: {e}")

    # ── AWS ──
    try:
        print("[*] Loading AWS IP ranges...")
        aws_count_before = len(ranges)
        req = urllib.request.Request("https://ip-ranges.amazonaws.com/ip-ranges.json",
                                     headers={"User-Agent": "NetGuard/3.1"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            for prefix in data.get("prefixes", []):
                cidr = prefix.get("ip_prefix")
                region = prefix.get("region", "")
                if cidr and region:
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        ranges.append((net, region, "AWS"))
                    except:
                        pass
        print(f"    ✓ AWS: {len(ranges) - aws_count_before} ranges")
    except Exception as e:
        print(f"    ✗ AWS failed: {e}")

    cloud_ip_ranges = ranges
    cloud_ranges_loaded = True
    print(f"[*] Total cloud ranges loaded: {len(cloud_ip_ranges)}")

def lookup_cloud_ip(ip_str):
    """Check if an IP belongs to a known cloud provider datacenter.
    Returns: (city, country_code, country_name, region, provider, scope) or None"""
    if not cloud_ranges_loaded or not cloud_ip_ranges:
        return None
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net, scope, provider in cloud_ip_ranges:
            if ip_obj in net:
                loc = CLOUD_REGION_MAP.get(scope)
                if loc:
                    return (loc["city"], loc["country"], loc["country_name"], loc["region"], provider, scope)
                # "global" or unknown scope = anycast/global load balancer
                if scope.lower() in ("global", "", "us", "eu", "ap"):
                    return (f"{provider} Global", "CDN", f"{provider} Anycast", "CDN", provider, scope)
                # Try partial match (e.g. "us-east" matching "us-east-1")
                for key, val in CLOUD_REGION_MAP.items():
                    if key.startswith(scope) or scope.startswith(key.split("-")[0]):
                        pass  # no reliable partial match
                return (scope, "??", f"{provider} ({scope})", "Other", provider, scope)
    except:
        pass
    return None

# ─── Helpers ───
def is_fw_blocked(ip):
    """Check if an IP is blocked — exact match, CIDR/subnet, or IP range."""
    if ip in blocked_ips or ip in all_fw_blocked:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        addr_int = int(addr)
        # Check CIDR/subnet networks (e.g. 34.166.0.0/255.255.0.0)
        for net in all_fw_networks:
            if addr in net:
                return True
        # Check IP ranges (e.g. 34.0.0.0-34.0.255.255)
        for start_int, end_int in all_fw_ranges:
            if start_int <= addr_int <= end_int:
                return True
    except:
        pass
    return False

def is_private(ip):
    try:
        p = ip.split(".")
        f, s = int(p[0]), int(p[1])
        if f == 10 or f == 127 or (f == 172 and 16 <= s <= 31) or (f == 192 and s == 168) or f >= 224 or f == 0:
            return True
    except:
        return True
    return False

def geo_lookup(ip):
    if ip in ip_geo_cache:
        return ip_geo_cache[ip]
    if is_private(ip):
        ip_geo_cache[ip] = {"country": "LAN", "city": "", "flag": "🏠", "is_me": False, "region": "LAN",
                            "hosting": False, "org": "", "lat": 0, "lon": 0, "timezone": ""}
        return ip_geo_cache[ip]

    # ── FIRST: Check cloud provider IP ranges (most accurate for cloud IPs) ──
    cloud = lookup_cloud_ip(ip)
    if cloud:
        city, cc, cn, region, provider, scope = cloud
        is_cloud_cdn = (cc == "CDN")  # global/anycast cloud IPs
        ip_geo_cache[ip] = {
            "country": cc if not is_cloud_cdn else "CDN",
            "country_name": cn,
            "city": city, "region_name": scope,
            "isp": f"{provider} ({scope})",
            "flag": "☁️" if is_cloud_cdn else flag_emoji(cc),
            "is_me": cc in MIDDLE_EAST,
            "region": region,
            "hosting": True, "is_cdn": is_cloud_cdn, "cdn_name": provider if is_cloud_cdn else "",
            "org": f"{provider} - {scope}",
            "lat": 0, "lon": 0, "timezone": "",
            "cloud_provider": provider, "cloud_region": scope,
        }
        return ip_geo_cache[ip]

        return ip_geo_cache[ip]
    # PRIMARY: ipinfo.io (more accurate for datacenter/gaming IPs)
    try:
        import urllib.request
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "NetGuard/3.1", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            d = json.loads(resp.read().decode())
            cc = d.get("country", "??")
            city = d.get("city", "")
            region = d.get("region", "")
            org = d.get("org", "")
            tz = d.get("timezone", "")
            lat, lon = 0, 0
            if d.get("loc"):
                parts = d["loc"].split(",")
                if len(parts) == 2:
                    lat, lon = float(parts[0]), float(parts[1])

            # ── CDN / Anycast detection ──
            # These providers use ANYCAST: same IP serves from many locations worldwide.
            # GeoIP returns HQ address (e.g. San Francisco) NOT real server location.
            CDN_ANYCAST = {
                "cloudflare": "Cloudflare",
                "akamai": "Akamai",
                "fastly": "Fastly",
                "cloudfront": "CloudFront",
                "incapsula": "Imperva",
                "sucuri": "Sucuri",
                "stackpath": "StackPath",
                "limelight": "Limelight",
                "edgecast": "Edgecast",
                "keycdn": "KeyCDN",
            }
            HOSTING_KEYWORDS = ["hosting", "server", "data center", "datacenter",
                               "amazon", "google cloud", "microsoft", "azure", "aws", "ovh",
                               "hetzner", "digitalocean", "vultr", "linode", "i3d", "multiplay",
                               "gameserver", "choopa", "leaseweb", "scaleway", "contabo", "zayo"]

            org_lower = org.lower()
            is_cdn = False
            cdn_name = ""
            for key, name in CDN_ANYCAST.items():
                if key in org_lower:
                    is_cdn = True
                    cdn_name = name
                    break

            is_hosting = False
            if not is_cdn:
                for kw in HOSTING_KEYWORDS:
                    if kw in org_lower:
                        is_hosting = True
                        break

            # Country name lookup
            COUNTRY_NAMES = {"US":"United States","NL":"Netherlands","FR":"France","DE":"Germany",
                "GB":"United Kingdom","SA":"Saudi Arabia","AE":"UAE","BH":"Bahrain","QA":"Qatar",
                "KW":"Kuwait","OM":"Oman","JO":"Jordan","IQ":"Iraq","TR":"Turkey","EG":"Egypt",
                "SE":"Sweden","NO":"Norway","FI":"Finland","DK":"Denmark","PL":"Poland",
                "IT":"Italy","ES":"Spain","PT":"Portugal","CH":"Switzerland","AT":"Austria",
                "BE":"Belgium","IE":"Ireland","CZ":"Czech Republic","RO":"Romania","HU":"Hungary",
                "GR":"Greece","RU":"Russia","UA":"Ukraine","CA":"Canada","MX":"Mexico","BR":"Brazil",
                "JP":"Japan","KR":"South Korea","CN":"China","IN":"India","AU":"Australia",
                "SG":"Singapore","HK":"Hong Kong","TW":"Taiwan","TH":"Thailand","IL":"Israel",
                "IR":"Iran","PK":"Pakistan","MY":"Malaysia","ID":"Indonesia","PH":"Philippines",
                "ZA":"South Africa","NG":"Nigeria","AR":"Argentina","CL":"Chile","CO":"Colombia"}

            if is_cdn:
                # CDN Anycast — GeoIP location is UNRELIABLE, show as CDN
                ip_geo_cache[ip] = {
                    "country": "CDN", "country_name": f"☁️ {cdn_name} Anycast",
                    "city": f"Nearest {cdn_name} PoP", "region_name": "",
                    "isp": org, "flag": "☁️",
                    "is_me": False, "region": "CDN",
                    "hosting": False, "is_cdn": True, "cdn_name": cdn_name,
                    "org": org, "lat": lat, "lon": lon, "timezone": tz,
                }
            else:
                country_name = COUNTRY_NAMES.get(cc, cc)
                ip_geo_cache[ip] = {
                    "country": cc, "country_name": country_name,
                    "city": city, "region_name": region,
                    "isp": org, "flag": flag_emoji(cc),
                    "is_me": cc in MIDDLE_EAST, "region": get_region(cc),
                    "hosting": is_hosting, "is_cdn": False, "cdn_name": "",
                    "org": org, "lat": lat, "lon": lon, "timezone": tz,
                }
            return ip_geo_cache[ip]
    except:
        pass

    # FALLBACK: ip-api.com
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=countryCode,country,city,isp,status,hosting,as,lat,lon,timezone"
        req = urllib.request.Request(url, headers={"User-Agent": "NetGuard/3.1"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            d = json.loads(resp.read().decode())
            if d.get("status") == "success":
                cc = d.get("countryCode", "??")
                ip_geo_cache[ip] = {
                    "country": cc, "country_name": d.get("country", ""),
                    "city": d.get("city", ""), "isp": d.get("isp", ""),
                    "flag": flag_emoji(cc), "is_me": cc in MIDDLE_EAST,
                    "region": get_region(cc),
                    "hosting": d.get("hosting", False),
                    "org": d.get("as", ""),
                    "lat": d.get("lat", 0), "lon": d.get("lon", 0),
                    "timezone": d.get("timezone", ""),
                }
                return ip_geo_cache[ip]
    except:
        pass
    ip_geo_cache[ip] = {"country": "??", "city": "", "flag": "❓", "is_me": False, "region": "Other",
                        "hosting": False, "org": "", "lat": 0, "lon": 0, "timezone": ""}
    return ip_geo_cache[ip]

def flag_emoji(cc):
    try:
        return "".join(chr(0x1F1E6 + ord(c) - ord('A')) for c in cc.upper())
    except:
        return "🌍"

def batch_geo(ips):
    """Look up geo for multiple IPs using individual ipinfo.io calls."""
    unknown = [ip for ip in ips if ip not in ip_geo_cache and not is_private(ip)]
    if not unknown:
        return
    for ip in unknown:
        geo_lookup(ip)
        time.sleep(0.15)  # Rate limit for ipinfo.io free tier

# ─── Ping ───
import re as _re

def measure_ping(ip, timeout=1.0):
    """Measure latency via ICMP ping (real ping, same as game). TCP fallback."""
    # PRIMARY: ICMP ping (same protocol games reference for latency)
    try:
        if os.name == 'nt':
            r = subprocess.run(['ping', '-n', '1', '-w', '1000', ip],
                             capture_output=True, text=True, timeout=3,
                             creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
            for line in r.stdout.split('\n'):
                if 'time=' in line.lower() or 'time<' in line.lower():
                    m = _re.search(r'time[=<](\d+)', line, _re.IGNORECASE)
                    if m:
                        return int(m.group(1))
        else:
            r = subprocess.run(['ping', '-c', '1', '-W', '1', ip],
                             capture_output=True, text=True, timeout=3)
            m = _re.search(r'time=([\d.]+)', r.stdout)
            if m:
                return round(float(m.group(1)), 1)
    except:
        pass

    # FALLBACK: TCP connect timing (if ICMP blocked)
    for port in [3478, 3479, 443, 80]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            start = time.perf_counter()
            result = sock.connect_ex((ip, port))
            elapsed = (time.perf_counter() - start) * 1000
            sock.close()
            if result == 0:
                return round(elapsed, 1)
        except:
            try: sock.close()
            except: pass
    return None

def ping_worker():
    """Background thread that pings IPs periodically."""
    while monitoring:
        ips_to_ping = []
        with monitor_lock:
            for ip, info in session_ips.items():
                if info.get("active") and not is_private(ip):
                    cached = ip_ping_cache.get(ip)
                    if not cached or (time.time() - cached.get("last_check", 0)) > 15:
                        ips_to_ping.append(ip)

        for ip in ips_to_ping[:30]:  # Max 30 per cycle
            if not monitoring:
                break
            latency = measure_ping(ip)
            with ping_lock:
                ip_ping_cache[ip] = {"latency_ms": latency, "last_check": time.time()}
            time.sleep(0.1)

        time.sleep(2)

# ─── Bandwidth Tracking ───
def track_process_bandwidth():
    """Track per-process network I/O using psutil io_counters."""
    while monitoring:
        try:
            with monitor_lock:
                current_pids = set()
                for ip, info in session_ips.items():
                    if info.get("pid"):
                        current_pids.add(info["pid"])

            for pid in current_pids:
                try:
                    proc = psutil.Process(pid)
                    io = proc.io_counters()
                    name = proc.name()
                    now = time.time()

                    if pid in process_bandwidth:
                        prev = process_bandwidth[pid]
                        dt = now - prev.get("timestamp", now)
                        if dt > 0:
                            rate_read = (io.read_bytes - prev.get("read_bytes", io.read_bytes)) / dt
                            rate_write = (io.write_bytes - prev.get("write_bytes", io.write_bytes)) / dt
                            process_bandwidth[pid] = {
                                "read_bytes": io.read_bytes, "write_bytes": io.write_bytes,
                                "rate_read": max(0, rate_read), "rate_write": max(0, rate_write),
                                "name": name, "timestamp": now
                            }
                        else:
                            process_bandwidth[pid]["timestamp"] = now
                    else:
                        process_bandwidth[pid] = {
                            "read_bytes": io.read_bytes, "write_bytes": io.write_bytes,
                            "rate_read": 0, "rate_write": 0,
                            "name": name, "timestamp": now
                        }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except:
            pass
        time.sleep(2)

# ─── Input Validation ───
import re as _re
_IP_PATTERN = _re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_CIDR_PATTERN = _re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
_RANGE_PATTERN = _re.compile(r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$')
_SAFE_RULE_NAME = _re.compile(r'^[A-Za-z0-9_.\-\s()®]+$')

def is_valid_ip_input(ip):
    """Validate IP, CIDR, or IP range — prevents command injection."""
    ip = ip.strip()
    if _IP_PATTERN.match(ip):
        parts = ip.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    if _CIDR_PATTERN.match(ip):
        addr, prefix = ip.rsplit('/', 1)
        parts = addr.split('.')
        return all(0 <= int(p) <= 255 for p in parts) and 0 <= int(prefix) <= 32
    if _RANGE_PATTERN.match(ip):
        return True
    return False

def sanitize_rule_name(name):
    """Sanitize a firewall rule name to prevent injection."""
    if _SAFE_RULE_NAME.match(name):
        return name
    # Strip anything dangerous
    return _re.sub(r'[^A-Za-z0-9_.\-\s]', '', name)

# ─── Firewall ───
def fw_block(ip):
    if not is_valid_ip_input(ip):
        print(f"[!] Invalid IP rejected: {ip}")
        return False
    name = f"{FIREWALL_RULE_PREFIX}{ip.replace('.','_')}"
    ok = True
    for d in ["in", "out"]:
        r = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
             f'name={name}_{d}', f'dir={d}', 'action=block',
             f'remoteip={ip}', 'protocol=any'],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode != 0:
            ok = False
    return ok

def fw_unblock(ip):
    if not is_valid_ip_input(ip):
        return
    name = f"{FIREWALL_RULE_PREFIX}{ip.replace('.','_')}"
    for d in ["in", "out"]:
        subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
             f'name={name}_{d}'],
            capture_output=True, text=True, timeout=10
        )

def load_blocked():
    global blocked_ips
    if os.path.exists(BLOCKED_FILE):
        try:
            with open(BLOCKED_FILE) as f:
                blocked_ips = set(json.load(f))
        except:
            pass
    refresh_fw_cache()

def save_blocked():
    with open(BLOCKED_FILE, "w") as f:
        json.dump(list(blocked_ips), f)
    refresh_fw_cache()

def refresh_fw_cache():
    """Scan ALL firewall block rules using PowerShell (language-independent)."""
    global all_fw_blocked, all_fw_networks, fw_cache_time
    now = time.time()
    # Don't scan more than once every 5 seconds
    if now - fw_cache_time < 5:
        return
    new_set = set(blocked_ips)  # Start with NetGuard's own list
    new_nets = []               # CIDR/subnet networks
    new_ranges = []             # IP ranges as (start_int, end_int)
    try:
        # PowerShell batch query — list args (no shell quoting issues)
        ps_script = (
            'Get-NetFirewallRule -Action Block -Enabled True -ErrorAction SilentlyContinue | '
            'Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | '
            'Select-Object -ExpandProperty RemoteAddress | '
            'Where-Object { $_ -ne "Any" -and $_ -ne "LocalSubnet" -and $_ -ne "*" } | '
            'Sort-Object -Unique'
        )
        result = subprocess.run(
            ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
            print(f"[FW] Found {len(lines)} blocked entries")
            for ip_part in lines:
                new_set.add(ip_part)  # Always store raw string for display
                if '-' in ip_part and '.' in ip_part:
                    # IP range: 34.0.0.0-34.0.255.255
                    try:
                        parts = ip_part.split('-')
                        start = int(ipaddress.ip_address(parts[0].strip()))
                        end = int(ipaddress.ip_address(parts[1].strip()))
                        new_ranges.append((start, end))
                    except:
                        pass
                elif '/' in ip_part:
                    # CIDR or subnet mask: 34.166.0.0/255.255.0.0 or 34.166.0.0/16
                    try:
                        net = ipaddress.ip_network(ip_part, strict=False)
                        if net.prefixlen == 32:
                            new_set.add(str(net.network_address))
                        else:
                            new_nets.append(net)
                    except:
                        pass
                # else: plain IP — already in new_set
        elif result.returncode != 0:
            print(f"[FW] PowerShell error (code {result.returncode}): {(result.stderr or '')[:300]}")
        else:
            print("[FW] PowerShell returned empty — no block rules found")
    except Exception as e:
        print(f"[FW] Exception: {e}")
        # Fallback: try netsh with flexible parsing
        try:
            import re
            for direction in ["out", "in"]:
                result = subprocess.run(
                    f'netsh advfirewall firewall show rule name=all dir={direction}',
                    shell=True, capture_output=True, text=True, timeout=15
                )
                lines = result.stdout.split('\n')
                found_block = False
                for line in lines:
                    line = line.strip()
                    if 'Block' in line or 'block' in line:
                        found_block = True
                    if line.startswith('---') or (not line and found_block):
                        found_block = False
                    if found_block:
                        ips_found = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', line)
                        for ip in ips_found:
                            if '/32' in ip:
                                new_set.add(ip.split('/')[0])
                            elif '/' in ip:
                                new_set.add(ip)
                                try:
                                    new_nets.append(ipaddress.ip_network(ip, strict=False))
                                except:
                                    pass
                            elif ip not in ('0.0.0.0', '127.0.0.1', '255.255.255.255'):
                                new_set.add(ip)
        except:
            pass
    all_fw_blocked = new_set
    all_fw_networks = new_nets
    all_fw_ranges = new_ranges
    fw_cache_time = now

# ─── Connection Scanner ───
def scan_connections():
    """Scan connections using psutil (TCP + some UDP)."""
    conns = []
    seen = set()

    try:
        for c in psutil.net_connections(kind='inet'):
            if not c.raddr:
                continue
            if c.type == socket.SOCK_STREAM and c.status not in ('ESTABLISHED', 'SYN_SENT'):
                continue

            ip = c.raddr.ip
            if is_private(ip):
                continue
            pid = c.pid
            # Skip NetGuard's own connections
            if pid == SELF_PID:
                continue
            proc = ""
            try:
                if pid:
                    proc = psutil.Process(pid).name()
            except:
                proc = f"pid:{pid}"

            proto = "UDP" if c.type == socket.SOCK_DGRAM else "TCP"
            key = (ip, c.raddr.port)
            if key not in seen:
                seen.add(key)
                conns.append({"ip": ip, "port": c.raddr.port, "process": proc, "pid": pid, "proto": proto})
    except:
        pass
    return conns

# ─── Scapy Packet Sniffer (captures ALL traffic — TCP + UDP + everything) ───
sniffed_ips = {}  # ip -> {last_seen, ports, proto, packet_count, bytes_in, bytes_out, process, pid}
sniffer_lock = threading.Lock()
sniffer_active = False
local_port_map = {}  # local_port -> (process_name, pid)  — updated periodically
port_map_lock = threading.Lock()

def get_local_ips():
    """Get all local IP addresses."""
    local_ips = set(["127.0.0.1"])
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    local_ips.add(addr.address)
    except:
        pass
    return local_ips

def update_port_map():
    """Build a map of local_port → (process_name, pid) for process identification."""
    global local_port_map
    new_map = {}
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.laddr and c.pid and c.pid != SELF_PID:
                try:
                    pname = psutil.Process(c.pid).name()
                    new_map[c.laddr.port] = (pname, c.pid)
                except:
                    pass
    except:
        pass
    with port_map_lock:
        local_port_map = new_map

def port_map_updater():
    """Background thread to keep port→process map fresh."""
    while monitoring:
        update_port_map()
        time.sleep(0.5)  # Update every 500ms for fast matching

def packet_sniffer():
    """Scapy packet sniffer — captures ALL packets like Resource Monitor/Wireshark."""
    global monitoring, sniffer_active

    try:
        from scapy.all import sniff as scapy_sniff, IP, TCP, UDP, conf
        conf.verb = 0
    except ImportError:
        print("[!] scapy not available — packet sniffer disabled")
        return

    local_ips = get_local_ips()
    print(f"[*] Scapy packet sniffer starting...")
    print(f"    Local IPs: {local_ips}")
    sniffer_active = True

    def identify_process(local_port):
        """Match a local port to a process using the port map."""
        with port_map_lock:
            return local_port_map.get(local_port, ("", None))

    def process_packet(pkt):
        """Called for each captured packet."""
        if not monitoring:
            return
        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_len = len(pkt)

        # Determine direction
        if src_ip in local_ips:
            remote_ip = dst_ip
            direction = "out"
        elif dst_ip in local_ips:
            remote_ip = src_ip
            direction = "in"
        else:
            return

        if is_private(remote_ip):
            return

        # Get port, protocol, and local port for process identification
        remote_port = 0
        local_port = 0
        proto_name = "IP"
        if pkt.haslayer(UDP):
            proto_name = "UDP"
            udp_layer = pkt[UDP]
            if direction == "out":
                remote_port = udp_layer.dport
                local_port = udp_layer.sport
            else:
                remote_port = udp_layer.sport
                local_port = udp_layer.dport
        elif pkt.haslayer(TCP):
            proto_name = "TCP"
            tcp_layer = pkt[TCP]
            if direction == "out":
                remote_port = tcp_layer.dport
                local_port = tcp_layer.sport
            else:
                remote_port = tcp_layer.sport
                local_port = tcp_layer.dport

        # Identify process from local port
        proc_name, proc_pid = identify_process(local_port)
        # Skip NetGuard's own traffic
        if proc_pid == SELF_PID:
            return

        now = datetime.now().strftime("%H:%M:%S")
        with sniffer_lock:
            if remote_ip not in sniffed_ips:
                sniffed_ips[remote_ip] = {
                    "first_seen": now, "ports": set(), "proto": set(),
                    "packet_count": 0, "bytes_in": 0, "bytes_out": 0,
                    "last_seen": now, "process": "", "pid": None,
                }
            entry = sniffed_ips[remote_ip]
            entry["last_seen"] = now
            if remote_port:
                entry["ports"].add(remote_port)
            entry["proto"].add(proto_name)
            entry["packet_count"] += 1
            # Update process if identified (keep the most common one)
            if proc_name and (not entry["process"] or proc_name.lower() in GAME_PROCS):
                entry["process"] = proc_name
                entry["pid"] = proc_pid
            if direction == "in":
                entry["bytes_in"] += pkt_len
            else:
                entry["bytes_out"] += pkt_len

    try:
        print("[*] Scapy sniffer active ✓ — capturing all packets")
        scapy_sniff(
            prn=process_packet,
            store=False,
            stop_filter=lambda p: not monitoring,
            filter="ip",
        )
    except Exception as e:
        print(f"[!] Scapy sniffer error: {e}")
        print("[!] Make sure Npcap is installed: https://npcap.com/")
        sniffer_active = False

def monitor_loop():
    global monitoring
    while monitoring:
        refresh_fw_cache()  # Keep firewall block cache fresh
        conns = scan_connections()
        new_ips = []
        now = datetime.now().strftime("%H:%M:%S")

        # Track active processes
        proc_counts = defaultdict(lambda: {"count": 0, "pids": set()})

        with monitor_lock:
            # Mark all as inactive
            for ip in session_ips:
                session_ips[ip]["active"] = False

            for c in conns:
                ip = c["ip"]
                proc_name = c["process"]
                pid = c["pid"]

                proc_counts[proc_name]["count"] += 1
                if pid:
                    proc_counts[proc_name]["pids"].add(pid)

                if ip not in session_ips:
                    session_ips[ip] = {
                        "first_seen": now, "ports": set(), "process": "",
                        "active": True, "hit_count": 0, "pid": pid,
                        "processes": set(), "protos": set()
                    }
                    new_ips.append(ip)

                session_ips[ip]["last_seen"] = now
                session_ips[ip]["ports"].add(c["port"])
                session_ips[ip]["process"] = proc_name
                session_ips[ip]["pid"] = pid
                session_ips[ip]["active"] = True
                session_ips[ip]["hit_count"] = session_ips[ip].get("hit_count", 0) + 1
                if not isinstance(session_ips[ip].get("processes"), set):
                    session_ips[ip]["processes"] = set()
                if not isinstance(session_ips[ip].get("protos"), set):
                    session_ips[ip]["protos"] = set()
                session_ips[ip]["protos"].add(c.get("proto", "TCP"))
                session_ips[ip]["processes"].add(proc_name)

            # Update active processes
            active_processes.clear()
            for pname, pdata in proc_counts.items():
                active_processes[pname] = {
                    "count": pdata["count"],
                    "pids": list(pdata["pids"])
                }

            # ── Merge sniffed IPs from packet sniffer ──
            # Build port→process map for process identification
            port_to_proc = {}
            try:
                for c in psutil.net_connections(kind='inet'):
                    if c.laddr and c.pid:
                        try:
                            pname = psutil.Process(c.pid).name()
                            port_to_proc[c.laddr.port] = (pname, c.pid)
                        except:
                            pass
            except:
                pass

            with sniffer_lock:
                for ip, sinfo in sniffed_ips.items():
                    # Use process info from sniffer (already matched via local port)
                    proc_name = sinfo.get("process", "")
                    proc_pid = sinfo.get("pid")
                    # Fallback: try port_to_proc map
                    if not proc_name:
                        for p in sinfo["ports"]:
                            if p in port_to_proc:
                                proc_name, proc_pid = port_to_proc[p]
                                break

                    if ip not in session_ips:
                        session_ips[ip] = {
                            "first_seen": sinfo["first_seen"],
                            "ports": set(sinfo["ports"]),
                            "process": proc_name or "📡 Sniffed",
                            "active": True, "hit_count": sinfo["packet_count"],
                            "pid": proc_pid, "processes": set(),
                            "protos": set(sinfo["proto"]),
                            "sniffed": True,
                            "bytes_in": sinfo["bytes_in"],
                            "bytes_out": sinfo["bytes_out"],
                        }
                        if proc_name:
                            session_ips[ip]["processes"].add(proc_name)
                            proc_counts[proc_name]["count"] += 1
                        new_ips.append(ip)
                    else:
                        session_ips[ip]["ports"].update(sinfo["ports"])
                        if not isinstance(session_ips[ip].get("protos"), set):
                            session_ips[ip]["protos"] = set()
                        session_ips[ip]["protos"].update(sinfo["proto"])
                        session_ips[ip]["hit_count"] += sinfo["packet_count"]
                        session_ips[ip]["active"] = True
                        session_ips[ip]["bytes_in"] = sinfo.get("bytes_in", 0)
                        session_ips[ip]["bytes_out"] = sinfo.get("bytes_out", 0)
                        session_ips[ip]["sniffed"] = True
                        if proc_name and not session_ips[ip]["process"]:
                            session_ips[ip]["process"] = proc_name
                            session_ips[ip]["pid"] = proc_pid

                # Reset sniffer counters for rate calculation
                for sip in sniffed_ips:
                    sniffed_ips[sip]["bytes_in"] = 0
                    sniffed_ips[sip]["bytes_out"] = 0
                    sniffed_ips[sip]["packet_count"] = 0

        if new_ips:
            batch_geo(new_ips)
        time.sleep(1)

def format_bytes(b):
    """Format bytes/sec to human readable."""
    if b < 1024:
        return f"{b:.0f} B/s"
    elif b < 1024 * 1024:
        return f"{b/1024:.1f} KB/s"
    else:
        return f"{b/(1024*1024):.1f} MB/s"

# ─── Flask App ───
app = Flask(__name__)

# ─── Local Font Serving (no Google/external connections) ───
# Support both normal and PyInstaller frozen mode
if getattr(sys, 'frozen', False):
    _BASE_DIR = os.path.dirname(sys.executable)
    # PyInstaller extracts to _MEIPASS, but we also check exe directory
    _INTERNAL_DIR = getattr(sys, '_MEIPASS', _BASE_DIR)
else:
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    _INTERNAL_DIR = _BASE_DIR

FONTS_DIR = os.path.join(_BASE_DIR, "fonts")
if not os.path.isdir(FONTS_DIR):
    FONTS_DIR = os.path.join(_INTERNAL_DIR, "fonts")

@app.route('/fonts/<path:filename>')
def serve_font(filename):
    from flask import send_from_directory
    return send_from_directory(FONTS_DIR, filename, mimetype='font/ttf')

HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetGuard v5.1</title>
<link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAGV0lEQVR42n1WW2wcZxX+zj+XnbV3vZtdObbXqV1MU1dqkRNCiELrBkhpaalahPrEY5F4QPAAD1xahFTBAw9UIJD6lKe+gUCVEAqXiKpFRN7QpEmdpInTuMnWdpL1db232Zl//v/wMJeddQvzsDvzz5lz/c45H41VpsEMAgCAiJkBxM8Dt/zxx1CWAIA5ekeg6CUDJAAGEUAAgUOp2BoYBDCDETlBII5VU6iaiEFp7Rx5Ep6YAy4RRV4RwBzqjKIjAgMEpsG4CKmIGSCmgdAFwAAT92UBhI+hu6GjFGeCuK82ioY5+Yr6AtFbETkfGqZ+egmRs9FvXAJOUhypAcU14DABiXwcQVwA9HNP/TgAjlxMHEzqlICDgNAOJ7pijWZ8GP0JgohNaYABQVH+kwgiDwUEURKKIOrDIWXDjGEVmen6HDDAYOJhS5gCUsGVnLHIMaDiIrEg0qykTAoQ4cEQZBng2GvATFACglI4fsAeHzYIrIHqqr/u8v0F4+hk5uI9/8aWzNsi0Awi+IHIZYc+fUA4dmSSQYRgt91bXYcgig2bSWEF0Az0kYnMtw8NXd6QD5XMX1Zbpy52n5vNfv8LIytN9fI/G0sbcsQR0pO5h6bLJ44EMlBuL8QXM1vFYVnfdmt3yTCTChm5fDHKF0Fp+IpP3u989287jiVmS9afb/Q+O5HJWnT6hvuj+cK/V/zNpl+c3r//2cd3zl3ZfvMd7/Zdb3ml++FaZ/ED3XbtUrG9dJuEiBMDM8GcBjIm3WwEbV8fm7TPrno/Pj5SzAqpueAYry92Rhzxu2dKL/7x3tCxOe+Dj1pXlidfOKmHsh03yI847Xevefe2YIi4K6OqCk41hSnQ6OnLG3L+vszVDekYNFsyPcXMGB02Tr3bOfOh+9qzZbpTr19YGp8/FAQa/3j7izfOOVtbznQld3BKECW+i9RvMkjAQHXNe2TU8hVqreDzFVtqgMAaP3288Pqlzvm6eqW0Rl03+8DU+n+uPbev+60p2bhe455v5bPuWp0MweBkLIg+tAENOAZdrMuMSZ8qGtU1/3MTlmWAGb2AZ8vmb58uvbrQXHHp1ScKG+evG43Glx8c+esdWq1t7y5c2vzXpdb1Ghki6iACCCLp27BFbINWmmqlGTx6IFNd9WaK5ljWkJpNge2ums6LXz9V+tmbDdcLvjd8Z66gyw4W3KGp5+fHnn608sLJ8vxhHaiURogw+8nwMQR1JV+4J49N2vWuPr3cOzxuCoAIlkk/P9sac/hXT5Z+8PednGP+4kTu6ra+equx85e3V35/ZmthkUyDWaemLYnUFiFigNkgOrfmzxQtqXC7IU9MOx3JRMIMgs545aXavkfy6qXHCi+f7dbN/IVVl6cO3PeNL+UfntFtFwRiSq0rNqMpFE0LaCBj0bWtYNdT33w4Ozdmn77ZG81bGqyYhyzqfebwD6vV3xxs1p+aecWfdIqZPGXdzR17X17utsN9E891JoKg9KgDGLAN2uyqy+vyxbncWzX/zK1eziZmCMvq1O5mXXdn7tBPFrzd8uh2y1t676PCTMWZ2K97MhlwYSZCtaI/18NxDhDgKVzdDDZd/afr3dFhQ4WD2hCy2dm+crPgiMte5rzKO5225Virb7wVgnLPJkC/DygBEYjBzJbA4rrvBfydI7mpgtnxdVeyVCxss/3+LenLya8ctVm3ltfGn3nMLuZunXpjq7pIQrDS8VKjeNghtfPCDcycMenmduAG/PXZ7B+W3INl67WvlR4sm0yGarba126XTh5tX1luLdVUoMa/elw2O6zZKua9jR0Oy8zMobrxyjQSnpFiAIpxdMLalzVqLT1TNGwDvkJ1TTa7gZnNZGcqfn3b29zlIMhURp3xMgcKRHK37a7WRQROBkBjlWlCas2mKIMbQDFsg3zFzExEwxYZgpTW7AVkGSQEE1gGHATRR6ZhmCanqIuJtOq4A8OTIYsI0ATHDMkHNENpBoiyNji8QJZJtoWY5DAzOGJUFI7r/jWw/sBhUzJU6l202TX388kxLRjghGEJEtqCAToQ4kz3KRQnMgkW+ycYQKcGdH8UhSiKmFy6w+NeTDCcuklXjNI0cS+rBaUjoI8lao/0Xha89/aTD8XgvvnfF6WIJf1fyQESl2y0REvylkCf7FXMSGivR5Q2Hsv/F7KhS5oNoX5EAAAAAElFTkSuQmCC">
<style>
/* ─── Local Fonts (zero external connections) ─── */
@font-face { font-family: 'Inter'; font-weight: 300; font-style: normal; font-display: swap; src: url('/fonts/inter-300.ttf') format('truetype'); }
@font-face { font-family: 'Inter'; font-weight: 400; font-style: normal; font-display: swap; src: url('/fonts/inter-400.ttf') format('truetype'); }
@font-face { font-family: 'Inter'; font-weight: 500; font-style: normal; font-display: swap; src: url('/fonts/inter-500.ttf') format('truetype'); }
@font-face { font-family: 'Inter'; font-weight: 600; font-style: normal; font-display: swap; src: url('/fonts/inter-600.ttf') format('truetype'); }
@font-face { font-family: 'Inter'; font-weight: 700; font-style: normal; font-display: swap; src: url('/fonts/inter-700.ttf') format('truetype'); }
@font-face { font-family: 'Inter'; font-weight: 800; font-style: normal; font-display: swap; src: url('/fonts/inter-800.ttf') format('truetype'); }
@font-face { font-family: 'JetBrains Mono'; font-weight: 400; font-style: normal; font-display: swap; src: url('/fonts/jetbrains-400.ttf') format('truetype'); }
@font-face { font-family: 'JetBrains Mono'; font-weight: 500; font-style: normal; font-display: swap; src: url('/fonts/jetbrains-500.ttf') format('truetype'); }
@font-face { font-family: 'JetBrains Mono'; font-weight: 600; font-style: normal; font-display: swap; src: url('/fonts/jetbrains-600.ttf') format('truetype'); }
</style>
<script>
if (localStorage.getItem('netguard-dark-mode') !== 'false') {
    document.documentElement.classList.add('dark');
}
</script>
<style>
/* ─── CSS Variables ─── */
:root {
    --bg: #FAFAF8;
    --bg-secondary: #F5F5F0;
    --card: #FFFFFF;
    --card-hover: #FEFEFE;
    --text-1: #1A1A1A;
    --text-2: #737373;
    --text-3: #A3A3A3;
    --accent: #D4763C;
    --accent-soft: rgba(212, 118, 60, 0.12);
    --accent2: #3D8B7A;
    --accent2-soft: rgba(61, 139, 122, 0.12);
    --border: rgba(0, 0, 0, 0.06);
    --border-strong: rgba(0, 0, 0, 0.1);
    --danger: #DC4A4A;
    --danger-soft: rgba(220, 74, 74, 0.1);
    --success: #3D8B7A;
    --success-soft: rgba(61, 139, 122, 0.1);
    --warning: #D4963C;
    --warning-soft: rgba(212, 150, 60, 0.1);
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.04);
    --shadow-md: 0 4px 12px rgba(0,0,0,0.06);
    --shadow-lg: 0 8px 32px rgba(0,0,0,0.08);
    --radius: 0.875rem;
    --radius-sm: 0.5rem;
    --radius-full: 9999px;
}

.dark {
    --bg: #09090B;
    --bg-secondary: #18181B;
    --card: rgba(255, 255, 255, 0.04);
    --card-hover: rgba(255, 255, 255, 0.06);
    --text-1: #FAFAF9;
    --text-2: #A1A1AA;
    --text-3: #52525B;
    --accent: #F59E5C;
    --accent-soft: rgba(245, 158, 92, 0.12);
    --accent2: #5EEAD4;
    --accent2-soft: rgba(94, 234, 212, 0.1);
    --border: rgba(255, 255, 255, 0.06);
    --border-strong: rgba(255, 255, 255, 0.1);
    --danger: #F87171;
    --danger-soft: rgba(248, 113, 113, 0.12);
    --success: #5EEAD4;
    --success-soft: rgba(94, 234, 212, 0.1);
    --warning: #FBBF24;
    --warning-soft: rgba(251, 191, 36, 0.1);
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.2);
    --shadow-md: 0 4px 12px rgba(0,0,0,0.3);
    --shadow-lg: 0 8px 32px rgba(0,0,0,0.4);
}

/* ─── Base Reset ─── */
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background: var(--bg);
    color: var(--text-1);
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    line-height: 1.5;
    transition: background 0.3s, color 0.3s;
}

/* ─── Scrollbar ─── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-3); }

/* ─── Header / Navbar ─── */
.header {
    background: var(--card);
    border-bottom: 1px solid var(--border);
    padding: 0 1.5rem;
    height: 56px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 100;
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
}

.dark .header {
    background: rgba(24, 24, 27, 0.8);
}

.header-left {
    display: flex;
    align-items: center;
    gap: 12px;
}

.header-logo {
    font-size: 1.25rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: var(--text-1);
    display: flex;
    align-items: center;
    gap: 6px;
}

.header-logo .shield { font-size: 1.4rem; }
.header-logo .ver {
    font-size: 0.65rem;
    font-weight: 600;
    color: var(--accent);
    background: var(--accent-soft);
    padding: 2px 8px;
    border-radius: var(--radius-full);
    letter-spacing: 0.03em;
}

.header-brand {
    font-size: 0.7rem;
    color: var(--text-3);
    letter-spacing: 0.05em;
}
.header-brand span {
    color: var(--accent);
    font-weight: 600;
}

.header-right {
    display: flex;
    align-items: center;
    gap: 12px;
}

#snifferStatus {
    font-size: 0.72rem;
    color: var(--text-3);
    font-family: 'JetBrains Mono', monospace;
}

.dark-toggle {
    width: 36px;
    height: 36px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--card);
    color: var(--text-2);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1rem;
    transition: all 0.2s;
}
.dark-toggle:hover {
    background: var(--accent-soft);
    color: var(--accent);
    border-color: var(--accent);
}

.status {
    font-size: 0.75rem;
    font-weight: 600;
    padding: 4px 12px;
    border-radius: var(--radius-full);
    display: flex;
    align-items: center;
    gap: 6px;
    transition: all 0.2s;
}
.status.on {
    background: var(--success-soft);
    color: var(--success);
}
.status.off {
    background: var(--danger-soft);
    color: var(--danger);
}
.status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
}
.status.on .status-dot {
    animation: pulse-dot 2s infinite;
}
@keyframes pulse-dot {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
}

/* ─── Main Container ─── */
.main-container {
    padding: 1rem 1.5rem;
    max-width: 100%;
}

/* ─── KPI Cards ─── */
.kpi-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.75rem;
    margin-bottom: 0.75rem;
}

.kpi-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1rem 1.25rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    transition: all 0.2s;
    backdrop-filter: blur(12px);
}

.dark .kpi-card {
    backdrop-filter: blur(20px);
}

.kpi-card:hover {
    transform: translateY(-1px);
    box-shadow: var(--shadow-md);
}

.kpi-icon {
    width: 44px;
    height: 44px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.25rem;
    flex-shrink: 0;
}

.kpi-icon.total { background: var(--accent-soft); }
.kpi-icon.active { background: var(--success-soft); }
.kpi-icon.me { background: var(--warning-soft); }
.kpi-icon.blocked { background: var(--danger-soft); }

.kpi-info { flex: 1; min-width: 0; }
.kpi-label {
    font-size: 0.7rem;
    font-weight: 500;
    color: var(--text-3);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 2px;
}
.kpi-value {
    font-size: 1.5rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
    line-height: 1.2;
}
.kpi-value.total-v { color: var(--accent); }
.kpi-value.active-v { color: var(--success); }
.kpi-value.me-v { color: var(--warning); }
.kpi-value.blocked-v { color: var(--danger); }

/* ─── Controls Bar ─── */
.controls {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.625rem 1rem;
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    align-items: center;
    margin-bottom: 0.75rem;
    backdrop-filter: blur(12px);
}

.btn {
    padding: 7px 16px;
    border: none;
    border-radius: var(--radius-full);
    cursor: pointer;
    font-size: 0.75rem;
    font-weight: 600;
    font-family: 'Inter', sans-serif;
    transition: all 0.2s;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    letter-spacing: 0.01em;
}
.btn:hover { transform: translateY(-1px); box-shadow: var(--shadow-sm); }
.btn:active { transform: translateY(0); }

.btn-start {
    background: var(--accent);
    color: white;
}
.btn-start:hover { filter: brightness(1.1); }
.btn-start.active {
    background: var(--danger);
    color: white;
}

.btn-block {
    background: var(--danger-soft);
    color: var(--danger);
}
.btn-block:hover { background: var(--danger); color: white; }

.btn-unblock {
    background: var(--success-soft);
    color: var(--success);
}
.btn-unblock:hover { background: var(--success); color: white; }

.btn-block-me {
    background: var(--warning-soft);
    color: var(--warning);
}
.btn-block-me:hover { background: var(--warning); color: white; }

.btn-export {
    background: var(--accent2-soft);
    color: var(--accent2);
}
.btn-export:hover { background: var(--accent2); color: white; }

.btn-clear {
    background: var(--bg-secondary);
    color: var(--text-2);
    border: 1px solid var(--border);
}
.btn-clear:hover { background: var(--border-strong); color: var(--text-1); }

.btn-exit {
    background: transparent;
    color: var(--danger);
    border: 1px solid var(--danger-soft);
    margin-left: auto;
}
.btn-exit:hover { background: var(--danger); color: white; }

/* ─── Filter Bar ─── */
.filter-bar {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.75rem 1rem;
    display: flex;
    gap: 14px;
    align-items: center;
    flex-wrap: wrap;
    margin-bottom: 0.75rem;
    backdrop-filter: blur(12px);
}

.filter-group {
    display: flex;
    align-items: center;
    gap: 6px;
}
.filter-group label {
    font-size: 0.72rem;
    color: var(--text-3);
    white-space: nowrap;
    font-weight: 500;
}

.filter-group select, .filter-group input[type=text] {
    background: var(--bg-secondary);
    color: var(--text-1);
    border: 1px solid var(--border);
    padding: 6px 12px;
    border-radius: var(--radius-sm);
    font-size: 0.75rem;
    font-family: 'Inter', sans-serif;
    outline: none;
    transition: border-color 0.2s;
    -webkit-appearance: none;
}
.filter-group select:focus, .filter-group input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
}

/* Region buttons */
.region-btns {
    display: flex;
    gap: 4px;
}
.region-btn {
    padding: 4px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-full);
    background: transparent;
    color: var(--text-2);
    font-size: 0.7rem;
    font-weight: 500;
    font-family: 'Inter', sans-serif;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
}
.region-btn:hover {
    border-color: var(--accent);
    color: var(--accent);
    background: var(--accent-soft);
}
.region-btn.active {
    background: var(--accent);
    border-color: var(--accent);
    color: white;
}

.filter-checks {
    display: flex;
    gap: 12px;
    align-items: center;
}
.filter-checks label {
    font-size: 0.72rem;
    cursor: pointer;
    user-select: none;
    color: var(--text-2);
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 4px;
}
.filter-checks input[type=checkbox] {
    width: 14px;
    height: 14px;
    accent-color: var(--accent);
    cursor: pointer;
    border-radius: 3px;
}

.stats {
    margin-left: auto;
    color: var(--text-3);
    font-size: 0.72rem;
    display: flex;
    gap: 14px;
    font-weight: 500;
}
.stats span { white-space: nowrap; }

/* ─── Process Bar ─── */
.proc-bar {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.5rem 1rem;
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
    margin-bottom: 0.75rem;
    font-size: 0.75rem;
    min-height: 38px;
    backdrop-filter: blur(12px);
}

.proc-chip {
    display: flex;
    align-items: center;
    gap: 6px;
    background: var(--bg-secondary);
    padding: 4px 12px;
    border-radius: var(--radius-full);
    font-size: 0.7rem;
    border: 1px solid var(--border);
    transition: all 0.2s;
}
.proc-chip:hover {
    border-color: var(--accent);
}
.proc-chip .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--success);
}
.proc-chip .name {
    color: var(--accent);
    font-weight: 600;
}
.proc-chip .count {
    color: var(--text-3);
    font-weight: 500;
}
.proc-chip .bw-info {
    color: var(--accent2);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
}

/* ─── Table Container ─── */
.table-wrap {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    margin-bottom: 0.75rem;
    backdrop-filter: blur(12px);
}

.table-scroll {
    overflow-x: auto;
    max-height: calc(100vh - 420px);
    overflow-y: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.78rem;
}

thead th {
    background: var(--bg-secondary);
    color: var(--text-2);
    padding: 10px 12px;
    text-align: left;
    position: sticky;
    top: 0;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
    z-index: 20;
    font-size: 0.68rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    border-bottom: 1px solid var(--border);
    transition: all 0.2s;
}
.dark thead th {
    background: rgba(39, 39, 42, 0.8);
}
thead th:hover {
    color: var(--accent);
    background: var(--accent-soft);
}
thead th.sorted-asc::after { content: ' ▲'; font-size: 8px; color: var(--accent); }
thead th.sorted-desc::after { content: ' ▼'; font-size: 8px; color: var(--accent); }

tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
}
tbody tr:last-child { border-bottom: none; }
tbody tr:hover {
    background: var(--accent-soft);
}
tbody tr.blocked {
    color: var(--danger);
    text-decoration: line-through;
    opacity: 0.45;
}
tbody tr.me-row {
    background: var(--warning-soft);
}
tbody tr.me-row:hover {
    background: rgba(212, 150, 60, 0.15);
}
tbody tr.active-conn td:first-child {
    border-left: 3px solid var(--success);
}
tbody td {
    padding: 8px 12px;
    white-space: nowrap;
    color: var(--text-1);
}

td.ip {
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    font-size: 0.78rem;
    color: var(--text-1);
}
td.process {
    color: var(--accent);
    font-weight: 600;
}
td.country-me {
    color: var(--warning);
    font-weight: 700;
}

/* Ping colors */
.ping-good { color: var(--success); font-weight: 700; }
.ping-ok { color: var(--warning); font-weight: 700; }
.ping-bad { color: var(--danger); font-weight: 700; }
.ping-na { color: var(--text-3); }

/* Bandwidth */
.bw { font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; }
.bw-in { color: var(--accent2); }
.bw-out { color: var(--accent); }

.checkbox-cell { text-align: center; width: 36px; }
.checkbox-cell input {
    width: 15px;
    height: 15px;
    accent-color: var(--accent);
    cursor: pointer;
    border-radius: 3px;
}

.action-btn {
    padding: 4px 10px;
    border: none;
    border-radius: var(--radius-full);
    cursor: pointer;
    font-size: 0.7rem;
    font-weight: 600;
    font-family: 'Inter', sans-serif;
    margin: 0 1px;
    transition: all 0.2s;
}
.action-btn.block {
    background: var(--danger-soft);
    color: var(--danger);
}
.action-btn.block:hover {
    background: var(--danger);
    color: white;
}
.action-btn.unblock {
    background: var(--success-soft);
    color: var(--success);
}
.action-btn.unblock:hover {
    background: var(--success);
    color: white;
}

/* ─── Log ─── */
.log {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.75rem 1rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    color: var(--text-2);
    max-height: 90px;
    overflow-y: auto;
    backdrop-filter: blur(12px);
}
.log .entry { margin: 2px 0; }
.log .time { color: var(--text-3); }

.empty {
    text-align: center;
    padding: 3rem;
    color: var(--text-3);
    font-size: 0.9rem;
    font-weight: 500;
}
.empty-icon {
    font-size: 2.5rem;
    margin-bottom: 0.5rem;
    display: block;
}

/* ─── Animations ─── */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(4px); }
    to { opacity: 1; transform: translateY(0); }
}
.animate-in { animation: fadeIn 0.3s ease-out; }

/* ─── Responsive ─── */
@media (max-width: 1024px) {
    .kpi-row { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 640px) {
    .kpi-row { grid-template-columns: 1fr; }
    .header { padding: 0 1rem; }
    .main-container { padding: 0.75rem; }
}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
    <div class="header-left">
        <div class="header-logo">
            <span class="shield">🛡️</span>
            <span>NetGuard</span>
            <span class="ver">v5.1</span>
        </div>
        <div class="header-brand">Designed by <span>WillyNilly</span></div>
    </div>
    <div class="header-right">
        <span id="updateBanner" style="display:none; background:var(--accent); color:white; padding:0.3rem 0.8rem; border-radius:var(--radius-full); font-size:0.75rem; font-weight:600; cursor:pointer; animation:pulse 2s infinite;" onclick="openUpdate()">🔄 Update Available</span>
        <span id="snifferStatus"></span>
        <button class="dark-toggle" onclick="toggleDarkMode()" title="Toggle dark/light mode" id="darkToggle">🌙</button>
        <span id="status" class="status off"><span class="status-dot"></span> ⏹ Stopped</span>
    </div>
</div>

<div class="main-container">

    <!-- KPI Cards -->
    <div class="kpi-row animate-in">
        <div class="kpi-card">
            <div class="kpi-icon total">🌐</div>
            <div class="kpi-info">
                <div class="kpi-label">Total IPs</div>
                <div id="statsTotal" class="kpi-value total-v">0</div>
            </div>
        </div>
        <div class="kpi-card">
            <div class="kpi-icon active">⚡</div>
            <div class="kpi-info">
                <div class="kpi-label">Active</div>
                <div id="statsActive" class="kpi-value active-v">0</div>
            </div>
        </div>
        <div class="kpi-card">
            <div class="kpi-icon me">🕌</div>
            <div class="kpi-info">
                <div class="kpi-label">Middle East</div>
                <div id="statsME" class="kpi-value me-v">0</div>
            </div>
        </div>
        <div class="kpi-card">
            <div class="kpi-icon blocked">🚫</div>
            <div class="kpi-info">
                <div class="kpi-label">Blocked</div>
                <div id="statsBlocked" class="kpi-value blocked-v">0</div>
            </div>
        </div>
    </div>

    <!-- Controls -->
    <div class="controls animate-in">
        <button id="btnStart" class="btn btn-start" onclick="toggleMonitor()">▶ Start</button>
        <button class="btn btn-block" onclick="blockSelected()">🚫 Block Selected</button>
        <button class="btn btn-unblock" onclick="unblockSelected()">✅ Unblock</button>
        <button class="btn btn-block-me" onclick="blockAllME()">🕌 Block ME</button>
        <button class="btn btn-export" onclick="exportLog()">📋 Export</button>
        <button class="btn btn-manage" onclick="toggleBlockManager()" style="background:var(--accent2-soft); color:var(--accent2);">🛡️ Manage Blocks</button>
        <button class="btn btn-clear" onclick="clearList()">🗑️ Clear</button>
        <button class="btn btn-exit" onclick="shutdownApp()">⏻ Exit</button>
    </div>

    <!-- Filter Bar -->
    <div class="filter-bar animate-in">
        <div class="filter-group">
            <label>🎮 Process:</label>
            <select id="filterProcess" onchange="refreshTable()">
                <option value="">All Processes</option>
            </select>
        </div>

        <div class="filter-group">
            <label>🌍 Region:</label>
            <div class="region-btns">
                <button class="region-btn active" onclick="setRegion(this, '')" data-r="">All</button>
                <button class="region-btn" onclick="setRegion(this, 'Europe')" data-r="Europe">🇪🇺 EU</button>
                <button class="region-btn" onclick="setRegion(this, 'Americas')" data-r="Americas">🌎 NA</button>
                <button class="region-btn" onclick="setRegion(this, 'Middle East')" data-r="Middle East">🕌 ME</button>
                <button class="region-btn" onclick="setRegion(this, 'Asia-Pacific')" data-r="Asia-Pacific">🌏 Asia</button>
                <button class="region-btn" onclick="setRegion(this, 'CDN')" data-r="CDN">☁️ CDN</button>
            </div>
        </div>

        <div class="filter-checks">
            <label><input type="checkbox" id="filterActive" onchange="refreshTable()"> ⚡ Active</label>
            <label><input type="checkbox" id="hideBlocked" onchange="onBlockFilter('hide')"> 🚫 Hide Blocked</label>
            <label><input type="checkbox" id="showBlockedOnly" onchange="onBlockFilter('only')"> 🔴 Blocked Only</label>
        </div>

        <div class="stats">
            <span id="statsTotal2" style="color:var(--accent)">0 IPs</span>
            <span id="statsME2" style="color:var(--warning)">0 ME</span>
            <span id="statsBlocked2" style="color:var(--danger)">0 blocked</span>
            <span id="statsActive2" style="color:var(--success)">0 active</span>
        </div>
    </div>

    <!-- Process Bar -->
    <div class="proc-bar animate-in" id="procBar"></div>

    <!-- Table -->
    <div class="table-wrap animate-in">
        <div class="table-scroll">
            <table>
            <thead>
            <tr>
                <th class="checkbox-cell"><input type="checkbox" id="selectAll" onchange="toggleSelectAll()"></th>
                <th data-col="ip" onclick="sortBy('ip')">IP Address</th>
                <th data-col="port" onclick="sortBy('port')">Port</th>
                <th data-col="ping" onclick="sortBy('ping')">Ping</th>
                <th data-col="country" onclick="sortBy('country')">Country</th>
                <th data-col="location" onclick="sortBy('location')">📍 Location</th>
                <th data-col="region" onclick="sortBy('region')">Region</th>
                <th data-col="process" onclick="sortBy('process')">Process</th>
                <th data-col="bw_in" onclick="sortBy('bw_in')">↓ In</th>
                <th data-col="bw_out" onclick="sortBy('bw_out')">↑ Out</th>
                <th data-col="first" onclick="sortBy('first')">Seen</th>
                <th>Actions</th>
            </tr>
            </thead>
            <tbody id="connTable"></tbody>
            </table>
            <div id="emptyMsg" class="empty"><span class="empty-icon">🎮</span>Click ▶ Start then launch your game</div>
        </div>
    </div>

    <!-- Log -->
    <div class="log animate-in" id="logArea"></div>

    <!-- Block Manager Panel -->
    <div id="blockManager" class="card animate-in" style="display:none; margin-top:1rem; padding:1.25rem;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
            <h3 style="margin:0; font-size:1.1rem; color:var(--text-1);">🛡️ Block Manager — Firewall Rules</h3>
            <div style="display:flex; gap:0.5rem;">
                <button class="btn btn-unblock" onclick="unblockAllBlocks()" style="font-size:0.8rem;">✅ Unblock All</button>
                <button class="btn btn-block" onclick="unblockSelectedBlocks()" style="font-size:0.8rem;">🔓 Unblock Selected</button>
                <button class="btn btn-clear" onclick="refreshBlockList()" style="font-size:0.8rem;">🔄 Refresh</button>
            </div>
        </div>

        <!-- Manual Block Input -->
        <div style="display:flex; gap:0.5rem; margin-bottom:1rem; align-items:stretch;">
            <input type="text" id="manualBlockInput" placeholder="أدخل IP أو أكثر (مثال: 1.2.3.4, 5.6.7.8 أو نطاق 10.0.0.0/24)" style="flex:1; padding:0.6rem 0.9rem; border-radius:var(--radius-sm); border:1px solid var(--border-strong); background:var(--bg-secondary); color:var(--text-1); font-family:'JetBrains Mono',monospace; font-size:0.85rem; outline:none;" onkeydown="if(event.key==='Enter')manualBlock()">
            <button class="btn btn-block" onclick="manualBlock()" style="font-size:0.85rem; white-space:nowrap;">🚫 Block</button>
        </div>

        <div id="blockCount" style="font-size:0.85rem; color:var(--text-2); margin-bottom:0.75rem;"></div>
        <div style="overflow-x:auto;">
            <table class="table" id="blockTable">
                <thead>
                    <tr>
                        <th style="width:40px"><input type="checkbox" id="selectAllBlocks" onchange="toggleAllBlocks(this)"></th>
                        <th>IP ADDRESS</th>
                        <th>COUNTRY</th>
                        <th>CITY</th>
                        <th>REGION</th>
                        <th>SOURCE</th>
                        <th>ACTIONS</th>
                    </tr>
                </thead>
                <tbody id="blockBody"></tbody>
            </table>
        </div>
        <div id="blockEmpty" class="empty" style="display:none; padding:2rem;">
            <span class="empty-icon">✅</span>No blocked IPs
        </div>
    </div>

</div>

<script>
let data = [];
let procData = {};
let selectedIps = new Set();
let sortField = 'first';
let sortAsc = false;
let isMonitoring = false;
let pollInterval = null;
let selectedRegion = '';

// ─── Dark Mode ───
function toggleDarkMode() {
    const isDark = document.documentElement.classList.toggle('dark');
    localStorage.setItem('netguard-dark-mode', isDark ? 'true' : 'false');
    document.getElementById('darkToggle').textContent = isDark ? '☀️' : '🌙';
}
// Init toggle icon
(function() {
    const isDark = document.documentElement.classList.contains('dark');
    const btn = document.getElementById('darkToggle');
    if (btn) btn.textContent = isDark ? '☀️' : '🌙';
})();

function log(msg) {
    const el = document.getElementById('logArea');
    const time = new Date().toLocaleTimeString();
    el.innerHTML += `<div class="entry"><span class="time">[${time}]</span> ${msg}</div>`;
    el.scrollTop = el.scrollHeight;
}

// ─── Block Filter (mutual exclusive) ───
function onBlockFilter(which) {
    if (which === 'hide' && document.getElementById('hideBlocked').checked) {
        document.getElementById('showBlockedOnly').checked = false;
    } else if (which === 'only' && document.getElementById('showBlockedOnly').checked) {
        document.getElementById('hideBlocked').checked = false;
    }
    refreshTable();
}

// ─── Region Filter ───
function setRegion(btn, region) {
    selectedRegion = region;
    document.querySelectorAll('.region-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    refreshTable();
}

// ─── Monitor Toggle ───
async function toggleMonitor() {
    const resp = await fetch('/api/monitor', {method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({action: isMonitoring ? 'stop' : 'start'})});
    const r = await resp.json();
    isMonitoring = r.monitoring;
    document.getElementById('btnStart').textContent = isMonitoring ? '⏹ Stop' : '▶ Start';
    document.getElementById('btnStart').className = 'btn btn-start' + (isMonitoring ? ' active' : '');
    document.getElementById('status').innerHTML = isMonitoring
        ? '<span class="status-dot"></span> 🔴 LIVE'
        : '<span class="status-dot"></span> ⏹ Stopped';
    document.getElementById('status').className = 'status ' + (isMonitoring ? 'on' : 'off');
    log(isMonitoring ? '🟢 Monitoring started' : '⏹ Stopped');
    if (isMonitoring && !pollInterval) pollInterval = setInterval(fetchData, 2000);
    if (!isMonitoring && pollInterval) { clearInterval(pollInterval); pollInterval = null; }
}

// ─── Fetch Data ───
async function fetchData() {
    try {
        const [connResp, procResp, sniffResp] = await Promise.all([
            fetch('/api/connections'),
            fetch('/api/processes'),
            fetch('/api/sniffer_status')
        ]);
        data = await connResp.json();
        procData = await procResp.json();
        const sniff = await sniffResp.json();
        const sniffEl = document.getElementById('snifferStatus');
        if (sniff.active) {
            sniffEl.innerHTML = `🔬 <span style="color:var(--success)">${sniff.total_packets} pkts</span> · <span style="color:var(--accent2)">${sniff.ips_found} IPs</span>`;
        } else {
            sniffEl.innerHTML = '<span style="color:var(--danger)">🔬 Sniffer OFF</span>';
        }
        updateProcessDropdown();
        updateProcessBar();
        refreshTable();
    } catch(e) {}
}

// ─── Process Dropdown ───
function updateProcessDropdown() {
    const sel = document.getElementById('filterProcess');
    const current = sel.value;
    const procs = [...new Set(data.map(c => c.process).filter(p => p))].sort();

    // Rebuild options
    sel.innerHTML = '<option value="">All Processes</option>';
    procs.forEach(p => {
        const count = data.filter(c => c.process === p).length;
        const isGame = data.find(c => c.process === p && c.is_game);
        const prefix = isGame ? '🎮 ' : '';
        sel.innerHTML += `<option value="${p}" ${p === current ? 'selected' : ''}>${prefix}${p} (${count})</option>`;
    });
}

// ─── Process Summary Bar ───
function updateProcessBar() {
    const bar = document.getElementById('procBar');
    const procs = Object.entries(procData);
    if (!procs.length) {
        bar.innerHTML = '<span style="color:var(--text-3);font-size:0.72rem">No active processes</span>';
        return;
    }
    bar.innerHTML = procs.map(([name, info]) => {
        const bw = info.rate_read || info.rate_write
            ? `<span class="bw-info">↓${formatBW(info.rate_read)} ↑${formatBW(info.rate_write)}</span>`
            : '';
        return `<div class="proc-chip">
            <span class="dot"></span>
            <span class="name">${name}</span>
            <span class="count">${info.connections}conn</span>
            ${bw}
        </div>`;
    }).join('');
}

function formatBW(bytes) {
    if (!bytes || bytes < 0) return '0';
    if (bytes < 1024) return bytes.toFixed(0) + 'B/s';
    if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + 'KB/s';
    return (bytes/(1024*1024)).toFixed(1) + 'MB/s';
}

// ─── Ping Display ───
function pingHtml(ms) {
    if (ms === null || ms === undefined) return '<span class="ping-na">—</span>';
    let cls = 'ping-good';
    if (ms > 100) cls = 'ping-bad';
    else if (ms > 60) cls = 'ping-ok';
    return `<span class="${cls}">${ms}ms</span>`;
}

// ─── Table Render ───
function refreshTable() {
    const tbody = document.getElementById('connTable');
    const procFilter = document.getElementById('filterProcess').value;
    const activeOnly = document.getElementById('filterActive').checked;
    const hideBlocked = document.getElementById('hideBlocked').checked;
    const blockedOnly = document.getElementById('showBlockedOnly').checked;

    let filtered = data.filter(c => {
        if (procFilter && c.process !== procFilter) return false;
        if (selectedRegion && c.region !== selectedRegion) return false;
        if (activeOnly && !c.active) return false;
        if (hideBlocked && c.blocked) return false;
        if (blockedOnly && !c.blocked) return false;
        return true;
    });

    // Sort
    filtered.sort((a, b) => {
        let va, vb;
        if (sortField === 'ping') {
            va = a.ping ?? 9999; vb = b.ping ?? 9999;
        } else if (sortField === 'bw_in') {
            va = a.bw_in || 0; vb = b.bw_in || 0;
        } else if (sortField === 'bw_out') {
            va = a.bw_out || 0; vb = b.bw_out || 0;
        } else {
            va = a[sortField] || ''; vb = b[sortField] || '';
            if (typeof va === 'string') va = va.toLowerCase();
            if (typeof vb === 'string') vb = vb.toLowerCase();
        }
        if (va < vb) return sortAsc ? -1 : 1;
        if (va > vb) return sortAsc ? 1 : -1;
        return 0;
    });

    // Stats — KPI cards (numbers only)
    const totalCount = data.length;
    const meCount = data.filter(c=>c.is_me).length;
    const blockedCount = data.filter(c=>c.blocked).length;
    const activeCount = data.filter(c=>c.active).length;

    document.getElementById('statsTotal').textContent = totalCount;
    document.getElementById('statsME').textContent = meCount;
    document.getElementById('statsBlocked').textContent = blockedCount;
    document.getElementById('statsActive').textContent = activeCount;

    // Stats — filter bar (with labels)
    document.getElementById('statsTotal2').textContent = totalCount + ' IPs';
    document.getElementById('statsME2').textContent = meCount + ' ME';
    document.getElementById('statsBlocked2').textContent = blockedCount + ' blocked';
    document.getElementById('statsActive2').textContent = activeCount + ' active';

    document.getElementById('emptyMsg').style.display = filtered.length ? 'none' : 'block';

    // Update sort indicators
    document.querySelectorAll('thead th').forEach(th => {
        th.classList.remove('sorted-asc', 'sorted-desc');
        if (th.dataset.col === sortField) {
            th.classList.add(sortAsc ? 'sorted-asc' : 'sorted-desc');
        }
    });

    tbody.innerHTML = filtered.map(c => {
        const cls = [
            c.blocked ? 'blocked' : '',
            c.is_me ? 'me-row' : '',
            c.active ? 'active-conn' : ''
        ].filter(Boolean).join(' ');
        const checked = selectedIps.has(c.ip) ? 'checked' : '';
        const countryClass = c.is_me ? 'country-me' : '';
        const actionBtn = c.blocked
            ? `<button class="action-btn unblock" onclick="unblockIp('${c.ip}')">✅</button>`
            : `<button class="action-btn block" onclick="blockIp('${c.ip}')">🚫</button>`;

        const hostTag = c.hosting ? ' <span style="color:var(--warning);font-size:10px">☁️</span>' : '';

        return `<tr class="${cls}">
            <td class="checkbox-cell"><input type="checkbox" ${checked} onchange="toggleSelect('${c.ip}', this.checked)"></td>
            <td class="ip">${c.ip}</td>
            <td>${c.ports}</td>
            <td>${pingHtml(c.ping)}</td>
            <td class="${countryClass}">${c.flag} ${c.country_name || c.country}${hostTag}</td>
            <td style="font-size:0.78rem">${c.location || c.city || ''}</td>
            <td style="color:var(--text-3);font-size:0.72rem">${c.region || ''}</td>
            <td class="process">${c.process}</td>
            <td class="bw bw-in">${c.bw_in ? formatBW(c.bw_in) : '—'}</td>
            <td class="bw bw-out">${c.bw_out ? formatBW(c.bw_out) : '—'}</td>
            <td style="color:var(--text-3)">${c.first_seen}</td>
            <td>${actionBtn}</td>
        </tr>`;
    }).join('');
}

function sortBy(field) {
    if (sortField === field) sortAsc = !sortAsc;
    else { sortField = field; sortAsc = true; }
    refreshTable();
}

function toggleSelect(ip, checked) {
    if (checked) selectedIps.add(ip); else selectedIps.delete(ip);
}
function toggleSelectAll() {
    const all = document.getElementById('selectAll').checked;
    document.querySelectorAll('#connTable input[type=checkbox]').forEach(cb => { cb.checked = all; });
    if (all) data.forEach(c => selectedIps.add(c.ip)); else selectedIps.clear();
}

// ─── Block/Unblock Actions ───
async function blockIp(ip) {
    const r = await fetch('/api/block', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ips:[ip]})});
    const res = await r.json();
    log(`🚫 Blocked ${ip}`);
    fetchData();
}
async function unblockIp(ip) {
    await fetch('/api/unblock', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ips:[ip]})});
    log(`✅ Unblocked ${ip}`);
    fetchData();
}

async function blockSelected() {
    const ips = [...selectedIps];
    if (!ips.length) return alert('Select IPs first');
    if (!confirm(`Block ${ips.length} IPs?`)) return;
    await fetch('/api/block', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ips})});
    log(`🚫 Blocked ${ips.length} IPs`);
    selectedIps.clear(); fetchData();
}
async function unblockSelected() {
    const ips = [...selectedIps];
    if (!ips.length) return alert('Select IPs first');
    await fetch('/api/unblock', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ips})});
    log(`✅ Unblocked ${ips.length} IPs`);
    selectedIps.clear(); fetchData();
}
async function blockAllME() {
    const meIps = data.filter(c => c.is_me && !c.blocked).map(c => c.ip);
    if (!meIps.length) return alert('No ME IPs to block');
    if (!confirm(`Block ${meIps.length} Middle East IPs?`)) return;
    await fetch('/api/block', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ips: meIps})});
    log(`🚫 Blocked ${meIps.length} ME IPs`);
    fetchData();
}
async function clearList() {
    if (!confirm('Clear all?')) return;
    await fetch('/api/clear', {method:'POST'});
    data = []; refreshTable();
    log('🗑️ Cleared');
}

function exportLog() {
    let txt = `NetGuard v5.1 - ${new Date().toLocaleString()}\n${'='.repeat(100)}\n\n`;
    txt += `${'IP'.padEnd(18)}${'Port'.padEnd(8)}${'Country'.padEnd(16)}${'City'.padEnd(16)}${'Region'.padEnd(14)}${'Process'.padEnd(22)}${'ISP'.padEnd(25)}${'Ping'.padEnd(8)}${'Blocked'.padEnd(8)}Seen\n`;
    txt += `${'-'.repeat(140)}\n`;
    data.forEach(c => {
        txt += `${c.ip.padEnd(18)}${(c.ports||'').toString().padEnd(8)}${(c.country_name||c.country).padEnd(16)}${(c.city||'').padEnd(16)}${(c.region||'').padEnd(14)}${c.process.padEnd(22)}${(c.isp||'').slice(0,24).padEnd(25)}${(c.ping ? c.ping+'ms' : '-').padEnd(8)}${(c.blocked?'YES':'').padEnd(8)}${c.first_seen}\n`;
    });
    txt += `\nTotal: ${data.length} | ME: ${data.filter(c=>c.is_me).length} | Blocked: ${data.filter(c=>c.blocked).length}\n`;

    const blob = new Blob([txt], {type:'text/plain'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `netguard_${new Date().toISOString().slice(0,10)}.txt`;
    a.click();
    log('📋 Exported');
}

async function shutdownApp() {
    if (!confirm('Exit NetGuard?')) return;
    await fetch('/api/shutdown', {method:'POST'});
    document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;font-size:20px;flex-direction:column;gap:8px;background:var(--bg);color:var(--text-2)"><span style="font-size:3rem">🛡️</span>NetGuard stopped. You can close this tab.</div>';
}

// ─── Block Manager Functions ───
let blockManagerOpen = false;
let selectedBlocks = new Set();

function toggleBlockManager() {
    const panel = document.getElementById('blockManager');
    blockManagerOpen = !blockManagerOpen;
    panel.style.display = blockManagerOpen ? 'block' : 'none';
    if (blockManagerOpen) refreshBlockList();
}

async function refreshBlockList() {
    try {
        const resp = await fetch('/api/blocks');
        const d = await resp.json();
        const body = document.getElementById('blockBody');
        const empty = document.getElementById('blockEmpty');
        const count = document.getElementById('blockCount');
        selectedBlocks.clear();
        document.getElementById('selectAllBlocks').checked = false;

        count.textContent = `${d.total} blocked IP${d.total !== 1 ? 's' : ''} in firewall`;

        if (d.blocks.length === 0) {
            body.innerHTML = '';
            empty.style.display = 'block';
            document.getElementById('blockTable').style.display = 'none';
            return;
        }

        empty.style.display = 'none';
        document.getElementById('blockTable').style.display = 'table';

        body.innerHTML = d.blocks.map(b => {
            const flag = b.cc ? getFlagEmoji(b.cc) : '🌐';
            const srcBadge = b.is_netguard
                ? '<span style="background:var(--accent2-soft);color:var(--accent2);padding:0.1rem 0.4rem;border-radius:4px;font-size:0.7rem;">NetGuard</span>'
                : `<span style="background:var(--warning-soft);color:var(--warning);padding:0.1rem 0.4rem;border-radius:4px;font-size:0.7rem;">${b.source}</span>`;
            return `<tr data-bip="${b.ip}" data-rule="${b.rule_name || ''}">
                <td><input type="checkbox" class="block-cb" value="${b.rule_name || b.ip}" data-ip="${b.ip}" onchange="toggleBlockSelect(this)"></td>
                <td style="font-family:'JetBrains Mono',monospace; font-weight:600; color:var(--danger);">${b.ip}</td>
                <td>${flag} ${b.country}</td>
                <td>${b.city || '—'}</td>
                <td>${b.region || '—'}</td>
                <td>${srcBadge}</td>
                <td><button class="btn btn-unblock" style="font-size:0.75rem; padding:0.25rem 0.6rem;" onclick="unblockOneRule('${b.ip}','${(b.rule_name||'').replace(/'/g,"\\'")}')">🔓 Unblock</button></td>
            </tr>`;
        }).join('');
    } catch(e) {
        console.error('Block list error:', e);
    }
}

function getFlagEmoji(cc) {
    if (!cc || cc.length !== 2) return '🌐';
    const codePoints = [...cc.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65);
    return String.fromCodePoint(...codePoints);
}

function toggleBlockSelect(cb) {
    if (cb.checked) selectedBlocks.add(cb.value);
    else selectedBlocks.delete(cb.value);
}

function toggleAllBlocks(master) {
    document.querySelectorAll('.block-cb').forEach(cb => {
        cb.checked = master.checked;
        if (master.checked) selectedBlocks.add(cb.value);
        else selectedBlocks.delete(cb.value);
    });
}

async function unblockOneRule(ip, ruleName) {
    await fetch('/api/unblock_rule', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip, rule_name: ruleName})});
    log(`🔓 Unblocked: ${ip}`);
    refreshBlockList();
}

async function manualBlock() {
    const input = document.getElementById('manualBlockInput');
    const raw = input.value.trim();
    if (!raw) return;
    // Split by comma, newline, space, or semicolon
    const ips = raw.split(/[,;\s\n]+/).map(s => s.trim()).filter(s => s.length > 0);
    if (ips.length === 0) return;

    const resp = await fetch('/api/block', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ips})});
    const d = await resp.json();
    const ok = Object.values(d.results || {}).filter(v => v).length;
    log(`🚫 Blocked ${ok}/${ips.length} IP(s)`);
    input.value = '';
    refreshBlockList();
}

// Legacy single unblock
async function unblockOne(ip) {
    await fetch('/api/unblock', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ips:[ip]})});
    log(`🔓 Unblocked: ${ip}`);
    refreshBlockList();
}

async function unblockSelectedBlocks() {
    if (selectedBlocks.size === 0) { alert('Select IPs to unblock'); return; }
    for (const val of selectedBlocks) {
        const cb = document.querySelector(`.block-cb[value="${val}"]`);
        const ip = cb ? cb.dataset.ip : val;
        await fetch('/api/unblock_rule', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip, rule_name: val})});
    }
    log(`🔓 Unblocked ${selectedBlocks.size} rule(s)`);
    refreshBlockList();
}

async function unblockAllBlocks() {
    if (!confirm('Unblock ALL IPs?')) return;
    await fetch('/api/unblock_all', {method:'POST'});
    log('🔓 All blocks removed');
    refreshBlockList();
}

// ─── Update Checker ───
let updateUrl = '';
async function checkUpdate() {
    try {
        const resp = await fetch('/api/update_check');
        const d = await resp.json();
        if (d.available) {
            updateUrl = d.download_url;
            document.getElementById('updateBanner').style.display = 'inline-block';
            document.getElementById('updateBanner').textContent = `🔄 v${d.latest} Available!`;
            log(`🔄 Update available: v${d.latest} — click the banner to download`);
        }
    } catch(e) {}
}
function openUpdate() {
    if (updateUrl) window.open(updateUrl, '_blank');
}

log('🛡️ NetGuard v5.1 ready — auto-starting monitor...');
// Auto-start monitoring on page load
setTimeout(() => toggleMonitor(), 500);
// Check for updates after 3 seconds
setTimeout(() => checkUpdate(), 3000);
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/monitor', methods=['POST'])
def api_monitor():
    global monitoring
    action = request.json.get('action', 'start')
    if action == 'start' and not monitoring:
        monitoring = True
        threading.Thread(target=monitor_loop, daemon=True).start()
        threading.Thread(target=ping_worker, daemon=True).start()
        threading.Thread(target=track_process_bandwidth, daemon=True).start()
        threading.Thread(target=port_map_updater, daemon=True).start()
        threading.Thread(target=packet_sniffer, daemon=True).start()
    elif action == 'stop':
        monitoring = False
    return jsonify({"monitoring": monitoring})

@app.route('/api/connections')
def api_connections():
    result = []
    with monitor_lock:
        for ip, info in session_ips.items():
            geo = ip_geo_cache.get(ip, {})
            ping_info = ip_ping_cache.get(ip, {})
            ports = sorted(info.get("ports", set()))
            protos = info.get("protos", set())
            proto_tag = ""
            if "UDP" in protos and "TCP" in protos:
                proto_tag = "TCP+UDP "
            elif "UDP" in protos:
                proto_tag = "UDP "
            port_str = proto_tag + ", ".join(str(p) for p in ports[:6])
            if len(ports) > 6:
                port_str += f" +{len(ports)-6}"

            proc = info.get("process", "")
            pid = info.get("pid")

            # Get bandwidth — prefer real sniffed bytes, fallback to process estimate
            bw_in = 0
            bw_out = 0
            if info.get("sniffed") and (info.get("bytes_in", 0) > 0 or info.get("bytes_out", 0) > 0):
                # Real per-IP bandwidth from packet sniffer
                bw_in = info.get("bytes_in", 0)
                bw_out = info.get("bytes_out", 0)
            elif pid and pid in process_bandwidth:
                pb = process_bandwidth[pid]
                my_hits = info.get("hit_count", 1)
                total_hits = sum(inf2.get("hit_count", 1)
                                 for i2, inf2 in session_ips.items()
                                 if inf2.get("pid") == pid and inf2.get("active"))
                if total_hits > 0:
                    weight = my_hits / total_hits
                    bw_in = pb.get("rate_read", 0) * weight
                    bw_out = pb.get("rate_write", 0) * weight

            ping_ms = ping_info.get("latency_ms")
            is_datacenter = geo.get("hosting", False)
            tz = geo.get("timezone", "")

            # Build location display: City, Country + timezone region
            loc_parts = []
            if geo.get("city"): loc_parts.append(geo["city"])
            if geo.get("region_name") and geo.get("region_name") != geo.get("city"):
                loc_parts.append(geo["region_name"])
            location_str = ", ".join(loc_parts) if loc_parts else ""

            result.append({
                "ip": ip,
                "ports": port_str,
                "country": geo.get("country", "??"),
                "country_name": geo.get("country_name", ""),
                "city": geo.get("city", ""),
                "location": location_str,
                "isp": geo.get("isp", ""),
                "flag": geo.get("flag", "❓"),
                "is_me": geo.get("is_me", False),
                "region": geo.get("region", "Other"),
                "hosting": is_datacenter,
                "org": geo.get("org", ""),
                "timezone": tz,
                "lat": geo.get("lat", 0),
                "lon": geo.get("lon", 0),
                "process": proc,
                "is_game": proc.lower() in GAME_PROCS,
                "active": info.get("active", False),
                "first_seen": info.get("first_seen", ""),
                "last_seen": info.get("last_seen", ""),
                "blocked": is_fw_blocked(ip),
                "hit_count": info.get("hit_count", 0),
                "ping": ping_ms,
                "bw_in": bw_in,
                "bw_out": bw_out,
            })
    return jsonify(result)

@app.route('/api/processes')
def api_processes():
    """Return active process summary with bandwidth."""
    result = {}
    with monitor_lock:
        for pname, pinfo in active_processes.items():
            total_read = 0
            total_write = 0
            for pid in pinfo.get("pids", []):
                if pid in process_bandwidth:
                    total_read += process_bandwidth[pid].get("rate_read", 0)
                    total_write += process_bandwidth[pid].get("rate_write", 0)
            result[pname] = {
                "connections": pinfo["count"],
                "rate_read": total_read,
                "rate_write": total_write,
            }
    return jsonify(result)

@app.route('/api/block', methods=['POST'])
def api_block():
    ips = request.json.get('ips', [])
    results = {}
    for ip in ips:
        ip = ip.strip()
        if not is_valid_ip_input(ip):
            results[ip] = False
            continue
        ok = fw_block(ip)
        if ok:
            blocked_ips.add(ip)
        results[ip] = ok
    save_blocked()
    return jsonify({"results": results})

@app.route('/api/unblock', methods=['POST'])
def api_unblock():
    ips = request.json.get('ips', [])
    for ip in ips:
        fw_unblock(ip)
        blocked_ips.discard(ip)
    save_blocked()
    return jsonify({"ok": True})

@app.route('/api/blocks')
def api_blocks():
    """Return ALL blocked IPs from Windows Firewall using PowerShell (language-independent)."""
    blocks = []
    seen_ips = set()

    # PowerShell: get all block rules with their names and remote addresses (works on any locale)
    try:
        ps_cmd = (
            'powershell -NoProfile -Command "'
            '$rules = Get-NetFirewallRule -Action Block -Enabled True -ErrorAction SilentlyContinue; '
            'if ($rules) { '
            '  foreach($r in $rules) { '
            '    $name = $r.DisplayName; '
            '    $addrs = ($r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress; '
            '    foreach($a in $addrs) { '
            '      if ($a -ne \'Any\' -and $a -ne \'LocalSubnet\' -and $a -ne \'*\') { '
            '        Write-Output \\"$name|||$a\\" '
            '      } '
            '    } '
            '  } '
            '}'
            '"'
        )
        result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if '|||' not in line:
                    continue
                name, ip_part = line.split('|||', 1)
                name = name.strip()
                ip_part = ip_part.strip()
                if not ip_part:
                    continue
                clean_ip = ip_part.split('/')[0] if '/32' in ip_part else ip_part
                if clean_ip in seen_ips:
                    continue
                seen_ips.add(clean_ip)

                # Lookup geo for display
                lookup_ip = clean_ip.split('-')[0].split('/')[0]
                geo = ip_geo_cache.get(lookup_ip, {})
                source = "NetGuard" if name.startswith(FIREWALL_RULE_PREFIX) else name
                blocks.append({
                    "ip": clean_ip,
                    "country": geo.get("country_name", "—"),
                    "cc": geo.get("cc", ""),
                    "city": geo.get("city", ""),
                    "region": geo.get("region", ""),
                    "isp": geo.get("isp", ""),
                    "rule_name": name,
                    "source": source,
                    "is_netguard": name.startswith(FIREWALL_RULE_PREFIX),
                })
    except Exception as e:
        print(f"[!] PowerShell firewall scan error: {e}")

    # Also include NetGuard's internal blocked_ips
    for ip in blocked_ips:
        if ip not in seen_ips:
            geo = ip_geo_cache.get(ip, {})
            blocks.append({
                "ip": ip,
                "country": geo.get("country_name", "—"),
                "cc": geo.get("cc", ""),
                "city": geo.get("city", ""),
                "region": geo.get("region", ""),
                "isp": geo.get("isp", ""),
                "rule_name": f"{FIREWALL_RULE_PREFIX}{ip.replace('.','_')}",
                "source": "NetGuard",
                "is_netguard": True,
            })

    return jsonify({"blocks": sorted(blocks, key=lambda x: x["ip"]), "total": len(blocks)})

@app.route('/api/firewall_rules')
def api_firewall_rules():
    """Read all NetGuard firewall rules from Windows Firewall."""
    rules = []
    try:
        result = subprocess.run(
            'netsh advfirewall firewall show rule name=all dir=out',
            shell=True, capture_output=True, text=True, timeout=15
        )
        current_rule = {}
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith('Rule Name:'):
                if current_rule and current_rule.get('name', '').startswith(FIREWALL_RULE_PREFIX):
                    rules.append(current_rule)
                current_rule = {'name': line.split(':', 1)[1].strip()}
            elif ':' in line and current_rule:
                key, val = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                current_rule[key] = val.strip()
        if current_rule and current_rule.get('name', '').startswith(FIREWALL_RULE_PREFIX):
            rules.append(current_rule)
    except:
        pass
    return jsonify({"rules": rules, "total": len(rules)})

@app.route('/api/unblock_rule', methods=['POST'])
def api_unblock_rule():
    """Unblock by rule name (works for any firewall rule, not just NetGuard's)."""
    rule_name = request.json.get('rule_name', '')
    ip = request.json.get('ip', '')
    if rule_name:
        safe_name = sanitize_rule_name(rule_name)
        if safe_name:
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={safe_name}'],
                capture_output=True, text=True, timeout=10
            )
        if ip and is_valid_ip_input(ip):
            blocked_ips.discard(ip)
            fw_unblock(ip)
            save_blocked()
    return jsonify({"ok": True})

@app.route('/api/unblock_all', methods=['POST'])
def api_unblock_all():
    """Unblock ALL firewall block rules (NetGuard + any others)."""
    count = 0
    # First: unblock all NetGuard tracked IPs
    for ip in list(blocked_ips):
        fw_unblock(ip)
        blocked_ips.discard(ip)
        count += 1
    save_blocked()

    # Second: use PowerShell to find and remove ALL block rules
    try:
        ps_cmd = (
            'powershell -NoProfile -Command "'
            'Get-NetFirewallRule -Action Block -Enabled True -ErrorAction SilentlyContinue | '
            'ForEach-Object { Write-Output $_.Name }'
            '"'
        )
        result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True, timeout=20)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                rule_id = line.strip()
                if rule_id:
                    subprocess.run(
                        ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_id}'],
                        capture_output=True, text=True, timeout=10
                    )
                    count += 1
    except:
        pass

    return jsonify({"ok": True, "unblocked": count})

@app.route('/api/clear', methods=['POST'])
def api_clear():
    global session_ips, sniffed_ips
    with monitor_lock:
        session_ips = {}
    with sniffer_lock:
        sniffed_ips = {}
    return jsonify({"ok": True})

@app.route('/api/update_check')
def api_update_check():
    """Return update status."""
    return jsonify(update_info)

@app.route('/api/version')
def api_version():
    """Return current version."""
    return jsonify({"version": VERSION})

@app.route('/api/fw_debug')
def api_fw_debug():
    """Debug: test PowerShell firewall query and show raw output."""
    try:
        ps_script = (
            'Get-NetFirewallRule -Action Block -Enabled True -ErrorAction SilentlyContinue | '
            'Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | '
            'Select-Object -ExpandProperty RemoteAddress | '
            'Where-Object { $_ -ne "Any" -and $_ -ne "LocalSubnet" -and $_ -ne "*" } | '
            'Sort-Object -Unique'
        )
        result = subprocess.run(
            ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
            capture_output=True, text=True, timeout=30
        )
        # Test matching against a sample IP
        test_ip = request.args.get('test', '')
        test_result = is_fw_blocked(test_ip) if test_ip else None
        return jsonify({
            "returncode": result.returncode,
            "stdout": result.stdout[:5000],
            "stderr": result.stderr[:2000],
            "blocked_ips_internal": list(blocked_ips)[:50],
            "all_fw_blocked_count": len(all_fw_blocked),
            "all_fw_networks_count": len(all_fw_networks),
            "all_fw_ranges_count": len(all_fw_ranges),
            "all_fw_blocked_sample": list(all_fw_blocked)[:20],
            "all_fw_networks": [str(n) for n in all_fw_networks],
            "all_fw_ranges": [f"{ipaddress.ip_address(s)}-{ipaddress.ip_address(e)}" for s, e in all_fw_ranges],
            "test_ip": test_ip,
            "test_blocked": test_result,
        })
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/sniffer_status')
def api_sniffer_status():
    with sniffer_lock:
        count = len(sniffed_ips)
        total_packets = sum(s["packet_count"] for s in sniffed_ips.values())
    return jsonify({"active": sniffer_active, "ips_found": count, "total_packets": total_packets})

@app.route('/api/shutdown', methods=['POST'])
def api_shutdown():
    """Shutdown NetGuard from the dashboard."""
    global monitoring
    monitoring = False
    save_blocked()
    func = request.environ.get('werkzeug.server.shutdown')
    if func:
        func()
    else:
        # Force exit after response
        threading.Timer(0.5, lambda: os._exit(0)).start()
    return jsonify({"ok": True, "message": "NetGuard shutting down..."})

if __name__ == '__main__':
    try:
        load_blocked()
        print(f"""
    ╔══════════════════════════════════════╗
    ║  🛡️  NetGuard v4.0                   ║
    ║  Game Network Monitor & IP Blocker   ║
    ║  Designed by WillyNilly              ║
    ║                                      ║
    ║  🎮 Process Filter                   ║
    ║  📡 Live Ping / Latency (ICMP)       ║
    ║  🌍 Region Filter                    ║
    ║  📊 Bandwidth Tracking               ║
    ║  ☁️  Cloud IP Range Detection         ║
    ║                                      ║
    ║  Open: http://localhost:{PORT}          ║
    ║  Press Ctrl+C to stop                ║
    ╚══════════════════════════════════════╝
        """)
        # Load cloud IP ranges in background (Google Cloud + AWS)
        print("[*] Loading cloud provider IP ranges...")
        threading.Thread(target=load_cloud_ip_ranges, daemon=True).start()

        # Hide console window after 2 seconds (let it show startup info briefly)
        threading.Timer(2.0, hide_console).start()

        threading.Timer(1.5, lambda: open_app_window(PORT)).start()
        app.run(host='127.0.0.1', port=PORT, debug=False, use_reloader=False)
    except Exception as e:
        print(f"\n{'='*50}")
        print(f"[ERROR] NetGuard crashed!")
        print(f"{'='*50}")
        print(f"\n{type(e).__name__}: {e}\n")
        import traceback
        traceback.print_exc()
        print(f"\n{'='*50}")
        input("\nPress Enter to close...")
