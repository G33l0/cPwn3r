# cPwn3r – Red Team cPanel Exploitation Framework

**cPwn3r** is a modular, multi-threaded framework designed for authorised red‑team engagements targeting cPanel & WHM hosting platforms. It combines port scanning, vulnerability detection, session hijacking, email harvesting, log cleaning, and C2 reporting into a single command‑line tool.

> **FOR AUTHORISED TESTING ONLY.** Unauthorised access to computer systems is illegal. Use this tool solely on infrastructure you own or have explicit written permission to test.

---

## Key Features

- **Multi‑vector exploitation** – attempts GraphQL injection (cPanel v120+) and legacy `Authorization` header bypass.
- **Intelligent scanning** – IPv4/IPv6 port scanning across standard cPanel ports (2082, 2083, 2086, 2087, 2095, 2096).
- **Session persistence** – stores and re‑uses valid tokens (`sessions.json`) across runs.
- **Email extraction** – pulls account email lists from cPanel/WHM APIs, with WHOIS fallback.
- **Telegram C2** – sends result summaries and full email lists as attachments.
- **Post‑exploitation** – list accounts, clean bandwidth logs, and create backdoor users (WHM ports).
- **Thread‑safe database** – SQLite with WAL mode for reliable state tracking.
- **Graceful fallbacks** – uses `curl_cffi` for TLS impersonation if available, otherwise falls back to `requests`.

---

## Installation

### Prerequisites
- Python 3.8+
- pip
- Git

### Clone & Setup
```bash
git clone https://github.com/g33l0/cPwn3r.git
cd cPwn3r
pip install -r requirements.txt
```

Dependencies

· requests / curl_cffi
· colorama, pyfiglet, tqdm
· python-whois, shodan (optional)
· filelock

On Alpine Linux (iSH):

```bash
apk add python3 py3-pip build-base libffi-dev openssl-dev
pip install -r requirements.txt
```

---

Usage

Basic Workflow

1. Add targets – load from file, add single host, or use Shodan discovery.
2. Scan – discover open cPanel ports.
3. Exploit – attempt all exploit methods and extract emails.
4. Export / Report – save results or send via Telegram.

Command‑line Interface

```bash
python3 cpwn3r.py
```

Follow the interactive menu:

```
[ MAIN MENU ]
1. Load targets from file
2. Add single target
3. Shodan discovery
4. Scan targets
5. Exploit & extract emails
6. Configure Telegram C2
7. Export results
8. Send results via Telegram
9. Clean logs (post-exploit)
10. Toggle debug mode
11. Post-exploit actions
12. Exit
```

Environment Variables

· SHODAN_API_KEY – for Shodan discovery.
· TELEGRAM_BOT_TOKEN – Telegram bot token.
· TELEGRAM_CHAT_ID – Telegram chat ID.

---

File Structure

```
cPwn3r/
├── cpwn3r.py              # Main script
├── targets.db             # SQLite database (created at runtime)
├── sessions.json          # Stored session tokens
├── results.json           # Exported results
├── emails.txt             # Extracted email addresses
└── requirements.txt       # Python dependencies
```

---

Legal Disclaimer

This software is provided as‑is for educational and authorised security testing purposes. The authors assume no liability for any misuse or damage caused by this tool. By using this software, you agree to:

· Only use it on systems you own or have explicit permission to test.
· Comply with all applicable laws and regulations.
· Not use it for any malicious or unauthorised activities.

---

How It Works (Technical Overview)

1. Discovery – Shodan or manual input adds targets to the database.
2. Scanning – Multi‑threaded TCP connect scans for open cPanel ports.
3. Version Detection – Attempts to fetch cPanel version via /json-api/version, /version, or HTML banner.
4. Exploitation:
   · GraphQL – probes /graphql with a malformed introspection query to leak the session cookie (cPanel v120+).
   · Legacy – injects a crafted Authorization: Basic header to bypass authentication.
5. Session Reuse – stored tokens are validated and reused, avoiding repeated exploitation.
6. Email Extraction – uses cPanel/WHM APIs to list accounts and build email lists.
7. Reporting – exports JSON and plain‑text email lists; Telegram sends a summary plus the full file.

---

Contributing

Pull requests and issue reports are welcome. Please ensure changes maintain compatibility with Alpine Linux and iSH.

---

License

This project is released under the MIT License. See LICENSE for details.

---

Acknowledgements

· Inspired by various red‑team tools and cPanel security research.
· Thanks to the open‑source community for the underlying libraries.

---

Remember: With great power comes great responsibility. Use this tool wisely.
