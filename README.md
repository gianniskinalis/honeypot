# Python Honeypot — SSH & HTTP Threat Capture System

A custom-built, internet-facing honeypot deployed on a cloud VPS that captures real-world attack traffic across SSH and HTTP protocols. Built from scratch in Python with no off-the-shelf honeypot frameworks.

## Live Deployment Results (48 hours)

| Metric | Value |
|--------|-------|
| SSH connections | 30,243 |
| SSH login attempts | 29,124 |
| Unique SSH attackers | 542 |
| HTTP connections | 14,321 |
| Unique HTTP attackers | 398 |
| Total attack interactions | 75,160+ |

> First attack attempt received within **30 seconds** of going live.

## What It Does

- **SSH Honeypot** — Listens on port 22, emulates a real SSH server using `paramiko`, logs every credential attempt without granting access
- **HTTP Honeypot** — Listens on port 80, mimics an Apache Ubuntu server, logs every request path, User-Agent, and probe attempt
- **IOC Extractor** — Parses both log files and generates a structured threat intelligence report including top attacker IPs, most tried credentials, probed paths, and scanning tools identified

## Project Structure
```
honeypot/
├── main.py              # Launches both honeypots simultaneously
├── ssh_honeypot.py      # Custom SSH server (paramiko)
├── http_honeypot.py     # Custom HTTP server (raw sockets)
├── ioc_extractor.py     # Log parser and IOC report generator
├── sample_ioc_report.txt # Real data captured from live deployment
└── logs/                # Live log files (gitignored)
```

## Sample Findings

**Top attacked credentials:**
- Most tried username: `root` (27,920 times)
- Most tried password: `123456` (58 times)
- Credentials from leaked databases observed (e.g. complex passwords replayed from breaches)

**Top probed HTTP paths:**
- `/.env` — attackers hunting for exposed API keys and database credentials
- `/wp-content/plugins/hellopress/wp_filemanager.php` — WordPress exploit attempt
- `/gptsh.php`, `/bolt.php` — web shell upload attempts

**Notable attacker behavior:**
- Single IP (`46.62.145.156`) responsible for 23,205 of 30,243 SSH attempts
- Microsoft Azure IPs (`20.x.x.x`) used for automated HTTP scanning
- 542 unique IPs from across the world targeting port 22 within 48 hours

## Tech Stack

- **Python 3** — core language
- **paramiko** — SSH protocol implementation
- **socket / threading** — raw HTTP server and concurrent connection handling
- **re / collections.Counter** — log parsing and IOC extraction
- **systemd** — deployed as a persistent background service on Ubuntu 24.04
- **Hetzner VPS** — cloud deployment (Helsinki, Finland)

## How to Run

### Requirements
```bash
pip install paramiko
```

### Start the honeypot
```bash
python3 main.py
```

### Generate IOC report
```bash
python3 ioc_extractor.py
```

## Legal & Ethical Notice
This honeypot was deployed on a personally owned cloud VPS for educational and portfolio purposes. No offensive actions were taken against any systems. All data collected consists of unsolicited inbound attack traffic.

## Author
**Giannis Kinalis**
*Cybersecurity Enthusiast*
- **GitHub:** [gianniskinalis](https://github.com/gianniskinalis)
- **LinkedIn:** [Ioannis Kinalis](https://linkedin.com/in/ioannis-kinalis)
