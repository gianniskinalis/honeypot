import re
import json
from collections import Counter
from datetime import datetime

SSH_LOG = 'logs/ssh_honeypot.log'
HTTP_LOG = 'logs/http_honeypot.log'
REPORT_FILE = 'logs/ioc_report.txt'

def parse_ssh_logs():
    ips = []
    credentials = []
    usernames = []
    passwords = []

    with open(SSH_LOG, 'r') as f:
        for line in f:
            # Extract IPs from connection lines
            ip_match = re.search(r'SSH connection received from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ips.append(ip_match.group(1))

            # Extract credentials from attempt lines
            cred_match = re.search(r'SSH attempt \| IP: (\d+\.\d+\.\d+\.\d+) \| Username: (.+?) \| Password: (.+)', line)
            if cred_match:
                ip = cred_match.group(1)
                username = cred_match.group(2).strip()
                password = cred_match.group(3).strip()
                credentials.append((ip, username, password))
                usernames.append(username)
                passwords.append(password)

    return ips, credentials, usernames, passwords

def parse_http_logs():
    ips = []
    paths = []
    user_agents = []

    with open(HTTP_LOG, 'r') as f:
        for line in f:
            # Extract IPs from connection lines
            ip_match = re.search(r'HTTP connection received from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ips.append(ip_match.group(1))

            # Extract request details
            req_match = re.search(r'HTTP request \| IP: (\d+\.\d+\.\d+\.\d+) \| Request: (.+?) \| User-Agent: (.+?) \| Host:', line)
            if req_match:
                ip = req_match.group(1)
                request = req_match.group(2).strip()
                user_agent = req_match.group(3).strip()
                ips.append(ip)
                user_agents.append(user_agent)

                # Extract path from request line (e.g. GET /admin HTTP/1.1)
                path_match = re.search(r'\w+ (.+?) HTTP', request)
                if path_match:
                    paths.append(path_match.group(1))

    return ips, paths, user_agents

def generate_report():
    print("[*] Parsing SSH logs...")
    ssh_ips, credentials, usernames, passwords = parse_ssh_logs()

    print("[*] Parsing HTTP logs...")
    http_ips, paths, user_agents = parse_http_logs()

    print("[*] Generating report...")

    all_ssh_ips = Counter(ssh_ips)
    all_http_ips = Counter(http_ips)
    top_usernames = Counter(usernames)
    top_passwords = Counter(passwords)
    top_paths = Counter(paths)
    top_agents = Counter(user_agents)

    report = []
    report.append("=" * 60)
    report.append("        HONEYPOT IOC REPORT")
    report.append(f"        Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    report.append("=" * 60)

    report.append("\n[SSH SUMMARY]")
    report.append(f"  Total SSH connections : {len(ssh_ips)}")
    report.append(f"  Total login attempts  : {len(credentials)}")
    report.append(f"  Unique attacker IPs   : {len(all_ssh_ips)}")

    report.append("\n[TOP 10 SSH ATTACKER IPs]")
    for ip, count in all_ssh_ips.most_common(10):
        report.append(f"  {ip:<20} {count} attempts")

    report.append("\n[TOP 10 USERNAMES TRIED]")
    for username, count in top_usernames.most_common(10):
        report.append(f"  {username:<30} {count} times")

    report.append("\n[TOP 10 PASSWORDS TRIED]")
    for password, count in top_passwords.most_common(10):
        report.append(f"  {password:<30} {count} times")

    report.append("\n[HTTP SUMMARY]")
    report.append(f"  Total HTTP connections : {len(http_ips)}")
    report.append(f"  Unique attacker IPs    : {len(set(http_ips))}")

    report.append("\n[TOP 10 HTTP ATTACKER IPs]")
    for ip, count in all_http_ips.most_common(10):
        report.append(f"  {ip:<20} {count} requests")

    report.append("\n[TOP 10 PROBED PATHS]")
    for path, count in top_paths.most_common(10):
        report.append(f"  {path:<40} {count} times")

    report.append("\n[TOP 10 USER AGENTS]")
    for agent, count in top_agents.most_common(10):
        report.append(f"  {agent[:50]:<50} {count} times")

    report.append("\n[ALL UNIQUE ATTACKER IPs - SSH]")
    for ip in sorted(all_ssh_ips.keys()):
        report.append(f"  {ip}")

    report.append("\n[ALL UNIQUE ATTACKER IPs - HTTP]")
    for ip in sorted(set(http_ips)):
        report.append(f"  {ip}")

    report.append("\n" + "=" * 60)
    report.append("        END OF REPORT")
    report.append("=" * 60)

    report_text = '\n'.join(report)
    print(report_text)

    with open(REPORT_FILE, 'w') as f:
        f.write(report_text)

    print(f"\n[*] Report saved to {REPORT_FILE}")

if __name__ == '__main__':
    generate_report()
