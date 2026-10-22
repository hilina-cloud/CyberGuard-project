import re
from collections import Counter

FAILED_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.I),
    re.compile(r"authentication failure.*rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*user=(?P<user>\S+)", re.I),
]
SUCCESS_PATTERNS = [
    re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.I),
]
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SAMPLE_LOG = """Oct 21 09:12:01 kali sshd[2101]: Failed password for admin from 203.0.113.44 port 42111 ssh2
Oct 21 09:12:04 kali sshd[2102]: Failed password for admin from 203.0.113.44 port 42112 ssh2
Oct 21 09:12:07 kali sshd[2103]: Failed password for root from 203.0.113.44 port 42113 ssh2
Oct 21 09:12:10 kali sshd[2104]: Failed password for invalid user guest from 203.0.113.44 port 42114 ssh2
Oct 21 09:12:14 kali sshd[2105]: Failed password for test from 198.51.100.27 port 42115 ssh2
Oct 21 09:13:02 kali sshd[2106]: Accepted publickey for student from 192.0.2.18 port 42120 ssh2
Oct 21 09:14:41 kali sudo: student : TTY=pts/0 ; PWD=/home/student ; USER=root ; COMMAND=/usr/bin/id
Oct 21 09:15:10 kali sshd[2107]: Failed password for admin from 203.0.113.44 port 42116 ssh2
Oct 21 09:15:12 kali sshd[2108]: Accepted password for admin from 203.0.113.44 port 42117 ssh2
Oct 21 09:16:01 kali sshd[2109]: Invalid user oracle from 198.51.100.27
This is a sample malformed/unrecognized line for parser demonstration.
"""

def classify_line(line, line_no):
    for pattern in FAILED_PATTERNS:
        match = pattern.search(line)
        if match:
            return {
                "line": line_no, "event": "Failed login", "severity": "HIGH",
                "ip": match.group("ip"), "user": match.group("user"),
                "details": line.strip()
            }
    for pattern in SUCCESS_PATTERNS:
        match = pattern.search(line)
        if match:
            return {
                "line": line_no, "event": "Successful login", "severity": "INFO",
                "ip": match.group("ip"), "user": match.group("user"),
                "details": line.strip()
            }
    if re.search(r"invalid user", line, re.I):
        ip_match = IP_RE.search(line)
        return {
            "line": line_no, "event": "Invalid user", "severity": "MEDIUM",
            "ip": ip_match.group(0) if ip_match else "Unknown",
            "user": "Unknown", "details": line.strip()
        }
    if re.search(r"\bsudo\b.*COMMAND=", line, re.I):
        return {
            "line": line_no, "event": "Privilege command", "severity": "LOW",
            "ip": "Local", "user": "Unknown", "details": line.strip()
        }
    return None

def analyze_text(text):
    events = []
    for idx, line in enumerate(text.splitlines(), start=1):
        event = classify_line(line, idx)
        if event:
            events.append(event)

    failures_by_ip = Counter(e["ip"] for e in events if e["event"] == "Failed login")
    failed_user_counts = Counter(e["user"] for e in events if e["event"] == "Failed login")
    successful = [e for e in events if e["event"] == "Successful login"]
    alerts = []

    for ip, count in failures_by_ip.items():
        if ip != "Unknown" and count >= 3:
            alerts.append({
                "severity": "CRITICAL" if count >= 5 else "HIGH",
                "title": "Repeated failed logins",
                "source": ip,
                "count": count,
                "description": f"{count} failed login attempts were detected from {ip}."
            })

    for success in successful:
        prior_failures = sum(
            1 for e in events
            if e["event"] == "Failed login" and e["ip"] == success["ip"] and e["line"] < success["line"]
        )
        if prior_failures >= 3:
            alerts.append({
                "severity": "CRITICAL",
                "title": "Success after repeated failures",
                "source": success["ip"],
                "count": prior_failures,
                "description": f"A successful login from {success['ip']} occurred after {prior_failures} failed attempt(s) earlier in this file."
            })

    alerts.sort(key=lambda a: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(a["severity"], 4))
    return {
        "events": events,
        "alerts": alerts,
        "total_lines": len(text.splitlines()),
        "recognized": len(events),
        "failed": sum(1 for e in events if e["event"] == "Failed login"),
        "successful": len(successful),
        "unique_ips": len(set(e["ip"] for e in events if e["ip"] not in ("Unknown", "Local"))),
        "failures_by_ip": dict(failures_by_ip),
        "failed_user_counts": dict(failed_user_counts),
    }

