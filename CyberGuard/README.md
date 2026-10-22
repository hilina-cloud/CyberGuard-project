# CyberGuard — Linux Threat Monitoring & Log Analysis

## Features
- Upload and parse text-based Linux/OpenSSH authentication logs (max 2 MB).
- Detect failed logins, successful logins, invalid-user messages, and sudo command entries.
- Alert on repeated failures from one source and success following repeated failures.
- Filter parsed events and export alerts to CSV.
- Includes a built-in sample dataset so the demo works without privileged log access.

## Run on Kali Linux
```bash
cd ~/Desktop/CyberGuard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 in Firefox. Keep the terminal open.

## Run tests
```bash
python -m unittest discover -s tests -v
```

## Using a real log
On Kali/Debian systems, authentication messages may be available in `/var/log/auth.log`; other systems may use journald. Access may require elevated privileges. To avoid running the web app as root, copy a log you are authorized to inspect to your project folder, for example:
```bash
sudo cp /var/log/auth.log ./auth-sample.log
sudo chown "$USER":"$USER" ./auth-sample.log
```
Then upload `auth-sample.log` through the dashboard. If that file does not exist, use `journalctl` to inspect authentication-related service logs where available, or use the included sample.

## Important limitations
- Rules are heuristic examples, not a complete intrusion detection system.
- OpenSSH log formats vary; only supported patterns are recognized.
- Sample IPs use documentation ranges and do not identify real attackers.
- The currently loaded log is held in server memory for this local single-user demo; it is replaced when a new file or sample is loaded and clears on restart. Do not use sensitive logs or expose the development app. For production, use authenticated server-side storage, CSRF protection, robust session management, secret management, and access controls.
- App binds to 127.0.0.1 and debug mode is disabled.

## Project title
CyberGuard: Linux Log Threat Detection and Monitoring System
