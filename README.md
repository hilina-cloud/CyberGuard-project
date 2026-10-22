# CyberGuard-project
CyberGuard is a Python and Flask-based Linux authentication log analyzer that detects suspicious login patterns, generates security alerts, and visualizes results through a local web dashboard.
# CyberGuard — Linux Log Threat Detection and Monitoring System

CyberGuard is an educational cybersecurity project designed to simplify the analysis of Linux authentication logs. It uses Python and Flask to process log data, identify potentially suspicious login activity, and present findings through a local web-based dashboard.

## Features

- **Authentication Log Analysis:** Analyze supported Linux authentication log entries.
- **Suspicious Login Detection:** Identify repeated failed login attempts and successful logins following multiple failures.
- **Security Alerts:** Generate alerts based on predefined detection rules and severity thresholds.
- **Interactive Dashboard:** View summary metrics, alerts, and individual authentication events.
- **Event Filtering:** Explore analyzed events more efficiently.
- **CSV Export:** Export results for further analysis and reporting.
- **Local Execution:** Run the application locally for learning, testing, and demonstration.

## Technologies

- Python
- Flask
- HTML, CSS, and JavaScript
- Linux authentication logs
- CSV
- Python unit testing

## Purpose

The goal of CyberGuard is to make authentication log analysis more accessible to cybersecurity students and beginners. It demonstrates how log parsing, rule-based threat detection, and web-based visualization can be combined in a practical security tool.

## Disclaimer

CyberGuard is an educational prototype, not a production SIEM or a real-time intrusion detection system. Its alerts indicate patterns that may require investigation and do not prove that an attack has occurred. Use only log data you are authorized to access.

In the future - Potential enhancements include broader log-format support, configurable detection thresholds, improved testing, and additional monitoring capabilities.
