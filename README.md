# SOC Log Analyzer 🔐

A Python-based Security Operations Center (SOC) log analysis tool for parsing, correlating, and investigating security events from multiple log sources.

## 🚀 Features

- Automatic log type detection
- Linux authentication and system log analysis
- SSH login and authentication analysis
- Successful and failed login detection
- Invalid user detection
- Brute-force and rapid authentication detection
- Suspicious IP identification and classification
- Per-IP risk scoring
- Security findings with supporting evidence
- Ground-truth detection matching
- System, CRON, SYSTEMD and KERNEL event analysis
- Apache / Nginx web request analysis
- HTTP status code analysis
- Suspicious URL and request detection
- Mail / Postfix event analysis
- DNS event analysis
- Firewall event analysis
- Database event analysis
- JSON / NDJSON and CSV log support
- Parsing coverage and unparsed-line tracking
- Large-file streaming analysis
- Processing time and throughput statistics
- Automatic security report generation

## 🔍 Security Detection

The analyzer correlates multiple indicators instead of relying on a single event.

It can identify patterns such as:

- Authentication failures
- Invalid usernames
- Repeated login failures
- Brute-force behaviour
- Rapid authentication attempts
- Suspicious web requests
- Suspicious URLs
- Error-heavy request activity
- Suspicious IP behaviour

Suspicious activity is investigated per IP and assigned a risk score and severity level:

- 🟢 LOW
- 🟡 MEDIUM
- 🔴 HIGH

Each finding includes supporting evidence to help with investigation.

## 📂 Supported Log Sources

The analyzer supports common security and system log sources including:

- Linux authentication logs
- Syslog / system logs
- SSH logs
- Apache / Nginx access logs
- Postfix / mail logs
- DNS logs
- Firewall events
- Database logs
- JSON / NDJSON logs
- CEF-style security events
- CSV-based logs

## 🧪 Quick Test

A medium-sized mixed sample log is included in the repository.

After cloning the repository, run:

python3 analyzer.py sample.log

No external log download is required for the basic demonstration.

The included sample contains:

- SSH authentication events
- Failed logins
- Invalid users
- Brute-force activity
- System events
- CRON activity
- Sudo activity
- Mail events
- DNS events
- Nginx requests
- Suspicious web requests
- Normal traffic

## ⚙️ Usage

Analyze the included sample:

python3 analyzer.py sample.log

Analyze another log file:

python3 analyzer.py /path/to/logfile

The analyzer displays the analysis in the terminal and generates:

report.txt

## 📊 Analysis Output

The analyzer provides structured sections including:

- Analysis Summary
- IP Classification
- IP Investigation
- System / Authentication Events
- Authentication Methods
- Mail / SMTP / IMAP Events
- DNS Events
- Security Findings
- Security Assessment
- Unparsed Logs
- Recommendations
- Processing Statistics

The report can include:

- Total lines processed
- Parsed events
- Authentication events
- Unique IP addresses
- Unique URLs
- HTTP status codes
- Suspicious IPs
- Risk scores
- Security findings
- Supporting evidence
- Parse coverage
- Processing time
- Throughput

## 📈 Large Log Analysis

The analyzer is designed to process large log files using streaming-style processing.

It has been tested against multi-million-line datasets and can report:

- Total lines processed
- Recognized events
- Unknown / unparsed lines
- Parse coverage
- Input size
- Processing time
- Processing throughput

## 📁 Project Structure

SOC-Log-Analyzer/
├── analyzer.py
├── README.md
├── sample.log
└── .gitignore

## 🛠️ Requirements

- Python 3
- Linux / Kali Linux recommended

The basic analyzer does not require an external database or SIEM platform.

## 🎯 Project Purpose

This project was developed as a practical SOC / Blue Team learning project to understand how raw security logs can be parsed, correlated, investigated, and converted into actionable security findings.

## ⚠️ Disclaimer

The included sample log is intended for testing and demonstration purposes.

Risk scores and detections are analytical indicators and should be validated against the surrounding environment, additional telemetry, and organizational security context before taking action.
