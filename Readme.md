# SOC Log Analyzer 🔐

A beginner-friendly SOC (Security Operations Center) log analysis tool built using Python.

This tool analyzes log files and helps detect suspicious login activity.

## Features

- Detects failed login attempts
- Counts successful logins
- Identifies suspicious IP activity
- Detects top attacker IP
- Assigns risk levels (Low, Medium, High)
- Generates a security report

## Technologies Used

- Python
- Kali Linux

## How to Run

Run the following command:

```bash
python analyzer.py
```

Then enter the log file path:

```text
logs/sampple_logs.txt
```

## Example Output

```text
===== ANALYSIS REPORT =====

Total Failed Logins: 5
Total Successful Logins: 3

⚠️ Alert: Multiple failed login attempts detected.

===== Suspicious IP Activity =====

192.168.1.15 --> 3 failed attempts

🚨 Top Attacker IP: 192.168.1.15

===== RISK LEVEL =====
Risk: HIGH
```

## Project Goal

This project was created to practice SOC concepts such as:

- Log Analysis
- Incident Detection
- Suspicious Activity Monitoring
- Brute Force Detection

---

Created by **Darshan Mishra**
