import re
import gzip
import shlex
import sys
import ipaddress
import json
import csv
import time
import os
from datetime import datetime
from collections import Counter, defaultdict
from urllib.parse import unquote


# ============================================================
# SOC LOG ANALYZER
# ============================================================

AUTHOR = "Darshan Mishra"  # source metadata only; not printed
BOX_WIDTH = 100


# ============================================================
# TERMINAL / TABLE HELPERS
# ============================================================

def print_box(title, width=BOX_WIDTH):
    print("┌" + "─" * (width - 2) + "┐")
    print("│" + f" {title} ".center(width - 2) + "│")
    print("└" + "─" * (width - 2) + "┘")


def make_box(title, width=BOX_WIDTH):
    return "\n".join([
        "┌" + "─" * (width - 2) + "┐",
        "│" + f" {title} ".center(width - 2) + "│",
        "└" + "─" * (width - 2) + "┘"
    ])


def print_table(headers, rows, widths):
    top = "┌" + "┬".join("─" * (w + 2) for w in widths) + "┐"
    middle = "├" + "┼".join("─" * (w + 2) for w in widths) + "┤"
    bottom = "└" + "┴".join("─" * (w + 2) for w in widths) + "┘"

    def format_row(values):
        cells = []

        for value, width in zip(values, widths):
            text = str(value)

            if len(text) > width:
                text = text[:width - 1] + "…"

            cells.append(f" {text:<{width}} ")

        return "│" + "│".join(cells) + "│"

    print(top)
    print(format_row(headers))
    print(middle)

    for row in rows:
        print(format_row(row))

    print(bottom)


def make_table(headers, rows, widths):
    lines = []

    top = "┌" + "┬".join("─" * (w + 2) for w in widths) + "┐"
    middle = "├" + "┼".join("─" * (w + 2) for w in widths) + "┤"
    bottom = "└" + "┴".join("─" * (w + 2) for w in widths) + "┘"

    def format_row(values):
        cells = []

        for value, width in zip(values, widths):
            text = str(value)

            if len(text) > width:
                text = text[:width - 1] + "…"

            cells.append(f" {text:<{width}} ")

        return "│" + "│".join(cells) + "│"

    lines.append(top)
    lines.append(format_row(headers))
    lines.append(middle)

    for row in rows:
        lines.append(format_row(row))

    lines.append(bottom)

    return "\n".join(lines)


def percentage(count, total):
    if total == 0:
        return "0.00%"

    return f"{count / total * 100:.2f}%"


# ============================================================
# PROGRESS / STATUS DISPLAY
# ============================================================

STATUS_ACTIVE = False
PROGRESS_TOTAL_LINES = None
PROGRESS_LAST = -1
PROGRESS_WIDTH = 32


def show_status(message):
    global STATUS_ACTIVE

    if sys.stdout.isatty():
        print("\r\033[2K" + message, end="", flush=True)
        STATUS_ACTIVE = True


def clear_status_line():
    global STATUS_ACTIVE

    if STATUS_ACTIVE and sys.stdout.isatty():
        print("\r\033[2K", end="", flush=True)

    STATUS_ACTIVE = False


def estimate_total_lines(path):
    """Estimate total lines from a small sample without a second full scan."""
    sample_limit = 256 * 1024
    try:
        if path.lower().endswith(".gz"):
            compressed_sample = 0
            with open(path, "rb") as raw:
                compressed_sample = len(raw.read(sample_limit))
            with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as gz:
                sample = gz.read(sample_limit)
            if not sample:
                return 0
            line_count = sample.count("\n") or 1
            decompressed_bytes = len(sample.encode("utf-8", errors="ignore"))
            if compressed_sample and decompressed_bytes:
                compressed_size = os.path.getsize(path)
                estimated_decompressed = compressed_size * (decompressed_bytes / compressed_sample)
                avg_line = decompressed_bytes / line_count
                return max(1, int(estimated_decompressed / avg_line))
            return None
        with open(path, "rb") as file:
            sample = file.read(sample_limit)
        if not sample:
            return 0
        line_count = sample.count(b"\n") or 1
        avg_line_bytes = len(sample) / line_count
        return max(1, int(os.path.getsize(path) / avg_line_bytes))
    except (OSError, EOFError, ValueError, ZeroDivisionError):
        return None


def progress_bar(percent):
    percent = max(0.0, min(100.0, percent))
    filled = int(PROGRESS_WIDTH * percent / 100)
    return "[" + "█" * filled + "░" * (PROGRESS_WIDTH - filled) + "]"


def show_progress(line_number):
    global PROGRESS_LAST
    if not sys.stdout.isatty():
        return
    if PROGRESS_TOTAL_LINES is None:
        return
    if line_number != PROGRESS_TOTAL_LINES and line_number - PROGRESS_LAST < 50000:
        return
    percent = (line_number / PROGRESS_TOTAL_LINES) * 100 if PROGRESS_TOTAL_LINES else 100.0
    percent = min(percent, 99.9)
    show_status(f"Analyzing log data... {progress_bar(percent)} {percent:5.1f}%")
    PROGRESS_LAST = line_number


# ============================================================
# FILE READER
# ============================================================

def read_log_file(path):
    """Stream log lines instead of loading the entire file into RAM."""

    try:
        if path.lower().endswith(".gz"):
            with gzip.open(
                path,
                "rt",
                encoding="utf-8",
                errors="ignore"
            ) as file:
                for line in file:
                    yield line
        else:
            with open(
                path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:
                for line in file:
                    yield line

    except FileNotFoundError:
        clear_status_line()
        print("\n❌ File not found.")
        sys.exit(1)

    except OSError as error:
        clear_status_line()
        print(
            f"\n❌ Unable to read file: {error}"
        )
        sys.exit(1)


# ============================================================
# INPUT
# ============================================================

print("\n" + "=" * BOX_WIDTH)
print(" " * 31 + "SOC LOG ANALYZER")
print("=" * BOX_WIDTH)


if len(sys.argv) > 1:

    # Allows:
    # python3 analyzer.py file.log
    #
    # Also handles a path containing spaces.
    log_file = " ".join(sys.argv[1:]).strip()

else:

    log_file = input(
        "Enter log file path: "
    ).strip()


if not log_file:

    print(
        "\n❌ No file path provided."
    )

    sys.exit(1)

if log_file.lower().endswith(".evtx"):
    print("\n⚠ EVTX detected. Native EVTX parsing requires the optional python-evtx package.")
    print("  Install it with: pip install python-evtx")
    print("  Or export the EVTX to XML/CSV and analyze the exported file.")
    sys.exit(2)


source_is_gzip = log_file.lower().endswith(".gz")
try:
    source_file_size = os.path.getsize(log_file)
except OSError:
    source_file_size = 0

logs = read_log_file(log_file)
# Re-check size after opening the user-supplied path.
try:
    source_file_size = os.path.getsize(log_file)
except OSError:
    pass

PROGRESS_TOTAL_LINES = estimate_total_lines(log_file)

csv_mode = log_file.lower().endswith(".csv")
csv_headers = None


# ============================================================
# DATA STORAGE
# ============================================================

total_lines = 0
blank_lines = 0

web_requests = 0
login_events = 0
unknown_lines = 0

ip_count = Counter()
url_count = Counter()
status_codes = Counter()
http_methods = Counter()
user_agents = Counter()
referrers = Counter()

ip_status = defaultdict(Counter)
ip_urls = defaultdict(Counter)
ip_methods = defaultdict(Counter)

login_success = Counter()
login_failed = Counter()
system_events = Counter()
system_indicator_lines = 0
system_programs = Counter()
auth_users = Counter()
auth_sources = Counter()
auth_methods = Counter()

# Authentication telemetry is kept separate to avoid double-counting
# PAM failures and SSH failed-password records as the same login attempt.
failed_password_events = Counter()
pam_failure_events = Counter()
invalid_user_events = Counter()

# Event-family counters for heterogeneous real-world logs
mail_events = Counter()
network_events = Counter()
firewall_events = Counter()
dns_events = Counter()
database_events = Counter()
ids_events = Counter()
other_syslog_events = Counter()
parsed_syslog_lines = 0
structured_json_lines = 0
cef_lines = 0
structured_csv_lines = 0
journald_lines = 0
recognized_lines = 0

# Coverage / quality telemetry
parse_family_counts = Counter()
parse_failure_reasons = Counter()
security_severity_counts = Counter()
analysis_started = time.monotonic()

# Bounded correlation state: intentionally small so multi-million-line files
# do not accumulate unbounded per-event memory.
auth_failure_windows = defaultdict(list)
web_error_windows = defaultdict(list)

# IOC / behaviour telemetry
source_domains = Counter()
dns_query_names = Counter()
firewall_sources = Counter()
firewall_destinations = Counter()

attack_types = defaultdict(set)
attack_evidence = defaultdict(list)

ground_truth_types = defaultdict(set)
ground_truth_counts = Counter()

risk_scores = Counter()

# IP context / classification telemetry
ip_classifications = Counter()
rapid_auth_peak = Counter()
nul_padding_lines = 0

unparsed_examples = []


# ============================================================
# LOCAL / PRIVATE IP HANDLING
# ============================================================

def is_local_or_private(ip):

    if ip in {
        "127.0.0.1",
        "::1",
        "localhost"
    }:

        return True

    try:

        address = ipaddress.ip_address(ip)

        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
        )

    except ValueError:

        return False


def valid_ip(ip):

    if ip == "localhost":

        return True

    try:

        ipaddress.ip_address(ip)

        return True

    except ValueError:

        return False


def classify_ip(ip):
    """Classify an IP without treating classification itself as maliciousness."""
    if ip == "localhost":
        return "LOOPBACK"
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "INVALID"
    if address.is_loopback:
        return "LOOPBACK"
    if address.is_private:
        if address.is_reserved:
            return "RESERVED / SPECIAL"
        return "PRIVATE"
    if address.is_link_local:
        return "LINK-LOCAL"
    if address.is_multicast:
        return "MULTICAST"
    if address.is_reserved or not address.is_global:
        return "RESERVED / SPECIAL"
    return "PUBLIC"


# ============================================================
# LOGIN LOG PARSER
# ============================================================

LOGIN_PATTERN = re.compile(
    r"LOGIN\s+(SUCCESS|FAILED).*?"
    r"IP:\s*(\S+)",
    re.IGNORECASE
)


# ============================================================
# APACHE / NGINX LOG PARSER
#
# Supports:
# Common Log Format
# Combined Log Format
# ============================================================

WEB_PATTERN = re.compile(

    r'^(?P<ip>\S+)\s+'
    r'\S+\s+'
    r'\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+'
    r'"(?P<agent>[^"]*)")?'

)

# Linux syslog / auth.log support
SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+"
    r"(?P<host>\S+)\s+(?P<program>[A-Za-z0-9_.@/-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

AUTH_PATTERNS = {
    "failed_password": re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\S+)", re.I
    ),
    "accepted_password": re.compile(
        r"Accepted password for (\S+) from (\S+)", re.I
    ),
    "accepted_publickey": re.compile(
        r"Accepted publickey for (\S+) from (\S+)", re.I
    ),
    "invalid_user": re.compile(
        r"Invalid user (\S+) from (\S+)", re.I
    ),
}

SYSTEM_EVENT_PATTERNS = {
    "SSH": re.compile(r"\bsshd(?:\[\d+\])?:", re.I),
    "SUDO": re.compile(r"\bsudo(?:\[\d+\])?:", re.I),
    "SYSTEMD": re.compile(r"\bsystemd(?:\[\d+\])?:", re.I),
    "CRON": re.compile(r"\b(?:CRON|cron)(?:\[\d+\])?:", re.I),
    "KERNEL": re.compile(r"\bkernel:", re.I),
    "PAM": re.compile(r"\bpam_[A-Za-z0-9_]+", re.I),
}


# ============================================================
# GROUND-TRUTH RULES
#
# Based on organization-x.yaml supplied with the dataset.
#
# Ground-truth filters use AND conditions where multiple
# patterns are specified.
# ============================================================

def detect_ground_truth(
    line,
    method="",
    status="",
    user_agent=""
):

    low_line = line.lower()
    low_agent = user_agent.lower()
    method = method.upper()
    status = str(status)

    labels = []

    # --------------------------------------------------------
    # DIRECTORY SCANNING
    # --------------------------------------------------------

    if (
        status == "404"
        and
        "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"
        in low_agent
    ):

        labels.append(
            "dir_scan"
        )


    if "go-http-client" in low_agent:

        labels.append(
            "dir_scan_go"
        )


    if (
        status == "302"
        and
        "python" in low_agent
    ):

        labels.append(
            "dir_scan_python"
        )


    if (
        "mozilla/5.0 (windows nt 10.0; win64; x64)"
        in low_agent
        and
        method == "POST"
        and
        status == "400"
    ):

        labels.append(
            "dir_scan"
        )


    if (
        "mozilla/5.0 (windows nt 10.0; win64; x64)"
        in low_agent
        and
        method == "GET"
        and
        status == "302"
    ):

        labels.append(
            "dir_scan"
        )


    # --------------------------------------------------------
    # PATH TRAVERSAL
    # --------------------------------------------------------

    if (
        "readme.txt" in low_line
        and
        "mozilla/5.0 (windows nt 10.0; win64; x64)"
        in low_agent
    ):

        labels.append(
            "path_traversal"
        )


    # --------------------------------------------------------
    # RCE
    # --------------------------------------------------------

    if (
        method == "POST"
        and
        "python" in low_agent
    ):

        labels.append(
            "rce_shell"
        )


    if (
        method == "HEAD"
        and
        "python" in low_agent
    ):

        labels.append(
            "rce_shell"
        )


    if "md5(" in low_line:

        labels.append(
            "rce_shell"
        )


    if "etc/passwd" in low_line:

        labels.append(
            "rce_read_file"
        )


    if "ipconfig" in low_line:

        labels.append(
            "rce_sysinfo"
        )


    if (
        "java" in low_line
        and
        "runtime" in low_line
    ):

        labels.append(
            "rce_java"
        )


    # --------------------------------------------------------
    # API CALL
    # --------------------------------------------------------

    if (
        method == "POST"
        and
        "mgmt/tm/util/bash" in low_line
    ):

        labels.append(
            "api_call"
        )


    # --------------------------------------------------------
    # XSS
    # --------------------------------------------------------

    if (
        "alert" in low_line
        and
        "document" in low_line
    ):

        labels.append(
            "cross_site_scripting"
        )


    # --------------------------------------------------------
    # FILE INCLUSION
    # --------------------------------------------------------

    if "=http://" in low_line:

        labels.append(
            "file_inclusion"
        )


    if "=https://" in low_line:

        labels.append(
            "file_inclusion"
        )


    # --------------------------------------------------------
    # SHELL EXECUTION
    # --------------------------------------------------------

    if (
        "cgi-bin" in low_line
        and
        ".sh" in low_line
    ):

        labels.append(
            "shell_execution"
        )


    if (
        "cgi-bin" in low_line
        and
        "msie" in low_line
    ):

        labels.append(
            "shell_execution"
        )


    # --------------------------------------------------------
    # REMOTE CODE
    # --------------------------------------------------------

    if "command=" in low_line:

        labels.append(
            "remote_code"
        )


    if "cmd=" in low_line:

        labels.append(
            "remote_code"
        )


    if "<?=" in low_line:

        labels.append(
            "remote_code"
        )


    if "base64" in low_line:

        labels.append(
            "remote_code"
        )


    if "<?php" in low_line:

        labels.append(
            "remote_code"
        )


    # --------------------------------------------------------
    # SERVER BRUTE FORCE
    # --------------------------------------------------------

    if (
        "authentication failure"
        in low_line
    ):

        labels.append(
            "bruteforce_login_server_attempt"
        )


    if (
        "failed password for root"
        in low_line
    ):

        labels.append(
            "bruteforce_login_server_attempt"
        )


    # --------------------------------------------------------
    # WEB BRUTE FORCE
    # --------------------------------------------------------

    if (
        "/login/" in low_line
        and
        method == "POST"
        and
        status == "404"
    ):

        labels.append(
            "bruteforce_login_web_attempt"
        )


    # --------------------------------------------------------
    # SQL INJECTION
    # --------------------------------------------------------

    sql_patterns = [

        "select%",
        "select+",
        "union%",
        "union+",
        "sleep%",
        "sleep+",
        "sleep(",
        "concat%",
        "concat+",
        "concat("

    ]

    if any(
        pattern in low_line
        for pattern in sql_patterns
    ):

        labels.append(
            "sql_injection_attempt"
        )


    # --------------------------------------------------------
    # RSYNC
    # --------------------------------------------------------

    if (
        "rsyncd" in low_line
        and
        "rsync to" in low_line
        and
        "unknown" in low_line
    ):

        labels.append(
            "unkown_sync"
        )


    return sorted(
        set(labels)
    )


# ============================================================
# GENERIC ATTACK DETECTION
# ============================================================

ATTACK_PATTERNS = {

    "SQL Injection": [

        r"union(?:%20|\+|\s)+select",

        r"select(?:%20|\+|\s)+.*(?:from|where)",

        r"(?:or|and)\s+['\"]?\d+['\"]?"
        r"\s*=\s*['\"]?\d+",

        r"(?:or|and)\s+['\"]?1['\"]?"
        r"\s*=\s*['\"]?1",

        r"information_schema",

        r"sleep\s*\(",

        r"benchmark\s*\(",

        r"waitfor\s+delay",

        r"concat\s*\("

    ],


    "Cross-Site Scripting": [

        r"<script",

        r"%3cscript",

        r"javascript:",

        r"onerror\s*=",

        r"onload\s*=",

        r"<img[^>]+onerror"

    ],


    "Directory Traversal": [

        r"\.\./",

        r"\.\.\\",

        r"%2e%2e%2f",

        r"%2e%2e/",

        r"\.\.%2f",

        r"%252e%252e"

    ],


    "Local File Inclusion": [

        r"/etc/passwd",

        r"/etc/shadow",

        r"proc/self/environ",

        r"boot\.ini",

        r"win\.ini",

        r"file://"

    ],


    "Remote File Inclusion": [

        r"https?://.*\.(?:php|txt|conf)",

        r"php://input",

        r"php://filter"

    ],


    "Command Injection": [

        r";\s*(?:whoami|id|uname|cat|ls)\b",

        r"\|\s*(?:whoami|id|uname|cat|ls)\b",

        r"\$\(",

        r"`(?:whoami|id)`",

        r"\|\|\s*(?:whoami|id|uname)\b",

        r"&&\s*(?:whoami|id|uname)\b"

    ],


    "Sensitive File Probing": [

        r"/\.env(?:/|$)",

        r"/\.git(?:/|$)",

        r"/\.htaccess",

        r"/config\.php",

        r"/wp-config\.php",

        r"/(?:backup|database|dump)(?:/|$)"

    ],


    "Admin Panel Probing": [

        r"/wp-admin(?:/|$)",

        r"/phpmyadmin(?:/|$)",

        r"/administrator(?:/|$)",

        r"/admin/login",

        r"/admin(?:/|$)",

        r"/manager/html"

    ]

}


# ============================================================
# SCANNER USER AGENTS
# ============================================================

SCANNER_AGENTS = [

    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "gobuster",
    "dirbuster",
    "dirb",
    "wpscan",
    "burpsuite",
    "zgrab",
    "nuclei"

]


# ============================================================
# UNUSUAL METHODS
# ============================================================

UNUSUAL_METHODS = {

    "TRACE",
    "CONNECT",
    "PATCH"

}



# ============================================================
# LINUX SYSTEM / AUTH LOG PARSER
# ============================================================

def extract_ipv4_addresses(text):
    found = []
    for candidate in re.findall(
        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])",
        text
    ):
        try:
            ipaddress.ip_address(candidate)
            if candidate not in found:
                found.append(candidate)
        except ValueError:
            pass
    return found


def add_bounded_timestamp(store, key, timestamp_value, limit=50):
    values = store[key]
    values.append(timestamp_value)
    if len(values) > limit:
        del values[:-limit]


def extract_urls_and_domains(text):
    for match in re.findall(r"https?://([^/\\s\"'<>]+)", text, re.I):
        domain = match.split(":", 1)[0].lower().rstrip(".")
        if domain:
            source_domains[domain] += 1


def classify_structured_json(line):
    """Recognize common JSON/NDJSON security and application events."""
    global structured_json_lines, recognized_lines
    if not line.startswith(("{", "[")):
        return False
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return False
    if not isinstance(obj, dict):
        return False

    structured_json_lines += 1
    recognized_lines += 1
    parse_family_counts["JSON / NDJSON"] += 1

    # Flexible key extraction used by common security/application logs.
    event_text = " ".join(str(obj.get(k, "")) for k in (
        "message", "msg", "event", "action", "request", "url", "uri", "path",
        "rule", "signature", "alert", "description", "error"
    ))
    low = event_text.lower()

    ip = None
    for key in ("src_ip", "source_ip", "client_ip", "remote_addr", "src", "ip"):
        value = obj.get(key)
        if value and valid_ip(str(value)):
            ip = str(value)
            break
    if ip:
        ip_count[ip] += 1

    if any(k in low for k in ("failed password", "authentication failure", "login failed", "invalid user")):
        if ip:
            login_failed[ip] += 1
            attack_types[ip].add("Authentication Failure")
            attack_evidence[ip].append("JSON authentication failure event")
        system_events["Authentication failure"] += 1

    if any(k in low for k in ("accepted password", "accepted publickey", "login success", "authentication success")):
        if ip:
            login_success[ip] += 1
        system_events["Successful authentication"] += 1

    if any(k in low for k in ("sql injection", "xss", "cross-site", "command injection", "path traversal", "rce")):
        if ip:
            attack_types[ip].add("Security Detection Alert")
            attack_evidence[ip].append(event_text[:180])
        ids_events["JSON security alert"] += 1

    if any(k in low for k in ("deny", "denied", "blocked", "reject", "rejected")):
        firewall_events["JSON security decision"] += 1

    extract_urls_and_domains(event_text)
    return True


def classify_cef(line):
    """Recognize ArcSight Common Event Format lines."""
    global cef_lines, recognized_lines
    if not line.startswith("CEF:"):
        return False
    cef_lines += 1
    recognized_lines += 1
    parse_family_counts["CEF"] += 1
    parts = line.split("|", 7)
    extension = parts[7] if len(parts) >= 8 else ""
    fields = {}
    for token in re.findall(r"(?:^|\\s)([A-Za-z][A-Za-z0-9_.-]*)=([^\\s]+)", extension):
        fields[token[0].lower()] = token[1]
    ip = fields.get("src") or fields.get("sourceip") or fields.get("srcip")
    if ip and valid_ip(ip):
        ip_count[ip] += 1
    sev = fields.get("severity")
    if sev:
        try:
            security_severity_counts[sev] += 1
        except Exception:
            pass
    name = (parts[5] if len(parts) > 5 else "CEF event").strip()
    low = line.lower()
    if any(x in low for x in ("attack", "exploit", "malware", "intrusion", "brute force", "sql injection")):
        if ip:
            attack_types[ip].add("CEF Security Alert")
            attack_evidence[ip].append(f"CEF: {name}")
        ids_events["CEF security alert"] += 1
    return True


def parse_journald_line(line):
    """Recognize systemd-journal export/key=value records."""
    global journald_lines
    if not ("MESSAGE=" in line or "SYSLOG_IDENTIFIER=" in line or "_COMM=" in line):
        return False
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        return False
    fields = {}
    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            if key.isupper() or key.startswith("_"):
                fields[key] = value
    if not fields:
        return False
    journald_lines += 1
    parse_family_counts["systemd-journal"] += 1
    message = fields.get("MESSAGE", "")
    program = fields.get("SYSLOG_IDENTIFIER") or fields.get("_COMM") or "journald"
    synthetic = f"Jan 01 00:00:00 localhost {program}: {message}"
    parse_system_log(synthetic)
    return True


def parse_csv_line(line, headers=None):
    """Parse a CSV security/application record when the file is clearly CSV."""
    try:
        row = next(csv.reader([line]))
    except Exception:
        return False, headers
    if headers is None:
        normalized = [re.sub(r"[^a-z0-9]", "", h.lower()) for h in row]
        known = {"timestamp", "time", "date", "srcip", "sourceip", "clientip", "remoteip", "dstip", "destip", "status", "method", "url", "uri", "message", "event", "action", "user", "username"}
        return (bool(set(normalized) & known), row if bool(set(normalized) & known) else None)
    if not row:
        return False, headers
    mapping = {re.sub(r"[^a-z0-9]", "", h.lower()): i for i, h in enumerate(headers)}
    get = lambda *names: next((row[mapping[n]] for n in names if n in mapping and mapping[n] < len(row)), "")
    ip = get("srcip", "sourceip", "clientip", "remoteip", "ip")
    if ip and valid_ip(ip):
        ip_count[ip] += 1
    status = get("status", "statuscode")
    if status.isdigit() and len(status) == 3:
        status_codes[status] += 1
    method = get("method", "httpmethod").upper()
    url = get("url", "uri", "path", "request")
    if method:
        http_methods[method] += 1
    if url:
        url_count[url] += 1
    message = get("message", "event", "action", "description").lower()
    user = get("user", "username", "account")
    if any(x in message for x in ("failed password", "authentication failure", "login failed", "invalid user")):
        if ip:
            login_failed[ip] += 1
            attack_types[ip].add("Authentication Failure")
            attack_evidence[ip].append(f"CSV authentication failure for {user or 'unknown user'}")
    if any(x in message for x in ("accepted password", "login success", "authentication success")):
        if ip:
            login_success[ip] += 1
    if any(x in message for x in ("sql injection", "xss", "command injection", "path traversal", "rce", "malware", "intrusion")):
        if ip:
            attack_types[ip].add("Security Detection Alert")
            attack_evidence[ip].append(message[:180])
        ids_events["CSV security alert"] += 1
    return True, headers


def parse_syslog_timestamp(line):
    match = re.search(r"^(?P<m>[A-Z][a-z]{2})\s+(?P<d>\d{1,2})\s+(?P<t>\d{2}:\d{2}:\d{2})", line)
    if not match:
        return None
    try:
        return datetime.strptime(
            f"{datetime.now().year} {match.group('m')} {match.group('d')} {match.group('t')}",
            "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None


def parse_system_log(line):
    """Parse RFC3164-style syslog and classify common log families."""
    global parsed_syslog_lines, recognized_lines, system_indicator_lines

    match = SYSLOG_PATTERN.search(line)

    if not match:
        return False

    parsed_syslog_lines += 1
    recognized_lines += 1
    parse_family_counts["Syslog"] += 1

    program = match.group("program")
    message = match.group("message")
    low = line.lower()
    program_low = program.lower()

    system_programs[program] += 1

    # Classify each syslog line into one primary family.  A line belongs to
    # exactly one family so family totals do not overlap.
    known_family = False
    if program_low.startswith(("postfix", "exim", "dovecot")):
        mail_events[program] += 1
        known_family = True
    elif program_low.startswith(("ufw", "iptables", "ip6tables", "nftables", "firewalld")):
        firewall_events[program] += 1
        known_family = True
    elif program_low.startswith(("named", "bind", "dnsmasq", "systemd-resolve", "resolved")):
        dns_events[program] += 1
        known_family = True
    elif program_low.startswith(("mysqld", "mysql", "postgres", "postgresql", "mariadbd", "mssql", "sqlservr")):
        database_events[program] += 1
        known_family = True
    elif program_low.startswith(("suricata", "snort", "zeek")):
        ids_events[program] += 1
        known_family = True
    elif program_low.startswith(("dhcpd", "dhclient", "networkmanager", "systemd-networkd")):
        network_events[program] += 1
        known_family = True

    # Core Linux security/system programs are intentionally not placed in
    # the generic bucket.
    core_system_program = program_low in {
        "sshd", "sudo", "systemd", "systemd-logind", "cron", "crond",
        "anacron", "kernel", "su", "login", "polkitd"
    } or program_low.startswith("pam_")

    if not known_family and not core_system_program:
        other_syslog_events[program] += 1

    # System indicators are overlapping detections by design.  Keep both the
    # per-indicator hit counts and a unique per-line count for reporting.
    line_had_system_indicator = False
    for name, pattern in SYSTEM_EVENT_PATTERNS.items():
        if pattern.search(line):
            system_events[name] += 1
            line_had_system_indicator = True

    if line_had_system_indicator:
        system_indicator_lines += 1

    # SSH failed password
    match = AUTH_PATTERNS["failed_password"].search(message)
    if match:
        user, ip = match.groups()
        login_failed[ip] += 1
        failed_password_events[ip] += 1
        ip_count[ip] += 1
        auth_users[user] += 1
        auth_sources[ip] += 1
        auth_methods["SSH password"] += 1
        system_events["Failed password"] += 1

        ground_truth_types[ip].add("bruteforce_login_server_attempt")
        ground_truth_counts["bruteforce_login_server_attempt"] += 1

        attack_types[ip].add("Authentication Failure")
        attack_evidence[ip].append(
            f"Failed password for {user} from {ip}"
        )

    # Successful SSH authentication
    for key, event_name, method_name in [
        ("accepted_password", "Accepted password", "SSH password"),
        ("accepted_publickey", "Accepted publickey", "SSH publickey"),
    ]:
        match = AUTH_PATTERNS[key].search(message)
        if match:
            user, ip = match.groups()
            login_success[ip] += 1
            ip_count[ip] += 1
            auth_users[user] += 1
            auth_sources[ip] += 1
            auth_methods[method_name] += 1
            system_events[event_name] += 1

    # Invalid SSH user
    match = AUTH_PATTERNS["invalid_user"].search(message)
    if match:
        user, ip = match.groups()
        login_failed[ip] += 1
        invalid_user_events[ip] += 1
        ip_count[ip] += 1
        auth_users[user] += 1
        auth_sources[ip] += 1
        system_events["Invalid user"] += 1

        attack_types[ip].add("Invalid User")
        attack_evidence[ip].append(
            f"Invalid user {user} from {ip}"
        )

    # PAM authentication failure
    if "authentication failure" in low:
        for ip in extract_ipv4_addresses(line):
            pam_failure_events[ip] += 1
            ip_count[ip] += 1
            auth_sources[ip] += 1
            attack_types[ip].add("Authentication Failure")
            attack_evidence[ip].append(
                f"Authentication failure from {ip}"
            )

        system_events["Authentication failure"] += 1

    # System health indicators
    for keyword, label in [
        ("segfault", "Segmentation fault"),
        ("out of memory", "Out of memory"),
        ("oom-killer", "OOM killer"),
        ("kernel panic", "Kernel panic"),
        ("sudo:", "Sudo activity"),
    ]:
        if keyword in low:
            system_events[label] += 1

    # Firewall/security events
    if program_low.startswith(("ufw", "iptables", "ip6tables", "nftables", "firewalld")):
        if any(k in low for k in ("drop", "reject", "denied", "blocked", "accept")):
            firewall_events["Security decision"] += 1

    # IDS/IPS events
    if program_low.startswith(("suricata", "snort", "zeek")):
        if any(k in low for k in ("alert", "signature", "priority", "notice")):
            ids_events["Security alert"] += 1

    # Mail security/rejection indicators
    if program_low.startswith(("postfix", "exim", "dovecot")):
        if any(k in low for k in (
            "authentication failed",
            "auth failed",
            "sasl authentication failure",
            "login failed",
            "reject",
            "rejected",
        )):
            mail_events["Mail security/rejection"] += 1

    # Network telemetry / connection indicators
    if program_low.startswith(("dhcpd", "dhclient", "networkmanager", "systemd-networkd")):
        network_events["Network management event"] += 1
        for candidate in extract_ipv4_addresses(line):
            firewall_sources[candidate] += 1

    # Common privilege escalation / account-management indicators
    if any(term in low for term in ("useradd", "usermod", "userdel", "groupadd", "passwd:", "new user", "new group")):
        system_events["Account management"] += 1
    if any(term in low for term in ("session opened for user root", "sudo:", "uid=0")):
        system_events["Privileged activity"] += 1

    # Security-relevant kernel/service health events
    if any(term in low for term in ("kernel panic", "segfault", "oom-killer", "out of memory")):
        security_severity_counts["HIGH"] += 1

    # Lightweight bounded brute-force correlation within one syslog file.
    ts = parse_syslog_timestamp(line)
    if ts and ip_count:
        for candidate in extract_ipv4_addresses(line):
            if "authentication failure" in low or "failed password" in low or "invalid user" in low:
                add_bounded_timestamp(auth_failure_windows, candidate, ts)
                recent = [x for x in auth_failure_windows[candidate] if abs((ts - x).total_seconds()) <= 60]
                if len(recent) >= 10 and not is_local_or_private(candidate):
                    attack_types[candidate].add("Rapid Authentication Failures")
                    rapid_auth_peak[candidate] = max(rapid_auth_peak[candidate], len(recent))

    # Mail, DNS, firewall and generic syslog lines can contain source URLs/IPs.
    extract_urls_and_domains(line)

    # DNS query extraction when available.
    if program_low.startswith(("named", "bind", "dnsmasq", "systemd-resolve", "resolved")):
        for q in re.findall(r"(?:query|name)[:=]\s*([A-Za-z0-9_.-]+)", line, re.I):
            dns_query_names[q.lower()] += 1

    # Firewall source/destination telemetry.
    if program_low.startswith(("ufw", "iptables", "ip6tables", "nftables", "firewalld")):
        candidates = extract_ipv4_addresses(line)
        if candidates:
            firewall_sources[candidates[0]] += 1
        if len(candidates) > 1:
            firewall_destinations[candidates[1]] += 1

    # DNS failures / notable responses
    if program_low.startswith(("named", "bind", "dnsmasq", "systemd-resolve", "resolved")):

        if any(k in low for k in (
            "servfail", "refused", "nxdomain", "timeout", "failure"
        )):
            dns_events["DNS failure/response"] += 1

    return True

# ============================================================
# PARSE LOGS
# ============================================================

show_status("Analyzing log data...")

for line_number, raw_line in enumerate(
    logs,
    start=1
):

    total_lines = line_number

    show_progress(line_number)

    # Treat NUL-only records as file padding, not malformed log events.
    cleaned_line = raw_line.replace("\x00", "")
    if not cleaned_line.strip():
        if raw_line.strip("\r\n"):
            nul_padding_lines += 1
        else:
            blank_lines += 1
        continue

    line = raw_line.strip()


    # --------------------------------------------------------
    # STRUCTURED / CEF / JOURNAL / CSV LOGS
    # --------------------------------------------------------

    if csv_mode:
        if csv_headers is None:
            ok, candidate = parse_csv_line(line, None)
            if ok:
                csv_headers = candidate
                structured_csv_lines += 1
                recognized_lines += 1
                parse_family_counts["CSV"] += 1
                continue
        else:
            ok, csv_headers = parse_csv_line(line, csv_headers)
            if ok:
                structured_csv_lines += 1
                recognized_lines += 1
                parse_family_counts["CSV"] += 1
                continue

    if parse_journald_line(line):
        continue

    if classify_cef(line):
        continue

    if classify_structured_json(line):
        continue

    # --------------------------------------------------------
    # LOGIN LOG
    # --------------------------------------------------------

    login_match = LOGIN_PATTERN.search(
        line
    )


    if login_match:

        result = login_match.group(1).upper()

        ip = login_match.group(2)

        login_events += 1

        ip_count[ip] += 1


        if result == "SUCCESS":

            login_success[ip] += 1

        else:

            login_failed[ip] += 1


        labels = detect_ground_truth(
            line
        )


        for label in labels:

            ground_truth_types[ip].add(
                label
            )

            ground_truth_counts[label] += 1


        continue


    # --------------------------------------------------------
    # WEB LOG
    # --------------------------------------------------------

    web_match = WEB_PATTERN.search(
        line
    )


    if not web_match:

        if parse_system_log(line):
            continue

        unknown_lines += 1


        if len(unparsed_examples) < 5:

            unparsed_examples.append(
                f"Line {line_number}: "
                f"{line[:180]}"
            )

        continue


    ip = web_match.group("ip")

    timestamp = web_match.group("time")

    request = web_match.group("request")

    status = web_match.group("status")

    size = web_match.group("size")

    referrer = (
        web_match.group("referrer")
        or ""
    )

    user_agent = (
        web_match.group("agent")
        or ""
    )


    # --------------------------------------------------------
    # REQUEST PARSING
    # --------------------------------------------------------

    try:

        request_parts = shlex.split(
            request
        )

    except ValueError:

        request_parts = request.split()


    if len(request_parts) < 2:

        unknown_lines += 1

        if len(unparsed_examples) < 5:

            unparsed_examples.append(
                f"Line {line_number}: "
                f"{line[:180]}"
            )

        continue


    method = request_parts[0].upper()

    url = request_parts[1]

    decoded_url = unquote(url)


    # --------------------------------------------------------
    # BASIC COUNTERS
    # --------------------------------------------------------

    web_requests += 1
    recognized_lines += 1
    parse_family_counts["Web"] += 1

    ip_count[ip] += 1

    url_count[url] += 1

    status_codes[status] += 1

    http_methods[method] += 1

    ip_status[ip][status] += 1

    ip_urls[ip][url] += 1

    ip_methods[ip][method] += 1


    if user_agent:

        user_agents[user_agent] += 1


    if referrer:

        referrers[referrer] += 1


    # ========================================================
    # GROUND-TRUTH DETECTION
    # ========================================================

    labels = detect_ground_truth(

        line,

        method=method,

        status=status,

        user_agent=user_agent

    )


    for label in labels:

        ground_truth_types[ip].add(
            label
        )

        ground_truth_counts[label] += 1


    # ========================================================
    # GENERIC ATTACK DETECTION
    #
    # Deliberately checks request URL rather than referrer.
    # This reduces false positives from normal external links.
    # ========================================================

    detection_text = (
        f"{method} "
        f"{decoded_url}"
    ).lower()


    for attack_name, patterns in ATTACK_PATTERNS.items():

        detected = False


        for pattern in patterns:

            try:

                if re.search(
                    pattern,
                    detection_text,
                    re.IGNORECASE
                ):

                    detected = True

                    break

            except re.error:

                continue


        if detected:

            attack_types[ip].add(
                attack_name
            )


            evidence = (

                f"{attack_name}: "
                f"{method} {url}"

            )


            if evidence not in attack_evidence[ip]:

                attack_evidence[ip].append(
                    evidence
                )


    # ========================================================
    # SCANNER USER-AGENT
    # ========================================================

    agent_lower = user_agent.lower()


    for scanner in SCANNER_AGENTS:

        if scanner in agent_lower:

            attack_types[ip].add(
                "Security Scanner"
            )


            evidence = (

                f"Scanner User-Agent: "
                f"{user_agent}"

            )


            if evidence not in attack_evidence[ip]:

                attack_evidence[ip].append(
                    evidence
                )


            break


    # ========================================================
    # UNUSUAL HTTP METHOD
    # ========================================================

    if method in UNUSUAL_METHODS:

        attack_types[ip].add(
            "Unusual HTTP Method"
        )


        evidence = (

            f"Unusual HTTP method: "
            f"{method} {url}"

        )


        if evidence not in attack_evidence[ip]:

            attack_evidence[ip].append(
                evidence
            )


clear_status_line()

# ============================================================
# POST-PROCESSING SECURITY ANALYSIS
# ============================================================

STRONG_GENERIC_ATTACKS = {

    "SQL Injection",
    "Cross-Site Scripting",
    "Directory Traversal",
    "Local File Inclusion",
    "Remote File Inclusion",
    "Command Injection",
    "Sensitive File Probing",
    "Admin Panel Probing"

}


GROUND_TRUTH_STRONG = {

    "path_traversal",
    "rce_shell",
    "rce_read_file",
    "rce_sysinfo",
    "rce_java",
    "api_call",
    "cross_site_scripting",
    "file_inclusion",
    "shell_execution",
    "remote_code",
    "sql_injection_attempt"

}


GROUND_TRUTH_SCAN = {

    "dir_scan",
    "dir_scan_go",
    "dir_scan_python"

}


GROUND_TRUTH_AUTH = {

    "bruteforce_login_server_attempt",
    "bruteforce_login_web_attempt"

}


for ip, peak in rapid_auth_peak.items():
    if peak >= 10:
        attack_evidence[ip].append(f"{peak} authentication failures within ~60 seconds")


for ip in ip_count:

    ip_classifications["INVALID" if not valid_ip(ip) else classify_ip(ip)] += 1

    local_or_private = (
        is_local_or_private(ip)
    )

    request_count = ip_count[ip]

    unique_urls = len(
        ip_urls[ip]
    )

    not_found = (
        ip_status[ip]["404"]
    )

    unauthorized = (
        ip_status[ip]["401"]
    )

    forbidden = (
        ip_status[ip]["403"]
    )

    failed = (
        login_failed[ip]
    )


    # ========================================================
    # GROUND-TRUTH ATTACK WEIGHTS
    # ========================================================

    for label in ground_truth_types[ip]:

        if label in GROUND_TRUTH_STRONG:

            risk_scores[ip] += 45

        elif label in GROUND_TRUTH_SCAN:

            risk_scores[ip] += 30

        elif label in GROUND_TRUTH_AUTH:

            risk_scores[ip] += 30


    # ========================================================
    # GENERIC ATTACK WEIGHTS
    # ========================================================

    for attack in (
        attack_types[ip]
        & STRONG_GENERIC_ATTACKS
    ):

        risk_scores[ip] += 40


    if "Security Scanner" in attack_types[ip]:

        risk_scores[ip] += 20


    if "Unusual HTTP Method" in attack_types[ip]:

        risk_scores[ip] += 10


    # ========================================================
    # LOGIN BRUTE FORCE
    # ========================================================

    if failed >= 10:

        risk_scores[ip] += 40

        attack_types[ip].add(
            "Brute Force"
        )

        attack_evidence[ip].append(
            f"{failed} failed login attempts"
        )


    elif failed >= 5:

        risk_scores[ip] += 25

        attack_types[ip].add(
            "Possible Brute Force"
        )

        attack_evidence[ip].append(
            f"{failed} failed login attempts"
        )


    elif failed >= 3:

        risk_scores[ip] += 15

        attack_types[ip].add(
            "Repeated Authentication Failures"
        )

        attack_evidence[ip].append(
            f"{failed} failed login attempts"
        )


    # ========================================================
    # WEB SCANNING BEHAVIOUR
    #
    # Local/private systems are not penalized simply because
    # they generate high traffic.
    # ========================================================

    if not local_or_private:

        if not_found >= 20:

            risk_scores[ip] += 25

            attack_types[ip].add(
                "Path Scanning"
            )

            attack_evidence[ip].append(
                f"{not_found} HTTP 404 responses"
            )


        elif not_found >= 10:

            risk_scores[ip] += 15

            attack_types[ip].add(
                "Possible Path Scanning"
            )

            attack_evidence[ip].append(
                f"{not_found} HTTP 404 responses"
            )


        if unauthorized >= 5:

            risk_scores[ip] += 15

            attack_types[ip].add(
                "Unauthorized Access Attempts"
            )

            attack_evidence[ip].append(
                f"{unauthorized} HTTP 401 responses"
            )


        if forbidden >= 5:

            risk_scores[ip] += 15

            attack_types[ip].add(
                "Access Probing"
            )

            attack_evidence[ip].append(
                f"{forbidden} HTTP 403 responses"
            )


        # ----------------------------------------------------
        # REQUEST VOLUME
        # ----------------------------------------------------

        if request_count >= 1000:

            risk_scores[ip] += 15

            attack_types[ip].add(
                "High Request Volume"
            )

            attack_evidence[ip].append(
                f"{request_count} requests"
            )


        elif request_count >= 500:

            risk_scores[ip] += 10

            attack_types[ip].add(
                "Elevated Request Volume"
            )

            attack_evidence[ip].append(
                f"{request_count} requests"
            )


        # ----------------------------------------------------
        # BROAD URL SCANNING
        # ----------------------------------------------------

        if (
            unique_urls >= 50
            and
            request_count >= 100
        ):

            risk_scores[ip] += 15

            attack_types[ip].add(
                "Broad URL Scanning"
            )

            attack_evidence[ip].append(
                f"{unique_urls} unique URLs requested"
            )


    # ========================================================
    # HIGH REPETITION
    #
    # Behaviour only.
    # It does NOT automatically mean malicious activity.
    # ========================================================

    if request_count > 100:

        top_url_count = max(
            ip_urls[ip].values(),
            default=0
        )


        if (
            top_url_count / request_count
            >= 0.90
        ):

            attack_types[ip].add(
                "Highly Repetitive Traffic"
            )

            attack_evidence[ip].append(

                f"{top_url_count} of "
                f"{request_count} requests "
                f"targeted the same URL"

            )


    # ========================================================
    # INVALID IP WARNING
    # ========================================================

    if not valid_ip(ip):
        attack_types[ip].add("Invalid / Non-standard IP Address")
        attack_evidence[ip].append(f"Parsed source address: {ip}")


    # Linux authentication risk
    if login_failed[ip] >= 20 and not local_or_private:
        risk_scores[ip] += 35
    elif login_failed[ip] >= 10 and not local_or_private:
        risk_scores[ip] += 25

    # ========================================================
    # SCORE CAP
    # ========================================================

    risk_scores[ip] = min(
        risk_scores[ip],
        100
    )


# ============================================================
# RISK LEVEL
# ============================================================

def risk_level(score):

    if score >= 70:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


def display_risk_level(level):
    return level if level in {"HIGH", "MEDIUM", "LOW", "REVIEW"} else "LOW"


# ============================================================
# SUSPICIOUS IPS
# ============================================================

suspicious_ips = [

    ip

    for ip in ip_count

    if (
        risk_scores[ip] >= 30
        or
        attack_types[ip]
    )

]


# ============================================================
# OVERALL RISK
# ============================================================

highest_score = max(
    risk_scores.values(),
    default=0
)

overall_risk = risk_level(
    highest_score
)

# A low risk score is not trustworthy when parser coverage is poor.
# This prevents the dangerous "millions of unparsed lines = LOW RISK" result.
coverage_ratio = (recognized_lines / total_lines) if total_lines else 0
if overall_risk == "LOW" and total_lines >= 100 and coverage_ratio < 0.50:
    overall_risk = "REVIEW"



# ============================================================
# STATUS GROUPS
# ============================================================

status_2xx = sum(

    count

    for code, count
    in status_codes.items()

    if code.startswith("2")

)


status_3xx = sum(

    count

    for code, count
    in status_codes.items()

    if code.startswith("3")

)


status_4xx = sum(

    count

    for code, count
    in status_codes.items()

    if code.startswith("4")

)


status_5xx = sum(

    count

    for code, count
    in status_codes.items()

    if code.startswith("5")

)


# ============================================================
# LOG TYPE
# ============================================================

auth_event_count = (
    sum(login_success.values())
    + sum(login_failed.values())
)

if web_requests > 0 and auth_event_count > 0:

    log_type = "Mixed Web + Authentication/System Logs"

elif web_requests > 0:

    log_type = "Web Server Logs"

elif (
    auth_event_count > 0
    or system_events
    or parsed_syslog_lines
    or mail_events
    or dns_events
    or database_events
    or ids_events
):

    log_type = "Linux / Syslog / System Logs"

else:

    log_type = "Unknown / Unsupported"


clear_status_line()

# ============================================================
# SUMMARY
# ============================================================

summary_rows = [

    (
        "Log Type",
        log_type
    ),

    (
        "Total File Lines",
        total_lines
    ),

    (
        "Parsed Web Requests",
        web_requests
    ),

    (
        "Login / Auth Events",
        sum(login_success.values()) + sum(login_failed.values())
    ),

    (
        "Successful Logins",
        sum(login_success.values())
    ),

    (
        "Authentication Failure Events",
        sum(login_failed.values())
    ),

    (
        "Failed Password Events",
        sum(failed_password_events.values())
    ),

    (
        "PAM Authentication Failures",
        sum(pam_failure_events.values())
    ),

    (
        "Invalid User Events",
        sum(invalid_user_events.values())
    ),

    (
        "Unique IP Addresses",
        len(ip_count)
    ),

    (
        "Unique URLs",
        len(url_count)
    ),

    (
        "2xx Successful",
        status_2xx
    ),

    (
        "3xx Redirects",
        status_3xx
    ),

    (
        "4xx Client Errors",
        status_4xx
    ),

    (
        "5xx Server Errors",
        status_5xx
    ),

    (
        "Blank / Whitespace Lines",
        blank_lines
    ),

    (
        "NUL Padding Lines",
        nul_padding_lines
    ),

    (
        "Unknown / Unparsed Lines",
        unknown_lines
    ),

    (
        "Ground-Truth Rule Matches",
        sum(ground_truth_counts.values())
    ),

    (
        "Parsed Syslog Lines",
        parsed_syslog_lines
    ),

    (
        "System Event Indicators (overlapping)",
        system_indicator_lines
    ),

    (
        "Mail Events",
        sum(mail_events.values())
    ),

    (
        "Firewall Events",
        sum(firewall_events.values())
    ),

    (
        "DNS Events",
        sum(dns_events.values())
    ),

    (
        "Database Events",
        sum(database_events.values())
    ),

    (
        "IDS / IPS Events",
        sum(ids_events.values())
    ),

    (
        "Other / Unclassified Syslog Lines",
        sum(other_syslog_events.values())
    ),

    (
        "Structured JSON / NDJSON Lines",
        structured_json_lines
    ),

    (
        "CEF Lines",
        cef_lines
    ),

    (
        "CSV Lines",
        structured_csv_lines
    ),

    (
        "Journald Lines",
        journald_lines
    ),

    (
        "Recognized Lines",
        recognized_lines
    ),

    (
        "Parse Coverage",
        percentage(recognized_lines, max(total_lines - blank_lines, 0))
    ),

    (
        "Suspicious IPs",
        len(suspicious_ips)
    ),

    (
        "Overall Risk",
        overall_risk
    )

]


# ============================================================
# IP TABLE DATA
# ============================================================

ip_rows = []


for ip, count in ip_count.most_common():

    ip_rows.append([

        ip,

        count,

        len(
            ip_urls[ip]
        ),

        ip_status[ip]["404"],

        ip_status[ip]["401"],

        ip_status[ip]["403"],

        login_failed[ip],

        pam_failure_events[ip],

        invalid_user_events[ip],

        risk_scores[ip],

        risk_level(
            risk_scores[ip]
        )

    ])


# ============================================================
# PRINT SUMMARY
# ============================================================

print()

print_box(
    "ANALYSIS SUMMARY"
)

print_table(

    [
        "Metric",
        "Value"
    ],

    summary_rows,

    [
        40,
        56
    ]

)


# ============================================================
# PARSING COVERAGE
# ============================================================

print()
print_box("PARSING COVERAGE")
print_table(
    ["Parser Family", "Recognized Lines"],
    parse_family_counts.most_common(),
    [65, 31]
)


# ============================================================
# IP CLASSIFICATION
# ============================================================

print()
print_box("IP CLASSIFICATION")
print_table(
    ["Classification", "Count"],
    ip_classifications.most_common(),
    [65, 31]
)


# ============================================================
# IP INVESTIGATION
# ============================================================

print()

print_box(
    "IP INVESTIGATION"
)

print_table(

    [
        "IP Address",
        "Observations",
        "Unique URL",
        "404",
        "401",
        "403",
        "Failed",
        "PAM Fail",
        "Invalid User",
        "Score",
        "Risk"
    ],

    ip_rows,

    [
        22,
        10,
        12,
        7,
        7,
        7,
        9,
        12,
        9,
        9,
        9
    ]

)


# ============================================================
# HTTP STATUS
# ============================================================

status_names = {

    "200": "OK",
    "201": "Created",
    "204": "No Content",

    "301": "Moved Permanently",
    "302": "Found",
    "304": "Not Modified",

    "400": "Bad Request",
    "401": "Unauthorized",
    "403": "Forbidden",
    "404": "Not Found",
    "405": "Method Not Allowed",
    "408": "Request Timeout",
    "429": "Too Many Requests",

    "500": "Server Error",
    "502": "Bad Gateway",
    "503": "Service Unavailable"

}


if status_codes:

    print()

    print_box(
        "HTTP STATUS ANALYSIS"
    )


    status_rows = []


    for code, count in status_codes.most_common():

        status_rows.append([

            code,

            status_names.get(
                code,
                "Unknown Status"
            ),

            count,

            percentage(
                count,
                web_requests
            )

        ])


    print_table(

        [
            "Code",
            "Meaning",
            "Count",
            "Percentage"
        ],

        status_rows,

        [
            10,
            30,
            16,
            20
        ]

    )


# ============================================================
# HTTP METHODS
# ============================================================

if http_methods:

    print()

    print_box(
        "HTTP METHODS"
    )


    method_rows = []


    for method, count in http_methods.most_common():

        method_rows.append([

            method,

            count,

            percentage(
                count,
                web_requests
            )

        ])


    print_table(

        [
            "Method",
            "Requests",
            "Percentage"
        ],

        method_rows,

        [
            20,
            20,
            36
        ]

    )


# ============================================================
# TOP URLS
# ============================================================

if url_count:

    print()

    print_box(
        "TOP REQUESTED URLS"
    )


    url_rows = [

        [
            url,
            count
        ]

        for url, count
        in url_count.most_common(15)

    ]


    print_table(

        [
            "URL / PATH",
            "Requests"
        ],

        url_rows,

        [
            78,
            18
        ]

    )


# ============================================================
# TOP USER AGENTS
# ============================================================

if user_agents:

    print()

    print_box(
        "TOP USER AGENTS"
    )


    agent_rows = [

        [
            agent,
            count
        ]

        for agent, count
        in user_agents.most_common(10)

    ]


    print_table(

        [
            "User Agent",
            "Requests"
        ],

        agent_rows,

        [
            78,
            18
        ]

    )


# ============================================================
# GROUND-TRUTH DETECTIONS
# ============================================================

if ground_truth_counts:

    print()

    print_box(
        "GROUND-TRUTH DETECTIONS"
    )


    ground_truth_rows = []


    for label, count in (
        ground_truth_counts.most_common()
    ):

        affected_ips = sum(

            1

            for ip
            in ground_truth_types

            if label
            in ground_truth_types[ip]

        )


        ground_truth_rows.append([

            label,

            count,

            affected_ips

        ])


    print_table(

        [
            "Ground-Truth Label",
            "Matching Events",
            "Affected IPs"
        ],

        ground_truth_rows,

        [
            52,
            20,
            20
        ]

    )



# ============================================================
# SYSTEM / AUTHENTICATION TABLES
# ============================================================

if system_events:

    print()
    print_box("SYSTEM / AUTHENTICATION INDICATORS")

    print_table(
        ["Event", "Count"],
        [
            [event, count]
            for event, count
            in system_events.most_common(20)
        ],
        [65, 31]
    )


if auth_methods:

    print()
    print_box("AUTHENTICATION METHODS")

    print_table(
        ["Method", "Events"],
        [
            [method, count]
            for method, count
            in auth_methods.most_common()
        ],
        [65, 31]
    )


# ============================================================
# LOG FAMILY TABLES
# ============================================================

family_tables = [
    ("MAIL / SMTP / IMAP EVENTS", mail_events),
    ("FIREWALL / NETWORK EVENTS", firewall_events),
    ("DNS EVENTS", dns_events),
    ("DATABASE EVENTS", database_events),
    ("IDS / IPS EVENTS", ids_events),
    ("NETWORK EVENTS", network_events),
    ("GENERIC / OTHER SYSLOG PROGRAMS", other_syslog_events),
]

for title, counter in family_tables:
    if counter:
        print()
        print_box(title)
        print_table(
            ["Program / Event", "Count"],
            counter.most_common(20),
            [65, 31]
        )


# ============================================================
# SECURITY FINDINGS
# ============================================================

print()

print_box(
    "SECURITY FINDINGS"
)


if suspicious_ips:

    sorted_ips = sorted(

        suspicious_ips,

        key=lambda ip:
        risk_scores[ip],

        reverse=True

    )


    for ip in sorted_ips:

        print()

        print(
            f"IP: {ip}"
        )

        print(

            f"Risk Score: "
            f"{risk_scores[ip]}/100 "
            f"({risk_level(risk_scores[ip])})"

        )


        if attack_types[ip]:

            print(
                "\nDetected Behaviour:"
            )


            for attack in sorted(
                attack_types[ip]
            ):

                print(
                    f"  ⚠ {attack}"
                )


        if ground_truth_types[ip]:

            print(
                "\nGround-Truth Labels:"
            )


            for label in sorted(
                ground_truth_types[ip]
            ):

                print(
                    f"  ✓ {label}"
                )


        evidence = list(

            dict.fromkeys(
                attack_evidence[ip]
            )

        )


        if evidence:

            print(
                "\nEvidence:"
            )


            for item in evidence[:12]:

                print(
                    f"  • {item}"
                )


else:

    print(
        "✅ No suspicious indicators detected."
    )


# ============================================================
# SECURITY ASSESSMENT
# ============================================================

print()

print_box(
    "SECURITY ASSESSMENT"
)


if overall_risk == "HIGH":

    print(
        "🔴 HIGH RISK"
    )

    print(
        "Multiple indicators require investigation."
    )


elif overall_risk == "MEDIUM":

    print(
        "🟠 MEDIUM RISK"
    )

    print(
        "Some activity requires further investigation."
    )

elif overall_risk == "REVIEW":

    print(
        "🟡 REVIEW REQUIRED"
    )

    print(
        "Parser coverage is too low to confidently classify this dataset as LOW RISK."
    )

else:

    print(
        "🟢 LOW RISK"
    )

    print(
        "No strong malicious indicators were identified."
    )


if overall_risk == "LOW":
    print(
        "Low risk does not guarantee that the environment "
        "is completely safe."
    )


# ============================================================
# LOG QUALITY
# ============================================================

if nul_padding_lines:
    print()
    print_box("LOG QUALITY")
    print(f"NUL padding records ignored: {nul_padding_lines}")


# ============================================================
# UNPARSED LOGS
# ============================================================

if unknown_lines:

    print()

    print_box(
        "UNPARSED LOGS"
    )


    print(
        f"Unparsed lines: {unknown_lines}"
    )


    for example in unparsed_examples:

        print(
            f"  • {example}"
        )


# ============================================================
# RECOMMENDATION
# ============================================================

print()

print_box(
    "RECOMMENDATION"
)


if overall_risk == "HIGH":

    recommendations = [

        "Investigate the highest-risk IP addresses.",

        "Review suspicious URLs, methods and "
        "authentication events.",

        "Correlate findings with authentication "
        "and system logs.",

        "Preserve relevant log entries for "
        "further investigation."

    ]


elif overall_risk == "MEDIUM":

    recommendations = [

        "Review flagged IP addresses and repeated failures.",
        "Inspect suspicious URLs and response codes.",
        "Continue monitoring related activity."

    ]

elif overall_risk == "REVIEW":

    recommendations = [
        "Improve parser coverage before treating this dataset as LOW RISK.",
        "Review the PARSING COVERAGE and UNPARSED LOGS sections.",
        "Identify the dominant unparsed log format and add a dedicated parser."
    ]

else:

    recommendations = [

        "Continue monitoring the logs "
        "for unusual behaviour.",

        "Review future changes in "
        "traffic patterns."

    ]


for number, recommendation in enumerate(
    recommendations,
    start=1
):

    print(
        f"{number}. {recommendation}"
    )


# ============================================================
# REPORT.TXT GENERATION
# ============================================================

report_lines = []


def report_add(text=""):

    report_lines.append(
        text
    )


def report_box(title):

    report_add(
        make_box(title)
    )


def report_table(
    headers,
    rows,
    widths
):

    report_add(
        make_table(
            headers,
            rows,
            widths
        )
    )


# ============================================================
# REPORT HEADER
# ============================================================

report_box(
    "SOC LOG ANALYZER"
)

report_add(
    f"Input: {log_file}"
)

report_add()


# ============================================================
# REPORT SUMMARY
# ============================================================

report_box(
    "ANALYSIS SUMMARY"
)

report_table(

    [
        "Metric",
        "Value"
    ],

    summary_rows,

    [
        40,
        56
    ]

)

report_add()

report_box("PARSING COVERAGE")
report_table(
    ["Parser Family", "Recognized Lines"],
    parse_family_counts.most_common(),
    [65, 31]
)
report_add()


# ============================================================
# REPORT IP CLASSIFICATION
# ============================================================

report_box("IP CLASSIFICATION")
report_table(
    ["Classification", "Count"],
    ip_classifications.most_common(),
    [65, 31]
)
report_add()


# ============================================================
# REPORT IP TABLE
# ============================================================

report_box(
    "IP INVESTIGATION"
)

report_table(

    [
        "IP Address",
        "Observations",
        "Unique URL",
        "404",
        "401",
        "403",
        "Failed",
        "PAM Fail",
        "Invalid User",
        "Score",
        "Risk"
    ],

    ip_rows,

    [
        22,
        10,
        12,
        7,
        7,
        7,
        9,
        12,
        12,
        9,
        9
    ]

)

report_add()


# ============================================================
# REPORT STATUS
# ============================================================

if status_codes:

    report_box(
        "HTTP STATUS ANALYSIS"
    )


    report_table(

        [
            "Code",
            "Meaning",
            "Count",
            "Percentage"
        ],

        status_rows,

        [
            10,
            30,
            16,
            20
        ]

    )

    report_add()


# ============================================================
# REPORT METHODS
# ============================================================

if http_methods:

    report_box(
        "HTTP METHODS"
    )


    report_table(

        [
            "Method",
            "Requests",
            "Percentage"
        ],

        method_rows,

        [
            20,
            20,
            36
        ]

    )

    report_add()


# ============================================================
# REPORT URLS
# ============================================================

if url_count:

    report_box(
        "TOP REQUESTED URLS"
    )


    report_table(

        [
            "URL / PATH",
            "Requests"
        ],

        url_rows,

        [
            78,
            18
        ]

    )

    report_add()


# ============================================================
# REPORT USER AGENTS
# ============================================================

if user_agents:

    report_box(
        "TOP USER AGENTS"
    )


    report_table(

        [
            "User Agent",
            "Requests"
        ],

        agent_rows,

        [
            78,
            18
        ]

    )

    report_add()


# ============================================================
# REPORT GROUND TRUTH
# ============================================================

if ground_truth_counts:

    report_box(
        "GROUND-TRUTH DETECTIONS"
    )


    report_table(

        [
            "Ground-Truth Label",
            "Matching Events",
            "Affected IPs"
        ],

        ground_truth_rows,

        [
            52,
            20,
            20
        ]

    )

    report_add()



# ============================================================
# REPORT SYSTEM / AUTHENTICATION TABLES
# ============================================================

if system_events:

    report_box("SYSTEM / AUTHENTICATION INDICATORS")

    report_table(
        ["Event", "Count"],
        [
            [event, count]
            for event, count
            in system_events.most_common(20)
        ],
        [65, 31]
    )

    report_add()


if auth_methods:

    report_box("AUTHENTICATION METHODS")

    report_table(
        ["Method", "Events"],
        [
            [method, count]
            for method, count
            in auth_methods.most_common()
        ],
        [65, 31]
    )

    report_add()


# ============================================================
# REPORT LOG FAMILY TABLES
# ============================================================

family_tables = [
    ("MAIL / SMTP / IMAP EVENTS", mail_events),
    ("FIREWALL / NETWORK EVENTS", firewall_events),
    ("DNS EVENTS", dns_events),
    ("DATABASE EVENTS", database_events),
    ("IDS / IPS EVENTS", ids_events),
    ("NETWORK EVENTS", network_events),
    ("GENERIC / OTHER SYSLOG PROGRAMS", other_syslog_events),
]

for title, counter in family_tables:
    if counter:
        report_box(title)
        report_table(
            ["Program / Event", "Count"],
            counter.most_common(20),
            [65, 31]
        )
        report_add()


# ============================================================
# REPORT SECURITY FINDINGS
# ============================================================

report_box(
    "SECURITY FINDINGS"
)


if suspicious_ips:

    for ip in sorted(

        suspicious_ips,

        key=lambda value:
        risk_scores[value],

        reverse=True

    ):

        report_add()

        report_add(
            f"IP: {ip}"
        )

        report_add(

            f"Risk Score: "
            f"{risk_scores[ip]}/100 "
            f"({risk_level(risk_scores[ip])})"

        )


        if attack_types[ip]:

            report_add(
                "Detected Behaviour:"
            )


            for attack in sorted(
                attack_types[ip]
            ):

                report_add(
                    f"  - {attack}"
                )


        if ground_truth_types[ip]:

            report_add(
                "Ground-Truth Labels:"
            )


            for label in sorted(
                ground_truth_types[ip]
            ):

                report_add(
                    f"  - {label}"
                )


        evidence = list(

            dict.fromkeys(
                attack_evidence[ip]
            )

        )


        if evidence:

            report_add(
                "Evidence:"
            )


            for item in evidence[:12]:

                report_add(
                    f"  - {item}"
                )


else:

    report_add(
        "No suspicious indicators detected."
    )


report_add()


# ============================================================
# REPORT ASSESSMENT
# ============================================================

report_box(
    "SECURITY ASSESSMENT"
)


report_add(
    f"Overall Risk: {overall_risk}"
)


if overall_risk == "HIGH":

    report_add(
        "Multiple indicators require investigation."
    )


elif overall_risk == "MEDIUM":

    report_add(
        "Some activity requires further investigation."
    )

elif overall_risk == "REVIEW":

    report_add(
        "Parser coverage is too low to confidently classify this dataset as LOW RISK."
    )

else:

    report_add(
        "No strong malicious indicators were identified."
    )


if overall_risk == "LOW":
    report_add(
        "Low risk does not guarantee that the environment "
        "is completely safe."
    )


report_add()


# ============================================================
# REPORT LOG QUALITY
# ============================================================

if nul_padding_lines:
    report_box("LOG QUALITY")
    report_add(f"NUL padding records ignored: {nul_padding_lines}")
    report_add()


# ============================================================
# REPORT UNPARSED
# ============================================================

if unknown_lines:

    report_box(
        "UNPARSED LOGS"
    )


    report_add(
        f"Unparsed lines: {unknown_lines}"
    )


    for example in unparsed_examples:

        report_add(
            f"  - {example}"
        )


    report_add()


# ============================================================
# REPORT RECOMMENDATION
# ============================================================

report_box(
    "RECOMMENDATION"
)


for number, recommendation in enumerate(
    recommendations,
    start=1
):

    report_add(
        f"{number}. {recommendation}"
    )


# ============================================================
# PROCESSING METADATA
# ============================================================

analysis_duration = max(time.monotonic() - analysis_started, 0.001)
lines_per_second = total_lines / analysis_duration
processing_rows = [
    ["Input size", f"{source_file_size / (1024**3):.2f} GB" if source_file_size >= 1024**3 else f"{source_file_size / (1024**2):.2f} MB"],
    ["Compression", "gzip" if source_is_gzip else "plain text"],
    ["Processing time", f"{analysis_duration:.1f} seconds"],
    ["Throughput", f"{lines_per_second:,.0f} lines/sec"],
]

print()
print_box("PROCESSING STATISTICS")
print_table(["Metric", "Value"], processing_rows, [65, 31])

# ============================================================
# REPORT PROCESSING STATISTICS
# ============================================================

report_box("PROCESSING STATISTICS")
report_table(["Metric", "Value"], processing_rows, [65, 31])
report_add()

with open(
    "report.txt",
    "w",
    encoding="utf-8"
) as report:

    report.write(
        "\n".join(report_lines)
    )

    report.write("\n")


clear_status_line()

print(
    "\n📄 Report generated: report.txt"
)

print(
    f"📊 Analysis complete — {total_lines:,} log lines processed."
)
