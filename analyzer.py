# Apache Log Analyzer
# Created by Darshan Mishra

log_file = input("Enter  log file path: ")

# Open file
try:
    with open(log_file, "r") as file:
        logs = file.readlines()

except FileNotFoundError:
    print("❌ File not found.")
    exit()

# Variables
total_requests = 0
ip_count = {}
status_codes = {}
url_count = {}
http_methods = {}

print("\n===== SOC WEB LOG ANALYZER =====")
# Analyze logs
for line in logs:

    parts = line.split()

    # Skip broken lines
    if len(parts) < 9:
        continue

    total_requests += 1

    # Extract IP
    ip = parts[0]

    if ip in ip_count:
        ip_count[ip] += 1
    else:
        ip_count[ip] = 1

    # Extract status code
    status_code = parts[8]

    if status_code in status_codes:
        status_codes[status_code] += 1
    else:
        status_codes[status_code] = 1

    # Extract HTTP method
    method = parts[5].replace('"', "")

    if method in http_methods:
        http_methods[method] += 1
    else:
        http_methods[method] = 1

    # Extract URL
    url = parts[6]

    if url in url_count:
        url_count[url] += 1
    else:
        url_count[url] = 1


print("\n===== ANALYSIS REPORT =====")
print("Total Requests:", total_requests)

# Top active IP
print("\n===== TOP ACTIVE IPS =====")

sorted_ips = sorted(
    ip_count.items(),
    key=lambda x: x[1],
    reverse=True
)

for ip, count in sorted_ips:
    print(f"{ip} → {count} requests")

top_ip = sorted_ips[0][0]

# Scanning threshold
if ip_count[top_ip] >= 10:
    print("\n⚠ High activity detected.")
    print("Possible scanning activity.")
# Status Code Analysis
# HTTP Status Code Names
status_meaning = {
    "200": "OK",
    "301": "Redirect",
    "302": "Found",
    "400": "Bad Request",
    "401": "Unauthorized",
    "403": "Forbidden",
    "404": "Not Found",
    "500": "Internal Server Error",
    "503": "Service Unavailable"
}

print("\n===== STATUS CODE ANALYSIS =====")

for code, count in status_codes.items():

    meaning = status_meaning.get(
        code,
        "Unknown Status"
    )

    print(
        f"HTTP {code} ({meaning}) → {count}"
    )
# HTTP Method Analysis
print("\n===== HTTP METHODS =====")

for method, count in http_methods.items():
    print(f"{method} → {count}")

# Top URLs
print("\n===== MOST REQUESTED URLS =====")

for url, count in sorted(
    url_count.items(),
    key=lambda x: x[1],
    reverse=True
):
    print(f"{url} → {count}")

# Detection Logic
if "404" in status_codes and status_codes["404"] >= 3:
    print("\n⚠ High number of 404 requests detected.")
    print("Possible scanning activity.")

if ip_count[top_ip] >= 10:
    print("\n⚠ High activity from one IP detected.")
    print("Possible reconnaissance or scanning.")

# Generate report
with open("report.txt", "w") as report:

    report.write("=====  LOG ANALYSIS =====\n\n")
    report.write(f"Total Requests: {total_requests}\n\n")

    report.write("===== TOP ACTIVE IP =====\n")
    report.write(f"IP Address: {top_ip}\n")
    report.write(f"Requests: {ip_count[top_ip]}\n\n")

    report.write("===== STATUS CODE ANALYSIS =====\n")

    for code, count in status_codes.items():
        report.write(f"{code} -> {count}\n")

    report.write("\n===== HTTP METHODS =====\n")

    for method, count in http_methods.items():
        report.write(f"{method} -> {count}\n")

    report.write("\n===== MOST REQUESTED URLS =====\n")

    for url, count in sorted(
        url_count.items(),
        key=lambda x: x[1],
        reverse=True
    ):
        report.write(f"{url} -> {count}\n")

print("\n📄 Report generated: report.txt")
