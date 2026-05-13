# SOC Log Analyzer
# Created by: Darshan Mishra

# Ask user for log file path
log_file = input("Enter log file path: ")


# Try opening the file
try:
    with open(log_file, "r") as file:
        logs = file.readlines()

except FileNotFoundError:
    print("❌ File not found! Please check the file path.")
    exit()


# Counters
failed_logins = 0
successful_logins = 0
ip_attempts = {}


print("\n===== SOC LOG ANALYZER =====")


# Analyze logs
for line in logs:

    line = line.strip()

    # Count failed logins
    if "LOGIN FAILED" in line:
        failed_logins += 1

        # Extract IP address
        if "IP:" in line:
            ip = line.split("IP:")[1].strip()

            # Count failed attempts for each IP
            if ip in ip_attempts:
                ip_attempts[ip] += 1
            else:
                ip_attempts[ip] = 1

    # Count successful logins
    elif "LOGIN SUCCESS" in line:
        successful_logins += 1


# Show report
print("\n===== ANALYSIS REPORT =====")
print(f"Total Failed Logins: {failed_logins}")
print(f"Total Successful Logins: {successful_logins}")


# Detect suspicious activity
if failed_logins >= 3:
    print("\n⚠️ Alert: Multiple failed login attempts detected.")
    print("Possible brute-force activity.")


# Show suspicious IPs
if ip_attempts:
    print("\n===== Suspicious IP Activity =====")

    for ip, count in ip_attempts.items():
        print(f"{ip} --> {count} failed attempts")

    top_attacker = max(ip_attempts, key=ip_attempts.get)

    print("\n🚨 Top Attacker IP:", top_attacker)
    print("Failed Attempts:", ip_attempts[top_attacker])


# Risk level
if failed_logins <= 2:
    risk_level = "LOW"

elif failed_logins <= 4:
    risk_level = "MEDIUM"

else:
    risk_level = "HIGH"

print("\n===== RISK LEVEL =====")
print("Risk:", risk_level)


# Generate report file
with open("security_report.txt", "w") as report:

    report.write("===== SOC LOG ANALYZER REPORT =====\n\n")

    report.write(f"Total Failed Logins: {failed_logins}\n")
    report.write(f"Total Successful Logins: {successful_logins}\n")

    report.write("\n===== Suspicious IP Activity =====\n")

    for ip, count in ip_attempts.items():
        report.write(f"{ip} --> {count} failed attempts\n")

    if ip_attempts:
        report.write(f"\nTop Attacker IP: {top_attacker}\n")
        report.write(
            f"Failed Attempts: {ip_attempts[top_attacker]}\n"
        )

    report.write(f"\nRisk Level: {risk_level}\n")


print("\n📄 Security report generated successfully!")
