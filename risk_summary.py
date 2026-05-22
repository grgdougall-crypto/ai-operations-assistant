import csv
from datetime import datetime

# AI Operations Assistant
# Simple operational risk summary example

risks = []

# Load existing risks from the CSV file
with open("risks.csv", mode="r") as file:
    csv_reader = csv.DictReader(file)

    for row in csv_reader:
        risks.append({
            "name": row["name"],
            "severity": int(row["severity"]),
            "timestamp": row["timestamp"]
        })


def determine_priority(severity):
    if severity >= 9:
        return "CRITICAL"
    elif severity >= 7:
        return "HIGH"
    else:
        return "MODERATE"


def recommend_action(risk_name):
    risk_name = risk_name.lower()

    if "password" in risk_name:
        return "Enforce stronger password policies and password rotation."
    elif "mfa" in risk_name:
        return "Enable multi-factor authentication for all remote access."
    elif "firewall" in risk_name:
        return "Update firewall firmware and review network rules."
    elif "inactive" in risk_name:
        return "Disable or remove inactive user accounts."
    elif "phishing" in risk_name:
        return "Provide phishing awareness training to employees."
    else:
        return "Review and remediate this risk as soon as possible."


print("=== AI Operations Risk Summary ===\n")

# Collect a new risk from the user
new_risk_name = input("Enter a new risk name: ")
new_risk_severity = int(input("Enter severity level (1-10): "))
timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Add the new risk into the list
risks.append({
    "name": new_risk_name,
    "severity": new_risk_severity,
    "timestamp": timestamp
})

# Save the new risk back into the CSV file
with open("risks.csv", mode="a", newline="") as file:
    csv_writer = csv.writer(file)
    csv_writer.writerow([new_risk_name, new_risk_severity, timestamp])

# Sort risks by severity, highest first
sorted_risks = sorted(risks, key=lambda risk: risk["severity"], reverse=True)

critical_count = 0
high_count = 0
moderate_count = 0

for risk in sorted_risks:
    severity = risk["severity"]
    priority = determine_priority(severity)
    recommendation = recommend_action(risk["name"])

    if priority == "CRITICAL":
        critical_count += 1
    elif priority == "HIGH":
        high_count += 1
    else:
        moderate_count += 1

    print(f"[{priority}] Severity {severity} - {risk['name']}")
    print(f"Timestamp: {risk['timestamp']}")
    print(f"Recommendation: {recommendation}\n")

print("=== Executive Summary ===")
print(f"Critical Risks: {critical_count}")
print(f"High Risks: {high_count}")
print(f"Moderate Risks: {moderate_count}")

print("\nRecommended Actions:")
print("Prioritize remediation of critical authentication and network security risks.")