import csv
from datetime import datetime

CSV_FILE = "risks.csv"
TXT_REPORT = "risk_report.txt"
MD_REPORT = "risk_report.md"

categories = [
    "Authentication",
    "Network",
    "Endpoint Security",
    "Data Protection",
    "Backup and Recovery",
    "Incident Response",
    "Security Awareness",
    "Infrastructure",
    "User Access",
    "Physical Security"
]

risks = []

with open(CSV_FILE, mode="r") as file:
    reader = csv.DictReader(file)

    for row in reader:
        risks.append({
            "name": row["name"].upper(),
            "severity": int(row["severity"]),
            "category": row["category"],
            "status": row["status"],
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
    elif "backup" in risk_name:
        return "Verify backup integrity and perform a test restore."
    elif "data" in risk_name or "leak" in risk_name:
        return "Review data access controls and investigate possible exposure."
    elif "incident" in risk_name:
        return "Review and test the incident response plan."
    elif "wifi" in risk_name or "wi-fi" in risk_name:
        return "Review wireless security settings and enforce strong encryption."
    elif "admin" in risk_name:
        return "Review privileged access and remove shared or unnecessary admin accounts."
    elif "laptop" in risk_name:
        return "Enable full-disk encryption and verify endpoint security controls."
    elif "router" in risk_name:
        return "Replace default credentials and restrict management access."
    elif "domain controller" in risk_name:
        return "Patch and harden domain controllers immediately."
    elif "dns" in risk_name:
        return "Review DNS configuration, restrict zone transfers, and validate records."
    elif "tls" in risk_name:
        return "Disable deprecated TLS versions and enforce modern encryption standards."
    elif "antivirus" in risk_name:
        return "Update antivirus signatures and confirm endpoint protection status."
    elif "service account" in risk_name:
        return "Review service account permissions, rotate credentials, and remove unused accounts."
    else:
        return "Review and remediate this risk as soon as possible."


def choose_category():
    print("\nSelect a category:")

    for index, category in enumerate(categories, start=1):
        print(f"{index}. {category}")

    choice = int(input("Enter category number: "))

    return categories[choice - 1]


print("=== AI Operations Risk Summary ===\n")

new_risk_name = input("Enter a new risk name: ").upper()
new_risk_severity = int(input("Enter severity level (1-10): "))
new_risk_category = choose_category()
new_risk_status = input("Enter status: ").upper()

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

new_risk = {
    "name": new_risk_name,
    "severity": new_risk_severity,
    "category": new_risk_category,
    "status": new_risk_status,
    "timestamp": timestamp
}

risks.append(new_risk)

with open(CSV_FILE, mode="a", newline="") as file:
    writer = csv.writer(file)
    writer.writerow([
        new_risk["name"],
        new_risk["severity"],
        new_risk["category"],
        new_risk["status"],
        new_risk["timestamp"]
    ])

for risk in risks:
    risk["priority"] = determine_priority(risk["severity"])
    risk["recommendation"] = recommend_action(risk["name"])

sorted_risks = sorted(risks, key=lambda risk: risk["severity"], reverse=True)

critical_count = sum(1 for risk in risks if risk["priority"] == "CRITICAL")
high_count = sum(1 for risk in risks if risk["priority"] == "HIGH")
moderate_count = sum(1 for risk in risks if risk["priority"] == "MODERATE")

category_counts = {}
status_counts = {}

for risk in risks:
    category_counts[risk["category"]] = category_counts.get(risk["category"], 0) + 1
    status_counts[risk["status"]] = status_counts.get(risk["status"], 0) + 1

average_severity = sum(risk["severity"] for risk in risks) / len(risks)
highest_risk = max(risks, key=lambda risk: risk["severity"])
newest_risk = risks[-1]

for risk in sorted_risks:
    print(f"[{risk['priority']}] Severity {risk['severity']} - {risk['name']}")
    print(f"Category: {risk['category']}")
    print(f"Status: {risk['status']}")
    print(f"Timestamp: {risk['timestamp']}")
    print(f"Recommendation: {risk['recommendation']}\n")

print("=== Executive Summary ===")
print(f"Critical Risks: {critical_count}")
print(f"High Risks: {high_count}")
print(f"Moderate Risks: {moderate_count}")
print(f"Average Severity: {average_severity:.2f}")
print(f"Highest Risk: {highest_risk['name']} (Severity {highest_risk['severity']})")
print(f"Newest Risk Added: {newest_risk['name']}")

print("\n=== Category Summary ===")
for category, count in category_counts.items():
    print(f"{category}: {count}")

print("\n=== Status Summary ===")
for status, count in status_counts.items():
    print(f"{status}: {count}")

with open(TXT_REPORT, mode="w") as report:
    report.write("AI Operations Risk Report\n")
    report.write("=========================\n\n")

    for risk in sorted_risks:
        report.write(f"[{risk['priority']}] Severity {risk['severity']} - {risk['name']}\n")
        report.write(f"Category: {risk['category']}\n")
        report.write(f"Status: {risk['status']}\n")
        report.write(f"Timestamp: {risk['timestamp']}\n")
        report.write(f"Recommendation: {risk['recommendation']}\n\n")

    report.write("Executive Summary\n")
    report.write("=================\n")
    report.write(f"Critical Risks: {critical_count}\n")
    report.write(f"High Risks: {high_count}\n")
    report.write(f"Moderate Risks: {moderate_count}\n")
    report.write(f"Average Severity: {average_severity:.2f}\n")
    report.write(f"Highest Risk: {highest_risk['name']} (Severity {highest_risk['severity']})\n")
    report.write(f"Newest Risk Added: {newest_risk['name']}\n\n")

    report.write("Category Summary\n")
    report.write("================\n")
    for category, count in category_counts.items():
        report.write(f"{category}: {count}\n")

    report.write("\nStatus Summary\n")
    report.write("==============\n")
    for status, count in status_counts.items():
        report.write(f"{status}: {count}\n")

with open(MD_REPORT, mode="w") as report:
    report.write("# AI Operations Risk Report\n\n")

    report.write("| Risk | Priority | Severity | Category | Status | Timestamp | Recommendation |\n")
    report.write("|------|----------|----------|----------|--------|------------|----------------|\n")

    for risk in sorted_risks:
        report.write(
            f"| {risk['name']} | "
            f"{risk['priority']} | "
            f"{risk['severity']} | "
            f"{risk['category']} | "
            f"{risk['status']} | "
            f"{risk['timestamp']} | "
            f"{risk['recommendation']} |\n"
        )

    report.write("\n---\n\n")
    report.write("## Executive Summary\n\n")
    report.write(f"- Critical Risks: **{critical_count}**\n")
    report.write(f"- High Risks: **{high_count}**\n")
    report.write(f"- Moderate Risks: **{moderate_count}**\n")
    report.write(f"- Average Severity: **{average_severity:.2f}**\n")
    report.write(f"- Highest Risk: **{highest_risk['name']}** (Severity {highest_risk['severity']})\n")
    report.write(f"- Newest Risk Added: **{newest_risk['name']}**\n")

    report.write("\n---\n\n")
    report.write("## Category Summary\n\n")
    for category, count in category_counts.items():
        report.write(f"- {category}: **{count}**\n")

    report.write("\n---\n\n")
    report.write("## Status Summary\n\n")
    for status, count in status_counts.items():
        report.write(f"- {status}: **{count}**\n")