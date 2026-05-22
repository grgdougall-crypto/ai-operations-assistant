import csv

# AI Operations Assistant
# Simple operational risk summary example

risks = []

# Load existing risks from the CSV file
with open("risks.csv", mode="r") as file:
    csv_reader = csv.DictReader(file)

    for row in csv_reader:
        risks.append({
            "name": row["name"],
            "severity": int(row["severity"])
        })


def determine_priority(severity):
    if severity >= 9:
        return "CRITICAL"
    elif severity >= 7:
        return "HIGH"
    else:
        return "MODERATE"


print("=== AI Operations Risk Summary ===\n")

# Collect a new risk from the user
new_risk_name = input("Enter a new risk name: ")
new_risk_severity = int(input("Enter severity level (1-10): "))

# Add the new risk into the list
risks.append({
    "name": new_risk_name,
    "severity": new_risk_severity
})

# Save the new risk back into the CSV file
with open("risks.csv", mode="a", newline="\n") as file:
    csv_writer = csv.writer(file)
    csv_writer.writerow([new_risk_name, new_risk_severity])

# Sort risks by severity, highest first
sorted_risks = sorted(risks, key=lambda risk: risk["severity"], reverse=True)

critical_count = 0
high_count = 0
moderate_count = 0

for risk in sorted_risks:
    severity = risk["severity"]
    priority = determine_priority(severity)

    if priority == "CRITICAL":
        critical_count += 1
    elif priority == "HIGH":
        high_count += 1
    else:
        moderate_count += 1

    print(f"[{priority}] Severity {severity} - {risk['name']}")

print("\n=== Executive Summary ===")
print(f"Critical Risks: {critical_count}")
print(f"High Risks: {high_count}")
print(f"Moderate Risks: {moderate_count}")

print("\nRecommended Actions:")
print("Prioritize remediation of critical authentication and network security risks.")