# AI Operations Assistant
# Simple operational risk summary example

risks = [
    {"name": "Weak Password Policy", "severity": 9},
    {"name": "Outdated Firewall Firmware", "severity": 8},
    {"name": "No MFA for VPN", "severity": 10},
    {"name": "Inactive User Accounts", "severity": 6}
]

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

sorted_risks = sorted(risks, key=lambda risk: risk["severity"], reverse=True)

critical_count = 0
high_count = 0
moderate_count = 0

for risk in sorted_risks:

    # Store the severity number from the dictionary
    severity = risk["severity"]

    # Determine priority level
    priority = determine_priority(severity)

    # Count priority totals
    if priority == "CRITICAL":
        critical_count += 1

    elif priority == "HIGH":
        high_count += 1

    else:
        moderate_count += 1

    # Print formatted output
    print(f"[{priority}] Severity {severity} - {risk['name']}")

print("\n=== Executive Summary ===")

print(f"Critical Risks: {critical_count}")
print(f"High Risks: {high_count}")
print(f"Moderate Risks: {moderate_count}")

print("\nRecommended Actions:")
print("Prioritize remediation of critical authentication and network security risks.")