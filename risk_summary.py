# AI Operations Assistant
# Simple operational risk summary example

risks = [
    {"name": "Weak Password Policy", "severity": 9},
    {"name": "Outdated Firewall Firmware", "severity": 8},
    {"name": "No MFA for VPN", "severity": 10},
    {"name": "Inactive User Accounts", "severity": 6}
]

print("=== AI Operations Risk Summary ===\n")

for risk in risks:

    # Store the severity number from the dictionary
    severity = risk["severity"]

    # Determine priority level
    if severity >= 9:
        priority = "CRITICAL"

    elif severity >= 7:
        priority = "HIGH"

    else:
        priority = "MODERATE"

    # Print formatted output
    print(f"[{priority}] Severity {severity} - {risk['name']}")

print("\nRecommended Actions:")
print("Prioritize remediation of the highest severity risks first.")
