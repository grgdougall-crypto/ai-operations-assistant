# AI Operations Assistant
# Simple operational risk summary example

high_risk_items = [
    "Outdated firewall firmware",
    "Weak password policy",
    "No MFA enabled for VPN access"
]

print("=== AI Operations Risk Summary ===\n")

for item in high_risk_items:
    print(f"[HIGH RISK] {item}")

print("\nRecommended Actions:")
print("Prioritize remediation of authentication and network security controls.")
