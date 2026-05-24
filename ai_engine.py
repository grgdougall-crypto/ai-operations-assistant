RECOMMENDATION_LIBRARY = [
    {
        "keywords": ["mfa", "multi-factor", "2fa", "vpn", "remote access"],
        "recommendation": "Require MFA for VPN, remote access, privileged accounts, and cloud applications. Review access logs and disable accounts that no longer require remote access.",
        "rationale": "Remote access weaknesses can allow unauthorized users to enter the environment and move laterally if credentials are compromised.",
    },
    {
        "keywords": ["password", "weak password", "credential", "login"],
        "recommendation": "Enforce stronger password policies, require password length and complexity, enable account lockout protections, and review failed login activity.",
        "rationale": "Credential weaknesses increase the likelihood of account takeover, privilege abuse, and unauthorized access to sensitive systems.",
    },
    {
        "keywords": ["firewall", "open port", "rule", "inbound"],
        "recommendation": "Review firewall rules, remove unnecessary inbound access, restrict management ports, document approved exceptions, and verify firmware is current.",
        "rationale": "Overly permissive network rules increase attack surface and can expose internal services to unauthorized access.",
    },
    {
        "keywords": ["rdp", "remote desktop", "3389"],
        "recommendation": "Disable public RDP exposure, restrict access through VPN or jump hosts, enforce MFA, and limit access to approved administrative users.",
        "rationale": "Exposed remote desktop access is a common entry point for ransomware, brute-force attacks, and unauthorized administrative access.",
    },
    {
        "keywords": ["phishing", "email", "social engineering"],
        "recommendation": "Provide phishing awareness training, enable email filtering, review reported messages, and run targeted simulations for high-risk user groups.",
        "rationale": "Phishing risk can lead to credential theft, malware infection, financial fraud, and unauthorized access to business systems.",
    },
    {
        "keywords": ["backup", "restore", "backup share", "recovery"],
        "recommendation": "Verify backup integrity, restrict backup share permissions, perform a documented test restore, and confirm backups are protected from ransomware.",
        "rationale": "Weak backup controls can prevent recovery during ransomware, accidental deletion, system failure, or disaster scenarios.",
    },
    {
        "keywords": ["database", "sql", "data exposure", "db"],
        "recommendation": "Restrict database access, review user permissions, disable public exposure, enforce encryption, and monitor for unauthorized queries.",
        "rationale": "Database exposure can compromise sensitive information, business records, customer data, or regulated data.",
    },
    {
        "keywords": ["cloud", "s3", "azure", "storage bucket", "cloud storage"],
        "recommendation": "Review cloud permissions, disable public access where not required, enforce least privilege, enable logging, and validate configuration baselines.",
        "rationale": "Cloud misconfiguration can expose sensitive data or allow unauthorized changes across hosted systems and services.",
    },
    {
        "keywords": ["admin", "administrator", "privileged", "local admin", "shared admin"],
        "recommendation": "Review privileged access, remove unnecessary admin rights, rotate credentials, enforce MFA, and replace shared admin accounts with named accounts.",
        "rationale": "Excessive administrative access increases the impact of compromised accounts and weakens accountability.",
    },
    {
        "keywords": ["laptop", "endpoint", "workstation", "device", "edr"],
        "recommendation": "Verify endpoint protection, enable full-disk encryption, confirm patch compliance, and ensure the device is enrolled in centralized management.",
        "rationale": "Endpoint weaknesses can create entry points for malware, data loss, unauthorized access, or unmanaged system exposure.",
    },
    {
        "keywords": ["api", "endpoint", "token", "key"],
        "recommendation": "Review API authentication, rotate exposed keys or tokens, restrict public access, validate rate limiting, and monitor API activity logs.",
        "rationale": "Weak API controls can expose application functions, sensitive data, or backend services to unauthorized use.",
    },
    {
        "keywords": ["ssl", "tls", "certificate", "cert"],
        "recommendation": "Renew expired certificates, verify TLS configuration, remove weak protocols, and document certificate ownership and renewal dates.",
        "rationale": "Certificate and TLS issues can disrupt service availability or weaken encrypted communications.",
    },
    {
        "keywords": ["unsupported", "legacy", "operating system", "end of life", "eol"],
        "recommendation": "Upgrade unsupported systems, isolate legacy assets, apply compensating controls, and create a retirement or replacement plan.",
        "rationale": "Legacy or unsupported systems may lack security patches and can create persistent exposure across the environment.",
    },
    {
        "keywords": ["monitoring", "logging", "logs", "siem", "alert"],
        "recommendation": "Enable centralized logging, configure alerting for high-risk events, review monitoring coverage, and validate that alerts are assigned to an owner.",
        "rationale": "Weak monitoring reduces visibility and delays detection, escalation, and response during security or operational incidents.",
    },
    {
        "keywords": ["encryption", "unencrypted", "weak encryption", "plaintext"],
        "recommendation": "Enable strong encryption, remove weak protocols, protect sensitive data at rest and in transit, and verify encryption settings through policy review.",
        "rationale": "Weak encryption controls can expose sensitive information during storage, transmission, or unauthorized access events.",
    },
    {
        "keywords": ["patch", "unpatched", "vulnerability", "outdated", "firmware"],
        "recommendation": "Prioritize patching based on severity, validate the affected asset, confirm maintenance windows, apply updates, and rescan to verify remediation.",
        "rationale": "Unpatched systems increase the likelihood of exploitation, especially when vulnerabilities are public or actively targeted.",
    },
]


def determine_priority_label(severity):
    if severity >= 9:
        return "Critical"
    if severity >= 7:
        return "High"
    if severity >= 4:
        return "Moderate"
    return "Low"


def find_best_ai_match(name, category):
    risk_text = f"{name} {category}".lower()
    best_match = None
    best_score = 0

    for item in RECOMMENDATION_LIBRARY:
        score = 0

        for keyword in item["keywords"]:
            if keyword in risk_text:
                score += 1

        if score > best_score:
            best_score = score
            best_match = item

    return best_match


def generate_ai_recommendation(name, category):
    best_match = find_best_ai_match(name, category)

    if best_match:
        return best_match["recommendation"]

    return "Review the risk, validate business impact, assign an owner, document remediation steps, and track progress until the risk is reduced or formally accepted."


def generate_ai_rationale(name, category, severity):
    best_match = find_best_ai_match(name, category)
    priority_label = determine_priority_label(severity)

    if best_match:
        base_rationale = best_match["rationale"]
    else:
        base_rationale = "This item should be reviewed because it may affect confidentiality, integrity, availability, compliance, or operational continuity."

    return f"{priority_label} priority: {base_rationale}"


def generate_ai_analysis(name, category, severity):
    return {
        "recommendation": generate_ai_recommendation(name, category),
        "rationale": generate_ai_rationale(name, category, severity),
    }
