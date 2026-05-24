import json
import os

try:
    from google import genai
except ImportError:
    genai = None

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


RECOMMENDATION_LIBRARY = [
    {
        "keywords": ["mfa", "multi-factor", "2fa", "vpn", "remote access"],
        "recommendation": (
            "Require MFA for VPN, remote access, privileged accounts, "
            "and cloud applications. Review access logs and disable "
            "accounts that no longer require remote access."
        ),
        "rationale": (
            "Remote access weaknesses can allow unauthorized users "
            "to enter the environment and move laterally if "
            "credentials are compromised."
        ),
    },
    {
        "keywords": ["password", "weak password", "credential", "login"],
        "recommendation": (
            "Enforce stronger password policies, require password "
            "length and complexity, enable account lockout protections, "
            "and review failed login activity."
        ),
        "rationale": (
            "Credential weaknesses increase the likelihood of account "
            "takeover, privilege abuse, and unauthorized access "
            "to sensitive systems."
        ),
    },
    {
        "keywords": ["firewall", "open port", "rule", "inbound"],
        "recommendation": (
            "Review firewall rules, remove unnecessary inbound access, "
            "restrict management ports, document approved exceptions, "
            "and verify firmware is current."
        ),
        "rationale": (
            "Overly permissive network rules increase attack surface "
            "and can expose internal services to unauthorized access."
        ),
    },
    {
        "keywords": ["rdp", "remote desktop", "3389"],
        "recommendation": (
            "Disable public RDP exposure, restrict access through VPN "
            "or jump hosts, enforce MFA, and limit access to approved "
            "administrative users."
        ),
        "rationale": (
            "Exposed remote desktop access is a common entry point "
            "for ransomware, brute-force attacks, and unauthorized "
            "administrative access."
        ),
    },
    {
        "keywords": ["phishing", "email", "social engineering"],
        "recommendation": (
            "Provide phishing awareness training, enable email filtering, "
            "review reported messages, and run targeted simulations "
            "for high-risk user groups."
        ),
        "rationale": (
            "Phishing risk can lead to credential theft, malware infection, "
            "financial fraud, and unauthorized access to business systems."
        ),
    },
    {
        "keywords": ["backup", "restore", "backup share", "recovery"],
        "recommendation": (
            "Verify backup integrity, restrict backup share permissions, "
            "perform a documented test restore, and confirm backups "
            "are protected from ransomware."
        ),
        "rationale": (
            "Weak backup controls can prevent recovery during ransomware, "
            "accidental deletion, system failure, or disaster scenarios."
        ),
    },
    {
        "keywords": ["database", "sql", "data exposure", "db"],
        "recommendation": (
            "Restrict database access, review user permissions, "
            "disable public exposure, enforce encryption, "
            "and monitor for unauthorized queries."
        ),
        "rationale": (
            "Database exposure can compromise sensitive information, "
            "business records, customer data, or regulated data."
        ),
    },
    {
        "keywords": ["cloud", "s3", "azure", "storage bucket", "cloud storage"],
        "recommendation": (
            "Review cloud permissions, disable public access where "
            "not required, enforce least privilege, enable logging, "
            "and validate configuration baselines."
        ),
        "rationale": (
            "Cloud misconfiguration can expose sensitive data or allow "
            "unauthorized changes across hosted systems and services."
        ),
    },
    {
        "keywords": ["admin", "administrator", "privileged", "local admin", "shared admin"],
        "recommendation": (
            "Review privileged access, remove unnecessary admin rights, "
            "rotate credentials, enforce MFA, and replace shared "
            "admin accounts with named accounts."
        ),
        "rationale": (
            "Excessive administrative access increases the impact "
            "of compromised accounts and weakens accountability."
        ),
    },
    {
        "keywords": ["endpoint", "workstation", "laptop", "device", "edr"],
        "recommendation": (
            "Verify endpoint protection, enable full-disk encryption, "
            "confirm patch compliance, and ensure the device is enrolled "
            "in centralized management."
        ),
        "rationale": (
            "Endpoint weaknesses can create entry points for malware, "
            "data loss, unauthorized access, or unmanaged system exposure."
        ),
    },
    {
        "keywords": ["api", "token", "key", "secret"],
        "recommendation": (
            "Review API authentication, rotate exposed keys or tokens, "
            "restrict public access, validate rate limiting, and monitor "
            "API activity logs."
        ),
        "rationale": (
            "Weak API controls can expose application functions, "
            "sensitive data, or backend services to unauthorized use."
        ),
    },
    {
        "keywords": ["ssl", "tls", "certificate", "cert"],
        "recommendation": (
            "Renew expired certificates, verify TLS configuration, "
            "remove weak protocols, and document certificate ownership "
            "and renewal dates."
        ),
        "rationale": (
            "Certificate and TLS issues can disrupt service availability "
            "or weaken encrypted communications."
        ),
    },
    {
        "keywords": ["unsupported", "legacy", "operating system", "end of life", "eol"],
        "recommendation": (
            "Upgrade unsupported systems, isolate legacy assets, "
            "apply compensating controls, and create a retirement "
            "or replacement plan."
        ),
        "rationale": (
            "Legacy or unsupported systems may lack security patches "
            "and can create persistent exposure across the environment."
        ),
    },
    {
        "keywords": ["monitoring", "logging", "logs", "siem", "alert"],
        "recommendation": (
            "Enable centralized logging, configure alerting for high-risk "
            "events, review monitoring coverage, and validate that alerts "
            "are assigned to an owner."
        ),
        "rationale": (
            "Weak monitoring reduces visibility and delays detection, "
            "escalation, and response during security or operational incidents."
        ),
    },
    {
        "keywords": ["encryption", "unencrypted", "weak encryption", "plaintext"],
        "recommendation": (
            "Enable strong encryption, remove weak protocols, protect "
            "sensitive data at rest and in transit, and verify encryption "
            "settings through policy review."
        ),
        "rationale": (
            "Weak encryption controls can expose sensitive information "
            "during storage, transmission, or unauthorized access events."
        ),
    },
    {
        "keywords": ["patch", "unpatched", "vulnerability", "outdated", "firmware"],
        "recommendation": (
            "Prioritize patching based on severity, validate the affected "
            "asset, confirm maintenance windows, apply updates, and rescan "
            "to verify remediation."
        ),
        "rationale": (
            "Unpatched systems increase the likelihood of exploitation, "
            "especially when vulnerabilities are public or actively targeted."
        ),
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


def build_ai_prompt(name, category, severity):
    priority_label = determine_priority_label(severity)

    return f"""
You are an IT/security operations risk analyst.

Create a concise remediation recommendation and rationale for the following operational risk.

Risk Name: {name}
Category: {category}
Severity: {severity}/10
Priority Label: {priority_label}

Return ONLY valid JSON using this exact structure:
{{
  "recommendation": "one concise paragraph with practical remediation steps",
  "rationale": "one concise paragraph explaining operational/security impact"
}}

Guidelines:
- Be specific and realistic.
- Keep each paragraph under 70 words.
- Do not include markdown.
- Do not invent regulatory requirements.
- Use clear IT operations language.
"""


def parse_json_response(response_text):
    cleaned_text = response_text.strip()

    if cleaned_text.startswith("```"):
        cleaned_text = cleaned_text.replace("```json", "")
        cleaned_text = cleaned_text.replace("```", "")
        cleaned_text = cleaned_text.strip()

    try:
        parsed = json.loads(cleaned_text)
    except json.JSONDecodeError:
        return None

    recommendation = parsed.get("recommendation", "").strip()
    rationale = parsed.get("rationale", "").strip()

    if not recommendation or not rationale:
        return None

    return {
        "recommendation": recommendation,
        "rationale": rationale,
    }


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


def generate_rule_based_analysis(name, category, severity):
    best_match = find_best_ai_match(name, category)
    priority_label = determine_priority_label(severity)

    if best_match:
        recommendation = best_match["recommendation"]
        rationale = f"{priority_label} priority: {best_match['rationale']}"
    else:
        recommendation = (
            "Review the risk, validate business impact, assign an owner, "
            "document remediation steps, and track progress until the risk "
            "is reduced or formally accepted."
        )
        rationale = (
            f"{priority_label} priority: This item should be reviewed "
            "because it may affect confidentiality, integrity, availability, "
            "compliance, or operational continuity."
        )

    return {
        "recommendation": recommendation,
        "rationale": rationale,
        "source": "rule-based",
    }


def should_use_gemini():
    api_key = os.getenv("GEMINI_API_KEY")
    provider = os.getenv("AI_PROVIDER", "gemini").lower()

    return (
        provider == "gemini"
        and genai is not None
        and api_key is not None
        and api_key.strip() != ""
    )


def should_use_openai():
    api_key = os.getenv("OPENAI_API_KEY")
    provider = os.getenv("AI_PROVIDER", "gemini").lower()

    return (
        provider == "openai"
        and OpenAI is not None
        and api_key is not None
        and api_key.strip() != ""
    )


def generate_gemini_analysis(name, category, severity):
    client = genai.Client()
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    prompt = build_ai_prompt(name, category, severity)

    response = client.models.generate_content(
        model=model,
        contents=prompt,
    )

    print("GEMINI RAW RESPONSE:")
    print(response.text)

    parsed = parse_json_response(response.text)

    if parsed is None:
        raise ValueError("Gemini response was not valid JSON.")

    parsed["source"] = "gemini"
    return parsed


def generate_openai_analysis(name, category, severity):
    client = OpenAI()
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    prompt = build_ai_prompt(name, category, severity)

    response = client.responses.create(
        model=model,
        input=prompt,
    )

    print("OPENAI RAW RESPONSE:")
    print(response.output_text)

    parsed = parse_json_response(response.output_text)

    if parsed is None:
        raise ValueError("OpenAI response was not valid JSON.")

    parsed["source"] = "openai"
    return parsed


def generate_ai_analysis(name, category, severity):
    if should_use_gemini():
        try:
            return generate_gemini_analysis(name, category, severity)

        except Exception as error:
            print("GEMINI ERROR:", error)

            fallback = generate_rule_based_analysis(name, category, severity)
            fallback["rationale"] = (
                f"{fallback['rationale']} Gemini generation was unavailable, "
                "so the platform used the local rule-based recommendation engine."
            )
            fallback["source"] = "rule-based-fallback"
            return fallback

    if should_use_openai():
        try:
            return generate_openai_analysis(name, category, severity)

        except Exception as error:
            print("OPENAI ERROR:", error)

            fallback = generate_rule_based_analysis(name, category, severity)
            fallback["rationale"] = (
                f"{fallback['rationale']} OpenAI generation was unavailable, "
                "so the platform used the local rule-based recommendation engine."
            )
            fallback["source"] = "rule-based-fallback"
            return fallback

    return generate_rule_based_analysis(name, category, severity)