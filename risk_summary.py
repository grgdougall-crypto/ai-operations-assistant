import csv
from datetime import datetime, date, timedelta

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

statuses = [
    "OPEN",
    "IN PROGRESS",
    "PENDING REVIEW",
    "MITIGATED",
    "ACCEPTED",
    "CLOSED"
]

owners = [
    "Security Team",
    "Network Operations",
    "Infrastructure Team",
    "Help Desk",
    "SOC Analyst",
    "Compliance Team"
]

due_date_options = [1, 3, 5, 7, 10, 14, 30]


recommendation_library = [
    {
        "name": "MFA / Remote Access",
        "keywords": ["mfa", "multi-factor", "2fa", "vpn", "remote access"],
        "recommendation": "Require MFA for VPN, remote access, privileged accounts, and cloud applications. Review access logs and disable accounts that no longer require remote access."
    },
    {
        "name": "Weak Passwords",
        "keywords": ["password", "weak password", "credential", "login"],
        "recommendation": "Enforce stronger password policies, require password length and complexity, enable account lockout protections, and review failed login activity."
    },
    {
        "name": "Firewall Exposure",
        "keywords": ["firewall", "open port", "rule", "inbound"],
        "recommendation": "Review firewall rules, remove unnecessary inbound access, restrict management ports, document approved exceptions, and verify firmware is current."
    },
    {
        "name": "RDP Exposure",
        "keywords": ["rdp", "remote desktop", "3389"],
        "recommendation": "Disable public RDP exposure, restrict access through VPN or jump hosts, enforce MFA, and limit access to approved administrative users."
    },
    {
        "name": "Phishing",
        "keywords": ["phishing", "email", "social engineering"],
        "recommendation": "Provide phishing awareness training, enable email filtering, review reported messages, and run targeted simulations for high-risk user groups."
    },
    {
        "name": "Backup Risk",
        "keywords": ["backup", "restore", "backup share", "recovery"],
        "recommendation": "Verify backup integrity, restrict backup share permissions, perform a documented test restore, and confirm backups are protected from ransomware."
    },
    {
        "name": "Database Exposure",
        "keywords": ["database", "sql", "data exposure", "db"],
        "recommendation": "Restrict database access, review user permissions, disable public exposure, enforce encryption, and monitor for unauthorized queries."
    },
    {
        "name": "Cloud Misconfiguration",
        "keywords": ["cloud", "s3", "azure", "storage bucket", "cloud storage"],
        "recommendation": "Review cloud permissions, disable public access where not required, enforce least privilege, enable logging, and validate configuration baselines."
    },
    {
        "name": "Admin Account Risk",
        "keywords": ["admin", "administrator", "privileged", "local admin", "shared admin"],
        "recommendation": "Review privileged access, remove unnecessary admin rights, rotate credentials, enforce MFA, and replace shared admin accounts with named accounts."
    },
    {
        "name": "Endpoint Security",
        "keywords": ["laptop", "endpoint", "workstation", "device"],
        "recommendation": "Verify endpoint protection, enable full-disk encryption, confirm patch compliance, and ensure the device is enrolled in centralized management."
    },
    {
        "name": "API Exposure",
        "keywords": ["api", "endpoint", "token", "key"],
        "recommendation": "Review API authentication, rotate exposed keys or tokens, restrict public access, validate rate limiting, and monitor API activity logs."
    },
    {
        "name": "SSL / Certificate",
        "keywords": ["ssl", "tls", "certificate", "cert"],
        "recommendation": "Renew expired certificates, verify TLS configuration, remove weak protocols, and document certificate ownership and renewal dates."
    },
    {
        "name": "Unsupported Systems",
        "keywords": ["unsupported", "legacy", "operating system", "end of life", "eol"],
        "recommendation": "Upgrade unsupported systems, isolate legacy assets, apply compensating controls, and create a retirement or replacement plan."
    },
    {
        "name": "Monitoring Gap",
        "keywords": ["monitoring", "logging", "logs", "siem", "alert"],
        "recommendation": "Enable centralized logging, configure alerting for high-risk events, review monitoring coverage, and validate that alerts are assigned to an owner."
    },
    {
        "name": "Encryption Weakness",
        "keywords": ["encryption", "unencrypted", "weak encryption", "plaintext"],
        "recommendation": "Enable strong encryption, remove weak protocols, protect sensitive data at rest and in transit, and verify encryption settings through policy review."
    }
]


def load_risks():
    risks = []

    try:
        with open(CSV_FILE, mode="r") as file:
            reader = csv.DictReader(file)

            for row in reader:
                risks.append({
                    "id": row["id"],
                    "name": row["name"].upper(),
                    "severity": int(row["severity"]),
                    "category": row["category"],
                    "status": row["status"],
                    "owner": row["owner"],
                    "timestamp": row["timestamp"],
                    "due_date": row["due_date"]
                })

    except FileNotFoundError:
        print("risks.csv not found. A new file will be created when you add a risk.")

    return risks


def save_risks_to_csv(risks):
    with open(CSV_FILE, mode="w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "id",
            "name",
            "severity",
            "category",
            "status",
            "owner",
            "timestamp",
            "due_date"
        ])

        for risk in risks:
            writer.writerow([
                risk["id"],
                risk["name"],
                risk["severity"],
                risk["category"],
                risk["status"],
                risk["owner"],
                risk["timestamp"],
                risk["due_date"]
            ])


def generate_risk_id(risks):
    highest_number = 0

    for risk in risks:
        number = int(risk["id"].split("-")[1])

        if number > highest_number:
            highest_number = number

    return f"RISK-{highest_number + 1:03d}"


def determine_priority(severity):
    if severity >= 9:
        return "CRITICAL"
    elif severity >= 7:
        return "HIGH"
    else:
        return "MODERATE"


def determine_due_status(due_date, status):
    due_date_object = datetime.strptime(due_date, "%Y-%m-%d").date()
    today = date.today()

    if status in ["CLOSED", "MITIGATED", "ACCEPTED"]:
        return "NOT ACTIVE"

    if due_date_object < today:
        return "OVERDUE"

    return "ON TRACK"


def calculate_days_open(timestamp):
    created_date = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").date()
    today = date.today()

    return (today - created_date).days


def calculate_days_until_due(due_date):
    due_date_object = datetime.strptime(due_date, "%Y-%m-%d").date()
    today = date.today()

    return (due_date_object - today).days


def recommend_action(risk_name, category):
    risk_text = f"{risk_name} {category}".lower()

    best_match = None
    best_score = 0

    for item in recommendation_library:
        score = 0

        for keyword in item["keywords"]:
            if keyword in risk_text:
                score += 1

        if score > best_score:
            best_score = score
            best_match = item

    if best_match:
        return best_match["recommendation"]

    return "Review the risk, validate business impact, assign an owner, document remediation steps, and track progress until the risk is reduced or formally accepted."


def enrich_risks(risks):
    for risk in risks:
        risk["priority"] = determine_priority(risk["severity"])
        risk["recommendation"] = recommend_action(risk["name"], risk["category"])
        risk["due_status"] = determine_due_status(risk["due_date"], risk["status"])
        risk["days_open"] = calculate_days_open(risk["timestamp"])
        risk["days_until_due"] = calculate_days_until_due(risk["due_date"])


def choose_category():
    print("\nSelect a category:")

    for index, category in enumerate(categories, start=1):
        print(f"{index}. {category}")

    choice = int(input("Enter category number: "))
    return categories[choice - 1]


def choose_status():
    print("\nSelect a status:")

    for index, status in enumerate(statuses, start=1):
        print(f"{index}. {status}")

    choice = int(input("Enter status number: "))
    return statuses[choice - 1]


def choose_owner():
    print("\nSelect an owner:")

    for index, owner in enumerate(owners, start=1):
        print(f"{index}. {owner}")

    choice = int(input("Enter owner number: "))
    return owners[choice - 1]


def choose_due_date():
    print("\nSelect due date timeframe:")

    for index, days in enumerate(due_date_options, start=1):
        print(f"{index}. {days} days")

    choice = int(input("Enter due date option number: "))
    selected_days = due_date_options[choice - 1]
    due_date = date.today() + timedelta(days=selected_days)

    return due_date.strftime("%Y-%m-%d")


def add_new_risk(risks):
    print("\n=== Add New Risk ===")

    new_risk = {
        "id": generate_risk_id(risks),
        "name": input("Enter a new risk name: ").upper(),
        "severity": int(input("Enter severity level (1-10): ")),
        "category": choose_category(),
        "status": choose_status(),
        "owner": choose_owner(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "due_date": choose_due_date()
    }

    risks.append(new_risk)
    save_risks_to_csv(risks)

    print(f"\n{new_risk['id']} has been added successfully.")


def display_risks(risks_to_display):
    if not risks_to_display:
        print("No matching risks found.")
        return

    enrich_risks(risks_to_display)
    sorted_risks = sorted(risks_to_display, key=lambda risk: risk["severity"], reverse=True)

    for risk in sorted_risks:
        print(f"\n[{risk['priority']}] {risk['id']} - {risk['name']}")
        print(f"Severity: {risk['severity']}")
        print(f"Category: {risk['category']}")
        print(f"Status: {risk['status']}")
        print(f"Owner: {risk['owner']}")
        print(f"Due Date: {risk['due_date']}")
        print(f"Due Status: {risk['due_status']}")
        print(f"Days Open: {risk['days_open']}")
        print(f"Days Until Due: {risk['days_until_due']}")
        print(f"Recommendation: {risk['recommendation']}")


def view_all_risks(risks):
    print("\n=== Current Risks ===")
    display_risks(risks)


def find_risk_by_id(risks, risk_id):
    for risk in risks:
        if risk["id"].upper() == risk_id.upper():
            return risk

    return None


def update_risk_status(risks):
    print("\n=== Update Risk Status ===")

    risk_id = input("Enter Risk ID: ").upper()
    risk = find_risk_by_id(risks, risk_id)

    if risk is None:
        print("Risk not found.")
        return

    print(f"\nCurrent Risk: {risk['id']} - {risk['name']}")
    print(f"Current Status: {risk['status']}")

    new_status = choose_status()
    risk["status"] = new_status

    save_risks_to_csv(risks)

    print(f"\n{risk['id']} status updated to {new_status}.")


def update_risk_owner(risks):
    print("\n=== Update Risk Owner ===")

    risk_id = input("Enter Risk ID: ").upper()
    risk = find_risk_by_id(risks, risk_id)

    if risk is None:
        print("Risk not found.")
        return

    print(f"\nCurrent Risk: {risk['id']} - {risk['name']}")
    print(f"Current Owner: {risk['owner']}")

    new_owner = choose_owner()
    risk["owner"] = new_owner

    save_risks_to_csv(risks)

    print(f"\n{risk['id']} owner updated to {new_owner}.")


def close_risk(risks):
    print("\n=== Close Risk ===")

    risk_id = input("Enter Risk ID to close: ").upper()
    risk = find_risk_by_id(risks, risk_id)

    if risk is None:
        print("Risk not found.")
        return

    print(f"\nRisk Selected: {risk['id']} - {risk['name']}")
    confirm = input("Are you sure you want to close this risk? (y/n): ").lower()

    if confirm == "y":
        risk["status"] = "CLOSED"
        save_risks_to_csv(risks)
        print(f"\n{risk['id']} has been closed.")
    else:
        print("\nClose action cancelled.")


def show_critical_risks(risks):
    print("\n=== Critical Risks ===")

    enrich_risks(risks)

    critical_risks = [
        risk for risk in risks
        if risk["priority"] == "CRITICAL"
    ]

    display_risks(critical_risks)


def show_overdue_risks(risks):
    print("\n=== Overdue Risks ===")

    enrich_risks(risks)

    overdue_risks = [
        risk for risk in risks
        if risk["due_status"] == "OVERDUE"
    ]

    display_risks(overdue_risks)


def filter_by_status(risks):
    print("\n=== Filter by Status ===")

    selected_status = choose_status()

    filtered_risks = [
        risk for risk in risks
        if risk["status"] == selected_status
    ]

    display_risks(filtered_risks)


def filter_by_owner(risks):
    print("\n=== Filter by Owner ===")

    selected_owner = choose_owner()

    filtered_risks = [
        risk for risk in risks
        if risk["owner"] == selected_owner
    ]

    display_risks(filtered_risks)


def filter_by_category(risks):
    print("\n=== Filter by Category ===")

    selected_category = choose_category()

    filtered_risks = [
        risk for risk in risks
        if risk["category"] == selected_category
    ]

    display_risks(filtered_risks)


def search_by_keyword(risks):
    print("\n=== Search Risks by Keyword ===")

    keyword = input("Enter keyword to search: ").lower()

    matching_risks = [
        risk for risk in risks
        if keyword in risk["name"].lower()
        or keyword in risk["category"].lower()
        or keyword in risk["status"].lower()
        or keyword in risk["owner"].lower()
    ]

    display_risks(matching_risks)


def show_filter_menu(risks):
    while True:
        print("\n=== Filter and Search Menu ===")
        print("1. Show Critical Risks")
        print("2. Show Overdue Risks")
        print("3. Filter by Status")
        print("4. Filter by Owner")
        print("5. Filter by Category")
        print("6. Search by Keyword")
        print("7. Return to Main Menu")

        choice = input("\nEnter filter option: ")

        if choice == "1":
            show_critical_risks(risks)
        elif choice == "2":
            show_overdue_risks(risks)
        elif choice == "3":
            filter_by_status(risks)
        elif choice == "4":
            filter_by_owner(risks)
        elif choice == "5":
            filter_by_category(risks)
        elif choice == "6":
            search_by_keyword(risks)
        elif choice == "7":
            break
        else:
            print("\nInvalid option. Please choose 1-7.")


def generate_reports(risks):
    print("\n=== Generating Reports ===")

    if not risks:
        print("No risks available to report.")
        return

    enrich_risks(risks)

    sorted_risks = sorted(risks, key=lambda risk: risk["severity"], reverse=True)

    critical_count = sum(1 for risk in risks if risk["priority"] == "CRITICAL")
    high_count = sum(1 for risk in risks if risk["priority"] == "HIGH")
    moderate_count = sum(1 for risk in risks if risk["priority"] == "MODERATE")
    overdue_count = sum(1 for risk in risks if risk["due_status"] == "OVERDUE")
    on_track_count = sum(1 for risk in risks if risk["due_status"] == "ON TRACK")

    critical_overdue_count = sum(
        1 for risk in risks
        if risk["priority"] == "CRITICAL" and risk["due_status"] == "OVERDUE"
    )

    due_soon_count = sum(
        1 for risk in risks
        if 0 <= risk["days_until_due"] <= 7
        and risk["status"] not in ["CLOSED", "MITIGATED", "ACCEPTED"]
    )

    open_risks = [
        risk for risk in risks
        if risk["status"] in ["OPEN", "IN PROGRESS", "PENDING REVIEW"]
    ]

    oldest_open_risk = None

    if open_risks:
        oldest_open_risk = max(open_risks, key=lambda risk: risk["days_open"])

    average_severity = sum(risk["severity"] for risk in risks) / len(risks)
    highest_risk = max(risks, key=lambda risk: risk["severity"])

    category_counts = {}
    status_counts = {}
    owner_counts = {}
    due_status_counts = {}

    for risk in risks:
        category_counts[risk["category"]] = category_counts.get(risk["category"], 0) + 1
        status_counts[risk["status"]] = status_counts.get(risk["status"], 0) + 1
        owner_counts[risk["owner"]] = owner_counts.get(risk["owner"], 0) + 1
        due_status_counts[risk["due_status"]] = due_status_counts.get(risk["due_status"], 0) + 1

    with open(TXT_REPORT, mode="w") as report:
        report.write("AI Operations Risk Report\n")
        report.write("=========================\n\n")

        for risk in sorted_risks:
            report.write(f"[{risk['priority']}] {risk['id']} - {risk['name']}\n")
            report.write(f"Severity: {risk['severity']}\n")
            report.write(f"Category: {risk['category']}\n")
            report.write(f"Status: {risk['status']}\n")
            report.write(f"Owner: {risk['owner']}\n")
            report.write(f"Timestamp: {risk['timestamp']}\n")
            report.write(f"Due Date: {risk['due_date']}\n")
            report.write(f"Due Status: {risk['due_status']}\n")
            report.write(f"Days Open: {risk['days_open']}\n")
            report.write(f"Days Until Due: {risk['days_until_due']}\n")
            report.write(f"Recommendation: {risk['recommendation']}\n\n")

        report.write("=== Executive Summary ===\n")
        report.write(f"Critical Risks: {critical_count}\n")
        report.write(f"High Risks: {high_count}\n")
        report.write(f"Moderate Risks: {moderate_count}\n")
        report.write(f"Average Severity: {average_severity:.2f}\n")
        report.write(f"Highest Risk: {highest_risk['id']} - {highest_risk['name']}\n")
        report.write(f"Overdue Risks: {overdue_count}\n")
        report.write(f"On Track Risks: {on_track_count}\n\n")

        report.write("=== SLA Summary ===\n")
        report.write(f"Critical Risks Overdue: {critical_overdue_count}\n")
        report.write(f"Risks Due Within 7 Days: {due_soon_count}\n")

        if oldest_open_risk:
            report.write(f"Oldest Open Risk: {oldest_open_risk['id']} ({oldest_open_risk['days_open']} days open)\n\n")
        else:
            report.write("Oldest Open Risk: None\n\n")

        report.write("=== Category Summary ===\n")
        for category, count in category_counts.items():
            report.write(f"{category}: {count}\n")

        report.write("\n=== Status Summary ===\n")
        for status, count in status_counts.items():
            report.write(f"{status}: {count}\n")

        report.write("\n=== Owner Summary ===\n")
        for owner, count in owner_counts.items():
            report.write(f"{owner}: {count}\n")

        report.write("\n=== Due Status Summary ===\n")
        for due_status, count in due_status_counts.items():
            report.write(f"{due_status}: {count}\n")

    with open(MD_REPORT, mode="w") as report:
        report.write("# AI Operations Risk Report\n\n")

        report.write("| ID | Risk | Priority | Severity | Category | Status | Owner | Timestamp | Due Date | Due Status | Days Open | Days Until Due | Recommendation |\n")
        report.write("|----|------|----------|----------|----------|--------|-------|------------|----------|------------|-----------|----------------|----------------|\n")

        for risk in sorted_risks:
            report.write(
                f"| {risk['id']} | {risk['name']} | {risk['priority']} | "
                f"{risk['severity']} | {risk['category']} | {risk['status']} | "
                f"{risk['owner']} | {risk['timestamp']} | {risk['due_date']} | "
                f"{risk['due_status']} | {risk['days_open']} | "
                f"{risk['days_until_due']} | {risk['recommendation']} |\n"
            )

        report.write("\n## Executive Summary\n\n")
        report.write(f"- Critical Risks: {critical_count}\n")
        report.write(f"- High Risks: {high_count}\n")
        report.write(f"- Moderate Risks: {moderate_count}\n")
        report.write(f"- Average Severity: {average_severity:.2f}\n")
        report.write(f"- Highest Risk: {highest_risk['id']} - {highest_risk['name']}\n")
        report.write(f"- Overdue Risks: {overdue_count}\n")
        report.write(f"- On Track Risks: {on_track_count}\n")

        report.write("\n## SLA Summary\n\n")
        report.write(f"- Critical Risks Overdue: {critical_overdue_count}\n")
        report.write(f"- Risks Due Within 7 Days: {due_soon_count}\n")

        if oldest_open_risk:
            report.write(f"- Oldest Open Risk: {oldest_open_risk['id']} ({oldest_open_risk['days_open']} days open)\n")
        else:
            report.write("- Oldest Open Risk: None\n")

        report.write("\n## Category Summary\n\n")
        for category, count in category_counts.items():
            report.write(f"- {category}: {count}\n")

        report.write("\n## Status Summary\n\n")
        for status, count in status_counts.items():
            report.write(f"- {status}: {count}\n")

        report.write("\n## Owner Summary\n\n")
        for owner, count in owner_counts.items():
            report.write(f"- {owner}: {count}\n")

        report.write("\n## Due Status Summary\n\n")
        for due_status, count in due_status_counts.items():
            report.write(f"- {due_status}: {count}\n")

    print("Reports generated successfully.")
    print(f"- {TXT_REPORT}")
    print(f"- {MD_REPORT}")


def show_menu():
    print("\n=== AI Operations Assistant ===")
    print("1. Add New Risk")
    print("2. View All Risks")
    print("3. Update Risk Status")
    print("4. Update Risk Owner")
    print("5. Close Risk")
    print("6. Filter/Search Risks")
    print("7. Generate Reports")
    print("8. Exit")


def main():
    risks = load_risks()

    while True:
        show_menu()

        choice = input("\nEnter menu option: ")

        if choice == "1":
            add_new_risk(risks)
        elif choice == "2":
            view_all_risks(risks)
        elif choice == "3":
            update_risk_status(risks)
        elif choice == "4":
            update_risk_owner(risks)
        elif choice == "5":
            close_risk(risks)
        elif choice == "6":
            show_filter_menu(risks)
        elif choice == "7":
            generate_reports(risks)
        elif choice == "8":
            print("\nExiting AI Operations Assistant.")
            break
        else:
            print("\nInvalid option. Please choose 1-8.")


main()