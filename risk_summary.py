import csv
import os
from datetime import datetime, date, timedelta

import matplotlib.pyplot as plt


CSV_FILE = "risks.csv"
TXT_REPORT = "risk_report.txt"
MD_REPORT = "risk_report.md"
HTML_REPORT = "dashboard.html"
CHARTS_DIR = "charts"
TEMPLATE_FILE = os.path.join("templates", "dashboard_template.html")

CATEGORIES = [
    "Authentication",
    "Network",
    "Endpoint Security",
    "Data Protection",
    "Backup and Recovery",
    "Incident Response",
    "Security Awareness",
    "Infrastructure",
    "User Access",
    "Physical Security",
]

STATUSES = [
    "OPEN",
    "IN PROGRESS",
    "PENDING REVIEW",
    "MITIGATED",
    "ACCEPTED",
    "CLOSED",
]

OWNERS = [
    "Security Team",
    "Network Operations",
    "Infrastructure Team",
    "Help Desk",
    "SOC Analyst",
    "Compliance Team",
]

DUE_DATE_OPTIONS = [1, 3, 5, 7, 10, 14, 30]

ACTIVE_STATUSES = ["OPEN", "IN PROGRESS", "PENDING REVIEW"]
INACTIVE_STATUSES = ["CLOSED", "MITIGATED", "ACCEPTED"]

RECOMMENDATION_LIBRARY = [
    {
        "keywords": ["mfa", "multi-factor", "2fa", "vpn", "remote access"],
        "recommendation": "Require MFA for VPN, remote access, privileged accounts, and cloud applications. Review access logs and disable accounts that no longer require remote access.",
    },
    {
        "keywords": ["password", "weak password", "credential", "login"],
        "recommendation": "Enforce stronger password policies, require password length and complexity, enable account lockout protections, and review failed login activity.",
    },
    {
        "keywords": ["firewall", "open port", "rule", "inbound"],
        "recommendation": "Review firewall rules, remove unnecessary inbound access, restrict management ports, document approved exceptions, and verify firmware is current.",
    },
    {
        "keywords": ["rdp", "remote desktop", "3389"],
        "recommendation": "Disable public RDP exposure, restrict access through VPN or jump hosts, enforce MFA, and limit access to approved administrative users.",
    },
    {
        "keywords": ["phishing", "email", "social engineering"],
        "recommendation": "Provide phishing awareness training, enable email filtering, review reported messages, and run targeted simulations for high-risk user groups.",
    },
    {
        "keywords": ["backup", "restore", "backup share", "recovery"],
        "recommendation": "Verify backup integrity, restrict backup share permissions, perform a documented test restore, and confirm backups are protected from ransomware.",
    },
    {
        "keywords": ["database", "sql", "data exposure", "db"],
        "recommendation": "Restrict database access, review user permissions, disable public exposure, enforce encryption, and monitor for unauthorized queries.",
    },
    {
        "keywords": ["cloud", "s3", "azure", "storage bucket", "cloud storage"],
        "recommendation": "Review cloud permissions, disable public access where not required, enforce least privilege, enable logging, and validate configuration baselines.",
    },
    {
        "keywords": ["admin", "administrator", "privileged", "local admin", "shared admin"],
        "recommendation": "Review privileged access, remove unnecessary admin rights, rotate credentials, enforce MFA, and replace shared admin accounts with named accounts.",
    },
    {
        "keywords": ["laptop", "endpoint", "workstation", "device"],
        "recommendation": "Verify endpoint protection, enable full-disk encryption, confirm patch compliance, and ensure the device is enrolled in centralized management.",
    },
    {
        "keywords": ["api", "endpoint", "token", "key"],
        "recommendation": "Review API authentication, rotate exposed keys or tokens, restrict public access, validate rate limiting, and monitor API activity logs.",
    },
    {
        "keywords": ["ssl", "tls", "certificate", "cert"],
        "recommendation": "Renew expired certificates, verify TLS configuration, remove weak protocols, and document certificate ownership and renewal dates.",
    },
    {
        "keywords": ["unsupported", "legacy", "operating system", "end of life", "eol"],
        "recommendation": "Upgrade unsupported systems, isolate legacy assets, apply compensating controls, and create a retirement or replacement plan.",
    },
    {
        "keywords": ["monitoring", "logging", "logs", "siem", "alert"],
        "recommendation": "Enable centralized logging, configure alerting for high-risk events, review monitoring coverage, and validate that alerts are assigned to an owner.",
    },
    {
        "keywords": ["encryption", "unencrypted", "weak encryption", "plaintext"],
        "recommendation": "Enable strong encryption, remove weak protocols, protect sensitive data at rest and in transit, and verify encryption settings through policy review.",
    },
]

PRIORITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "orange",
    "MODERATE": "gold",
    "LOW": "green",
}

STATUS_COLORS = {
    "OPEN": "royalblue",
    "IN PROGRESS": "purple",
    "PENDING REVIEW": "gray",
    "MITIGATED": "green",
    "ACCEPTED": "teal",
    "CLOSED": "darkgreen",
}

DUE_STATUS_COLORS = {
    "OVERDUE": "red",
    "ON TRACK": "green",
    "NOT ACTIVE": "gray",
}

DEFAULT_CHART_COLOR = "steelblue"


def load_risks():
    risks = []

    try:
        with open(CSV_FILE, mode="r", newline="") as file:
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
                    "due_date": row["due_date"],
                })

    except FileNotFoundError:
        print("risks.csv not found. A new file will be created when you add a risk.")

    return risks


def save_risks_to_csv(risks):
    with open(CSV_FILE, mode="w", newline="") as file:
        fieldnames = ["id", "name", "severity", "category", "status", "owner", "timestamp", "due_date"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()

        for risk in risks:
            writer.writerow({
                "id": risk["id"],
                "name": risk["name"],
                "severity": risk["severity"],
                "category": risk["category"],
                "status": risk["status"],
                "owner": risk["owner"],
                "timestamp": risk["timestamp"],
                "due_date": risk["due_date"],
            })


def generate_risk_id(risks):
    highest_number = 0

    for risk in risks:
        try:
            number = int(risk["id"].split("-")[1])
            highest_number = max(highest_number, number)
        except (IndexError, ValueError):
            continue

    return f"RISK-{highest_number + 1:03d}"


def determine_priority(severity):
    if severity >= 9:
        return "CRITICAL"
    if severity >= 7:
        return "HIGH"
    return "MODERATE"


def determine_due_status(due_date, status):
    due_date_object = datetime.strptime(due_date, "%Y-%m-%d").date()
    today = date.today()

    if status in INACTIVE_STATUSES:
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

    for item in RECOMMENDATION_LIBRARY:
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


def choose_from_menu(title, options):
    print(f"\n{title}")

    for index, option in enumerate(options, start=1):
        print(f"{index}. {option}")

    while True:
        try:
            choice = int(input("Enter option number: "))

            if 1 <= choice <= len(options):
                return options[choice - 1]

            print(f"Please enter a number from 1 to {len(options)}.")

        except ValueError:
            print("Please enter a valid number.")


def choose_category():
    return choose_from_menu("Select a category:", CATEGORIES)


def choose_status():
    return choose_from_menu("Select a status:", STATUSES)


def choose_owner():
    return choose_from_menu("Select an owner:", OWNERS)


def choose_due_date():
    print("\nSelect due date timeframe:")

    for index, days in enumerate(DUE_DATE_OPTIONS, start=1):
        print(f"{index}. {days} days")

    while True:
        try:
            choice = int(input("Enter due date option number: "))

            if 1 <= choice <= len(DUE_DATE_OPTIONS):
                selected_days = DUE_DATE_OPTIONS[choice - 1]
                due_date = date.today() + timedelta(days=selected_days)
                return due_date.strftime("%Y-%m-%d")

            print(f"Please enter a number from 1 to {len(DUE_DATE_OPTIONS)}.")

        except ValueError:
            print("Please enter a valid number.")


def add_new_risk(risks):
    print("\n=== Add New Risk ===")

    while True:
        try:
            severity = int(input("Enter severity level (1-10): "))

            if 1 <= severity <= 10:
                break

            print("Severity must be between 1 and 10.")

        except ValueError:
            print("Please enter a valid number from 1 to 10.")

    new_risk = {
        "id": generate_risk_id(risks),
        "name": input("Enter a new risk name: ").upper(),
        "severity": severity,
        "category": choose_category(),
        "status": choose_status(),
        "owner": choose_owner(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "due_date": choose_due_date(),
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


def get_count_dictionary(risks, key):
    counts = {}

    for risk in risks:
        value = risk[key]
        counts[value] = counts.get(value, 0) + 1

    return counts


def get_colors_for_labels(labels, color_map):
    return [color_map.get(label, DEFAULT_CHART_COLOR) for label in labels]


def add_value_labels_to_bars(bars):
    for bar in bars:
        height = bar.get_height()

        plt.text(
            bar.get_x() + bar.get_width() / 2,
            height + 0.2,
            str(int(height)),
            ha="center",
            fontsize=11,
        )


def add_value_labels_to_horizontal_bars(bars):
    for bar in bars:
        width = bar.get_width()

        plt.text(
            width + 0.2,
            bar.get_y() + bar.get_height() / 2,
            str(int(width)),
            va="center",
            fontsize=11,
        )


def create_vertical_bar_chart(title, labels, values, filename, x_label, color_map=None):
    if not labels or not values:
        return

    plt.figure(figsize=(7.5, 4.5), dpi=130)

    colors = get_colors_for_labels(labels, color_map) if color_map else DEFAULT_CHART_COLOR
    bars = plt.bar(labels, values, color=colors)

    plt.title(title, fontsize=13, fontweight="bold")
    plt.xlabel(x_label, fontsize=10)
    plt.ylabel("Count", fontsize=10)
    plt.xticks(rotation=25, ha="right", fontsize=8)
    plt.yticks(fontsize=8)
    plt.grid(axis="y", linestyle="--", alpha=0.35)

    add_value_labels_to_bars(bars)

    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, filename), bbox_inches="tight")
    plt.close()


def create_horizontal_bar_chart(title, labels, values, filename, y_label, colors=None):
    if not labels or not values:
        return

    plt.figure(figsize=(7.8, 4.8), dpi=130)

    bars = plt.barh(
        labels,
        values,
        color=colors if colors else DEFAULT_CHART_COLOR,
    )

    plt.title(title, fontsize=13, fontweight="bold")
    plt.xlabel("Count", fontsize=10)
    plt.ylabel(y_label, fontsize=10)
    plt.xticks(fontsize=8)
    plt.yticks(fontsize=8)
    plt.grid(axis="x", linestyle="--", alpha=0.35)

    add_value_labels_to_horizontal_bars(bars)

    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, filename), bbox_inches="tight")
    plt.close()


def create_operational_heat_map(risks):
    priority_order = ["CRITICAL", "HIGH", "MODERATE"]
    due_status_order = ["OVERDUE", "ON TRACK", "NOT ACTIVE"]

    heatmap_data = []

    for priority in priority_order:
        row = []

        for due_status in due_status_order:
            count = sum(
                1 for risk in risks
                if risk["priority"] == priority and risk["due_status"] == due_status
            )
            row.append(count)

        heatmap_data.append(row)

    plt.figure(figsize=(6.8, 4.4), dpi=130)
    plt.imshow(heatmap_data, cmap="Reds")

    plt.title("Operational Risk Heat Map", fontsize=13, fontweight="bold")
    plt.xlabel("Due Status", fontsize=10)
    plt.ylabel("Priority", fontsize=10)

    plt.xticks(range(len(due_status_order)), due_status_order, fontsize=8)
    plt.yticks(range(len(priority_order)), priority_order, fontsize=8)

    for row_index in range(len(priority_order)):
        for col_index in range(len(due_status_order)):
            value = heatmap_data[row_index][col_index]
            text_color = "white" if value >= 8 else "black"

            plt.text(
                col_index,
                row_index,
                str(value),
                ha="center",
                va="center",
                fontsize=13,
                fontweight="bold",
                color=text_color,
            )

    plt.colorbar(label="Risk Count")
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, "operational_risk_heat_map.png"), bbox_inches="tight")
    plt.close()


def create_trend_analytics_charts(risks):
    active_risks = [
        risk for risk in risks
        if risk["status"] in ACTIVE_STATUSES
    ]

    inactive_risks = [
        risk for risk in risks
        if risk["status"] in INACTIVE_STATUSES
    ]

    create_vertical_bar_chart(
        "Active vs Inactive Risk Workload",
        ["ACTIVE", "INACTIVE"],
        [len(active_risks), len(inactive_risks)],
        "active_vs_inactive_risks.png",
        "Risk Workload State",
    )

    age_buckets = {
        "0-7 Days": 0,
        "8-14 Days": 0,
        "15-30 Days": 0,
        "31+ Days": 0,
    }

    for risk in active_risks:
        days_open = risk["days_open"]

        if days_open <= 7:
            age_buckets["0-7 Days"] += 1
        elif days_open <= 14:
            age_buckets["8-14 Days"] += 1
        elif days_open <= 30:
            age_buckets["15-30 Days"] += 1
        else:
            age_buckets["31+ Days"] += 1

    create_vertical_bar_chart(
        "Open Risk Aging Distribution",
        list(age_buckets.keys()),
        list(age_buckets.values()),
        "open_risk_aging_distribution.png",
        "Days Open",
    )

    created_by_date = {}

    for risk in risks:
        created_date = risk["timestamp"].split(" ")[0]
        created_by_date[created_date] = created_by_date.get(created_date, 0) + 1

    sorted_dates = sorted(created_by_date.keys())
    sorted_counts = [created_by_date[created_date] for created_date in sorted_dates]

    create_vertical_bar_chart(
        "Risks Created by Date",
        sorted_dates,
        sorted_counts,
        "risks_created_by_date.png",
        "Created Date",
    )


def generate_charts(risks):
    if not os.path.exists(CHARTS_DIR):
        os.makedirs(CHARTS_DIR)

    enrich_risks(risks)

    priority_counts = get_count_dictionary(risks, "priority")
    status_counts = get_count_dictionary(risks, "status")
    category_counts = get_count_dictionary(risks, "category")
    owner_counts = get_count_dictionary(risks, "owner")
    due_status_counts = get_count_dictionary(risks, "due_status")

    create_vertical_bar_chart(
        "Risk Distribution by Priority",
        list(priority_counts.keys()),
        list(priority_counts.values()),
        "risks_by_priority.png",
        "Priority Level",
        PRIORITY_COLORS,
    )

    create_vertical_bar_chart(
        "Risk Lifecycle Status Overview",
        list(status_counts.keys()),
        list(status_counts.values()),
        "risks_by_status.png",
        "Risk Status",
        STATUS_COLORS,
    )

    create_horizontal_bar_chart(
        "Risk Distribution by Category",
        list(category_counts.keys()),
        list(category_counts.values()),
        "risks_by_category.png",
        "Category",
    )

    create_horizontal_bar_chart(
        "Open Risk Workload by Owner",
        list(owner_counts.keys()),
        list(owner_counts.values()),
        "risks_by_owner.png",
        "Owner",
    )

    create_vertical_bar_chart(
        "SLA Due Status Overview",
        list(due_status_counts.keys()),
        list(due_status_counts.values()),
        "risks_by_due_status.png",
        "Due Status",
        DUE_STATUS_COLORS,
    )

    top_risks = sorted(risks, key=lambda risk: risk["severity"], reverse=True)[:5]
    top_risk_labels = [f"{risk['id']} - {risk['name'][:25]}" for risk in top_risks]
    top_risk_values = [risk["severity"] for risk in top_risks]
    top_risk_colors = [
        PRIORITY_COLORS.get(risk["priority"], DEFAULT_CHART_COLOR)
        for risk in top_risks
    ]

    create_horizontal_bar_chart(
        "Top 5 Highest Severity Risks",
        top_risk_labels,
        top_risk_values,
        "top_5_risks.png",
        "Risk",
        top_risk_colors,
    )

    create_operational_heat_map(risks)
    create_trend_analytics_charts(risks)


def calculate_report_metrics(risks):
    enrich_risks(risks)

    total_risks = len(risks)
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
        if 0 <= risk["days_until_due"] <= 7 and risk["status"] not in INACTIVE_STATUSES
    )

    active_risks = [
        risk for risk in risks
        if risk["status"] in ACTIVE_STATUSES
    ]

    inactive_risks = [
        risk for risk in risks
        if risk["status"] in INACTIVE_STATUSES
    ]

    active_count = len(active_risks)
    inactive_count = len(inactive_risks)

    if active_risks:
        average_days_open_active = sum(risk["days_open"] for risk in active_risks) / len(active_risks)
        oldest_open_risk = max(active_risks, key=lambda risk: risk["days_open"])
    else:
        average_days_open_active = 0
        oldest_open_risk = None

    average_severity = sum(risk["severity"] for risk in risks) / total_risks if total_risks else 0
    highest_risk = max(risks, key=lambda risk: risk["severity"]) if risks else None
    sla_compliance = (on_track_count / total_risks) * 100 if total_risks else 0

    category_counts = get_count_dictionary(risks, "category")
    status_counts = get_count_dictionary(risks, "status")
    owner_counts = get_count_dictionary(risks, "owner")
    due_status_counts = get_count_dictionary(risks, "due_status")

    most_common_category = max(category_counts, key=category_counts.get) if category_counts else "None"

    return {
        "total_risks": total_risks,
        "critical_count": critical_count,
        "high_count": high_count,
        "moderate_count": moderate_count,
        "overdue_count": overdue_count,
        "on_track_count": on_track_count,
        "critical_overdue_count": critical_overdue_count,
        "due_soon_count": due_soon_count,
        "active_count": active_count,
        "inactive_count": inactive_count,
        "average_days_open_active": average_days_open_active,
        "oldest_open_risk": oldest_open_risk,
        "average_severity": average_severity,
        "highest_risk": highest_risk,
        "sla_compliance": sla_compliance,
        "category_counts": category_counts,
        "status_counts": status_counts,
        "owner_counts": owner_counts,
        "due_status_counts": due_status_counts,
        "most_common_category": most_common_category,
    }


def write_txt_report(risks, metrics):
    sorted_risks = sorted(risks, key=lambda risk: risk["severity"], reverse=True)

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
        report.write(f"Total Risks: {metrics['total_risks']}\n")
        report.write(f"Critical Risks: {metrics['critical_count']}\n")
        report.write(f"High Risks: {metrics['high_count']}\n")
        report.write(f"Moderate Risks: {metrics['moderate_count']}\n")
        report.write(f"Average Severity: {metrics['average_severity']:.2f}\n")

        highest_risk = metrics["highest_risk"]
        if highest_risk:
            report.write(f"Highest Risk: {highest_risk['id']} - {highest_risk['name']}\n")

        report.write(f"Overdue Risks: {metrics['overdue_count']}\n")
        report.write(f"On Track Risks: {metrics['on_track_count']}\n")
        report.write(f"SLA Compliance: {metrics['sla_compliance']:.1f}%\n")
        report.write(f"Active Risks: {metrics['active_count']}\n")
        report.write(f"Inactive Risks: {metrics['inactive_count']}\n")
        report.write(f"Average Days Open - Active Risks: {metrics['average_days_open_active']:.1f}\n")
        report.write(f"Most Common Risk Category: {metrics['most_common_category']}\n\n")

        report.write("=== SLA Summary ===\n")
        report.write(f"Critical Risks Overdue: {metrics['critical_overdue_count']}\n")
        report.write(f"Risks Due Within 7 Days: {metrics['due_soon_count']}\n")

        oldest_open_risk = metrics["oldest_open_risk"]
        if oldest_open_risk:
            report.write(f"Oldest Open Risk: {oldest_open_risk['id']} ({oldest_open_risk['days_open']} days open)\n\n")
        else:
            report.write("Oldest Open Risk: None\n\n")

        report.write("=== Category Summary ===\n")
        for category, count in metrics["category_counts"].items():
            report.write(f"{category}: {count}\n")

        report.write("\n=== Status Summary ===\n")
        for status, count in metrics["status_counts"].items():
            report.write(f"{status}: {count}\n")

        report.write("\n=== Owner Summary ===\n")
        for owner, count in metrics["owner_counts"].items():
            report.write(f"{owner}: {count}\n")

        report.write("\n=== Due Status Summary ===\n")
        for due_status, count in metrics["due_status_counts"].items():
            report.write(f"{due_status}: {count}\n")


def write_md_report(risks, metrics):
    sorted_risks = sorted(risks, key=lambda risk: risk["severity"], reverse=True)
    highest_risk = metrics["highest_risk"]

    with open(MD_REPORT, mode="w") as report:
        report.write("# AI Operations Risk Report\n\n")

        report.write("## Executive KPI Dashboard\n\n")
        report.write("| KPI | Value |\n")
        report.write("|---|---:|\n")
        report.write(f"| Total Risks | {metrics['total_risks']} |\n")
        report.write(f"| Critical Risks | {metrics['critical_count']} |\n")
        report.write(f"| High Risks | {metrics['high_count']} |\n")
        report.write(f"| Moderate Risks | {metrics['moderate_count']} |\n")
        report.write(f"| Overdue Risks | {metrics['overdue_count']} |\n")
        report.write(f"| On Track Risks | {metrics['on_track_count']} |\n")
        report.write(f"| Risks Due Within 7 Days | {metrics['due_soon_count']} |\n")
        report.write(f"| SLA Compliance | {metrics['sla_compliance']:.1f}% |\n")
        report.write(f"| Average Severity | {metrics['average_severity']:.2f} |\n")

        if highest_risk:
            report.write(f"| Highest Risk | {highest_risk['id']} - {highest_risk['name']} |\n")

        report.write(f"| Active Risks | {metrics['active_count']} |\n")
        report.write(f"| Inactive Risks | {metrics['inactive_count']} |\n")
        report.write(f"| Average Days Open - Active Risks | {metrics['average_days_open_active']:.1f} |\n")
        report.write(f"| Most Common Risk Category | {metrics['most_common_category']} |\n\n")

        report.write("## Dashboard Charts\n\n")
        report.write("![Risk Distribution by Priority](charts/risks_by_priority.png)\n\n")
        report.write("![Risk Lifecycle Status Overview](charts/risks_by_status.png)\n\n")
        report.write("![Risk Distribution by Category](charts/risks_by_category.png)\n\n")
        report.write("![Open Risk Workload by Owner](charts/risks_by_owner.png)\n\n")
        report.write("![SLA Due Status Overview](charts/risks_by_due_status.png)\n\n")
        report.write("![Top 5 Highest Severity Risks](charts/top_5_risks.png)\n\n")
        report.write("![Operational Risk Heat Map](charts/operational_risk_heat_map.png)\n\n")

        report.write("## Trend Analytics\n\n")
        report.write("![Active vs Inactive Risk Workload](charts/active_vs_inactive_risks.png)\n\n")
        report.write("![Open Risk Aging Distribution](charts/open_risk_aging_distribution.png)\n\n")
        report.write("![Risks Created by Date](charts/risks_created_by_date.png)\n\n")

        report.write("## Risk Detail Table\n\n")
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

        report.write("\n## Category Summary\n\n")
        for category, count in metrics["category_counts"].items():
            report.write(f"- {category}: {count}\n")

        report.write("\n## Status Summary\n\n")
        for status, count in metrics["status_counts"].items():
            report.write(f"- {status}: {count}\n")

        report.write("\n## Owner Summary\n\n")
        for owner, count in metrics["owner_counts"].items():
            report.write(f"- {owner}: {count}\n")

        report.write("\n## Due Status Summary\n\n")
        for due_status, count in metrics["due_status_counts"].items():
            report.write(f"- {due_status}: {count}\n")


def build_html_risk_rows(risks):
    rows = ""

    active_risks = [
        risk for risk in risks
        if risk["status"] in ACTIVE_STATUSES
    ]

    sorted_active_risks = sorted(active_risks, key=lambda risk: risk["severity"], reverse=True)

    for risk in sorted_active_risks:
        if risk["priority"] == "CRITICAL":
            priority_class = "priority-critical"
        elif risk["priority"] == "HIGH":
            priority_class = "priority-high"
        else:
            priority_class = "priority-moderate"

        rows += f"""
<tr>
<td>{risk['id']}</td>
<td>{risk['name']}</td>
<td class=\"{priority_class}\">{risk['severity']}</td>
<td>{risk['status']}</td>
<td>{risk['owner']}</td>
<td>{risk['due_date']}</td>
</tr>
"""

    return rows


def write_html_dashboard(risks, metrics):
    if not os.path.exists(TEMPLATE_FILE):
        print("HTML template not found. Skipping dashboard.html generation.")
        print(f"Missing file: {TEMPLATE_FILE}")
        return

    highest_risk = metrics["highest_risk"]
    highest_risk_text = "None"

    if highest_risk:
        highest_risk_text = f"{highest_risk['id']} - {highest_risk['name']}"

    with open(TEMPLATE_FILE, mode="r", encoding="utf-8") as template_file:
        html = template_file.read()

    replacements = {
        "{{TOTAL_RISKS}}": str(metrics["total_risks"]),
        "{{CRITICAL_RISKS}}": str(metrics["critical_count"]),
        "{{HIGH_RISKS}}": str(metrics["high_count"]),
        "{{SLA_COMPLIANCE}}": f"{metrics['sla_compliance']:.1f}",
        "{{OVERDUE_RISKS}}": str(metrics["overdue_count"]),
        "{{HIGHEST_RISK}}": highest_risk_text,
        "{{AVERAGE_SEVERITY}}": f"{metrics['average_severity']:.2f}",
        "{{MOST_COMMON_CATEGORY}}": metrics["most_common_category"],
        "{{AVG_DAYS_OPEN}}": f"{metrics['average_days_open_active']:.1f}",
        "{{RISK_ROWS}}": build_html_risk_rows(risks),
    }

    for placeholder, value in replacements.items():
        html = html.replace(placeholder, value)

    with open(HTML_REPORT, mode="w", encoding="utf-8") as dashboard_file:
        dashboard_file.write(html)


def generate_reports(risks):
    print("\n=== Generating Reports ===")

    if not risks:
        print("No risks available to report.")
        return

    enrich_risks(risks)
    generate_charts(risks)

    metrics = calculate_report_metrics(risks)

    write_txt_report(risks, metrics)
    write_md_report(risks, metrics)
    write_html_dashboard(risks, metrics)

    print("Reports and charts generated successfully.")
    print(f"- {TXT_REPORT}")
    print(f"- {MD_REPORT}")
    print(f"- {HTML_REPORT}")
    print(f"- {CHARTS_DIR}/")


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


if __name__ == "__main__":
    main()
