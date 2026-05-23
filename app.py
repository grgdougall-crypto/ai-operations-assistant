from datetime import datetime
import sqlite3

from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)

DATABASE = "risks.db"

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
    "Cloud Security",
    "Security Operations",
    "Governance",
    "Compliance",
    "Identity and Access",
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
    "Cloud Operations",
    "Identity Team",
]


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def get_all_risks():
    conn = get_db_connection()

    risks = conn.execute("""
        SELECT
            id,
            name,
            severity,
            category,
            status,
            owner,
            timestamp,
            due_date
        FROM risks
        ORDER BY severity DESC, due_date ASC
    """).fetchall()

    conn.close()
    return risks


def calculate_kpis(risks):
    total_risks = len(risks)
    critical_risks = sum(1 for risk in risks if risk["severity"] >= 9)
    high_risks = sum(1 for risk in risks if 7 <= risk["severity"] <= 8)
    open_risks = sum(1 for risk in risks if risk["status"] == "OPEN")

    return {
        "total_risks": total_risks,
        "critical_risks": critical_risks,
        "high_risks": high_risks,
        "open_risks": open_risks,
    }


def generate_next_risk_id():
    conn = get_db_connection()

    rows = conn.execute("SELECT id FROM risks").fetchall()
    conn.close()

    highest_number = 0

    for row in rows:
        risk_id = row["id"]

        try:
            number = int(risk_id.split("-")[1])
            highest_number = max(highest_number, number)
        except (IndexError, ValueError):
            continue

    return f"RISK-{highest_number + 1:03d}"


def insert_new_risk(name, severity, category, status, owner, due_date):
    conn = get_db_connection()

    new_risk_id = generate_next_risk_id()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute(
        """
        INSERT INTO risks (
            id,
            name,
            severity,
            category,
            status,
            owner,
            timestamp,
            due_date
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            new_risk_id,
            name.upper(),
            severity,
            category,
            status,
            owner,
            timestamp,
            due_date,
        ),
    )

    conn.commit()
    conn.close()


@app.route("/")
def dashboard():
    risks = get_all_risks()
    kpis = calculate_kpis(risks)

    return render_template(
        "dashboard.html",
        risks=risks,
        kpis=kpis,
        categories=CATEGORIES,
        statuses=STATUSES,
        owners=OWNERS,
    )


@app.route("/add", methods=["POST"])
def add_risk():
    name = request.form.get("name", "").strip()
    severity = request.form.get("severity", "").strip()
    category = request.form.get("category", "").strip()
    status = request.form.get("status", "").strip()
    owner = request.form.get("owner", "").strip()
    due_date = request.form.get("due_date", "").strip()

    if not name or not severity or not category or not status or not owner or not due_date:
        return redirect(url_for("dashboard"))

    try:
        severity_number = int(severity)
    except ValueError:
        return redirect(url_for("dashboard"))

    if severity_number < 1 or severity_number > 10:
        return redirect(url_for("dashboard"))

    insert_new_risk(
        name=name,
        severity=severity_number,
        category=category,
        status=status,
        owner=owner,
        due_date=due_date,
    )

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True)
