from datetime import datetime
import sqlite3

from flask import Flask, redirect, render_template, request, url_for

from ai_engine import generate_ai_analysis

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


def ensure_database_schema():
    conn = get_db_connection()
    columns = conn.execute("PRAGMA table_info(risks)").fetchall()
    column_names = [column["name"] for column in columns]

    if "recommendation" not in column_names:
        conn.execute("ALTER TABLE risks ADD COLUMN recommendation TEXT")
        conn.commit()

    if "ai_rationale" not in column_names:
        conn.execute("ALTER TABLE risks ADD COLUMN ai_rationale TEXT")
        conn.commit()

    conn.close()


def backfill_missing_ai_fields():
    conn = get_db_connection()

    risks = conn.execute("""
        SELECT id, name, category, severity, recommendation, ai_rationale
        FROM risks
    """).fetchall()

    for risk in risks:
        needs_recommendation = risk["recommendation"] is None or risk["recommendation"].strip() == ""
        needs_rationale = risk["ai_rationale"] is None or risk["ai_rationale"].strip() == ""

        if needs_recommendation or needs_rationale:
            ai_analysis = generate_ai_analysis(
                name=risk["name"],
                category=risk["category"],
                severity=risk["severity"],
            )

            conn.execute(
                """
                UPDATE risks
                SET recommendation = ?, ai_rationale = ?
                WHERE id = ?
                """,
                (
                    ai_analysis["recommendation"],
                    ai_analysis["rationale"],
                    risk["id"],
                ),
            )

    conn.commit()
    conn.close()


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
            due_date,
            recommendation,
            ai_rationale
        FROM risks
        ORDER BY severity DESC, due_date ASC
    """).fetchall()

    conn.close()
    return risks


def get_risk_by_id(risk_id):
    conn = get_db_connection()
    risk = conn.execute(
        """
        SELECT
            id,
            name,
            severity,
            category,
            status,
            owner,
            timestamp,
            due_date,
            recommendation,
            ai_rationale
        FROM risks
        WHERE id = ?
        """,
        (risk_id,),
    ).fetchone()
    conn.close()
    return risk


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
    ai_analysis = generate_ai_analysis(name, category, severity)

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
            due_date,
            recommendation,
            ai_rationale
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ai_analysis["recommendation"],
            ai_analysis["rationale"],
        ),
    )

    conn.commit()
    conn.close()


def update_existing_risk(risk_id, name, severity, category, status, owner, due_date):
    conn = get_db_connection()
    ai_analysis = generate_ai_analysis(name, category, severity)

    conn.execute(
        """
        UPDATE risks
        SET
            name = ?,
            severity = ?,
            category = ?,
            status = ?,
            owner = ?,
            due_date = ?,
            recommendation = ?,
            ai_rationale = ?
        WHERE id = ?
        """,
        (
            name.upper(),
            severity,
            category,
            status,
            owner,
            due_date,
            ai_analysis["recommendation"],
            ai_analysis["rationale"],
            risk_id,
        ),
    )

    conn.commit()
    conn.close()


def delete_existing_risk(risk_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM risks WHERE id = ?", (risk_id,))
    conn.commit()
    conn.close()


def validate_risk_form(form):
    name = form.get("name", "").strip()
    severity = form.get("severity", "").strip()
    category = form.get("category", "").strip()
    status = form.get("status", "").strip()
    owner = form.get("owner", "").strip()
    due_date = form.get("due_date", "").strip()

    if not name or not severity or not category or not status or not owner or not due_date:
        return None

    try:
        severity_number = int(severity)
    except ValueError:
        return None

    if severity_number < 1 or severity_number > 10:
        return None

    return {
        "name": name,
        "severity": severity_number,
        "category": category,
        "status": status,
        "owner": owner,
        "due_date": due_date,
    }


@app.route("/")
def dashboard():
    ensure_database_schema()
    backfill_missing_ai_fields()

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
    ensure_database_schema()
    form_data = validate_risk_form(request.form)

    if form_data is None:
        return redirect(url_for("dashboard"))

    insert_new_risk(**form_data)
    return redirect(url_for("dashboard"))


@app.route("/edit/<risk_id>", methods=["GET", "POST"])
def edit_risk(risk_id):
    ensure_database_schema()
    risk = get_risk_by_id(risk_id)

    if risk is None:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        form_data = validate_risk_form(request.form)

        if form_data is None:
            return redirect(url_for("edit_risk", risk_id=risk_id))

        update_existing_risk(risk_id=risk_id, **form_data)
        return redirect(url_for("dashboard"))

    return render_template(
        "edit_risk.html",
        risk=risk,
        categories=CATEGORIES,
        statuses=STATUSES,
        owners=OWNERS,
    )


@app.route("/delete/<risk_id>", methods=["POST"])
def delete_risk(risk_id):
    ensure_database_schema()
    delete_existing_risk(risk_id)
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    ensure_database_schema()
    app.run(debug=True)
