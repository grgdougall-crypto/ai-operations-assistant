from collections import Counter
from datetime import datetime, date
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
    """
    Ensure required columns exist.
    This function only updates SQLite schema. It does not call Gemini/OpenAI.
    """
    conn = get_db_connection()
    columns = conn.execute("PRAGMA table_info(risks)").fetchall()
    column_names = [column["name"] for column in columns]

    if "recommendation" not in column_names:
        conn.execute("ALTER TABLE risks ADD COLUMN recommendation TEXT")
        conn.commit()

    if "ai_rationale" not in column_names:
        conn.execute("ALTER TABLE risks ADD COLUMN ai_rationale TEXT")
        conn.commit()

    if "ai_source" not in column_names:
        conn.execute("ALTER TABLE risks ADD COLUMN ai_source TEXT")
        conn.commit()

    conn.close()


def normalize_legacy_ai_source_labels():
    """
    Label older records without making AI API calls.
    """
    conn = get_db_connection()

    conn.execute(
        """
        UPDATE risks
        SET ai_source = 'rule-based'
        WHERE ai_source IS NULL OR TRIM(ai_source) = ''
        """
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
            ai_rationale,
            ai_source
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
            ai_rationale,
            ai_source
        FROM risks
        WHERE id = ?
        """,
        (risk_id,),
    ).fetchone()
    conn.close()
    return risk


def is_active_status(status):
    return status in ["OPEN", "IN PROGRESS", "PENDING REVIEW"]


def parse_due_date(due_date_text):
    try:
        return datetime.strptime(due_date_text, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


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


def convert_counter_to_bar_data(counter, total_count, limit=None):
    items = counter.most_common(limit)
    results = []

    for label, count in items:
        percent = round((count / total_count) * 100, 1) if total_count else 0
        results.append(
            {
                "label": label,
                "count": count,
                "percent": percent,
            }
        )

    return results


def calculate_executive_analytics(risks):
    today = date.today()
    total_risks = len(risks)

    active_risks = [risk for risk in risks if is_active_status(risk["status"])]
    active_count = len(active_risks)

    critical_count = sum(1 for risk in risks if risk["severity"] >= 9)
    high_count = sum(1 for risk in risks if 7 <= risk["severity"] <= 8)
    moderate_count = sum(1 for risk in risks if 4 <= risk["severity"] <= 6)
    low_count = sum(1 for risk in risks if risk["severity"] <= 3)

    overdue_count = 0
    due_soon_count = 0

    for risk in active_risks:
        due_date = parse_due_date(risk["due_date"])

        if due_date is None:
            continue

        days_until_due = (due_date - today).days

        if days_until_due < 0:
            overdue_count += 1
        elif days_until_due <= 7:
            due_soon_count += 1

    closed_count = sum(1 for risk in risks if risk["status"] == "CLOSED")
    mitigated_count = sum(1 for risk in risks if risk["status"] == "MITIGATED")
    resolved_count = closed_count + mitigated_count

    resolution_rate = round((resolved_count / total_risks) * 100, 1) if total_risks else 0

    average_severity = (
        round(sum(risk["severity"] for risk in risks) / total_risks, 1)
        if total_risks
        else 0
    )

    status_counter = Counter(risk["status"] for risk in risks)
    category_counter = Counter(risk["category"] for risk in risks)
    owner_counter = Counter(risk["owner"] for risk in active_risks)
    ai_source_counter = Counter(risk["ai_source"] or "unknown" for risk in risks)

    severity_counter = Counter()
    severity_counter["Critical"] = critical_count
    severity_counter["High"] = high_count
    severity_counter["Moderate"] = moderate_count
    severity_counter["Low"] = low_count

    highest_risk = risks[0] if risks else None
    top_category = category_counter.most_common(1)[0][0] if category_counter else "N/A"
    top_owner = owner_counter.most_common(1)[0][0] if owner_counter else "N/A"

    if critical_count > 0 or overdue_count > 0:
        posture = "Needs Attention"
        posture_class = "posture-risk"
    elif high_count > 0 or due_soon_count > 0:
        posture = "Watch"
        posture_class = "posture-watch"
    else:
        posture = "Stable"
        posture_class = "posture-stable"

    executive_brief = (
        f"Current portfolio contains {total_risks} tracked risks with "
        f"{active_count} active items. There are {critical_count} critical risks, "
        f"{high_count} high risks, and {overdue_count} overdue active risks. "
        f"The most common category is {top_category}, and the most loaded "
        f"active owner is {top_owner}."
    )

    return {
        "posture": posture,
        "posture_class": posture_class,
        "executive_brief": executive_brief,
        "active_count": active_count,
        "overdue_count": overdue_count,
        "due_soon_count": due_soon_count,
        "resolution_rate": resolution_rate,
        "average_severity": average_severity,
        "top_category": top_category,
        "top_owner": top_owner,
        "highest_risk": highest_risk,
        "severity_distribution": convert_counter_to_bar_data(severity_counter, total_risks),
        "status_distribution": convert_counter_to_bar_data(status_counter, total_risks),
        "category_distribution": convert_counter_to_bar_data(category_counter, total_risks, limit=6),
        "owner_workload": convert_counter_to_bar_data(owner_counter, active_count, limit=6),
        "ai_source_distribution": convert_counter_to_bar_data(ai_source_counter, total_risks),
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
            ai_rationale,
            ai_source
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ai_analysis.get("source", "unknown"),
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
            ai_rationale = ?,
            ai_source = ?
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
            ai_analysis.get("source", "unknown"),
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
    normalize_legacy_ai_source_labels()

    risks = get_all_risks()
    kpis = calculate_kpis(risks)
    executive = calculate_executive_analytics(risks)

    return render_template(
        "dashboard.html",
        risks=risks,
        kpis=kpis,
        executive=executive,
        categories=CATEGORIES,
        statuses=STATUSES,
        owners=OWNERS,
    )


@app.route("/risk/<risk_id>")
def risk_detail(risk_id):
    ensure_database_schema()
    normalize_legacy_ai_source_labels()

    risk = get_risk_by_id(risk_id)

    if risk is None:
        return redirect(url_for("dashboard"))

    return render_template("risk_detail.html", risk=risk)


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
