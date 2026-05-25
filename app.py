from collections import Counter
from datetime import datetime, date
import csv
import io
import sqlite3

from dotenv import load_dotenv
from flask import Flask, make_response, redirect, render_template, request, url_for

load_dotenv()

from ai_engine import generate_ai_analysis, generate_ai_executive_summary

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

RESOLVED_STATUSES = ["CLOSED", "MITIGATED", "ACCEPTED"]
ACTIVE_STATUSES = ["OPEN", "IN PROGRESS", "PENDING REVIEW"]


def get_db_connection():
    conn = sqlite3.connect(DATABASE, timeout=10)
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

    if "ai_source" not in column_names:
        conn.execute("ALTER TABLE risks ADD COLUMN ai_source TEXT")
        conn.commit()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS executive_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            generated_at TEXT NOT NULL,
            summary TEXT NOT NULL,
            priority_focus TEXT NOT NULL,
            business_impact TEXT NOT NULL,
            ai_source TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            event_description TEXT NOT NULL,
            related_risk_id TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    conn.commit()
    conn.close()


def normalize_legacy_ai_source_labels():
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


def create_audit_log(event_type, event_description, related_risk_id=None):
    conn = get_db_connection()
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute(
        """
        INSERT INTO audit_logs (
            event_type,
            event_description,
            related_risk_id,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            event_type,
            event_description,
            related_risk_id,
            created_at,
        ),
    )

    conn.commit()
    conn.close()


def get_recent_audit_logs(limit=10):
    conn = get_db_connection()

    rows = conn.execute(
        """
        SELECT
            id,
            event_type,
            event_description,
            related_risk_id,
            created_at
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    conn.close()
    return rows


def get_audit_event_types():
    conn = get_db_connection()

    rows = conn.execute(
        """
        SELECT DISTINCT event_type
        FROM audit_logs
        ORDER BY event_type ASC
        """
    ).fetchall()

    conn.close()
    return [row["event_type"] for row in rows]


def get_all_audit_logs(search_query="", event_type=""):
    conn = get_db_connection()

    base_query = """
        SELECT
            id,
            event_type,
            event_description,
            related_risk_id,
            created_at
        FROM audit_logs
        WHERE 1 = 1
    """

    params = []

    if search_query:
        base_query += """
            AND (
                LOWER(event_description) LIKE ?
                OR LOWER(related_risk_id) LIKE ?
                OR LOWER(event_type) LIKE ?
            )
        """
        search_pattern = f"%{search_query.lower()}%"
        params.extend([search_pattern, search_pattern, search_pattern])

    if event_type:
        base_query += " AND event_type = ?"
        params.append(event_type)

    base_query += " ORDER BY id DESC"

    rows = conn.execute(base_query, params).fetchall()
    conn.close()
    return rows


def calculate_audit_summary(audit_logs):
    total_events = len(audit_logs)
    event_counter = Counter(log["event_type"] for log in audit_logs)

    return {
        "total_events": total_events,
        "risk_created": event_counter.get("Risk Created", 0),
        "risk_updated": event_counter.get("Risk Updated", 0),
        "risk_deleted": event_counter.get("Risk Deleted", 0),
        "exports": event_counter.get("CSV Export", 0) + event_counter.get("Markdown Export", 0),
        "summaries": event_counter.get("Executive Summary Generated", 0),
    }


def describe_risk_changes(old_risk, new_data):
    changes = []

    comparison_fields = [
        ("name", "Name"),
        ("severity", "Severity"),
        ("category", "Category"),
        ("status", "Status"),
        ("owner", "Owner"),
        ("due_date", "Due Date"),
    ]

    for field_name, label in comparison_fields:
        old_value = old_risk[field_name]
        new_value = new_data[field_name]

        if str(old_value) != str(new_value):
            changes.append(f"{label} changed from {old_value} to {new_value}")

    if not changes:
        return "Risk saved with no field changes."

    return "; ".join(changes)


def parse_due_date(due_date_text):
    try:
        return datetime.strptime(due_date_text, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def calculate_sla_status(status, due_date_text):
    if status in RESOLVED_STATUSES:
        return {
            "label": "Resolved",
            "class": "sla-resolved",
            "days_until_due": None,
        }

    due_date = parse_due_date(due_date_text)

    if due_date is None:
        return {
            "label": "Unknown",
            "class": "sla-unknown",
            "days_until_due": None,
        }

    days_until_due = (due_date - date.today()).days

    if days_until_due < 0:
        return {
            "label": "Breached",
            "class": "sla-breached",
            "days_until_due": days_until_due,
        }

    if days_until_due <= 7:
        return {
            "label": "Due Soon",
            "class": "sla-due-soon",
            "days_until_due": days_until_due,
        }

    return {
        "label": "On Track",
        "class": "sla-on-track",
        "days_until_due": days_until_due,
    }


def add_sla_metadata(risk):
    risk_dict = dict(risk)
    risk_dict["sla"] = calculate_sla_status(
        risk_dict["status"],
        risk_dict["due_date"],
    )
    return risk_dict


def get_all_risks():
    conn = get_db_connection()

    rows = conn.execute(
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
        ORDER BY severity DESC, due_date ASC
        """
    ).fetchall()

    conn.close()
    return [add_sla_metadata(row) for row in rows]


def get_risk_by_id(risk_id):
    conn = get_db_connection()

    row = conn.execute(
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

    if row is None:
        return None

    return add_sla_metadata(row)


def get_latest_executive_summary():
    conn = get_db_connection()

    summary = conn.execute(
        """
        SELECT
            id,
            generated_at,
            summary,
            priority_focus,
            business_impact,
            ai_source
        FROM executive_summaries
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    conn.close()
    return summary


def save_executive_summary(summary_data):
    conn = get_db_connection()
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute(
        """
        INSERT INTO executive_summaries (
            generated_at,
            summary,
            priority_focus,
            business_impact,
            ai_source
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            generated_at,
            summary_data["summary"],
            summary_data["priority_focus"],
            summary_data["business_impact"],
            summary_data.get("source", "unknown"),
        ),
    )

    conn.commit()
    conn.close()


def is_active_status(status):
    return status in ACTIVE_STATUSES


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


def convert_counter_to_chart_data(counter, limit=None):
    items = counter.most_common(limit)

    return {
        "labels": [label for label, count in items],
        "values": [count for label, count in items],
    }


def calculate_executive_analytics(risks):
    total_risks = len(risks)
    active_risks = [risk for risk in risks if is_active_status(risk["status"])]
    active_count = len(active_risks)

    critical_count = sum(1 for risk in risks if risk["severity"] >= 9)
    high_count = sum(1 for risk in risks if 7 <= risk["severity"] <= 8)
    moderate_count = sum(1 for risk in risks if 4 <= risk["severity"] <= 6)
    low_count = sum(1 for risk in risks if risk["severity"] <= 3)

    overdue_count = sum(1 for risk in active_risks if risk["sla"]["label"] == "Breached")
    due_soon_count = sum(1 for risk in active_risks if risk["sla"]["label"] == "Due Soon")
    on_track_count = sum(1 for risk in active_risks if risk["sla"]["label"] == "On Track")

    resolved_count = sum(1 for risk in risks if risk["status"] in RESOLVED_STATUSES)

    resolution_rate = round((resolved_count / total_risks) * 100, 1) if total_risks else 0
    sla_health_rate = round((on_track_count / active_count) * 100, 1) if active_count else 0

    average_severity = (
        round(sum(risk["severity"] for risk in risks) / total_risks, 1)
        if total_risks
        else 0
    )

    status_counter = Counter(risk["status"] for risk in risks)
    category_counter = Counter(risk["category"] for risk in risks)
    owner_counter = Counter(risk["owner"] for risk in active_risks)
    ai_source_counter = Counter(risk["ai_source"] or "unknown" for risk in risks)
    sla_counter = Counter(risk["sla"]["label"] for risk in risks)

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
        f"{high_count} high risks, {overdue_count} breached SLA items, "
        f"and {due_soon_count} items due within 7 days. The most common category "
        f"is {top_category}, and the most loaded active owner is {top_owner}."
    )

    return {
        "posture": posture,
        "posture_class": posture_class,
        "executive_brief": executive_brief,
        "total_risks": total_risks,
        "active_count": active_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "overdue_count": overdue_count,
        "due_soon_count": due_soon_count,
        "on_track_count": on_track_count,
        "sla_health_rate": sla_health_rate,
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
        "sla_distribution": convert_counter_to_bar_data(sla_counter, total_risks),
        "chart_data": {
            "severity": convert_counter_to_chart_data(severity_counter),
            "sla": convert_counter_to_chart_data(sla_counter),
            "categories": convert_counter_to_chart_data(category_counter, limit=6),
            "owners": convert_counter_to_chart_data(owner_counter, limit=6),
            "ai_sources": convert_counter_to_chart_data(ai_source_counter),
            "statuses": convert_counter_to_chart_data(status_counter),
        },
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

    create_audit_log(
        "Risk Created",
        f"Risk created: {name.upper()} with severity {severity}, assigned to {owner}.",
        new_risk_id,
    )


def update_existing_risk(risk_id, name, severity, category, status, owner, due_date):
    old_risk = get_risk_by_id(risk_id)

    if old_risk is None:
        return

    new_data = {
        "name": name.upper(),
        "severity": severity,
        "category": category,
        "status": status,
        "owner": owner,
        "due_date": due_date,
    }

    change_description = describe_risk_changes(old_risk, new_data)

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

    create_audit_log(
        "Risk Updated",
        f"Risk updated: {risk_id}. {change_description}",
        risk_id,
    )


def delete_existing_risk(risk_id):
    risk = get_risk_by_id(risk_id)
    risk_name = risk["name"] if risk else risk_id

    conn = get_db_connection()
    conn.execute("DELETE FROM risks WHERE id = ?", (risk_id,))
    conn.commit()
    conn.close()

    create_audit_log(
        "Risk Deleted",
        f"Risk deleted: {risk_name} ({risk_id}).",
        risk_id,
    )


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


def build_risk_export_csv(risks):
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(
        [
            "Risk ID",
            "Risk Name",
            "Severity",
            "Category",
            "Status",
            "SLA Status",
            "Days Until Due",
            "Owner",
            "Created Timestamp",
            "Due Date",
            "AI Source",
            "AI Recommendation",
            "AI Rationale",
        ]
    )

    for risk in risks:
        writer.writerow(
            [
                risk["id"],
                risk["name"],
                risk["severity"],
                risk["category"],
                risk["status"],
                risk["sla"]["label"],
                risk["sla"]["days_until_due"],
                risk["owner"],
                risk["timestamp"],
                risk["due_date"],
                risk["ai_source"],
                risk["recommendation"],
                risk["ai_rationale"],
            ]
        )

    return output.getvalue()


def build_markdown_executive_report(executive, risks, latest_summary):
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    top_risks = sorted(risks, key=lambda risk: risk["severity"], reverse=True)[:10]

    report_lines = [
        "# AI Operations Executive Risk Report",
        "",
        f"Generated: {generated_at}",
        "",
        "## Executive Posture",
        "",
        f"**Current Posture:** {executive['posture']}",
        "",
        executive["executive_brief"],
        "",
        "## KPI Snapshot",
        "",
        f"- Total Risks: {executive['total_risks']}",
        f"- Active Risks: {executive['active_count']}",
        f"- Critical Risks: {executive['critical_count']}",
        f"- High Risks: {executive['high_count']}",
        f"- SLA Breached: {executive['overdue_count']}",
        f"- Due Within 7 Days: {executive['due_soon_count']}",
        f"- SLA Health Rate: {executive['sla_health_rate']}%",
        f"- Resolution Rate: {executive['resolution_rate']}%",
        f"- Average Severity: {executive['average_severity']}",
        "",
        "## Operational Insights",
        "",
        f"- Top Risk Category: {executive['top_category']}",
        f"- Highest Workload Owner: {executive['top_owner']}",
        "",
    ]

    if latest_summary:
        report_lines.extend(
            [
                "## AI Executive Summary",
                "",
                f"**AI Source:** {latest_summary['ai_source']}",
                "",
                "### Summary",
                "",
                latest_summary["summary"],
                "",
                "### Priority Focus",
                "",
                latest_summary["priority_focus"],
                "",
                "### Business Impact",
                "",
                latest_summary["business_impact"],
                "",
            ]
        )
    else:
        report_lines.extend(
            [
                "## AI Executive Summary",
                "",
                "No AI executive summary has been generated yet.",
                "",
            ]
        )

    report_lines.extend(
        [
            "## Highest Priority Risks",
            "",
        ]
    )

    if not top_risks:
        report_lines.extend(["No risks are currently available.", ""])

    for risk in top_risks:
        report_lines.extend(
            [
                f"### {risk['id']} - {risk['name']}",
                "",
                f"- Severity: {risk['severity']}",
                f"- Category: {risk['category']}",
                f"- Status: {risk['status']}",
                f"- SLA: {risk['sla']['label']}",
                f"- Owner: {risk['owner']}",
                f"- Due Date: {risk['due_date']}",
                f"- AI Source: {risk['ai_source']}",
                "",
                "**AI Recommendation**",
                "",
                risk["recommendation"] or "No AI recommendation available.",
                "",
            ]
        )

    report_lines.extend(
        [
            "---",
            "",
            "Generated by AI Operations Risk Platform",
        ]
    )

    return "\n".join(report_lines)


@app.route("/")
def dashboard():
    ensure_database_schema()
    normalize_legacy_ai_source_labels()

    risks = get_all_risks()
    kpis = calculate_kpis(risks)
    executive = calculate_executive_analytics(risks)
    latest_executive_summary = get_latest_executive_summary()
    recent_audit_logs = get_recent_audit_logs()

    return render_template(
        "dashboard.html",
        risks=risks,
        kpis=kpis,
        executive=executive,
        latest_executive_summary=latest_executive_summary,
        recent_audit_logs=recent_audit_logs,
        categories=CATEGORIES,
        statuses=STATUSES,
        owners=OWNERS,
    )


@app.route("/audit-log")
def audit_log():
    ensure_database_schema()

    search_query = request.args.get("search", "").strip()
    selected_event_type = request.args.get("event_type", "").strip()

    audit_logs = get_all_audit_logs(
        search_query=search_query,
        event_type=selected_event_type,
    )
    event_types = get_audit_event_types()
    audit_summary = calculate_audit_summary(audit_logs)

    return render_template(
        "audit_log.html",
        audit_logs=audit_logs,
        event_types=event_types,
        audit_summary=audit_summary,
        search_query=search_query,
        selected_event_type=selected_event_type,
    )


@app.route("/export/risks.csv")
def export_risks_csv():
    ensure_database_schema()
    normalize_legacy_ai_source_labels()

    risks = get_all_risks()
    csv_data = build_risk_export_csv(risks)
    generated_at = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ai_operations_risk_export_{generated_at}.csv"

    create_audit_log(
        "CSV Export",
        f"CSV risk export generated with {len(risks)} risks.",
    )

    response = make_response(csv_data)
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"

    return response


@app.route("/export/executive-report.md")
def export_executive_report():
    ensure_database_schema()
    normalize_legacy_ai_source_labels()

    risks = get_all_risks()
    executive = calculate_executive_analytics(risks)
    latest_summary = get_latest_executive_summary()

    markdown_report = build_markdown_executive_report(
        executive,
        risks,
        latest_summary,
    )

    generated_at = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"executive_risk_report_{generated_at}.md"

    create_audit_log(
        "Markdown Export",
        f"Executive markdown report generated with {len(risks)} risks.",
    )

    response = make_response(markdown_report)
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "text/markdown; charset=utf-8"

    return response


@app.route("/generate-executive-summary", methods=["POST"])
def generate_executive_summary():
    ensure_database_schema()
    normalize_legacy_ai_source_labels()

    risks = get_all_risks()
    executive = calculate_executive_analytics(risks)
    summary_data = generate_ai_executive_summary(executive)
    save_executive_summary(summary_data)

    create_audit_log(
        "Executive Summary Generated",
        f"AI executive summary generated using {summary_data.get('source', 'unknown')}.",
    )

    return redirect(url_for("dashboard"))


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
