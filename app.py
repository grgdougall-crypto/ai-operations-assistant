from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

DATABASE = "risks.db"


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


@app.route("/")
def dashboard():
    risks = get_all_risks()
    kpis = calculate_kpis(risks)

    return render_template(
        "dashboard.html",
        risks=risks,
        kpis=kpis,
    )


if __name__ == "__main__":
    app.run(debug=True)