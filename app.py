from flask import Flask, render_template_string
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


@app.route("/")
def home():
    risks = get_all_risks()

    total_risks = len(risks)
    critical_risks = sum(1 for risk in risks if risk["severity"] >= 9)
    high_risks = sum(1 for risk in risks if 7 <= risk["severity"] <= 8)
    open_risks = sum(1 for risk in risks if risk["status"] == "OPEN")

    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>AI Operations Risk Platform</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #eef2f6;
                color: #111827;
                margin: 20px;
            }

            h1 {
                text-align: center;
                margin-bottom: 20px;
            }

            .kpi-grid {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 12px;
                margin-bottom: 20px;
            }

            .kpi-card {
                background: white;
                border: 1px solid #cfd8e3;
                border-radius: 6px;
                padding: 16px;
                box-shadow: 0 1px 4px rgba(0,0,0,0.08);
            }

            .kpi-title {
                color: #475569;
                font-size: 13px;
                margin-bottom: 8px;
            }

            .kpi-value {
                font-size: 28px;
                font-weight: bold;
            }

            .panel {
                background: white;
                border: 1px solid #cfd8e3;
                border-radius: 6px;
                overflow: hidden;
                box-shadow: 0 1px 4px rgba(0,0,0,0.08);
            }

            .panel h2 {
                background: #202938;
                color: white;
                font-size: 15px;
                padding: 10px;
                margin: 0;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                font-size: 14px;
            }

            th {
                background: #f8fafc;
                text-align: left;
                padding: 10px;
                border-bottom: 1px solid #d0d7de;
            }

            td {
                padding: 9px 10px;
                border-bottom: 1px solid #e5e7eb;
            }

            tr:nth-child(even) {
                background: #f8fafc;
            }

            .critical {
                color: #b91c1c;
                font-weight: bold;
            }

            .high {
                color: #c2410c;
                font-weight: bold;
            }

            .moderate {
                color: #ca8a04;
                font-weight: bold;
            }
        </style>
    </head>
    <body>

        <h1>AI Operations Risk Platform</h1>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-title">Total Risks</div>
                <div class="kpi-value">{{ total_risks }}</div>
            </div>

            <div class="kpi-card">
                <div class="kpi-title">Critical Risks</div>
                <div class="kpi-value critical">{{ critical_risks }}</div>
            </div>

            <div class="kpi-card">
                <div class="kpi-title">High Risks</div>
                <div class="kpi-value high">{{ high_risks }}</div>
            </div>

            <div class="kpi-card">
                <div class="kpi-title">Open Risks</div>
                <div class="kpi-value">{{ open_risks }}</div>
            </div>
        </div>

        <div class="panel">
            <h2>Live Risks from SQLite Database</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Severity</th>
                        <th>Category</th>
                        <th>Status</th>
                        <th>Owner</th>
                        <th>Due Date</th>
                    </tr>
                </thead>
                <tbody>
                    {% for risk in risks %}
                    <tr>
                        <td>{{ risk["id"] }}</td>
                        <td>{{ risk["name"] }}</td>
                        <td class="{% if risk['severity'] >= 9 %}critical{% elif risk['severity'] >= 7 %}high{% else %}moderate{% endif %}">
                            {{ risk["severity"] }}
                        </td>
                        <td>{{ risk["category"] }}</td>
                        <td>{{ risk["status"] }}</td>
                        <td>{{ risk["owner"] }}</td>
                        <td>{{ risk["due_date"] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

    </body>
    </html>
    """

    return render_template_string(
        html,
        risks=risks,
        total_risks=total_risks,
        critical_risks=critical_risks,
        high_risks=high_risks,
        open_risks=open_risks,
    )


if __name__ == "__main__":
    app.run(debug=True)
