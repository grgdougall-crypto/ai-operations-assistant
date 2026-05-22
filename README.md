# AI Operations Assistant

Python-based operational risk tracking and remediation coordination platform designed to simulate real-world security and IT operations workflows.

This project focuses on:
- operational risk management
- SLA tracking
- remediation coordination
- lifecycle management
- reporting automation
- governance/risk concepts
- future AI-assisted operational workflows

---

# Features

## Current Capabilities

- CSV-based risk tracking
- Automatic risk ID generation
- Severity-based priority calculation
- SLA monitoring and due-date tracking
- Risk aging metrics
- TXT report generation
- Markdown report generation
- Owner assignment workflows
- Recommendation mapping
- Category and status management
- Interactive operational menu system
- Risk lifecycle management
- Risk status updates
- Risk owner reassignment
- Risk closure workflows
- Persistent CSV rewrite/save functionality
- Filter and search workflows
- Keyword-based operational search
- Critical risk visibility
- Overdue risk tracking

---

# Operational Workflow

The application currently supports the following workflow:

1. Add new operational/security risks
2. View existing risks
3. Update risk status
4. Reassign risk ownership
5. Close risks
6. Filter/search operational risks
7. Generate operational reports
8. Persist updates to CSV storage

---

# Example Risk Categories

- Authentication
- Network
- Endpoint Security
- Data Protection
- Backup and Recovery
- Incident Response
- Security Awareness
- Infrastructure
- User Access
- Physical Security

---

# Example Risk Types

- Weak password policy
- Exposed RDP services
- Unsupported operating systems
- Expired SSL certificates
- Public-facing insecure APIs
- Backup share exposure
- Missing MFA enforcement
- Phishing susceptibility
- Firewall misconfiguration

---

# Generated Reports

The platform currently generates:

## TXT Executive Report

Includes:
- risk summaries
- SLA metrics
- overdue risks
- owner statistics
- category summaries
- operational metrics

## Markdown Risk Report

Includes:
- formatted risk tables
- operational summaries
- lifecycle tracking
- executive reporting sections

---

# Technologies Used

- Python
- CSV
- Markdown
- VS Code
- Git
- GitHub

---

# Current Architecture

```text
ai-operations-assistant/
│
├── screenshots/
├── risk_summary.py
├── risks.csv
├── risk_report.txt
├── risk_report.md
└── README.md
```

---

# Screenshots

## Main Menu

The primary operational interface for interacting with the AI Operations Assistant.

![Main Menu](screenshots/01_AI_Assist_SS1_Main_Menu.png)

---

## Filter and Search Menu

Operational filtering and search workflows for identifying risks by severity, owner, category, status, or keyword.

![Filter Search Menu](screenshots/02_AI_Assist_SS2_Filter_Search_Menu.png)

---

## Keyword Search Workflow

Example keyword-based operational risk search using the term `backup`.

![Keyword Search](screenshots/03_AI_Assist_SS3_Keyword_Search.png)

---

## Critical Risk Output

Prioritized operational risk output showing severity, ownership, SLA metrics, and remediation recommendations.

![Critical Risks](screenshots/04_AI_Assist_SS4_Critical_Risk_Output.png)

---

## Markdown Risk Report

Automatically generated markdown-based operational risk reporting.

![Markdown Report](screenshots/05_AI_Assist_SS5_Markdown_Report.png)

---

## Executive and SLA Summaries

Executive summary metrics including:
- severity distribution
- SLA tracking
- category summaries
- operational reporting metrics

![Markdown Summaries](screenshots/06_AI_Assist_SS6_Markdown_Summaries.png)

---

## CSV Operational Data

Structured CSV-based operational risk storage and persistence.

![CSV Data](screenshots/07_AI_Assist_SS7_CSV_Data.png)

---

# Planned Enhancements

## Phase 1 — Filtering and Search
- Filter by severity
- Filter by owner
- Filter by category
- Filter by status
- Search by keyword
- Show overdue risks

## Phase 2 — Dashboard Metrics
- Risk visualizations
- SLA dashboards
- Aging charts
- Severity distributions
- Operational metrics

## Phase 3 — SQLite Integration
- Replace CSV backend
- Queryable data storage
- Improved scalability
- Faster filtering/search

## Phase 4 — Web Interface
- Streamlit dashboard
- Browser-based workflows
- Interactive reporting
- Operational UI improvements

## Phase 5 — AI-Assisted Operations
- AI-generated remediation recommendations
- Intelligent prioritization
- SLA escalation suggestions
- Risk trend analysis
- Operational coordination assistance

---

# Future Direction

This project is evolving toward a lightweight AI-assisted operational risk and remediation platform inspired by:
- GRC workflows
- security operations coordination
- remediation tracking systems
- operational governance tooling
- project management workflows

---

# Author

Greg Dougall

GitHub:
https://github.com/grgdougall-crypto
