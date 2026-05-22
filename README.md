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

---

# Operational Workflow

The application currently supports the following workflow:

1. Add new operational/security risks
2. View existing risks
3. Update risk status
4. Reassign risk ownership
5. Close risks
6. Generate operational reports
7. Persist updates to CSV storage

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
├── risk_summary.py
├── risks.csv
├── risk_report.txt
├── risk_report.md
└── README.md
