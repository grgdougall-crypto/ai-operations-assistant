# AI Operations Risk Report

## Executive KPI Dashboard

| KPI | Value |
|---|---:|
| Total Risks | 27 |
| Critical Risks | 10 |
| High Risks | 13 |
| Moderate Risks | 4 |
| Overdue Risks | 0 |
| On Track Risks | 25 |
| Risks Due Within 7 Days | 12 |
| SLA Compliance | 92.6% |
| Average Severity | 7.63 |
| Highest Risk | RISK-003 - NO MFA FOR VPN |

## Dashboard Charts

![Risk Distribution by Priority](charts/risks_by_priority.png)

![Risk Lifecycle Status Overview](charts/risks_by_status.png)

![Risk Distribution by Category](charts/risks_by_category.png)

![Open Risk Workload by Owner](charts/risks_by_owner.png)

![SLA Due Status Overview](charts/risks_by_due_status.png)

![Top 5 Highest Severity Risks](charts/top_5_risks.png)

![Operational Risk Heat Map](charts/operational_risk_heat_map.png)

## Risk Detail Table

| ID | Risk | Priority | Severity | Category | Status | Owner | Timestamp | Due Date | Due Status | Days Open | Days Until Due | Recommendation |
|----|------|----------|----------|----------|--------|-------|------------|----------|------------|-----------|----------------|----------------|
| RISK-003 | NO MFA FOR VPN | CRITICAL | 10 | Authentication | OPEN | Security Team | 2026-05-16 08:45:00 | 2026-05-30 | ON TRACK | 7 | 7 | Require MFA for VPN, remote access, privileged accounts, and cloud applications. Review access logs and disable accounts that no longer require remote access. |
| RISK-001 | WEAK PASSWORD POLICY | CRITICAL | 9 | Authentication | OPEN | Security Team | 2026-05-15 10:30:00 | 2026-06-01 | ON TRACK | 8 | 9 | Enforce stronger password policies, require password length and complexity, enable account lockout protections, and review failed login activity. |
| RISK-004 | PHISHING CAMPAIGN EXPOSURE | CRITICAL | 9 | Security Awareness | OPEN | Security Team | 2026-05-17 09:10:00 | 2026-06-10 | ON TRACK | 6 | 18 | Provide phishing awareness training, enable email filtering, review reported messages, and run targeted simulations for high-risk user groups. |
| RISK-005 | EXPOSED RDP PORT | CRITICAL | 9 | Network | IN PROGRESS | Network Operations | 2026-05-18 16:05:00 | 2026-05-28 | ON TRACK | 5 | 5 | Disable public RDP exposure, restrict access through VPN or jump hosts, enforce MFA, and limit access to approved administrative users. |
| RISK-007 | SHARED ADMIN ACCOUNT | CRITICAL | 9 | Authentication | OPEN | Security Team | 2026-05-21 20:35:09 | 2026-05-29 | ON TRACK | 2 | 6 | Review privileged access, remove unnecessary admin rights, rotate credentials, enforce MFA, and replace shared admin accounts with named accounts. |
| RISK-008 | EXPOSED DATABASE PORT | CRITICAL | 9 | Network | OPEN | Infrastructure Team | 2026-05-21 21:02:11 | 2026-05-27 | ON TRACK | 2 | 4 | Restrict database access, review user permissions, disable public exposure, enforce encryption, and monitor for unauthorized queries. |
| RISK-013 | UNSUPPORTED OPERATING SYSTEM | CRITICAL | 9 | Infrastructure | IN PROGRESS | Infrastructure Team | 2026-05-21 22:30:00 | 2026-06-15 | ON TRACK | 2 | 23 | Upgrade unsupported systems, isolate legacy assets, apply compensating controls, and create a retirement or replacement plan. |
| RISK-018 | UNMANAGED LOCAL ADMIN ACCOUNT | CRITICAL | 9 | Authentication | OPEN | Security Team | 2026-05-21 23:05:01 | 2026-05-28 | ON TRACK | 2 | 5 | Review privileged access, remove unnecessary admin rights, rotate credentials, enforce MFA, and replace shared admin accounts with named accounts. |
| RISK-023 | PUBLIC RDP PORT EXPOSED | CRITICAL | 9 | Infrastructure | OPEN | Infrastructure Team | 2026-05-22 16:21:49 | 2026-05-25 | ON TRACK | 1 | 2 | Disable public RDP exposure, restrict access through VPN or jump hosts, enforce MFA, and limit access to approved administrative users. |
| RISK-026 | UNSUPPORTED OPERATING SYSTEM | CRITICAL | 9 | Endpoint Security | OPEN | Security Team | 2026-05-22 16:28:32 | 2026-05-27 | ON TRACK | 1 | 4 | Upgrade unsupported systems, isolate legacy assets, apply compensating controls, and create a retirement or replacement plan. |
| RISK-002 | OUTDATED FIREWALL FIRMWARE | HIGH | 8 | Network | IN PROGRESS | Network Operations | 2026-05-15 11:15:00 | 2026-06-05 | ON TRACK | 8 | 13 | Review firewall rules, remove unnecessary inbound access, restrict management ports, document approved exceptions, and verify firmware is current. |
| RISK-006 | UNENCRYPTED LAPTOP | HIGH | 8 | Endpoint Security | OPEN | Help Desk | 2026-05-21 20:20:33 | 2026-06-12 | ON TRACK | 2 | 20 | Verify endpoint protection, enable full-disk encryption, confirm patch compliance, and ensure the device is enrolled in centralized management. |
| RISK-009 | INSECURE API ENDPOINT | HIGH | 8 | Infrastructure | OPEN | Infrastructure Team | 2026-05-21 21:45:25 | 2026-06-08 | ON TRACK | 2 | 16 | Review API authentication, rotate exposed keys or tokens, restrict public access, validate rate limiting, and monitor API activity logs. |
| RISK-010 | LEGACY VPN APPLIANCE | HIGH | 8 | Network | IN PROGRESS | Network Operations | 2026-05-21 21:50:03 | 2026-06-15 | ON TRACK | 2 | 23 | Require MFA for VPN, remote access, privileged accounts, and cloud applications. Review access logs and disable accounts that no longer require remote access. |
| RISK-012 | UNAUTHORIZED CLOUD STORAGE | HIGH | 8 | Data Protection | OPEN | Compliance Team | 2026-05-21 22:18:00 | 2026-06-18 | ON TRACK | 2 | 26 | Review cloud permissions, disable public access where not required, enforce least privilege, enable logging, and validate configuration baselines. |
| RISK-014 | EXPOSED TEST ENVIRONMENT  | HIGH | 8 | Infrastructure | OPEN | Infrastructure Team | 2026-05-21 22:29:22 | 2026-06-22 | ON TRACK | 2 | 30 | Review the risk, validate business impact, assign an owner, document remediation steps, and track progress until the risk is reduced or formally accepted. |
| RISK-015 | INSECURE SERVICE ACCOUNT | HIGH | 8 | Authentication | OPEN | Security Team | 2026-05-21 22:38:39 | 2026-06-25 | ON TRACK | 2 | 33 | Review the risk, validate business impact, assign an owner, document remediation steps, and track progress until the risk is reduced or formally accepted. |
| RISK-016 | WEAK ENCRYPTION SETTING | HIGH | 8 | Infrastructure | OPEN | Infrastructure Team | 2026-05-21 22:44:39 | 2026-06-28 | ON TRACK | 2 | 36 | Enable strong encryption, remove weak protocols, protect sensitive data at rest and in transit, and verify encryption settings through policy review. |
| RISK-019 | EXPOSED BACKUP SHARE | HIGH | 8 | Backup and Recovery | OPEN | Infrastructure Team | 2026-05-21 23:23:52 | 2026-05-26 | ON TRACK | 2 | 3 | Verify backup integrity, restrict backup share permissions, perform a documented test restore, and confirm backups are protected from ransomware. |
| RISK-020 | EXPOSED BACKUP SHARE | HIGH | 8 | Backup and Recovery | OPEN | Infrastructure Team | 2026-05-21 23:31:01 | 2026-05-26 | ON TRACK | 2 | 3 | Verify backup integrity, restrict backup share permissions, perform a documented test restore, and confirm backups are protected from ransomware. |
| RISK-024 | EXPIRED SSL CERTIFICATE | HIGH | 8 | Authentication | OPEN | Security Team | 2026-05-22 16:22:53 | 2026-05-25 | ON TRACK | 1 | 2 | Renew expired certificates, verify TLS configuration, remove weak protocols, and document certificate ownership and renewal dates. |
| RISK-011 | MISSING ENDPOINT MONITORING | HIGH | 7 | Endpoint Security | OPEN | Security Team | 2026-05-21 22:05:00 | 2026-06-20 | ON TRACK | 2 | 28 | Verify endpoint protection, enable full-disk encryption, confirm patch compliance, and ensure the device is enrolled in centralized management. |
| RISK-017 | EXPIRED SSL CERTIFICATE | HIGH | 7 | Infrastructure | OPEN | Infrastructure Team | 2026-05-21 22:55:00 | 2026-05-25 | ON TRACK | 2 | 2 | Renew expired certificates, verify TLS configuration, remove weak protocols, and document certificate ownership and renewal dates. |
| RISK-025 | SHARED ADMIN ACCOUNT | MODERATE | 6 | User Access | OPEN | Network Operations | 2026-05-22 16:27:36 | 2026-05-25 | ON TRACK | 1 | 2 | Review privileged access, remove unnecessary admin rights, rotate credentials, enforce MFA, and replace shared admin accounts with named accounts. |
| RISK-027 | TEST 2 | MODERATE | 5 | Incident Response | MITIGATED | SOC Analyst | 2026-05-22 17:16:55 | 2026-06-01 | NOT ACTIVE | 1 | 9 | Review the risk, validate business impact, assign an owner, document remediation steps, and track progress until the risk is reduced or formally accepted. |
| RISK-021 | TEST | MODERATE | 1 | Authentication | CLOSED | SOC Analyst | 2026-05-21 23:47:33 | 2026-05-22 | NOT ACTIVE | 2 | -1 | Review the risk, validate business impact, assign an owner, document remediation steps, and track progress until the risk is reduced or formally accepted. |
| RISK-022 | TEST 1 | MODERATE | 1 | Backup and Recovery | OPEN | Network Operations | 2026-05-22 16:19:37 | 2026-06-01 | ON TRACK | 1 | 9 | Verify backup integrity, restrict backup share permissions, perform a documented test restore, and confirm backups are protected from ransomware. |

## Category Summary

- Authentication: 7
- Network: 4
- Security Awareness: 1
- Endpoint Security: 3
- Infrastructure: 6
- Data Protection: 1
- Backup and Recovery: 3
- User Access: 1
- Incident Response: 1

## Status Summary

- OPEN: 21
- IN PROGRESS: 4
- CLOSED: 1
- MITIGATED: 1

## Owner Summary

- Security Team: 9
- Network Operations: 5
- Help Desk: 1
- Infrastructure Team: 9
- Compliance Team: 1
- SOC Analyst: 2

## Due Status Summary

- ON TRACK: 25
- NOT ACTIVE: 2
