# AI Operations Risk Report

| ID | Risk | Priority | Severity | Category | Status | Owner | Timestamp | Due Date | Due Status | Days Open | Days Until Due | Recommendation |
|----|------|----------|----------|----------|--------|-------|------------|----------|------------|-----------|----------------|----------------|
| RISK-003 | NO MFA FOR VPN | CRITICAL | 10 | Authentication | OPEN | Security Team | 2026-05-16 08:45:00 | 2026-05-30 | ON TRACK | 6 | 8 | Enable multi-factor authentication for all remote access. |
| RISK-001 | WEAK PASSWORD POLICY | CRITICAL | 9 | Authentication | OPEN | Security Team | 2026-05-15 10:30:00 | 2026-06-01 | ON TRACK | 7 | 10 | Enforce stronger password policies and password rotation. |
| RISK-004 | PHISHING CAMPAIGN EXPOSURE | CRITICAL | 9 | Security Awareness | OPEN | Security Team | 2026-05-17 09:10:00 | 2026-06-10 | ON TRACK | 5 | 19 | Provide phishing awareness training to employees. |
| RISK-005 | EXPOSED RDP PORT | CRITICAL | 9 | Network | IN PROGRESS | Network Operations | 2026-05-18 16:05:00 | 2026-05-28 | ON TRACK | 4 | 6 | Review and remediate this risk as soon as possible. |
| RISK-007 | SHARED ADMIN ACCOUNT | CRITICAL | 9 | Authentication | OPEN | Security Team | 2026-05-21 20:35:09 | 2026-05-29 | ON TRACK | 1 | 7 | Review privileged access, rotate credentials, and remove unnecessary accounts. |
| RISK-008 | EXPOSED DATABASE PORT | CRITICAL | 9 | Network | OPEN | Infrastructure Team | 2026-05-21 21:02:11 | 2026-05-27 | ON TRACK | 1 | 5 | Review database access controls and restrict exposure. |
| RISK-013 | UNSUPPORTED OPERATING SYSTEM | CRITICAL | 9 | Infrastructure | IN PROGRESS | Infrastructure Team | 2026-05-21 22:30:00 | 2026-06-15 | ON TRACK | 1 | 24 | Upgrade unsupported systems and apply compensating controls. |
| RISK-018 | UNMANAGED LOCAL ADMIN ACCOUNT | CRITICAL | 9 | Authentication | OPEN | Security Team | 2026-05-21 23:05:01 | 2026-05-28 | ON TRACK | 1 | 6 | Review privileged access, rotate credentials, and remove unnecessary accounts. |
| RISK-002 | OUTDATED FIREWALL FIRMWARE | HIGH | 8 | Network | IN PROGRESS | Network Operations | 2026-05-15 11:15:00 | 2026-06-05 | ON TRACK | 7 | 14 | Update firewall firmware and review network rules. |
| RISK-006 | UNENCRYPTED LAPTOP | HIGH | 8 | Endpoint Security | OPEN | Help Desk | 2026-05-21 20:20:33 | 2026-06-12 | ON TRACK | 1 | 21 | Enable full-disk encryption and verify endpoint protections. |
| RISK-009 | INSECURE API ENDPOINT | HIGH | 8 | Infrastructure | OPEN | Infrastructure Team | 2026-05-21 21:45:25 | 2026-06-08 | ON TRACK | 1 | 17 | Review API authentication and restrict public exposure. |
| RISK-010 | LEGACY VPN APPLIANCE | HIGH | 8 | Network | IN PROGRESS | Network Operations | 2026-05-21 21:50:03 | 2026-06-15 | ON TRACK | 1 | 24 | Review VPN configuration, patch appliances, and enforce MFA. |
| RISK-012 | UNAUTHORIZED CLOUD STORAGE | HIGH | 8 | Data Protection | OPEN | Compliance Team | 2026-05-21 22:18:00 | 2026-06-18 | ON TRACK | 1 | 27 | Review cloud storage permissions and enforce approved configurations. |
| RISK-014 | EXPOSED TEST ENVIRONMENT  | HIGH | 8 | Infrastructure | OPEN | Infrastructure Team | 2026-05-21 22:29:22 | 2026-06-22 | ON TRACK | 1 | 31 | Review and remediate this risk as soon as possible. |
| RISK-015 | INSECURE SERVICE ACCOUNT | HIGH | 8 | Authentication | OPEN | Security Team | 2026-05-21 22:38:39 | 2026-06-25 | ON TRACK | 1 | 34 | Review and remediate this risk as soon as possible. |
| RISK-016 | WEAK ENCRYPTION SETTING | HIGH | 8 | Infrastructure | OPEN | Infrastructure Team | 2026-05-21 22:44:39 | 2026-06-28 | ON TRACK | 1 | 37 | Review and remediate this risk as soon as possible. |
| RISK-019 | EXPOSED BACKUP SHARE | HIGH | 8 | Backup and Recovery | OPEN | Infrastructure Team | 2026-05-21 23:23:52 | 2026-05-26 | ON TRACK | 1 | 4 | Verify backup integrity and perform a test restore. |
| RISK-020 | EXPOSED BACKUP SHARE | HIGH | 8 | Backup and Recovery | OPEN | Infrastructure Team | 2026-05-21 23:31:01 | 2026-05-26 | ON TRACK | 1 | 4 | Verify backup integrity and perform a test restore. |
| RISK-011 | MISSING ENDPOINT MONITORING | HIGH | 7 | Endpoint Security | OPEN | Security Team | 2026-05-21 22:05:00 | 2026-06-20 | ON TRACK | 1 | 29 | Review and remediate this risk as soon as possible. |
| RISK-017 | EXPIRED SSL CERTIFICATE | HIGH | 7 | Infrastructure | OPEN | Infrastructure Team | 2026-05-21 22:55:00 | 2026-05-25 | ON TRACK | 1 | 3 | Renew the certificate and verify TLS configuration. |
| RISK-021 | TEST | MODERATE | 1 | Authentication | CLOSED | SOC Analyst | 2026-05-21 23:47:33 | 2026-05-22 | NOT ACTIVE | 1 | 0 | Review and remediate this risk as soon as possible. |

## Executive Summary

- Critical Risks: 8
- High Risks: 12
- Moderate Risks: 1
- Average Severity: 8.00
- Highest Risk: RISK-003 - NO MFA FOR VPN
- Overdue Risks: 0
- On Track Risks: 20

## SLA Summary

- Critical Risks Overdue: 0
- Risks Due Within 7 Days: 7
- Oldest Open Risk: RISK-001 (7 days open)

## Category Summary

- Authentication: 6
- Network: 4
- Security Awareness: 1
- Endpoint Security: 2
- Infrastructure: 5
- Data Protection: 1
- Backup and Recovery: 2

## Status Summary

- OPEN: 16
- IN PROGRESS: 4
- CLOSED: 1

## Owner Summary

- Security Team: 7
- Network Operations: 3
- Help Desk: 1
- Infrastructure Team: 8
- Compliance Team: 1
- SOC Analyst: 1

## Due Status Summary

- ON TRACK: 20
- NOT ACTIVE: 1
