# Operational Workflow Diagram

This diagram shows the operational lifecycle of risks within the AI Operations Risk Platform.

```mermaid
flowchart TD
    Analyst[Analyst / Operator] --> Create[Create New Risk]

    Create --> SQLite[(SQLite Database)]

    SQLite --> AIEngine[AI Recommendation Engine]

    AIEngine --> Recommendation[Generate Recommendation]
    AIEngine --> Summary[Generate AI Rationale]

    Recommendation --> Dashboard[Executive Dashboard]
    Summary --> Dashboard

    Dashboard --> AnalystReview[Analyst Reviews Risk]

    AnalystReview --> Update[Update Risk Status]
    AnalystReview --> Export[Generate Reports]
    AnalystReview --> SummaryGen[Generate Executive Summary]

    Update --> SQLite
    Export --> Reports[CSV / Markdown Reports]
    SummaryGen --> ExecutiveSummary[AI Executive Summary]

    ExecutiveSummary --> Dashboard

    SQLite --> AuditLog[Audit Logging Engine]

    AuditLog --> ActivityTimeline[Recent Activity Timeline]
    AuditLog --> FullAudit[Full Audit Log Page]

    Dashboard --> Charts[Chart.js Analytics]
    Dashboard --> KPIs[Executive KPI Metrics]
    Dashboard --> SLA[SLA Tracking]