# System Architecture Diagram

This diagram shows the core architecture of the AI Operations Risk Platform, including the Flask web application, SQLite database, dashboard layer, reporting exports, audit logging, and AI recommendation engine.

```mermaid
flowchart TD
    User[User / Analyst] --> Browser[Web Browser]

    Browser --> Flask[Flask Web Application]

    Flask --> Routes[Application Routes]
    Routes --> Dashboard[Executive Dashboard]
    Routes --> CRUD[Risk CRUD Workflows]
    Routes --> Reports[CSV and Markdown Exports]
    Routes --> Audit[Audit Log Page]

    Flask --> DB[(SQLite Database)]

    DB --> Risks[Risks Table]
    DB --> Summaries[Executive Summaries Table]
    DB --> AuditLogs[Audit Logs Table]

    Flask --> AIEngine[AI Engine]

    AIEngine --> Gemini[Gemini API]
    AIEngine --> OpenAI[OpenAI API]
    AIEngine --> Fallback[Rule-Based Fallback]

    AIEngine --> Recommendations[AI Recommendations]
    AIEngine --> ExecutiveSummaries[AI Executive Summaries]

    Recommendations --> DB
    ExecutiveSummaries --> DB

    DB --> Dashboard
    DB --> Reports
    DB --> Audit

    Dashboard --> Charts[Chart.js Visualizations]
    Dashboard --> KPIs[Executive KPIs]
    Dashboard --> RecentActivity[Recent Activity Timeline]