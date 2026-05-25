# AI Fallback Flow Diagram

This diagram shows how the AI Operations Risk Platform handles AI-generated recommendations and executive summaries using a resilient fallback hierarchy.

```mermaid
flowchart TD
    Request[Risk Analysis Request] --> AIEngine[AI Engine]

    AIEngine --> GeminiCheck{Gemini Available?}

    GeminiCheck -->|Yes| Gemini[Gemini API]
    GeminiCheck -->|No| OpenAICheck{OpenAI Available?}

    Gemini --> GeminiSuccess{Successful Response?}

    GeminiSuccess -->|Yes| GeminiOutput[Return Gemini Recommendation]
    GeminiSuccess -->|No| OpenAICheck

    OpenAICheck -->|Yes| OpenAI[OpenAI API]
    OpenAICheck -->|No| RuleBased[Rule-Based Fallback Engine]

    OpenAI --> OpenAISuccess{Successful Response?}

    OpenAISuccess -->|Yes| OpenAIOutput[Return OpenAI Recommendation]
    OpenAISuccess -->|No| RuleBased

    RuleBased --> LocalRecommendation[Generate Local Recommendation]

    GeminiOutput --> FinalOutput[Store Recommendation in SQLite]
    OpenAIOutput --> FinalOutput
    LocalRecommendation --> FinalOutput

    FinalOutput --> Dashboard[Dashboard Display]
    FinalOutput --> Reports[CSV / Markdown Exports]
    FinalOutput --> AuditLogs[Audit Logging]