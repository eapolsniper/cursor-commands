# cursor-commands

A collection of cursor commands for application security analysis and dependency risk assessment.

## Available Commands

### `/owaspcheck`
Performs a comprehensive security review of the selected project based on the OWASP Top 10 (2021). Analyzes code for vulnerabilities across all ten categories including broken access control, injection flaws, cryptographic failures, and more. Generates a detailed markdown report with specific, actionable fixes for each identified vulnerability.

**Output:** `CURSOR_OWASP_CHECK.md`

### `/checkdeps`
Conducts a supply chain risk assessment of all project dependencies. Analyzes direct and transitive dependencies for maintenance health, developer concentration, typosquatting risks, and geopolitical concerns. Focuses on qualitative risks beyond standard CVEs and flags high/critical risk packages requiring immediate security review.

**Output:** `DEPENDENCY_RISK_ASSESSMENT.md`
