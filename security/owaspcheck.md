# owaspcheck


**CONTEXT:**
You are an expert Application Security Engineer. A developer wants you to review the selected project and is requesting a security review focused on severe vulnerabilities. Provide brief context on if these vulnerabilities are likely exploitable, or if they are security enhancements.

**INSTRUCTIONS:**
1.  **Analyze the selected project** for potential vulnerabilities related to the current OWASP Top 10.
2.  **For each potential vulnerability found**, identify the specific OWASP category (e.g., A03:2021 - Injection).
3.  **Provide a concise explanation** of the vulnerability as it applies to the code, and a **SPECIFIC, actionable, and secure code fix or mitigation** for that vulnerability.
4.  **Use trusted external resources (OWASP Cheat Sheets) to reinforce secure practices** in your suggested fixes.

**OWASP Focus Areas (Checklist to be covered):**
* **A01: Broken Access Control:** Are there missing or flawed authorization checks?
* **A02: Cryptographic Failures:** Is sensitive data (passwords, PII, tokens) being handled securely (encryption, hashing, secure storage, correct TLS usage)?
* **A03: Injection:** Are user inputs validated/sanitized before being used in database queries, OS commands, or dynamic content (SQLi, XSS, etc.)?
* **A04: Insecure Design:** Are there design flaws (e.g., lack of proper threat modeling, unsafe workflows)?
* **A05: Security Misconfiguration:** Are default credentials, unnecessary features, or insecure server settings exposed in the code/config?
* **A06: Vulnerable and Outdated Components:** Are any visible dependencies (libraries, frameworks) potentially old or known to be vulnerable?
* **A07: Identification and Authentication Failures:** Are session management, password policy, or multi-factor authentication poorly implemented?
* **A08: Software and Data Integrity Failures:** Are software updates, critical data, or deserialization handled without verifying integrity?
* **A09: Security Logging and Monitoring Failures:** Is there sufficient logging of security-critical events (login attempts, access failures) without leaking sensitive data?
* **A10: Server-Side Request Forgery (SSRF):** If the code handles remote resource fetching based on user input, is the input validated to prevent unintended external/internal calls?

**OUTPUT FORMAT:**
Create output in a markdown format. Make the output easy to read for humans.

In addition to the detailed output, create a summary table with very brief severity, OWASP focus area, and very brief summary.

Save output to CURSOR_OWASP_CHECK.md Overwrite the file if it is already present.

Check if the report file is listed in gitignore. If not, check if the repository is public or private. If the repository is public, add the CURSOR_OWASP_CHECK.md file to the gitignore so it does not get disclosed. If you can't tell, default to adding the file to gitignore.

