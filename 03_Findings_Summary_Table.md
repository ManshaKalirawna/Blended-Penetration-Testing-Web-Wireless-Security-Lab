Findings Summary Table
3.1 Overview

In this section, I summarize the main vulnerabilities I discovered while testing the OWASP Juice Shop web application. Each finding is listed with its impact, risk level, and brief description. Detailed explanations, step-by-step reproduction, and screenshots are included in the next section (Detailed Vulnerability Write-Up).

3.2 Findings Summary Table
| # | Vulnerability                           | Category                  | Risk Level | Brief Description                                                                                         |
| - | --------------------------------------- | ------------------------- | ---------- | --------------------------------------------------------------------------------------------------------- |
| 1 | SQL Injection                           | Injection                 | High       | Input fields in search and login forms were vulnerable to SQL queries, allowing unauthorized data access. |
| 2 | Cross-Site Scripting (XSS)              | Client-Side Injection     | Medium     | Input fields were not properly sanitized, allowing injection of malicious JavaScript.                     |
| 3 | Broken Authentication                   | Authentication & Session  | High       | Default admin credentials were accessible; password strength checks were insufficient.                    |
| 4 | Open Redirect                           | Unvalidated Redirects     | Medium     | Users could be redirected to arbitrary external sites via URL parameters.                                 |
| 5 | Security Misconfiguration / Exposed API | Security Misconfiguration | Medium     | Public API endpoint returned sensitive product data without authentication.                               |
| 6 | Optional / Bonus Findings               | Miscellaneous             | Low        | Minor headers missing, outdated allowlists, or other low-risk issues.                                     |

Note: Risk levels were determined based on impact on confidentiality, integrity, and availability of the web application.

3.3 Notes

1. This table provides a high-level view of vulnerabilities.

2. Screenshots and detailed reproduction steps are in Section 4 — Detailed Vulnerability Write-Up.

3. Risk levels are relative to the Juice Shop instance running in a controlled, lab environment.
