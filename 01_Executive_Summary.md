EXECUTIVE SUMMARY

This report documents the findings from the web application penetration test performed on the OWASP Juice Shop environment. The purpose of this assessment was to identify common web application vulnerabilities, evaluate the security posture of the platform, and produce actionable recommendations for remediation.

Testing was performed using industry‑standard tools, including OWASP ZAP, Burp Suite, and Nikto, supplemented by manual exploitation to validate each finding. Multiple high‑impact vulnerabilities were discovered, including SQL Injection, Cross‑Site Scripting (XSS), Broken Authentication, Open Redirect, and Security Misconfigurations exposing sensitive backend API endpoints.

The vulnerabilities identified could allow attackers to:

1. Access or manipulate backend data

2. Steal user sessions or inject malicious scripts

3. Bypass authentication controls

4. Redirect users to malicious external sites

5. Retrieve sensitive information without authorization

All findings have been verified with screenshots, proof‑of‑concept steps, and technical evidence.

Overall, the application is highly vulnerable and susceptible to common web attacks due to missing authentication layers, outdated validation, insecure defaults, and lax input handling. Immediate remediation is recommended to strengthen the environment and reduce security risks.
