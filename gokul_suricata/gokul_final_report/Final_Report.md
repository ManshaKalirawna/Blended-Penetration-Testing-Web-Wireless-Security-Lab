# Blended Penetration Testing – Web & Wireless Security Lab  
### Final Report (Compiled by: Gokulhesh – Detection & Reporting Lead)

---

## 1. Executive Summary
EXECUTIVE SUMMARY

This report documents the findings from the web application penetration test performed on the OWASP Juice Shop environment. The purpose of this assessment was to identify common web application vulnerabilities, evaluate the security posture of the platform, and produce actionable recommendations for remediation.

Testing was performed using industry‑standard tools, including OWASP ZAP, Burp Suite, and Nikto, supplemented by manual exploitation to validate each finding. Multiple high‑impact vulnerabilities were discovered, including SQL Injection, Cross‑Site Scripting (XSS), Broken Authentication, Open Redirect, and Security Misconfigurations exposing sensitive backend API endpoints.

The vulnerabilities identified could allow attackers to:

Access or manipulate backend data

Steal user sessions or inject malicious scripts

Bypass authentication controls

Redirect users to malicious external sites

Retrieve sensitive information without authorization

All findings have been verified with screenshots, proof‑of‑concept steps, and technical evidence.

Overall, the application is highly vulnerable and susceptible to common web attacks due to missing authentication layers, outdated validation, insecure defaults, and lax input handling. Immediate remediation is recommended to strengthen the environment and reduce security risks.

## 2. Scope & Methodology
(To be merged from group content)

---

## 3. Web Application Testing Results (Rahool)
[Placeholder — pending Rahool’s submission]

---

## 4. Wireless & Hardware Testing (Mansha)
[Placeholder — pending Mansha’s submission]

---

## 5. Detection & Suricata Rule Implementation (Gokulhesh)

### 5.1 Overview
This section describes the custom detection rules created to monitor critical web attacks inside the Juice Shop application.

### 5.2 Summary of Implemented Rules
- SQL Injection detection  
- XSS detection  
- Brute-force login detection  
- Unauthorized admin page access detection  

### 5.3 Evidence Screenshots
(To be added after testing the rules)

---

## 6. Validation (Before & After Remediation)

### 6.1 Pre-Fix Scan Results
(To be completed after Rahool submits vulnerabilities)

### 6.2 Post-Remediation Scan Results
(To be completed after Nippun submits remediation steps)

---

## 7. Risk & Remediation (Nippun)
[Placeholder — waiting for Nippun’s content]

---

## 8. Conclusion & Recommendations
(To be written after all parts are merged)

---

## 9. Appendix
- Suricata rules  
- Logs  
- Screenshots  
- Tool versions  
