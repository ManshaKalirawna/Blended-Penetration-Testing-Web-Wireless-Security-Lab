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
This part of the project focuses on evaluating the security posture of the OWASP Juice Shop application. My role in the group was specifically the web application testing portion, so all the work in this section reflects the tests I personally carried out using Kali Linux and Windows as needed.

2.1 Scope of Testing

The scope included the following:

Testing the publicly accessible features of the Juice Shop instance running on my Windows machine

Using Kali Linux tools (ZAP, Nikto, Burp Suite Community) to perform Black‑Box style testing

Identifying at least five real vulnerabilities with screenshots and proof-of-concept steps

Documenting everything in a clean and repeatable format for my teammates to later merge into the final group report

The goal was not to “break” the system as much as possible, but to simulate how a normal penetration tester approaches a new web application and gathers evidence.

Out‑of‑scope items included:

Attacks against the underlying Windows host OS

Denial‑of‑service tests

Database-level exploitation beyond what the Juice Shop environment intentionally exposes

Anything impacting other machines on the network (only my local isolated setup was used)

2.2 Testing Approach & Methodology

I followed a fairly standard workflow similar to what you’d see in a junior penetration testing engagement. Here's the high‑level process I used:

Recon & Application Mapping
I first accessed the Juice Shop through the browser to understand how the app behaves from a regular user’s perspective. I clicked through menus, forms, login areas, and product pages to get a feel for how the app is structured. This helped me identify any parts of the app worth targeting with tools later, like the login form, search box, product catalogue, and API endpoints.

Automated Scanning
Once the basic layout was clear, I used the following tools:

OWASP ZAP (Kali) – Passive and active scanning to detect common issues (XSS, IDOR, security misconfigurations).

Nikto – To quickly check for server misconfigurations or outdated components.

Burp Suite Community – Mainly for intercepting requests, modifying parameters, and understanding how the backend responds.

The automated scans helped highlight a list of potential vulnerabilities that I later confirmed manually.

Manual Testing & Exploitation
Using the results from the tools as a starting point, I manually attempted:

Broken Authentication tests

Parameter tampering

SQL injection attempts

Unvalidated redirect tests

API endpoint manipulation

Business logic flaws

Reviewing JSON responses and hidden API paths

The Juice Shop challenges were extremely helpful for confirming that my exploitation attempts actually worked. Each challenge pop‑up essentially validated my proof‑of‑concept attempts.

Documentation & Evidence Capture
Throughout the process, I took screenshots of:

Tool scans

Raw requests/responses

Successful exploit results

Challenge completion pop‑ups

Any sensitive information I managed to access

All screenshots are included inside each vulnerability write‑up and stored neatly in the /evidence/ folder for organized version control.

2.3 Tools Used

Kali Linux

OWASP ZAP

Burp Suite Community Edition

Nikto

Curl (for direct requests)

Windows 10 (hosting Juice Shop instance)

2.4 Deliverables From My Part

As the student responsible for the Web Application portion, my final deliverables include:

Web Application Vulnerability Report (.md + screenshots)

5+ Confirmed vulnerabilities with PoC evidence

ZAP and Nikto scan outputs

Clean GitHub repository for the group to add to later

## 3. Web Application Testing Results (Rahool)
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

## 4. Wireless & Hardware Testing (Mansha)
4.1 SQL Injection (High Severity) Overview

During testing, I found that several user-input fields—particularly the search bar and the login form—did not properly validate or sanitize user-supplied data. This allowed me to inject SQL queries into the backend database.

Testing Steps

Navigated to the login page.
2 Entered a basic SQL payload into the username field:

' OR '1'='1

Submitted the login form without providing a valid password.

The application responded with a successful authentication message.

Impact

Bypassing authentication without valid credentials

Possible exposure of user account data

Risk of full database compromise
<img width="1285" height="763" alt="image" src="https://github.com/user-attachments/assets/e888c519-7a30-4a73-870d-1909ceee70ed" />
<img width="1279" height="769" alt="image" src="https://github.com/user-attachments/assets/02a91263-7d4a-4df0-8489-eb23f20cccbe" />
4.2 Broken Authentication – Weak Default Password (High Severity) Overview

The administrator account still used its default credentials. I could log in as the admin using these default passwords.

Testing Steps

Navigated to the admin login page.

Entered default username/password combinations.

The application displayed a pop-up confirming successful admin login.

Impact

Full system compromise possible

Administrative access exposes all sensitive data

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
