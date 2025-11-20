Scope & Methodology

This part of the project focuses on evaluating the security posture of the OWASP Juice Shop application. My role in the group was specifically the web application testing portion, so all the work in this section reflects the tests I personally carried out using Kali Linux and Windows as needed.

2.1 Scope of Testing

The scope included the following:

1. Testing the publicly accessible features of the Juice Shop instance running on my Windows machine

2. Using Kali Linux tools (ZAP, Nikto, Burp Suite Community) to perform Black‑Box style testing

3. Identifying at least five real vulnerabilities with screenshots and proof-of-concept steps

4. Documenting everything in a clean and repeatable format for my teammates to later merge into the final group report

 The goal was not to “break” the system as much as possible, but to simulate how a normal penetration tester approaches a new web application and gathers evidence.
 
 Out‑of‑scope items included:

1. Attacks against the underlying Windows host OS

2. Denial‑of‑service tests

3. Database-level exploitation beyond what the Juice Shop environment intentionally exposes

4. Anything impacting other machines on the network (only my local isolated setup was used)

2.2 Testing Approach & Methodology

I followed a fairly standard workflow similar to what you’d see in a junior penetration testing engagement. Here's the high‑level process I used:

1. Recon & Application Mapping

I first accessed the Juice Shop through the browser to understand how the app behaves from a regular user’s perspective. I clicked through menus, forms, login areas, and product pages to get a feel for how the app is structured.
This helped me identify any parts of the app worth targeting with tools later, like the login form, search box, product catalogue, and API endpoints.

2. Automated Scanning

Once the basic layout was clear, I used the following tools:

OWASP ZAP (Kali) – Passive and active scanning to detect common issues (XSS, IDOR, security misconfigurations).

Nikto – To quickly check for server misconfigurations or outdated components.

Burp Suite Community – Mainly for intercepting requests, modifying parameters, and understanding how the backend responds.

The automated scans helped highlight a list of potential vulnerabilities that I later confirmed manually.

3. Manual Testing & Exploitation

Using the results from the tools as a starting point, I manually attempted:

Broken Authentication tests

Parameter tampering

SQL injection attempts

Unvalidated redirect tests

API endpoint manipulation

Business logic flaws

Reviewing JSON responses and hidden API paths

The Juice Shop challenges were extremely helpful for confirming that my exploitation attempts actually worked. Each challenge pop‑up essentially validated my proof‑of‑concept attempts.

4. Documentation & Evidence Capture

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
