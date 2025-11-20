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

1. OWASP ZAP (Kali) – Passive and active scanning to detect common issues (XSS, IDOR, security misconfigurations).

2. Nikto – To quickly check for server misconfigurations or outdated components.

3. Burp Suite Community – Mainly for intercepting requests, modifying parameters, and understanding how the backend responds.

The automated scans helped highlight a list of potential vulnerabilities that I later confirmed manually.



3. Manual Testing & Exploitation

Using the results from the tools as a starting point, I manually attempted:

1. Broken Authentication tests

2. Parameter tampering

3. SQL injection attempts

4. Unvalidated redirect tests

5. API endpoint manipulation

6. Business logic flaws

7. Reviewing JSON responses and hidden API paths

The Juice Shop challenges were extremely helpful for confirming that my exploitation attempts actually worked. Each challenge pop‑up essentially validated my proof‑of‑concept attempts.



4. Documentation & Evidence Capture

Throughout the process, I took screenshots of:

1. Tool scans

2. Raw requests/responses

3. Successful exploit results

4. Challenge completion pop‑ups

Any sensitive information I managed to access

All screenshots are included inside each vulnerability write‑up and stored neatly in the /evidence/ folder for organized version control.



2.3 Tools Used

1. Kali Linux

2. OWASP ZAP

3. Burp Suite Community Edition

4. Nikto

5. Curl (for direct requests)

6. Windows 10 (hosting Juice Shop instance)



2.4 Deliverables From My Part

As the student responsible for the Web Application portion, my final deliverables include:

1. Web Application Vulnerability Report (.md + screenshots)

2. 5+ Confirmed vulnerabilities with PoC evidence

3. ZAP and Nikto scan outputs

4. Clean GitHub repository for the group to add to later
