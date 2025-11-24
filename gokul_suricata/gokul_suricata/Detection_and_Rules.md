# 4. Detection & Validation – Suricata (Gokulhesh)

## 4.1 Role & Objective
As the Detection & Reporting Lead, my role was to design and document Suricata-based network detection for the most critical web attacks identified during testing of the OWASP Juice Shop application. The goal was to show how a blue-team defender could monitor for these attacks in real time and validate that our remediation efforts were effective.

## 4.2 Environment Overview
- IDS: Suricata
- Target: OWASP Juice Shop (web application)
- Tools used to trigger alerts:
  - Browser-based manual testing
  - ZAP / Nikto (web scanning)
- Log files reviewed:
  - `/var/log/suricata/fast.log`
  - `/var/log/suricata/eve.json`

## 4.3 Custom Suricata Rules Implemented

The following custom rules were added in `gokul_suricata_rules.rules`:

1. **SQL Injection Detection**
   - **Purpose:** Detect common SQL injection payloads such as `' OR '1'='1`.
   - **Use case:** Monitors incoming HTTP requests to the web server and raises an alert when SQL injection strings are seen in the payload.

2. **Cross-Site Scripting (XSS) Detection**
   - **Purpose:** Detect injection of `<script>` tags in HTTP requests.
   - **Use case:** Helps identify reflected or stored XSS attempts where an attacker injects JavaScript into input fields or query parameters.

3. **Brute Force Login Attempt Detection**
   - **Purpose:** Detect multiple login attempts against the `/rest/user/login` endpoint.
   - **Logic:** If the same source IP hits the login endpoint 5 times within 60 seconds, an alert is generated.
   - **Use case:** Useful for detecting credential stuffing or password guessing attacks.

4. **Unauthorized Admin Panel Access**
   - **Purpose:** Detect attempts to access admin-only paths such as `/admin`.
   - **Use case:** Helps catch enumeration and unauthorized browsing of sensitive administrative interfaces.

> All four rules are stored in: `gokul_suricata/gokul_suricata_rules.rules`.

## 4.4 Testing Methodology

For each rule, the following approach will be used:

- **SQL Injection Rule**
  - Manually browse to vulnerable parameters in Juice Shop and append payloads such as:
    - `?id=1' OR '1'='1`
  - Confirm that Suricata generates an alert in `fast.log`.

- **XSS Rule**
  - Inject payloads such as:
    - `<script>alert(1)</script>`
  - into search boxes or input fields.
  - Verify that an XSS alert is logged.

- **Brute Force Login Rule**
  - Perform repeated login attempts to `/rest/user/login` using invalid credentials.
  - Ensure at least 5 attempts are made within 60 seconds.
  - Confirm that the threshold rule triggers.

- **Admin Access Rule**
  - Attempt to access `/admin` or similar admin-only endpoints.
  - Validate that Suricata raises an alert whenever these URIs are requested.

## 4.5 Evidence & Screenshots (To Be Added)

The following evidence will be added after live testing:

- Screenshots of Suricata alerts from a terminal or dashboard.
- Snippets from `fast.log` and/or `eve.json` showing each rule firing.
- Short explanation for each screenshot linking it to the corresponding attack.

## 4.6 Value to the Project

These Suricata rules demonstrate how:
- The **offensive findings** from web testing can be translated into **defensive monitoring**.
- The organization can continuously watch for:
  - SQL injection attempts,
  - XSS payloads,
  - Brute-force login behavior,
  - Unauthorized admin access.
- This closes the loop between penetration testing and blue-team detection, which is a key goal of blended web + wireless security assessments.
