# Project Name: **Blended Penetration Testing: Web & Wireless Security Lab**

## Project Description

This project demonstrates a comprehensive, blended penetration testing exercise that evaluates both **web application** and **wireless network security** in a controlled lab environment. It simulates a real-world assessment where attackers often exploit vulnerabilities across multiple layers, from web apps to the network perimeter.

On the **web application side**, we used OWASP Juice Shop, a deliberately vulnerable platform, to identify critical security issues. Automated tools like **OWASP ZAP** and **Nikto** were combined with manual testing through **Burp Suite** to detect vulnerabilities such as **SQL Injection (SQLi)**, **Cross-Site Scripting (XSS)**, **Broken Authentication**, **Open Redirects**, and **Insecure Direct Object References (IDOR)**. Each finding was verified, documented with screenshots and proof-of-concept (PoC) evidence, and accompanied by recommendations for remediation.

On the **wireless network side**, the lab environment enabled safe testing of WPA2-protected networks, including **handshake captures**, controlled passphrase tests, and demonstration of hardware-based weaknesses using a **Flipper Zero**. These experiments highlight risks associated with insecure physical-layer protocols and how attackers might pivot between wireless and web targets.

The **deliverables** include:

* A detailed technical penetration testing report
* Annotated PoC evidence (screenshots, JSON/API responses, Burp requests)
* A management-friendly executive summary
* A live demo and presentation showcasing safe exploit proofs and the potential business impact

This project provides practical, hands-on experience with industry-standard penetration testing tools and methodologies, emphasizing ethical and professional conduct. It also illustrates the importance of understanding both application-layer and network-layer security for a complete organizational defense strategy.

