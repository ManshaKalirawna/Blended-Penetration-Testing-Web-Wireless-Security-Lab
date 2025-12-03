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


2.5 Wireless and Hardware Testing Scope

In addition to the web application testing described above, I also carried out the wireless and hardware security portion of the blended penetration test. The goal of this part of the project was to evaluate how weak Wi Fi configurations and basic hardware level attacks could be exploited in a realistic, but controlled, lab environment.

The wireless testing was intentionally limited to my own devices and a small home lab setup. I did not test any third party networks, production systems, or building infrastructure. Instead, I created a dedicated test Wi Fi network on my personal phone and used it to demonstrate:

- How easily a WPA2 PSK handshake can be captured and tested offline when a weak password is used.  
- How a rogue access point (evil twin) could confuse users by copying a legitimate SSID.  
- How a Flipper Zero can clone simple RFID/NFC tags or replay infrared (IR) remote signals against lab approved devices.

The scope for the wireless and hardware component therefore included:

- One dedicated lab SSID (`CIS145-LAB`) hosted on my own phone.  
- One client laptop (Lenovo Legion) connected as a normal user device.  
- One capture laptop (Microsoft Surface running Kali Linux) used only for monitoring and analysis.  
- Optional lab friendly RFID/NFC tags and an IR controlled device for Flipper Zero demonstrations.

Out of scope items for this part of the project were:

- Any Wi Fi testing against neighbours, campus networks, or production access points.  
- Any attempts to crack real user passwords beyond the intentionally weak lab passphrase.  
- Any interaction with real building access control systems, car keys, or alarm systems.

2.6 Wireless and Hardware Testing Methodology

My wireless and hardware methodology followed the same basic pattern as a small scale penetration test: set up a controlled environment, capture evidence, and then try to break weak configurations in a safe way.

Wireless Test Environment (Home Lab Setup)

To create the wireless lab, I configured a mobile hotspot on a personal OnePlus 7 Pro smartphone. The hotspot was set to use WPA2 Personal security on the 2.4 GHz band and was given a dedicated SSID, `CIS145-LAB`, that was used only for this project. For demonstration purposes, I deliberately chose a short numeric password (`123456789`) to model a weak but realistic configuration.

Two laptops participated in this setup:

- The Lenovo Legion laptop connected to `CIS145-LAB` as a normal Wi Fi client and behaved like an everyday user device.  
- The Microsoft Surface laptop ran Kali Linux and acted as the dedicated capture machine. Its wireless interface was put into monitor mode and never joined the SSID as a client.

This separation allowed me to generate traffic from the Legion while passively capturing and analyzing frames from the Surface.

WPA2 Handshake Capture and Password Strength Assessment

The first wireless objective was to capture a WPA2 4 way handshake for `CIS145-LAB` and test how easily the weak pre shared key could be recovered.

On the Surface Kali machine, I switched the Wi Fi interface into monitor mode and used a wireless discovery tool to locate the `CIS145-LAB` network. From this scan I recorded the BSSID (MAC address of the OnePlus hotspot) and the channel it was using. I then started a packet capture on that specific channel and saved all frames into a file named `lab_wifi_handshake.pcap`.

While the capture was running, I disconnected the Lenovo Legion from `CIS145-LAB` and then reconnected it using the same password (`123456789`). This forced a new WPA2 4 way handshake between the hotspot and the client. When I later opened the PCAP in Wireshark and filtered for `eapol` frames, I could clearly see the four handshake messages between the hotspot MAC address and the Legion’s Wi Fi MAC address, confirming that a complete handshake had been captured.

For the password strength test, I created a very small wordlist file (`weak_words.txt`) containing only weak and commonly used passwords, including simple numeric patterns like `123456789`. Using a standard WPA key recovery tool on the Surface, I tested the captured handshake against this limited wordlist in an offline manner. Because the lab passphrase was intentionally weak and included in the list, the tool was able to recover `123456789` almost immediately. This result demonstrates how little effort is required to crack a short numeric WPA2 password once an attacker has captured a handshake.

Rogue Access Point (Evil Twin) Simulation

The second wireless objective was to simulate a rogue access point (evil twin) and observe how a user device might behave when presented with a fake network that looks legitimate.

To do this, I used one of the laptops to create a software based access point that copied the SSID `CIS145-LAB` but ran on a different channel and separate internal network. This rogue access point did not provide real internet access or connect to any other systems; it only existed to mimic the name of the legitimate hotspot.

With the rogue AP active, I scanned for networks from a client device and observed how both the real and fake `CIS145-LAB` entries appeared in the Wi Fi list. I monitored whether the client tried to auto connect to the stronger signal and captured association attempts in a separate PCAP. This experiment shows how easy it is for an attacker to create a Wi Fi network that visually looks correct to end users simply by reusing the same SSID.

Flipper Zero Hardware Experiments

Finally, I used a Flipper Zero device to demonstrate basic hardware level attacks in the lab:

- RFID/NFC cloning: I scanned a test RFID or NFC tag that I was allowed to use, saved its profile on the Flipper, and then used the emulation feature to act as a cloned tag in the same test scenario.  
- IR signal capture and replay: I captured infrared remote commands from a lab friendly device (such as a TV or monitor), stored them on the Flipper, and replayed them to confirm that the device responded as if it had received the original remote signal.

All of these tests were performed only on tags and devices that I personally owned or that were explicitly safe to test. No building access cards, car remotes, or production equipment were involved. The goal was to show that many basic RFID/NFC and IR systems lack encryption or authentication, making them easy to copy or replay if an attacker gets temporary access to a legitimate tag or remote.

Deliverables From Wireless and Hardware Testing

From the wireless and hardware side, my deliverables include:

- A documented home lab setup for the `CIS145-LAB` SSID and device roles.  
- A WPA2 handshake capture file (`lab_wifi_handshake.pcap`) with confirmed EAPOL frames.  
- An offline password test showing that the weak passphrase `123456789` was easily recovered from a small wordlist.  
- Notes and packet captures from the rogue access point simulation.  
- Screenshots and notes from the Flipper Zero RFID/NFC and IR replay demonstrations.  
- A written explanation of the risks and how stronger passwords, better Wi Fi configurations, and more secure access control technologies can mitigate these issues.
