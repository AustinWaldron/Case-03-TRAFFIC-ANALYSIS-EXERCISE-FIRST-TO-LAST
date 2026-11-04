# 🚀 Case 03: Traffic Analysis Exercise – First to Last

> **Analyst Note:** For this investigation, I intentionally pivoted away from relying solely on standard Wireshark display filters (like `ip.addr` or `dhcp`) to deepen my understanding of network forensics. By leveraging Wireshark's built-in statistical menus and protocol breakdown features, I established a top-down triage workflow—spotting volume anomalies first, extracting threat indicators second, and mapping Active Directory identity structures third.

---

## 📌 Executive Incident Summary (IRT Escalation Report)

| Incident Question | IRT Findings | Verification Method / Protocol |
| :--- | :--- | :--- |
| **Infected Host IP** | `[internal-IP-A]` | Isolated high-volume outbound TCP chatter via `Statistics ➔ Conversations` |
| **Victim MAC Address** | `[MAC-A]` | Parsed Layer 2 Ethernet II frame details (Dell NIC) |
| **Workstation Hostname** | `HOST-A` | Captured via `Protocol Hierarchy ➔ NBNS` broadcast registrations |
| **User Account Name** | `user-A` | Inspected Kerberos `AS-REQ` client name (`cname ➔ cname-string`) |
| **User Full Name** | `[name redacted]` | Extracted from Domain Controller Active Directory `SAMR QueryDisplayInfo` response |

---

## 🚨 Threat Indicators (IOCs)

* **Malicious C2 Domain:** `www.21207628[.]shop`
* **Exfiltration Path Pattern:** `/hut9/?2kn1=...`
* **Malware Classification:** FormBook / XLoader (Characterized by encrypted GET query string parameters designed to evade standard firewalls)

---

## 🔬 Triage Methodology & Analytical Workflow

### 1. Identifying Anomaly Traffic via Volume Analysis
* **Feature Used:** `Statistics ➔ Conversations`
* **Methodology:** Sorted endpoints and conversation streams by total packet and byte count.
* **Finding:** Flagged `[internal-IP-A]` generating an unusually high volume of outbound traffic compared to normal baseline network activity.

### 2. Threat & Web Exfiltration Discovery
* **Feature Used:** `Statistics ➔ HTTP ➔ Requests`
* **Methodology:** Analyzed top-level URI paths and host requests across all HTTP sessions.
* **Finding:** Identified suspicious outbound GET requests targeting `www.21207628[.]shop`. The structure confirmed a known infostealer C2 channel attempting to bypass perimeter security.

### 3. Workstation Resolution via Broadcast Protocols
* **Feature Used:** `Statistics ➔ Protocol Hierarchy` ➔ NetBIOS Name Service (NBNS)
* **Methodology:** Used Protocol Hierarchy to locate local broadcast protocols where client endpoints regularly announce their presence.
* **Finding:** Pivoted to NBNS to resolve the physical hostname (`HOST-A`) directly from packet broadcasts, bypassing the need for initial DHCP handshake packets.

### 4. User Identity Extraction via Kerberos & SAMR
* **Kerberos Inspection (`AS-REQ`):** Filtered Kerberos authentication requests sent to the Domain Controller (`[DC-IP-A]`). Expanding the Client Name (`cname ➔ cname-string`) revealed the account handle: **`user-A`**.
* **SAMR Query Inspection:** Inspected Security Account Manager Remote (`samr`) responses coming back from the Domain Controller. Parsing the `QueryDisplayInfo` payload confirmed the user's full display name: **`[name redacted]`**.

---

## 🛠️ Tools & Technologies Used
* **Wireshark** (Network Protocol Analyzer)
  * Statistical Conversations & Endpoint Analysis
  * HTTP Request Stream Extraction
  * Protocol Hierarchy Inspection
  * Frame Detail Layer Parsing (Layer 2 through Layer 7)
* **Active Directory Protocols:** Kerberos, SAMR, NetBIOS (NBNS)

---

## 🛡️ Recommended Remediation Steps
1. **Isolate the host:** remove `HOST-A` (`[internal-IP-A]`) from the network.
2. **Contain the account:** revoke sessions and reset the password for `user-A`. Infostealers like FormBook/XLoader collect saved credentials, so reset any other credentials used on the host.
3. **Block the C2:** block `www.21207628[.]shop` at DNS and the proxy.
4. **Hunt:** search for the same domain and URI pattern across other endpoints.
