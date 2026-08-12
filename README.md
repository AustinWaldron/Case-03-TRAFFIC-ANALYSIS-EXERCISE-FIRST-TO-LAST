# 🚀 Case 03: Traffic Analysis Exercise – First to Last

> **Analyst Note:** For this investigation, I intentionally pivoted away from relying solely on standard Wireshark display filters (like `ip.addr` or `dhcp`) to deepen my understanding of network forensics. By leveraging Wireshark's built-in statistical menus and protocol breakdown features, I established a top-down triage workflow—spotting volume anomalies first, extracting threat indicators second, and mapping Active Directory identity structures third.

---

## 📌 Executive Incident Summary (IRT Escalation Report)

| Incident Question | IRT Findings | Verification Method / Protocol |
| :--- | :--- | :--- |
| **Infected Host IP** | `172.16.8.49` | Isolated high-volume outbound TCP chatter via `Statistics ➔ Conversations` |
| **Victim MAC Address** | `00:c0:4f:21:95:a6` | Parsed Layer 2 Ethernet II frame details (Dell NIC) |
| **Workstation Hostname** | `DESKTOP-5NLV63K` | Captured via `Protocol Hierarchy ➔ NBNS` broadcast registrations |
| **User Account Name** | `rvance` | Inspected Kerberos `AS-REQ` client name (`cname ➔ cname-string`) |
| **User Full Name** | `Raymond Vance` | Extracted from Domain Controller Active Directory `SAMR QueryDisplayInfo` response |

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
* **Finding:** Flagged `172.16.8.49` generating an unusually high volume of outbound traffic compared to normal baseline network activity.

### 2. Threat & Web Exfiltration Discovery
* **Feature Used:** `Statistics ➔ HTTP ➔ Requests`
* **Methodology:** Analyzed top-level URI paths and host requests across all HTTP sessions.
* **Finding:** Identified suspicious outbound GET requests targeting `www.21207628[.]shop`. The structure confirmed a known infostealer C2 channel attempting to bypass perimeter security.

### 3. Workstation Resolution via Broadcast Protocols
* **Feature Used:** `Statistics ➔ Protocol Hierarchy` ➔ NetBIOS Name Service (NBNS)
* **Methodology:** Used Protocol Hierarchy to locate local broadcast protocols where client endpoints regularly announce their presence.
* **Finding:** Pivoted to NBNS to resolve the physical hostname (`DESKTOP-5NLV63K`) directly from packet broadcasts, bypassing the need for initial DHCP handshake packets.

### 4. User Identity Extraction via Kerberos & SAMR
* **Kerberos Inspection (`AS-REQ`):** Filtered Kerberos authentication requests sent to the Domain Controller (`172.16.8.8`). Expanding the Client Name (`cname ➔ cname-string`) revealed the account handle: **`rvance`**.
* **SAMR Query Inspection:** Inspected Security Account Manager Remote (`samr`) responses coming back from the Domain Controller. Parsing the `QueryDisplayInfo` payload confirmed the user's full display name: **`Raymond Vance`**.

---

## 🛠️ Tools & Technologies Used
* **Wireshark** (Network Protocol Analyzer)
  * Statistical Conversations & Endpoint Analysis
  * HTTP Request Stream Extraction
  * Protocol Hierarchy Inspection
  * Frame Detail Layer Parsing (Layer 2 through Layer 7)
* **Active Directory Protocols:** Kerberos, SAMR, NetBIOS (NBNS)
