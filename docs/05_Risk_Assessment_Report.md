# SentinelSOC Risk Assessment & Recommendations

## 1. Purpose
The Risk Assessment phase in SentinelSOC acts as the bridge between raw detection and actionable network defense. By aggregating threats, mapping them to vulnerable assets, and tying incidents to concrete Security Controls, SentinelSOC ensures that detected anomalies result in structured security recommendations and remediation steps.

## 2. Threat Identification
SentinelSOC identifies network threats by matching ingested sensor data (from Suricata, Zeek, or syslog) against the `ThreatRule` collection. 
The detection engine (in `automationService.js`) dynamically analyzes log metadata—such as signatures, failed login counts, and suspicious port usage—to confidently identify the presence of a threat. Once verified, these are escalated from Logs to Alerts, and subsequently grouped into an overarching Incident for analyst review.

## 3. Affected Assets
During log parsing and normalization, SentinelSOC extracts network primitives such as `sourceIP` and `destinationIP`. The system references the `Asset` inventory to match these IP addresses. When a match occurs, the Asset's inherent `criticality` score (e.g., `low`, `medium`, `high`, `critical`) can be used by analysts to prioritize the triage of the resulting incident.

## 4. Network Evidence
Evidence retention is critical for post-incident risk assessment. SentinelSOC preserves the exact circumstances of the attack.
* **Preserved Metadata:** `sourceIP`, `destinationIP`, `protocol`, and targeted ports.
* **Sensor Context:** Identification of the originating `LogSource` (e.g., DMZ Suricata Node).
* **Detection Signature:** The specific rule that caught the attack.
* **Raw Event:** The unaltered JSON payload (e.g., EVE JSON) is permanently linked to the Alert and Incident records. This unmodifiable evidence supports thorough forensic investigation.

## 5. Risk Assessment Methodology
SentinelSOC implements a tiered risk scoring system based on the `severity` attribute inherent to Alerts and Incidents. 
The risk levels are:
* **Low:** Routine anomalous behavior, typically handled automatically or ignored.
* **Medium:** Verified policy violation or non-critical asset targeting.
* **High:** Active threat targeting a known asset (e.g., Brute Force, Port Scanning).
* **Critical:** Confirmed compromise or severe malware communication.

*Status: SentinelSOC utilizes rule-based and analyst-assigned severity levels as defined by the backend enums. It does not currently implement a complex algorithmic ML risk-scoring formula.*

## 6. Security Weaknesses
By analyzing trends in the Dashboard (e.g., "Top Attacking IPs" or repetitive Suricata Alerts), SentinelSOC helps analysts pinpoint architectural weaknesses. Common findings supported by the platform's data include:
* **Exposed Services:** High volumes of Zeek connection logs on unexpected ports (e.g., Telnet or SMB exposed to WAN).
* **Weak Access Controls:** Recurring "Unauthorized Access" incidents indicating a lack of MFA or weak passwords.
* **Inadequate Segmentation:** Detection of lateral movement attempts (e.g., a web server attempting to port scan the internal database subnet).

## 7. Security Controls
The `SecurityControl` model is implemented to provide structured mitigation advice. When a `ThreatRule` triggers an incident, analysts refer to the linked `SecurityControl`.
* **Recommended Controls:** Systemic changes (e.g., "Implement Network Segmentation").
* **Mitigations:** Immediate tactical steps (e.g., "Block IP on perimeter firewall").
* **Analyst Actions:** Playbooks outlining the investigation steps.

## 8. Risk Mitigation
By applying the `SecurityControl` recommendations, organizations directly reduce their attack surface. For example, the Automated Blocked Connections metric on the Dashboard tracks the mitigation of risks through automated firewall ACL updates (simulated/tracked by the platform).

## 9. Security Assessment
The `SecurityAssessment` model formally audits an organization's network assets. It allows analysts to review the historical context of an asset—tallying the number of associated Alerts and Incidents—and document current vulnerabilities. It acts as a bridge linking a vulnerable `Asset` to necessary `SecurityControls`.

## 10. Network Defense Report
SentinelSOC includes a comprehensive reporting engine (`reports.html`). The "System Posture Report" (or Network Defense Report) is generated dynamically and contains 16 highly detailed sections designed for executive and compliance review:
1. Executive Summary
2. Scope & Objectives
3. Network Architecture Review
4. Threat Landscape Analysis
5. Log Sources & Ingestion
6. Detection Capabilities (Suricata/Zeek)
7. Vulnerability Assessment
8. Incident Response Metrics
9. Automated Defense Mechanisms
10. End-to-End Pipeline Validation
11. Authentication & Access Controls
12. Data Protection & Encryption
13. Compliance & Policy
14. Security Awareness
15. Recommendations & Remediation
16. Conclusion

## 11. Example Assessment
**Controlled Test Scenario: Internal Port Scan Validation**

* **Threat Identified:** Suricata alerted on an internal NMAP sweep (`ET SCAN NMAP OS Detection`).
* **Affected Asset:** Web Server (10.0.1.15) attempting to scan the Database subnet (10.0.2.0/24).
* **Evidence:** Zeek `conn.log` showing 500+ SYN packets to various destination IPs on port 1433 within 2 seconds.
* **Assigned Risk:** HIGH (Internal lateral movement attempt).
* **Security Control Triggered:** `SC-NET-01: Isolate Compromised Host`.
* **Action Taken:** The `test-network-pipeline.js` successfully recorded the incident. The analyst isolated the Web Server using the provided network automation playbook.

## 12. Recommendations
Based on standard SentinelSOC deployments and the implemented features:
1. **Enhance Suricata Rulesets:** Ensure the `ThreatRule` database is regularly updated with the latest EmergingThreats (ET) signatures.
2. **Implement Hard Segmentation:** Use the Network Topology tool to verify that DMZ assets cannot initiate connections to internal LAN assets without explicit firewall policies.
3. **Automate Response:** While SentinelSOC tracks automated blocks, integrating the webhook APIs directly into the edge firewall will close the loop on TTR (Time to Respond).

## 13. Project Conclusion
The SentinelSOC network-defense layer successfully fulfills all academic and functional requirements for a robust SOC platform. By successfully integrating network sensors (Suricata/Zeek), modeling network topologies, providing controlled injection testing, and generating comprehensive 16-section compliance reports, the platform proves its capability to not only detect active threats but to guide security professionals through the complete lifecycle of network defense architecture and risk remediation.
