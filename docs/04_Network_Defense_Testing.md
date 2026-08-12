# SentinelSOC Network Defense Testing

## 1. Testing Objectives
The objective of the SentinelSOC network defense testing module is to programmatically and safely validate the complete Security Operations Center (SOC) pipeline. It ensures that critical network threats (e.g., port scans, brute force attempts) are correctly ingested, parsed, detected, and escalated into incidents without requiring live malware deployment in the production environment.

## 2. Test Environment
* **Development Machine:** Local SentinelSOC backend (Node.js/Express)
* **Database:** Local MongoDB instance
* **Network Sensors:** Simulated Suricata and Zeek payloads mapped via the `LogService`.
* **Testing Framework:** Custom Node.js automated pipeline script (`test-network-pipeline.js`).
* **Environment Separation:** Test events are flagged with `isTestEvent: true` to prevent corruption of production threat metrics.

## 3. Network Architecture Under Test

```text
Internet
   ↓
Firewall
   ↓
DMZ / Internal LAN
   ↓
Windows / Linux Assets
   ↓
Network Traffic
   ↓
Suricata / Zeek (Sensors)
   ↓
SentinelSOC Ingestion API
```
* **Suricata:** Functions as the primary Intrusion Detection System (IDS), generating signature-based alerts.
* **Zeek:** Provides extensive connection and protocol logging.
* **SentinelSOC:** Consumes these logs to detect cross-sensor patterns and manage the incident response workflow.

## 4. Test Scenarios

### Test 1: Port Scan Detection
* **Objective:** Validate that a simulated Suricata port scan alert correctly triggers the SentinelSOC detection engine.
* **Input:** A mock Suricata EVE JSON payload indicating a port scan (e.g., NMAP activity).
* **Expected Behavior:** The `SuricataParser` successfully parses the log. The `AutomationService` matches it against the Network Reconnaissance rule.
* **Detection Rule:** `ThreatRule` with category `network` and threatType `port_scan`.
* **Expected Alert:** "Port Scan Alert" (High severity).
* **Expected Incident:** Network Intrusion incident generated based on deduplication thresholds.
* **Network Evidence:** The original mock log retained with a `securityTestId`.
* **Actual Result:** PASS

### Test 2: Brute Force Detection
* **Objective:** Verify identity threat rules by simulating multiple failed authentication logs.
* **Input:** Logs containing `eventType: 'failed login'`.
* **Expected Behavior:** Matched against a brute force threshold rule via regular expression (`$regex: 'brute|failed'`).
* **Detection Rule:** `ThreatRule` with category `authentication`.
* **Expected Alert:** "Brute Force Attack" (High severity).
* **Expected Incident:** Unauthorized Access incident.
* **Network Evidence:** Raw authentication logs retained as evidence.
* **Actual Result:** PASS

### Test 3: Suspicious Network Connection
* **Objective:** Validate that outbound connections to known malicious ports (e.g., 4444 - typically associated with reverse shells/Metasploit) trigger an alert.
* **Input:** Outbound connection log targeting port 4444.
* **Expected Behavior:** Detected by the `malware_communication` rule.
* **Detection Rule:** `ThreatRule` with category `network` matching suspicious outbound traffic.
* **Expected Alert:** "Suspicious Connection" (Medium/High severity).
* **Expected Incident:** Malware Campaign incident.
* **Network Evidence:** Connection details (Source, Destination, Port) retained.
* **Actual Result:** PASS

## 5. Automated Pipeline Test

The script `test-network-pipeline.js` orchestrates the end-to-end testing process programmatically.

**Execution Flow:**
1. **Database Connection:** Connects directly to the MongoDB instance.
2. **Test Setup:** Cleans up previous test states (`deleteMany` for Logs, Alerts, Incidents) and creates the `System User` for automated audit logging. Adjusts `incidentDeduplicationThreshold: 1` to ensure immediate incident creation.
3. **Sensor Creation:** Creates mock `Asset` and `LogSource` entries (e.g., a Suricata sensor).
4. **Controlled Event:** Injects the JSON payload via `logService.normalizeLog()`.
5. **Detection:** Passes the saved Log to `automationService.processLog()`.
6. **Alert/Incident:** The automation service generates the Alert and automatically escalates it to an Incident.
7. **Network Evidence:** The script verifies the existence of the `isTestEvent: true` log.
8. **SecurityTest Result:** Saves the pass/fail state to the `SecurityTest` document.

## 6. Pipeline Verification
During execution, the script prints the exact status of the validation chain:

```text
Log Generated:       PASS
Log Ingested:        PASS
Detection Triggered: PASS
Alert Created:       PASS
Incident Created:    PASS
Evidence Recorded:   PASS
RESULT:              PASS
```

## 7. Suricata Testing
* **EVE JSON Input:** The script provides a payload simulating Suricata's output.
* **Parser:** `SuricataParser.parse()` relies on the `event_type` field. (If `event_type` is missing, it falls back to generic parsing).
* **Normalized Output:** Maps Suricata `alert.severity` to SOC severities (`low`, `medium`, `high`, `critical`) and sets `eventCategory` to `network`.
* **Incident:** Correlates directly to `network_intrusion` incidents.

## 8. Zeek Testing
* **Supported Log Types:** SentinelSOC specifically monitors Zeek `conn.log` and `dns.log`.
* **Parser:** Extracts `id.orig_h` (sourceIP), `id.resp_h` (destinationIP), `id.resp_p` (destinationPort).
* **Detection:** Zeek logs are heavily utilized in the "Suspicious Network Connection" test scenario to identify unauthorized port usage.

## 9. Security Testing Lab
In the frontend UI (`security-testing.html`), tests can be reviewed and executed.
To prevent test logs from interfering with actual analyst metrics or external reporting, SentinelSOC explicitly tags them:
```json
{
  "isTestEvent": true,
  "securityTestId": "ObjectId(...)"
}
```
They are retained permanently because they act as the verifiable **Network Evidence** proving that the pipeline is actively functioning.

## 10. Test Results

| Test | Log | Detection | Alert | Incident | Evidence | Result |
| --- | --- | --- | --- | --- | --- | --- |
| Port Scan Detection | PASS | PASS | PASS | PASS | PASS | PASS |
| Brute Force Simulation | PASS | PASS | PASS | PASS | PASS | PASS |
| Suspicious Connection | PASS | PASS | PASS | PASS | PASS | PASS |

*(Note: These results reflect the actual output of `test-network-pipeline.js` executed on the local deployment).*

## 11. Limitations
* **Simulated Injection:** The test script bypasses the HTTP API (`/api/v1/logs`) and invokes the `LogService` directly. Network-level validation (e.g., firing real NMAP packets at a live Suricata interface) must be done out-of-band.
* **Deduplication Threshold:** To ensure incidents are created during the test, the global deduplication threshold is artificially set to `1`. In production, this threshold is usually higher.
