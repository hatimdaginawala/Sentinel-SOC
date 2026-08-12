# SentinelSOC Project Overview

## 1. Project Information
* **Project Name:** SentinelSOC
* **Project Type:** Security Operations Center (SOC) & Network Defense Platform
* **Technology Stack:** Node.js, Express.js, MongoDB (Mongoose), Vanilla JS, HTML/CSS
* **Target Users:** Security Analysts, SOC Managers, Security Engineers
* **Current Implementation Status:** Implemented

## 2. Problem Statement
Modern networks generate vast amounts of traffic and security logs, making it nearly impossible to identify and prioritize legitimate threats manually. SentinelSOC addresses this by providing an automated pipeline that ingests logs from diverse sources (including Suricata and Zeek), normalizes them, and correlates them against signature-based threat rules to automatically generate prioritized alerts and incidents, drastically reducing the "time-to-detect" (TTD) and "time-to-respond" (TTR).

## 3. Objectives
* **Security monitoring:** Monitor continuous log streams from network assets.
* **Log collection:** Ingest logs via API from multiple heterogeneous log sources.
* **Event normalization:** Standardize raw events (such as Suricata EVE JSON) into a unified logging schema.
* **Detection:** Evaluate normalized logs against predefined Threat Rules (e.g., regex pattern matching, signature rules).
* **Alerting:** Automatically generate Alerts when a Threat Rule is triggered.
* **Incident management:** Correlate multiple Alerts into actionable Incidents and automatically assign them to analysts based on RBAC and threshold settings.
* **Network defense:** Visualize network topologies and implement automated defense tests (e.g., automated blocking or isolation simulation).
* **Security analysis:** Support deep investigation into network evidence attached to incidents.

## 4. Project Scope
SentinelSOC is designed to act as the centralized brain for a network defense architecture.
* **What it does:** Ingests logs, runs them through an automated detection engine, groups alerts into incidents, provides a centralized dashboard, manages assets and sensors, and visualizes network topology.
* **What it does not do:** It does not natively run the packet capturing (it relies on external tools like Suricata and Zeek to forward logs to it).
* **Supported Data Sources:** Suricata, Zeek, standard system logs (Linux/Windows event logs).
* **Supported Network-Defense Functionality:** Network Topology visualization, Asset Management, Security Testing workflows, Threat Rule configuration, incident evidence tracking.
* **Limitations:** Does not have built-in SOAR orchestration to directly interact with external firewalls without custom manual integration.

## 5. Major Features

### SOC Management
* **Authentication:** JWT-based secure authentication mechanism.
* **RBAC:** Detailed permission enforcement per role.
* **Organizations:** Multi-tenant architecture allowing data segregation per organization.
* **Users & Assets:** Manage analysts and monitored network assets.

### Security Monitoring
* **Log Sources:** Configuration for log ingesters.
* **Log Ingestion:** High-throughput API for receiving raw logs.
* **Event Normalization:** Parsing logic specific to Suricata and generic logs.
* **Detection Rules:** Configurable Threat Rules mapped to categories and MITRE tactics.
* **Alerts:** Automated threat notifications.

### Incident Management
* **Incidents:** Aggregated alerts that require investigation.
* **Investigation:** Capturing network evidence natively on the Incident record.
* **Incident Workflow:** Status transitions (New, Investigating, Resolved, Closed).

### Network Defense
* **Network Topology:** Modeling of relationships between assets and zones.
* **Security Sensors:** Tracking Suricata/Zeek deployment per network zone.
* **Security Testing:** Controlled injection of benign network threats (Port Scans, Brute Force) to validate detection pipelines.
* **Network Evidence:** Retaining test events as evidence attached to incidents.
* **Security Controls & Assessment:** Implemented as models linking Threat Rules to actionable mitigating steps and auditing asset vulnerabilities.

### Reporting
* **Dashboards:** Real-time KPI metrics, logs-per-minute, active alerts, Zeek flows, Suricata alerts, Top Attacking IPs.
* **Reports:** 16-section compliant network defense report generation.

## 6. User Roles and Permissions
Based on the RBAC implementation (`Role` and `User` models, and `nav-permissions.js`):
* **Super Admin:**
  * *Purpose:* Full system configuration and multi-tenant oversight.
  * *Permissions:* `manage_orgs`, `manage_users`, `manage_roles`, `manage_assets`, `view_reports`, `manage_alerts`, `manage_incidents`, `view_audit_logs`.
* **SOC Manager:**
  * *Purpose:* Oversee SOC operations within an organization.
  * *Permissions:* `manage_users`, `manage_assets`, `view_reports`, `manage_incidents`, `manage_threat_rules`.
* **Security Analyst (Tier 1 & 2):**
  * *Purpose:* Triage alerts and investigate incidents.
  * *Permissions:* `view_alerts`, `manage_alerts`, `view_incidents`, `manage_incidents`.

## 7. End-to-End Workflow

```text
Security Sensor (Suricata/Zeek)
 ↓
SentinelSOC Ingestion API (/api/v1/logs)
 ↓
Parser (SuricataParser / ZeekParser)
 ↓
Normalization (LogService)
 ↓
Detection Engine (AutomationService - ThreatRule evaluation)
 ↓
Alert Generation
 ↓
Incident Correlation & Creation
 ↓
Investigation (Network Evidence review)
 ↓
Security Controls (Mitigation)
 ↓
Risk Assessment Report
```

## 8. Subject Alignment: Advanced Network Defense and Security Architecture
| College Requirement | SentinelSOC Implementation | Evidence |
| --- | --- | --- |
| Network-security problem | Automated threat identification across vast network traffic | `automationService.js` detection engine |
| Secure network design | Network topology modeling, zoning, DMZ tracking | `NetworkTopology` and `Asset` models |
| Security technology | Integrates natively with Suricata and Zeek | `SuricataParser.js`, `test-network-pipeline.js` |
| Network diagram | Frontend visual representation of nodes/edges | `network-topology.html` |
| System testing | Automated pipeline injection tests for Port Scans and Brute Force | `test-network-pipeline.js`, `SecurityTest` model |
| Result analysis | Capturing network evidence on generated incidents | `Incident` model `networkEvidence` array |
| Security recommendations | 16-section assessment reporting | `reports.html` and `SecurityControl` model |
