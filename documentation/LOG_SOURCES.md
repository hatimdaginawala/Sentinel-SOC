# SentinelSOC Log Ingestion Documentation

## Overview

Log ingestion is the foundational capability of SentinelSOC. This document details exactly how logs enter the system, from source configuration through normalization and storage.

---

## Supported Log Sources

SentinelSOC supports ingestion from the following source types:

| Source Type | Description | Key Events |
|-------------|-------------|------------|
| **Windows** | Windows Event Logs | Security, System, Application events (Event IDs: 4624, 4625, 4740, 4720, 4723, 4725, 4726, 4732, 4733, 4767, 4771, 4776, 1000, 1001, 1026) |
| **Linux** | Linux System Logs | SSH login, SSH failed login, sudo execution, service events, kernel events |
| **Apache** | Apache HTTP Server Logs | Access logs, error logs, attack detection (SQL injection, XSS, command injection) |
| **Nginx** | Nginx HTTP Server/Proxy Logs | Access logs, reverse proxy errors, rate limiting, health checks |
| **Suricata** | Suricata IDS/IPS Alerts | Malware communication, SQL injection, XSS, port scanning, DDoS, privilege escalation |
| **Snort** | Snort IDS Alerts | Port scans, DDoS, suspicious traffic, malware, SQL injection, XSS, buffer overflow |
| **pfSense** | pfSense Firewall Logs | Connection allowed/blocked/rejected, NAT, port forwarding, VPN connections |
| **Custom** | Custom Application Logs | User-defined events with flexible schema |

---

## Log Source Registration

Before ingesting logs, a log source must be registered in SentinelSOC.

### Step 1: Create a Log Source

**Endpoint:** `POST /api/v1/log-sources`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "organization": "6a68446a894f7943cb4bb926",
  "asset": "6a6848afc15e297a26a27165",
  "sourceName": "Windows-Server-01",
  "sourceType": "Windows",
  "hostname": "win-srv-01.acme.com",
  "ipAddress": "192.168.1.50",
  "operatingSystem": "Windows Server 2022",
  "protocol": "REST",
  "description": "Windows domain controller and file server",
  "status": "Online",
  "configuration": {
    "logLevel": "info",
    "batchSize": 100,
    "flushInterval": 60,
    "enabled": true
  }
}
```

### Step 2: Response

**Success Response (201 Created):**
```json
{
  "success": true,
  "message": "Log source created successfully",
  "data": {
    "_id": "6a6848b0c15e297a26a2716f",
    "organization": {
      "_id": "6a68446a894f7943cb4bb926",
      "name": "Acme Corporation",
      "code": "ACME"
    },
    "asset": {
      "_id": "6a6848afc15e297a26a27165",
      "name": "ACME-DB-Server-01",
      "hostname": "db-srv-01.acme.com"
    },
    "sourceName": "Windows-Server-01",
    "sourceType": "Windows",
    "hostname": "win-srv-01.acme.com",
    "ipAddress": "192.168.1.50",
    "status": "Online",
    "protocol": "REST",
    "authenticationToken": "2f1ef8ee761d37ad889c66b39ac8f1acdedd605b5c529abd8f42f81b7a75fa3b",
    "createdAt": "2026-07-29T17:20:51.713Z",
    "updatedAt": "2026-07-29T17:20:51.713Z"
  }
}
```

**Important:** The `authenticationToken` is automatically generated and must be used for all subsequent log ingestion requests.

---

## Authentication

### Authentication Mechanism

Log ingestion uses a **source-based authentication model**, not JWT authentication.

1. **Source ID**: The unique identifier of the log source (`_id` from creation response)
2. **Authentication Token**: The token generated during log source creation

This authentication is separate from user authentication and is designed for machine-to-machine communication.

### Authentication Headers

The ingestion endpoint does not use `Authorization` headers. Instead, credentials are included in the request body:

```json
{
  "sourceId": "6a6848b0c15e297a26a2716f",
  "authToken": "2f1ef8ee761d37ad889c66b39ac8f1acdedd605b5c529abd8f42f81b7a75fa3b",
  "log": { ... }
}
```

### Validation Flow

1. **Source Exists**: Validate that `sourceId` corresponds to an existing log source
2. **Token Valid**: Validate that `authToken` matches the stored token for that source
3. **Source Active**: Verify that the source is `Online` and `configuration.enabled` is `true`
4. **Heartbeat Updated**: On successful validation, the source's `lastHeartbeat` timestamp is updated

---

## Ingestion Endpoint

### Endpoint Details

| Property | Value |
|----------|-------|
| **Method** | POST |
| **URL** | `/api/v1/logs/ingest` |
| **Authentication** | Source-based (no JWT required) |
| **Content-Type** | `application/json` |
| **Rate Limiting** | Standard API rate limiting applies |

### Example Request

```bash
curl -X POST http://localhost:3000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "sourceId": "6a6848b0c15e297a26a2716f",
    "authToken": "2f1ef8ee761d37ad889c66b39ac8f1acdedd605b5c529abd8f42f81b7a75fa3b",
    "log": {
      "eventType": "Failed Login",
      "eventCategory": "authentication",
      "severity": "high",
      "message": "Failed login attempt for user Administrator",
      "sourceIP": "192.168.1.100",
      "username": "Administrator",
      "eventTime": "2026-07-29T17:20:51.726Z"
    }
  }'
```

### Example Response

**Success (201 Created):**
```json
{
  "success": true,
  "message": "Log ingested successfully",
  "data": {
    "_id": "6a6848b0c15e297a26a2716f",
    "organization": "6a68446a894f7943cb4bb926",
    "asset": "6a6848afc15e297a26a27165",
    "logSource": "6a6848b0c15e297a26a2716f",
    "sourceType": "Windows",
    "eventCategory": "authentication",
    "eventType": "Failed Login",
    "severity": "high",
    "message": "Failed login attempt for user Administrator",
    "sourceIP": "192.168.1.100",
    "username": "Administrator",
    "eventTime": "2026-07-29T17:20:51.726Z",
    "ingestionTime": "2026-07-29T17:21:00.000Z",
    "status": "processed"
  }
}
```

---

## Request Format

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `sourceId` | string | Valid MongoDB ObjectId of the log source |
| `authToken` | string | Authentication token from log source creation |
| `log` | object | The log payload (see below for required log fields) |

### Required Log Fields

| Field | Type | Description |
|-------|------|-------------|
| `eventType` | string | The type of event (e.g., "Failed Login", "SQL Injection") |
| `eventCategory` | string | Category: `authentication`, `network`, `system`, `application`, `database`, `web`, `malware`, `policy`, `access`, `error` |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `message` | string | Human-readable description of the event |
| `eventTime` | string | ISO 8601 timestamp of when the event occurred |

### Optional Log Fields

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | Source hostname |
| `ipAddress` | string | Source IP address |
| `username` | string | User associated with the event |
| `sourceIP` | string | Originating IP address |
| `destinationIP` | string | Destination IP address |
| `destinationPort` | number | Destination port number |
| `protocol` | string | Network protocol (TCP, UDP, ICMP) |
| `processName` | string | Process name generating the log |
| `tags` | array | Array of string tags |
| `rawLog` | object | Original raw log payload (preserved for audit) |
| `normalizedData` | object | Additional normalized fields |

---

## Validation

### Request Validation

SentinelSOC validates all incoming log requests using `express-validator`:

```javascript
router.post('/logs/ingest',
  [
    body('sourceId').isMongoId().withMessage('Invalid log source ID'),
    body('authToken').isLength({ min: 1 }).withMessage('Authentication token is required'),
    body('log').isObject().withMessage('Log data must be an object'),
    body('log.eventType').isString().notEmpty().withMessage('Event type is required'),
    body('log.eventCategory').isIn([
      'authentication', 'network', 'system', 'application', 'database',
      'web', 'malware', 'policy', 'access', 'error'
    ]).withMessage('Invalid event category'),
    body('log.severity').isIn(['critical', 'high', 'medium', 'low', 'info'])
      .withMessage('Invalid severity'),
    body('log.message').isString().notEmpty().withMessage('Message is required'),
    body('log.eventTime').isISO8601().withMessage('Invalid event time format')
  ],
  validateRequest,
  sanitizeRequest,
  LogController.ingestLog
);
```

### Validation Errors

**400 Bad Request:**
```json
{
  "success": false,
  "message": "Validation failed",
  "errorCode": "VALIDATION_ERROR",
  "errors": [
    {
      "field": "log.eventCategory",
      "message": "Invalid event category",
      "value": "invalid_category"
    }
  ],
  "timestamp": "2026-07-29T17:21:00.000Z"
}
```

---

## Normalization

### Normalization Process

1. **Parse Raw Log**: Extract fields from the incoming log payload
2. **Extract Key Fields**: Identify `eventType`, `eventCategory`, `severity`, `message`, `timestamp`
3. **Apply Source-Specific Normalization**: Different handlers for Windows, Linux, Apache, Nginx, Suricata, Snort, pfSense
4. **Standardize Format**: Convert to the unified Log schema
5. **Preserve Raw Data**: Store original log in `rawLog` field

### Source-Specific Normalization

#### Windows Normalization

| Event ID | Normalized Event Type | Severity |
|----------|----------------------|----------|
| 4624 | Successful Login | low |
| 4625 | Failed Login | high |
| 4634 | Logoff | info |
| 4647 | User Initiated Logoff | info |
| 4740 | Account Locked | critical |
| 4720 | User Created | low |
| 4722 | User Enabled | low |
| 4723 | Password Changed | info |
| 4724 | Password Reset | info |
| 4725 | User Disabled | medium |
| 4726 | User Deleted | high |
| 4732 | Member Added | low |
| 4733 | Member Removed | low |
| 4767 | User Unlocked | info |
| 4771 | Kerberos Pre-Authentication Failed | high |
| 4776 | Credential Validation | high |
| 1000 | Application Error | medium |
| 1001 | Application Hang | medium |
| 1026 | .NET Runtime Error | medium |

#### Linux Normalization

| Event Type | Normalized Event Type | Category | Severity |
|-----------|----------------------|----------|----------|
| sshd (success) | SSH Login | authentication | info |
| sshd (failed) | SSH Failed Login | authentication | high |
| sudo_session | sudo Execution | access | low |
| sudo_command | sudo Execution | access | low |
| system_boot | System Boot | system | info |
| system_shutdown | System Shutdown | system | info |
| kernel_panic | Kernel Panic | system | critical |
| service_start | Service Started | system | info |
| service_stop | Service Stopped | system | info |
| service_fail | Service Failed | system | high |

#### Apache Normalization

| Status Code | Normalized Event Type | Severity |
|-------------|----------------------|----------|
| 200-299 | Successful Request | info |
| 301-308 | Redirect | info |
| 400 | Bad Request | low |
| 401 | Unauthorized | medium |
| 403 | Access Denied | high |
| 404 | 404 Not Found | medium |
| 405 | Method Not Allowed | medium |
| 429 | Too Many Requests | medium |
| 500-505 | Server Error | high |
| SQL Injection Pattern | SQL Injection Attempt | critical |
| XSS Pattern | XSS Attempt | critical |
| Command Injection Pattern | Command Injection Attempt | critical |
| Path Traversal Pattern | Directory Traversal | high |

#### Nginx Normalization

| Status Code | Normalized Event Type | Severity |
|-------------|----------------------|----------|
| 200-299 | Successful Request | info |
| 301-308 | Redirect | info |
| 400-409 | Client Error | medium |
| 401 | Unauthorized | medium |
| 403 | Access Denied | high |
| 404 | 404 Not Found | medium |
| 429 | Rate Limited | medium |
| 500-505 | Server Error | high |
| 502 | Reverse Proxy Error | critical |
| 503 | Service Unavailable | critical |
| 504 | Gateway Timeout | critical |

#### Suricata Normalization

| Signature | Normalized Event Type | Category | Severity |
|-----------|----------------------|----------|----------|
| SQL Injection | SQL Injection Attempt | web | critical |
| XSS | XSS Attack | web | critical |
| Command Injection | Command Injection Attempt | web | critical |
| Malware Communication | Malware Communication | malware | critical |
| Port Scan | Port Scan Detected | network | high |
| DDoS | DDoS Attack | network | critical |
| Privilege Escalation | Privilege Escalation Attempt | system | high |
| Shellcode | Shellcode Detection | malware | critical |
| DNS Tunneling | DNS Tunneling Detected | network | high |

#### Snort Normalization

| Rule SID | Normalized Event Type | Category | Severity |
|----------|----------------------|----------|----------|
| 1000001 | Port Scan Detected | network | high |
| 1000002 | DDoS Attack | network | critical |
| 1000003 | Suspicious Network Traffic | network | medium |
| 1000004 | Malware Communication | malware | critical |
| 1000005 | SQL Injection Attempt | web | critical |
| 1000006 | XSS Attack | web | high |
| 1000007 | Buffer Overflow Attempt | system | critical |
| 1000008 | DNS Amplification Attack | network | high |
| 1000009 | SNMP Attack Detected | system | medium |
| 1000010 | SSH Brute Force Attack | authentication | high |

#### pfSense Normalization

| Action | Normalized Event Type | Severity |
|--------|----------------------|----------|
| pass | Connection Allowed | low |
| block | Connection Blocked | medium |
| reject | Connection Rejected | high |
| (NAT) pass | NAT Connection | info |
| (Port Forward) pass | Port Forward | info |
| (Invalid traffic) block | Invalid Traffic | medium |

---

## Storage

### Log Schema

```javascript
{
  organization: ObjectId,          // Organization ID
  asset: ObjectId,                 // Asset ID
  logSource: ObjectId,             // Log Source ID
  sourceType: String,              // Windows, Linux, Apache, etc.
  hostname: String,                // Source hostname
  ipAddress: String,               // Source IP address
  eventCategory: String,           // authentication, network, system, etc.
  eventType: String,               // Failed Login, SQL Injection, etc.
  severity: String,                // critical, high, medium, low, info
  username: String,                // User associated with event
  processName: String,             // Process name
  sourceIP: String,                // Originating IP
  destinationIP: String,           // Destination IP
  destinationPort: Number,         // Destination port
  protocol: String,                // TCP, UDP, ICMP
  message: String,                 // Human-readable message
  rawLog: Mixed,                   // Original raw log
  normalizedData: Mixed,           // Source-specific normalized fields
  eventTime: Date,                 // Event timestamp
  ingestionTime: Date,             // Ingestion timestamp
  status: String,                  // processed, failed, pending
  processingErrors: [String],      // Any processing errors
  tags: [String]                   // Auto-generated tags
}
```

### TTL Index

Logs are automatically deleted after 90 days using MongoDB TTL:

```javascript
logSchema.index({ eventTime: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 });
```

---

## Error Handling

### Error Types

| Error Type | HTTP Status | Error Code | Description |
|------------|-------------|------------|-------------|
| Missing Fields | 400 | VALIDATION_ERROR | Required fields missing |
| Invalid Fields | 400 | VALIDATION_ERROR | Field validation failed |
| Source Not Found | 404 | LOG_SOURCE_NOT_FOUND | Source ID does not exist |
| Invalid Token | 401 | INVALID_TOKEN | Authentication token mismatch |
| Source Inactive | 403 | LOG_SOURCE_INACTIVE | Source is offline or disabled |

### Error Response Format

```json
{
  "success": false,
  "message": "Invalid authentication token",
  "errorCode": "INVALID_TOKEN",
  "timestamp": "2026-07-29T17:21:00.000Z",
  "path": "/api/v1/logs/ingest",
  "stack": "Error: Invalid authentication token\n    at LogService.ingestLog (services/logService.js:30:15)"
}
```

---

## Duplicate Handling

### Deduplication Strategy

SentinelSOC does not automatically deduplicate logs at the ingestion layer. However:

1. **Alert Deduplication**: The alert engine deduplicates alerts within a configurable time window (default: 5 minutes)
2. **Threat Rule Cooldown**: Threat rules have a cooldown period to prevent alert flooding
3. **Log Source Heartbeat**: Prevents duplicate source registrations

### Duplicate Detection

To detect duplicates, use:

1. **Log Source ID + Timestamp + Event Type**: Query combination for duplicate detection
2. **Alert Grouping**: Alerts from the same source IP and threat type are grouped

---

## Log Source Status

### Status Values

| Status | Description |
|--------|-------------|
| **Online** | Source is active and accepting logs |
| **Offline** | Source is inactive |
| **Pending** | Source is created but not yet activated |
| **Error** | Source is in an error state |

### Heartbeat Mechanism

1. Every successful log ingestion updates `lastHeartbeat`
2. A cron job (or manual check) identifies stale heartbeats
3. Sources with no heartbeat for 5+ minutes are marked as `Offline`

### Heartbeat Check

```bash
# Manual heartbeat check
curl -X PATCH http://localhost:3000/api/v1/log-sources/:id/heartbeat \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Simulator → SentinelSOC Flow

### Complete End-to-End Flow

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                         SIMULATOR → SENTINELSOC FLOW                               │
├──────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────────────┐    │
│  │                        1. SIMULATOR GENERATES LOG                           │    │
│  │                                                                             │    │
│  │  - windowsSimulator.js     → Windows Security/System/Application events     │    │
│  │  - linuxSimulator.js       → SSH, sudo, kernel, service events              │    │
│  │  - apacheSimulator.js      → HTTP access, SQL injection, XSS, errors       │    │
│  │  - nginxSimulator.js       → HTTP access, proxy errors, abuse patterns      │    │
│  │  - suricataSimulator.js    → IDS alerts: SQLi, XSS, malware, DDoS          │    │
│  │  - snortSimulator.js       → IDS alerts: port scan, DDoS, malware          │    │
│  │  - firewallSimulator.js    → Firewall events: pass, block, reject, NAT     │    │
│  └─────────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                                  │
│                                    ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐    │
│  │                    2. SIMULATOR BUILDS PAYLOAD                             │    │
│  │                                                                             │    │
│  │  {                                                                         │    │
│  │    "sourceId": "6a6848b0c15e297a26a2716f",                                 │    │
│  │    "authToken": "2f1ef8ee761d37ad889c66b39ac8f1ac...",                    │    │
│  │    "log": {                                                                │    │
│  │      "eventType": "Failed Login",                                          │    │
│  │      "eventCategory": "authentication",                                    │    │
│  │      "severity": "high",                                                   │    │
│  │      "message": "Failed login for user admin from 192.168.1.100",         │    │
│  │      "sourceIP": "192.168.1.100",                                          │    │
│  │      "username": "admin",                                                  │    │
│  │      "eventTime": "2026-07-29T17:20:51.726Z"                              │    │
│  │    }                                                                       │    │
│  │  }                                                                         │    │
│  └─────────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                                  │
│                                    ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐    │
│  │                    3. HTTP POST TO /api/v1/logs/ingest                    │    │
│  │                                                                             │    │
│  │  - No JWT required                                                         │    │
│  │  - Source-based authentication                                             │    │
│  │  - JSON payload                                                           │    │
│  └─────────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                                  │
│                                    ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐    │
│  │                    4. SENTINELSOC INGESTION PIPELINE                       │    │
│  │                                                                             │    │
│  │  ┌────────────────────────────────────────────────────────────────────┐   │    │
│  │  │  a. Source Validation                                               │   │    │
│  │  │     - Validate sourceId exists                                       │   │    │
│  │  │     - Validate authToken matches                                    │   │    │
│  │  │     - Check status (Online/Offline)                                │   │    │
│  │  │     - Check configuration.enabled                                   │   │    │
│  │  └────────────────────────────────────────────────────────────────────┘   │    │
│  │                                   │                                         │    │
│  │                                   ▼                                         │    │
│  │  ┌────────────────────────────────────────────────────────────────────┐   │    │
│  │  │  b. Heartbeat Update                                                │   │    │
│  │  │     - Update lastHeartbeat to current timestamp                    │   │    │
│  │  └────────────────────────────────────────────────────────────────────┘   │    │
│  │                                   │                                         │    │
│  │                                   ▼                                         │    │
│  │  ┌────────────────────────────────────────────────────────────────────┐   │    │
│  │  │  c. Log Normalization                                              │   │    │
│  │  │     - Parse raw log                                                │   │    │
│  │  │     - Extract fields                                               │   │    │
│  │  │     - Apply source-specific normalization                         │   │    │
│  │  │     - Map to standard schema                                       │   │    │
│  │  └────────────────────────────────────────────────────────────────────┘   │    │
│  │                                   │                                         │    │
│  │                                   ▼                                         │    │
│  │  ┌────────────────────────────────────────────────────────────────────┐   │    │
│  │  │  d. Storage                                                        │   │    │
│  │  │     - Save to MongoDB (Logs collection)                           │   │    │
│  │  │     - Status: "processed"                                          │   │    │
│  │  └────────────────────────────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                                  │
│                                    ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐    │
│  │                    5. AUTOMATION PIPELINE                                   │    │
│  │                                                                             │    │
│  │  ┌────────────────────────────────────────────────────────────────────┐   │    │
│  │  │  a. Threat Rule Evaluation                                          │   │    │
│  │  │     - Fetch enabled rules                                           │   │    │
│  │  │     - Evaluate rule conditions                                     │   │    │
│  │  │     - Check cooldown                                               │   │    │
│  │  └────────────────────────────────────────────────────────────────────┘   │    │
│  │                                   │                                         │    │
│  │                                   ▼                                         │    │
│  │  ┌────────────────────────────────────────────────────────────────────┐   │    │
│  │  │  b. Alert Generation                                               │   │    │
│  │  │     - Create alert from matched rule                              │   │    │
│  │  │     - Set severity, risk score, confidence                        │   │    │
│  │  │     - Save to Alerts collection                                   │   │    │
│  │  └────────────────────────────────────────────────────────────────────┘   │    │
│  │                                   │                                         │    │
│  │                                   ▼                                         │    │
│  │  ┌────────────────────────────────────────────────────────────────────┐   │    │
│  │  │  c. Incident Creation (if multiple alerts)                        │   │    │
│  │  │     - Group alerts by source IP and threat type                  │   │    │
│  │  │     - Create incident if threshold met (3+ alerts)               │   │    │
│  │  │     - Auto-assign to analyst                                      │   │    │
│  │  └────────────────────────────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                                  │
│                                    ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐    │
│  │                    6. RESPONSE TO SIMULATOR                                 │    │
│  │                                                                             │    │
│  │  HTTP 201 Created                                                          │    │
│  │  {                                                                         │    │
│  │    "success": true,                                                        │    │
│  │    "message": "Log ingested successfully",                                 │    │
│  │    "data": { ... normalized log ... }                                      │    │
│  │  }                                                                         │    │
│  └─────────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                                  │
│                                    ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐    │
│  │                    7. SIMULATOR CONTINUES GENERATING LOGS                    │    │
│  │                                                                             │    │
│  │  - Interval: 2-5 seconds                                                   │    │
│  │  - Random variations in fields                                             │    │
│  │  - Patterns generated (brute force, lockout, scanning)                    │    │
│  │  - Random organization selection (multi-tenant)                           │    │
│  └─────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### Simulator Configuration

Each simulator requires:

```env
# simulators/.env
API_URL=http://localhost:3000/api/v1/logs/ingest

WINDOWS_SOURCE_ID=6a6848b0c15e297a26a2716f
WINDOWS_AUTH_TOKEN=2f1ef8ee761d37ad889c66b39ac8f1acdedd605b5c529abd8f42f81b7a75fa3b

LINUX_SOURCE_ID=6a6848b0c15e297a26a2717a
LINUX_AUTH_TOKEN=8d547e86bedc86ea3be59e5a4ba1458e1514570e11c8a41395e3ae17ace9731b
```

### Simulator Code Example

```javascript
// windowsSimulator.js (simplified)
const CONFIG = {
  API_URL: 'http://localhost:3000/api/v1/logs/ingest',
  SOURCE_ID: process.env.WINDOWS_SOURCE_ID,
  AUTH_TOKEN: process.env.WINDOWS_AUTH_TOKEN,
  INTERVAL_MIN: 2000,
  INTERVAL_MAX: 5000
};

async function generateEvent() {
  const eventTypes = [
    { eventId: '4624', name: 'Successful Login', severity: 'low' },
    { eventId: '4625', name: 'Failed Login', severity: 'high' },
    { eventId: '4740', name: 'Account Locked', severity: 'critical' }
  ];
  
  const selected = eventTypes[Math.floor(Math.random() * eventTypes.length)];
  
  return {
    eventType: selected.name,
    eventCategory: 'authentication',
    severity: selected.severity,
    message: `${selected.name} for user ${Math.random().toString(36).substring(7)}`,
    sourceIP: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
    username: Math.random().toString(36).substring(7),
    eventTime: new Date().toISOString()
  };
}

async function sendLog() {
  const log = await generateEvent();
  const payload = {
    sourceId: CONFIG.SOURCE_ID,
    authToken: CONFIG.AUTH_TOKEN,
    log: log
  };
  
  await axios.post(CONFIG.API_URL, payload);
}

// Main loop
setInterval(sendLog, Math.random() * (CONFIG.INTERVAL_MAX - CONFIG.INTERVAL_MIN) + CONFIG.INTERVAL_MIN);
```

---

## Troubleshooting

### Common Issues

| Issue | Likely Cause | Solution |
|-------|--------------|----------|
| 401 Invalid Token | Token expired or incorrect | Regenerate token via PATCH /log-sources/:id/regenerate-token |
| 404 Source Not Found | Source ID incorrect | Verify source ID from MongoDB or creation response |
| 403 Source Inactive | Source status is Offline or disabled | Update source status to Online or enable configuration |
| 500 Validation Error | Missing required fields | Ensure all required fields are present in log payload |
| Slow Ingestion | High volume or network issues | Increase batch size or use asynchronous ingestion |

### Debugging

1. **Enable Debug Logging**:
   ```javascript
   // Set LOG_LEVEL=debug in .env
   LOG_LEVEL=debug
   ```

2. **Check Log Source Status**:
   ```javascript
   db.logsources.findOne({ _id: ObjectId("SOURCE_ID") })
   ```

3. **View Recent Logs**:
   ```javascript
   db.logs.find().sort({ ingestionTime: -1 }).limit(10).pretty()
   ```

4. **Test Ingestion with curl**:
   ```bash
   curl -X POST http://localhost:3000/api/v1/logs/ingest \
     -H "Content-Type: application/json" \
     -d '{
       "sourceId": "YOUR_SOURCE_ID",
       "authToken": "YOUR_AUTH_TOKEN",
       "log": {
         "eventType": "Test Event",
         "eventCategory": "system",
         "severity": "info",
         "message": "Test log for troubleshooting",
         "eventTime": "2026-07-29T17:30:00.000Z"
       }
     }'
   ```