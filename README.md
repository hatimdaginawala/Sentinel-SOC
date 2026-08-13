# SentinelSOC

## Enterprise Security Operations Center (SOC) & Security Information and Event Management (SIEM) Platform

[![Node.js](https://img.shields.io/badge/Node.js-18.x-green.svg)](https://nodejs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-6.x-brightgreen.svg)](https://www.mongodb.com/)
[![Express.js](https://img.shields.io/badge/Express.js-4.x-blue.svg)](https://expressjs.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Table of Contents

- [Overview](#overview)
- [Why SentinelSOC](#why-sentinelsoc)
- [How It Works](#how-it-works)
- [Core Modules](#core-modules)
- [Network Defense Modules](#network-defense-modules)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Database Schema](#database-schema)
- [Authentication & Authorization](#authentication--authorization)
- [Log Ingestion Pipeline](#log-ingestion-pipeline)
- [Log Normalization](#log-normalization)
- [Threat Detection & Alerting](#threat-detection--alerting)
- [Incident Management](#incident-management)
- [Network Topology & Visualization](#network-topology--visualization)
- [Security Controls Library](#security-controls-library)
- [Security Assessments](#security-assessments)
- [Security Testing Lab](#security-testing-lab)
- [Simulators](#simulators)
- [API Reference](#api-reference)
- [Security Controls](#security-controls)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

SentinelSOC is a **Security Operations Center (SOC) and Security Information and Event Management (SIEM) platform** built for organizations that need centralized visibility into their security posture. It ingests, normalizes, and analyzes security events from multiple sources—servers, firewalls, IDS/IPS systems, web servers, and applications—then generates alerts, creates incidents, and provides a unified interface for security analysts to investigate and respond to threats.

The platform implements the core workflows of a modern SOC: log collection → normalization → threat detection → alerting → incident response → remediation → continuous monitoring. It is designed to be run locally for demonstration, evaluation, or as a foundation for production security monitoring.

---

## Why SentinelSOC

Security teams face three persistent problems:

1. **Fragmented Visibility** – Security data is spread across dozens of tools and log sources. Analysts waste time switching between consoles to correlate events.

2. **Alert Fatigue** – Many security tools generate too many low-fidelity alerts. Analysts spend more time triaging false positives than investigating genuine threats.

3. **Manual Incident Response** – Without a structured incident management process, investigations lack consistency, and critical details are lost.

4. **Limited Remediation Guidance** – Security teams often struggle to determine the right actions to take when a threat is detected.

5. **No Validation of Detection Pipeline** – Organizations rarely test whether their security monitoring actually works before an attack occurs.

6. **Gap in Security Posture Visibility** – Understanding overall security risk across the organization is difficult without a centralized assessment process.

SentinelSOC solves these problems by providing:
- A **single pane of glass** for security operations
- **Rule-based detection** to filter noise and focus on genuine threats
- A **structured incident lifecycle** from detection through investigation, containment, and resolution
- A **Security Controls Library** with pre-defined remediation actions and mitigations
- A **Security Testing Lab** to validate detection capabilities without real attacks
- **Network Topology** visualization to understand security sensor placement
- **Security Assessments** to evaluate and document organizational security posture

---

## How It Works

SentinelSOC operates on a **comprehensive security operations pipeline**:

### The Security Pipeline

```
Log Sources → Ingestion → Normalization → Detection → Alerts → Incidents → Security Controls → Remediation → Continuous Monitoring
```

### The Network Defense Lifecycle

The platform implements the **full security lifecycle** following the NIST Cybersecurity Framework:

1. **Identify** – Understand your network architecture and assets (Network Topology)
2. **Protect** – Implement security controls and mitigations (Security Controls Library)
3. **Detect** – Monitor for threats and anomalies (Log Ingestion, Detection Engine)
4. **Respond** – Investigate and contain incidents (Incident Management)
5. **Recover** – Restore normal operations and improve posture (Security Assessments)

### Complete End-to-End Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SECURITY DATA FLOW                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. LOG COLLECTION                                                         │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ Windows │ Linux │ Apache │ Nginx │ Suricata │ Zeek │ Firewall │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                      │                                      │
│                                      ▼                                      │
│  2. NETWORK TOPOLOGY VISUALIZATION                                         │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ Internet → Firewall → DMZ → Internal LAN → SentinelSOC         │     │
│     │          Suricata IDS placed in DMZ                            │     │
│     │          Zeek Monitor placed in Internal LAN                   │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                      │                                      │
│                                      ▼                                      │
│  3. LOG INGESTION & NORMALIZATION                                          │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ REST API endpoint → Normalization → Storage                     │     │
│     │ Source validation → Field extraction → Standardized format     │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                      │                                      │
│                                      ▼                                      │
│  4. THREAT DETECTION & ALERTING                                            │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ Detection Engine evaluates logs against Threat Rules           │     │
│     │ Matching rules → Alerts created with severity & risk score     │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                      │                                      │
│                                      ▼                                      │
│  5. INCIDENT MANAGEMENT                                                     │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ Related alerts grouped into Incidents                          │     │
│     │ Investigate → Assign → Resolve → Close                         │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                      │                                      │
│                                      ▼                                      │
│  6. SECURITY TESTING LAB (Validation)                                      │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ Controlled tests → Validate pipeline                           │     │
│     │ Pass/Fail reporting → Evidence recording                       │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                      │                                      │
│                                      ▼                                      │
│  7. SECURITY CONTROLS LIBRARY (Remediation)                                │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ Threat Name → Recommended Controls → Mitigations → Actions     │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                      │                                      │
│                                      ▼                                      │
│  8. SECURITY ASSESSMENTS (Evaluation)                                      │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ Risk Level → Weaknesses → Controls → Final Assessment          │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Modules

| Module | Description |
|--------|-------------|
| **Authentication** | JWT-based authentication with refresh token rotation |
| **Role-Based Access Control (RBAC)** | Granular permissions across five roles: Super Admin, Security Admin, SOC Analyst, Incident Responder, Auditor |
| **User Management** | Full CRUD for users with role assignment and organization scoping |
| **Organization Management** | Multi-organization support with isolated data per organization |
| **Asset Management** | Inventory of security assets (servers, firewalls, databases, web apps) with criticality and risk scoring |
| **Log Source Management** | Configure log sources with type, protocol, status, and authentication tokens |
| **Log Ingestion** | REST API endpoint for receiving logs from any source |
| **Log Normalization** | Automatic parsing and standardization of logs from Windows, Linux, Apache, Nginx, Suricata, Snort, and pfSense |
| **Detection Engine** | JSON-based threat rules with conditions on any log field |
| **Alert Management** | Lifecycle for security alerts: active, investigating, resolved, suppressed |
| **Incident Management** | Full incident lifecycle: new, investigating, in_progress, resolved, closed |
| **IOC Management** | Indicators of Compromise with types: IP, domain, URL, email, file_hash, file_path, registry_key, process, service, user_agent, CVE, campaign, exploit, signature, pattern |
| **Threat Rules** | Custom detection rules with severity, category, threat type, and actions |
| **Dashboard** | Real-time security metrics, charts, and log feeds using Socket.io |
| **Reporting** | Generate security reports (daily, weekly, monthly, executive, incident, risk) |
| **Audit Logging** | Complete audit trail of all user actions and system events |
| **Settings** | System configuration: general, security, notifications, retention, detection, dashboard, logging |

---

## Network Defense Modules

The following modules extend SentinelSOC's capabilities for comprehensive network security operations:

### Network Topology & Visualization

| Feature | Description |
|---------|-------------|
| **Network Visualization** | Interactive network diagram using vis-network library |
| **Node Types** | Internet, Firewall, Router, Server, Workstation, Security Sensor, SentinelSOC |
| **Network Zones** | External, Perimeter, DMZ, Internal LAN, Management |
| **Security Sensors** | Display sensor placement and status on the network map |
| **Asset Linking** | Connect assets to topology nodes for context |
| **Node Details** | Click nodes to view detailed information |
| **Legend & Zones** | Visual legend and zone-based grouping |

### Security Controls Library

| Feature | Description |
|---------|-------------|
| **Threat Remediation** | Pre-defined controls, mitigations, and analyst actions |
| **Priority Levels** | Critical, High, Medium, Low priorities |
| **Status Tracking** | Pending, In Progress, Implemented, Verified, Not Applicable |
| **Compliance Frameworks** | NIST, ISO27001, SOC2, HIPAA, GDPR, PCI-DSS |
| **Versioning** | Track changes to controls over time |
| **Risk Scoring** | Automated risk calculation based on severity and priority |
| **Effectiveness Metrics** | Track control effectiveness and completion |

### Security Assessments

| Feature | Description |
|---------|-------------|
| **Risk Evaluation** | Comprehensive risk assessment with scoring |
| **Weakness Identification** | Document security weaknesses |
| **Control Linking** | Link assessments to security controls |
| **Incident Integration** | Review incidents as part of assessment |
| **Asset Impact** | Identify affected assets |
| **Status Lifecycle** | Draft → In Progress → Review → Final |
| **Review Tracking** | Track who reviewed and when |
| **Next Review Dates** | Schedule follow-up assessments |

### Security Testing Lab

| Feature | Description |
|---------|-------------|
| **Controlled Testing** | Inject benign test events to validate detection |
| **Test Scenarios** | Port Scan, Brute Force, Suspicious Connection, SQL Injection, XSS |
| **Pipeline Validation** | Test each stage: Log Generation → Ingestion → Detection → Alert → Incident → Evidence |
| **Status Tracking** | PENDING, RUNNING, PASS, FAIL |
| **Result Details** | View detailed test results and pipeline status |
| **Real-time Polling** | Automatic status updates during test execution |
| **Evidence Recording** | Verify evidence is properly recorded |

### Security Sensors

| Feature | Description |
|---------|-------------|
| **Sensor Types** | Suricata, Zeek, Firewall, Host Collector, Wazuh, Snort, Custom |
| **Health Monitoring** | Heartbeat tracking and health scoring |
| **Capabilities** | IDS, IPS, Network Monitoring, Host Monitoring, Log Collection, Threat Detection |
| **Event Tracking** | Track events received, forwarded, and alerts generated |
| **Status Management** | Active, Inactive, Error, Pending, Degraded |
| **Asset Linking** | Link sensors to assets for context |
| **Network Zone Assignment** | Place sensors in appropriate network zones |

---

## Technology Stack

### Backend

| Technology | Purpose |
|------------|---------|
| **Node.js** | JavaScript runtime |
| **Express.js** | Web framework |
| **MongoDB** | Document database |
| **Mongoose** | MongoDB ODM |
| **JSON Web Tokens (JWT)** | Stateless authentication |
| **bcrypt** | Password hashing |
| **Helmet** | Security headers |
| **CORS** | Cross-origin resource sharing |
| **Winston** | Application logging |
| **Morgan** | HTTP request logging |
| **Socket.io** | Real-time WebSocket communication |
| **PDFKit** | PDF report generation |
| **ExcelJS** | Excel report generation |
| **node-cron** | Scheduled tasks |

### Frontend

| Technology | Purpose |
|------------|---------|
| **HTML5** | Structure |
| **CSS3** | Styling (dark theme, responsive) |
| **Vanilla JavaScript (ES6+)** | Interactivity |
| **Chart.js** | Dashboard charts |
| **DataTables.js** | Data tables with search and pagination |
| **Socket.io Client** | Real-time updates |
| **SweetAlert2** | Alert dialogs |
| **Font Awesome** | Icons |
| **vis-network** | Network topology visualization |

---

## Architecture

### Layered Architecture

The application follows a strict layered architecture where each layer has a single responsibility:

```
┌─────────────────────────────────────────────┐
│              Frontend (UI)                  │
│         HTML/CSS/JavaScript                │
└─────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────┐
│              REST API Layer                 │
│           Express.js Routes                 │
└─────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────┐
│             Controller Layer                │
│         Request/Response Handling           │
└─────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────┐
│              Service Layer                  │
│           Business Logic                    │
└─────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────┐
│              Model Layer                    │
│           Mongoose Schemas                  │
└─────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────┐
│             Database Layer                  │
│              MongoDB                        │
└─────────────────────────────────────────────┘
```

### Network Defense Module Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   NETWORK DEFENSE MODULES                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────┐    ┌─────────────────────┐                        │
│  │   Network Topology   │    │  Security Sensors   │                        │
│  │  - Visualization     │    │  - Data Collection  │                        │
│  │  - Node Management   │    │  - Health Monitoring│                        │
│  │  - Zone Grouping     │    │  - Event Tracking   │                        │
│  └──────────┬──────────┘    └──────────┬──────────┘                        │
│             │                           │                                   │
│             │      ┌────────────────────┼────────────────────┐              │
│             │      │                    │                    │              │
│             ▼      ▼                    ▼                    ▼              │
│  ┌─────────────────────┐    ┌─────────────────────┐    ┌──────────────────┐│
│  │  Security Testing   │    │   Security Controls │    │   Security       ││
│  │  - Pipeline Testing │    │  - Remediation     │    │   Assessment     ││
│  │  - Validation       │    │  - Mitigations     │    │  - Risk          ││
│  │  - Evidence Tracking│    │  - Compliance      │    │  - Weaknesses    ││
│  └─────────────────────┘    └─────────────────────┘    └──────────────────┘│
│             │                           │                                   │
│             └───────────────────────────┼───────────────────────────────────┘│
│                                         │                                   │
│                                         ▼                                   │
│                               ┌─────────────────────┐                       │
│                               │  Unified SOC View  │                       │
│                               │  - Dashboard       │                       │
│                               │  - Reports         │                       │
│                               │  - Audit Trail     │                       │
│                               └─────────────────────┘                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Principle Layers

- **Routes** – Define API endpoints, apply middleware, and route to controllers
- **Controllers** – Handle request/response, validate input, call services
- **Services** – Implement business logic, coordinate data operations
- **Models** – Define schemas, handle database interactions
- **Middleware** – Authentication, authorization, validation, logging, error handling, rate limiting

---

## Project Structure

```
sentinel-soc/
├── backend/
│   ├── src/
│   │   ├── config/
│   │   │   ├── database.js          # MongoDB connection
│   │   │   ├── logger.js            # Winston logger
│   │   │   └── constants.js         # Application constants
│   │   ├── models/                  # Mongoose schemas
│   │   │   ├── User.js
│   │   │   ├── Role.js
│   │   │   ├── Organization.js
│   │   │   ├── Asset.js
│   │   │   ├── LogSource.js
│   │   │   ├── Log.js
│   │   │   ├── Alert.js
│   │   │   ├── Incident.js
│   │   │   ├── IOC.js
│   │   │   ├── ThreatRule.js
│   │   │   ├── Report.js
│   │   │   ├── AuditLog.js
│   │   │   ├── Settings.js
│   │   │   ├── NetworkTopology.js   # Network visualization
│   │   │   ├── SecurityControl.js   # Remediation library
│   │   │   ├── SecuritySensor.js    # Data collection
│   │   │   ├── SecurityTest.js      # Pipeline validation
│   │   │   └── SecurityAssessment.js # Risk evaluation
│   │   ├── controllers/             # Request handlers
│   │   ├── services/                # Business logic
│   │   ├── routes/                  # API route definitions
│   │   ├── middleware/              # Express middleware
│   │   │   ├── auth.js              # JWT authentication
│   │   │   ├── rbac.js              # Role-based access control
│   │   │   ├── validation.js        # Request validation
│   │   │   ├── errorHandler.js      # Global error handling
│   │   │   └── rateLimiter.js       # Rate limiting
│   │   ├── utils/                   # Utility functions
│   │   │   ├── responseHandler.js   # Standardized responses
│   │   │   ├── passwordUtils.js     # Password utilities
│   │   │   └── tokenUtils.js        # JWT utilities
│   │   ├── seed.js                  # Database seeding
│   │   └── app.js                   # Application entry
│   ├── package.json
│   ├── .env                         # Environment variables
│   └── .gitignore
├── frontend/
│   ├── assets/
│   │   ├── css/
│   │   │   ├── layout.css
│   │   │   ├── components.css
│   │   │   ├── dashboard.css
│   │   │   ├── forms.css
│   │   │   ├── tables.css
│   │   │   ├── responsive.css
│   │   │   └── themes.css
│   │   ├── js/
│   │   │   ├── api.js               # API client
│   │   │   ├── auth.js              # Authentication
│   │   │   ├── dashboard.js         # Dashboard logic
│   │   │   ├── charts.js            # Chart.js integration
│   │   │   ├── utils.js
│   │   │   └── socket.js            # Socket.io client
│   │   └── images/
│   └── pages/
│       ├── login.html
│       ├── dashboard.html
│       ├── assets.html
│       ├── logs.html
│       ├── alerts.html
│       ├── incidents.html
│       ├── reports.html
│       ├── users.html
│       ├── settings.html
│       ├── profile.html
│       ├── network-topology.html    # Network visualization
│       ├── security-testing.html    # Pipeline validation
│       └── security-assessment.html # Risk evaluation
├── simulators/                      # Log simulators
│   ├── config.js
│   ├── windowsSimulator.js
│   ├── linuxSimulator.js
│   ├── apacheSimulator.js
│   ├── nginxSimulator.js
│   ├── suricataSimulator.js
│   ├── snortSimulator.js
│   ├── firewallSimulator.js
│   ├── setup-simulators.js
│   ├── package.json
│   └── .env
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── nginx.conf
└── docs/
    └── api-documentation.md
```

---

## Installation

### Prerequisites

- Node.js 18.x or higher
- MongoDB 6.x or higher (running locally or accessible via connection string)

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-username/sentinel-soc.git
cd sentinel-soc
```

### Step 2: Install Backend Dependencies

```bash
cd backend
npm install
```

### Step 3: Install Simulator Dependencies

```bash
cd simulators
npm install
```

### Step 4: Configure Environment Variables

Create a `.env` file in the `backend` directory:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database Configuration
MONGODB_URI=mongodb://127.0.0.1:27017/sentinel_soc

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRY=7d
JWT_REFRESH_SECRET=your-refresh-secret-key-change-this-in-production
JWT_REFRESH_EXPIRY=30d

# Security Configuration
BCRYPT_ROUNDS=12
CORS_ORIGIN=http://localhost:3000
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100

# API Configuration
API_PREFIX=/api/v1
```

### Step 5: Seed the Database

```bash
cd backend
node src/seed.js
```

The seed script creates:
- **3 Organizations**: Acme Corporation, Global Finance Inc, Healthcare Systems
- **7 Users**: Super Admin, Security Admins, SOC Analysts, Incident Responders, Auditor
- **10+ Assets**: Servers, databases, firewalls, web applications
- **9 Log Sources**: Windows, Linux, Apache, Nginx, Suricata, Snort, pfSense
- **6 Threat Rules**: Brute Force, SQL Injection, Malware Communication, Port Scan, etc.
- **6 Alerts**: Sample security alerts
- **3 Incidents**: Ransomware, Phishing, Data Breach
- **6 IOCs**: IPs, domains, file hashes, email addresses, URLs
- **4 Audit Logs**: Sample audit trail entries
- **Security Controls**: Pre-defined controls and mitigations
- **Security Sensors**: Sample sensor configurations
- **Network Topology**: Default network architecture

### Step 6: Start the Server

```bash
# Development mode with auto-reload
npm run dev

# Production mode
npm start
```

### Step 7: Start Log Simulators

```bash
cd simulators

# Run all simulators
npm run all

# Or run individually
npm run windows
npm run linux
npm run apache
npm run nginx
npm run suricata
npm run snort
npm run firewall
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3000 |
| `NODE_ENV` | Environment mode | development |
| `MONGODB_URI` | MongoDB connection string | mongodb://127.0.0.1:27017/sentinel_soc |
| `JWT_SECRET` | JWT secret key | Required |
| `JWT_EXPIRY` | JWT token expiry | 7d |
| `JWT_REFRESH_SECRET` | Refresh token secret | Required |
| `JWT_REFRESH_EXPIRY` | Refresh token expiry | 30d |
| `BCRYPT_ROUNDS` | Bcrypt salt rounds | 12 |
| `CORS_ORIGIN` | CORS allowed origin | http://localhost:3000 |
| `RATE_LIMIT_WINDOW` | Rate limit window (minutes) | 15 |
| `RATE_LIMIT_MAX` | Max requests per window | 100 |
| `API_PREFIX` | API route prefix | /api/v1 |

---

## Database Schema

### Core Collections

| Collection | Description |
|------------|-------------|
| `users` | User accounts and authentication |
| `roles` | Roles and permissions |
| `organizations` | Organization/tenant data |
| `assets` | Security assets (servers, firewalls, etc.) |
| `logSources` | Configured log sources |
| `logs` | Normalized security events |
| `alerts` | Security alerts |
| `incidents` | Security incidents |
| `iocs` | Indicators of Compromise |
| `threatRules` | Detection rules |
| `reports` | Generated reports |
| `auditLogs` | Audit trail |
| `settings` | System configuration |
| `networkTopologies` | Network architecture diagrams |
| `securityControls` | Remediation and mitigation library |
| `securitySensors` | Security data collection points |
| `securityTests` | Pipeline validation tests |
| `securityAssessments` | Security posture evaluations |

### Key Relationships

```
Organization
    ├── Users (One-to-Many)
    ├── Assets (One-to-Many)
    ├── LogSources (One-to-Many)
    ├── Logs (One-to-Many)
    ├── Alerts (One-to-Many)
    ├── Incidents (One-to-Many)
    ├── IOCs (One-to-Many)
    ├── Reports (One-to-Many)
    ├── AuditLogs (One-to-Many)
    ├── Settings (One-to-One)
    ├── NetworkTopologies (One-to-Many)
    ├── SecurityControls (One-to-Many)
    ├── SecuritySensors (One-to-Many)
    ├── SecurityTests (One-to-Many)
    └── SecurityAssessments (One-to-Many)

SecurityAssessment
    ├── Threats (Alerts) (Many-to-Many)
    ├── Incidents (Many-to-Many)
    ├── Assets (Many-to-Many)
    └── SecurityControls (Many-to-Many)

SecurityControl
    ├── ThreatRule (Many-to-One)
    ├── RecommendedControls (Embedded)
    ├── Mitigations (Embedded)
    └── AnalystActions (Embedded)

NetworkTopology
    ├── Nodes (Embedded) → Assets/Sensors
    └── Edges (Embedded)

SecurityTest
    ├── ExpectedDetection → ThreatRule
    ├── RelatedAlert → Alert
    └── RelatedIncident → Incident

SecuritySensor
    ├── Asset → Asset
    └── LogSource → LogSource
```

---

## Authentication & Authorization

### Authentication Flow

1. User submits credentials to `/api/v1/auth/login`
2. Server validates credentials using bcrypt comparison
3. Server returns a JWT access token (expires in 7 days) and a refresh token (expires in 30 days)
4. Client includes the access token in the `Authorization: Bearer <token>` header for subsequent requests
5. Server validates the token on protected routes using the `protect` middleware
6. When the access token expires, the client can request a new one using `/api/v1/auth/refresh`

### Roles & Permissions

| Role | Permissions |
|------|-------------|
| **Super Admin** | Full system access, all permissions |
| **Security Admin** | Manage assets, manage threat rules, manage notifications, view users |
| **SOC Analyst** | View logs, view alerts, manage alerts, view incidents, manage incidents, generate reports |
| **Incident Responder** | View and respond to incidents, add evidence, resolve incidents |
| **Auditor** | Read-only access for compliance and audit review |

### RBAC Implementation

- Every API endpoint validates user permissions using the `authorize(permission)` middleware
- Super admin bypasses all permission checks
- Permissions are defined as constants in `config/constants.js` and assigned to roles

---

## Log Ingestion Pipeline

### REST API Endpoint

```
POST /api/v1/logs/ingest
```

### Request Format

```json
{
  "sourceId": "6a6848b0c15e297a26a2716f",
  "authToken": "062be5000135e7ff805e0c4ec1a37cad21dc9fe6b7ee612e6b600bae1d120e3b",
  "log": {
    "eventType": "Failed Login",
    "eventCategory": "authentication",
    "severity": "high",
    "message": "Failed login attempt for user admin",
    "sourceIP": "192.168.1.100",
    "username": "admin",
    "eventTime": "2026-07-28T06:30:00.000Z"
  }
}
```

### Ingestion Pipeline Steps

1. **Source Validation** – The source ID and authentication token are validated against the database. The source's status and heartbeat are updated.

2. **Log Normalization** – The raw log is parsed and normalized into the standard Log schema.

3. **Storage** – The normalized log is saved to the `logs` collection with status `processed`.

4. **Threat Detection** – The detection engine evaluates the log against enabled threat rules.

5. **Alert Generation** – If a rule matches, an alert is created with the appropriate severity and risk score.

6. **Incident Creation** – Related alerts are automatically grouped into incidents.

---

## Log Normalization

Incoming logs are normalized to the standard Log schema. Normalization is source-type aware and handles:

| Source Type | Normalization Logic |
|-------------|---------------------|
| Windows | Maps event IDs to event types (4624 → Successful Login, 4625 → Failed Login, 4740 → Account Locked) |
| Linux | Detects SSH login, SSH failed login, sudo execution, service events |
| Apache | Detects SQL injection, XSS, command injection in URIs; maps status codes to severities |
| Nginx | Similar to Apache with additional proxy error detection |
| Suricata | Extracts signature details, threat type, and severity from alerts |
| Snort | Extracts rule details, classification, and priority from alerts |
| pfSense | Maps action (pass/block/reject) to event type and severity |

The normalized log includes:
- `eventCategory`: authentication, network, system, application, database, web, malware, policy, access, error, ids, firewall
- `eventType`: Derived from the log (e.g., "Failed Login", "SQL Injection")
- `severity`: critical, high, medium, low, info
- `sourceIP`, `destinationIP`, `username`, `message`
- `rawLog`: The original, unmodified log payload
- `normalizedData`: Additional source-specific fields

---

## Threat Detection & Alerting

### Threat Rule Structure

Threat rules are defined in JSON with the following structure:

```json
{
  "name": "Brute Force Detection",
  "description": "Detects multiple failed login attempts from the same IP",
  "type": "signature",
  "severity": "high",
  "category": "authentication",
  "threatType": "brute_force",
  "condition": {
    "eventCategory": "authentication",
    "eventType": "Failed Login"
  },
  "actions": [
    {
      "type": "alert",
      "configuration": { "priority": "high" }
    }
  ],
  "enabled": true,
  "priority": 8,
  "cooldown": 60,
  "tags": ["brute_force", "authentication"]
}
```

### Rule Conditions

Rules support complex conditions using:
- `$and` – All conditions must match
- `$or` – Any condition must match
- `$not` – Condition must not match
- Field comparators: `$eq`, `$ne`, `$gt`, `$gte`, `$lt`, `$lte`, `$in`, `$nin`, `$regex`, `$contains`, `$startsWith`, `$endsWith`

### Alert Lifecycle

Alerts have the following statuses:
- `active` – Newly created, awaiting investigation
- `investigating` – Under active investigation
- `resolved` – Has been resolved (mitigated, false positive, accepted risk)
- `suppressed` – Temporarily suppressed (e.g., during maintenance)

### Risk Score Calculation

The risk score (0-10) is calculated based on:
- **Severity**: critical=10, high=7, medium=5, low=3, info=1
- **Priority**: Added to the score
- **Effectiveness**: True positive rate of the rule

---

## Incident Management

### Incident Lifecycle

Incidents progress through the following statuses:
- `new` – Unassigned, awaiting triage
- `investigating` – Under active investigation
- `in_progress` – Containment or remediation in progress
- `resolved` – Resolved (mitigated, false positive, accepted risk)
- `closed` – Fully closed, lessons learned documented

### Incident Features

Each incident supports:
- **Timeline** – Full audit trail of all actions (created, assigned, investigating, escalated, resolved, closed)
- **Evidence** – Attach logs, alerts, files, screenshots, network PCAPs
- **Affected Assets** – Link assets impacted by the incident
- **Containment Measures** – Track steps taken to contain the incident
- **Resolution** – Record resolution type, summary, and lessons learned
- **Escalation** – Escalate to another analyst or team lead

### Automatic Incident Creation

When multiple alerts from the same source IP or threat type occur within a configurable time window (default: 1 hour), they are automatically grouped into an incident. The incident severity and category are derived from the highest severity alert.

---

## Network Topology & Visualization

### Overview

The Network Topology module provides a visual representation of your organization's network architecture, showing how all security components connect.

### Key Features

| Feature | Description |
|---------|-------------|
| **Interactive Visualization** | Drag, zoom, and click on network nodes using vis-network library |
| **Node Types** | Internet, Firewall, Router, DMZ, Server, Workstation, Security Sensor, Switch, Other |
| **Network Zones** | External, Perimeter, DMZ, Internal LAN, Management, Unassigned |
| **Security Sensor Integration** | Display sensors as star-shaped nodes with status indicators |
| **Asset Linking** | Click nodes to view associated asset details |
| **Edge Labeling** | Label connections between nodes |
| **Legend** | Color-coded legend for node types |
| **Zone Grouping** | Organize nodes by network zone |

### Node Types & Visual Indicators

| Node Type | Color | Shape |
|-----------|-------|-------|
| Internet | #dc3545 | Hexagon |
| Firewall | #fd7e14 | Square |
| Router | #6f42c1 | Triangle |
| Server | #0d6efd | Square |
| Workstation | #198754 | Dot |
| Security Sensor | #0dcaf0 | Star |
| SentinelSOC | #2F855A | Square |
| Switch/Other | #6c757d | Square |

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/network-topology` | Get topology for organization |
| POST | `/api/v1/network-topology` | Create/Update topology |
| DELETE | `/api/v1/network-topology` | Clear topology |
| GET | `/api/v1/network-topology/stats` | Get topology statistics |
| POST | `/api/v1/network-topology/nodes` | Add a node |
| DELETE | `/api/v1/network-topology/nodes/:nodeId` | Remove a node |

### Integration with Security Sensors

Sensors automatically appear as nodes in the network topology when created. Each sensor node:
- Displays sensor name, type, and status
- Shows network zone placement
- Links to associated asset details
- Updates status based on sensor health

---

## Security Controls Library

### Overview

The Security Controls module is a knowledge base that defines remediation actions, mitigations, and recommended fixes for specific threats. It provides structured guidance for responding to security incidents.

### Key Components

| Component | Description |
|-----------|-------------|
| **Threat Name** | The threat being addressed |
| **Description** | Details about the threat |
| **Risk Level** | Critical, High, Medium, Low |
| **Risk Score** | Numeric score (0-10) |
| **Recommended Controls** | Actions to prevent the threat |
| **Mitigations** | Steps to reduce impact |
| **Analyst Actions** | Steps for SOC analysts to take |
| **Compliance Frameworks** | NIST, ISO27001, SOC2, HIPAA, GDPR, PCI-DSS |
| **Status** | Draft, Active, Deprecated, Archived |
| **Versioning** | Track changes over time |

### Example Control

```json
{
  "threatName": "SSH Brute Force Attack",
  "riskLevel": "High",
  "recommendedControls": [
    {
      "name": "Enable fail2ban",
      "description": "Install and configure fail2ban",
      "priority": "High",
      "status": "Implemented"
    },
    {
      "name": "Implement rate limiting",
      "description": "Configure rate limiting for SSH",
      "priority": "Medium",
      "status": "Pending"
    }
  ],
  "mitigations": [
    {
      "name": "Block IP after 5 attempts",
      "description": "Implement IP blocking",
      "priority": "High",
      "status": "Verified"
    }
  ],
  "analystActions": [
    {
      "name": "Review SSH logs",
      "description": "Check for successful breaches",
      "priority": "Medium"
    }
  ],
  "complianceFrameworks": ["NIST", "ISO27001"]
}
```

### Use Cases

1. **Security Assessments** – Link assessments to controls for remediation guidance
2. **Incident Response** – Provide structured response actions
3. **Compliance** – Map controls to compliance frameworks
4. **Reporting** – Track control effectiveness and implementation status

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/security-controls` | Get all controls |
| POST | `/api/v1/security-controls` | Create a control |
| GET | `/api/v1/security-controls/:id` | Get control by ID |
| PUT | `/api/v1/security-controls/:id` | Update a control |
| DELETE | `/api/v1/security-controls/:id` | Delete a control |
| POST | `/api/v1/security-controls/:id/recommended-controls` | Add recommended control |
| PUT | `/api/v1/security-controls/:id/recommended-controls/:index` | Update control status |
| POST | `/api/v1/security-controls/:id/mitigations` | Add mitigation |
| POST | `/api/v1/security-controls/:id/analyst-actions` | Add analyst action |

---

## Security Assessments

### Overview

The Security Assessment module provides comprehensive evaluation of your organization's security posture. It identifies weaknesses, links to security controls, and provides actionable recommendations.

### Assessment Lifecycle

```
Draft → In Progress → Review → Final
```

### Key Features

| Feature | Description |
|---------|-------------|
| **Risk Evaluation** | Comprehensive risk assessment with scoring |
| **Weakness Identification** | Document security weaknesses |
| **Control Linking** | Link assessments to security controls |
| **Incident Integration** | Review incidents as part of assessment |
| **Asset Impact** | Identify affected assets |
| **Status Lifecycle** | Draft → In Progress → Review → Final |
| **Review Tracking** | Track who reviewed and when |
| **Next Review Dates** | Schedule follow-up assessments |
| **Versioning** | Track changes to assessments |

### Assessment Components

| Component | Description |
|-----------|-------------|
| **Title** | Assessment title |
| **Description** | Scope and objectives |
| **Date** | Assessment date |
| **Assessment Period** | Start and end dates |
| **Risk Level** | Low, Medium, High, Critical |
| **Risk Score** | Numeric score (0-10) |
| **Threats Detected** | Linked alerts |
| **Incidents** | Linked incidents |
| **Affected Assets** | Assets impacted |
| **Security Weaknesses** | Identified vulnerabilities |
| **Recommended Controls** | Remediation actions |
| **Mitigations** | Risk reduction steps |
| **Status** | Draft, In Progress, Review, Final |
| **Summary** | Executive summary |
| **Next Review Date** | Scheduled follow-up |
| **Tags** | Categorization |

### Integration with Other Modules

1. **Threats** – Link alerts from detection engine
2. **Incidents** – Include incidents from response
3. **Assets** – Identify affected assets
4. **Controls** – Link to security controls for remediation

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/security-assessments` | Get all assessments |
| POST | `/api/v1/security-assessments` | Create assessment |
| GET | `/api/v1/security-assessments/:id` | Get assessment by ID |
| PUT | `/api/v1/security-assessments/:id` | Update assessment |
| DELETE | `/api/v1/security-assessments/:id` | Delete assessment |
| POST | `/api/v1/security-assessments/:id/link-threats` | Link alerts |
| POST | `/api/v1/security-assessments/:id/link-incidents` | Link incidents |
| POST | `/api/v1/security-assessments/:id/link-assets` | Link assets |
| PATCH | `/api/v1/security-assessments/:id/status` | Update status |
| POST | `/api/v1/security-assessments/:id/calculate-risk` | Calculate risk |
| GET | `/api/v1/security-assessments/stats` | Get statistics |

---

## Security Testing Lab

### Overview

The Security Testing Lab provides controlled testing of your detection pipeline without running real attacks. It validates that the entire pipeline works correctly from log generation to incident creation.

### Test Scenarios

| Test Type | Description |
|-----------|-------------|
| **Port Scan** | Simulates a Suricata port scan alert |
| **Brute Force** | Injects multiple failed authentication logs |
| **Suspicious Traffic** | Simulates outbound connections to known malicious ports |
| **Unauthorized Connection** | Simulates unauthorized network connections |
| **SQL Injection** | Simulates SQL injection attempts |
| **XSS** | Simulates cross-site scripting attempts |
| **Other** | Custom test scenarios |

### Pipeline Validation

Each test validates the complete security pipeline:

```
1. Event Generated → 2. Log Ingested → 3. Detection Triggered → 4. Alert Created → 5. Incident Created → 6. Evidence Recorded
```

### Test Status

| Status | Description |
|--------|-------------|
| **PENDING** | Test created, waiting to run |
| **RUNNING** | Test is currently executing |
| **PASS** | All pipeline stages completed successfully |
| **FAIL** | One or more pipeline stages failed |

### Test Results

Each test captures:
- **Generated Event** – The test payload
- **Log Details** – Source IP, destination IP, ports, protocol
- **Detection Result** – Whether detection was triggered
- **Alert ID** – Linked alert if created
- **Incident ID** – Linked incident if created
- **Evidence Recorded** – Whether evidence was properly captured

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/security-tests` | Get all tests |
| POST | `/api/v1/security-tests` | Create test |
| GET | `/api/v1/security-tests/:id` | Get test by ID |
| PUT | `/api/v1/security-tests/:id` | Update test |
| DELETE | `/api/v1/security-tests/:id` | Delete test |
| POST | `/api/v1/security-tests/:id/run` | Run test |
| POST | `/api/v1/security-tests/:id/cancel` | Cancel running test |
| GET | `/api/v1/security-tests/stats` | Get statistics |
| GET | `/api/v1/security-tests/types` | Get test types |

---

## Security Sensors

### Overview

Security Sensors are data collection points that monitor network traffic, system events, or security logs. They serve as the "eyes and ears" of the SOC.

### Sensor Types

| Type | Description |
|------|-------------|
| **Suricata** | Network IDS/IPS - detects intrusions and suspicious traffic |
| **Zeek** | Network monitoring - analyzes network protocols and flows |
| **Firewall** | Tracks blocked/allowed connections and firewall events |
| **Host Collector** | Monitors system logs, processes, and file changes |
| **Wazuh** | Security monitoring agent for endpoints |
| **Snort** | Open-source IDS/IPS |
| **Custom** | Custom sensor implementation |

### Sensor Capabilities

| Capability | Description |
|------------|-------------|
| `ids` | Intrusion Detection System |
| `ips` | Intrusion Prevention System |
| `network_monitoring` | Network traffic analysis |
| `host_monitoring` | System/host monitoring |
| `log_collection` | Log aggregation |
| `threat_detection` | Threat detection |
| `packet_capture` | Packet sniffing |
| `dns_monitoring` | DNS traffic analysis |
| `http_monitoring` | HTTP traffic analysis |
| `tls_monitoring` | TLS/SSL traffic analysis |

### Sensor Health Monitoring

| Metric | Description |
|--------|-------------|
| **Health Score** | 0-100 score based on uptime and performance |
| **Last Heartbeat** | Timestamp of last sensor check-in |
| **Events Received** | Total events received |
| **Events Forwarded** | Total events forwarded |
| **Alerts Generated** | Total alerts generated |
| **Uptime** | Sensor uptime in seconds |

### Sensor Status

| Status | Description |
|--------|-------------|
| **Active** | Running and sending data |
| **Inactive** | Stopped or disabled |
| **Error** | Error condition |
| **Pending** | Newly created, not yet active |
| **Degraded** | Partially working |

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/security-sensors` | Get all sensors |
| POST | `/api/v1/security-sensors` | Create sensor |
| GET | `/api/v1/security-sensors/:id` | Get sensor by ID |
| PUT | `/api/v1/security-sensors/:id` | Update sensor |
| DELETE | `/api/v1/security-sensors/:id` | Delete sensor |
| POST | `/api/v1/security-sensors/:id/heartbeat` | Update heartbeat |
| POST | `/api/v1/security-sensors/:id/event` | Record event |
| POST | `/api/v1/security-sensors/bulk` | Bulk create sensors |
| GET | `/api/v1/security-sensors/stats` | Get statistics |
| GET | `/api/v1/security-sensors/types` | Get sensor types |

---

## Simulators

The project includes 7 log simulators for generating realistic security telemetry:

| Simulator | Source Type | Events Generated |
|-----------|-------------|------------------|
| **Windows** | Windows | Security (4624, 4625, 4740, 4720, 4723, 4725, 4726, 4732, 4733, 4767, 4771, 4776), System (41, 6005, 6006, 6008, 7000, 7009, 7036), Application (1000, 1001, 1026, 1028, 1030) |
| **Linux** | Linux | SSH login, SSH failed login, sudo execution, service start/stop/fail, system boot/shutdown, kernel panic, user/group modifications |
| **Apache** | Apache | HTTP access logs, 404 errors, 403 access denied, 500 server errors, SQL injection attempts, XSS attempts, command injection attempts, directory traversal attempts |
| **Nginx** | Nginx | HTTP access logs, reverse proxy errors (502, 504), rate limiting events, health checks, API abuse detection |
| **Suricata** | Suricata | Malware communication, SQL injection detection, XSS detection, port scanning, DDoS pattern detection, privilege escalation, shellcode detection, DNS tunneling |
| **Snort** | Snort | Port scans, DDoS attacks, suspicious traffic, malware communication, SQL injection, XSS, buffer overflow attempts, DNS amplification, SNMP attacks, SSH brute force |
| **Firewall** | pfSense | Connection allowed, connection blocked, connection rejected, NAT rules, port forwarding, VPN connections, attack attempts (brute force, DDoS, malware C2, port scans) |

### Running Simulators

```bash
cd simulators

# First, set up log sources and get authentication tokens
node setup-simulators.js

# Then run individual simulators
node windowsSimulator.js
node linuxSimulator.js
node apacheSimulator.js
node nginxSimulator.js
node suricataSimulator.js
node snortSimulator.js
node firewallSimulator.js

# Or run all simultaneously
npm run all
```

Each simulator generates logs every 2-5 seconds with randomized fields (IP addresses, usernames, hostnames, timestamps) and sends them to the ingestion API using the source ID and authentication token.

---

## API Reference

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | User login, returns access and refresh tokens |
| POST | `/api/v1/auth/refresh` | Refresh access token using refresh token |
| POST | `/api/v1/auth/forgot-password` | Initiate password reset |
| POST | `/api/v1/auth/reset-password` | Complete password reset |
| POST | `/api/v1/auth/logout` | User logout |

### User Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/users` | Get all users (paginated) |
| GET | `/api/v1/users/:id` | Get user by ID |
| POST | `/api/v1/users` | Create a new user |
| PUT | `/api/v1/users/:id` | Update a user |
| DELETE | `/api/v1/users/:id` | Soft delete a user |

### Organization Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/organizations` | Get all organizations |
| GET | `/api/v1/organizations/:id` | Get organization by ID |
| POST | `/api/v1/organizations` | Create an organization |
| PUT | `/api/v1/organizations/:id` | Update an organization |
| DELETE | `/api/v1/organizations/:id` | Delete an organization |

### Asset Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/assets` | Get all assets (paginated) |
| GET | `/api/v1/assets/:id` | Get asset by ID |
| POST | `/api/v1/assets` | Create an asset |
| PUT | `/api/v1/assets/:id` | Update an asset |
| DELETE | `/api/v1/assets/:id` | Delete an asset |

### Log Source Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/log-sources` | Get all log sources |
| GET | `/api/v1/log-sources/:id` | Get log source by ID |
| POST | `/api/v1/log-sources` | Create a log source |
| PUT | `/api/v1/log-sources/:id` | Update a log source |
| DELETE | `/api/v1/log-sources/:id` | Delete a log source |
| PATCH | `/api/v1/log-sources/:id/status` | Update log source status |
| PATCH | `/api/v1/log-sources/:id/heartbeat` | Update heartbeat timestamp |

### Log Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/logs/ingest` | Ingest a log (public endpoint) |
| GET | `/api/v1/logs` | Get logs with filtering and pagination |
| GET | `/api/v1/logs/:id` | Get log by ID |
| GET | `/api/v1/logs/statistics` | Get log statistics |

### Alert Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/alerts` | Get alerts with filtering |
| GET | `/api/v1/alerts/:id` | Get alert by ID |
| POST | `/api/v1/alerts/from-log` | Create alert from a log |
| PUT | `/api/v1/alerts/:id` | Update an alert |
| POST | `/api/v1/alerts/:id/assign` | Assign alert to user |
| PATCH | `/api/v1/alerts/:id/status` | Update alert status |
| POST | `/api/v1/alerts/:id/resolve` | Resolve an alert |
| POST | `/api/v1/alerts/:id/escalate` | Escalate an alert |

### Incident Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/incidents` | Get incidents with filtering |
| GET | `/api/v1/incidents/:id` | Get incident by ID |
| POST | `/api/v1/incidents` | Create an incident |
| PUT | `/api/v1/incidents/:id` | Update an incident |
| POST | `/api/v1/incidents/:id/assign` | Assign incident to user |
| POST | `/api/v1/incidents/:id/resolve` | Resolve an incident |
| POST | `/api/v1/incidents/:id/close` | Close an incident |
| POST | `/api/v1/incidents/:id/escalate` | Escalate an incident |
| POST | `/api/v1/incidents/:id/evidence` | Add evidence to an incident |
| POST | `/api/v1/incidents/:id/note` | Add a note to an incident |

### IOC Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/iocs` | Get all IOCs |
| GET | `/api/v1/iocs/:id` | Get IOC by ID |
| POST | `/api/v1/iocs` | Create an IOC |
| PUT | `/api/v1/iocs/:id` | Update an IOC |
| DELETE | `/api/v1/iocs/:id` | Delete an IOC |
| POST | `/api/v1/iocs/:id/link-incident` | Link IOC to incident |
| POST | `/api/v1/iocs/:id/link-alert` | Link IOC to alert |

### Threat Rule Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/threat-rules` | Get all threat rules |
| GET | `/api/v1/threat-rules/:id` | Get threat rule by ID |
| POST | `/api/v1/threat-rules` | Create a threat rule |
| PUT | `/api/v1/threat-rules/:id` | Update a threat rule |
| DELETE | `/api/v1/threat-rules/:id` | Delete a threat rule |
| PATCH | `/api/v1/threat-rules/:id/toggle` | Enable/disable a threat rule |

### Report Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/reports` | Get all reports |
| GET | `/api/v1/reports/:id` | Get report by ID |
| POST | `/api/v1/reports` | Create a report |
| POST | `/api/v1/reports/:id/generate` | Generate a report |
| DELETE | `/api/v1/reports/:id` | Delete a report |

### Audit Log Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/audit-logs` | Get audit logs with filtering |
| GET | `/api/v1/audit-logs/:id` | Get audit log by ID |
| GET | `/api/v1/audit-logs/statistics` | Get audit log statistics |

### Network Defense Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/network-topology` | Get network topology |
| POST | `/api/v1/network-topology` | Create/Update topology |
| GET | `/api/v1/security-sensors` | Get all sensors |
| POST | `/api/v1/security-sensors` | Create sensor |
| GET | `/api/v1/security-controls` | Get all controls |
| POST | `/api/v1/security-controls` | Create control |
| GET | `/api/v1/security-tests` | Get all tests |
| POST | `/api/v1/security-tests` | Create test |
| POST | `/api/v1/security-tests/:id/run` | Run test |
| GET | `/api/v1/security-assessments` | Get all assessments |
| POST | `/api/v1/security-assessments` | Create assessment |

---

## Security Controls

| Control | Implementation |
|---------|----------------|
| **Authentication** | JWT with refresh token rotation |
| **Password Security** | bcrypt hashing with configurable salt rounds |
| **Rate Limiting** | express-rate-limit on API endpoints |
| **Security Headers** | Helmet.js |
| **CORS** | Configurable CORS policies |
| **Input Validation** | express-validator on all requests |
| **Data Sanitization** | Request body sanitization |
| **Secrets Management** | Environment variables, no hardcoded secrets |
| **Audit Logging** | Complete audit trail of all user actions |
| **Access Control** | RBAC with granular permissions |
| **Secure Password Reset** | Token-based password reset with expiration |

---

## Deployment

### Docker Deployment

```bash
# Build the Docker image
docker build -t sentinel-soc .

# Run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f
```

### Production Considerations

1. **Set strong JWT secrets** in `.env` (use a cryptographically random string)
2. **Enable HTTPS** with a valid certificate (Let's Encrypt or commercial)
3. **Use MongoDB Atlas** or a replicated self-hosted MongoDB cluster
4. **Configure a firewall** to restrict access to the server
5. **Set up monitoring** and alerting for the application
6. **Perform regular backups** of the MongoDB database
7. **Use a process manager** like PM2 for production

### Production Environment Variables

```env
NODE_ENV=production
MONGODB_URI=mongodb://production-db:27017/sentinel_soc
JWT_SECRET=your-production-jwt-secret
JWT_REFRESH_SECRET=your-production-refresh-secret
BCRYPT_ROUNDS=12
CORS_ORIGIN=https://your-domain.com
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
```

---

## Development

### Seeding the Database

```bash
cd backend
node src/seed.js
```

### Creating Custom Log Sources

```bash
# Login to get a JWT token
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"superadmin@sentinel-soc.com","password":"SuperAdmin@2024!"}'

# Create a log source (replace token and IDs)
curl -X POST http://localhost:3000/api/v1/log-sources \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "organization": "ORG_ID",
    "asset": "ASSET_ID",
    "sourceName": "Custom-Source",
    "sourceType": "Custom",
    "protocol": "REST",
    "status": "Online"
  }'
```

### Creating Security Sensors

```bash
# Create a sensor
curl -X POST http://localhost:3000/api/v1/security-sensors \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Suricata-IDS-01",
    "type": "Suricata",
    "networkZone": "DMZ",
    "ipAddress": "10.0.1.100",
    "capabilities": ["ids", "network_monitoring"]
  }'
```

### Running Tests

```bash
# Run backend tests
cd backend
npm test

# Run security pipeline tests
npm run test:network

# Lint the codebase
npm run lint

# Format the code
npm run format
```

---

## Contributing

### Development Guidelines

1. **Follow MVC Architecture** – Business logic belongs in services, not controllers or routes
2. **Use Async/Await** – No callbacks
3. **Write Clean Code** – Follow SOLID principles
4. **DRY Principle** – Reuse code where possible
5. **Document Everything** – Add comments and update the README
6. **Write Tests** – Unit and integration tests for new features
7. **Secure Coding** – Validate all inputs, sanitize outputs

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request against the `main` branch

---

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **Node.js** – Runtime environment
- **MongoDB** – Database
- **Express.js** – Web framework
- **vis-network** – Network visualization library
- **All open-source contributors** – The libraries and tools that make SentinelSOC possible

---

## Security Disclaimer

SentinelSOC is an educational and research-oriented SOC/SIEM platform.

The security testing functionality is designed for controlled environments
and uses benign test events to validate detection and response workflows.

Do not use SentinelSOC's testing functionality against systems or networks
without explicit authorization.

The authors are not responsible for unauthorized use, misuse, damage, or
security incidents resulting from the use of this software.

---

## Support

For support, email **hfdaginawala@gmail.com** or create an issue in the repository.

---

## Tags

`soc` `siem` `security` `monitoring` `incident-response` `threat-detection` `network-topology` `security-assessment` `security-testing` `nodejs` `mongodb` `express` `cybersecurity` `enterprise` `network-defense` `remediation` `compliance`
