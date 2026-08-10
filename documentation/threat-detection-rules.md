# SentinelSOC - Threat Rules Documentation

This document provides a comprehensive list of all threat rules available in SentinelSOC. These rules are used by the detection engine to identify security threats from incoming logs.

---

## Threat Rule Structure

Each threat rule follows this JSON structure:

```json
{
  "organization": "Organization ID",
  "name": "Rule Name",
  "description": "Rule Description",
  "type": "signature | behavioral | anomaly | statistical",
  "severity": "critical | high | medium | low | info",
  "category": "authentication | network | system | application | database | web | malware | policy | access | error | ids | firewall",
  "threatType": "threat_type_identifier",
  "condition": { "field": "value" },
  "actions": [ { "type": "alert" } ],
  "enabled": true,
  "priority": 1-10,
  "cooldown": 60,
  "tags": ["tag1", "tag2"],
  "references": ["reference_url"]
}
```

---

## Authentication Threat Rules

### 1. Brute Force Attack Detection

```json
{
  "name": "Brute Force Attack Detection",
  "description": "Detects multiple failed login attempts from the same IP address within a short time window",
  "type": "signature",
  "severity": "high",
  "category": "authentication",
  "threatType": "brute_force",
  "condition": {
    "eventCategory": "authentication",
    "eventType": "Failed Login",
    "sourceIP": { "$exists": true }
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "high",
        "notify": true
      }
    },
    {
      "type": "block",
      "configuration": {
        "duration": 300,
        "source": "sourceIP"
      }
    }
  ],
  "enabled": true,
  "priority": 8,
  "cooldown": 60,
  "tags": ["brute_force", "authentication", "attack"],
  "references": ["https://owasp.org/brute-force"]
}
```

### 2. Account Lockout Detection

```json
{
  "name": "Account Lockout Detection",
  "description": "Detects when a user account has been locked due to multiple failed login attempts",
  "type": "signature",
  "severity": "high",
  "category": "authentication",
  "threatType": "brute_force",
  "condition": {
    "eventCategory": "authentication",
    "eventType": "Account Locked"
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "high",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 7,
  "cooldown": 300,
  "tags": ["account_lockout", "authentication", "attack"],
  "references": ["https://owasp.org/account-lockout"]
}
```

### 3. Suspicious Login Activity

```json
{
  "name": "Suspicious Login Activity",
  "description": "Detects successful logins from unusual IP addresses or at unusual times",
  "type": "behavioral",
  "severity": "medium",
  "category": "authentication",
  "threatType": "unauthorized_access",
  "condition": {
    "eventCategory": "authentication",
    "eventType": "Successful Login",
    "sourceIP": { "$regex": "^(?!192\\.168\\.).*$" }
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "medium",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 5,
  "cooldown": 60,
  "tags": ["suspicious_login", "authentication", "unusual_activity"]
}
```

### 4. Kerberos Pre-Authentication Failure

```json
{
  "name": "Kerberos Pre-Authentication Failure",
  "description": "Detects Kerberos pre-authentication failures which may indicate password spraying attacks",
  "type": "signature",
  "severity": "high",
  "category": "authentication",
  "threatType": "brute_force",
  "condition": {
    "eventCategory": "authentication",
    "eventType": "Kerberos Pre-Authentication Failed"
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "high",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 7,
  "cooldown": 60,
  "tags": ["kerberos", "authentication", "attack"],
  "references": ["https://attack.mitre.org/techniques/T1110/"]
}
```

### 5. Credential Validation Attack

```json
{
  "name": "Credential Validation Attack",
  "description": "Detects credential validation attempts which may indicate password guessing attacks",
  "type": "signature",
  "severity": "high",
  "category": "authentication",
  "threatType": "brute_force",
  "condition": {
    "eventCategory": "authentication",
    "eventType": "Credential Validation"
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "high",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 7,
  "cooldown": 60,
  "tags": ["credential_validation", "authentication", "attack"]
}
```

---

## Web Application Threat Rules

### 6. SQL Injection Detection

```json
{
  "name": "SQL Injection Detection",
  "description": "Detects SQL injection attempts in web application requests",
  "type": "signature",
  "severity": "critical",
  "category": "web",
  "threatType": "sql_injection",
  "condition": {
    "eventCategory": "web",
    "$or": [
      { "message": { "$regex": ".*(OR|UNION|SELECT|DROP|DELETE|INSERT|UPDATE|WHERE).*" } },
      { "rawLog": { "$regex": ".*(OR|UNION|SELECT|DROP|DELETE|INSERT|UPDATE|WHERE).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    },
    {
      "type": "block",
      "configuration": {
        "duration": 600,
        "source": "sourceIP"
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 30,
  "tags": ["web_attack", "sql_injection", "owasp_top_10"],
  "references": ["https://owasp.org/sql-injection"]
}
```

### 7. Cross-Site Scripting (XSS) Detection

```json
{
  "name": "Cross-Site Scripting (XSS) Detection",
  "description": "Detects Cross-Site Scripting (XSS) attempts in web application requests",
  "type": "signature",
  "severity": "critical",
  "category": "web",
  "threatType": "xss",
  "condition": {
    "eventCategory": "web",
    "$or": [
      { "message": { "$regex": ".*(<script|onerror|onload|alert|prompt|confirm).*" } },
      { "rawLog": { "$regex": ".*(<script|onerror|onload|alert|prompt|confirm).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    },
    {
      "type": "block",
      "configuration": {
        "duration": 600,
        "source": "sourceIP"
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 30,
  "tags": ["web_attack", "xss", "owasp_top_10"],
  "references": ["https://owasp.org/xss"]
}
```

### 8. Command Injection Detection

```json
{
  "name": "Command Injection Detection",
  "description": "Detects command injection attempts in web application requests",
  "type": "signature",
  "severity": "critical",
  "category": "web",
  "threatType": "command_injection",
  "condition": {
    "eventCategory": "web",
    "$or": [
      { "message": { "$regex": ".*(;|\\||&&|`|\\(\\).*" } },
      { "rawLog": { "$regex": ".*(;|\\||&&|`|\\(\\).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    },
    {
      "type": "block",
      "configuration": {
        "duration": 600,
        "source": "sourceIP"
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 30,
  "tags": ["web_attack", "command_injection", "owasp_top_10"],
  "references": ["https://owasp.org/command-injection"]
}
```

### 9. Directory Traversal Detection

```json
{
  "name": "Directory Traversal Detection",
  "description": "Detects directory traversal attempts in web application requests",
  "type": "signature",
  "severity": "high",
  "category": "web",
  "threatType": "unauthorized_access",
  "condition": {
    "eventCategory": "web",
    "$or": [
      { "message": { "$regex": ".*(\\.\\./|\\.\\.\\\\.*" } },
      { "rawLog": { "$regex": ".*(\\.\\./|\\.\\.\\\\.*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "high",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 8,
  "cooldown": 60,
  "tags": ["web_attack", "directory_traversal", "path_traversal"],
  "references": ["https://owasp.org/path-traversal"]
}
```

### 10. Web Application Scanning Detection

```json
{
  "name": "Web Application Scanning Detection",
  "description": "Detects web application scanning and probing attempts",
  "type": "behavioral",
  "severity": "medium",
  "category": "web",
  "threatType": "port_scan",
  "condition": {
    "eventCategory": "web",
    "$or": [
      { "eventType": "404 Not Found" },
      { "eventType": "Access Denied" }
    ],
    "sourceIP": { "$exists": true }
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "medium",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 4,
  "cooldown": 120,
  "tags": ["web_scanning", "reconnaissance", "probing"]
}
```

---

## Network Threat Rules

### 11. Port Scan Detection

```json
{
  "name": "Port Scan Detection",
  "description": "Detects port scanning activity from external sources targeting internal hosts",
  "type": "signature",
  "severity": "high",
  "category": "network",
  "threatType": "port_scan",
  "condition": {
    "eventCategory": "network",
    "eventType": "Port Scan"
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "high",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 6,
  "cooldown": 300,
  "tags": ["reconnaissance", "port_scan", "network_scan"],
  "references": ["https://attack.mitre.org/techniques/T1046/"]
}
```

### 12. DDoS Attack Detection

```json
{
  "name": "DDoS Attack Detection",
  "description": "Detects Denial of Service (DoS/DDoS) attack patterns in network traffic",
  "type": "statistical",
  "severity": "critical",
  "category": "network",
  "threatType": "ddos",
  "condition": {
    "eventCategory": "network",
    "$or": [
      { "eventType": "DDoS Attack" },
      { "eventType": "Flood Attack Blocked" },
      { "eventType": "DNS Amplification Attack" }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    },
    {
      "type": "block",
      "configuration": {
        "duration": 3600,
        "source": "sourceIP"
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 0,
  "tags": ["ddos", "dos", "attack", "network"],
  "references": ["https://attack.mitre.org/techniques/T1498/"]
}
```

### 13. Suspicious Network Traffic Detection

```json
{
  "name": "Suspicious Network Traffic Detection",
  "description": "Detects suspicious network traffic patterns that may indicate compromise",
  "type": "behavioral",
  "severity": "medium",
  "category": "network",
  "threatType": "suspicious_traffic",
  "condition": {
    "eventCategory": "network",
    "eventType": "Suspicious Traffic"
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "medium",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 5,
  "cooldown": 60,
  "tags": ["suspicious", "network", "anomaly"]
}
```

### 14. Reverse Shell Detection

```json
{
  "name": "Reverse Shell Detection",
  "description": "Detects reverse shell attempts or connections to known command and control infrastructure",
  "type": "signature",
  "severity": "critical",
  "category": "network",
  "threatType": "reverse_shell",
  "condition": {
    "eventCategory": "network",
    "$or": [
      { "destinationPort": { "$in": [4444, 5555, 6666, 7777, 8888, 9001, 31337] } },
      { "message": { "$regex": ".*(reverse|shell|exec|cmd).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    },
    {
      "type": "isolate",
      "configuration": {
        "duration": 3600,
        "target": "asset"
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 0,
  "tags": ["reverse_shell", "c2", "command_and_control"],
  "references": ["https://attack.mitre.org/techniques/T1204/"]
}
```

### 15. DNS Tunneling Detection

```json
{
  "name": "DNS Tunneling Detection",
  "description": "Detects DNS tunneling activity which may indicate data exfiltration or C2 communication",
  "type": "signature",
  "severity": "critical",
  "category": "network",
  "threatType": "dns_tunneling",
  "condition": {
    "eventCategory": "network",
    "eventType": "DNS Tunneling"
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    },
    {
      "type": "block",
      "configuration": {
        "duration": 3600,
        "source": "sourceIP"
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 0,
  "tags": ["dns_tunneling", "data_exfiltration", "c2"],
  "references": ["https://attack.mitre.org/techniques/T1572/"]
}
```

---

## Malware & Intrusion Threat Rules

### 16. Malware Communication Detection

```json
{
  "name": "Malware Communication Detection",
  "description": "Detects communication with known malicious domains or IP addresses",
  "type": "signature",
  "severity": "critical",
  "category": "malware",
  "threatType": "malware_communication",
  "condition": {
    "eventCategory": "malware",
    "eventType": "Malware Communication"
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    },
    {
      "type": "isolate",
      "configuration": {
        "duration": 3600,
        "target": "asset"
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 0,
  "tags": ["malware", "c2", "command_and_control"],
  "references": ["https://www.mandiant.com/malware"]
}
```

### 17. Malware Detection (Generic)

```json
{
  "name": "Malware Detection (Generic)",
  "description": "Detects generic malware signatures including known hashes and patterns",
  "type": "signature",
  "severity": "critical",
  "category": "malware",
  "threatType": "malware",
  "condition": {
    "eventCategory": "malware",
    "$or": [
      { "threatType": "malware" },
      { "message": { "$regex": ".*(malware|virus|trojan|ransomware|worm).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    },
    {
      "type": "isolate",
      "configuration": {
        "duration": 3600,
        "target": "asset"
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 0,
  "tags": ["malware", "virus", "trojan", "ransomware"]
}
```

### 18. Ransomware Detection

```json
{
  "name": "Ransomware Detection",
  "description": "Detects ransomware activity including file encryption patterns and known ransomware signatures",
  "type": "signature",
  "severity": "critical",
  "category": "malware",
  "threatType": "ransomware",
  "condition": {
    "eventCategory": "malware",
    "$or": [
      { "threatType": "ransomware" },
      { "message": { "$regex": ".*(encrypt|\\.encrypted|ransomware|decrypt).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    },
    {
      "type": "isolate",
      "configuration": {
        "duration": 7200,
        "target": "asset"
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 0,
  "tags": ["ransomware", "malware", "encryption"]
}
```

### 19. Phishing Detection

```json
{
  "name": "Phishing Detection",
  "description": "Detects phishing attempts including malicious URLs and email patterns",
  "type": "signature",
  "severity": "high",
  "category": "malware",
  "threatType": "phishing",
  "condition": {
    "eventCategory": "malware",
    "$or": [
      { "threatType": "phishing" },
      { "message": { "$regex": ".*(phishing|malicious|fake|spoof).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "high",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 8,
  "cooldown": 60,
  "tags": ["phishing", "social_engineering", "email"],
  "references": ["https://attack.mitre.org/techniques/T1566/"]
}
```

### 20. Suspicious PowerShell Activity

```json
{
  "name": "Suspicious PowerShell Activity",
  "description": "Detects suspicious PowerShell execution with potentially malicious parameters",
  "type": "signature",
  "severity": "high",
  "category": "system",
  "threatType": "suspicious_powershell",
  "condition": {
    "eventCategory": "system",
    "$or": [
      { "eventType": "Suspicious PowerShell" },
      { "message": { "$regex": ".*(PowerShell.*-e|powershell.*-enc|powershell.*bypass).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "high",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 8,
  "cooldown": 60,
  "tags": ["powershell", "suspicious", "command_line"],
  "references": ["https://attack.mitre.org/techniques/T1059/001/"]
}
```

---

## Intrusion & Attack Threat Rules

### 21. Buffer Overflow Detection

```json
{
  "name": "Buffer Overflow Detection",
  "description": "Detects buffer overflow attempts which may indicate exploitation attempts",
  "type": "signature",
  "severity": "critical",
  "category": "system",
  "threatType": "privilege_escalation",
  "condition": {
    "eventCategory": "system",
    "eventType": "Buffer Overflow Attempt"
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 0,
  "tags": ["buffer_overflow", "exploit", "privilege_escalation"],
  "references": ["https://attack.mitre.org/techniques/T1190/"]
}
```

### 22. Privilege Escalation Detection

```json
{
  "name": "Privilege Escalation Detection",
  "description": "Detects privilege escalation attempts or successful privilege escalation",
  "type": "signature",
  "severity": "critical",
  "category": "system",
  "threatType": "privilege_escalation",
  "condition": {
    "eventCategory": "system",
    "$or": [
      { "eventType": "Privilege Escalation" },
      { "message": { "$regex": ".*(privilege escalation|sudo|admin).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 0,
  "tags": ["privilege_escalation", "attack", "system"],
  "references": ["https://attack.mitre.org/tactics/TA0004/"]
}
```

### 23. SSH Brute Force Detection

```json
{
  "name": "SSH Brute Force Detection",
  "description": "Detects SSH brute force attacks targeting SSH services",
  "type": "signature",
  "severity": "high",
  "category": "authentication",
  "threatType": "brute_force",
  "condition": {
    "eventCategory": "authentication",
    "$or": [
      { "eventType": "SSH Failed Login" },
      { "eventType": "SSH Brute Force Attack" }
    ],
    "sourceIP": { "$exists": true }
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "high",
        "notify": true
      }
    },
    {
      "type": "block",
      "configuration": {
        "duration": 600,
        "source": "sourceIP"
      }
    }
  ],
  "enabled": true,
  "priority": 8,
  "cooldown": 60,
  "tags": ["ssh", "brute_force", "authentication"],
  "references": ["https://attack.mitre.org/techniques/T1110/"]
}
```

---

## Firewall & Network Security Threat Rules

### 24. Firewall Block Detection

```json
{
  "name": "Firewall Block Detection",
  "description": "Detects when a firewall blocks connection attempts, which may indicate unauthorized access attempts",
  "type": "signature",
  "severity": "medium",
  "category": "firewall",
  "threatType": "unauthorized_access",
  "condition": {
    "eventCategory": "network",
    "eventType": "Connection Blocked"
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "medium",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 5,
  "cooldown": 60,
  "tags": ["firewall", "block", "unauthorized"],
  "references": ["https://attack.mitre.org/techniques/T1135/"]
}
```

### 25. IDS/IPS Signature Match

```json
{
  "name": "IDS/IPS Signature Match",
  "description": "Detects when an IDS/IPS system (Suricata/Snort) matches a known attack signature",
  "type": "signature",
  "severity": "high",
  "category": "ids",
  "threatType": "malware",
  "condition": {
    "eventCategory": "ids",
    "$or": [
      { "sourceType": "Suricata" },
      { "sourceType": "Snort" }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "high",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 8,
  "cooldown": 30,
  "tags": ["ids", "ips", "signature", "intrusion_detection"]
}
```

---

## System & Application Threat Rules

### 26. System Compromise Detection

```json
{
  "name": "System Compromise Detection",
  "description": "Detects indicators of system compromise including unauthorized changes and suspicious processes",
  "type": "behavioral",
  "severity": "critical",
  "category": "system",
  "threatType": "unauthorized_access",
  "condition": {
    "eventCategory": "system",
    "$or": [
      { "eventType": "system_compromise" },
      { "message": { "$regex": ".*(compromised|breach|unauthorized|intrusion).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 0,
  "tags": ["compromise", "system", "breach"]
}
```

### 27. Service Failure Detection

```json
{
  "name": "Service Failure Detection",
  "description": "Detects critical service failures which may indicate compromise or operational issues",
  "type": "signature",
  "severity": "medium",
  "category": "system",
  "threatType": "system_compromise",
  "condition": {
    "eventCategory": "system",
    "$or": [
      { "eventType": "Service Failed" },
      { "message": { "$regex": ".*(failed to start|stopped unexpectedly|crash).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "medium",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 4,
  "cooldown": 120,
  "tags": ["service_failure", "system", "operational"]
}
```

---

## Data Security Threat Rules

### 28. Data Exfiltration Detection

```json
{
  "name": "Data Exfiltration Detection",
  "description": "Detects potential data exfiltration through large data transfers or unusual outbound connections",
  "type": "statistical",
  "severity": "critical",
  "category": "network",
  "threatType": "data_exfiltration",
  "condition": {
    "eventCategory": "network",
    "$or": [
      { "eventType": "Data Exfiltration" },
      { "message": { "$regex": ".*(exfil|exfiltration|data leak|exfiltration).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "critical",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 10,
  "cooldown": 0,
  "tags": ["data_exfiltration", "data_leak", "exfiltration"],
  "references": ["https://attack.mitre.org/tactics/TA0010/"]
}
```

### 29. Unauthorized Access Detection

```json
{
  "name": "Unauthorized Access Detection",
  "description": "Detects unauthorized access attempts to systems, applications, or data",
  "type": "signature",
  "severity": "high",
  "category": "access",
  "threatType": "unauthorized_access",
  "condition": {
    "eventCategory": "access",
    "$or": [
      { "eventType": "Unauthorized Access" },
      { "message": { "$regex": ".*(unauthorized|access denied|forbidden|403).*" } }
    ]
  },
  "actions": [
    {
      "type": "alert",
      "configuration": {
        "priority": "high",
        "notify": true
      }
    }
  ],
  "enabled": true,
  "priority": 8,
  "cooldown": 60,
  "tags": ["unauthorized_access", "access_control", "authorization"],
  "references": ["https://attack.mitre.org/techniques/T1078/"]
}
```

---

## Summary Table

| # | Rule Name | Severity | Category | Threat Type |
|---|-----------|----------|----------|-------------|
| 1 | Brute Force Attack Detection | High | Authentication | brute_force |
| 2 | Account Lockout Detection | High | Authentication | brute_force |
| 3 | Suspicious Login Activity | Medium | Authentication | unauthorized_access |
| 4 | Kerberos Pre-Authentication Failure | High | Authentication | brute_force |
| 5 | Credential Validation Attack | High | Authentication | brute_force |
| 6 | SQL Injection Detection | Critical | Web | sql_injection |
| 7 | Cross-Site Scripting (XSS) Detection | Critical | Web | xss |
| 8 | Command Injection Detection | Critical | Web | command_injection |
| 9 | Directory Traversal Detection | High | Web | unauthorized_access |
| 10 | Web Application Scanning Detection | Medium | Web | port_scan |
| 11 | Port Scan Detection | High | Network | port_scan |
| 12 | DDoS Attack Detection | Critical | Network | ddos |
| 13 | Suspicious Network Traffic Detection | Medium | Network | suspicious_traffic |
| 14 | Reverse Shell Detection | Critical | Network | reverse_shell |
| 15 | DNS Tunneling Detection | Critical | Network | dns_tunneling |
| 16 | Malware Communication Detection | Critical | Malware | malware_communication |
| 17 | Malware Detection (Generic) | Critical | Malware | malware |
| 18 | Ransomware Detection | Critical | Malware | ransomware |
| 19 | Phishing Detection | High | Malware | phishing |
| 20 | Suspicious PowerShell Activity | High | System | suspicious_powershell |
| 21 | Buffer Overflow Detection | Critical | System | privilege_escalation |
| 22 | Privilege Escalation Detection | Critical | System | privilege_escalation |
| 23 | SSH Brute Force Detection | High | Authentication | brute_force |
| 24 | Firewall Block Detection | Medium | Firewall | unauthorized_access |
| 25 | IDS/IPS Signature Match | High | IDS | malware |
| 26 | System Compromise Detection | Critical | System | unauthorized_access |
| 27 | Service Failure Detection | Medium | System | system_compromise |
| 28 | Data Exfiltration Detection | Critical | Network | data_exfiltration |
| 29 | Unauthorized Access Detection | High | Access | unauthorized_access |

---

## Custom Rule Creation

To create custom rules, use the `POST /api/v1/threat-rules` endpoint:

```bash
curl -X POST http://localhost:3000/api/v1/threat-rules \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "organization": "ORG_ID",
    "name": "Custom Rule Name",
    "description": "Custom rule description",
    "type": "signature",
    "severity": "high",
    "category": "authentication",
    "threatType": "brute_force",
    "condition": {
      "eventCategory": "authentication",
      "eventType": "Failed Login",
      "sourceIP": "192.168.1.100"
    },
    "actions": [
      {
        "type": "alert",
        "configuration": {
          "priority": "high"
        }
      }
    ],
    "enabled": true,
    "priority": 8,
    "cooldown": 60,
    "tags": ["custom", "example"]
  }'
```