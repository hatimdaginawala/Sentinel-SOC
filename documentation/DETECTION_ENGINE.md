# SentinelSOC Detection Engine Documentation

## Overview

The SentinelSOC Detection Engine is the core threat detection component of the platform. It evaluates incoming normalized logs against configured threat rules and generates alerts when matches are found.

This document explains **how** the detection engine works, not just what rules exist.

---

## Detection Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                         DETECTION ENGINE FLOW                                      │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                    1. INCOMING LOG RECEIVED                                 │   │
│  │                                                                             │   │
│  │  - Log is normalized and stored                                             │   │
│  │  - Triggered by: POST /api/v1/logs/ingest                                  │   │
│  │  - Log document contains: eventCategory, eventType, severity, sourceIP,    │   │
│  │    destinationIP, username, message, etc.                                  │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                                  │
│                                    ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                    2. LOAD ACTIVE RULES                                     │   │
│  │                                                                             │   │
│  │  - Query: ThreatRule.find({ enabled: true })                               │   │
│  │  - Rules are loaded from MongoDB                                            │   │
│  │  - Cached for performance (optional)                                       │   │
│  │  - Organization-scoped rules only (no cross-org)                          │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                                  │
│                                    ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                    3. EVALUATE EACH RULE AGAINST LOG                        │   │
│  │                                                                             │   │
│  │  For Each Active Rule:                                                      │   │
│  │  ┌──────────────────────────────────────────────────────────────────────┐  │   │
│  │  │  a. Check Cooldown                                                    │  │   │
│  │  │     - If rule.lastTriggered + cooldown > now → SKIP                 │  │   │
│  │  │                                                                       │  │   │
│  │  │  b. Evaluate Conditions                                               │  │   │
│  │  │     - Simple field comparison                                         │  │   │
│  │  │     - Logical operators ($and, $or, $not)                            │  │   │
│  │  │     - Comparison operators ($eq, $ne, $gt, $gte, $lt, $lte)         │  │   │
│  │  │     - String operators ($regex, $contains, $startsWith, $endsWith)  │  │   │
│  │  │     - Array operators ($in, $nin)                                    │  │   │
│  │  │                                                                       │  │   │
│  │  │  c. Check Suppression                                                 │  │   │
│  │  │     - If suppression enabled and threshold met → SKIP               │  │   │
│  │  └──────────────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                                  │
│                                    ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                    4. RULE MATCH?                                           │   │
│  │                                                                             │   │
│  │                         ┌─────────────┐                                    │   │
│  │                         │    MATCH?   │                                    │   │
│  │                         └──────┬──────┘                                    │   │
│  │                         ┌──────┴──────┐                                    │   │
│  │                         │             │                                    │   │
│  │                        NO            YES                                   │   │
│  │                         │             │                                    │   │
│  │                         ▼             ▼                                    │   │
│  │              ┌─────────────────┐ ┌──────────────────────────────────────┐  │   │
│  │              │    DONE        │ │      5. CREATE ALERT                  │  │   │
│  │              │  (No Alert)    │ │                                       │  │   │
│  │              └─────────────────┘ │  - Generate alert from matched rule │  │   │
│  │                                   │  - Calculate risk score             │  │   │
│  │                                   │  - Set confidence level             │  │   │
│  │                                   │  - Link to source log               │  │   │
│  │                                   │  - Save to Alerts collection        │  │   │
│  │                                   └──────────────────────────────────────┘  │   │
│  │                                   │                                         │   │
│  │                                   ▼                                         │   │
│  │                         ┌──────────────────────────────────────────────┐   │   │
│  │                         │      6. EXECUTE ACTIONS                     │   │   │
│  │                         │                                              │   │   │
│  │                         │  - alert: Create alert notification         │   │   │
│  │                         │  - block: Block source IP                   │   │   │
│  │                         │  - notify: Send notification                │   │   │
│  │                         │  - log: Already logged                     │   │   │
│  │                         │  - quarantine: Isolate asset                │   │   │
│  │                         │  - isolate: Isolate asset                   │   │   │
│  │                         └──────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                    │                                                  │
│                                    ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                    7. UPDATE RULE STATISTICS                                │   │
│  │                                                                             │   │
│  │  - rule.triggerCount += 1                                                   │   │
│  │  - rule.lastTriggered = now                                                 │   │
│  │  - Save rule statistics                                                     │   │
│  │  - Track true/false positives (manual/automated)                           │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Rule Loading

### Rule Query

When a log is ingested, the detection engine loads all enabled rules:

```javascript
// services/automationService.js
async checkThreatRules(log) {
  const rules = await ThreatRule.find({
    organization: log.organization,
    enabled: true
  });
  
  const matchedRules = [];
  const now = new Date();

  for (const rule of rules) {
    // Check cooldown
    if (this.isInCooldown(rule, now)) continue;
    
    // Check suppression
    if (this.isSuppressed(rule)) continue;
    
    // Evaluate condition
    if (this.matchesRule(log, rule)) {
      matchedRules.push(rule);
      
      // Update rule statistics
      rule.triggerCount += 1;
      rule.lastTriggered = now;
      await rule.save();
    }
  }
  
  return matchedRules;
}
```

### Rule Caching (Optional)

For performance, rules can be cached:

```javascript
// services/ruleCache.js (optional)
class RuleCache {
  constructor() {
    this.cache = new Map();
    this.lastRefresh = null;
    this.refreshInterval = 60000; // 1 minute
  }

  async getActiveRules(organizationId) {
    const cacheKey = `rules_${organizationId}`;
    const now = Date.now();
    
    if (this.cache.has(cacheKey) && 
        (now - this.lastRefresh) < this.refreshInterval) {
      return this.cache.get(cacheKey);
    }
    
    const rules = await ThreatRule.find({
      organization: organizationId,
      enabled: true
    });
    
    this.cache.set(cacheKey, rules);
    this.lastRefresh = now;
    return rules;
  }
}
```

---

## Condition Evaluation

### Condition Structure

Rules use a flexible JSON-based condition structure:

```json
{
  "condition": {
    "eventCategory": "authentication",
    "eventType": "Failed Login",
    "sourceIP": { "$exists": true },
    "$or": [
      { "severity": "high" },
      { "severity": "critical" }
    ]
  }
}
```

### Supported Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `$eq` | Equal to | `{ "severity": { "$eq": "high" } }` |
| `$ne` | Not equal to | `{ "severity": { "$ne": "info" } }` |
| `$gt` | Greater than | `{ "riskScore": { "$gt": 5 } }` |
| `$gte` | Greater than or equal | `{ "riskScore": { "$gte": 7 } }` |
| `$lt` | Less than | `{ "riskScore": { "$lt": 3 } }` |
| `$lte` | Less than or equal | `{ "riskScore": { "$lte": 2 } }` |
| `$in` | In array | `{ "severity": { "$in": ["critical", "high"] } }` |
| `$nin` | Not in array | `{ "severity": { "$nin": ["low", "info"] } }` |
| `$regex` | Regular expression | `{ "message": { "$regex": ".*attack.*" } }` |
| `$contains` | String contains | `{ "message": { "$contains": "SQL" } }` |
| `$startsWith` | String starts with | `{ "username": { "$startsWith": "admin" } }` |
| `$endsWith` | String ends with | `{ "hostname": { "$endsWith": ".com" } }` |
| `$exists` | Field exists | `{ "sourceIP": { "$exists": true } }` |
| `$and` | Logical AND | `{ "$and": [ { "a": 1 }, { "b": 2 } ] }` |
| `$or` | Logical OR | `{ "$or": [ { "a": 1 }, { "b": 2 } ] }` |
| `$not` | Logical NOT | `{ "$not": { "severity": "low" } }` |

### Evaluation Implementation

```javascript
// services/automationService.js
matchesRule(log, rule) {
  const condition = rule.condition;
  
  // Handle logical operators
  if (condition.$and) {
    return condition.$and.every(c => this.evaluateCondition(c, log));
  }
  if (condition.$or) {
    return condition.$or.some(c => this.evaluateCondition(c, log));
  }
  if (condition.$not) {
    return !this.evaluateCondition(condition.$not, log));
  }
  
  // Simple field matching
  return this.evaluateCondition(condition, log);
}

evaluateCondition(condition, log) {
  for (const [field, value] of Object.entries(condition)) {
    const logValue = this.getFieldValue(log, field);
    
    if (logValue === undefined) return false;
    
    if (typeof value === 'object' && value !== null) {
      for (const [operator, operand] of Object.entries(value)) {
        switch (operator) {
          case '$eq': return logValue === operand;
          case '$ne': return logValue !== operand;
          case '$gt': return logValue > operand;
          case '$gte': return logValue >= operand;
          case '$lt': return logValue < operand;
          case '$lte': return logValue <= operand;
          case '$in': return Array.isArray(operand) && operand.includes(logValue);
          case '$nin': return Array.isArray(operand) && !operand.includes(logValue);
          case '$regex': return new RegExp(operand, 'i').test(String(logValue));
          case '$contains': return String(logValue).includes(operand);
          case '$startsWith': return String(logValue).startsWith(operand);
          case '$endsWith': return String(logValue).endsWith(operand);
          case '$exists': return operand === true;
          default: return false;
        }
      }
    }
    
    return logValue === value;
  }
  return false;
}

getFieldValue(obj, path) {
  return path.split('.').reduce((current, key) => {
    return current && current[key] !== undefined ? current[key] : undefined;
  }, obj);
}
```

---

## Severity Handling

### Severity Levels

| Level | Value | Description |
|-------|-------|-------------|
| **Critical** | 4 | Immediate threat to confidentiality, integrity, or availability |
| **High** | 3 | Significant threat requiring prompt investigation |
| **Medium** | 2 | Moderate threat requiring investigation |
| **Low** | 1 | Minor threat or informational |
| **Info** | 0 | Informational only |

### Severity Mapping

Rule severity is mapped to a numeric value for risk calculation:

```javascript
const severityMap = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
};

const severityColorMap = {
  critical: '#dc3545',
  high: '#fd7e14',
  medium: '#ffc107',
  low: '#28a745',
  info: '#17a2b8'
};
```

### Risk Score Calculation

```javascript
// In Alert model pre-save hook
const severityMap = {
  critical: 10,
  high: 7,
  medium: 5,
  low: 3,
  info: 1
};

// Risk Score = Base severity + Priority + Confidence adjustment
this.riskScore = Math.min(
  severityMap[this.severity] + 
  (this.confidence / 100) * 5 +
  (this.priority || 0),
  10
);
```

---

## Priority

### Priority Levels

| Value | Description |
|-------|-------------|
| **10** | Highest priority – Critical threats |
| **8-9** | High priority – Severe threats |
| **5-7** | Medium priority – Standard threats |
| **3-4** | Low priority – Minor threats |
| **1-2** | Lowest priority – Informational |

### Priority Influence

Priority affects:
1. **Alert Display**: Higher priority alerts appear first
2. **Risk Score**: Priority contributes to risk score calculation
3. **Incident Creation**: Higher priority alerts are more likely to trigger incidents
4. **Notification**: Critical alerts trigger immediate notifications

---

## Cooldown

### Purpose

Prevents alert flooding when the same rule matches repeatedly in a short time.

### Implementation

```javascript
// In rule evaluation
isInCooldown(rule, now) {
  if (!rule.cooldown || rule.cooldown === 0) return false;
  if (!rule.lastTriggered) return false;
  
  const timeSinceLastTrigger = (now - rule.lastTriggered) / 1000;
  return timeSinceLastTrigger < rule.cooldown;
}

// Rule definition
{
  "cooldown": 60  // 60 seconds cooldown
}
```

### Behavior

1. First match → Alert created, `lastTriggered` updated
2. Subsequent matches within cooldown period → No alert created
3. After cooldown period expires → Alert can be created again

---

## Enabled/Disabled Rules

### Rule Status

```javascript
// Rule schema
{
  enabled: {
    type: Boolean,
    default: true,
    index: true
  }
}
```

### Toggling Rules

**Endpoint:** `PATCH /api/v1/threat-rules/:id/toggle`

```bash
curl -X PATCH http://localhost:3000/api/v1/threat-rules/:id/toggle \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": false
  }'
```

### Impact

- **Enabled**: Rule participates in detection
- **Disabled**: Rule is skipped during detection
- Disabled rules still exist in the database but are not evaluated

---

## Actions

### Action Types

| Action Type | Description | Configuration |
|-------------|-------------|---------------|
| **alert** | Create a security alert | priority, notify |
| **block** | Block the source IP | duration, source |
| **notify** | Send a notification | channel, message |
| **log** | Log the event (always performed) | None |
| **quarantine** | Quarantine the asset | duration, target |
| **isolate** | Isolate the asset | duration, target |

### Action Configuration

```javascript
// Example rule with actions
{
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
    },
    {
      "type": "notify",
      "configuration": {
        "channel": "email",
        "message": "Critical alert: ${rule.name} triggered"
      }
    }
  ]
}
```

### Action Execution

```javascript
// services/automationService.js
async executeRuleActions(rule, alert, log) {
  for (const action of rule.actions) {
    switch (action.type) {
      case 'alert':
        await this.createAlert(alert);
        break;
      case 'block':
        await this.blockSource(log, action.configuration);
        break;
      case 'notify':
        await this.sendNotification(alert, action.configuration);
        break;
      case 'quarantine':
        await this.quarantineAsset(log.asset, action.configuration);
        break;
      case 'isolate':
        await this.isolateAsset(log.asset, action.configuration);
        break;
      // 'log' is always performed (the log is already stored)
    }
  }
}
```

### Action Logging

All actions are logged in the alert's timeline:

```javascript
alert.timeline.push({
  action: action.type,
  note: `Executed ${action.type} action`,
  performedBy: 'system',
  performedAt: new Date()
});
```

---

## Alert Creation

### Alert Generation Process

```javascript
// services/automationService.js
async generateAlerts(log, matchedRules) {
  const alerts = [];
  const now = new Date();

  for (const rule of matchedRules) {
    // Check for existing alert (deduplication)
    const settings = await Settings.findOne({ 
      organization: log.organization 
    });
    const dedupWindow = settings?.detection?.alerts?.deduplication?.windowMs || 
                         5 * 60 * 1000;
    
    const existingAlert = await Alert.findOne({
      organization: log.organization,
      threatType: rule.threatType,
      sourceIP: log.sourceIP,
      status: { $in: ['active', 'investigating'] },
      createdAt: { $gte: new Date(now - dedupWindow) }
    });

    if (existingAlert) {
      // Update existing alert
      existingAlert.triggerCount = (existingAlert.triggerCount || 0) + 1;
      existingAlert.lastTriggered = now;
      await existingAlert.save();
      alerts.push(existingAlert);
      continue;
    }

    // Create new alert
    const alertData = {
      organization: log.organization,
      asset: log.asset,
      logSource: log.logSource,
      log: log._id,
      title: this.generateAlertTitle(rule, log),
      description: this.generateAlertDescription(rule, log),
      severity: rule.severity,
      category: rule.category,
      threatType: rule.threatType,
      sourceIP: log.sourceIP,
      destinationIP: log.destinationIP,
      username: log.username,
      confidence: 80,
      tags: rule.tags || [],
      createdBy: null, // System generated
      status: 'active'
    };

    const alert = new Alert(alertData);
    await alert.save();
    alerts.push(alert);

    // Add to timeline
    alert.timeline.push({
      action: 'created',
      note: `Alert generated by rule: ${rule.name}`,
      performedBy: null,
      performedAt: new Date()
    });
    await alert.save();
  }

  return alerts;
}

// Alert title generation
generateAlertTitle(rule, log) {
  const threatLabels = {
    brute_force: 'Brute Force Attack',
    sql_injection: 'SQL Injection Attempt',
    xss: 'XSS Attack',
    malware_communication: 'Malware Communication',
    port_scan: 'Port Scan Detected',
    ddos: 'DDoS Attack Detected',
    privilege_escalation: 'Privilege Escalation Attempt',
    unauthorized_access: 'Unauthorized Access Attempt'
  };

  const threatLabel = threatLabels[rule.threatType] || 
                       rule.threatType.replace(/_/g, ' ').toUpperCase();
  return `${threatLabel} - ${log.hostname || 'Unknown Host'}`;
}
```

### Alert Fields

| Field | Source | Description |
|-------|--------|-------------|
| `title` | Generated | Alert title (threat + host) |
| `description` | Generated | Detailed alert description |
| `severity` | Rule | From rule definition |
| `category` | Rule | From rule definition |
| `threatType` | Rule | From rule definition |
| `sourceIP` | Log | From normalized log |
| `destinationIP` | Log | From normalized log |
| `username` | Log | From normalized log |
| `confidence` | Rule/Log | 0-100 confidence score |
| `riskScore` | Calculated | 0-10 risk score |
| `status` | Default | "active" (initial) |

---

## Suppression

### Purpose

Suppresses alerts after a threshold of occurrences within a time window.

### Configuration

```javascript
{
  "suppression": {
    "enabled": true,
    "threshold": 5,      // Number of occurrences before suppression
    "duration": 300      // Suppression duration in seconds
  }
}
```

### Implementation

```javascript
// In rule evaluation
isSuppressed(rule) {
  if (!rule.suppression.enabled) return false;
  if (!rule.suppression.suppressUntil) return false;
  return new Date() < rule.suppression.suppressUntil;
}

// When rule triggers
async recordTrigger(rule, log) {
  rule.triggerCount += 1;
  rule.lastTriggered = new Date();
  
  // Check if should suppress
  if (rule.suppression.enabled && 
      rule.triggerCount >= rule.suppression.threshold) {
    const suppressUntil = new Date();
    suppressUntil.setSeconds(
      suppressUntil.getSeconds() + rule.suppression.duration
    );
    rule.suppression.suppressUntil = suppressUntil;
  }
  
  await rule.save();
}
```

---

## Performance Considerations

### Rule Complexity

| Complexity | Description | Performance Impact |
|------------|-------------|-------------------|
| **Simple** | Single field comparison | Minimal (fast) |
| **Medium** | Multiple fields, simple operators | Moderate |
| **Complex** | Nested logical operators, regex | Higher (slower) |

### Optimization Recommendations

1. **Index Fields**: Ensure indexed fields used in conditions
2. **Limit Regex**: Use `$regex` sparingly
3. **Order Conditions**: Put most selective conditions first
4. **Cache Rules**: Cache active rules to reduce DB queries
5. **Batch Processing**: Process logs in batches when possible

### Index Recommendations

```javascript
// For rule evaluation performance
db.threatrules.createIndex({ organization: 1, enabled: 1 });
db.threatrules.createIndex({ enabled: 1, priority: -1 });
db.threatrules.createIndex({ threatType: 1, organization: 1 });
```

---

## Error Handling

### Detection Errors

| Error Type | Handling | Recovery |
|------------|----------|----------|
| **Rule Load Failure** | Log error, continue without rules | Retry on next log |
| **Condition Evaluation Error** | Log error, skip rule | Continue with next rule |
| **Alert Creation Failure** | Log error, retry async | Manual alert creation |
| **Database Connection Lost** | Queue logs, retry | Auto-reconnect |

### Error Logging

```javascript
// services/automationService.js
try {
  // Detection logic
} catch (error) {
  console.error('❌ Detection error:', error.message);
  
  // Log to audit
  await AuditLog.create({
    organization: log.organization,
    action: 'detection_error',
    resource: 'log',
    resourceId: log._id,
    status: 'failure',
    errorMessage: error.message,
    severity: 'medium'
  });
  
  // Mark log as failed
  log.status = 'failed';
  log.processingErrors.push(error.message);
  await log.save();
}
```

---

## Detection Statistics

### Rule Performance Metrics

| Metric | Description | Tracking |
|--------|-------------|----------|
| **Trigger Count** | Number of times rule matched | `triggerCount` |
| **Last Triggered** | Timestamp of last match | `lastTriggered` |
| **True Positives** | Verified correct matches | Manual/auto |
| **False Positives** | Verified incorrect matches | Manual/auto |

### Viewing Statistics

**API Endpoint:** `GET /api/v1/threat-rules/statistics`

```bash
curl -X GET http://localhost:3000/api/v1/threat-rules/statistics \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "summary": {
      "total": 29,
      "enabled": 25,
      "disabled": 4,
      "critical": 12,
      "high": 8,
      "medium": 6,
      "low": 2,
      "info": 1,
      "avgPriority": 6.8,
      "totalTriggers": 1547,
      "avgEffectiveness": 82.5
    },
    "typeBreakdown": [
      { "_id": "signature", "count": 20 },
      { "_id": "behavioral", "count": 7 },
      { "_id": "statistical", "count": 2 }
    ],
    "categoryBreakdown": [
      { "_id": "authentication", "count": 8 },
      { "_id": "network", "count": 6 },
      { "_id": "web", "count": 5 },
      { "_id": "malware", "count": 4 },
      { "_id": "system", "count": 3 },
      { "_id": "access", "count": 2 },
      { "_id": "ids", "count": 1 }
    ]
  }
}
```

---

## Summary

| Component | Description |
|-----------|-------------|
| **Rule Loading** | Fetches enabled rules from database |
| **Condition Evaluation** | Compares log fields against rule conditions |
| **Severity** | Maps rule severity to numeric risk value |
| **Priority** | Influences alert display and risk score |
| **Cooldown** | Prevents alert flooding |
| **Suppression** | Temporarily silences rules after threshold |
| **Actions** | Executes configured actions (alert, block, notify, quarantine, isolate) |
| **Alert Creation** | Generates security alerts from rule matches |
| **Error Handling** | Logs errors and continues processing |

---

## Quick Reference

### Rule Template

```json
{
  "name": "Rule Name",
  "description": "Rule Description",
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
  "suppression": {
    "enabled": true,
    "threshold": 5,
    "duration": 300
  },
  "tags": ["tag1", "tag2"]
}
```

### Debugging Detection

1. **Check Rule Status**: `db.threatrules.find({ enabled: true })`
2. **View Rule Triggers**: `db.threatrules.find({}, { name: 1, triggerCount: 1 })`
3. **View Recent Alerts**: `db.alerts.find().sort({ createdAt: -1 }).limit(10)`
4. **Enable Debug Logging**: `LOG_LEVEL=debug`
5. **Test Rule with Log**: Manually create log and observe detection

### Common Detection Issues

| Issue | Likely Cause | Solution |
|-------|--------------|----------|
| Rule not triggering | Condition doesn't match log | Review condition and log fields |
| Too many alerts | Cooldown not configured | Add cooldown to rule |
| False positives | Condition too broad | Narrow condition or add more fields |
| No alerts | Rules disabled | Check `enabled: true` |
| Slow detection | Complex conditions | Optimize conditions, add indexes |