// services/automationService.js
const Log = require('../models/Log');
const Alert = require('../models/Alert');
const Incident = require('../models/Incident');
const IOC = require('../models/IOC');
const ThreatRule = require('../models/ThreatRule');
const Report = require('../models/Report');
const AuditLog = require('../models/AuditLog');
const Settings = require('../models/Settings');
const AlertService = require('./alertService');
const IncidentService = require('./incidentService');
const IOCService = require('./iocService');
const logger = require('../config/logger');

class AutomationService {
  /**
   * Main automation pipeline - called when a log is ingested
   */
 async processLog(log) {
    try {
      logger.info(` Processing log: ${log._id} - ${log.eventType || 'unknown'} - Org: ${log.organization}`);
      
      // Step 1: Check against threat rules (for ALL organizations)
      const matchedRules = await this.checkThreatRules(log);
      
      if (matchedRules.length === 0) {
        // No match - mark log as processed
        await this.markLogProcessed(log);
        return null;
      }

      // Step 2: Generate alerts from matched rules
      const alerts = await this.generateAlerts(log, matchedRules);
      
      // Step 3: Check for IOC matches
      const matchedIOCs = await this.checkIOCMatches(log);
      if (matchedIOCs.length > 0) {
        await this.linkIOCsToAlerts(alerts, matchedIOCs);
      }

      // Step 4: Check if alerts should be escalated to incidents
      const incidents = await this.checkIncidentCreation(alerts);

      // Step 5: Auto-resolve incidents if conditions met
      await this.autoResolveIncidents(incidents);

      // Step 6: Update threat intelligence
      await this.updateThreatIntelligence(log, alerts);

      // Step 7: Create audit log
      await this.createAuditLog(log, alerts, incidents);

      // Mark log as processed
      await this.markLogProcessed(log);

      return {
        alerts,
        incidents,
        matchedIOCs,
        matchedRules
      };
    } catch (error) {
      logger.error(' Error in automation pipeline:', error.message);
      // Don't throw - just log the error so the log ingestion continues
      return null;
    }
  }

  /**
   * Step 1: Check log against threat rules
   */
 async checkThreatRules(log) {
    // Get ALL enabled rules (not filtered by organization)
    const rules = await ThreatRule.find({
      enabled: true
      // organization: log.organization // REMOVE THIS LINE if it exists
    });

    const matchedRules = [];
    const now = new Date();

    for (const rule of rules) {
      // Check if rule is in cooldown
      if (rule.cooldown > 0 && rule.lastTriggered) {
        const timeSinceLastTrigger = (now - rule.lastTriggered) / 1000;
        if (timeSinceLastTrigger < rule.cooldown) {
          continue;
        }
      }

      // Check if rule matches
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

  /**
   * Check if log matches a rule condition
   */
  matchesRule(log, rule) {
    const condition = rule.condition;
    
    // Handle different condition types
    if (condition.$and) {
      return condition.$and.every(c => this.evaluateCondition(c, log));
    }
    if (condition.$or) {
      return condition.$or.some(c => this.evaluateCondition(c, log));
    }
    if (condition.$not) {
      return !this.evaluateCondition(condition.$not, log);
    }
    
    // Simple field matching
    return this.evaluateCondition(condition, log);
  }

  /**
   * Evaluate a single condition
   */
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
            default: return false;
          }
        }
      }
      
      return logValue === value;
    }
    return false;
  }

  /**
   * Get nested field value from object
   */
  getFieldValue(obj, path) {
    return path.split('.').reduce((current, key) => {
      return current && current[key] !== undefined ? current[key] : undefined;
    }, obj);
  }

  /**
   * Step 2: Generate alerts from matched rules
   */
  async generateAlerts(log, matchedRules) {
    const alerts = [];
    const now = new Date();

    for (const rule of matchedRules) {
      // Check for existing alert (deduplication)
      const settings = await Settings.findOne({ organization: log.organization });
      const dedupWindow = settings?.detection?.alerts?.deduplication?.windowMs || 5 * 60 * 1000;
      
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

      const alert = await AlertService.createAlertFromLog(log._id, alertData, null);
      alerts.push(alert);

      // Execute rule actions
      await this.executeRuleActions(rule, alert, log);
    }

    return alerts;
  }

  /**
   * Generate alert title from rule and log
   */
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

    const threatLabel = threatLabels[rule.threatType] || rule.threatType.replace(/_/g, ' ').toUpperCase();
    return `${threatLabel} - ${log.hostname || 'Unknown Host'}`;
  }

  /**
   * Generate alert description from rule and log
   */
  generateAlertDescription(rule, log) {
    let description = `${rule.description || rule.name}\n`;
    description += `\nDetails:\n`;
    description += `- Source: ${log.sourceIP || 'Unknown'}\n`;
    description += `- Destination: ${log.destinationIP || 'Unknown'}\n`;
    description += `- Username: ${log.username || 'Unknown'}\n`;
    description += `- Message: ${log.message || 'No message'}`;
    return description;
  }

  /**
   * Execute rule actions (alert, block, notify, isolate)
   */
  async executeRuleActions(rule, alert, log) {
    for (const action of rule.actions) {
      switch (action.type) {
        case 'block':
          await this.blockSource(log, action.configuration);
          break;
        case 'notify':
          await this.sendNotification(alert, action.configuration);
          break;
        case 'isolate':
          await this.isolateAsset(log.asset, action.configuration);
          break;
        case 'log':
          // Log is already being stored
          break;
        default:
          break;
      }
    }
  }

  /**
   * Step 3: Check IOC matches
   */
  async checkIOCMatches(log) {
    const iocs = await IOC.find({
      organization: log.organization,
      status: 'active'
    });

    const matchedIOCs = [];
    for (const ioc of iocs) {
      if (this.iocMatchesLog(ioc, log)) {
        matchedIOCs.push(ioc);
        // Record occurrence
        await IOCService.recordOccurrence(ioc._id, log.sourceIP);
      }
    }

    return matchedIOCs;
  }

  /**
   * Check if IOC matches log data
   */
  iocMatchesLog(ioc, log) {
    const values = [log.sourceIP, log.destinationIP, log.username, log.hostname, log.message];
    
    for (const value of values) {
      if (!value) continue;
      if (ioc.matches(value)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Link IOCs to alerts
   */
  async linkIOCsToAlerts(alerts, iocs) {
    for (const alert of alerts) {
      for (const ioc of iocs) {
        if (!alert.iocs) alert.iocs = [];
        if (!alert.iocs.includes(ioc._id)) {
          await IOCService.linkToAlert(ioc._id, alert._id);
          alert.iocs.push(ioc._id);
        }
      }
      await alert.save();
    }
  }

  /**
   * Step 4: Check if alerts should create incidents
   */
  async checkIncidentCreation(alerts) {
    const incidents = [];
    const now = new Date();

    // Group alerts by source IP and threat type
    const groupedAlerts = {};
    for (const alert of alerts) {
      const key = `${alert.sourceIP}-${alert.threatType}`;
      if (!groupedAlerts[key]) {
        groupedAlerts[key] = [];
      }
      groupedAlerts[key].push(alert);
    }

    // Check each group
    for (const [key, alertGroup] of Object.entries(groupedAlerts)) {
      // Check if there are enough alerts to create an incident
      const settings = await Settings.findOne({ organization: alertGroup[0].organization });
      const threshold = settings?.detection?.alerts?.deduplication?.threshold || 3;

      if (alertGroup.length >= threshold) {
        // Check if incident already exists
        const existingIncident = await Incident.findOne({
          organization: alertGroup[0].organization,
          alerts: { $in: alertGroup.map(a => a._id) },
          status: { $in: ['new', 'investigating', 'in_progress'] }
        });

        if (existingIncident) {
          // Update existing incident
          for (const alert of alertGroup) {
            if (!existingIncident.alerts.includes(alert._id)) {
              existingIncident.alerts.push(alert._id);
            }
          }
          await existingIncident.save();
          incidents.push(existingIncident);
        } else {
          // Create new incident
          const incidentData = {
            organization: alertGroup[0].organization,
            title: this.generateIncidentTitle(alertGroup),
            description: this.generateIncidentDescription(alertGroup),
            severity: this.calculateIncidentSeverity(alertGroup),
            category: this.calculateIncidentCategory(alertGroup),
            alerts: alertGroup.map(a => a._id),
            detectionSource: 'automated',
            discoveredAt: now,
            status: 'new'
          };

          const incident = await IncidentService.createIncident(incidentData, null);
          incidents.push(incident);

          // Auto-assign if configured
          await this.autoAssignIncident(incident);

          // Send notification
          await this.sendIncidentNotification(incident);
        }
      }
    }

    return incidents;
  }

  /**
   * Generate incident title from alerts
   */
  generateIncidentTitle(alerts) {
    const threatTypes = alerts.map(a => a.threatType);
    const mostCommon = this.getMostCommon(threatTypes);
    const labels = {
      brute_force: 'Brute Force Campaign',
      sql_injection: 'SQL Injection Campaign',
      xss: 'XSS Campaign',
      malware_communication: 'Malware Campaign',
      port_scan: 'Reconnaissance Campaign',
      ddos: 'DDoS Campaign'
    };
    return labels[mostCommon] || `${mostCommon?.replace(/_/g, ' ').toUpperCase() || 'Security'} Incident`;
  }

  /**
   * Generate incident description from alerts
   */
  generateIncidentDescription(alerts) {
    const sources = [...new Set(alerts.map(a => a.sourceIP))];
    const victims = [...new Set(alerts.map(a => a.destinationIP))];
    
    return `Security incident involving ${alerts.length} alerts\n` +
           `- Affected Sources: ${sources.join(', ')}\n` +
           `- Affected Targets: ${victims.join(', ')}\n` +
           `- First Alert: ${new Date(Math.min(...alerts.map(a => a.createdAt))).toISOString()}\n` +
           `- Last Alert: ${new Date(Math.max(...alerts.map(a => a.createdAt))).toISOString()}`;
  }

  /**
   * Calculate incident severity
   */
  calculateIncidentSeverity(alerts) {
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const maxSeverity = alerts.reduce((max, a) => {
      return severityOrder[a.severity] > severityOrder[max] ? a.severity : max;
    }, 'low');
    return maxSeverity;
  }

  /**
   * Calculate incident category
   */
  calculateIncidentCategory(alerts) {
    const categories = alerts.map(a => a.category);
    return this.getMostCommon(categories);
  }

  /**
   * Get most common item in array
   */
  getMostCommon(arr) {
    const counts = {};
    let maxCount = 0;
    let maxItem = arr[0];
    
    for (const item of arr) {
      counts[item] = (counts[item] || 0) + 1;
      if (counts[item] > maxCount) {
        maxCount = counts[item];
        maxItem = item;
      }
    }
    return maxItem;
  }

  /**
   * Auto-assign incident to analyst
   */
  async autoAssignIncident(incident) {
    // Find least busy analyst
    const analysts = await User.find({
      role: { $in: ['soc_analyst', 'incident_responder'] },
      status: 'active'
    });

    if (analysts.length === 0) return;

    // Get incident count per analyst
    const counts = {};
    for (const analyst of analysts) {
      counts[analyst._id] = await Incident.countDocuments({
        assignedTo: analyst._id,
        status: { $in: ['new', 'investigating', 'in_progress'] }
      });
    }

    // Find analyst with least incidents
    let minCount = Infinity;
    let selectedAnalyst = analysts[0];
    for (const analyst of analysts) {
      if (counts[analyst._id] < minCount) {
        minCount = counts[analyst._id];
        selectedAnalyst = analyst;
      }
    }

    await IncidentService.assignIncident(incident._id, selectedAnalyst._id, null);
  }

  /**
   * Step 5: Auto-resolve incidents
   */
  async autoResolveIncidents(incidents) {
    for (const incident of incidents) {
      const settings = await Settings.findOne({ organization: incident.organization });
      const autoResolveEnabled = settings?.detection?.alerts?.autoResolution?.enabled || false;
      
      if (!autoResolveEnabled) continue;

      const timeout = settings?.detection?.alerts?.autoResolution?.timeout || 24; // hours
      const ageInHours = (Date.now() - incident.createdAt) / (1000 * 60 * 60);

      if (ageInHours >= timeout) {
        // Check if all alerts are resolved
        const unresolvedAlerts = await Alert.find({
          _id: { $in: incident.alerts },
          status: { $ne: 'resolved' }
        });

        if (unresolvedAlerts.length === 0) {
          await IncidentService.resolveIncident(
            incident._id,
            null,
            'contained',
            'Auto-resolved after all alerts were resolved',
            [],
            'Automated resolution'
          );
        } else {
          // Escalate if too old
          if (ageInHours >= timeout * 2) {
            await IncidentService.escalateIncident(
              incident._id,
              null,
              null,
              'Auto-escalated due to timeout'
            );
          }
        }
      }
    }
  }

  /**
   * Step 6: Update threat intelligence
   */
  async updateThreatIntelligence(log, alerts) {
    // Check if any new indicators should be added as IOCs
    for (const alert of alerts) {
      if (alert.severity === 'critical' && alert.confidence > 90) {
        // Check if IOC already exists
        const existingIOC = await IOC.findOne({
          organization: log.organization,
          type: 'ip',
          value: alert.sourceIP
        });

        if (!existingIOC) {
          // Create new IOC
          await IOCService.createIOC({
            organization: log.organization,
            type: 'ip',
            value: alert.sourceIP,
            indicator: alert.sourceIP,
            description: `Auto-generated from alert: ${alert.title}`,
            severity: alert.severity,
            confidence: alert.confidence,
            source: 'automated',
            threatType: alert.threatType,
            tags: ['auto_generated', alert.threatType]
          }, null);
        }
      }
    }
  }

  /**
   * Step 7: Check report schedules
   */
  async checkReportSchedules() {
    const now = new Date();
    
    // Find scheduled reports that need to run
    const scheduledReports = await Report.find({
      'scheduled.enabled': true,
      'scheduled.nextRun': { $lte: now }
    });

    for (const report of scheduledReports) {
      // Generate report
      await ReportService.generateReportData(report._id);
      
      // Update next run
      report.scheduled.lastRun = now;
      report.scheduled.nextRun = this.calculateNextRun(report.scheduled);
      await report.save();
    }
  }

  /**
   * Calculate next run time for scheduled report
   */
  calculateNextRun(schedule) {
    const now = new Date();
    const [hours, minutes] = (schedule.time || '09:00').split(':').map(Number);
    const nextRun = new Date(now);
    nextRun.setHours(hours, minutes, 0, 0);

    switch (schedule.frequency) {
      case 'daily':
        if (nextRun <= now) nextRun.setDate(nextRun.getDate() + 1);
        break;
      case 'weekly':
        const targetDay = schedule.dayOfWeek || 1;
        while (nextRun.getDay() !== targetDay) {
          nextRun.setDate(nextRun.getDate() + 1);
        }
        if (nextRun <= now) nextRun.setDate(nextRun.getDate() + 7);
        break;
      case 'monthly':
        const targetDate = schedule.dayOfMonth || 1;
        nextRun.setDate(targetDate);
        if (nextRun <= now) nextRun.setMonth(nextRun.getMonth() + 1);
        break;
      case 'quarterly':
        nextRun.setMonth(Math.floor(now.getMonth() / 3) * 3 + 3);
        if (nextRun <= now) nextRun.setMonth(nextRun.getMonth() + 3);
        break;
    }

    return nextRun;
  }

  /**
   * Step 8: Create audit log
   */
  async createAuditLog(log, alerts, incidents) {
    const auditData = {
      organization: log.organization,
      user: null,
      action: 'log_processed',
      resource: 'log',
      resourceId: log._id,
      resourceName: log.eventType,
      status: 'success',
      severity: alerts.length > 0 ? 'medium' : 'info',
      details: {
        matchedRules: alerts.length,
        incidentsCreated: incidents.length,
        logSource: log.sourceType
      }
    };

    await AuditLog.create(auditData);
  }

  /**
   * Mark log as processed
   */
  async markLogProcessed(log) {
    log.status = 'processed';
    await log.save();
  }

  /**
   * Block source (implement based on your infrastructure)
   */
  async blockSource(log, config) {
    // Implementation depends on your firewall/network infrastructure
    logger.info(`Blocking source: ${log.sourceIP} for ${config.duration || 300}s`);
    // Add to blocklist, update firewall rules, etc.
  }

  /**
   * Send notification (email, slack, teams)
   */
  async sendNotification(alert, config) {
    // Implementation depends on your notification system
    logger.info(`Sending notification for alert: ${alert._id}`);
  }

  /**
   * Isolate asset (quarantine)
   */
  async isolateAsset(assetId, config) {
    // Implementation depends on your infrastructure
    logger.info(`Isolating asset: ${assetId}`);
  }

  /**
   * Send incident notification
   */
  async sendIncidentNotification(incident) {
    logger.info(`Incident created: ${incident.title}`);
    // Send to assigned analyst, notify team, etc.
  }
}

module.exports = new AutomationService();