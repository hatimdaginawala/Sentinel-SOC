const Log = require('../models/Log');
const LogSource = require('../models/LogSource');
const Organization = require('../models/Organization');
const Asset = require('../models/Asset');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');
const logger = require('../config/logger');

class LogService {
  /**
   * Ingest a log from a log source
   * This is the main entry point for log ingestion
   */
  async ingestLog(sourceId, authToken, rawLogData) {
    try {
      // Validate log source
      const logSource = await LogSource.findById(sourceId).select('+authenticationToken');
      
      if (!logSource) {
        throw new AppError('Log source not found', HTTP_STATUS.NOT_FOUND, 'LOG_SOURCE_NOT_FOUND');
      }

      // Check if source is active
      if (!logSource.isActive()) {
        throw new AppError('Log source is not active', HTTP_STATUS.FORBIDDEN, 'LOG_SOURCE_INACTIVE');
      }

      // Validate token
      if (!logSource.validateToken(authToken)) {
        throw new AppError('Invalid authentication token', HTTP_STATUS.UNAUTHORIZED, 'INVALID_TOKEN');
      }

      // Update heartbeat
      await logSource.updateHeartbeat();

      // Normalize the log
      const normalizedLog = this.normalizeLog(rawLogData, logSource);

      // Create log document
      const log = new Log(normalizedLog);
      await log.save();

      logger.debug(`Log ingested: ${log.eventType} from ${logSource.sourceName}`);

      return log;
    } catch (error) {
      logger.error('Error ingesting log:', error);
      throw error;
    }
  }

  /**
   * Normalize raw log data into standard log schema
   */
  normalizeLog(rawLog, logSource) {
    // Extract basic fields
    const eventTime = rawLog.eventTime || rawLog.timestamp || rawLog.time || new Date();
    const message = rawLog.message || rawLog.msg || rawLog.log || '';

    // Determine event category based on source type and event type
    const eventCategory = this.determineEventCategory(rawLog, logSource);
    
    // Determine severity
    const severity = this.determineSeverity(rawLog);

    // Normalize based on source type
    let normalized = {
      organization: logSource.organization,
      asset: logSource.asset,
      logSource: logSource._id,
      sourceType: logSource.sourceType,
      hostname: rawLog.hostname || logSource.hostname || rawLog.host || '',
      ipAddress: rawLog.ipAddress || logSource.ipAddress || rawLog.ip || '',
      eventCategory: eventCategory,
      eventType: rawLog.eventType || rawLog.type || rawLog.event || 'unknown',
      severity: severity,
      username: rawLog.username || rawLog.user || rawLog.userName || '',
      processName: rawLog.processName || rawLog.process || rawLog.proc || '',
      sourceIP: rawLog.sourceIP || rawLog.srcIP || rawLog.src_ip || rawLog.source_ip || '',
      destinationIP: rawLog.destinationIP || rawLog.destIP || rawLog.dst_ip || rawLog.dest_ip || '',
      destinationPort: rawLog.destinationPort || rawLog.destPort || rawLog.dst_port || rawLog.dest_port || 0,
      protocol: rawLog.protocol || rawLog.proto || '',
      message: message,
      rawLog: rawLog,
      normalizedData: {},
      eventTime: new Date(eventTime),
      status: 'processed'
    };

    // Add source-type specific normalization
    switch(logSource.sourceType) {
      case 'Windows':
        normalized = this.normalizeWindowsLog(normalized, rawLog);
        break;
      case 'Linux':
        normalized = this.normalizeLinuxLog(normalized, rawLog);
        break;
      case 'Apache':
        normalized = this.normalizeApacheLog(normalized, rawLog);
        break;
      case 'Nginx':
        normalized = this.normalizeNginxLog(normalized, rawLog);
        break;
      case 'Suricata': {
        const SuricataParser = require('../utils/SuricataParser');
        const parsed = SuricataParser.parse(rawLog, logSource.organization, logSource.asset, logSource._id);
        if (parsed) {
          normalized = parsed;
        } else {
          normalized = this.normalizeSuricataLog(normalized, rawLog);
        }
        break;
      }
      case 'Zeek': {
        const ZeekParser = require('../utils/ZeekParser');
        const parsed = ZeekParser.parse(rawLog, rawLog.event_type || rawLog.type || rawLog._path || 'unknown', logSource.organization, logSource.asset, logSource._id);
        if (parsed) {
          normalized = parsed;
        }
        break;
      }
      case 'Snort':
        normalized = this.normalizeSnortLog(normalized, rawLog);
        break;
      case 'pfSense':
        normalized = this.normalizeFirewallLog(normalized, rawLog);
        break;
      case 'Node Application':
        normalized = this.normalizeApplicationLog(normalized, rawLog);
        break;
      default:
        // Custom - just use as is
        break;
    }

    // Add tags
    normalized.tags = this.generateTags(normalized);

    return normalized;
  }

  /**
   * Determine event category based on log data
   */
  determineEventCategory(rawLog, logSource) {
    // Check for specific event types
    const eventType = (rawLog.eventType || rawLog.type || rawLog.event || '').toLowerCase();
    const message = (rawLog.message || rawLog.msg || '').toLowerCase();

    // Authentication events
    if (eventType.includes('login') || eventType.includes('auth') || eventType.includes('authentication') ||
        message.includes('login') || message.includes('auth') || message.includes('authenticated')) {
      return 'authentication';
    }

    // Network events
    if (eventType.includes('connection') || eventType.includes('network') || 
        message.includes('connection') || message.includes('network')) {
      return 'network';
    }

    // Web events
    if (eventType.includes('http') || eventType.includes('request') || eventType.includes('response') ||
        message.includes('http') || message.includes('request') || message.includes('response')) {
      return 'web';
    }

    // Database events
    if (eventType.includes('db') || eventType.includes('database') || eventType.includes('sql') ||
        message.includes('database') || message.includes('sql')) {
      return 'database';
    }

    // Malware events
    if (eventType.includes('malware') || eventType.includes('virus') || eventType.includes('trojan') ||
        message.includes('malware') || message.includes('virus') || message.includes('trojan')) {
      return 'malware';
    }

    // Application events
    if (eventType.includes('app') || eventType.includes('application') || eventType.includes('error') ||
        message.includes('application') || message.includes('error')) {
      return 'application';
    }

    // System events
    if (eventType.includes('system') || eventType.includes('kernel') || eventType.includes('service') ||
        message.includes('system') || message.includes('kernel') || message.includes('service')) {
      return 'system';
    }

    // Policy events
    if (eventType.includes('policy') || eventType.includes('rule') || eventType.includes('compliance') ||
        message.includes('policy') || message.includes('rule') || message.includes('compliance')) {
      return 'policy';
    }

    // Access events
    if (eventType.includes('access') || eventType.includes('permission') || eventType.includes('authorization') ||
        message.includes('access') || message.includes('permission') || message.includes('authorization')) {
      return 'access';
    }

    // Default to system
    return 'system';
  }

  /**
   * Determine severity based on log data
   */
  determineSeverity(rawLog) {
    // Check if severity is provided
    if (rawLog.severity) {
      const severity = rawLog.severity.toLowerCase();
      if (['critical', 'high', 'medium', 'low', 'info'].includes(severity)) {
        return severity;
      }
      // Map other severity names
      if (severity === 'emergency' || severity === 'alert' || severity === 'emerg') return 'critical';
      if (severity === 'error' || severity === 'err') return 'high';
      if (severity === 'warning' || severity === 'warn') return 'medium';
      if (severity === 'notice') return 'low';
      if (severity === 'debug' || severity === 'trace') return 'info';
    }

    // Check message content
    const message = (rawLog.message || rawLog.msg || '').toLowerCase();
    if (message.includes('emergency') || message.includes('critical') || message.includes('fatal')) return 'critical';
    if (message.includes('error') || message.includes('failed') || message.includes('attack')) return 'high';
    if (message.includes('warning') || message.includes('attempt') || message.includes('suspicious')) return 'medium';
    if (message.includes('notice') || message.includes('info')) return 'low';

    // Check event type
    const eventType = (rawLog.eventType || rawLog.type || '').toLowerCase();
    if (eventType.includes('error') || eventType.includes('failed') || eventType.includes('attack')) return 'high';
    if (eventType.includes('warning') || eventType.includes('suspicious')) return 'medium';

    return 'info';
  }

  /**
   * Normalize Windows logs
   */
  normalizeWindowsLog(normalized, rawLog) {
    // Map Windows event IDs to event types
    const eventIdMap = {
      '4624': 'Successful Login',
      '4625': 'Failed Login',
      '4634': 'Logoff',
      '4647': 'User Initiated Logoff',
      '4740': 'Account Locked',
      '4720': 'User Created',
      '4722': 'User Enabled',
      '4723': 'Password Changed',
      '4724': 'Password Reset',
      '4725': 'User Disabled',
      '4726': 'User Deleted',
      '4732': 'Member Added',
      '4733': 'Member Removed',
      '4767': 'User Unlocked',
      '4771': 'Kerberos Pre-Authentication Failed',
      '4776': 'Credential Validation'
    };

    if (rawLog.eventId && eventIdMap[rawLog.eventId]) {
      normalized.eventType = eventIdMap[rawLog.eventId];
      
      // Set severity based on event ID
      if (['4625', '4740', '4771', '4776'].includes(rawLog.eventId)) {
        normalized.severity = 'high';
      } else if (['4725', '4726'].includes(rawLog.eventId)) {
        normalized.severity = 'medium';
      }
    }

    return normalized;
  }

  /**
   * Normalize Linux logs
   */
  normalizeLinuxLog(normalized, rawLog) {
    // Map Linux event types
    if (rawLog.eventType) {
      if (rawLog.eventType.includes('sudo') || rawLog.eventType.includes('sudo_session')) {
        normalized.eventType = 'sudo Execution';
        normalized.eventCategory = 'access';
      } else if (rawLog.eventType.includes('ssh')) {
        if (rawLog.eventType.includes('failed')) {
          normalized.eventType = 'Failed SSH Login';
          normalized.severity = 'high';
        } else {
          normalized.eventType = 'SSH Login';
        }
        normalized.eventCategory = 'authentication';
      }
    }

    return normalized;
  }

  /**
   * Normalize Apache logs
   */
  normalizeApacheLog(normalized, rawLog) {
    // Map Apache log patterns
    if (rawLog.status) {
      const status = parseInt(rawLog.status);
      if (status >= 400 && status < 500) {
        normalized.severity = 'medium';
        if (status === 404) {
          normalized.eventType = '404 Not Found';
        }
      } else if (status >= 500) {
        normalized.severity = 'high';
        normalized.eventType = '500 Server Error';
      } else if (status >= 200 && status < 300) {
        normalized.eventType = 'Successful Request';
      }
    }

    // Check for SQL injection in URI
    if (rawLog.uri && rawLog.uri.includes('sql')) {
      normalized.eventType = 'SQL Injection Attempt';
      normalized.severity = 'critical';
      normalized.eventCategory = 'web';
    }

    return normalized;
  }

  /**
   * Normalize Nginx logs
   */
  normalizeNginxLog(normalized, rawLog) {
    // Similar to Apache
    if (rawLog.status) {
      const status = parseInt(rawLog.status);
      if (status >= 400 && status < 500) {
        normalized.severity = 'medium';
        if (status === 404) {
          normalized.eventType = '404 Not Found';
        }
      } else if (status >= 500) {
        normalized.severity = 'high';
        normalized.eventType = '500 Server Error';
      } else if (status >= 200 && status < 300) {
        normalized.eventType = 'Successful Request';
      }
    }

    return normalized;
  }

  /**
   * Normalize Suricata logs
   */
  normalizeSuricataLog(normalized, rawLog) {
    if (rawLog.alert) {
      normalized.eventType = rawLog.alert.signature || 'Suricata Alert';
      normalized.severity = 'critical';
      normalized.eventCategory = 'malware';
      
      if (rawLog.alert.signature && rawLog.alert.signature.includes('SQL')) {
        normalized.eventType = 'SQL Injection';
        normalized.eventCategory = 'web';
      } else if (rawLog.alert.signature && rawLog.alert.signature.includes('XSS')) {
        normalized.eventType = 'XSS Attack';
        normalized.eventCategory = 'web';
      } else if (rawLog.alert.signature && rawLog.alert.signature.includes('Command')) {
        normalized.eventType = 'Command Injection';
        normalized.eventCategory = 'web';
      }
    }

    return normalized;
  }

  /**
   * Normalize Snort logs
   */
  normalizeSnortLog(normalized, rawLog) {
    if (rawLog.alert) {
      normalized.eventType = rawLog.alert.signature || 'Snort Alert';
      normalized.severity = 'critical';
      normalized.eventCategory = 'network';
      
      if (rawLog.alert.signature && rawLog.alert.signature.includes('Port Scan')) {
        normalized.eventType = 'Port Scan';
        normalized.eventCategory = 'network';
      } else if (rawLog.alert.signature && rawLog.alert.signature.includes('DOS')) {
        normalized.eventType = 'DOS Attack';
        normalized.eventCategory = 'network';
      } else if (rawLog.alert.signature && rawLog.alert.signature.includes('Suspicious')) {
        normalized.eventType = 'Suspicious Traffic';
        normalized.eventCategory = 'network';
      }
    }

    return normalized;
  }

  /**
   * Normalize Firewall (pfSense) logs
   */
  normalizeFirewallLog(normalized, rawLog) {
    if (rawLog.action) {
      if (rawLog.action === 'block') {
        normalized.eventType = 'Connection Blocked';
        normalized.severity = 'medium';
      } else if (rawLog.action === 'pass') {
        normalized.eventType = 'Connection Allowed';
        normalized.severity = 'low';
      }
      normalized.eventCategory = 'network';
    }

    return normalized;
  }

  /**
   * Normalize Application logs
   */
  normalizeApplicationLog(normalized, rawLog) {
    if (rawLog.eventType) {
      if (rawLog.eventType.includes('login') || rawLog.eventType.includes('auth')) {
        normalized.eventCategory = 'authentication';
        if (rawLog.eventType.includes('failed')) {
          normalized.severity = 'high';
        }
      } else if (rawLog.eventType.includes('payment') || rawLog.eventType.includes('transaction')) {
        normalized.eventCategory = 'application';
        if (rawLog.eventType.includes('failed') || rawLog.eventType.includes('error')) {
          normalized.severity = 'high';
        }
      } else if (rawLog.eventType.includes('api') || rawLog.eventType.includes('error')) {
        normalized.eventCategory = 'application';
        if (rawLog.eventType.includes('error') || rawLog.status >= 400) {
          normalized.severity = 'medium';
        }
      }
    }

    return normalized;
  }

  /**
   * Generate tags for a log
   */
  generateTags(log) {
    const tags = [];

    // Add severity tag
    tags.push(log.severity);

    // Add category tag
    tags.push(log.eventCategory);

    // Add source type tag
    tags.push(log.sourceType);

    // Add event type if important
    if (log.eventType && ['Failed Login', 'SQL Injection', 'Port Scan', 'Malware'].includes(log.eventType)) {
      tags.push('critical_event');
    }

    // Add source IP tag if present
    if (log.sourceIP) {
      tags.push('source_tracked');
    }

    return tags;
  }

  /**
   * Get logs with pagination and filtering
   */
  async getLogs(filters = {}) {
    try {
      const result = await Log.getLogs(filters);
      return result;
    } catch (error) {
      logger.error('Error getting logs:', error);
      throw error;
    }
  }

  /**
   * Get log by ID
   */
  async getLogById(logId) {
    try {
      const log = await Log.getWithPopulated(logId);
      
      if (!log) {
        throw new AppError('Log not found', HTTP_STATUS.NOT_FOUND, 'LOG_NOT_FOUND');
      }

      return log;
    } catch (error) {
      logger.error('Error getting log:', error);
      throw error;
    }
  }

  /**
   * Get logs by organization
   */
  async getLogsByOrganization(organizationId, options = {}) {
    try {
      const result = await Log.findByOrganization(organizationId, options);
      return result;
    } catch (error) {
      logger.error('Error getting logs by organization:', error);
      throw error;
    }
  }

  /**
   * Get logs by log source
   */
  async getLogsByLogSource(logSourceId, options = {}) {
    try {
      const result = await Log.findByLogSource(logSourceId, options);
      return result;
    } catch (error) {
      logger.error('Error getting logs by log source:', error);
      throw error;
    }
  }

  /**
   * Get log statistics
   */
  async getLogStatistics(organizationId = null, timeRange = '24h') {
    try {
      const stats = await Log.getStatistics(organizationId, timeRange);
      return stats;
    } catch (error) {
      logger.error('Error getting log statistics:', error);
      throw error;
    }
  }

  /**
   * Delete log
   */
  async deleteLog(logId, deletedBy) {
    try {
      const log = await Log.findById(logId);
      
      if (!log) {
        throw new AppError('Log not found', HTTP_STATUS.NOT_FOUND, 'LOG_NOT_FOUND');
      }

      await log.remove();

      logger.info(`Log deleted: ${log._id} by ${deletedBy}`);

      return { success: true, message: 'Log deleted successfully' };
    } catch (error) {
      logger.error('Error deleting log:', error);
      throw error;
    }
  }

  /**
   * Delete old logs
   */
  async deleteOldLogs(retentionDays = 90) {
    try {
      const result = await Log.deleteOldLogs(retentionDays);
      logger.info(`Deleted ${result.deletedCount} old logs (older than ${retentionDays} days)`);
      return result;
    } catch (error) {
      logger.error('Error deleting old logs:', error);
      throw error;
    }
  }

  /**
   * Get event categories for dropdown
   */
  getEventCategories() {
    return [
      'authentication', 'network', 'system', 'application', 'database',
      'web', 'malware', 'policy', 'access', 'error'
    ].map(category => ({
      value: category,
      label: category.charAt(0).toUpperCase() + category.slice(1)
    }));
  }

  /**
   * Get severities for dropdown
   */
  getSeverities() {
    return ['critical', 'high', 'medium', 'low', 'info'].map(severity => ({
      value: severity,
      label: severity.charAt(0).toUpperCase() + severity.slice(1)
    }));
  }

  /**
   * Get statuses for dropdown
   */
  getStatuses() {
    return ['processed', 'failed', 'pending'].map(status => ({
      value: status,
      label: status.charAt(0).toUpperCase() + status.slice(1)
    }));
  }
}

module.exports = new LogService();