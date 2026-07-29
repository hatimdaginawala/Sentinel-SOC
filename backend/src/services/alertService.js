const Alert = require('../models/Alert');
const Log = require('../models/Log');
const User = require('../models/User');
const Organization = require('../models/Organization');
const Asset = require('../models/Asset');
const LogSource = require('../models/LogSource');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS, SEVERITY, ALERT_STATUS } = require('../config/constants');
const logger = require('../config/logger');

class AlertService {
  /**
   * Create a new alert from a log
   */
  async createAlertFromLog(logId, alertData, createdBy) {
    try {
      // Get the log
      const log = await Log.findById(logId);
      if (!log) {
        throw new AppError('Log not found', HTTP_STATUS.NOT_FOUND, 'LOG_NOT_FOUND');
      }

      // Validate organization
      const organization = await Organization.findById(log.organization);
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Create alert
      const alert = new Alert({
        organization: log.organization,
        asset: log.asset,
        logSource: log.logSource,
        log: log._id,
        title: alertData.title || `Security Alert: ${alertData.threatType || log.eventType}`,
        description: alertData.description || log.message || 'Security alert detected',
        severity: alertData.severity || log.severity || SEVERITY.MEDIUM,
        category: alertData.category || log.eventCategory || 'security',
        threatType: alertData.threatType,
        sourceIP: alertData.sourceIP || log.sourceIP || '',
        destinationIP: alertData.destinationIP || log.destinationIP || '',
        username: alertData.username || log.username || '',
        confidence: alertData.confidence || 80,
        tags: alertData.tags || [],
        createdBy: createdBy
      });

      await alert.save();

      logger.info(`Alert created: ${alert.title} (${alert.severity}) from log ${logId}`);

      return await Alert.getAlertWithPopulated(alert._id);
    } catch (error) {
      logger.error('Error creating alert from log:', error);
      throw error;
    }
  }

  /**
   * Create multiple alerts from logs
   */
  async createAlertsFromLogs(logIds, alertData, createdBy) {
    try {
      const alerts = [];
      const errors = [];

      for (const logId of logIds) {
        try {
          const alert = await this.createAlertFromLog(logId, alertData, createdBy);
          alerts.push(alert);
        } catch (error) {
          errors.push({ logId, error: error.message });
        }
      }

      return {
        created: alerts,
        errors: errors,
        total: logIds.length,
        successful: alerts.length,
        failed: errors.length
      };
    } catch (error) {
      logger.error('Error creating multiple alerts:', error);
      throw error;
    }
  }

  /**
   * Get alert by ID
   */
  async getAlertById(alertId) {
    try {
      const alert = await Alert.getAlertWithPopulated(alertId);
      
      if (!alert) {
        throw new AppError('Alert not found', HTTP_STATUS.NOT_FOUND, 'ALERT_NOT_FOUND');
      }

      return alert;
    } catch (error) {
      logger.error('Error getting alert:', error);
      throw error;
    }
  }

  /**
   * Get alerts with pagination and filtering
   */
  async getAlerts(filters = {}) {
    try {
      const result = await Alert.getAlerts(filters);
      return result;
    } catch (error) {
      logger.error('Error getting alerts:', error);
      throw error;
    }
  }

  /**
   * Get alerts by organization
   */
  async getAlertsByOrganization(organizationId, options = {}) {
    try {
      const result = await Alert.findByOrganization(organizationId, options);
      return result;
    } catch (error) {
      logger.error('Error getting alerts by organization:', error);
      throw error;
    }
  }

  /**
   * Get alerts assigned to user
   */
  async getAlertsAssignedToUser(userId, options = {}) {
    try {
      const result = await Alert.findByAssignedUser(userId, options);
      return result;
    } catch (error) {
      logger.error('Error getting alerts assigned to user:', error);
      throw error;
    }
  }

  /**
   * Get high priority alerts
   */
  async getHighPriorityAlerts(organizationId = null) {
    try {
      const alerts = await Alert.getHighPriorityAlerts(organizationId);
      return alerts;
    } catch (error) {
      logger.error('Error getting high priority alerts:', error);
      throw error;
    }
  }

  /**
   * Get alert statistics
   */
  async getAlertStatistics(organizationId = null, timeRange = '24h') {
    try {
      const stats = await Alert.getStatistics(organizationId, timeRange);
      return stats;
    } catch (error) {
      logger.error('Error getting alert statistics:', error);
      throw error;
    }
  }

  /**
   * Update alert
   */
  async updateAlert(alertId, updateData, updatedBy) {
    try {
      const alert = await Alert.findById(alertId);
      
      if (!alert) {
        throw new AppError('Alert not found', HTTP_STATUS.NOT_FOUND, 'ALERT_NOT_FOUND');
      }

      // Update alert
      const updatedAlert = await Alert.findByIdAndUpdate(
        alertId,
        {
          ...updateData,
          updatedBy: updatedBy,
          updatedAt: new Date()
        },
        {
          new: true,
          runValidators: true
        }
      )
      .populate('organization', 'name code')
      .populate('asset', 'name hostname')
      .populate('assignedTo', 'username email')
      .populate('createdBy', 'username email')
      .populate('updatedBy', 'username email');

      logger.info(`Alert updated: ${updatedAlert.title} by ${updatedBy}`);

      return updatedAlert;
    } catch (error) {
      logger.error('Error updating alert:', error);
      throw error;
    }
  }

  /**
   * Assign alert to user
   */
  async assignAlert(alertId, userId, assignedBy) {
    try {
      const alert = await Alert.findById(alertId);
      
      if (!alert) {
        throw new AppError('Alert not found', HTTP_STATUS.NOT_FOUND, 'ALERT_NOT_FOUND');
      }

      const user = await User.findById(userId);
      if (!user) {
        throw new AppError('User not found', HTTP_STATUS.NOT_FOUND, 'USER_NOT_FOUND');
      }

      await alert.assignTo(userId, assignedBy);

      logger.info(`Alert ${alertId} assigned to user ${userId} by ${assignedBy}`);

      return await Alert.getAlertWithPopulated(alert._id);
    } catch (error) {
      logger.error('Error assigning alert:', error);
      throw error;
    }
  }

  /**
   * Update alert status
   */
  async updateAlertStatus(alertId, newStatus, userId, note = '') {
    try {
      const alert = await Alert.findById(alertId);
      
      if (!alert) {
        throw new AppError('Alert not found', HTTP_STATUS.NOT_FOUND, 'ALERT_NOT_FOUND');
      }

      await alert.updateStatus(newStatus, userId, note);

      logger.info(`Alert ${alertId} status updated to ${newStatus} by ${userId}`);

      return await Alert.getAlertWithPopulated(alert._id);
    } catch (error) {
      logger.error('Error updating alert status:', error);
      throw error;
    }
  }

  /**
   * Add note to alert
   */
  async addNote(alertId, note, userId) {
    try {
      const alert = await Alert.findById(alertId);
      
      if (!alert) {
        throw new AppError('Alert not found', HTTP_STATUS.NOT_FOUND, 'ALERT_NOT_FOUND');
      }

      await alert.addNote(note, userId);

      logger.info(`Note added to alert ${alertId} by ${userId}`);

      return await Alert.getAlertWithPopulated(alert._id);
    } catch (error) {
      logger.error('Error adding note to alert:', error);
      throw error;
    }
  }

  /**
   * Escalate alert
   */
  async escalateAlert(alertId, userId, escalateTo, reason = '') {
    try {
      const alert = await Alert.findById(alertId);
      
      if (!alert) {
        throw new AppError('Alert not found', HTTP_STATUS.NOT_FOUND, 'ALERT_NOT_FOUND');
      }

      const targetUser = await User.findById(escalateTo);
      if (!targetUser) {
        throw new AppError('Target user not found', HTTP_STATUS.NOT_FOUND, 'USER_NOT_FOUND');
      }

      await alert.escalate(userId, escalateTo, reason);

      logger.info(`Alert ${alertId} escalated to ${escalateTo} by ${userId}`);

      return await Alert.getAlertWithPopulated(alert._id);
    } catch (error) {
      logger.error('Error escalating alert:', error);
      throw error;
    }
  }

  /**
   * Resolve alert
   */
  async resolveAlert(alertId, userId, resolutionStatus, notes = '') {
    try {
      const alert = await Alert.findById(alertId);
      
      if (!alert) {
        throw new AppError('Alert not found', HTTP_STATUS.NOT_FOUND, 'ALERT_NOT_FOUND');
      }

      await alert.resolve(userId, resolutionStatus, notes);

      logger.info(`Alert ${alertId} resolved by ${userId} as ${resolutionStatus}`);

      return await Alert.getAlertWithPopulated(alert._id);
    } catch (error) {
      logger.error('Error resolving alert:', error);
      throw error;
    }
  }

  /**
   * Delete alert
   */
  async deleteAlert(alertId, deletedBy) {
    try {
      const alert = await Alert.findById(alertId);
      
      if (!alert) {
        throw new AppError('Alert not found', HTTP_STATUS.NOT_FOUND, 'ALERT_NOT_FOUND');
      }

      await alert.remove();

      logger.info(`Alert deleted: ${alertId} by ${deletedBy}`);

      return { success: true, message: 'Alert deleted successfully' };
    } catch (error) {
      logger.error('Error deleting alert:', error);
      throw error;
    }
  }

  /**
   * Search alerts
   */
  async searchAlerts(query, organizationId = null, options = {}) {
    try {
      const result = await Alert.searchAlerts(query, organizationId, options);
      return result;
    } catch (error) {
      logger.error('Error searching alerts:', error);
      throw error;
    }
  }

  /**
   * Get alert categories for dropdown
   */
  getAlertCategories() {
    return Alert.getCategories();
  }

  /**
   * Get threat types for dropdown
   */
  getThreatTypes() {
    return Alert.getThreatTypes();
  }

  /**
   * Get resolution statuses for dropdown
   */
  getResolutionStatuses() {
    return Alert.getResolutionStatuses();
  }

  /**
   * Get severity levels for dropdown
   */
  getSeverityLevels() {
    return Object.values(SEVERITY).map(severity => ({
      value: severity,
      label: severity.charAt(0).toUpperCase() + severity.slice(1)
    }));
  }

  /**
   * Get alert statuses for dropdown
   */
  getAlertStatuses() {
    return Object.values(ALERT_STATUS).map(status => ({
      value: status,
      label: status.charAt(0).toUpperCase() + status.slice(1)
    }));
  }

  /**
   * Generate alert from log automatically
   * This is called by the detection engine
   */
  async generateAlertFromLog(logId, threatType, severity, createdBy) {
    try {
      const log = await Log.findById(logId);
      if (!log) {
        throw new AppError('Log not found', HTTP_STATUS.NOT_FOUND, 'LOG_NOT_FOUND');
      }

      // Check if alert already exists for this log
      const existingAlert = await Alert.findOne({ log: logId });
      if (existingAlert) {
        return existingAlert;
      }

      const alertData = {
        title: `${threatType.replace(/_/g, ' ').toUpperCase()} Detected`,
        description: `Security alert: ${threatType.replace(/_/g, ' ')} detected on ${log.hostname || 'asset'}`,
        severity: severity || SEVERITY.MEDIUM,
        category: log.eventCategory || 'security',
        threatType: threatType,
        sourceIP: log.sourceIP,
        destinationIP: log.destinationIP,
        username: log.username,
        tags: ['auto_generated', threatType]
      };

      return await this.createAlertFromLog(logId, alertData, createdBy);
    } catch (error) {
      logger.error('Error generating alert from log:', error);
      throw error;
    }
  }

  /**
   * Batch generate alerts from logs
   */
  async batchGenerateAlerts(logs, threatType, severity, createdBy) {
    try {
      const results = [];
      
      for (const log of logs) {
        try {
          const alert = await this.generateAlertFromLog(log._id, threatType, severity, createdBy);
          results.push({ logId: log._id, alertId: alert._id, success: true });
        } catch (error) {
          results.push({ logId: log._id, error: error.message, success: false });
        }
      }

      return results;
    } catch (error) {
      logger.error('Error batch generating alerts:', error);
      throw error;
    }
  }
}

module.exports = new AlertService();