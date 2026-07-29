const AuditLog = require('../models/AuditLog');
const Organization = require('../models/Organization');
const User = require('../models/User');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');
const logger = require('../config/logger');

class AuditLogService {
  /**
   * Create a new audit log entry
   */
  async createAuditLog(logData) {
    try {
      // Validate organization
      if (logData.organization) {
        const organization = await Organization.findById(logData.organization);
        if (!organization) {
          throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
        }
      }

      // Validate user
      if (logData.user) {
        const user = await User.findById(logData.user);
        if (!user) {
          throw new AppError('User not found', HTTP_STATUS.NOT_FOUND, 'USER_NOT_FOUND');
        }
      }

      // Create audit log
      const auditLog = new AuditLog(logData);
      await auditLog.save();

      // Log to Winston as well
      logger.info(`Audit Log: ${auditLog.action} - ${auditLog.resource} - ${auditLog.resourceName || auditLog.resourceId}`);

      return auditLog;
    } catch (error) {
      logger.error('Error creating audit log:', error);
      throw error;
    }
  }

  /**
   * Get audit log by ID
   */
  async getAuditLogById(logId) {
    try {
      const log = await AuditLog.findById(logId)
        .populate('organization', 'name code')
        .populate('user', 'username email firstName lastName')
        .populate('performedBy', 'username email firstName lastName');

      if (!log) {
        throw new AppError('Audit log not found', HTTP_STATUS.NOT_FOUND, 'AUDIT_LOG_NOT_FOUND');
      }

      return log;
    } catch (error) {
      logger.error('Error getting audit log:', error);
      throw error;
    }
  }

  /**
   * Get audit logs with pagination and filtering
   */
  async getAuditLogs(filters = {}) {
    try {
      const result = await AuditLog.getAuditLogs(filters);
      return result;
    } catch (error) {
      logger.error('Error getting audit logs:', error);
      throw error;
    }
  }

  /**
   * Get audit log statistics
   */
  async getAuditStatistics(organizationId = null, timeRange = '24h') {
    try {
      const stats = await AuditLog.getStatistics(organizationId, timeRange);
      return stats;
    } catch (error) {
      logger.error('Error getting audit statistics:', error);
      throw error;
    }
  }

  /**
   * Get audit logs by user
   */
  async getAuditLogsByUser(userId, options = {}) {
    try {
      const result = await AuditLog.findByUser(userId, options);
      return result;
    } catch (error) {
      logger.error('Error getting audit logs by user:', error);
      throw error;
    }
  }

  /**
   * Get audit logs by IP
   */
  async getAuditLogsByIP(ipAddress, options = {}) {
    try {
      const result = await AuditLog.findByIP(ipAddress, options);
      return result;
    } catch (error) {
      logger.error('Error getting audit logs by IP:', error);
      throw error;
    }
  }

  /**
   * Get audit trail for resource
   */
  async getAuditTrail(resource, resourceId, organizationId = null) {
    try {
      const logs = await AuditLog.getAuditTrail(resource, resourceId, organizationId);
      return logs;
    } catch (error) {
      logger.error('Error getting audit trail:', error);
      throw error;
    }
  }

  /**
   * Search audit logs
   */
  async searchAuditLogs(query, organizationId = null, options = {}) {
    try {
      const result = await AuditLog.searchLogs(query, organizationId, options);
      return result;
    } catch (error) {
      logger.error('Error searching audit logs:', error);
      throw error;
    }
  }

  /**
   * Log user login
   */
  async logLogin(user, ipAddress, userAgent, status = 'success', errorMessage = null) {
    return await this.createAuditLog({
      organization: user.organization,
      user: user._id,
      action: status === 'success' ? 'login' : 'login_failed',
      resource: 'authentication',
      resourceName: user.email,
      status: status,
      errorMessage: errorMessage,
      ipAddress: ipAddress,
      userAgent: userAgent,
      severity: status === 'success' ? 'info' : 'medium',
      performedBy: user._id
    });
  }

  /**
   * Log user logout
   */
  async logLogout(user, ipAddress, userAgent) {
    return await this.createAuditLog({
      organization: user.organization,
      user: user._id,
      action: 'logout',
      resource: 'authentication',
      resourceName: user.email,
      status: 'success',
      ipAddress: ipAddress,
      userAgent: userAgent,
      severity: 'info',
      performedBy: user._id
    });
  }

  /**
   * Log CRUD operations
   */
  async logCrud(user, action, resource, resourceId, resourceName, changes = {}, status = 'success') {
    return await this.createAuditLog({
      organization: user.organization,
      user: user._id,
      action: action,
      resource: resource,
      resourceId: resourceId,
      resourceName: resourceName,
      changes: changes,
      status: status,
      severity: this.getCrudSeverity(action, resource),
      performedBy: user._id
    });
  }

  /**
   * Get severity for CRUD operations
   */
  getCrudSeverity(action, resource) {
    const highSeverityResources = ['organization', 'user', 'role', 'system'];
    const mediumSeverityResources = ['asset', 'alert', 'incident', 'threat_rule'];
    
    if (action.includes('delete')) {
      return highSeverityResources.includes(resource) ? 'critical' : 'high';
    }
    if (action.includes('update') || action.includes('edit')) {
      return highSeverityResources.includes(resource) ? 'high' : 'medium';
    }
    if (action.includes('create')) {
      return 'low';
    }
    return 'info';
  }

  /**
   * Get actions for dropdown
   */
  getActions() {
    return AuditLog.getActions();
  }

  /**
   * Get resources for dropdown
   */
  getResources() {
    return AuditLog.getResources();
  }

  /**
   * Get statuses for dropdown
   */
  getStatuses() {
    return AuditLog.getStatuses();
  }

  /**
   * Get severity levels for dropdown
   */
  getSeverityLevels() {
    return AuditLog.getSeverityLevels();
  }

  /**
   * Export audit logs
   */
  async exportAuditLogs(filters = {}) {
    try {
      const { logs } = await AuditLog.getAuditLogs({ ...filters, limit: 10000 });
      
      return logs.map(log => ({
        timestamp: log.createdAt,
        user: log.user?.username || 'System',
        action: log.action,
        resource: log.resource,
        resourceName: log.resourceName || log.resourceId,
        status: log.status,
        severity: log.severity,
        ipAddress: log.ipAddress,
        userAgent: log.userAgent,
        errorMessage: log.errorMessage || ''
      }));
    } catch (error) {
      logger.error('Error exporting audit logs:', error);
      throw error;
    }
  }

  /**
   * Clean up old audit logs
   */
  async cleanupOldLogs(retentionDays = 90) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      const result = await AuditLog.deleteMany({
        createdAt: { $lt: cutoffDate }
      });

      logger.info(`Cleaned up ${result.deletedCount} old audit logs`);
      
      return {
        deletedCount: result.deletedCount,
        retentionDays: retentionDays
      };
    } catch (error) {
      logger.error('Error cleaning up audit logs:', error);
      throw error;
    }
  }
}

module.exports = new AuditLogService();