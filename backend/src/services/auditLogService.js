// services/auditLogService.js
const AuditLog = require('../models/AuditLog');
const logger = require('../config/logger');
const mongoose = require('mongoose');

class AuditLogService {
  /**
   * Create a new audit log entry
   */
  async createAuditLog(logData) {
    try {
      // Validate required fields
      if (!logData.organization || !logData.user || !logData.action || !logData.resource) {
        console.warn('⚠️ Audit log missing required fields:', {
          organization: !!logData.organization,
          user: !!logData.user,
          action: !!logData.action,
          resource: !!logData.resource
        });
        return null;
      }

      // Create audit log
      const auditLog = new AuditLog({
        organization: logData.organization,
        user: logData.user,
        action: logData.action,
        resource: logData.resource,
        resourceId: logData.resourceId || null,
        resourceName: logData.resourceName || null,
        details: logData.details || {},
        changes: logData.changes || {},
        ipAddress: logData.ipAddress || '0.0.0.0',
        userAgent: logData.userAgent || 'Unknown',
        status: logData.status || 'success',
        errorMessage: logData.errorMessage || null,
        severity: logData.severity || 'info',
        performedBy: logData.performedBy || logData.user
      });

      await auditLog.save();

      // Console log for visibility
      console.log(`📝 AUDIT: ${logData.action} | ${logData.resource} | ${logData.resourceName || 'N/A'}`);

      return auditLog;
    } catch (error) {
      console.error('❌ Error creating audit log:', error.message);
      return null;
    }
  }

  /**
   * Get audit logs with pagination and filtering
   */
  async getAuditLogs(filters = {}) {
    try {
      const {
        organization,
        user,
        action,
        resource,
        resourceId,
        status,
        severity,
        search,
        startDate,
        endDate,
        ipAddress,
        page = 1,
        limit = 20,
        sort = '-createdAt'
      } = filters;

      const query = {};

      if (organization) query.organization = organization;
      if (user) query.user = user;
      if (action && action !== 'all') query.action = action;
      if (resource && resource !== 'all') query.resource = resource;
      if (resourceId) query.resourceId = resourceId;
      if (status && status !== 'all') query.status = status;
      if (severity && severity !== 'all') query.severity = severity;
      if (ipAddress) query.ipAddress = ipAddress;

      if (startDate || endDate) {
        query.createdAt = {};
        if (startDate) query.createdAt.$gte = new Date(startDate);
        if (endDate) query.createdAt.$lte = new Date(endDate);
      }

      if (search) {
        query.$or = [
          { action: { $regex: search, $options: 'i' } },
          { resource: { $regex: search, $options: 'i' } },
          { resourceName: { $regex: search, $options: 'i' } },
          { resourceId: { $regex: search, $options: 'i' } },
          { ipAddress: { $regex: search, $options: 'i' } },
          { errorMessage: { $regex: search, $options: 'i' } }
        ];
      }

      const skip = (page - 1) * limit;

      const [logs, total] = await Promise.all([
        AuditLog.find(query)
          .populate('organization', 'name code')
          .populate('user', 'username email firstName lastName')
          .populate('performedBy', 'username email firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        AuditLog.countDocuments(query)
      ]);

      return {
        logs,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      console.error('Error getting audit logs:', error);
      throw error;
    }
  }

  /**
   * Get audit log statistics
   */
  async getAuditStatistics(organizationId = null, timeRange = '24h') {
    try {
      const match = {};
      if (organizationId) {
        match.organization = new mongoose.Types.ObjectId(organizationId);
      }

      // Set time range
      const now = new Date();
      let startDate = new Date();
      switch(timeRange) {
        case '1h':
          startDate.setHours(now.getHours() - 1);
          break;
        case '24h':
          startDate.setDate(now.getDate() - 1);
          break;
        case '7d':
          startDate.setDate(now.getDate() - 7);
          break;
        case '30d':
          startDate.setDate(now.getDate() - 30);
          break;
        default:
          startDate.setDate(now.getDate() - 1);
      }
      match.createdAt = { $gte: startDate };

      const stats = await AuditLog.aggregate([
        { $match: match },
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            success: {
              $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] }
            },
            failure: {
              $sum: { $cond: [{ $eq: ['$status', 'failure'] }, 1, 0] }
            },
            pending: {
              $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
            },
            critical: {
              $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] }
            },
            high: {
              $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] }
            },
            medium: {
              $sum: { $cond: [{ $eq: ['$severity', 'medium'] }, 1, 0] }
            },
            low: {
              $sum: { $cond: [{ $eq: ['$severity', 'low'] }, 1, 0] }
            },
            info: {
              $sum: { $cond: [{ $eq: ['$severity', 'info'] }, 1, 0] }
            }
          }
        }
      ]);

      return stats[0] || {
        total: 0,
        success: 0,
        failure: 0,
        pending: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      };
    } catch (error) {
      console.error('Error getting audit statistics:', error);
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
        throw new Error('Audit log not found');
      }

      return log;
    } catch (error) {
      console.error('Error getting audit log:', error);
      throw error;
    }
  }

  /**
   * Get audit logs by user
   */
  async getAuditLogsByUser(userId, options = {}) {
    const { limit = 50, page = 1, sort = '-createdAt' } = options;
    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      AuditLog.find({ user: userId })
        .populate('organization', 'name code')
        .populate('user', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      AuditLog.countDocuments({ user: userId })
    ]);

    return {
      logs,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    };
  }

  /**
   * Get audit logs by IP
   */
  async getAuditLogsByIP(ipAddress, options = {}) {
    const { limit = 50, page = 1, sort = '-createdAt' } = options;
    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      AuditLog.find({ ipAddress })
        .populate('user', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      AuditLog.countDocuments({ ipAddress })
    ]);

    return {
      logs,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    };
  }

  /**
   * Get audit trail for resource
   */
  async getAuditTrail(resource, resourceId, organizationId = null) {
    const query = { resource, resourceId };
    if (organizationId) query.organization = organizationId;

    return await AuditLog.find(query)
      .populate('user', 'username email firstName lastName')
      .sort({ createdAt: 1 });
  }

  /**
   * Search audit logs
   */
  async searchAuditLogs(query, organizationId = null, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-createdAt' } = options;
    
    const filter = {
      $or: [
        { action: searchRegex },
        { resource: searchRegex },
        { resourceName: searchRegex },
        { resourceId: searchRegex },
        { ipAddress: searchRegex },
        { errorMessage: searchRegex }
      ]
    };
    
    if (organizationId) filter.organization = organizationId;
    
    const skip = (page - 1) * limit;
    
    const [logs, total] = await Promise.all([
      AuditLog.find(filter)
        .populate('organization', 'name code')
        .populate('user', 'username email firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      AuditLog.countDocuments(filter)
    ]);
    
    return {
      logs,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    };
  }

  /**
   * Export audit logs
   */
  async exportAuditLogs(filters = {}) {
    try {
      const { logs } = await this.getAuditLogs({ ...filters, limit: 10000 });
      
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
      console.error('Error exporting audit logs:', error);
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

      console.log(`🧹 Cleaned up ${result.deletedCount} old audit logs`);
      
      return {
        deletedCount: result.deletedCount,
        retentionDays: retentionDays
      };
    } catch (error) {
      console.error('Error cleaning up audit logs:', error);
      throw error;
    }
  }

  /**
   * Get actions for dropdown
   */
  getActions() {
    return [
      'login', 'logout', 'login_failed', 'password_changed', 'password_reset',
      'user_created', 'user_updated', 'user_deleted', 'user_activated', 'user_deactivated', 'user_locked',
      'role_created', 'role_updated', 'role_deleted', 'role_assigned', 'role_revoked',
      'org_created', 'org_updated', 'org_deleted',
      'asset_created', 'asset_updated', 'asset_deleted', 'asset_activated', 'asset_decommissioned',
      'log_ingested', 'log_deleted', 'log_exported',
      'alert_created', 'alert_updated', 'alert_assigned', 'alert_resolved', 'alert_closed', 'alert_escalated',
      'incident_created', 'incident_updated', 'incident_assigned', 'incident_resolved', 'incident_closed', 'incident_escalated',
      'ioc_created', 'ioc_updated', 'ioc_deleted', 'ioc_linked',
      'rule_created', 'rule_updated', 'rule_deleted', 'rule_enabled', 'rule_disabled', 'rule_triggered',
      'report_created', 'report_generated', 'report_downloaded', 'report_deleted', 'report_scheduled',
      'system_configured', 'settings_updated', 'backup_created', 'restore_performed'
    ].map(action => ({
      value: action,
      label: action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  }

  /**
   * Get resources for dropdown
   */
  getResources() {
    return [
      'user', 'role', 'organization', 'asset', 'log', 'alert', 'incident',
      'ioc', 'threat_rule', 'report', 'settings', 'system', 'authentication'
    ].map(resource => ({
      value: resource,
      label: resource.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  }

  /**
   * Get statuses for dropdown
   */
  getStatuses() {
    return ['success', 'failure', 'pending'].map(status => ({
      value: status,
      label: status.charAt(0).toUpperCase() + status.slice(1)
    }));
  }

  /**
   * Get severity levels for dropdown
   */
  getSeverityLevels() {
    return ['critical', 'high', 'medium', 'low', 'info'].map(severity => ({
      value: severity,
      label: severity.charAt(0).toUpperCase() + severity.slice(1)
    }));
  }
}

module.exports = new AuditLogService();