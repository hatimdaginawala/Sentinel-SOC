const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  action: {
  type: String,
  required: true,
  enum: [
    // Authentication
    'login', 'logout', 'login_failed', 'password_changed', 'password_reset',
    // User Management
    'user_created', 'user_updated', 'user_deleted', 'user_activated', 'user_deactivated', 'user_locked',
    // Role Management
    'role_created', 'role_updated', 'role_deleted', 'role_assigned', 'role_revoked',
    // Organization Management
    'org_created', 'org_updated', 'org_deleted',
    // Asset Management
    'asset_created', 'asset_updated', 'asset_deleted', 'asset_activated', 'asset_decommissioned',
    // Log Management
    'log_ingested', 'log_deleted', 'log_exported',
    // Alert Management
    'alert_created', 'alert_updated', 'alert_assigned', 'alert_resolved', 'alert_closed', 'alert_escalated',
    // Incident Management
    'incident_created', 'incident_updated', 'incident_assigned', 'incident_resolved', 'incident_closed', 'incident_escalated',
    // IOC Management
    'ioc_created', 'ioc_updated', 'ioc_deleted', 'ioc_linked',
    // Threat Rule Management
    'rule_created', 'rule_updated', 'rule_deleted', 'rule_enabled', 'rule_disabled', 'rule_triggered',
    // Report Management
    'report_created', 'report_generated', 'report_downloaded', 'report_deleted', 'report_scheduled',
    // System
    'system_configured', 'settings_updated', 'backup_created', 'restore_performed',
    // Generic read access — every GET request that doesn't match a more specific action above
    'view'
  ],
  index: true
},
  resource: {
    type: String,
    required: true,
    enum: [
      'user', 'role', 'organization', 'asset', 'log', 'alert', 'incident',
      'ioc', 'threat_rule', 'report', 'settings', 'system', 'authentication'
    ],
    index: true
  },
  resourceId: {
    type: String,
    trim: true,
    index: true
  },
  resourceName: {
    type: String,
    trim: true
  },
  details: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  },
  changes: {
    before: {
      type: Map,
      of: mongoose.Schema.Types.Mixed
    },
    after: {
      type: Map,
      of: mongoose.Schema.Types.Mixed
    }
  },
  ipAddress: {
    type: String,
    trim: true,
    index: true
  },
  userAgent: {
    type: String,
    trim: true
  },
  status: {
    type: String,
    enum: ['success', 'failure', 'pending'],
    default: 'success',
    index: true
  },
  errorMessage: {
    type: String,
    trim: true
  },
  severity: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low', 'info'],
    default: 'info',
    index: true
  },
  sessionId: {
    type: String,
    trim: true
  },
  requestId: {
    type: String,
    trim: true
  },
  tags: [{
    type: String,
    trim: true
  }],
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  },
  performedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      delete ret.__v;
      return ret;
    }
  }
});

// Indexes for performance
// auditLogSchema.index({ organization: 1, createdAt: -1 });
// auditLogSchema.index({ organization: 1, action: 1 });
// auditLogSchema.index({ organization: 1, resource: 1 });
// auditLogSchema.index({ organization: 1, user: 1 });
// auditLogSchema.index({ organization: 1, severity: 1 });
// auditLogSchema.index({ organization: 1, status: 1 });
// auditLogSchema.index({ ipAddress: 1, createdAt: -1 });
// auditLogSchema.index({ resourceId: 1, resource: 1 });

// // Compound indexes for common queries
// auditLogSchema.index({ organization: 1, createdAt: -1, severity: 1 });
// auditLogSchema.index({ organization: 1, user: 1, createdAt: -1 });
// auditLogSchema.index({ organization: 1, action: 1, createdAt: -1 });

// TTL index for automatic cleanup (retention period)
auditLogSchema.index({ createdAt: 1 }, { 
  expireAfterSeconds: 90 * 24 * 60 * 60 // 90 days retention
});

// Pre-save middleware
auditLogSchema.pre('save', function(next) {
  // Set default severity based on action
  if (!this.severity) {
    const severityMap = {
      'login_failed': 'medium',
      'user_deleted': 'high',
      'role_deleted': 'high',
      'org_deleted': 'critical',
      'asset_deleted': 'medium',
      'alert_created': 'low',
      'incident_created': 'low',
      'rule_triggered': 'medium',
      'system_configured': 'high',
      'settings_updated': 'medium',
      'backup_created': 'low',
      'restore_performed': 'critical'
    };
    this.severity = severityMap[this.action] || 'info';
  }
  next();
});

// Instance methods
auditLogSchema.methods = {
  /**
   * Get formatted log entry for display
   */
  getFormattedLog() {
    const actionLabels = {
      'login': 'Login',
      'logout': 'Logout',
      'login_failed': 'Failed Login',
      'password_changed': 'Password Changed',
      'password_reset': 'Password Reset',
      'user_created': 'User Created',
      'user_updated': 'User Updated',
      'user_deleted': 'User Deleted',
      'user_activated': 'User Activated',
      'user_deactivated': 'User Deactivated',
      'user_locked': 'User Locked',
      'role_created': 'Role Created',
      'role_updated': 'Role Updated',
      'role_deleted': 'Role Deleted',
      'role_assigned': 'Role Assigned',
      'role_revoked': 'Role Revoked',
      'org_created': 'Organization Created',
      'org_updated': 'Organization Updated',
      'org_deleted': 'Organization Deleted',
      'asset_created': 'Asset Created',
      'asset_updated': 'Asset Updated',
      'asset_deleted': 'Asset Deleted',
      'asset_activated': 'Asset Activated',
      'asset_decommissioned': 'Asset Decommissioned',
      'log_ingested': 'Log Ingested',
      'log_deleted': 'Log Deleted',
      'log_exported': 'Log Exported',
      'alert_created': 'Alert Created',
      'alert_updated': 'Alert Updated',
      'alert_assigned': 'Alert Assigned',
      'alert_resolved': 'Alert Resolved',
      'alert_closed': 'Alert Closed',
      'alert_escalated': 'Alert Escalated',
      'incident_created': 'Incident Created',
      'incident_updated': 'Incident Updated',
      'incident_assigned': 'Incident Assigned',
      'incident_resolved': 'Incident Resolved',
      'incident_closed': 'Incident Closed',
      'incident_escalated': 'Incident Escalated',
      'ioc_created': 'IOC Created',
      'ioc_updated': 'IOC Updated',
      'ioc_deleted': 'IOC Deleted',
      'ioc_linked': 'IOC Linked',
      'rule_created': 'Rule Created',
      'rule_updated': 'Rule Updated',
      'rule_deleted': 'Rule Deleted',
      'rule_enabled': 'Rule Enabled',
      'rule_disabled': 'Rule Disabled',
      'rule_triggered': 'Rule Triggered',
      'report_created': 'Report Created',
      'report_generated': 'Report Generated',
      'report_downloaded': 'Report Downloaded',
      'report_deleted': 'Report Deleted',
      'report_scheduled': 'Report Scheduled',
      'system_configured': 'System Configured',
      'settings_updated': 'Settings Updated',
      'backup_created': 'Backup Created',
      'restore_performed': 'Restore Performed',
      'view': 'Viewed'
    };

    const resourceLabels = {
      'user': 'User',
      'role': 'Role',
      'organization': 'Organization',
      'asset': 'Asset',
      'log': 'Log',
      'alert': 'Alert',
      'incident': 'Incident',
      'ioc': 'IOC',
      'threat_rule': 'Threat Rule',
      'report': 'Report',
      'settings': 'Settings',
      'system': 'System',
      'authentication': 'Authentication'
    };

    return {
      action: actionLabels[this.action] || this.action,
      resource: resourceLabels[this.resource] || this.resource,
      resourceName: this.resourceName || this.resourceId || 'N/A',
      timestamp: this.createdAt,
      user: this.user?.username || 'System',
      status: this.status,
      severity: this.severity,
      ipAddress: this.ipAddress
    };
  },

  /**
   * Get severity color
   */
  getSeverityColor() {
    const colors = {
      critical: '#dc3545',
      high: '#fd7e14',
      medium: '#ffc107',
      low: '#28a745',
      info: '#17a2b8'
    };
    return colors[this.severity] || '#6c757d';
  },

  /**
   * Get status color
   */
  getStatusColor() {
    const colors = {
      success: '#28a745',
      failure: '#dc3545',
      pending: '#ffc107'
    };
    return colors[this.status] || '#6c757d';
  }
};

// Static methods
auditLogSchema.statics = {
  /**
   * Get audit logs with pagination and filtering
   */
  async getAuditLogs(filters = {}) {
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
        { errorMessage: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      this.find(query)
        .populate('organization', 'name code')
        .populate('user', 'username email firstName lastName')
        .populate('performedBy', 'username email firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      this.countDocuments(query)
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
  },

  /**
   * Get audit log statistics
   */
  async getStatistics(organizationId = null, timeRange = '24h') {
    const match = {};
    if (organizationId) match.organization = new mongoose.Types.ObjectId(organizationId);

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

    const stats = await this.aggregate([
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
          },
          uniqueUsers: { $addToSet: '$user' },
          uniqueIPs: { $addToSet: '$ipAddress' }
        }
      }
    ]);

    // Get breakdown by action
    const actionStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$action',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 20 }
    ]);

    // Get breakdown by resource
    const resourceStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$resource',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Get hourly trend
    const hourlyTrend = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: {
            hour: { $hour: '$createdAt' },
            day: { $dayOfMonth: '$createdAt' },
            month: { $month: '$createdAt' },
            year: { $year: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1, '_id.hour': 1 } }
    ]);

    return {
      summary: stats[0] || {
        total: 0,
        success: 0,
        failure: 0,
        pending: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        uniqueUsers: [],
        uniqueIPs: []
      },
      actionBreakdown: actionStats,
      resourceBreakdown: resourceStats,
      hourlyTrend: hourlyTrend
    };
  },

  /**
   * Get audit logs by user
   */
  async findByUser(userId, options = {}) {
    const { limit = 50, page = 1, sort = '-createdAt' } = options;
    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      this.find({ user: userId })
        .populate('organization', 'name code')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments({ user: userId })
    ]);

    return {
      logs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get audit logs by IP address
   */
  async findByIP(ipAddress, options = {}) {
    const { limit = 50, page = 1, sort = '-createdAt' } = options;
    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      this.find({ ipAddress })
        .populate('user', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments({ ipAddress })
    ]);

    return {
      logs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

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
      'system_configured', 'settings_updated', 'backup_created', 'restore_performed',
          'view' 
    ].map(action => ({
      value: action,
      label: action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  },

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
  },

  /**
   * Get statuses for dropdown
   */
  getStatuses() {
    return ['success', 'failure', 'pending'].map(status => ({
      value: status,
      label: status.charAt(0).toUpperCase() + status.slice(1)
    }));
  },

  /**
   * Get severity levels for dropdown
   */
  getSeverityLevels() {
    return ['critical', 'high', 'medium', 'low', 'info'].map(severity => ({
      value: severity,
      label: severity.charAt(0).toUpperCase() + severity.slice(1)
    }));
  },

  /**
   * Search audit logs
   */
  async searchLogs(query, organizationId = null, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-createdAt' } = options;
    
    const filter = {
      $or: [
        { action: searchRegex },
        { resource: searchRegex },
        { resourceName: searchRegex },
        { resourceId: searchRegex },
        { ipAddress: searchRegex },
        { errorMessage: searchRegex },
        { tags: { $in: [searchRegex] } }
      ]
    };
    
    if (organizationId) filter.organization = organizationId;
    
    const skip = (page - 1) * limit;
    
    const [logs, total] = await Promise.all([
      this.find(filter)
        .populate('organization', 'name code')
        .populate('user', 'username email firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);
    
    return {
      logs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get audit trail for a specific resource
   */
  async getAuditTrail(resource, resourceId, organizationId = null) {
    const query = { resource, resourceId };
    if (organizationId) query.organization = organizationId;

    return await this.find(query)
      .populate('user', 'username email firstName lastName')
      .sort({ createdAt: 1 });
  }
};

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

module.exports = AuditLog;