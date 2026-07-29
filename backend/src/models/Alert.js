const mongoose = require('mongoose');
const { SEVERITY, ALERT_STATUS } = require('../config/constants');

const alertSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
  },
  asset: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Asset',
    required: true,
    index: true
  },
  logSource: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'LogSource',
    required: true,
    index: true
  },
  log: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Log',
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  description: {
    type: String,
    required: true,
    trim: true
  },
  severity: {
    type: String,
    enum: Object.values(SEVERITY),
    required: true,
    index: true
  },
  status: {
    type: String,
    enum: Object.values(ALERT_STATUS),
    default: ALERT_STATUS.ACTIVE,
    index: true
  },
  category: {
    type: String,
    enum: ['authentication', 'network', 'system', 'application', 'database', 'web', 'malware', 'policy', 'access', 'error', 'ids', 'firewall'],
    required: true,
    index: true
  },
  threatType: {
    type: String,
    enum: [
      'brute_force', 'sql_injection', 'xss', 'command_injection', 'rce',
      'reverse_shell', 'port_scan', 'malware_communication', 'dns_tunneling',
      'data_exfiltration', 'dos_attack', 'privilege_escalation',
      'suspicious_powershell', 'unauthorized_access', 'beaconing',
      'ddos', 'port_scan', 'malware', 'phishing', 'ransomware'
    ],
    index: true
  },
  sourceIP: {
    type: String,
    trim: true,
    index: true
  },
  destinationIP: {
    type: String,
    trim: true,
    index: true
  },
  username: {
    type: String,
    trim: true,
    index: true
  },
  confidence: {
    type: Number,
    min: 0,
    max: 100,
    default: 80
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 10,
    default: 5
  },
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
  },
  investigationNotes: [{
    note: {
      type: String,
      trim: true
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  timeline: [{
    action: {
      type: String,
      enum: ['created', 'assigned', 'investigating', 'escalated', 'resolved', 'closed', 'suppressed', 'commented'],
      required: true
    },
    note: {
      type: String,
      trim: true
    },
    performedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    performedAt: {
      type: Date,
      default: Date.now
    }
  }],
  resolution: {
    status: {
      type: String,
      enum: ['unresolved', 'mitigated', 'false_positive', 'accepted_risk', 'remediated', 'contained'],
      default: 'unresolved'
    },
    notes: {
      type: String,
      trim: true
    },
    resolvedAt: {
      type: Date
    },
    resolvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  },
  tags: [{
    type: String,
    trim: true
  }],
  isEscalated: {
    type: Boolean,
    default: false
  },
  escalatedAt: {
    type: Date
  },
  escalatedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  updatedBy: {
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

// // Indexes for performance
// alertSchema.index({ organization: 1, severity: 1 });
// alertSchema.index({ organization: 1, status: 1 });
// alertSchema.index({ organization: 1, createdAt: -1 });
// alertSchema.index({ assignedTo: 1, status: 1 });
// alertSchema.index({ severity: 1, status: 1 });
// alertSchema.index({ sourceIP: 1, organization: 1 });
// alertSchema.index({ threatType: 1, organization: 1 });
// alertSchema.index({ riskScore: -1 });

// // Compound indexes for common queries
// alertSchema.index({ organization: 1, status: 1, severity: 1 });
// alertSchema.index({ organization: 1, assignedTo: 1, status: 1 });

// Pre-save middleware
alertSchema.pre('save', function(next) {
  if (this.isNew) {
    // Add initial timeline entry
    this.timeline.push({
      action: 'created',
      note: 'Alert created',
      performedBy: this.createdBy,
      performedAt: new Date()
    });
    
    // Calculate risk score based on severity
    const severityMap = {
      critical: 10,
      high: 7,
      medium: 5,
      low: 3,
      info: 1
    };
    this.riskScore = severityMap[this.severity] || 5;
    
    // Set confidence based on threat type
    const confidenceMap = {
      sql_injection: 90,
      xss: 85,
      brute_force: 75,
      port_scan: 70,
      malware_communication: 85,
      dos_attack: 80,
      privilege_escalation: 75
    };
    if (this.threatType && confidenceMap[this.threatType]) {
      this.confidence = confidenceMap[this.threatType];
    }
  }
  next();
});

// Instance methods
alertSchema.methods = {
  /**
   * Assign alert to a user
   */
  async assignTo(userId, assignedBy) {
    this.assignedTo = userId;
    this.updatedBy = assignedBy;
    this.timeline.push({
      action: 'assigned',
      note: `Assigned to user ${userId}`,
      performedBy: assignedBy,
      performedAt: new Date()
    });
    await this.save();
    return this;
  },

  /**
   * Update alert status
   */
  async updateStatus(newStatus, userId, note = '') {
    const validTransitions = {
      [ALERT_STATUS.ACTIVE]: [ALERT_STATUS.INVESTIGATING, ALERT_STATUS.SUPPRESSED],
      [ALERT_STATUS.INVESTIGATING]: [ALERT_STATUS.ACTIVE, ALERT_STATUS.RESOLVED, ALERT_STATUS.INVESTIGATING],
      [ALERT_STATUS.RESOLVED]: [ALERT_STATUS.CLOSED, ALERT_STATUS.INVESTIGATING],
      [ALERT_STATUS.CLOSED]: [ALERT_STATUS.INVESTIGATING],
      [ALERT_STATUS.SUPPRESSED]: [ALERT_STATUS.ACTIVE]
    };

    if (!validTransitions[this.status] || !validTransitions[this.status].includes(newStatus)) {
      throw new Error(`Invalid status transition from ${this.status} to ${newStatus}`);
    }

    this.status = newStatus;
    this.updatedBy = userId;
    this.timeline.push({
      action: newStatus === ALERT_STATUS.RESOLVED ? 'resolved' : 
              newStatus === ALERT_STATUS.CLOSED ? 'closed' :
              newStatus === ALERT_STATUS.SUPPRESSED ? 'suppressed' : 'investigating',
      note: note || `Status changed to ${newStatus}`,
      performedBy: userId,
      performedAt: new Date()
    });

    if (newStatus === ALERT_STATUS.RESOLVED) {
      this.resolution.resolvedAt = new Date();
      this.resolution.resolvedBy = userId;
      this.resolution.status = 'mitigated';
    }

    await this.save();
    return this;
  },

  /**
   * Add investigation note
   */
  async addNote(note, userId) {
    this.investigationNotes.push({
      note: note,
      createdBy: userId,
      createdAt: new Date()
    });
    this.timeline.push({
      action: 'commented',
      note: `Added investigation note: ${note.substring(0, 50)}...`,
      performedBy: userId,
      performedAt: new Date()
    });
    await this.save();
    return this;
  },

  /**
   * Escalate alert
   */
  async escalate(userId, escalateTo, reason = '') {
    this.isEscalated = true;
    this.escalatedAt = new Date();
    this.escalatedTo = escalateTo;
    this.updatedBy = userId;
    this.timeline.push({
      action: 'escalated',
      note: `Escalated${reason ? `: ${reason}` : ''}`,
      performedBy: userId,
      performedAt: new Date()
    });
    await this.save();
    return this;
  },

  /**
   * Resolve alert
   */
  async resolve(userId, resolutionStatus, notes = '') {
    const validResolutions = ['mitigated', 'false_positive', 'accepted_risk', 'remediated', 'contained'];
    if (!validResolutions.includes(resolutionStatus)) {
      throw new Error('Invalid resolution status');
    }

    this.status = ALERT_STATUS.RESOLVED;
    this.resolution.status = resolutionStatus;
    this.resolution.notes = notes;
    this.resolution.resolvedAt = new Date();
    this.resolution.resolvedBy = userId;
    this.updatedBy = userId;
    
    this.timeline.push({
      action: 'resolved',
      note: `Alert resolved as ${resolutionStatus}: ${notes}`,
      performedBy: userId,
      performedAt: new Date()
    });
    
    await this.save();
    return this;
  },

  /**
   * Get alert severity color
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
   * Get alert status badge color
   */
  getStatusColor() {
    const colors = {
      active: '#dc3545',
      investigating: '#ffc107',
      resolved: '#28a745',
      closed: '#6c757d',
      suppressed: '#17a2b8'
    };
    return colors[this.status] || '#6c757d';
  },

  /**
   * Check if alert is actionable
   */
  isActionable() {
    return this.status === ALERT_STATUS.ACTIVE || this.status === ALERT_STATUS.INVESTIGATING;
  },

  /**
   * Get time to resolution
   */
  getTimeToResolution() {
    if (!this.resolution.resolvedAt) return null;
    return Math.floor((this.resolution.resolvedAt - this.createdAt) / 1000 / 60); // minutes
  }
};

// Static methods
alertSchema.statics = {
  /**
   * Get alerts with pagination and filtering
   */
  async getAlerts(filters = {}) {
    const {
      organization,
      asset,
      logSource,
      severity,
      status,
      category,
      threatType,
      assignedTo,
      search,
      startDate,
      endDate,
      isEscalated,
      page = 1,
      limit = 20,
      sort = '-createdAt'
    } = filters;

    const query = {};

    if (organization) query.organization = organization;
    if (asset) query.asset = asset;
    if (logSource) query.logSource = logSource;
    if (severity && severity !== 'all') query.severity = severity;
    if (status && status !== 'all') query.status = status;
    if (category && category !== 'all') query.category = category;
    if (threatType && threatType !== 'all') query.threatType = threatType;
    if (assignedTo && assignedTo !== 'all') query.assignedTo = assignedTo;
    if (isEscalated !== undefined && isEscalated !== '') query.isEscalated = isEscalated === 'true';

    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { sourceIP: { $regex: search, $options: 'i' } },
        { destinationIP: { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } },
        { threatType: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (page - 1) * limit;

    const [alerts, total] = await Promise.all([
      this.find(query)
        .populate('organization', 'name code')
        .populate('asset', 'name hostname ipAddress type')
        .populate('logSource', 'sourceName sourceType')
        .populate('assignedTo', 'username email firstName lastName')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName')
        .populate('escalatedTo', 'username email firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      this.countDocuments(query)
    ]);

    return {
      alerts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get alert statistics
   */
  async getStatistics(organizationId = null, timeRange = '24h') {
  const match = {};
  if (organizationId) {
    // Fix: Use 'new' with ObjectId
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

  const stats = await this.aggregate([
    { $match: match },
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
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
        active: {
          $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
        },
        investigating: {
          $sum: { $cond: [{ $eq: ['$status', 'investigating'] }, 1, 0] }
        },
        resolved: {
          $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] }
        },
        closed: {
          $sum: { $cond: [{ $eq: ['$status', 'closed'] }, 1, 0] }
        },
        suppressed: {
          $sum: { $cond: [{ $eq: ['$status', 'suppressed'] }, 1, 0] }
        },
        avgRiskScore: { $avg: '$riskScore' },
        avgTimeToResolution: { $avg: { $subtract: ['$resolution.resolvedAt', '$createdAt'] } }
      }
    }
  ]);
},

  /**
   * Get alerts by organization
   */
  async findByOrganization(organizationId, options = {}) {
    const { limit = 50, page = 1, sort = '-createdAt' } = options;
    const skip = (page - 1) * limit;

    const [alerts, total] = await Promise.all([
      this.find({ organization: organizationId })
        .populate('asset', 'name hostname')
        .populate('assignedTo', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments({ organization: organizationId })
    ]);

    return {
      alerts,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get alerts assigned to user
   */
  async findByAssignedUser(userId, options = {}) {
    const { limit = 50, page = 1, sort = '-createdAt' } = options;
    const skip = (page - 1) * limit;

    const [alerts, total] = await Promise.all([
      this.find({ assignedTo: userId })
        .populate('organization', 'name code')
        .populate('asset', 'name hostname')
        .populate('logSource', 'sourceName')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments({ assignedTo: userId })
    ]);

    return {
      alerts,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get alert with all populated references
   */
  async getAlertWithPopulated(id) {
    return await this.findById(id)
      .populate('organization', 'name code')
      .populate('asset', 'name hostname ipAddress type criticality')
      .populate('logSource', 'sourceName sourceType hostname')
      .populate('log', 'message eventType severity eventTime')
      .populate('assignedTo', 'username email firstName lastName')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName')
      .populate('escalatedTo', 'username email firstName lastName')
      .populate('investigationNotes.createdBy', 'username email firstName lastName')
      .populate('timeline.performedBy', 'username email firstName lastName');
  },

  /**
   * Get high priority alerts (critical and high severity)
   */
  async getHighPriorityAlerts(organizationId = null) {
    const query = { 
      severity: { $in: ['critical', 'high'] },
      status: { $in: ['active', 'investigating'] }
    };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .populate('asset', 'name hostname')
      .populate('assignedTo', 'username email')
      .sort({ riskScore: -1, createdAt: -1 });
  },

  /**
   * Search alerts
   */
  async searchAlerts(query, organizationId = null, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-createdAt' } = options;
    
    const filter = {
      $or: [
        { title: searchRegex },
        { description: searchRegex },
        { sourceIP: searchRegex },
        { destinationIP: searchRegex },
        { username: searchRegex },
        { threatType: searchRegex }
      ]
    };
    
    if (organizationId) filter.organization = organizationId;
    
    const skip = (page - 1) * limit;
    
    const [alerts, total] = await Promise.all([
      this.find(filter)
        .populate('organization', 'name code')
        .populate('asset', 'name hostname')
        .populate('assignedTo', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);
    
    return {
      alerts,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get alert categories for dropdown
   */
  getCategories() {
    return ['authentication', 'network', 'system', 'application', 'database', 'web', 'malware', 'policy', 'access', 'error', 'ids', 'firewall'].map(category => ({
      value: category,
      label: category.charAt(0).toUpperCase() + category.slice(1)
    }));
  },

  /**
   * Get threat types for dropdown
   */
  getThreatTypes() {
    return [
      'brute_force', 'sql_injection', 'xss', 'command_injection', 'rce',
      'reverse_shell', 'port_scan', 'malware_communication', 'dns_tunneling',
      'data_exfiltration', 'dos_attack', 'privilege_escalation',
      'suspicious_powershell', 'unauthorized_access', 'beaconing',
      'ddos', 'port_scan', 'malware', 'phishing', 'ransomware'
    ].map(type => ({
      value: type,
      label: type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  },

  /**
   * Get resolution statuses for dropdown
   */
  getResolutionStatuses() {
    return ['unresolved', 'mitigated', 'false_positive', 'accepted_risk', 'remediated', 'contained'].map(status => ({
      value: status,
      label: status.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  }
};

const Alert = mongoose.model('Alert', alertSchema);

module.exports = Alert;