const mongoose = require('mongoose');
const { SEVERITY, INCIDENT_STATUS } = require('../config/constants');

const incidentSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
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
    enum: Object.values(INCIDENT_STATUS),
    default: INCIDENT_STATUS.NEW,
    index: true
  },
  category: {
    type: String,
    enum: ['malware', 'ransomware', 'phishing', 'data_breach', 'dos', 'insider_threat',
           'unauthorized_access', 'system_compromise', 'data_loss', 'policy_violation',
           'network_intrusion', 'web_attack', 'physical_security', 'other'],
    required: true,
    index: true
  },
  alerts: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Alert'
  }],
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
  },
  assignedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  assignedAt: {
    type: Date
  },
  investigation: {
    lead: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    team: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }],
    startDate: {
      type: Date
    },
    endDate: {
      type: Date
    },
    findings: {
      type: String,
      trim: true
    },
    rootCause: {
      type: String,
      trim: true
    },
    impactAnalysis: {
      type: String,
      trim: true
    }
  },
  timeline: [{
    action: {
      type: String,
      enum: ['created', 'assigned', 'investigating', 'in_progress', 'escalated', 
             'resolved', 'closed', 'reopened', 'commented', 'evidence_added', 
             'status_changed', 'severity_changed'],
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
    },
    metadata: {
      type: Map,
      of: mongoose.Schema.Types.Mixed
    }
  }],
  evidence: [{
    type: {
      type: String,
      enum: ['log', 'alert', 'file', 'screenshot', 'network_pcap', 'memory_dump',
             'disk_image', 'email', 'link', 'note', 'other'],
      required: true
    },
    title: {
      type: String,
      required: true,
      trim: true
    },
    description: {
      type: String,
      trim: true
    },
    reference: {
      type: String,
      trim: true
    },
    fileUrl: {
      type: String,
      trim: true
    },
    fileName: {
      type: String,
      trim: true
    },
    fileSize: {
      type: Number
    },
    mimeType: {
      type: String,
      trim: true
    },
    hash: {
      type: String,
      trim: true
    },
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  resolution: {
    status: {
      type: String,
      enum: ['mitigated', 'contained', 'eradicated', 'recovered', 'accepted', 'false_positive'],
      default: 'mitigated'
    },
    summary: {
      type: String,
      trim: true
    },
    steps: [{
      type: String,
      trim: true
    }],
    lessonsLearned: {
      type: String,
      trim: true
    },
    resolvedAt: {
      type: Date
    },
    resolvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  },
  affectedAssets: [{
    asset: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Asset'
    },
    impact: {
      type: String,
      enum: ['compromised', 'affected', 'investigating', 'cleared'],
      default: 'affected'
    },
    notes: {
      type: String,
      trim: true
    }
  }],
  affectedUsers: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    impact: {
      type: String,
      enum: ['compromised', 'affected', 'investigating', 'cleared'],
      default: 'affected'
    },
    notes: {
      type: String,
      trim: true
    }
  }],
  containmentMeasures: [{
    measure: {
      type: String,
      required: true,
      trim: true
    },
    implementedAt: {
      type: Date
    },
    implementedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    effectiveness: {
      type: String,
      enum: ['effective', 'partially_effective', 'ineffective'],
      default: 'effective'
    }
  }],
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
  escalationReason: {
    type: String,
    trim: true
  },
  detectionSource: {
    type: String,
    enum: ['automated', 'manual', 'external', 'user_report'],
    default: 'automated'
  },
  discoveredAt: {
    type: Date,
    required: true
  },
  reportedBy: {
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
// incidentSchema.index({ organization: 1, severity: 1 });
// incidentSchema.index({ organization: 1, status: 1 });
// incidentSchema.index({ organization: 1, createdAt: -1 });
// incidentSchema.index({ assignedTo: 1, status: 1 });
// incidentSchema.index({ severity: 1, status: 1 });
// incidentSchema.index({ category: 1, organization: 1 });
// incidentSchema.index({ 'alerts': 1 });
// incidentSchema.index({ tags: 1 });

// // Compound indexes for common queries
// incidentSchema.index({ organization: 1, status: 1, severity: 1 });
// incidentSchema.index({ organization: 1, assignedTo: 1, status: 1 });

// Pre-save middleware
incidentSchema.pre('save', function(next) {
  if (this.isNew) {
    // Set discoveredAt if not provided
    if (!this.discoveredAt) {
      this.discoveredAt = new Date();
    }
    
    // Add initial timeline entry
    this.timeline.push({
      action: 'created',
      note: `Incident created: ${this.title}`,
      performedBy: this.createdBy,
      performedAt: new Date()
    });
  }
  next();
});

// Instance methods
incidentSchema.methods = {
  /**
   * Assign incident to a user
   */
  async assignTo(userId, assignedBy) {
    this.assignedTo = userId;
    this.assignedBy = assignedBy;
    this.assignedAt = new Date();
    this.updatedBy = assignedBy;
    
    // If status is NEW, change to INVESTIGATING
    if (this.status === INCIDENT_STATUS.NEW) {
      this.status = INCIDENT_STATUS.INVESTIGATING;
    }
    
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
   * Update incident status
   */
  async updateStatus(newStatus, userId, note = '') {
    this.status = newStatus;
    this.updatedBy = userId;
    
    this.timeline.push({
      action: newStatus === INCIDENT_STATUS.INVESTIGATING ? 'investigating' :
              newStatus === INCIDENT_STATUS.IN_PROGRESS ? 'in_progress' :
              newStatus === INCIDENT_STATUS.RESOLVED ? 'resolved' :
              newStatus === INCIDENT_STATUS.CLOSED ? 'closed' : 'status_changed',
      note: note || `Status changed to ${newStatus}`,
      performedBy: userId,
      performedAt: new Date()
    });

    if (newStatus === INCIDENT_STATUS.RESOLVED) {
      this.resolution.resolvedAt = new Date();
      this.resolution.resolvedBy = userId;
      this.investigation.endDate = new Date();
    }

    await this.save();
    return this;
  },

  /**
   * Add timeline entry
   */
  async addTimeline(action, note, userId, metadata = {}) {
    this.timeline.push({
      action: action,
      note: note,
      performedBy: userId,
      performedAt: new Date(),
      metadata: metadata
    });
    this.updatedBy = userId;
    await this.save();
    return this;
  },

  /**
   * Add evidence to incident
   */
  async addEvidence(evidenceData, uploadedBy) {
    evidenceData.uploadedBy = uploadedBy;
    evidenceData.uploadedAt = new Date();
    this.evidence.push(evidenceData);
    this.updatedBy = uploadedBy;
    
    this.timeline.push({
      action: 'evidence_added',
      note: `Evidence added: ${evidenceData.title}`,
      performedBy: uploadedBy,
      performedAt: new Date()
    });
    
    await this.save();
    return this;
  },

  /**
   * Add affected asset
   */
  async addAffectedAsset(assetId, impact = 'affected', notes = '') {
    this.affectedAssets.push({
      asset: assetId,
      impact: impact,
      notes: notes
    });
    this.updatedBy = this.updatedBy || this.createdBy;
    await this.save();
    return this;
  },

  /**
   * Add containment measure
   */
  async addContainmentMeasure(measure, implementedBy, effectiveness = 'effective') {
    this.containmentMeasures.push({
      measure: measure,
      implementedAt: new Date(),
      implementedBy: implementedBy,
      effectiveness: effectiveness
    });
    this.updatedBy = implementedBy;
    await this.save();
    return this;
  },

  /**
   * Escalate incident
   */
  async escalate(userId, escalateTo, reason = '') {
    this.isEscalated = true;
    this.escalatedAt = new Date();
    this.escalatedTo = escalateTo;
    this.escalationReason = reason;
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
   * Resolve incident
   */
  async resolve(userId, resolutionStatus, summary = '', steps = [], lessonsLearned = '') {
    this.status = INCIDENT_STATUS.RESOLVED;
    this.resolution.status = resolutionStatus;
    this.resolution.summary = summary;
    this.resolution.steps = steps;
    this.resolution.lessonsLearned = lessonsLearned;
    this.resolution.resolvedAt = new Date();
    this.resolution.resolvedBy = userId;
    this.updatedBy = userId;
    this.investigation.endDate = new Date();
    
    this.timeline.push({
      action: 'resolved',
      note: `Incident resolved as ${resolutionStatus}`,
      performedBy: userId,
      performedAt: new Date()
    });
    
    await this.save();
    return this;
  },

  /**
   * Close incident
   */
  async close(userId, note = '') {
    this.status = INCIDENT_STATUS.CLOSED;
    this.updatedBy = userId;
    
    this.timeline.push({
      action: 'closed',
      note: note || 'Incident closed',
      performedBy: userId,
      performedAt: new Date()
    });
    
    await this.save();
    return this;
  },

  /**
   * Reopen incident
   */
  async reopen(userId, reason = '') {
    this.status = INCIDENT_STATUS.INVESTIGATING;
    this.updatedBy = userId;
    
    this.timeline.push({
      action: 'reopened',
      note: `Reopened${reason ? `: ${reason}` : ''}`,
      performedBy: userId,
      performedAt: new Date()
    });
    
    await this.save();
    return this;
  },

  /**
   * Get incident severity color
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
   * Get incident status color
   */
  getStatusColor() {
    const colors = {
      new: '#17a2b8',
      investigating: '#ffc107',
      in_progress: '#fd7e14',
      resolved: '#28a745',
      closed: '#6c757d'
    };
    return colors[this.status] || '#6c757d';
  },

  /**
   * Get time to resolution in minutes
   */
  getTimeToResolution() {
    if (!this.resolution.resolvedAt) return null;
    return Math.floor((this.resolution.resolvedAt - this.createdAt) / 1000 / 60);
  },

  /**
   * Get time to response in minutes
   */
  getTimeToResponse() {
    if (!this.assignedAt) return null;
    return Math.floor((this.assignedAt - this.discoveredAt) / 1000 / 60);
  }
};

// Static methods
incidentSchema.statics = {
  /**
   * Get incidents with pagination and filtering
   */
  async getIncidents(filters = {}) {
    const {
      organization,
      severity,
      status,
      category,
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
    if (severity && severity !== 'all') query.severity = severity;
    if (status && status !== 'all') query.status = status;
    if (category && category !== 'all') query.category = category;
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
        { category: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const skip = (page - 1) * limit;

    const [incidents, total] = await Promise.all([
      this.find(query)
        .populate('organization', 'name code')
        .populate('assignedTo', 'username email firstName lastName')
        .populate('assignedBy', 'username email firstName lastName')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName')
        .populate('escalatedTo', 'username email firstName lastName')
        .populate('investigation.lead', 'username email firstName lastName')
        .populate('investigation.team', 'username email firstName lastName')
        .populate('alerts', 'title severity status')
        .populate('affectedAssets.asset', 'name hostname ipAddress type')
        .populate('resolution.resolvedBy', 'username email firstName lastName')
        .populate('resolution.verifiedBy', 'username email firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      this.countDocuments(query)
    ]);

    return {
      incidents,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get incident statistics
   */
  async getStatistics(organizationId = null, timeRange = '30d') {
    const match = {};
    if (organizationId) match.organization = mongoose.Types.ObjectId(organizationId);

    // Set time range
    const now = new Date();
    let startDate = new Date();
    switch(timeRange) {
      case '7d':
        startDate.setDate(now.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(now.getDate() - 30);
        break;
      case '90d':
        startDate.setDate(now.getDate() - 90);
        break;
      case '1y':
        startDate.setFullYear(now.getFullYear() - 1);
        break;
      default:
        startDate.setDate(now.getDate() - 30);
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
          new: {
            $sum: { $cond: [{ $eq: ['$status', 'new'] }, 1, 0] }
          },
          investigating: {
            $sum: { $cond: [{ $eq: ['$status', 'investigating'] }, 1, 0] }
          },
          in_progress: {
            $sum: { $cond: [{ $eq: ['$status', 'in_progress'] }, 1, 0] }
          },
          resolved: {
            $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] }
          },
          closed: {
            $sum: { $cond: [{ $eq: ['$status', 'closed'] }, 1, 0] }
          },
          avgTimeToResolution: { $avg: { $subtract: ['$resolution.resolvedAt', '$createdAt'] } },
          avgTimeToResponse: { $avg: { $subtract: ['$assignedAt', '$discoveredAt'] } }
        }
      }
    ]);

    // Get breakdown by category
    const categoryStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$category',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Get breakdown by detection source
    const detectionStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$detectionSource',
          count: { $sum: 1 }
        }
      }
    ]);

    return {
      summary: stats[0] || {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        new: 0,
        investigating: 0,
        in_progress: 0,
        resolved: 0,
        closed: 0,
        avgTimeToResolution: 0,
        avgTimeToResponse: 0
      },
      categoryBreakdown: categoryStats,
      detectionBreakdown: detectionStats
    };
  },

  /**
   * Get incidents by organization
   */
  async findByOrganization(organizationId, options = {}) {
    const { limit = 50, page = 1, sort = '-createdAt' } = options;
    const skip = (page - 1) * limit;

    const [incidents, total] = await Promise.all([
      this.find({ organization: organizationId })
        .populate('assignedTo', 'username email')
        .populate('alerts', 'title severity status')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments({ organization: organizationId })
    ]);

    return {
      incidents,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get incidents assigned to user
   */
  async findByAssignedUser(userId, options = {}) {
    const { limit = 50, page = 1, sort = '-createdAt' } = options;
    const skip = (page - 1) * limit;

    const [incidents, total] = await Promise.all([
      this.find({ assignedTo: userId })
        .populate('organization', 'name code')
        .populate('alerts', 'title severity status')
        .populate('assignedTo', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments({ assignedTo: userId })
    ]);

    return {
      incidents,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get incident with all populated references
   */
  async getIncidentWithPopulated(id) {
    return await this.findById(id)
      .populate('organization', 'name code')
      .populate('assignedTo', 'username email firstName lastName')
      .populate('assignedBy', 'username email firstName lastName')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName')
      .populate('escalatedTo', 'username email firstName lastName')
      .populate('alerts', 'title severity status threatType sourceIP createdAt')
      .populate('investigation.lead', 'username email firstName lastName')
      .populate('investigation.team', 'username email firstName lastName')
      .populate('affectedAssets.asset', 'name hostname ipAddress type criticality')
      .populate('evidence.uploadedBy', 'username email')
      .populate('resolution.resolvedBy', 'username email firstName lastName')
      .populate('resolution.verifiedBy', 'username email firstName lastName')
      .populate('containmentMeasures.implementedBy', 'username email');
  },

  /**
   * Search incidents
   */
  async searchIncidents(query, organizationId = null, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-createdAt' } = options;
    
    const filter = {
      $or: [
        { title: searchRegex },
        { description: searchRegex },
        { category: searchRegex },
        { tags: { $in: [searchRegex] } },
        { 'resolution.summary': searchRegex },
        { 'investigation.findings': searchRegex }
      ]
    };
    
    if (organizationId) filter.organization = organizationId;
    
    const skip = (page - 1) * limit;
    
    const [incidents, total] = await Promise.all([
      this.find(filter)
        .populate('organization', 'name code')
        .populate('assignedTo', 'username email')
        .populate('alerts', 'title severity status')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);
    
    return {
      incidents,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get incident categories for dropdown
   */
  getCategories() {
    return ['malware', 'ransomware', 'phishing', 'data_breach', 'dos', 'insider_threat',
            'unauthorized_access', 'system_compromise', 'data_loss', 'policy_violation',
            'network_intrusion', 'web_attack', 'physical_security', 'other'].map(category => ({
      value: category,
      label: category.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  },

  /**
   * Get resolution statuses for dropdown
   */
  getResolutionStatuses() {
    return ['mitigated', 'contained', 'eradicated', 'recovered', 'accepted', 'false_positive'].map(status => ({
      value: status,
      label: status.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  },

  /**
   * Get detection sources for dropdown
   */
  getDetectionSources() {
    return ['automated', 'manual', 'external', 'user_report'].map(source => ({
      value: source,
      label: source.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  },

  /**
   * Get containment effectiveness levels
   */
  getContainmentEffectiveness() {
    return ['effective', 'partially_effective', 'ineffective'].map(level => ({
      value: level,
      label: level.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  }
};

const Incident = mongoose.model('Incident', incidentSchema);

module.exports = Incident;