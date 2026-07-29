const mongoose = require('mongoose');

const iocSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
  },
  type: {
    type: String,
    required: true,
    enum: [
      'ip', 'domain', 'url', 'email', 'file_hash', 'file_path',
      'registry_key', 'process', 'service', 'user_agent',
      'cve', 'campaign', 'exploit', 'signature', 'pattern'
    ],
    index: true
  },
  value: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  indicator: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  description: {
    type: String,
    trim: true
  },
  severity: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low', 'info'],
    default: 'medium',
    index: true
  },
  confidence: {
    type: Number,
    min: 0,
    max: 100,
    default: 70
  },
  source: {
    type: String,
    enum: ['internal', 'external', 'threat_intelligence', 'community', 'automated', 'manual'],
    default: 'internal'
  },
  sourceReference: {
    type: String,
    trim: true
  },
  threatType: {
    type: String,
    enum: [
      'malware', 'ransomware', 'phishing', 'spam', 'botnet', 'trojan',
      'worm', 'virus', 'adware', 'spyware', 'rootkit', 'backdoor',
      'exploit', 'vulnerability', 'apt', 'scanner', 'c2', 'proxy'
    ],
    index: true
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'investigating', 'false_positive', 'archived'],
    default: 'active',
    index: true
  },
  firstSeen: {
    type: Date,
    default: Date.now,
    index: true
  },
  lastSeen: {
    type: Date
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date
  },
  tags: [{
    type: String,
    trim: true
  }],
  relatedIOCs: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'IOC'
  }],
  incidents: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Incident'
  }],
  alerts: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Alert'
  }],
  occurrences: {
    count: {
      type: Number,
      default: 0
    },
    lastOccurrence: {
      type: Date
    },
    sources: [{
      sourceIP: {
        type: String,
        trim: true
      },
      timestamp: {
        type: Date,
        default: Date.now
      },
      count: {
        type: Number,
        default: 1
      }
    }]
  },
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
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

// Compound indexes for performance
// iocSchema.index({ organization: 1, type: 1 });
// iocSchema.index({ organization: 1, status: 1 });
// iocSchema.index({ organization: 1, severity: 1 });
// iocSchema.index({ organization: 1, threatType: 1 });
// iocSchema.index({ value: 1, type: 1 }, { unique: true });
// iocSchema.index({ indicator: 1, organization: 1 });
// iocSchema.index({ firstSeen: -1, organization: 1 });

// Pre-save middleware
iocSchema.pre('save', function(next) {
  if (this.isNew) {
    this.firstSeen = new Date();
  }
  this.lastUpdated = new Date();
  
  // Update indicator if not provided
  if (!this.indicator) {
    this.indicator = this.value;
  }
  
  next();
});

// Instance methods
iocSchema.methods = {
  /**
   * Update occurrence count
   */
  async recordOccurrence(sourceIP = null) {
    this.occurrences.count += 1;
    this.occurrences.lastOccurrence = new Date();
    
    if (sourceIP) {
      const existingSource = this.occurrences.sources.find(
        s => s.sourceIP === sourceIP
      );
      if (existingSource) {
        existingSource.count += 1;
        existingSource.timestamp = new Date();
      } else {
        this.occurrences.sources.push({
          sourceIP: sourceIP,
          timestamp: new Date(),
          count: 1
        });
      }
    }
    
    this.lastSeen = new Date();
    await this.save();
    return this;
  },

  /**
   * Link to incident
   */
  async linkToIncident(incidentId) {
    if (!this.incidents.includes(incidentId)) {
      this.incidents.push(incidentId);
      await this.save();
    }
    return this;
  },

  /**
   * Link to alert
   */
  async linkToAlert(alertId) {
    if (!this.alerts.includes(alertId)) {
      this.alerts.push(alertId);
      await this.save();
    }
    return this;
  },

  /**
   * Expire IOC
   */
  async expire() {
    this.status = 'archived';
    this.expiresAt = new Date();
    this.lastUpdated = new Date();
    await this.save();
    return this;
  },

  /**
   * Reactivate IOC
   */
  async reactivate() {
    this.status = 'active';
    this.expiresAt = null;
    this.lastUpdated = new Date();
    await this.save();
    return this;
  },

  /**
   * Get IOC age in days
   */
  getAgeInDays() {
    return Math.floor((Date.now() - this.firstSeen.getTime()) / (1000 * 60 * 60 * 24));
  },

  /**
   * Get IOC health status
   */
  getHealthStatus() {
    if (this.status === 'archived' || this.status === 'false_positive') {
      return 'inactive';
    }
    
    if (this.expiresAt && this.expiresAt < new Date()) {
      return 'expired';
    }
    
    if (this.occurrences.count > 100) {
      return 'highly_active';
    }
    
    if (this.occurrences.count > 10) {
      return 'active';
    }
    
    return 'low_activity';
  },

  /**
   * Check if IOC matches a value
   */
  matches(value) {
    const normalizedValue = value.toLowerCase().trim();
    const normalizedIndicator = this.indicator.toLowerCase().trim();
    
    if (this.type === 'domain') {
      return normalizedValue === normalizedIndicator || 
             normalizedValue.endsWith(`.${normalizedIndicator}`);
    }
    
    if (this.type === 'file_hash') {
      return normalizedValue.includes(normalizedIndicator);
    }
    
    if (this.type === 'pattern') {
      try {
        const regex = new RegExp(this.indicator, 'i');
        return regex.test(value);
      } catch {
        return normalizedValue.includes(normalizedIndicator);
      }
    }
    
    return normalizedValue === normalizedIndicator;
  },

  /**
   * Get IOC risk score
   */
  getRiskScore() {
    let score = 0;
    
    // Base on severity
    const severityMap = {
      critical: 10,
      high: 7,
      medium: 5,
      low: 3,
      info: 1
    };
    score += severityMap[this.severity] || 0;
    
    // Based on confidence
    score += (this.confidence / 100) * 5;
    
    // Based on occurrences
    if (this.occurrences.count > 100) {
      score += 2;
    } else if (this.occurrences.count > 10) {
      score += 1;
    }
    
    return Math.min(Math.round(score * 10) / 10, 10);
  }
};

// Static methods
iocSchema.statics = {
  /**
   * Get IOCs with pagination and filtering
   */
  async getIOCs(filters = {}) {
    const {
      organization,
      type,
      status,
      severity,
      threatType,
      source,
      search,
      tags,
      startDate,
      endDate,
      isActive,
      page = 1,
      limit = 20,
      sort = '-createdAt'
    } = filters;

    const query = {};

    if (organization) query.organization = organization;
    if (type && type !== 'all') query.type = type;
    if (status && status !== 'all') query.status = status;
    if (severity && severity !== 'all') query.severity = severity;
    if (threatType && threatType !== 'all') query.threatType = threatType;
    if (source && source !== 'all') query.source = source;
    if (tags && tags.length > 0) query.tags = { $in: tags };

    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    if (search) {
      query.$or = [
        { value: { $regex: search, $options: 'i' } },
        { indicator: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } },
        { sourceReference: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (page - 1) * limit;

    const [iocs, total] = await Promise.all([
      this.find(query)
        .populate('organization', 'name code')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName')
        .populate('relatedIOCs', 'type value indicator severity status')
        .populate('incidents', 'title severity status')
        .populate('alerts', 'title severity status')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      this.countDocuments(query)
    ]);

    return {
      iocs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get IOC statistics
   */
  async getStatistics(organizationId = null) {
    const match = {};
    if (organizationId) match.organization = mongoose.Types.ObjectId(organizationId);

    const stats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          active: {
            $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
          },
          inactive: {
            $sum: { $cond: [{ $eq: ['$status', 'inactive'] }, 1, 0] }
          },
          investigating: {
            $sum: { $cond: [{ $eq: ['$status', 'investigating'] }, 1, 0] }
          },
          false_positive: {
            $sum: { $cond: [{ $eq: ['$status', 'false_positive'] }, 1, 0] }
          },
          archived: {
            $sum: { $cond: [{ $eq: ['$status', 'archived'] }, 1, 0] }
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
          avgConfidence: { $avg: '$confidence' },
          totalOccurrences: { $sum: '$occurrences.count' }
        }
      }
    ]);

    // Get breakdown by type
    const typeStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Get breakdown by threat type
    const threatTypeStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$threatType',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Get breakdown by source
    const sourceStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$source',
          count: { $sum: 1 }
        }
      }
    ]);

    return {
      summary: stats[0] || {
        total: 0,
        active: 0,
        inactive: 0,
        investigating: 0,
        false_positive: 0,
        archived: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        avgConfidence: 0,
        totalOccurrences: 0
      },
      typeBreakdown: typeStats,
      threatTypeBreakdown: threatTypeStats,
      sourceBreakdown: sourceStats
    };
  },

  /**
   * Get IOC by type and value
   */
  async findByValue(type, value, organizationId = null) {
    const query = { type, value };
    if (organizationId) query.organization = organizationId;
    
    return await this.findOne(query)
      .populate('organization', 'name code')
      .populate('incidents', 'title severity status')
      .populate('alerts', 'title severity status');
  },

  /**
   * Get IOCs by incident
   */
  async findByIncident(incidentId) {
    return await this.find({ incidents: incidentId })
      .populate('organization', 'name code')
      .populate('createdBy', 'username email')
      .sort({ severity: -1, confidence: -1 });
  },

  /**
   * Get active IOCs
   */
  async getActiveIOCs(organizationId = null) {
    const query = { status: 'active' };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .sort({ severity: -1, confidence: -1 });
  },

  /**
   * Get IOCs by threat type
   */
  async findByThreatType(threatType, organizationId = null) {
    const query = { threatType };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .populate('organization', 'name code')
      .sort({ severity: -1 });
  },

  /**
   * Search IOCs
   */
  async searchIOCs(query, organizationId = null, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-createdAt' } = options;
    
    const filter = {
      $or: [
        { value: searchRegex },
        { indicator: searchRegex },
        { description: searchRegex },
        { tags: { $in: [searchRegex] } },
        { sourceReference: searchRegex },
        { threatType: searchRegex }
      ]
    };
    
    if (organizationId) filter.organization = organizationId;
    
    const skip = (page - 1) * limit;
    
    const [iocs, total] = await Promise.all([
      this.find(filter)
        .populate('organization', 'name code')
        .populate('createdBy', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);
    
    return {
      iocs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get IOC types for dropdown
   */
  getTypes() {
    return [
      'ip', 'domain', 'url', 'email', 'file_hash', 'file_path',
      'registry_key', 'process', 'service', 'user_agent',
      'cve', 'campaign', 'exploit', 'signature', 'pattern'
    ].map(type => ({
      value: type,
      label: type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  },

  /**
   * Get IOC statuses for dropdown
   */
  getStatuses() {
    return ['active', 'inactive', 'investigating', 'false_positive', 'archived'].map(status => ({
      value: status,
      label: status.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  },

  /**
   * Get IOC sources for dropdown
   */
  getSources() {
    return ['internal', 'external', 'threat_intelligence', 'community', 'automated', 'manual'].map(source => ({
      value: source,
      label: source.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  },

  /**
   * Get threat types for dropdown
   */
  getThreatTypes() {
    return [
      'malware', 'ransomware', 'phishing', 'spam', 'botnet', 'trojan',
      'worm', 'virus', 'adware', 'spyware', 'rootkit', 'backdoor',
      'exploit', 'vulnerability', 'apt', 'scanner', 'c2', 'proxy'
    ].map(type => ({
      value: type,
      label: type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
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
  }
};

// Ensure unique compound index
iocSchema.index({ value: 1, type: 1, organization: 1 }, { unique: true });

const IOC = mongoose.model('IOC', iocSchema);

module.exports = IOC;