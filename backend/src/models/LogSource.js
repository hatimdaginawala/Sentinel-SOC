const mongoose = require('mongoose');

const logSourceSchema = new mongoose.Schema({
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
  sourceName: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  sourceType: {
    type: String,
    required: true,
    enum: ['Windows', 'Linux', 'Apache', 'Nginx', 'IIS', 'pfSense', 'Suricata', 'Snort', 'Zeek', 'Node Application', 'Custom'],
    index: true
  },
  hostname: {
    type: String,
    trim: true,
    index: true
  },
  ipAddress: {
    type: String,
    trim: true,
    index: true
  },
  operatingSystem: {
    type: String,
    trim: true
  },
  status: {
    type: String,
    enum: ['Online', 'Offline', 'Pending', 'Error'],
    default: 'Pending'
  },
  protocol: {
    type: String,
    enum: ['REST', 'Syslog', 'Agent'],
    default: 'REST'
  },
  authenticationToken: {
    type: String,
    required: true,
    unique: true
  },
  lastHeartbeat: {
    type: Date,
    default: null
  },
  description: {
    type: String,
    trim: true
  },
  metadata: {
    version: {
      type: String,
      trim: true
    },
    location: {
      type: String,
      trim: true
    },
    department: {
      type: String,
      trim: true
    }
  },
  configuration: {
    logLevel: {
      type: String,
      enum: ['debug', 'info', 'warning', 'error'],
      default: 'info'
    },
    batchSize: {
      type: Number,
      default: 100
    },
    flushInterval: {
      type: Number,
      default: 60 // seconds
    },
    enabled: {
      type: Boolean,
      default: true
    }
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
      delete ret.authenticationToken;
      delete ret.__v;
      return ret;
    }
  }
});

// Indexes for performance
// logSourceSchema.index({ organization: 1, sourceType: 1 });
// logSourceSchema.index({ organization: 1, status: 1 });
// logSourceSchema.index({ asset: 1 });
// logSourceSchema.index({ sourceName: 1, organization: 1 }, { unique: true });
// logSourceSchema.index({ lastHeartbeat: 1 });
// logSourceSchema.index({ ipAddress: 1 });

// Pre-save middleware
logSourceSchema.pre('save', function(next) {
  if (this.isNew) {
    // Generate authentication token if not provided
    if (!this.authenticationToken) {
      const crypto = require('crypto');
      this.authenticationToken = crypto.randomBytes(32).toString('hex');
    }
    this.createdAt = new Date();
    this.updatedAt = new Date();
  } else {
    this.updatedAt = new Date();
  }
  next();
});

// Instance methods
logSourceSchema.methods = {
  // Check if log source is online
  isOnline() {
    if (!this.lastHeartbeat) return false;
    const heartbeatTimeout = 5 * 60 * 1000; // 5 minutes
    return this.status === 'Online' && 
           (Date.now() - this.lastHeartbeat.getTime()) < heartbeatTimeout;
  },

  // Update heartbeat
  async updateHeartbeat() {
    this.lastHeartbeat = new Date();
    this.status = 'Online';
    await this.save();
    return this;
  },

  // Mark as offline
  async markOffline() {
    this.status = 'Offline';
    await this.save();
    return this;
  },

  // Regenerate authentication token
  async regenerateToken() {
    const crypto = require('crypto');
    this.authenticationToken = crypto.randomBytes(32).toString('hex');
    await this.save();
    return this.authenticationToken;
  },

  // Validate authentication token
  validateToken(token) {
    return this.authenticationToken === token;
  },

  // Check if source is active
  isActive() {
    return this.status === 'Online' && this.configuration.enabled;
  },

  // Get source identifier
  getIdentifier() {
    return `${this.sourceType} - ${this.sourceName}`;
  }
};

// Static methods
logSourceSchema.statics = {
  // Find by organization
  async findByOrganization(organizationId, options = {}) {
    const { status, sourceType, limit = 20, page = 1, sort = '-createdAt' } = options;
    const query = { organization: organizationId };
    
    if (status) query.status = status;
    if (sourceType) query.sourceType = sourceType;
    
    const skip = (page - 1) * limit;
    
    const [sources, total] = await Promise.all([
      this.find(query)
        .populate('asset', 'name hostname ipAddress')
        .populate('createdBy', 'username email')
        .populate('updatedBy', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(query)
    ]);
    
    return {
      sources,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  // Find by asset
  async findByAsset(assetId) {
    return await this.find({ asset: assetId })
      .populate('organization', 'name code')
      .sort({ sourceName: 1 });
  },

  // Find online sources
  async findOnline() {
    const heartbeatTimeout = new Date(Date.now() - 5 * 60 * 1000);
    return await this.find({
      status: 'Online',
      lastHeartbeat: { $gt: heartbeatTimeout },
      'configuration.enabled': true
    })
    .populate('organization', 'name code')
    .populate('asset', 'name hostname ipAddress');
  },

  // Find sources with heartbeat older than threshold
  async findStaleHeartbeats(thresholdMinutes = 5) {
    const thresholdDate = new Date(Date.now() - thresholdMinutes * 60 * 1000);
    return await this.find({
      $or: [
        { lastHeartbeat: { $lt: thresholdDate } },
        { lastHeartbeat: { $exists: false } }
      ],
      status: 'Online'
    });
  },

  // Get log source with populated references
  async getWithPopulated(id) {
    return await this.findById(id)
      .populate('organization', 'name code')
      .populate('asset', 'name hostname ipAddress type criticality')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName');
  },

  // Get log source statistics
  async getStatistics(organizationId = null) {
    const match = {};
    if (organizationId) match.organization = mongoose.Types.ObjectId(organizationId);
    
    const stats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          online: {
            $sum: { $cond: [{ $eq: ['$status', 'Online'] }, 1, 0] }
          },
          offline: {
            $sum: { $cond: [{ $eq: ['$status', 'Offline'] }, 1, 0] }
          },
          error: {
            $sum: { $cond: [{ $eq: ['$status', 'Error'] }, 1, 0] }
          },
          pending: {
            $sum: { $cond: [{ $eq: ['$status', 'Pending'] }, 1, 0] }
          }
        }
      }
    ]);
    
    // Get breakdown by source type
    const typeStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$sourceType',
          count: { $sum: 1 }
        }
      }
    ]);
    
    // Get breakdown by protocol
    const protocolStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$protocol',
          count: { $sum: 1 }
        }
      }
    ]);
    
    return {
      ...(stats[0] || { total: 0, online: 0, offline: 0, error: 0, pending: 0 }),
      typeBreakdown: typeStats,
      protocolBreakdown: protocolStats
    };
  },

  // Search log sources
  async searchSources(query, organizationId = null, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-updatedAt' } = options;
    
    const filter = {
      $or: [
        { sourceName: searchRegex },
        { hostname: searchRegex },
        { ipAddress: searchRegex },
        { sourceType: searchRegex },
        { description: searchRegex },
        { 'metadata.location': searchRegex },
        { 'metadata.department': searchRegex }
      ]
    };
    
    if (organizationId) filter.organization = organizationId;
    
    const skip = (page - 1) * limit;
    
    const [sources, total] = await Promise.all([
      this.find(filter)
        .populate('organization', 'name code')
        .populate('asset', 'name hostname ipAddress')
        .populate('createdBy', 'username email')
        .populate('updatedBy', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);
    
    return {
      sources,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  // Get source types (for dropdowns)
  getSourceTypes() {
    return ['Windows', 'Linux', 'Apache', 'Nginx', 'IIS', 'pfSense', 'Suricata', 'Snort', 'Zeek', 'Node Application', 'Custom'].map(type => ({
      value: type,
      label: type
    }));
  },

  // Get protocols (for dropdowns)
  getProtocols() {
    return ['REST', 'Syslog', 'Agent'].map(protocol => ({
      value: protocol,
      label: protocol
    }));
  },

  // Get statuses (for dropdowns)
  getStatuses() {
    return ['Online', 'Offline', 'Pending', 'Error'].map(status => ({
      value: status,
      label: status
    }));
  }
};

const LogSource = mongoose.model('LogSource', logSourceSchema);

module.exports = LogSource;