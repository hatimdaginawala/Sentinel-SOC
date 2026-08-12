const mongoose = require('mongoose');
const { ASSET_TYPES } = require('../config/constants');

const assetSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  type: {
    type: String,
    enum: Object.values(ASSET_TYPES),
    required: true,
    index: true
  },
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
  },
  ipAddress: {
    type: String,
    trim: true,
    index: true
  },
  hostname: {
    type: String,
    trim: true,
    index: true
  },
  operatingSystem: {
    type: String,
    trim: true
  },
  osVersion: {
    type: String,
    trim: true
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'maintenance', 'decommissioned', 'compromised'],
    default: 'active',
    index: true
  },
  criticality: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium',
    index: true
  },
  location: {
    type: String,
    trim: true
  },
  department: {
    type: String,
    trim: true
  },
  owner: {
    type: String,
    trim: true
  },
  tags: [{
    type: String,
    trim: true
  }],
  hardware: {
    cpu: {
      type: String,
      trim: true
    },
    memory: {
      type: String,
      trim: true
    },
    storage: {
      type: String,
      trim: true
    },
    model: {
      type: String,
      trim: true
    },
    manufacturer: {
      type: String,
      trim: true
    }
  },
  software: [{
    name: {
      type: String,
      trim: true
    },
    version: {
      type: String,
      trim: true
    },
    vendor: {
      type: String,
      trim: true
    },
    installedDate: {
      type: Date
    }
  }],
  network: {
    macAddress: {
      type: String,
      trim: true
    },
    dnsName: {
      type: String,
      trim: true
    },
    subnet: {
      type: String,
      trim: true
    },
    gateway: {
      type: String,
      trim: true
    },
    interfaces: [{
      name: {
        type: String,
        trim: true
      },
      ip: {
        type: String,
        trim: true
      },
      mac: {
        type: String,
        trim: true
      }
    }],
    networkZone: {
      type: String,
      trim: true
    }
  },
  securitySensors: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SecuritySensor'
  }],
  security: {
    firewallEnabled: {
      type: Boolean,
      default: false
    },
    antivirusInstalled: {
      type: Boolean,
      default: false
    },
    antivirusStatus: {
      type: String,
      enum: ['active', 'inactive', 'outdated', 'unknown'],
      default: 'unknown'
    },
    lastPatchDate: {
      type: Date
    },
    vulnerabilityCount: {
      type: Number,
      default: 0
    },
    riskScore: {
      type: Number,
      min: 0,
      max: 10,
      default: 0
    },
    complianceStatus: {
      type: String,
      enum: ['compliant', 'non-compliant', 'unknown'],
      default: 'unknown'
    }
  },
  monitoring: {
    enabled: {
      type: Boolean,
      default: true
    },
    agentInstalled: {
      type: Boolean,
      default: false
    },
    agentVersion: {
      type: String,
      trim: true
    },
    lastSeen: {
      type: Date
    },
    healthStatus: {
      type: String,
      enum: ['healthy', 'warning', 'critical', 'offline'],
      default: 'offline'
    }
  },
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  },
  notes: {
    type: String,
    trim: true
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
// assetSchema.index({ organization: 1, type: 1 });
// assetSchema.index({ organization: 1, status: 1 });
// assetSchema.index({ organization: 1, criticality: 1 });
// assetSchema.index({ name: 1, organization: 1 }, { unique: true });
// assetSchema.index({ ipAddress: 1, organization: 1 });
// assetSchema.index({ hostname: 1, organization: 1 });
// assetSchema.index({ tags: 1 });
// assetSchema.index({ 'security.riskScore': 1 });
// assetSchema.index({ 'monitoring.healthStatus': 1 });

// Pre-save middleware
assetSchema.pre('save', function(next) {
  if (this.isNew) {
    this.createdAt = new Date();
    this.updatedAt = new Date();
  } else {
    this.updatedAt = new Date();
  }
  
  // Update monitoring lastSeen if status is being updated
  if (this.isModified('status') && this.status === 'active') {
    this.monitoring.lastSeen = new Date();
  }
  
  next();
});

// Instance methods
assetSchema.methods = {
  // Check if asset is active
  isActive() {
    return this.status === 'active';
  },

  // Check if asset is critical
  isCritical() {
    return this.criticality === 'critical' || this.criticality === 'high';
  },

  // Check if asset needs patching
  needsPatching() {
    if (!this.security.lastPatchDate) return true;
    const daysSincePatch = Math.floor((new Date() - this.security.lastPatchDate) / (1000 * 60 * 60 * 24));
    return daysSincePatch > 30; // Needs patching if older than 30 days
  },

  // Update risk score
  async updateRiskScore() {
    let score = 0;
    
    // Base risk from criticality
    const criticalityMap = {
      low: 1,
      medium: 3,
      high: 6,
      critical: 9
    };
    score += criticalityMap[this.criticality] || 0;
    
    // Add vulnerability risk
    if (this.security.vulnerabilityCount > 0) {
      score += Math.min(this.security.vulnerabilityCount * 0.5, 3);
    }
    
    // Add status risk
    if (this.status === 'compromised') {
      score += 2;
    }
    
    // Add compliance risk
    if (this.security.complianceStatus === 'non-compliant') {
      score += 1;
    }
    
    // Cap at 10
    this.security.riskScore = Math.min(Math.round(score * 10) / 10, 10);
    await this.save();
    return this.security.riskScore;
  },

  // Get asset health status
  getHealthStatus() {
    if (this.monitoring.healthStatus) {
      return this.monitoring.healthStatus;
    }
    
    // Calculate health based on other factors
    if (this.status === 'decommissioned' || this.status === 'inactive') {
      return 'offline';
    }
    
    if (this.security.vulnerabilityCount > 5) {
      return 'critical';
    }
    
    if (this.security.vulnerabilityCount > 0) {
      return 'warning';
    }
    
    return 'healthy';
  }
};

// Static methods
assetSchema.statics = {
  // Find assets by organization
  async findByOrganization(organizationId, options = {}) {
    const { status, type, criticality, limit = 100, page = 1 } = options;
    const query = { organization: organizationId };
    
    if (status) query.status = status;
    if (type) query.type = type;
    if (criticality) query.criticality = criticality;
    
    const skip = (page - 1) * limit;
    
    const [assets, total] = await Promise.all([
      this.find(query)
        .populate('createdBy', 'username email')
        .populate('updatedBy', 'username email')
        .sort({ criticality: -1, name: 1 })
        .skip(skip)
        .limit(limit),
      this.countDocuments(query)
    ]);
    
    return {
      assets,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  // Get assets by type
  async findByType(type, organizationId = null) {
    const query = { type };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .populate('organization', 'name code')
      .sort({ name: 1 });
  },

  // Get assets by criticality
  async findByCriticality(criticality, organizationId = null) {
    const query = { criticality };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .populate('organization', 'name code')
      .sort({ name: 1 });
  },

  // Get assets with vulnerabilities
  async findWithVulnerabilities(organizationId = null) {
    const query = { 'security.vulnerabilityCount': { $gt: 0 } };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .populate('organization', 'name code')
      .sort({ 'security.vulnerabilityCount': -1 });
  },

  // Get assets needing patching
  async findNeedingPatching(organizationId = null) {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const query = {
      $or: [
        { 'security.lastPatchDate': { $lt: thirtyDaysAgo } },
        { 'security.lastPatchDate': { $exists: false } }
      ],
      status: { $in: ['active', 'maintenance'] }
    };
    
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .populate('organization', 'name code')
      .sort({ 'security.riskScore': -1 });
  },

  // Get assets by IP range
  async findByIPRange(startIP, endIP, organizationId = null) {
    // Simple string comparison for IPv4 addresses
    // For production, use a more robust IP comparison method
    const query = {
      ipAddress: { $gte: startIP, $lte: endIP }
    };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query);
  },

  // Get asset statistics
  async getStatistics(organizationId = null) {
    const match = {};
    if (organizationId) match.organization = new mongoose.Types.ObjectId(organizationId);
    
    const stats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          active: {
            $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
          },
          compromised: {
            $sum: { $cond: [{ $eq: ['$status', 'compromised'] }, 1, 0] }
          },
          critical: {
            $sum: { $cond: [
              { $or: [
                { $eq: ['$criticality', 'critical'] },
                { $eq: ['$criticality', 'high'] }
              ] }, 
              1, 0
            ]}
          },
          avgRiskScore: { $avg: '$security.riskScore' },
          totalVulnerabilities: { $sum: '$security.vulnerabilityCount' }
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
      }
    ]);
    
    // Get breakdown by status
    const statusStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);
    
    return {
      ...(stats[0] || { total: 0, active: 0, compromised: 0, critical: 0, avgRiskScore: 0, totalVulnerabilities: 0 }),
      typeBreakdown: typeStats,
      statusBreakdown: statusStats
    };
  },

  // Search assets
  async searchAssets(query, organizationId = null, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-updatedAt' } = options;
    
    const filter = {
      $or: [
        { name: searchRegex },
        { hostname: searchRegex },
        { ipAddress: searchRegex },
        { location: searchRegex },
        { department: searchRegex },
        { owner: searchRegex },
        { tags: { $in: [searchRegex] } }
      ]
    };
    
    if (organizationId) filter.organization = organizationId;
    
    const skip = (page - 1) * limit;
    
    const [assets, total] = await Promise.all([
      this.find(filter)
        .populate('organization', 'name code')
        .populate('createdBy', 'username email')
        .populate('updatedBy', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);
    
    return {
      assets,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  // Get asset with all populated references
  async getAssetWithPopulated(id) {
    return await this.findById(id)
      .populate('organization', 'name code')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName');
  }
};

const Asset = mongoose.model('Asset', assetSchema);

module.exports = Asset;