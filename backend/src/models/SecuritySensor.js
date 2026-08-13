// models/SecuritySensor.js

const mongoose = require('mongoose');

const securitySensorSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: [true, 'Organization is required'],
    index: true
  },
  name: {
    type: String,
    required: [true, 'Sensor name is required'],
    trim: true,
    maxlength: [100, 'Name cannot exceed 100 characters'],
    index: true
  },
  type: {
    type: String,
    enum: ['Suricata', 'Zeek', 'Firewall', 'Host Collector', 'Wazuh', 'Snort', 'Custom', 'Other'],
    required: [true, 'Sensor type is required'],
    index: true
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  networkZone: {
    type: String,
    trim: true,
    default: 'Unassigned',
    index: true
  },
  ipAddress: {
    type: String,
    trim: true,
    validate: {
      validator: function(v) {
        if (!v) return true;
        return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(v);
      },
      message: props => `${props.value} is not a valid IP address!`
    }
  },
  port: {
    type: Number,
    min: 1,
    max: 65535
  },
  asset: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Asset',
    index: true
  },
  logSource: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'LogSource',
    index: true
  },
  status: {
    type: String,
    enum: ['Active', 'Inactive', 'Error', 'Pending', 'Degraded'],
    default: 'Pending',
    index: true
  },
  version: {
    type: String,
    trim: true,
    default: '1.0.0'
  },
  lastHeartbeat: {
    type: Date,
    default: null
  },
  lastEventReceived: {
    type: Date,
    default: null
  },
  eventsReceived: {
    type: Number,
    default: 0
  },
  eventsForwarded: {
    type: Number,
    default: 0
  },
  alertsGenerated: {
    type: Number,
    default: 0
  },
  uptime: {
    type: Number,
    default: 0 // in seconds
  },
  healthScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 100
  },
  configuration: {
    type: Map,
    of: mongoose.Schema.Types.Mixed,
    default: new Map()
  },
  capabilities: [{
    type: String,
    enum: ['ids', 'ips', 'network_monitoring', 'host_monitoring', 'log_collection', 'threat_detection', 'packet_capture', 'dns_monitoring', 'http_monitoring', 'tls_monitoring']
  }],
  tags: [{
    type: String,
    trim: true
  }],
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed,
    default: new Map()
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
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

// Indexes for performance
securitySensorSchema.index({ organization: 1, type: 1 });
securitySensorSchema.index({ organization: 1, status: 1 });
securitySensorSchema.index({ organization: 1, networkZone: 1 });
securitySensorSchema.index({ organization: 1, name: 1 });
securitySensorSchema.index({ lastHeartbeat: 1 });
securitySensorSchema.index({ healthScore: -1 });

// Pre-save middleware
securitySensorSchema.pre('save', function(next) {
  if (this.isNew) {
    this.createdAt = new Date();
    this.updatedAt = new Date();
  } else {
    this.updatedAt = new Date();
  }
  
  // If status is Active but no heartbeat, set to Pending
  if (this.status === 'Active' && !this.lastHeartbeat) {
    this.status = 'Pending';
  }
  
  next();
});

// Instance methods
securitySensorSchema.methods = {
  /**
   * Update heartbeat
   */
  async updateHeartbeat() {
    this.lastHeartbeat = new Date();
    this.status = 'Active';
    this.healthScore = Math.min(100, this.healthScore + 10);
    await this.save();
    return this;
  },

  /**
   * Update health score
   */
  async updateHealthScore(factor) {
    const newScore = this.healthScore + factor;
    this.healthScore = Math.max(0, Math.min(100, newScore));
    
    if (this.healthScore < 30) {
      this.status = 'Error';
    } else if (this.healthScore < 60) {
      this.status = 'Degraded';
    } else if (this.status === 'Error' || this.status === 'Degraded') {
      this.status = 'Active';
    }
    
    await this.save();
    return this;
  },

  /**
   * Record event
   */
  async recordEvent(type = 'received') {
    if (type === 'received') {
      this.eventsReceived += 1;
    } else if (type === 'forwarded') {
      this.eventsForwarded += 1;
    } else if (type === 'alert') {
      this.alertsGenerated += 1;
    }
    this.lastEventReceived = new Date();
    await this.save();
    return this;
  },

  /**
   * Get uptime status
   */
  getUptimeStatus() {
    if (!this.lastHeartbeat) return 'Unknown';
    const secondsSinceHeartbeat = (Date.now() - this.lastHeartbeat.getTime()) / 1000;
    
    if (secondsSinceHeartbeat < 60) return 'Healthy';
    if (secondsSinceHeartbeat < 300) return 'Degraded';
    return 'Unhealthy';
  },

  /**
   * Check if sensor is online
   */
  isOnline() {
    if (!this.lastHeartbeat) return false;
    const secondsSinceHeartbeat = (Date.now() - this.lastHeartbeat.getTime()) / 1000;
    return secondsSinceHeartbeat < 60 && this.status === 'Active';
  },

  /**
   * Get sensor summary
   */
  getSummary() {
    return {
      id: this._id,
      name: this.name,
      type: this.type,
      status: this.status,
      healthScore: this.healthScore,
      uptimeStatus: this.getUptimeStatus(),
      eventsReceived: this.eventsReceived,
      lastHeartbeat: this.lastHeartbeat,
      networkZone: this.networkZone
    };
  },

  /**
   * Get health status color
   */
  getHealthColor() {
    if (this.healthScore >= 80) return '#28a745';
    if (this.healthScore >= 60) return '#ffc107';
    if (this.healthScore >= 30) return '#fd7e14';
    return '#dc3545';
  }
};

// Static methods
securitySensorSchema.statics = {
  /**
   * Get sensors with pagination and filtering
   */
  async getSensors(filters = {}) {
    const {
      organization,
      type,
      status,
      networkZone,
      search,
      tags,
      healthScoreMin,
      healthScoreMax,
      page = 1,
      limit = 20,
      sort = '-createdAt'
    } = filters;

    const query = {};

    if (organization) query.organization = organization;
    if (type && type !== 'all') query.type = type;
    if (status && status !== 'all') query.status = status;
    if (networkZone && networkZone !== 'all') query.networkZone = networkZone;
    if (tags && tags.length > 0) query.tags = { $in: tags };
    if (healthScoreMin !== undefined) query.healthScore = { $gte: healthScoreMin };
    if (healthScoreMax !== undefined) {
      query.healthScore = { ...query.healthScore, $lte: healthScoreMax };
    }

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { type: { $regex: search, $options: 'i' } },
        { networkZone: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const skip = (page - 1) * limit;

    const [sensors, total] = await Promise.all([
      this.find(query)
        .populate('organization', 'name code')
        .populate('asset', 'name hostname ipAddress type')
        .populate('logSource', 'sourceName sourceType')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      this.countDocuments(query)
    ]);

    return {
      sensors,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get sensor statistics
   */
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
            $sum: { $cond: [{ $eq: ['$status', 'Active'] }, 1, 0] }
          },
          inactive: {
            $sum: { $cond: [{ $eq: ['$status', 'Inactive'] }, 1, 0] }
          },
          error: {
            $sum: { $cond: [{ $eq: ['$status', 'Error'] }, 1, 0] }
          },
          pending: {
            $sum: { $cond: [{ $eq: ['$status', 'Pending'] }, 1, 0] }
          },
          degraded: {
            $sum: { $cond: [{ $eq: ['$status', 'Degraded'] }, 1, 0] }
          },
          avgHealthScore: { $avg: '$healthScore' },
          totalEventsReceived: { $sum: '$eventsReceived' },
          totalEventsForwarded: { $sum: '$eventsForwarded' },
          totalAlertsGenerated: { $sum: '$alertsGenerated' }
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

    // Get breakdown by network zone
    const zoneStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$networkZone',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Get online/offline status
    const heartbeatTimeout = new Date(Date.now() - 60 * 1000);
    const onlineCount = await this.countDocuments({
      ...match,
      lastHeartbeat: { $gt: heartbeatTimeout },
      status: 'Active'
    });

    return {
      summary: stats[0] || {
        total: 0,
        active: 0,
        inactive: 0,
        error: 0,
        pending: 0,
        degraded: 0,
        avgHealthScore: 0,
        totalEventsReceived: 0,
        totalEventsForwarded: 0,
        totalAlertsGenerated: 0
      },
      onlineCount,
      offlineCount: (stats[0]?.total || 0) - onlineCount,
      typeBreakdown: typeStats,
      zoneBreakdown: zoneStats
    };
  },

  /**
   * Get sensors by asset
   */
  async findByAsset(assetId, organizationId = null) {
    const query = { asset: assetId };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .populate('organization', 'name code')
      .sort({ type: 1, name: 1 });
  },

  /**
   * Get active sensors
   */
  async getActiveSensors(organizationId = null) {
    const query = { status: 'Active' };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .populate('asset', 'name hostname ipAddress')
      .sort({ name: 1 });
  },

  /**
   * Get sensor with all populated references
   */
  async getSensorWithPopulated(id) {
    return await this.findById(id)
      .populate('organization', 'name code')
      .populate('asset', 'name hostname ipAddress type criticality')
      .populate('logSource', 'sourceName sourceType status')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName');
  },

  /**
   * Search sensors
   */
  async searchSensors(query, organizationId = null, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-createdAt' } = options;
    
    const filter = {
      $or: [
        { name: searchRegex },
        { description: searchRegex },
        { type: searchRegex },
        { networkZone: searchRegex },
        { tags: { $in: [searchRegex] } },
        { 'metadata.location': searchRegex }
      ]
    };
    
    if (organizationId) filter.organization = organizationId;
    
    const skip = (page - 1) * limit;
    
    const [sensors, total] = await Promise.all([
      this.find(filter)
        .populate('organization', 'name code')
        .populate('asset', 'name hostname')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);
    
    return {
      sensors,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get sensor types for dropdown
   */
  getTypes() {
    return ['Suricata', 'Zeek', 'Firewall', 'Host Collector', 'Wazuh', 'Snort', 'Custom', 'Other'].map(type => ({
      value: type,
      label: type
    }));
  },

  /**
   * Get statuses for dropdown
   */
  getStatuses() {
    return ['Active', 'Inactive', 'Error', 'Pending', 'Degraded'].map(status => ({
      value: status,
      label: status
    }));
  },

  /**
   * Get capabilities for dropdown
   */
  getCapabilities() {
    return [
      'ids', 'ips', 'network_monitoring', 'host_monitoring', 'log_collection',
      'threat_detection', 'packet_capture', 'dns_monitoring', 'http_monitoring', 'tls_monitoring'
    ].map(cap => ({
      value: cap,
      label: cap.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  },

  /**
   * Update health scores for all sensors
   */
  async updateAllHealthScores() {
    const sensors = await this.find({});
    const now = Date.now();
    
    for (const sensor of sensors) {
      if (!sensor.lastHeartbeat) {
        sensor.healthScore = Math.max(0, sensor.healthScore - 10);
      } else {
        const secondsSinceHeartbeat = (now - sensor.lastHeartbeat.getTime()) / 1000;
        if (secondsSinceHeartbeat > 300) {
          sensor.healthScore = Math.max(0, sensor.healthScore - 5);
        } else if (secondsSinceHeartbeat > 60) {
          sensor.healthScore = Math.max(0, sensor.healthScore - 2);
        } else {
          sensor.healthScore = Math.min(100, sensor.healthScore + 2);
        }
        
        // Update status based on health score
        if (sensor.healthScore < 30) {
          sensor.status = 'Error';
        } else if (sensor.healthScore < 60) {
          sensor.status = 'Degraded';
        } else if (sensor.status === 'Error' || sensor.status === 'Degraded') {
          sensor.status = 'Active';
        }
      }
      
      await sensor.save();
    }
    
    return sensors;
  }
};

const SecuritySensor = mongoose.model('SecuritySensor', securitySensorSchema);

module.exports = SecuritySensor;