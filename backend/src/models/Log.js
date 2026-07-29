const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
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
  sourceType: {
    type: String,
    required: true,
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
  eventCategory: {
    type: String,
    required: true,
    enum: ['authentication', 'network', 'system', 'application', 'database', 'web', 'malware', 'policy', 'access', 'error'],
    index: true
  },
  eventType: {
    type: String,
    required: true,
    index: true
  },
  severity: {
    type: String,
    required: true,
    enum: ['critical', 'high', 'medium', 'low', 'info'],
    default: 'info',
    index: true
  },
  username: {
    type: String,
    trim: true,
    index: true
  },
  processName: {
    type: String,
    trim: true
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
  destinationPort: {
    type: Number,
    index: true
  },
  protocol: {
    type: String,
    trim: true,
    index: true
  },
  message: {
    type: String,
    required: true,
    trim: true
  },
  rawLog: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  normalizedData: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  eventTime: {
    type: Date,
    required: true,
    index: true
  },
  ingestionTime: {
    type: Date,
    default: Date.now,
    index: true
  },
  status: {
    type: String,
    enum: ['processed', 'failed', 'pending'],
    default: 'processed'
  },
  processingErrors: [{
    type: String
  }],
  tags: [{
    type: String,
    trim: true
  }],
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
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
// logSchema.index({ organization: 1, eventTime: -1 });
// logSchema.index({ organization: 1, eventCategory: 1 });
// logSchema.index({ organization: 1, severity: 1 });
// logSchema.index({ organization: 1, logSource: 1 });
// logSchema.index({ organization: 1, asset: 1 });
// logSchema.index({ organization: 1, sourceIP: 1 });
// logSchema.index({ organization: 1, destinationIP: 1 });
// logSchema.index({ eventTime: -1, severity: 1 });

// TTL index to automatically delete old logs (90 days retention)
logSchema.index({ eventTime: 1 }, { 
  expireAfterSeconds: 90 * 24 * 60 * 60 // 90 days
});

// Static methods
logSchema.statics = {
  /**
   * Get logs with pagination and filtering
   */
  async getLogs(filters = {}) {
    const {
      organization,
      asset,
      logSource,
      eventCategory,
      eventType,
      severity,
      status,
      search,
      startDate,
      endDate,
      sourceIP,
      destinationIP,
      username,
      page = 1,
      limit = 20,
      sort = '-eventTime'
    } = filters;

    const query = {};

    if (organization) query.organization = organization;
    if (asset) query.asset = asset;
    if (logSource) query.logSource = logSource;
    if (eventCategory && eventCategory !== 'all') query.eventCategory = eventCategory;
    if (eventType && eventType !== 'all') query.eventType = eventType;
    if (severity && severity !== 'all') query.severity = severity;
    if (status && status !== 'all') query.status = status;
    if (sourceIP) query.sourceIP = sourceIP;
    if (destinationIP) query.destinationIP = destinationIP;
    if (username) query.username = username;

    if (startDate || endDate) {
      query.eventTime = {};
      if (startDate) query.eventTime.$gte = new Date(startDate);
      if (endDate) query.eventTime.$lte = new Date(endDate);
    }

    if (search) {
      query.$or = [
        { message: { $regex: search, $options: 'i' } },
        { hostname: { $regex: search, $options: 'i' } },
        { ipAddress: { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } },
        { sourceIP: { $regex: search, $options: 'i' } },
        { destinationIP: { $regex: search, $options: 'i' } },
        { eventType: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      this.find(query)
        .populate('organization', 'name code')
        .populate('asset', 'name hostname ipAddress type')
        .populate('logSource', 'sourceName sourceType hostname')
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
   * Get log statistics
   */
  async getStatistics(organizationId = null, timeRange = '24h') {
    const match = {};
    if (organizationId) match.organization = mongoose.Types.ObjectId(organizationId);

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
    match.eventTime = { $gte: startDate };

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
          }
        }
      }
    ]);

    // Get breakdown by event category
    const categoryStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$eventCategory',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Get breakdown by source type
    const sourceTypeStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$sourceType',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Get top source IPs
    const topSourceIPs = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$sourceIP',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    // Get top event types
    const topEventTypes = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$eventType',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    // Get timeline data (group by hour)
    const timeline = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: {
            hour: { $hour: '$eventTime' },
            day: { $dayOfMonth: '$eventTime' },
            month: { $month: '$eventTime' },
            year: { $year: '$eventTime' }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1, '_id.hour': 1 } }
    ]);

    return {
      summary: stats[0] || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      categoryBreakdown: categoryStats,
      sourceTypeBreakdown: sourceTypeStats,
      topSourceIPs: topSourceIPs.filter(ip => ip._id && ip._id !== ''),
      topEventTypes: topEventTypes,
      timeline: timeline
    };
  },

  /**
   * Get logs by organization
   */
  async findByOrganization(organizationId, options = {}) {
    const { limit = 100, page = 1, sort = '-eventTime' } = options;
    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      this.find({ organization: organizationId })
        .populate('asset', 'name hostname ipAddress')
        .populate('logSource', 'sourceName sourceType')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments({ organization: organizationId })
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
   * Get logs by log source
   */
  async findByLogSource(logSourceId, options = {}) {
    const { limit = 100, page = 1, sort = '-eventTime' } = options;
    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      this.find({ logSource: logSourceId })
        .populate('organization', 'name code')
        .populate('asset', 'name hostname ipAddress')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments({ logSource: logSourceId })
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
   * Get logs with populated references
   */
  async getWithPopulated(id) {
    return await this.findById(id)
      .populate('organization', 'name code')
      .populate('asset', 'name hostname ipAddress type criticality')
      .populate('logSource', 'sourceName sourceType hostname ipAddress');
  },

  /**
   * Delete old logs based on retention period
   */
  async deleteOldLogs(retentionDays = 90) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    const result = await this.deleteMany({
      eventTime: { $lt: cutoffDate }
    });

    return result;
  }
};

const Log = mongoose.model('Log', logSchema);

module.exports = Log;