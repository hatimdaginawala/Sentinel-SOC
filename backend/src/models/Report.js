const mongoose = require('mongoose');
const { REPORT_TYPES, REPORT_FORMATS, SEVERITY } = require('../config/constants');

const reportSchema = new mongoose.Schema({
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
    trim: true
  },
  type: {
    type: String,
    enum: Object.values(REPORT_TYPES),
    required: true,
    index: true
  },
  format: {
    type: String,
    enum: Object.values(REPORT_FORMATS),
    default: REPORT_FORMATS.PDF,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed', 'cancelled'],
    default: 'pending',
    index: true
  },
  filters: {
    startDate: {
      type: Date,
      required: true
    },
    endDate: {
      type: Date,
      required: true
    },
    organization: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Organization'
    },
    severity: [{
      type: String,
      enum: Object.values(SEVERITY)
    }],
    status: [{
      type: String,
      enum: ['active', 'investigating', 'resolved', 'closed', 'suppressed']
    }],
    categories: [{
      type: String
    }],
    threatTypes: [{
      type: String
    }],
    assignedTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    includeResolved: {
      type: Boolean,
      default: false
    },
    includeClosed: {
      type: Boolean,
      default: false
    }
  },
  data: {
  summary: {
    total: { type: Number, default: 0 },
    alerts: { type: Number, default: 0 },    // add
    incidents: { type: Number, default: 0 }, // add
    logs: { type: Number, default: 0 },      // add
    critical: { type: Number, default: 0 },
    high: { type: Number, default: 0 },
    medium: { type: Number, default: 0 },
    low: { type: Number, default: 0 },
    info: { type: Number, default: 0 },
      byStatus: {
        active: { type: Number, default: 0 },
        investigating: { type: Number, default: 0 },
        resolved: { type: Number, default: 0 },
        closed: { type: Number, default: 0 },
        suppressed: { type: Number, default: 0 }
      }
    },
     alerts: { type: mongoose.Schema.Types.Mixed, default: [] },
  incidents: { type: mongoose.Schema.Types.Mixed, default: [] },
    categories: [{
      name: { type: String },
      count: { type: Number }
    }],
    threatTypes: [{
      name: { type: String },
      count: { type: Number }
    }],
    timeline: [{
      date: { type: Date },
      count: { type: Number }
    }],
    topSources: [{
      source: { type: String },
      count: { type: Number }
    }],
    topTargets: [{
      target: { type: String },
      count: { type: Number }
    }],
    detailed: {
      type: mongoose.Schema.Types.Mixed
    }
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
  filePath: {
    type: String,
    trim: true
  },
  generatedAt: {
    type: Date
  },
  expiresAt: {
    type: Date,
    default: function() {
      const date = new Date();
      date.setDate(date.getDate() + 7); // 7 days expiry
      return date;
    }
  },
  errorMessage: {
    type: String,
    trim: true
  },
  scheduled: {
    enabled: {
      type: Boolean,
      default: false
    },
    frequency: {
      type: String,
      enum: ['daily', 'weekly', 'monthly', 'quarterly'],
    },
    time: {
      type: String,
      match: /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/
    },
    dayOfWeek: {
      type: Number,
      min: 0,
      max: 6
    },
    dayOfMonth: {
      type: Number,
      min: 1,
      max: 31
    },
    lastRun: {
      type: Date
    },
    nextRun: {
      type: Date
    },
    recipients: [{
      type: String,
      match: /^\S+@\S+\.\S+$/
    }]
  },
  tags: [{
    type: String,
    trim: true
  }],
  version: {
    type: Number,
    default: 1
  },
  generatedBy: {
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

// Indexes for performance
reportSchema.index({ organization: 1, type: 1 });
reportSchema.index({ organization: 1, status: 1 });
reportSchema.index({ organization: 1, createdAt: -1 });
reportSchema.index({ type: 1, status: 1 });
reportSchema.index({ generatedAt: -1 });
reportSchema.index({ 'scheduled.enabled': 1 });
reportSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Pre-save middleware
reportSchema.pre('save', function(next) {
  if (this.isNew) {
    // Set default title if not provided
    if (!this.title) {
      const typeLabels = {
        daily: 'Daily',
        weekly: 'Weekly',
        monthly: 'Monthly',
        executive: 'Executive',
        incident: 'Incident',
        risk: 'Risk',
        compliance: 'Compliance'
      };
      const typeLabel = typeLabels[this.type] || 'Security';
      const dateStr = new Date().toISOString().split('T')[0];
      this.title = `${typeLabel} Security Report - ${dateStr}`;
    }
    
    // Set expiration date
    if (!this.expiresAt) {
      const date = new Date();
      date.setDate(date.getDate() + 7);
      this.expiresAt = date;
    }
  }
  next();
});

// Instance methods
reportSchema.methods = {
  /**
   * Check if report is expired
   */
  isExpired() {
    return this.expiresAt && new Date() > this.expiresAt;
  },

  /**
   * Check if report is downloadable
   */
  isDownloadable() {
    return this.status === 'completed' && this.fileUrl && !this.isExpired();
  },

  /**
   * Mark report as completed
   */
  async markCompleted(fileInfo) {
    this.status = 'completed';
    this.generatedAt = new Date();
    if (fileInfo) {
      this.fileUrl = fileInfo.url;
      this.fileName = fileInfo.name;
      this.fileSize = fileInfo.size;
      this.filePath = fileInfo.path;
    }
    await this.save();
    return this;
  },

  /**
   * Mark report as failed
   */
  async markFailed(errorMessage) {
    this.status = 'failed';
    this.errorMessage = errorMessage;
    await this.save();
    return this;
  },

  /**
   * Mark report as processing
   */
  async markProcessing() {
    this.status = 'processing';
    await this.save();
    return this;
  },

  /**
   * Update report data
   */
  async updateData(data) {
    this.data = data;
    await this.save();
    return this;
  },

  /**
   * Get report duration in days
   */
  getDurationInDays() {
    if (!this.filters.startDate || !this.filters.endDate) return 0;
    return Math.ceil((this.filters.endDate - this.filters.startDate) / (1000 * 60 * 60 * 24));
  },

  /**
   * Get file size in human-readable format
   */
  getFileSizeReadable() {
    if (!this.fileSize) return 'N/A';
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = this.fileSize;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    return `${size.toFixed(1)} ${units[unitIndex]}`;
  }
};

// Static methods
reportSchema.statics = {
  /**
   * Get reports with pagination and filtering
   */
  async getReports(filters = {}) {
    const {
      organization,
      type,
      status,
      format,
      search,
      startDate,
      endDate,
      scheduledOnly,
      page = 1,
      limit = 20,
      sort = '-createdAt'
    } = filters;

    const query = {};

    if (organization) query.organization = organization;
    if (type && type !== 'all') query.type = type;
    if (status && status !== 'all') query.status = status;
    if (format && format !== 'all') query.format = format;
    if (scheduledOnly === 'true') query['scheduled.enabled'] = true;

    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const skip = (page - 1) * limit;

    const [reports, total] = await Promise.all([
      this.find(query)
        .populate('organization', 'name code')
        .populate('generatedBy', 'username email firstName lastName')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      this.countDocuments(query)
    ]);

    return {
      reports,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get report statistics
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
          pending: {
            $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
          },
          processing: {
            $sum: { $cond: [{ $eq: ['$status', 'processing'] }, 1, 0] }
          },
          completed: {
            $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
          },
          failed: {
            $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
          },
          cancelled: {
            $sum: { $cond: [{ $eq: ['$status', 'cancelled'] }, 1, 0] }
          },
          scheduled: {
            $sum: { $cond: [{ $eq: ['$scheduled.enabled', true] }, 1, 0] }
          },
          avgGenerationTime: { $avg: { $subtract: ['$generatedAt', '$createdAt'] } }
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

    // Get breakdown by format
    const formatStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$format',
          count: { $sum: 1 }
        }
      }
    ]);

    return {
      summary: stats[0] || {
        total: 0,
        pending: 0,
        processing: 0,
        completed: 0,
        failed: 0,
        cancelled: 0,
        scheduled: 0,
        avgGenerationTime: 0
      },
      typeBreakdown: typeStats,
      formatBreakdown: formatStats
    };
  },

  /**
   * Get scheduled reports
   */
  async getScheduledReports(organizationId = null) {
    const query = { 'scheduled.enabled': true };
    if (organizationId) query.organization = organizationId;

    return await this.find(query)
      .populate('organization', 'name code')
      .sort({ 'scheduled.nextRun': 1 });
  },

  /**
   * Get reports by date range
   */
  async getReportsByDateRange(organizationId = null, startDate, endDate) {
    const query = {};
    if (organizationId) query.organization = organizationId;
    
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    return await this.find(query)
      .populate('organization', 'name code')
      .sort({ createdAt: -1 });
  },

  /**
   * Get report types for dropdown
   */
  getReportTypes() {
    return Object.values(REPORT_TYPES).map(type => ({
      value: type,
      label: type.charAt(0).toUpperCase() + type.slice(1)
    }));
  },

  /**
   * Get report formats for dropdown
   */
  getReportFormats() {
    return Object.values(REPORT_FORMATS).map(format => ({
      value: format,
      label: format.toUpperCase()
    }));
  },

  /**
   * Get report statuses for dropdown
   */
  getReportStatuses() {
    return ['pending', 'processing', 'completed', 'failed', 'cancelled'].map(status => ({
      value: status,
      label: status.charAt(0).toUpperCase() + status.slice(1)
    }));
  },

  /**
   * Get scheduled frequencies for dropdown
   */
  getScheduledFrequencies() {
    return ['daily', 'weekly', 'monthly', 'quarterly'].map(freq => ({
      value: freq,
      label: freq.charAt(0).toUpperCase() + freq.slice(1)
    }));
  }
};

const Report = mongoose.model('Report', reportSchema);

module.exports = Report;