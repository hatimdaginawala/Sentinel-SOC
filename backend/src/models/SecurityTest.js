// models/SecurityTest.js

const mongoose = require('mongoose');

const securityTestSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Test name is required'],
    trim: true,
    maxlength: [100, 'Test name cannot exceed 100 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  testType: {
    type: String,
    required: [true, 'Test type is required'],
    enum: ['port_scan', 'brute_force', 'suspicious_traffic', 'unauthorized_connection', 'sql_injection', 'xss', 'other']
  },
  expectedDetection: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ThreatRule'
  },
  status: {
    type: String,
    enum: ['PENDING', 'RUNNING', 'PASS', 'FAIL'],
    default: 'PENDING',
    index: true
  },
  actualResult: {
    type: String,
    trim: true
  },
  resultDetails: {
    logGenerated: { type: Boolean, default: false },
    logIngested: { type: Boolean, default: false },
    detectionTriggered: { type: Boolean, default: false },
    alertCreated: { type: Boolean, default: false },
    incidentCreated: { type: Boolean, default: false },
    evidenceRecorded: { type: Boolean, default: false }
  },
  relatedAlert: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Alert'
  },
  relatedIncident: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Incident'
  },
  relatedLogs: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Log'
  }],
  payload: {
    type: mongoose.Schema.Types.Mixed,
    required: [true, 'Test payload is required']
  },
  executionTime: {
    type: Date
  },
  completedAt: {
    type: Date
  },
  errorMessage: {
    type: String,
    trim: true
  },
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
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
securityTestSchema.index({ organization: 1, status: 1 });
securityTestSchema.index({ organization: 1, testType: 1 });
securityTestSchema.index({ organization: 1, createdAt: -1 });
securityTestSchema.index({ status: 1, createdAt: -1 });

// Pre-save middleware
securityTestSchema.pre('save', function(next) {
  if (this.isNew) {
    this.createdAt = new Date();
    this.updatedAt = new Date();
  } else {
    this.updatedAt = new Date();
  }
  next();
});

// Instance methods
securityTestSchema.methods = {
  /**
   * Start the test execution
   */
  async startTest() {
    this.status = 'RUNNING';
    this.executionTime = new Date();
    await this.save();
    return this;
  },

  /**
   * Mark test as PASS with details
   */
  async markPass(resultDetails) {
    this.status = 'PASS';
    this.completedAt = new Date();
    this.resultDetails = resultDetails || this.resultDetails;
    await this.save();
    return this;
  },

  /**
   * Mark test as FAIL with details
   */
  async markFail(errorMessage, resultDetails) {
    this.status = 'FAIL';
    this.completedAt = new Date();
    this.errorMessage = errorMessage;
    this.resultDetails = resultDetails || this.resultDetails;
    await this.save();
    return this;
  },

  /**
   * Update test progress
   */
  async updateProgress(resultDetails) {
    this.resultDetails = { ...this.resultDetails, ...resultDetails };
    await this.save();
    return this;
  },

  /**
   * Link alert and incident to test
   */
  async linkResults(alertId, incidentId) {
    if (alertId) this.relatedAlert = alertId;
    if (incidentId) this.relatedIncident = incidentId;
    await this.save();
    return this;
  },

  /**
   * Add a log to the test
   */
  async addLog(logId) {
    if (!this.relatedLogs.includes(logId)) {
      this.relatedLogs.push(logId);
      await this.save();
    }
    return this;
  },

  /**
   * Check if test passed
   */
  isPassed() {
    return this.status === 'PASS';
  },

  /**
   * Get test summary
   */
  getSummary() {
    return {
      id: this._id,
      name: this.name,
      type: this.testType,
      status: this.status,
      duration: this.executionTime && this.completedAt 
        ? (this.completedAt - this.executionTime) / 1000 
        : null,
      resultDetails: this.resultDetails
    };
  }
};

// Static methods
securityTestSchema.statics = {
  /**
   * Get tests with pagination and filtering
   */
  async getTests(filters = {}) {
    const {
      organization,
      status,
      testType,
      search,
      startDate,
      endDate,
      page = 1,
      limit = 20,
      sort = '-createdAt'
    } = filters;

    const query = {};

    if (organization) query.organization = organization;
    if (status && status !== 'all') query.status = status;
    if (testType && testType !== 'all') query.testType = testType;

    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { testType: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (page - 1) * limit;

    const [tests, total] = await Promise.all([
      this.find(query)
        .populate('expectedDetection', 'name severity')
        .populate('relatedAlert', 'title severity status')
        .populate('relatedIncident', 'title severity status')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName')
        .populate('organization', 'name code')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      this.countDocuments(query)
    ]);

    return {
      tests,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get test statistics
   */
  async getStatistics(organizationId = null, timeRange = '7d') {
    const match = {};
    if (organizationId) match.organization = new mongoose.Types.ObjectId(organizationId);

    // Set time range
    const now = new Date();
    let startDate = new Date();
    switch(timeRange) {
      case '24h':
        startDate.setHours(now.getHours() - 24);
        break;
      case '7d':
        startDate.setDate(now.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(now.getDate() - 30);
        break;
      case '90d':
        startDate.setDate(now.getDate() - 90);
        break;
      default:
        startDate.setDate(now.getDate() - 7);
    }
    match.createdAt = { $gte: startDate };

    const stats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          passed: {
            $sum: { $cond: [{ $eq: ['$status', 'PASS'] }, 1, 0] }
          },
          failed: {
            $sum: { $cond: [{ $eq: ['$status', 'FAIL'] }, 1, 0] }
          },
          running: {
            $sum: { $cond: [{ $eq: ['$status', 'RUNNING'] }, 1, 0] }
          },
          pending: {
            $sum: { $cond: [{ $eq: ['$status', 'PENDING'] }, 1, 0] }
          }
        }
      }
    ]);

    // Get breakdown by test type
    const typeStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$testType',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Get recent test results
    const recentTests = await this.find(match)
      .sort({ createdAt: -1 })
      .limit(10)
      .select('name testType status createdAt')
      .populate('createdBy', 'username');

    return {
      summary: stats[0] || { total: 0, passed: 0, failed: 0, running: 0, pending: 0 },
      typeBreakdown: typeStats,
      recentTests: recentTests
    };
  },

  /**
   * Find test with all populated references
   */
  async getTestWithPopulated(id) {
    return await this.findById(id)
      .populate('expectedDetection', 'name severity category')
      .populate('relatedAlert', 'title severity status sourceIP message')
      .populate('relatedIncident', 'title severity status description')
      .populate('relatedLogs', 'eventType severity message sourceIP eventTime')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName')
      .populate('organization', 'name code');
  },

  /**
   * Get test types for dropdown
   */
  getTestTypes() {
    return [
      { value: 'port_scan', label: 'Port Scan' },
      { value: 'brute_force', label: 'Brute Force' },
      { value: 'suspicious_traffic', label: 'Suspicious Traffic' },
      { value: 'unauthorized_connection', label: 'Unauthorized Connection' },
      { value: 'sql_injection', label: 'SQL Injection' },
      { value: 'xss', label: 'Cross-Site Scripting (XSS)' },
      { value: 'other', label: 'Other' }
    ];
  },

  /**
   * Get statuses for dropdown
   */
  getStatuses() {
    return [
      { value: 'PENDING', label: 'Pending' },
      { value: 'RUNNING', label: 'Running' },
      { value: 'PASS', label: 'Passed' },
      { value: 'FAIL', label: 'Failed' }
    ];
  }
};

const SecurityTest = mongoose.model('SecurityTest', securityTestSchema);

module.exports = SecurityTest;