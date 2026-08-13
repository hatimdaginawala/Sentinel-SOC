// models/SecurityAssessment.js

const mongoose = require('mongoose');

const securityAssessmentSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: [true, 'Organization is required'],
    index: true
  },
  title: {
    type: String,
    required: [true, 'Assessment title is required'],
    trim: true,
    maxlength: [200, 'Title cannot exceed 200 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [2000, 'Description cannot exceed 2000 characters']
  },
  date: {
    type: Date,
    default: Date.now
  },
  assessmentPeriod: {
    startDate: {
      type: Date,
      default: function() {
        const d = new Date();
        d.setDate(d.getDate() - 30);
        return d;
      }
    },
    endDate: {
      type: Date,
      default: Date.now
    }
  },
  threatsDetected: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Alert'
  }],
  incidents: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Incident'
  }],
  affectedAssets: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Asset'
  }],
  riskLevel: {
    type: String,
    enum: ['Low', 'Medium', 'High', 'Critical'],
    default: 'Medium',
    index: true
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 10,
    default: 5
  },
  securityWeaknesses: [{
    type: String,
    trim: true
  }],
  recommendedControls: [{
    name: {
      type: String,
      required: true,
      trim: true
    },
    description: {
      type: String,
      trim: true
    },
    priority: {
      type: String,
      enum: ['Low', 'Medium', 'High', 'Critical'],
      default: 'Medium'
    },
    status: {
      type: String,
      enum: ['Pending', 'In Progress', 'Completed', 'Not Started'],
      default: 'Pending'
    },
    implementationDate: {
      type: Date
    },
    implementedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  }],
  mitigations: [{
    name: {
      type: String,
      required: true,
      trim: true
    },
    description: {
      type: String,
      trim: true
    },
    priority: {
      type: String,
      enum: ['Low', 'Medium', 'High', 'Critical'],
      default: 'Medium'
    },
    status: {
      type: String,
      enum: ['Pending', 'In Progress', 'Completed', 'Not Started'],
      default: 'Pending'
    },
    implementationDate: {
      type: Date
    },
    implementedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  }],
  status: {
    type: String,
    enum: ['Draft', 'In Progress', 'Review', 'Final'],
    default: 'Draft',
    index: true
  },
  summary: {
    type: String,
    trim: true,
    maxlength: [5000, 'Summary cannot exceed 5000 characters']
  },
  nextReviewDate: {
    type: Date
  },
  reviewedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  reviewedAt: {
    type: Date
  },
  tags: [{
    type: String,
    trim: true
  }],
  version: {
    type: Number,
    default: 1
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
securityAssessmentSchema.index({ organization: 1, riskLevel: 1 });
securityAssessmentSchema.index({ organization: 1, status: 1 });
securityAssessmentSchema.index({ organization: 1, createdAt: -1 });
securityAssessmentSchema.index({ organization: 1, date: -1 });
securityAssessmentSchema.index({ tags: 1 });

// Pre-save middleware
securityAssessmentSchema.pre('save', function(next) {
  if (this.isNew) {
    this.createdAt = new Date();
    this.updatedAt = new Date();
  } else {
    this.updatedAt = new Date();
  }
  
  // Auto-calculate risk score based on risk level
  const riskScoreMap = {
    'Low': 2,
    'Medium': 5,
    'High': 8,
    'Critical': 10
  };
  this.riskScore = riskScoreMap[this.riskLevel] || 5;
  
  // Set next review date if not set
  if (!this.nextReviewDate) {
    const d = new Date();
    d.setMonth(d.getMonth() + 3); // 3 months from now
    this.nextReviewDate = d;
  }
  
  next();
});

// Instance methods
securityAssessmentSchema.methods = {
  /**
   * Update assessment status
   */
  async updateStatus(newStatus, userId) {
    const validTransitions = {
      'Draft': ['In Progress', 'Review'],
      'In Progress': ['Review', 'Final'],
      'Review': ['Final', 'In Progress'],
      'Final': ['Draft', 'Review']
    };
    
    if (!validTransitions[this.status] || !validTransitions[this.status].includes(newStatus)) {
      throw new Error(`Invalid status transition from ${this.status} to ${newStatus}`);
    }
    
    this.status = newStatus;
    this.updatedBy = userId;
    
    if (newStatus === 'Final') {
      this.reviewedAt = new Date();
      this.reviewedBy = userId;
    }
    
    await this.save();
    return this;
  },

  /**
   * Add a security weakness
   */
  async addWeakness(weakness) {
    if (!this.securityWeaknesses.includes(weakness)) {
      this.securityWeaknesses.push(weakness);
      await this.save();
    }
    return this;
  },

  /**
   * Add a recommended control
   */
  async addControl(control) {
    this.recommendedControls.push(control);
    await this.save();
    return this;
  },

  /**
   * Add a mitigation
   */
  async addMitigation(mitigation) {
    this.mitigations.push(mitigation);
    await this.save();
    return this;
  },

  /**
   * Link threats (alerts) to assessment
   */
  async linkThreats(alertIds) {
    const uniqueAlerts = [...new Set(alertIds)];
    for (const alertId of uniqueAlerts) {
      if (!this.threatsDetected.includes(alertId)) {
        this.threatsDetected.push(alertId);
      }
    }
    await this.save();
    return this;
  },

  /**
   * Link incidents to assessment
   */
  async linkIncidents(incidentIds) {
    const uniqueIncidents = [...new Set(incidentIds)];
    for (const incidentId of uniqueIncidents) {
      if (!this.incidents.includes(incidentId)) {
        this.incidents.push(incidentId);
      }
    }
    await this.save();
    return this;
  },

  /**
   * Link assets to assessment
   */
  async linkAssets(assetIds) {
    const uniqueAssets = [...new Set(assetIds)];
    for (const assetId of uniqueAssets) {
      if (!this.affectedAssets.includes(assetId)) {
        this.affectedAssets.push(assetId);
      }
    }
    await this.save();
    return this;
  },

  /**
   * Calculate risk level based on linked data
   */
  async calculateRiskLevel() {
    // Get all linked alerts and incidents
    const Alert = mongoose.model('Alert');
    const Incident = mongoose.model('Incident');
    
    const alerts = await Alert.find({ _id: { $in: this.threatsDetected } });
    const incidents = await Incident.find({ _id: { $in: this.incidents } });
    
    // Count critical/high severity items
    const criticalAlerts = alerts.filter(a => a.severity === 'critical').length;
    const highAlerts = alerts.filter(a => a.severity === 'high').length;
    const criticalIncidents = incidents.filter(i => i.severity === 'critical').length;
    const highIncidents = incidents.filter(i => i.severity === 'high').length;
    
    // Calculate risk score
    let score = 0;
    score += criticalAlerts * 2;
    score += highAlerts * 1;
    score += criticalIncidents * 3;
    score += highIncidents * 2;
    
    // Determine risk level
    let riskLevel = 'Low';
    if (score >= 15) riskLevel = 'Critical';
    else if (score >= 10) riskLevel = 'High';
    else if (score >= 5) riskLevel = 'Medium';
    
    this.riskLevel = riskLevel;
    this.riskScore = Math.min(score, 10);
    await this.save();
    
    return this.riskLevel;
  },

  /**
   * Get assessment summary
   */
  getSummary() {
    return {
      id: this._id,
      title: this.title,
      date: this.date,
      riskLevel: this.riskLevel,
      riskScore: this.riskScore,
      status: this.status,
      threatCount: this.threatsDetected.length,
      incidentCount: this.incidents.length,
      assetCount: this.affectedAssets.length,
      weaknessCount: this.securityWeaknesses.length,
      controlCount: this.recommendedControls.length,
      mitigationCount: this.mitigations.length
    };
  },

  /**
   * Get completion percentage
   */
  getCompletionPercentage() {
    let completed = 0;
    let total = 0;
    
    // Count completed controls
    for (const control of this.recommendedControls) {
      total++;
      if (control.status === 'Completed') completed++;
    }
    
    // Count completed mitigations
    for (const mitigation of this.mitigations) {
      total++;
      if (mitigation.status === 'Completed') completed++;
    }
    
    if (total === 0) return 0;
    return Math.round((completed / total) * 100);
  },

  /**
   * Check if assessment is overdue for review
   */
  isOverdue() {
    if (!this.nextReviewDate) return false;
    return new Date() > this.nextReviewDate;
  }
};

// Static methods
securityAssessmentSchema.statics = {
  /**
   * Get assessments with pagination and filtering
   */
  async getAssessments(filters = {}) {
    const {
      organization,
      riskLevel,
      status,
      search,
      startDate,
      endDate,
      tags,
      page = 1,
      limit = 20,
      sort = '-createdAt'
    } = filters;

    const query = {};

    if (organization) query.organization = organization;
    if (riskLevel && riskLevel !== 'all') query.riskLevel = riskLevel;
    if (status && status !== 'all') query.status = status;
    if (tags && tags.length > 0) query.tags = { $in: tags };

    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const skip = (page - 1) * limit;

    const [assessments, total] = await Promise.all([
      this.find(query)
        .populate('organization', 'name code')
        .populate('threatsDetected', 'title severity status')
        .populate('incidents', 'title severity status')
        .populate('affectedAssets', 'name hostname ipAddress type')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName')
        .populate('reviewedBy', 'username email firstName lastName')
        .populate('recommendedControls.implementedBy', 'username email firstName lastName')
        .populate('mitigations.implementedBy', 'username email firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      this.countDocuments(query)
    ]);

    return {
      assessments,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get assessment statistics
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
          draft: {
            $sum: { $cond: [{ $eq: ['$status', 'Draft'] }, 1, 0] }
          },
          inProgress: {
            $sum: { $cond: [{ $eq: ['$status', 'In Progress'] }, 1, 0] }
          },
          review: {
            $sum: { $cond: [{ $eq: ['$status', 'Review'] }, 1, 0] }
          },
          final: {
            $sum: { $cond: [{ $eq: ['$status', 'Final'] }, 1, 0] }
          },
          critical: {
            $sum: { $cond: [{ $eq: ['$riskLevel', 'Critical'] }, 1, 0] }
          },
          high: {
            $sum: { $cond: [{ $eq: ['$riskLevel', 'High'] }, 1, 0] }
          },
          medium: {
            $sum: { $cond: [{ $eq: ['$riskLevel', 'Medium'] }, 1, 0] }
          },
          low: {
            $sum: { $cond: [{ $eq: ['$riskLevel', 'Low'] }, 1, 0] }
          },
          avgRiskScore: { $avg: '$riskScore' }
        }
      }
    ]);

    // Get breakdown by risk level
    const riskStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$riskLevel',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Get monthly trend
    const monthlyTrend = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1 } }
    ]);

    // Get total linked entities
    const linkedStats = await this.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          totalThreats: { $sum: { $size: '$threatsDetected' } },
          totalIncidents: { $sum: { $size: '$incidents' } },
          totalAssets: { $sum: { $size: '$affectedAssets' } },
          totalWeaknesses: { $sum: { $size: '$securityWeaknesses' } },
          totalControls: { $sum: { $size: '$recommendedControls' } },
          totalMitigations: { $sum: { $size: '$mitigations' } }
        }
      }
    ]);

    return {
      summary: stats[0] || {
        total: 0,
        draft: 0,
        inProgress: 0,
        review: 0,
        final: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        avgRiskScore: 0
      },
      riskBreakdown: riskStats,
      monthlyTrend: monthlyTrend,
      linked: linkedStats[0] || {
        totalThreats: 0,
        totalIncidents: 0,
        totalAssets: 0,
        totalWeaknesses: 0,
        totalControls: 0,
        totalMitigations: 0
      }
    };
  },

  /**
   * Get assessment with all populated references
   */
  async getAssessmentWithPopulated(id) {
    return await this.findById(id)
      .populate('organization', 'name code')
      .populate('threatsDetected', 'title severity status sourceIP createdAt')
      .populate('incidents', 'title severity status description createdAt')
      .populate('affectedAssets', 'name hostname ipAddress type criticality status')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName')
      .populate('reviewedBy', 'username email firstName lastName')
      .populate('recommendedControls.implementedBy', 'username email firstName lastName')
      .populate('mitigations.implementedBy', 'username email firstName lastName');
  },

  /**
   * Get assessments by risk level
   */
  async findByRiskLevel(riskLevel, organizationId = null) {
    const query = { riskLevel };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .populate('organization', 'name code')
      .sort({ date: -1 });
  },

  /**
   * Get assessments by status
   */
  async findByStatus(status, organizationId = null) {
    const query = { status };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .populate('organization', 'name code')
      .sort({ date: -1 });
  },

  /**
   * Search assessments
   */
  async searchAssessments(query, organizationId = null, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-createdAt' } = options;
    
    const filter = {
      $or: [
        { title: searchRegex },
        { description: searchRegex },
        { tags: { $in: [searchRegex] } },
        { 'securityWeaknesses': { $in: [searchRegex] } }
      ]
    };
    
    if (organizationId) filter.organization = organizationId;
    
    const skip = (page - 1) * limit;
    
    const [assessments, total] = await Promise.all([
      this.find(filter)
        .populate('organization', 'name code')
        .populate('threatsDetected', 'title severity')
        .populate('incidents', 'title severity')
        .populate('affectedAssets', 'name hostname')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);
    
    return {
      assessments,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get risk levels for dropdown
   */
  getRiskLevels() {
    return ['Low', 'Medium', 'High', 'Critical'].map(level => ({
      value: level,
      label: level
    }));
  },

  /**
   * Get statuses for dropdown
   */
  getStatuses() {
    return ['Draft', 'In Progress', 'Review', 'Final'].map(status => ({
      value: status,
      label: status
    }));
  },

  /**
   * Get control priority levels for dropdown
   */
  getPriorityLevels() {
    return ['Low', 'Medium', 'High', 'Critical'].map(priority => ({
      value: priority,
      label: priority
    }));
  },

  /**
   * Get control statuses for dropdown
   */
  getControlStatuses() {
    return ['Pending', 'In Progress', 'Completed', 'Not Started'].map(status => ({
      value: status,
      label: status
    }));
  }
};

const SecurityAssessment = mongoose.model('SecurityAssessment', securityAssessmentSchema);

module.exports = SecurityAssessment;