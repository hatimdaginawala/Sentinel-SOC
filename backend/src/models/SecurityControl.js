// models/SecurityControl.js

const mongoose = require('mongoose');

const securityControlItemSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Control name is required'],
    trim: true,
    maxlength: [200, 'Name cannot exceed 200 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [1000, 'Description cannot exceed 1000 characters']
  },
  priority: {
    type: String,
    enum: ['Critical', 'High', 'Medium', 'Low'],
    default: 'Medium'
  },
  status: {
    type: String,
    enum: ['Pending', 'In Progress', 'Implemented', 'Verified', 'Not Applicable'],
    default: 'Pending'
  },
  implementationDate: {
    type: Date
  },
  implementedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  verifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  verifiedAt: {
    type: Date
  },
  evidence: {
    type: String,
    trim: true
  },
  notes: {
    type: String,
    trim: true
  }
}, { _id: false });

const securityControlSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: [true, 'Organization is required'],
    index: true
  },
  threatRule: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ThreatRule',
    required: [true, 'Threat rule is required'],
    index: true
  },
  threatName: {
    type: String,
    required: [true, 'Threat name is required'],
    trim: true,
    maxlength: [200, 'Threat name cannot exceed 200 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [2000, 'Description cannot exceed 2000 characters']
  },
  securityImpact: {
    type: String,
    trim: true,
    maxlength: [2000, 'Security impact cannot exceed 2000 characters']
  },
  riskLevel: {
    type: String,
    enum: ['Critical', 'High', 'Medium', 'Low'],
    default: 'Medium'
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 10,
    default: 5
  },
  recommendedControls: [securityControlItemSchema],
  mitigations: [securityControlItemSchema],
  analystActions: [securityControlItemSchema],
  complianceFrameworks: [{
    type: String,
    enum: ['NIST', 'ISO27001', 'SOC2', 'HIPAA', 'GDPR', 'PCI-DSS', 'NERC-CIP', 'Other']
  }],
  tags: [{
    type: String,
    trim: true
  }],
  references: [{
    type: String,
    trim: true
  }],
  version: {
    type: Number,
    default: 1
  },
  status: {
    type: String,
    enum: ['Draft', 'Active', 'Deprecated', 'Archived'],
    default: 'Active'
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
securityControlSchema.index({ organization: 1, threatRule: 1 });
securityControlSchema.index({ organization: 1, threatName: 1 });
securityControlSchema.index({ organization: 1, status: 1 });
securityControlSchema.index({ organization: 1, riskLevel: 1 });
securityControlSchema.index({ tags: 1 });
securityControlSchema.index({ 'recommendedControls.status': 1 });

// Pre-save middleware
securityControlSchema.pre('save', function(next) {
  if (this.isNew) {
    this.createdAt = new Date();
    this.updatedAt = new Date();
  } else {
    this.updatedAt = new Date();
  }
  
  // Calculate risk score based on risk level and priority
  const riskMap = {
    'Critical': 10,
    'High': 7,
    'Medium': 5,
    'Low': 3
  };
  this.riskScore = riskMap[this.riskLevel] || 5;
  
  // Update version on change
  if (!this.isNew) {
    this.version += 1;
  }
  
  next();
});

// Instance methods
securityControlSchema.methods = {
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
   * Add an analyst action
   */
  async addAnalystAction(action) {
    this.analystActions.push(action);
    await this.save();
    return this;
  },

  /**
   * Update control status
   */
  async updateStatus(newStatus, userId) {
    const validTransitions = {
      'Draft': ['Active'],
      'Active': ['Deprecated', 'Archived'],
      'Deprecated': ['Archived'],
      'Archived': ['Active']
    };
    
    if (!validTransitions[this.status] || !validTransitions[this.status].includes(newStatus)) {
      throw new Error(`Invalid status transition from ${this.status} to ${newStatus}`);
    }
    
    this.status = newStatus;
    this.updatedBy = userId;
    await this.save();
    return this;
  },

  /**
   * Get control effectiveness score
   */
  getEffectivenessScore() {
    const total = this.recommendedControls.length + this.mitigations.length;
    if (total === 0) return 0;
    
    const implemented = this.recommendedControls.filter(c => c.status === 'Implemented' || c.status === 'Verified').length;
    const mitigated = this.mitigations.filter(m => m.status === 'Implemented' || m.status === 'Verified').length;
    
    return Math.round(((implemented + mitigated) / total) * 100);
  },

  /**
   * Get completion status summary
   */
  getCompletionSummary() {
    const controls = this.recommendedControls;
    const mitigations = this.mitigations;
    const actions = this.analystActions;
    
    const total = controls.length + mitigations.length + actions.length;
    if (total === 0) return { total: 0, completed: 0, percentage: 0 };
    
    const completed = [
      ...controls.filter(c => c.status === 'Implemented' || c.status === 'Verified'),
      ...mitigations.filter(m => m.status === 'Implemented' || m.status === 'Verified'),
      ...actions.filter(a => a.status === 'Completed' || a.status === 'Verified')
    ].length;
    
    return {
      total,
      completed,
      percentage: Math.round((completed / total) * 100)
    };
  },

  /**
   * Check if control is fully implemented
   */
  isFullyImplemented() {
    const summary = this.getCompletionSummary();
    return summary.percentage === 100;
  },

  /**
   * Get priority matrix
   */
  getPriorityMatrix() {
    return {
      controls: {
        high: this.recommendedControls.filter(c => c.priority === 'High' || c.priority === 'Critical').length,
        medium: this.recommendedControls.filter(c => c.priority === 'Medium').length,
        low: this.recommendedControls.filter(c => c.priority === 'Low').length
      },
      mitigations: {
        high: this.mitigations.filter(m => m.priority === 'High' || m.priority === 'Critical').length,
        medium: this.mitigations.filter(m => m.priority === 'Medium').length,
        low: this.mitigations.filter(m => m.priority === 'Low').length
      }
    };
  }
};

// Static methods
securityControlSchema.statics = {
  /**
   * Get controls with pagination and filtering
   */
  async getControls(filters = {}) {
    const {
      organization,
      threatRule,
      threatName,
      status,
      riskLevel,
      search,
      tags,
      complianceFrameworks,
      page = 1,
      limit = 20,
      sort = '-createdAt'
    } = filters;

    const query = {};

    if (organization) query.organization = organization;
    if (threatRule) query.threatRule = threatRule;
    if (threatName) query.threatName = { $regex: threatName, $options: 'i' };
    if (status && status !== 'all') query.status = status;
    if (riskLevel && riskLevel !== 'all') query.riskLevel = riskLevel;
    if (tags && tags.length > 0) query.tags = { $in: tags };
    if (complianceFrameworks && complianceFrameworks.length > 0) {
      query.complianceFrameworks = { $in: complianceFrameworks };
    }

    if (search) {
      query.$or = [
        { threatName: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { securityImpact: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const skip = (page - 1) * limit;

    const [controls, total] = await Promise.all([
      this.find(query)
        .populate('organization', 'name code')
        .populate('threatRule', 'name severity category type')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName')
        .populate('recommendedControls.implementedBy', 'username email firstName lastName')
        .populate('recommendedControls.verifiedBy', 'username email firstName lastName')
        .populate('mitigations.implementedBy', 'username email firstName lastName')
        .populate('mitigations.verifiedBy', 'username email firstName lastName')
        .populate('analystActions.implementedBy', 'username email firstName lastName')
        .populate('analystActions.verifiedBy', 'username email firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      this.countDocuments(query)
    ]);

    return {
      controls,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get control statistics
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
          active: {
            $sum: { $cond: [{ $eq: ['$status', 'Active'] }, 1, 0] }
          },
          deprecated: {
            $sum: { $cond: [{ $eq: ['$status', 'Deprecated'] }, 1, 0] }
          },
          archived: {
            $sum: { $cond: [{ $eq: ['$status', 'Archived'] }, 1, 0] }
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
          avgRiskScore: { $avg: '$riskScore' },
          totalControls: { $sum: { $size: '$recommendedControls' } },
          totalMitigations: { $sum: { $size: '$mitigations' } },
          totalActions: { $sum: { $size: '$analystActions' } }
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

    // Get compliance framework breakdown
    const complianceStats = await this.aggregate([
      { $match: match },
      { $unwind: '$complianceFrameworks' },
      {
        $group: {
          _id: '$complianceFrameworks',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    return {
      summary: stats[0] || {
        total: 0,
        draft: 0,
        active: 0,
        deprecated: 0,
        archived: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        avgRiskScore: 0,
        totalControls: 0,
        totalMitigations: 0,
        totalActions: 0
      },
      riskBreakdown: riskStats,
      complianceBreakdown: complianceStats
    };
  },

  /**
   * Get controls by threat rule
   */
  async findByThreatRule(threatRuleId, organizationId = null) {
    const query = { threatRule: threatRuleId };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .populate('threatRule', 'name severity category')
      .sort({ threatName: 1 });
  },

  /**
   * Get controls by risk level
   */
  async findByRiskLevel(riskLevel, organizationId = null) {
    const query = { riskLevel };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .populate('threatRule', 'name severity')
      .sort({ riskScore: -1 });
  },

  /**
   * Get control with all populated references
   */
  async getControlWithPopulated(id) {
    return await this.findById(id)
      .populate('organization', 'name code')
      .populate('threatRule', 'name severity category type threatType')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName')
      .populate('recommendedControls.implementedBy', 'username email firstName lastName')
      .populate('recommendedControls.verifiedBy', 'username email firstName lastName')
      .populate('mitigations.implementedBy', 'username email firstName lastName')
      .populate('mitigations.verifiedBy', 'username email firstName lastName')
      .populate('analystActions.implementedBy', 'username email firstName lastName')
      .populate('analystActions.verifiedBy', 'username email firstName lastName');
  },

  /**
   * Search controls
   */
  async searchControls(query, organizationId = null, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-createdAt' } = options;
    
    const filter = {
      $or: [
        { threatName: searchRegex },
        { description: searchRegex },
        { securityImpact: searchRegex },
        { tags: { $in: [searchRegex] } },
        { 'recommendedControls.name': searchRegex },
        { 'mitigations.name': searchRegex },
        { 'analystActions.name': searchRegex }
      ]
    };
    
    if (organizationId) filter.organization = organizationId;
    
    const skip = (page - 1) * limit;
    
    const [controls, total] = await Promise.all([
      this.find(filter)
        .populate('organization', 'name code')
        .populate('threatRule', 'name severity')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);
    
    return {
      controls,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get priority levels for dropdown
   */
  getPriorityLevels() {
    return ['Critical', 'High', 'Medium', 'Low'].map(priority => ({
      value: priority,
      label: priority
    }));
  },

  /**
   * Get statuses for dropdown
   */
  getStatuses() {
    return ['Draft', 'Active', 'Deprecated', 'Archived'].map(status => ({
      value: status,
      label: status
    }));
  },

  /**
   * Get control statuses for dropdown
   */
  getControlStatuses() {
    return ['Pending', 'In Progress', 'Implemented', 'Verified', 'Not Applicable'].map(status => ({
      value: status,
      label: status
    }));
  },

  /**
   * Get compliance frameworks for dropdown
   */
  getComplianceFrameworks() {
    return ['NIST', 'ISO27001', 'SOC2', 'HIPAA', 'GDPR', 'PCI-DSS', 'NERC-CIP', 'Other'].map(framework => ({
      value: framework,
      label: framework
    }));
  },

  /**
   * Get risk levels for dropdown
   */
  getRiskLevels() {
    return ['Critical', 'High', 'Medium', 'Low'].map(level => ({
      value: level,
      label: level
    }));
  }
};

const SecurityControl = mongoose.model('SecurityControl', securityControlSchema);

module.exports = SecurityControl;