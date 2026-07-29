const mongoose = require('mongoose');
const { SEVERITY, RULE_TYPES } = require('../config/constants');

const threatRuleSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
  },
  name: {
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
  type: {
    type: String,
    enum: Object.values(RULE_TYPES),
    required: true,
    index: true
  },
  severity: {
    type: String,
    enum: Object.values(SEVERITY),
    required: true,
    index: true
  },
  category: {
    type: String,
    enum: ['authentication', 'network', 'system', 'application', 'database', 'web', 'malware', 'policy', 'access', 'error', 'ids', 'firewall'],
    required: true,
    index: true
  },
  threatType: {
    type: String,
    enum: [
      'brute_force', 'sql_injection', 'xss', 'command_injection', 'rce',
      'reverse_shell', 'port_scan', 'malware_communication', 'dns_tunneling',
      'data_exfiltration', 'dos_attack', 'privilege_escalation',
      'suspicious_powershell', 'unauthorized_access', 'beaconing',
      'ddos', 'malware', 'phishing', 'ransomware'
    ],
    index: true
  },
  condition: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  actions: {
    type: [{
      type: {
        type: String,
        enum: ['alert', 'block', 'notify', 'log', 'quarantine', 'isolate'],
        required: true
      },
      configuration: {
        type: Map,
        of: mongoose.Schema.Types.Mixed
      }
    }],
    default: []
  },
  enabled: {
    type: Boolean,
    default: true,
    index: true
  },
  priority: {
    type: Number,
    min: 1,
    max: 10,
    default: 5
  },
  cooldown: {
    type: Number,
    default: 60, // seconds
    min: 0
  },
  suppression: {
    enabled: {
      type: Boolean,
      default: false
    },
    threshold: {
      type: Number,
      default: 5 // number of occurrences before suppression
    },
    duration: {
      type: Number,
      default: 300 // seconds
    },
    suppressUntil: {
      type: Date
    }
  },
  tags: [{
    type: String,
    trim: true
  }],
  references: [{
    type: String,
    trim: true
  }],
  mitreAttack: [{
    technique: {
      type: String,
      trim: true
    },
    tactic: {
      type: String,
      trim: true
    },
    id: {
      type: String,
      trim: true
    }
  }],
  lastTriggered: {
    type: Date
  },
  triggerCount: {
    type: Number,
    default: 0
  },
  falsePositives: {
    type: Number,
    default: 0
  },
  truePositives: {
    type: Number,
    default: 0
  },
  version: {
    type: Number,
    default: 1
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
threatRuleSchema.index({ organization: 1, enabled: 1 });
threatRuleSchema.index({ organization: 1, type: 1 });
threatRuleSchema.index({ organization: 1, severity: 1 });
threatRuleSchema.index({ organization: 1, category: 1 });
threatRuleSchema.index({ threatType: 1, organization: 1 });
threatRuleSchema.index({ priority: -1, organization: 1 });
threatRuleSchema.index({ tags: 1 });

// Pre-save middleware
threatRuleSchema.pre('save', function(next) {
  if (this.isNew) {
    this.version = 1;
  } else {
    this.version += 1;
  }
  
  // Reset suppression if re-enabled
  if (this.isModified('suppression.enabled') && this.suppression.enabled) {
    this.suppression.suppressUntil = null;
  }
  
  next();
});

// Instance methods
threatRuleSchema.methods = {
  /**
   * Check if rule is currently suppressed
   */
  isSuppressed() {
    if (!this.suppression.enabled) return false;
    if (!this.suppression.suppressUntil) return false;
    return new Date() < this.suppression.suppressUntil;
  },

  /**
   * Check if rule should be triggered
   */
  shouldTrigger(log) {
    if (!this.enabled) return false;
    if (this.isSuppressed()) return false;
    
    // Check if log matches condition
    return this.matchesCondition(log);
  },

  /**
   * Match log against rule condition
   */
  matchesCondition(log) {
    const condition = this.condition;
    let result = true;

    // Check each condition
    for (const [key, value] of Object.entries(condition)) {
      if (key === '$and') {
        // AND condition
        result = result && value.every(cond => this.evaluateCondition(cond, log));
      } else if (key === '$or') {
        // OR condition
        result = result && value.some(cond => this.evaluateCondition(cond, log));
      } else if (key === '$not') {
        // NOT condition
        result = result && !this.evaluateCondition(value, log);
      } else {
        // Simple field comparison
        result = result && this.evaluateFieldCondition(key, value, log);
      }
    }

    return result;
  },

  /**
   * Evaluate a single condition
   */
  evaluateCondition(condition, log) {
    for (const [key, value] of Object.entries(condition)) {
      if (key === '$and') {
        return value.every(cond => this.evaluateCondition(cond, log));
      } else if (key === '$or') {
        return value.some(cond => this.evaluateCondition(cond, log));
      } else if (key === '$not') {
        return !this.evaluateCondition(value, log);
      } else {
        return this.evaluateFieldCondition(key, value, log);
      }
    }
    return false;
  },

  /**
   * Evaluate a field condition
   */
  evaluateFieldCondition(field, value, log) {
    const logValue = this.getValueFromPath(log, field);
    
    if (logValue === undefined) return false;

    // Handle different operators
    if (typeof value === 'object' && value !== null) {
      for (const [operator, operand] of Object.entries(value)) {
        switch (operator) {
          case '$eq':
            return logValue === operand;
          case '$ne':
            return logValue !== operand;
          case '$gt':
            return logValue > operand;
          case '$gte':
            return logValue >= operand;
          case '$lt':
            return logValue < operand;
          case '$lte':
            return logValue <= operand;
          case '$in':
            return Array.isArray(operand) && operand.includes(logValue);
          case '$nin':
            return Array.isArray(operand) && !operand.includes(logValue);
          case '$regex':
            return new RegExp(operand, 'i').test(String(logValue));
          case '$contains':
            return String(logValue).includes(operand);
          case '$startsWith':
            return String(logValue).startsWith(operand);
          case '$endsWith':
            return String(logValue).endsWith(operand);
          default:
            return false;
        }
      }
    }

    // Simple equality
    return logValue === value;
  },

  /**
   * Get value from object by path
   */
  getValueFromPath(obj, path) {
    return path.split('.').reduce((current, key) => {
      return current && current[key] !== undefined ? current[key] : undefined;
    }, obj);
  },

  /**
   * Record rule trigger
   */
  async recordTrigger(log) {
    this.triggerCount += 1;
    this.lastTriggered = new Date();
    
    // Check if should suppress
    if (this.suppression.enabled && this.triggerCount >= this.suppression.threshold) {
      const suppressUntil = new Date();
      suppressUntil.setSeconds(suppressUntil.getSeconds() + this.suppression.duration);
      this.suppression.suppressUntil = suppressUntil;
    }
    
    await this.save();
    return this;
  },

  /**
   * Get rule effectiveness score
   */
  getEffectivenessScore() {
    const total = this.truePositives + this.falsePositives;
    if (total === 0) return 0;
    return Math.round((this.truePositives / total) * 100);
  },

  /**
   * Calculate risk score
   */
  getRiskScore() {
    let score = 0;
    
    // Severity
    const severityMap = {
      critical: 10,
      high: 7,
      medium: 5,
      low: 3,
      info: 1
    };
    score += severityMap[this.severity] || 0;
    
    // Priority
    score += this.priority;
    
    // Effectiveness
    const effectiveness = this.getEffectivenessScore();
    if (effectiveness > 80) score += 2;
    else if (effectiveness > 60) score += 1;
    
    return Math.min(Math.round(score * 10) / 10, 10);
  },

  /**
   * Clone rule
   */
  async clone(newName, createdBy) {
    const ruleData = this.toObject();
    delete ruleData._id;
    delete ruleData.createdAt;
    delete ruleData.updatedAt;
    delete ruleData.triggerCount;
    delete ruleData.lastTriggered;
    delete ruleData.falsePositives;
    delete ruleData.truePositives;
    
    ruleData.name = newName || `${this.name} (Clone)`;
    ruleData.createdBy = createdBy;
    ruleData.version = 1;
    
    const Rule = mongoose.model('ThreatRule');
    const newRule = new Rule(ruleData);
    await newRule.save();
    return newRule;
  }
};

// Static methods
threatRuleSchema.statics = {
  /**
   * Get rules with pagination and filtering
   */
  async getRules(filters = {}) {
    const {
      organization,
      type,
      severity,
      category,
      threatType,
      enabled,
      search,
      tags,
      page = 1,
      limit = 20,
      sort = '-priority'
    } = filters;

    const query = {};

    if (organization) query.organization = organization;
    if (type && type !== 'all') query.type = type;
    if (severity && severity !== 'all') query.severity = severity;
    if (category && category !== 'all') query.category = category;
    if (threatType && threatType !== 'all') query.threatType = threatType;
    if (enabled !== undefined && enabled !== '') query.enabled = enabled === 'true';
    if (tags && tags.length > 0) query.tags = { $in: tags };

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } },
        { threatType: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (page - 1) * limit;

    const [rules, total] = await Promise.all([
      this.find(query)
        .populate('organization', 'name code')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      this.countDocuments(query)
    ]);

    return {
      rules,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get enabled rules
   */
  async getEnabledRules(organizationId = null) {
    const query = { enabled: true };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .sort({ priority: -1, severity: -1 });
  },

  /**
   * Get rules by threat type
   */
  async findByThreatType(threatType, organizationId = null) {
    const query = { threatType, enabled: true };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .sort({ priority: -1 });
  },

  /**
   * Get rules by category
   */
  async findByCategory(category, organizationId = null) {
    const query = { category, enabled: true };
    if (organizationId) query.organization = organizationId;
    
    return await this.find(query)
      .sort({ priority: -1 });
  },

  /**
   * Get rule with populated references
   */
  async getRuleWithPopulated(id) {
    return await this.findById(id)
      .populate('organization', 'name code')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName');
  },

  /**
   * Get rule statistics
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
          enabled: {
            $sum: { $cond: [{ $eq: ['$enabled', true] }, 1, 0] }
          },
          disabled: {
            $sum: { $cond: [{ $eq: ['$enabled', false] }, 1, 0] }
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
          avgPriority: { $avg: '$priority' },
          totalTriggers: { $sum: '$triggerCount' },
          avgEffectiveness: { $avg: { $multiply: [{ $divide: ['$truePositives', { $add: ['$truePositives', '$falsePositives'] }] }, 100] } }
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

    return {
      summary: stats[0] || {
        total: 0,
        enabled: 0,
        disabled: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        avgPriority: 0,
        totalTriggers: 0,
        avgEffectiveness: 0
      },
      typeBreakdown: typeStats,
      categoryBreakdown: categoryStats
    };
  },

  /**
   * Search rules
   */
  async searchRules(query, organizationId = null, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-priority' } = options;
    
    const filter = {
      $or: [
        { name: searchRegex },
        { description: searchRegex },
        { tags: { $in: [searchRegex] } },
        { threatType: searchRegex },
        { 'mitreAttack.technique': searchRegex }
      ]
    };
    
    if (organizationId) filter.organization = organizationId;
    
    const skip = (page - 1) * limit;
    
    const [rules, total] = await Promise.all([
      this.find(filter)
        .populate('organization', 'name code')
        .populate('createdBy', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);
    
    return {
      rules,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  },

  /**
   * Get rule types for dropdown
   */
  getRuleTypes() {
    return Object.values(RULE_TYPES).map(type => ({
      value: type,
      label: type.charAt(0).toUpperCase() + type.slice(1)
    }));
  },

  /**
   * Get categories for dropdown
   */
  getCategories() {
    return ['authentication', 'network', 'system', 'application', 'database', 'web', 'malware', 'policy', 'access', 'error', 'ids', 'firewall'].map(category => ({
      value: category,
      label: category.charAt(0).toUpperCase() + category.slice(1)
    }));
  },

  /**
   * Get threat types for dropdown
   */
  getThreatTypes() {
    return [
      'brute_force', 'sql_injection', 'xss', 'command_injection', 'rce',
      'reverse_shell', 'port_scan', 'malware_communication', 'dns_tunneling',
      'data_exfiltration', 'dos_attack', 'privilege_escalation',
      'suspicious_powershell', 'unauthorized_access', 'beaconing',
      'ddos', 'malware', 'phishing', 'ransomware'
    ].map(type => ({
      value: type,
      label: type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  },

  /**
   * Get action types for dropdown
   */
  getActionTypes() {
    return ['alert', 'block', 'notify', 'log', 'quarantine', 'isolate'].map(action => ({
      value: action,
      label: action.charAt(0).toUpperCase() + action.slice(1)
    }));
  },

  /**
   * Get MITRE ATT&CK tactics
   */
  getMitreTactics() {
    return [
      'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
      'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
      'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
      'Exfiltration', 'Impact'
    ].map(tactic => ({
      value: tactic,
      label: tactic
    }));
  }
};

const ThreatRule = mongoose.model('ThreatRule', threatRuleSchema);

module.exports = ThreatRule;