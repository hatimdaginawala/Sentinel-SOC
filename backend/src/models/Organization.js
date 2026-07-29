const mongoose = require('mongoose');

const organizationSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    index: true
  },
  code: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    uppercase: true,
    index: true
  },
  description: {
    type: String,
    trim: true
  },
  industry: {
    type: String,
    enum: ['technology', 'finance', 'healthcare', 'government', 'education', 'retail', 'manufacturing', 'energy', 'telecommunications', 'other'],
    default: 'other'
  },
  size: {
    type: String,
    enum: ['small', 'medium', 'large', 'enterprise'],
    default: 'medium'
  },
  website: {
    type: String,
    trim: true
  },
  address: {
    street: {
      type: String,
      trim: true
    },
    city: {
      type: String,
      trim: true
    },
    state: {
      type: String,
      trim: true
    },
    country: {
      type: String,
      trim: true
    },
    postalCode: {
      type: String,
      trim: true
    }
  },
  contactInfo: {
    email: {
      type: String,
      trim: true,
      lowercase: true
    },
    phone: {
      type: String,
      trim: true
    }
  },
  settings: {
    maxUsers: {
      type: Number,
      default: 100
    },
    maxAssets: {
      type: Number,
      default: 1000
    },
    maxLogsPerDay: {
      type: Number,
      default: 100000
    },
    retentionPeriod: {
      type: Number,
      default: 90 // days
    },
    timezone: {
      type: String,
      default: 'UTC'
    },
    features: {
      threatIntelligence: {
        type: Boolean,
        default: true
      },
      incidentResponse: {
        type: Boolean,
        default: true
      },
      complianceReporting: {
        type: Boolean,
        default: false
      },
      aiDetection: {
        type: Boolean,
        default: false
      },
      customRules: {
        type: Boolean,
        default: true
      }
    },
    notificationPreferences: {
      email: {
        type: Boolean,
        default: true
      },
      slack: {
        type: Boolean,
        default: false
      },
      teams: {
        type: Boolean,
        default: false
      },
      sms: {
        type: Boolean,
        default: false
      }
    }
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'suspended', 'pending'],
    default: 'active'
  },
  subscription: {
    plan: {
      type: String,
      enum: ['free', 'basic', 'professional', 'enterprise'],
      default: 'free'
    },
    startDate: {
      type: Date,
      default: Date.now
    },
    endDate: {
      type: Date
    },
    trialEndDate: {
      type: Date
    },
    isActive: {
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
      delete ret.__v;
      return ret;
    }
  }
});

// Indexes for performance
// organizationSchema.index({ name: 1, code: 1 });
// organizationSchema.index({ status: 1, 'subscription.isActive': 1 });
// organizationSchema.index({ 'settings.maxUsers': 1 });

// Pre-save middleware
organizationSchema.pre('save', function(next) {
  if (this.isNew) {
    this.createdAt = new Date();
    this.updatedAt = new Date();
  } else {
    this.updatedAt = new Date();
  }
  
  // Generate code if not provided
  if (!this.code && this.name) {
    this.code = this.name.substring(0, 3).toUpperCase() + 
                Math.random().toString(36).substring(2, 5).toUpperCase();
  }
  
  next();
});

// Instance methods
organizationSchema.methods = {
  // Check if organization is active
  isActive() {
    return this.status === 'active' && 
           this.subscription.isActive &&
           (!this.subscription.endDate || this.subscription.endDate > new Date());
  },

  // Check if organization has reached user limit
  async hasReachedUserLimit(userCount) {
    return userCount >= this.settings.maxUsers;
  },

  // Check if organization has reached asset limit
  async hasReachedAssetLimit(assetCount) {
    return assetCount >= this.settings.maxAssets;
  },

  // Check if subscription is expiring soon (within 30 days)
  isSubscriptionExpiringSoon() {
    if (!this.subscription.endDate) return false;
    const daysUntilExpiry = Math.ceil(
      (this.subscription.endDate - new Date()) / (1000 * 60 * 60 * 24)
    );
    return daysUntilExpiry <= 30 && daysUntilExpiry > 0;
  },

  // Get subscription status
  getSubscriptionStatus() {
    if (!this.subscription.isActive) return 'inactive';
    if (this.subscription.endDate && this.subscription.endDate < new Date()) {
      return 'expired';
    }
    if (this.isSubscriptionExpiringSoon()) {
      return 'expiring_soon';
    }
    return 'active';
  },

  // Get feature availability
  getFeatureAvailability(feature) {
    return this.settings.features[feature] || false;
  }
};

// Static methods
organizationSchema.statics = {
  // Find organization by name or code
  async findByNameOrCode(identifier) {
    return await this.findOne({
      $or: [
        { name: identifier },
        { code: identifier.toUpperCase() }
      ]
    });
  },

  // Get active organizations
  async getActiveOrganizations() {
    return await this.find({ 
      status: 'active',
      'subscription.isActive': true
    });
  },

  // Get organizations with expiring subscriptions
  async getExpiringSubscriptions(daysThreshold = 30) {
    const thresholdDate = new Date();
    thresholdDate.setDate(thresholdDate.getDate() + daysThreshold);
    
    return await this.find({
      'subscription.endDate': { 
        $lte: thresholdDate,
        $gte: new Date()
      },
      'subscription.isActive': true,
      status: 'active'
    });
  },

  // Get expired subscriptions
  async getExpiredSubscriptions() {
    return await this.find({
      'subscription.endDate': { $lt: new Date() },
      'subscription.isActive': true
    });
  },

  // Search organizations
  async searchOrganizations(query, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-createdAt' } = options;
    
    const filter = {
      $or: [
        { name: searchRegex },
        { code: searchRegex },
        { description: searchRegex },
        { industry: searchRegex },
        { 'address.city': searchRegex },
        { 'address.country': searchRegex }
      ]
    };

    const skip = (page - 1) * limit;
    
    const [organizations, total] = await Promise.all([
      this.find(filter)
        .populate('createdBy', 'username email')
        .populate('updatedBy', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);

    return {
      organizations,
      total,
      page,
      limit,
      pages: Math.ceil(total / limit)
    };
  },

  // Get organization statistics
  async getOrganizationStatistics() {
    const stats = await this.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 },
          organizations: { $push: { name: '$name', code: '$code' } }
        }
      }
    ]);

    const subscriptionStats = await this.aggregate([
      {
        $group: {
          _id: '$subscription.plan',
          count: { $sum: 1 },
          organizations: { $push: { name: '$name', code: '$code' } }
        }
      }
    ]);

    const industryStats = await this.aggregate([
      {
        $group: {
          _id: '$industry',
          count: { $sum: 1 }
        }
      }
    ]);

    return {
      statusDistribution: stats,
      subscriptionDistribution: subscriptionStats,
      industryDistribution: industryStats,
      totalOrganizations: await this.countDocuments(),
      activeOrganizations: await this.countDocuments({ status: 'active' })
    };
  },

  // Get organization with populated fields
  async getOrganizationWithPopulated(id) {
    return await this.findById(id)
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName');
  },

  // Get organization usage statistics
  async getUsageStatistics(organizationId) {
    const org = await this.findById(organizationId);
    if (!org) return null;

    // These will be populated from other services
    // Placeholder for actual implementation
    return {
      organization: {
        id: org._id,
        name: org.name,
        code: org.code
      },
      userCount: 0,
      assetCount: 0,
      logCount: 0,
      alertCount: 0,
      incidentCount: 0,
      storageUsed: '0 MB',
      limits: {
        maxUsers: org.settings.maxUsers,
        maxAssets: org.settings.maxAssets,
        maxLogsPerDay: org.settings.maxLogsPerDay
      }
    };
  }
};

const Organization = mongoose.model('Organization', organizationSchema);

module.exports = Organization;