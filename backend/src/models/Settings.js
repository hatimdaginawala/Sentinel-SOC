const mongoose = require('mongoose');

const settingsSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    unique: true,
    index: true
  },
  general: {
    type: mongoose.Schema.Types.Mixed,
    default: {
      timezone: 'UTC',
      dateFormat: 'YYYY-MM-DD',
      timeFormat: 'HH:mm:ss',
      language: 'en'
    }
  },
  security: {
    type: mongoose.Schema.Types.Mixed,
    default: {
      passwordPolicy: {
        minLength: 8,
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSpecialChars: true,
        expiryDays: 90,
        preventReuse: 5,
        maxLoginAttempts: 5,
        lockoutDuration: 30
      },
      session: {
        timeout: 60,
        maxConcurrentSessions: 5,
        requireMFA: false,
        mfaMethods: ['totp']
      },
      api: {
        rateLimit: {
          enabled: true,
          windowMs: 15 * 60 * 1000,
          maxRequests: 100
        },
        tokenExpiry: 7,
        refreshTokenExpiry: 30
      },
      ipWhitelist: [],
      ipBlacklist: []
    }
  },
  notifications: {
    type: mongoose.Schema.Types.Mixed,
    default: {
      email: { enabled: false },
      slack: { enabled: false },
      teams: { enabled: false },
      webhooks: []
    }
  },
  retention: {
    type: mongoose.Schema.Types.Mixed,
    default: {
      logs: { enabled: true, days: 90 },
      alerts: { enabled: true, days: 365 },
      incidents: { enabled: true, days: 365 },
      auditLogs: { enabled: true, days: 90 },
      reports: { enabled: true, days: 30 }
    }
  },
  detection: {
    type: mongoose.Schema.Types.Mixed,
    default: {
      rules: {
        autoUpdate: false,
        updateInterval: 24
      },
      alerts: {
        deduplication: {
          enabled: true,
          windowMs: 5 * 60 * 1000,
          threshold: 3
        },
        autoResolution: {
          enabled: false,
          timeout: 24
        },
        escalation: {
          enabled: true,
          levels: []
        }
      }
    }
  },
  dashboard: {
    type: mongoose.Schema.Types.Mixed,
    default: {
      refreshInterval: 30,
      defaultView: 'overview',
      widgets: [
        { type: 'alert_count', size: 'medium', position: { x: 0, y: 0 } },
        { type: 'incident_count', size: 'medium', position: { x: 1, y: 0 } },
        { type: 'severity_chart', size: 'large', position: { x: 0, y: 1 } }
      ]
    }
  },
  logging: {
    type: mongoose.Schema.Types.Mixed,
    default: {
      level: 'info',
      includeSensitiveData: false,
      retention: 30
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
  timestamps: true
});

// Indexes
settingsSchema.index({ organization: 1 }, { unique: true });

// Pre-save middleware
settingsSchema.pre('save', function(next) {
  if (this.isNew) {
    this.createdAt = new Date();
    this.updatedAt = new Date();
  } else {
    this.updatedAt = new Date();
  }
  next();
});

// Instance methods
settingsSchema.methods = {
  getSetting(path) {
    return path.split('.').reduce((obj, key) => {
      return obj && obj[key] !== undefined ? obj[key] : undefined;
    }, this.toObject());
  },

  async updateSetting(path, value, updatedBy) {
    const parts = path.split('.');
    let current = this;
    
    for (let i = 0; i < parts.length - 1; i++) {
      if (!current[parts[i]]) {
        current[parts[i]] = {};
      }
      current = current[parts[i]];
    }
    
    current[parts[parts.length - 1]] = value;
    this.updatedBy = updatedBy;
    await this.save();
    return this;
  },

  isFeatureEnabled(featurePath) {
    const value = this.getSetting(featurePath);
    return value === true || (typeof value === 'object' && value.enabled === true);
  }
};

// Static methods
settingsSchema.statics = {
  async getOrCreate(organizationId) {
    let settings = await this.findOne({ organization: organizationId });
    
    if (!settings) {
      settings = new this({
        organization: organizationId
      });
      await settings.save();
    }
    
    return settings;
  },

  async getSettingValue(organizationId, path) {
    const settings = await this.findOne({ organization: organizationId });
    if (!settings) return undefined;
    return settings.getSetting(path);
  },

  getDefaultSettings() {
    return {
      general: {
        timezone: 'UTC',
        dateFormat: 'YYYY-MM-DD',
        timeFormat: 'HH:mm:ss',
        language: 'en'
      },
      security: {
        passwordPolicy: {
          minLength: 8,
          requireUppercase: true,
          requireLowercase: true,
          requireNumbers: true,
          requireSpecialChars: true,
          expiryDays: 90,
          preventReuse: 5,
          maxLoginAttempts: 5,
          lockoutDuration: 30
        },
        session: {
          timeout: 60,
          maxConcurrentSessions: 5,
          requireMFA: false,
          mfaMethods: ['totp']
        },
        api: {
          rateLimit: {
            enabled: true,
            windowMs: 15 * 60 * 1000,
            maxRequests: 100
          },
          tokenExpiry: 7,
          refreshTokenExpiry: 30
        },
        ipWhitelist: [],
        ipBlacklist: []
      },
      notifications: {
        email: { enabled: false },
        slack: { enabled: false },
        teams: { enabled: false },
        webhooks: []
      },
      retention: {
        logs: { enabled: true, days: 90 },
        alerts: { enabled: true, days: 365 },
        incidents: { enabled: true, days: 365 },
        auditLogs: { enabled: true, days: 90 },
        reports: { enabled: true, days: 30 }
      },
      detection: {
        rules: {
          autoUpdate: false,
          updateInterval: 24
        },
        alerts: {
          deduplication: {
            enabled: true,
            windowMs: 5 * 60 * 1000,
            threshold: 3
          },
          autoResolution: {
            enabled: false,
            timeout: 24
          },
          escalation: {
            enabled: true,
            levels: []
          }
        }
      },
      dashboard: {
        refreshInterval: 30,
        defaultView: 'overview',
        widgets: [
          { type: 'alert_count', size: 'medium', position: { x: 0, y: 0 } },
          { type: 'incident_count', size: 'medium', position: { x: 1, y: 0 } },
          { type: 'severity_chart', size: 'large', position: { x: 0, y: 1 } }
        ]
      },
      logging: {
        level: 'info',
        includeSensitiveData: false,
        retention: 30
      }
    };
  }
};

const Settings = mongoose.model('Settings', settingsSchema);

module.exports = Settings;