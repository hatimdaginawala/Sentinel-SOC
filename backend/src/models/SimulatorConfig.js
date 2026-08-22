// models/SimulatorConfig.js

const mongoose = require('mongoose');

const simulatorConfigSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  type: {
    type: String,
    enum: ['windows', 'linux', 'apache', 'nginx', 'suricata', 'snort', 'firewall', 'all'],
    required: true
  },
  status: {
    type: String,
    enum: ['running', 'stopped', 'error', 'pending'],
    default: 'stopped'
  },
  sourceId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'LogSource',
    required: true
  },
  authToken: {
    type: String,
    required: true
  },
  configuration: {
    interval: {
      type: Number,
      default: 2000 // milliseconds
    },
    batchSize: {
      type: Number,
      default: 1
    },
    enabled: {
      type: Boolean,
      default: true
    }
  },
  stats: {
    eventsGenerated: {
      type: Number,
      default: 0
    },
    eventsSent: {
      type: Number,
      default: 0
    },
    eventsFailed: {
      type: Number,
      default: 0
    },
    lastEventTime: {
      type: Date
    },
    startTime: {
      type: Date
    },
    stopTime: {
      type: Date
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
      delete ret.authToken;
      delete ret.__v;
      return ret;
    }
  }
});

// Indexes
simulatorConfigSchema.index({ organization: 1, type: 1 });
simulatorConfigSchema.index({ status: 1 });
simulatorConfigSchema.index({ organization: 1, status: 1 });

const SimulatorConfig = mongoose.model('SimulatorConfig', simulatorConfigSchema);

module.exports = SimulatorConfig;