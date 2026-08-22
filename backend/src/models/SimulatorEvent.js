// models/SimulatorEvent.js

const mongoose = require('mongoose');

const simulatorEventSchema = new mongoose.Schema({
  simulator: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SimulatorConfig',
    required: true,
    index: true
  },
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
  },
  eventType: {
    type: String,
    required: true
  },
  severity: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low', 'info'],
    default: 'info'
  },
  payload: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'sent', 'failed'],
    default: 'pending'
  },
  response: {
    statusCode: Number,
    message: String,
    timestamp: Date
  },
  sentAt: {
    type: Date
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// Indexes for performance
simulatorEventSchema.index({ simulator: 1, createdAt: -1 });
simulatorEventSchema.index({ organization: 1, createdAt: -1 });
simulatorEventSchema.index({ status: 1 });

const SimulatorEvent = mongoose.model('SimulatorEvent', simulatorEventSchema);

module.exports = SimulatorEvent;