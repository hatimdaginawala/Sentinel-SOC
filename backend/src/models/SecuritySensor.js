const mongoose = require('mongoose');

const securitySensorSchema = new mongoose.Schema({
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
    enum: ['Suricata', 'Zeek', 'Firewall', 'Host Collector', 'Other'],
    required: true
  },
  networkZone: {
    type: String,
    trim: true
  },
  asset: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Asset'
  },
  status: {
    type: String,
    enum: ['Active', 'Inactive', 'Error', 'Pending'],
    default: 'Pending'
  },
  configuration: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
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

const SecuritySensor = mongoose.model('SecuritySensor', securitySensorSchema);

module.exports = SecuritySensor;
