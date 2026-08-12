const mongoose = require('mongoose');

const securityTestSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  testType: {
    type: String,
    required: true,
    enum: ['port_scan', 'brute_force', 'suspicious_traffic', 'unauthorized_connection', 'other']
  },
  expectedDetection: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ThreatRule'
  },
  status: {
    type: String,
    enum: ['PENDING', 'RUNNING', 'PASS', 'FAIL'],
    default: 'PENDING'
  },
  actualResult: {
    type: String
  },
  relatedAlert: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Alert'
  },
  relatedIncident: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Incident'
  },
  payload: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

const SecurityTest = mongoose.model('SecurityTest', securityTestSchema);

module.exports = SecurityTest;
