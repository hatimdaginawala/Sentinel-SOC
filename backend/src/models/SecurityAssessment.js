const mongoose = require('mongoose');

const securityAssessmentSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
  },
  title: {
    type: String,
    required: true
  },
  date: {
    type: Date,
    default: Date.now
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
    default: 'Medium'
  },
  securityWeaknesses: [{
    type: String
  }],
  recommendedControls: [{
    name: String,
    description: String,
    priority: String
  }],
  mitigations: [{
    name: String,
    description: String,
    priority: String
  }],
  status: {
    type: String,
    enum: ['Draft', 'Final'],
    default: 'Draft'
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

const SecurityAssessment = mongoose.model('SecurityAssessment', securityAssessmentSchema);

module.exports = SecurityAssessment;
