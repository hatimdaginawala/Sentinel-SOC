const mongoose = require('mongoose');

const securityControlItemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  priority: { type: String, enum: ['High', 'Medium', 'Low'], default: 'Medium' }
}, { _id: false });

const securityControlSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
  },
  threatRule: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ThreatRule',
    required: true
  },
  threatName: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String
  },
  securityImpact: {
    type: String
  },
  recommendedControls: [securityControlItemSchema],
  mitigations: [securityControlItemSchema],
  analystActions: [securityControlItemSchema],
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

const SecurityControl = mongoose.model('SecurityControl', securityControlSchema);

module.exports = SecurityControl;
