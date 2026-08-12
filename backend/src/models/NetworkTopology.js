const mongoose = require('mongoose');

const nodeSchema = new mongoose.Schema({
  id: {
    type: String,
    required: true,
    trim: true
  },
  label: {
    type: String,
    required: true,
    trim: true
  },
  group: {
    type: String,
    enum: ['internet', 'firewall', 'router', 'dmz', 'server', 'workstation', 'sensor', 'switch', 'other'],
    default: 'other'
  },
  zone: {
    type: String,
    trim: true,
    default: 'Unassigned'
  },
  ipAddress: {
    type: String,
    trim: true
  },
  asset: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Asset'
  },
  securitySensor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SecuritySensor'
  },
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed,
    default: new Map()
  }
}, {
  _id: false
});

const edgeSchema = new mongoose.Schema({
  from: {
    type: String,
    required: true,
    trim: true
  },
  to: {
    type: String,
    required: true,
    trim: true
  },
  label: {
    type: String,
    trim: true,
    default: ''
  },
  dashes: {
    type: Boolean,
    default: false
  },
  directional: {
    type: Boolean,
    default: false
  },
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed,
    default: new Map()
  }
}, {
  _id: false
});

const networkTopologySchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    unique: true,
    index: true
  },
  name: {
    type: String,
    default: 'Default Network Topology',
    trim: true
  },
  description: {
    type: String,
    default: '',
    trim: true
  },
  nodes: {
    type: [nodeSchema],
    default: []
  },
  edges: {
    type: [edgeSchema],
    default: []
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
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

// Compound index for common queries
networkTopologySchema.index({ organization: 1, createdAt: -1 });

// Pre-save middleware to clean up duplicates
networkTopologySchema.pre('save', function(next) {
  // Remove duplicate nodes based on id
  if (this.nodes && this.nodes.length > 0) {
    const seen = new Set();
    this.nodes = this.nodes.filter(node => {
      if (seen.has(node.id)) return false;
      seen.add(node.id);
      return true;
    });
  }

  // Remove duplicate edges based on from/to
  if (this.edges && this.edges.length > 0) {
    const seen = new Set();
    this.edges = this.edges.filter(edge => {
      const key = `${edge.from}|${edge.to}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  next();
});

// Instance methods
networkTopologySchema.methods = {
  getNode(nodeId) {
    return this.nodes.find(n => n.id === nodeId);
  },

  getNodesByGroup(group) {
    return this.nodes.filter(n => n.group === group);
  },

  getNodeEdges(nodeId) {
    return this.edges.filter(e => e.from === nodeId || e.to === nodeId);
  },

  addNode(nodeData) {
    if (!this.nodes.some(n => n.id === nodeData.id)) {
      this.nodes.push(nodeData);
      return true;
    }
    return false;
  },

  removeNode(nodeId) {
    this.nodes = this.nodes.filter(n => n.id !== nodeId);
    this.edges = this.edges.filter(e => e.from !== nodeId && e.to !== nodeId);
  }
};

// Static methods
networkTopologySchema.statics = {
  async findByOrganization(orgId) {
    return await this.findOne({ organization: orgId })
      .populate('nodes.asset')
      .populate('nodes.securitySensor')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName');
  },

  async findOrCreate(orgId, userId) {
    let topology = await this.findOne({ organization: orgId });
    
    if (!topology) {
      topology = new this({
        organization: orgId,
        nodes: [],
        edges: [],
        createdBy: userId,
        updatedBy: userId
      });
      await topology.save();
    }
    
    return topology;
  }
};

const NetworkTopology = mongoose.model('NetworkTopology', networkTopologySchema);

module.exports = NetworkTopology;