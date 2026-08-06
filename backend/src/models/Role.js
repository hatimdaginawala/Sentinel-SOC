const mongoose = require('mongoose');
const { PERMISSIONS, ROLES } = require('../config/constants');

const roleSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    enum: Object.values(ROLES)
  },
  displayName: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  permissions: [{
    type: String,
    enum: Object.values(PERMISSIONS)
  }],
  isSystem: {
    type: Boolean,
    default: false
  },
  priority: {
    type: Number,
    default: 0
  },
  status: {
    type: String,
    enum: ['active', 'inactive'],
    default: 'active'
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
// roleSchema.index({ name: 1 });
// roleSchema.index({ status: 1 });
// roleSchema.index({ priority: 1 });

// Pre-save middleware
roleSchema.pre('save', function(next) {
  if (this.isNew) {
    this.createdAt = new Date();
    this.updatedAt = new Date();
  } else {
    this.updatedAt = new Date();
  }
  next();
});

// Instance methods
roleSchema.methods = {
  // Check if role has specific permission
  hasPermission(permission) {
    return this.permissions.includes(permission);
  },

  // Check if role has all permissions
  hasAllPermissions(permissions) {
    return permissions.every(permission => this.permissions.includes(permission));
  },

  // Check if role has any of the permissions
  hasAnyPermission(permissions) {
    return permissions.some(permission => this.permissions.includes(permission));
  },

  // Get permission count
  getPermissionCount() {
    return this.permissions.length;
  },

  // Check if role can be deleted (system roles cannot be deleted)
  isDeletable() {
    return !this.isSystem;
  },

  // Check if role can be modified
  isModifiable() {
    return !this.isSystem;
  }
};

// Static methods
roleSchema.statics = {
  // Get default system roles
  async getSystemRoles() {
    return await this.find({ isSystem: true, status: 'active' });
  },

  // Get roles by permission
  async findByPermission(permission) {
    return await this.find({ 
      permissions: permission, 
      status: 'active' 
    });
  },

  // Get active roles
  async getActiveRoles() {
    return await this.find({ status: 'active' });
  },

  // Get roles with populated fields
  async getRoleWithPopulated(id) {
    return await this.findById(id)
      .populate('createdBy', 'username email')
      .populate('updatedBy', 'username email');
  },

  // Get all roles with populated fields
  async getAllRolesWithPopulated() {
    return await this.find({})
      .populate('createdBy', 'username email')
      .populate('updatedBy', 'username email')
      .sort({ priority: -1, name: 1 });
  },

  // Search roles
  async searchRoles(query, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-priority' } = options;
    
    const filter = {
      $or: [
        { name: searchRegex },
        { displayName: searchRegex },
        { description: searchRegex }
      ]
    };

    const skip = (page - 1) * limit;
    
    const [roles, total] = await Promise.all([
      this.find(filter)
        .populate('createdBy', 'username email')
        .populate('updatedBy', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);

    return {
      roles,
      total,
      page,
      limit,
      pages: Math.ceil(total / limit)
    };
  },

  // Get role statistics
  async getRoleStatistics() {
    const stats = await this.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 },
          roles: { $push: { name: '$name', displayName: '$displayName' } }
        }
      }
    ]);

    const totalPermissions = await this.aggregate([
      {
        $group: {
          _id: null,
          totalPermissions: { $sum: { $size: '$permissions' } },
          avgPermissions: { $avg: { $size: '$permissions' } }
        }
      }
    ]);

    return {
      statusDistribution: stats,
      totalPermissions: totalPermissions[0]?.totalPermissions || 0,
      averagePermissions: Math.round(totalPermissions[0]?.avgPermissions || 0),
      totalRoles: await this.countDocuments()
    };
  },

  // Get system role definitions
  getSystemRoleDefinitions() {
    return {
      [ROLES.SUPER_ADMIN]: {
        displayName: 'Super Administrator',
        description: 'Complete system access with all permissions',
        permissions: Object.values(PERMISSIONS),
        priority: 100
      },
      [ROLES.SECURITY_ADMIN]: {
        displayName: 'Security Administrator',
        description: 'Manage security infrastructure, assets, and rules',
        permissions: [
          PERMISSIONS.MANAGE_ASSETS,
          PERMISSIONS.VIEW_ASSETS,
          PERMISSIONS.MANAGE_LOGS,
          PERMISSIONS.VIEW_LOGS,
          PERMISSIONS.MANAGE_THREAT_RULES,
          PERMISSIONS.VIEW_THREAT_RULES,
          PERMISSIONS.VIEW_USERS,
          PERMISSIONS.VIEW_ALERTS,
          PERMISSIONS.VIEW_INCIDENTS,
          PERMISSIONS.MANAGE_REPORTS,
          PERMISSIONS.VIEW_REPORTS,
          PERMISSIONS.GENERATE_REPORTS,
          PERMISSIONS.VIEW_SETTINGS
        ],
        priority: 80
      },
      [ROLES.SOC_ANALYST]: {
        displayName: 'SOC Analyst',
        description: 'Monitor and investigate security events',
        permissions: [
          PERMISSIONS.VIEW_ASSETS,
          PERMISSIONS.VIEW_LOGS,
          PERMISSIONS.VIEW_ALERTS,
          PERMISSIONS.MANAGE_ALERTS,
          PERMISSIONS.VIEW_INCIDENTS,
          PERMISSIONS.MANAGE_INCIDENTS,
          PERMISSIONS.VIEW_THREAT_RULES,
          PERMISSIONS.VIEW_REPORTS,
          PERMISSIONS.GENERATE_REPORTS
        ],
        priority: 60
      },
      [ROLES.INCIDENT_RESPONDER]: {
        displayName: 'Incident Responder',
        description: 'Handle and resolve security incidents',
        permissions: [
          PERMISSIONS.VIEW_ASSETS,
          PERMISSIONS.VIEW_LOGS,
          PERMISSIONS.VIEW_ALERTS,
          PERMISSIONS.MANAGE_ALERTS,
          PERMISSIONS.VIEW_INCIDENTS,
          PERMISSIONS.MANAGE_INCIDENTS,
          PERMISSIONS.RESPOND_INCIDENTS,
          PERMISSIONS.VIEW_THREAT_RULES,
          PERMISSIONS.VIEW_REPORTS,
          PERMISSIONS.GENERATE_REPORTS
        ],
        priority: 70
      },
      [ROLES.AUDITOR]: {
        displayName: 'Auditor',
        description: 'Read-only access for compliance and auditing',
        permissions: [
          PERMISSIONS.VIEW_ASSETS,
          PERMISSIONS.VIEW_LOGS,
          PERMISSIONS.VIEW_ALERTS,
          PERMISSIONS.VIEW_INCIDENTS,
          PERMISSIONS.VIEW_THREAT_RULES,
          PERMISSIONS.VIEW_REPORTS,
          PERMISSIONS.VIEW_AUDIT_LOGS,
          PERMISSIONS.VIEW_SETTINGS
        ],
        priority: 40
      }
    };
  },

  // Initialize system roles
  async initializeSystemRoles() {
    const systemRoles = this.getSystemRoleDefinitions();
    const createdRoles = [];

    for (const [name, definition] of Object.entries(systemRoles)) {
      try {
        const existingRole = await this.findOne({ name });
        
        if (!existingRole) {
          const role = new this({
            name,
            displayName: definition.displayName,
            description: definition.description,
            permissions: definition.permissions,
            isSystem: true,
            priority: definition.priority,
            status: 'active'
          });
          
          await role.save();
          createdRoles.push(role);
          console.log(` System role created: ${name}`);
        } else {
          // Update existing system role if needed
          if (existingRole.isSystem) {
            existingRole.displayName = definition.displayName;
            existingRole.description = definition.description;
            existingRole.permissions = definition.permissions;
            existingRole.priority = definition.priority;
            await existingRole.save();
            console.log(` System role updated: ${name}`);
          }
          createdRoles.push(existingRole);
        }
      } catch (error) {
        console.error(` Error creating system role ${name}:`, error);
      }
    }

    return createdRoles;
  }
};

const Role = mongoose.model('Role', roleSchema);

module.exports = Role;