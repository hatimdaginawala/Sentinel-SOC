const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { ROLES } = require('../config/constants');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    index: true
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    index: true
  },
  password: {
    type: String,
    required: true,
    select: false
  },
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  role: {
    type: String,
    enum: Object.values(ROLES),
    default: ROLES.SOC_ANALYST,
    required: true
  },
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'locked', 'pending'],
    default: 'active'
  },
  lastLogin: {
    type: Date
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date
  },
  refreshToken: {
    type: String,
    select: false
  },
  passwordResetToken: {
    type: String,
    select: false
  },
  passwordResetExpires: {
    type: Date,
    select: false
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
      delete ret.password;
      delete ret.refreshToken;
      delete ret.passwordResetToken;
      delete ret.passwordResetExpires;
      delete ret.__v;
      return ret;
    }
  }
});

// Index for performance
// userSchema.index({ email: 1, username: 1 });
// userSchema.index({ organization: 1, status: 1 });
// userSchema.index({ role: 1 });

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_ROUNDS) || 12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Pre-save middleware to set createdBy and updatedBy
userSchema.pre('save', function(next) {
  if (this.isNew) {
    this.createdAt = new Date();
    this.updatedAt = new Date();
  } else {
    this.updatedAt = new Date();
  }
  next();
});

// Instance methods
userSchema.methods = {
  // Compare password
 async comparePassword(candidatePassword) {
    try {
      console.log(`🔐 Comparing password for: ${this.email}`);
      console.log(`📝 Candidate password provided: ${!!candidatePassword}`);
      console.log(`🔑 Stored password hash: ${this.password ? this.password.substring(0, 20) + '...' : 'MISSING'}`);
      
      if (!this.password) {
        console.error('❌ Password field is missing for user:', this.email);
        return false;
      }
      if (!candidatePassword) {
        console.error('❌ Candidate password is empty');
        return false;
      }
      
      const result = await bcrypt.compare(candidatePassword, this.password);
      console.log(`✅ bcrypt.compare result: ${result}`);
      return result;
    } catch (error) {
      console.error('❌ Error comparing password:', error.message);
      console.error(error.stack);
      return false;
    }
  },

  // Increment login attempts
  async incrementLoginAttempts() {
    this.loginAttempts += 1;
    
    if (this.loginAttempts >= 5) {
      this.status = 'locked';
      this.lockUntil = new Date(Date.now() + 30 * 60 * 1000); // Lock for 30 minutes
    }
    
    await this.save();
    return this;
  },

  // Reset login attempts
  async resetLoginAttempts() {
    this.loginAttempts = 0;
    this.lockUntil = null;
    await this.save();
    return this;
  },

  // Check if account is locked
  isLocked() {
    if (this.status === 'locked') {
      if (this.lockUntil && this.lockUntil < new Date()) {
        // Lock expired, auto-unlock
        this.status = 'active';
        this.loginAttempts = 0;
        this.lockUntil = null;
        this.save();
        return false;
      }
      return true;
    }
    return false;
  },

  // Update last login
  async updateLastLogin() {
    this.lastLogin = new Date();
    await this.save();
    return this;
  },

  // Generate full name
  getFullName() {
    return `${this.firstName} ${this.lastName}`;
  },

  // Check if user has permission
  hasPermission(permission) {
    // Super admin has all permissions
    if (this.role === ROLES.SUPER_ADMIN) return true;
    
    // Implementation will depend on role-permission mapping
    // This is a placeholder - actual implementation will be in service
    return false;
  }
};

// Static methods
userSchema.statics = {
  // Find by email or username
  async findByEmailOrUsername(identifier) {
    return await this.findOne({
      $or: [
        { email: identifier.toLowerCase() },
        { username: identifier.toLowerCase() }
      ]
    });
  },

  // Find active users
  async findActiveUsers() {
    return await this.find({ status: 'active' });
  },

  // Find users by role
  async findByRole(role) {
    return await this.find({ role, status: 'active' });
  },

  // Find users by organization
  async findByOrganization(organizationId) {
    return await this.find({ organization: organizationId, status: 'active' });
  },

  // Get user count by role
  async getCountByRole() {
    return await this.aggregate([
      { $group: { _id: '$role', count: { $sum: 1 } } }
    ]);
  },

  // Get active user count
  async getActiveCount() {
    return await this.countDocuments({ status: 'active' });
  },

  // Search users
  async searchUsers(query, options = {}) {
    const searchRegex = new RegExp(query, 'i');
    const { limit = 20, page = 1, sort = '-createdAt' } = options;
    
    const filter = {
      $or: [
        { email: searchRegex },
        { username: searchRegex },
        { firstName: searchRegex },
        { lastName: searchRegex }
      ]
    };

    const skip = (page - 1) * limit;
    
    const [users, total] = await Promise.all([
      this.find(filter)
        .populate('organization', 'name')
        .populate('createdBy', 'username email')
        .populate('updatedBy', 'username email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      this.countDocuments(filter)
    ]);

    return {
      users,
      total,
      page,
      limit,
      pages: Math.ceil(total / limit)
    };
  },

  // Get user with populated references
  async getUserWithPopulated(id) {
    return await this.findById(id)
      .populate('organization', 'name code')
      .populate('createdBy', 'username email')
      .populate('updatedBy', 'username email');
  }
};

const User = mongoose.model('User', userSchema);

module.exports = User;