const User = require('../models/User');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS, ROLES } = require('../config/constants');
const logger = require('../config/logger');
const PasswordUtils = require('../utils/passwordUtils');
const TokenUtils = require('../utils/tokenUtils');
const Role = require('../models/Role');

class UserService {
  /**
   * Create a new user
   */
  async createUser(userData, createdBy) {
    try {
      // Validate email and username uniqueness
      const existingUser = await User.findOne({
        $or: [
          { email: userData.email.toLowerCase() },
          { username: userData.username.toLowerCase() }
        ]
      });

      if (existingUser) {
        throw new AppError(
          'User with this email or username already exists',
          HTTP_STATUS.CONFLICT,
          'USER_EXISTS'
        );
      }

      // Validate password strength
      const passwordValidation = PasswordUtils.validatePasswordStrength(userData.password);
      if (!passwordValidation.isValid) {
        throw new AppError(
          'Password does not meet strength requirements',
          HTTP_STATUS.BAD_REQUEST,
          'WEAK_PASSWORD',
          { errors: passwordValidation.errors }
        );
      }

      // Hash password
      const hashedPassword = await PasswordUtils.hash(userData.password);

      // Create user
      const user = new User({
        ...userData,
        password: hashedPassword,
        createdBy: createdBy
      });

      await user.save();

      logger.info(`User created: ${user.email} by ${createdBy}`);

      return user.toJSON();
    } catch (error) {
      logger.error('Error creating user:', error);
      throw error;
    }
  }

  /**
   * Get user by ID
   */
  async getUserById(userId) {
    try {
      const user = await User.getUserWithPopulated(userId);
      
      if (!user) {
        throw new AppError('User not found', HTTP_STATUS.NOT_FOUND, 'USER_NOT_FOUND');
      }

      return user;
    } catch (error) {
      logger.error('Error getting user:', error);
      throw error;
    }
  }

  /**
   * Get user by email
   */
  async getUserByEmail(email) {
    try {
      const user = await User.findOne({ email: email.toLowerCase() })
        .populate('organization', 'name code')
        .populate('createdBy', 'username email')
        .populate('updatedBy', 'username email');

      if (!user) {
        throw new AppError('User not found', HTTP_STATUS.NOT_FOUND, 'USER_NOT_FOUND');
      }

      return user;
    } catch (error) {
      logger.error('Error getting user by email:', error);
      throw error;
    }
  }

  /**
   * Get all users with pagination and filtering
   */
  async getUsers(filters = {}, options = {}) {
    try {
      const {
        search,
        role,
        status,
        organization,
        page = 1,
        limit = 20,
        sort = '-createdAt'
      } = filters;

      const query = {};

      // Apply filters
      if (search) {
        query.$or = [
          { email: { $regex: search, $options: 'i' } },
          { username: { $regex: search, $options: 'i' } },
          { firstName: { $regex: search, $options: 'i' } },
          { lastName: { $regex: search, $options: 'i' } }
        ];
      }

      if (role && role !== 'all') {
        query.role = role;
      }

      if (status && status !== 'all') {
        query.status = status;
      }

      if (organization) {
        query.organization = organization;
      }

      const skip = (page - 1) * limit;

      const [users, total] = await Promise.all([
        User.find(query)
          .populate('organization', 'name code')
          .populate('createdBy', 'username email')
          .populate('updatedBy', 'username email')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        User.countDocuments(query)
      ]);

      return {
        users,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting users:', error);
      throw error;
    }
  }

  /**
   * Update user
   */
  async updateUser(userId, updateData, updatedBy) {
    try {
      const user = await User.findById(userId);
      
      if (!user) {
        throw new AppError('User not found', HTTP_STATUS.NOT_FOUND, 'USER_NOT_FOUND');
      }

      // Check if email or username is being changed and validate uniqueness
      if (updateData.email || updateData.username) {
        const query = {
          $or: []
        };

        if (updateData.email) {
          query.$or.push({ email: updateData.email.toLowerCase() });
        }
        if (updateData.username) {
          query.$or.push({ username: updateData.username.toLowerCase() });
        }

        const existingUser = await User.findOne({
          ...query,
          _id: { $ne: userId }
        });

        if (existingUser) {
          throw new AppError(
            'User with this email or username already exists',
            HTTP_STATUS.CONFLICT,
            'USER_EXISTS'
          );
        }
      }

      // If updating password, validate strength
      if (updateData.password) {
        const passwordValidation = PasswordUtils.validatePasswordStrength(updateData.password);
        if (!passwordValidation.isValid) {
          throw new AppError(
            'Password does not meet strength requirements',
            HTTP_STATUS.BAD_REQUEST,
            'WEAK_PASSWORD',
            { errors: passwordValidation.errors }
          );
        }
        updateData.password = await PasswordUtils.hash(updateData.password);
      }

      // Update user
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        {
          ...updateData,
          updatedBy: updatedBy,
          updatedAt: new Date()
        },
        {
          new: true,
          runValidators: true
        }
      )
      .populate('organization', 'name code')
      .populate('createdBy', 'username email')
      .populate('updatedBy', 'username email');

      logger.info(`User updated: ${updatedUser.email} by ${updatedBy}`);

      return updatedUser;
    } catch (error) {
      logger.error('Error updating user:', error);
      throw error;
    }
  }

  /**
   * Delete user (soft delete)
   */
  async deleteUser(userId, deletedBy) {
    try {
      const user = await User.findById(userId);
      
      if (!user) {
        throw new AppError('User not found', HTTP_STATUS.NOT_FOUND, 'USER_NOT_FOUND');
      }

      // Soft delete by setting status to inactive
      user.status = 'inactive';
      user.updatedBy = deletedBy;
      await user.save();

      logger.info(`User deleted (soft): ${user.email} by ${deletedBy}`);

      return { success: true, message: 'User deleted successfully' };
    } catch (error) {
      logger.error('Error deleting user:', error);
      throw error;
    }
  }

  /**
   * Hard delete user (permanent)
   */
  async hardDeleteUser(userId, deletedBy) {
    try {
      const user = await User.findById(userId);
      
      if (!user) {
        throw new AppError('User not found', HTTP_STATUS.NOT_FOUND, 'USER_NOT_FOUND');
      }

      await user.remove();

      logger.info(`User hard deleted: ${user.email} by ${deletedBy}`);

      return { success: true, message: 'User permanently deleted' };
    } catch (error) {
      logger.error('Error hard deleting user:', error);
      throw error;
    }
  }

async authenticateUser(identifier, password) {
  try {
    console.log(`🔐 Attempting login for: ${identifier}`);

    const user = await User.findOne({
      $or: [
        { email: identifier.toLowerCase() },
        { username: identifier.toLowerCase() }
      ]
    }).select('+password +refreshToken +passwordResetToken +passwordResetExpires');

    if (!user) {
      console.log(`❌ User not found: ${identifier}`);
      throw new AppError('Invalid credentials', HTTP_STATUS.UNAUTHORIZED, 'INVALID_CREDENTIALS');
    }

    console.log(`✅ User found: ${user.email}`);

    if (user.isLocked()) {
      throw new AppError('Account is locked', HTTP_STATUS.UNAUTHORIZED, 'ACCOUNT_LOCKED');
    }

    if (user.status !== 'active') {
      throw new AppError('Account is inactive', HTTP_STATUS.UNAUTHORIZED, 'ACCOUNT_INACTIVE');
    }

    if (!user.comparePassword) {
      console.error('❌ comparePassword method not found on user object');
      throw new AppError('Authentication error', HTTP_STATUS.INTERNAL_SERVER_ERROR, 'AUTH_ERROR');
    }

    const isPasswordValid = await user.comparePassword(password);
    console.log(`✅ Password valid: ${isPasswordValid}`);

    if (!isPasswordValid) {
      await user.incrementLoginAttempts();
      throw new AppError('Invalid credentials', HTTP_STATUS.UNAUTHORIZED, 'INVALID_CREDENTIALS');
    }

    await user.resetLoginAttempts();
    await user.updateLastLogin();

    // Generate tokens FIRST — everything below depends on these existing.
    const payload = {
      id: user._id,
      email: user.email,
      username: user.username,
      role: user.role,
      organization: user.organization
    };

    const accessToken = TokenUtils.generateAccessToken(payload);
    const refreshToken = TokenUtils.generateRefreshToken(payload);

    // Save refresh token
    user.refreshToken = refreshToken;
    await user.save();

    // Attach real permissions from the Role collection (or full access for super_admin)
    // so the frontend's Auth.hasPermission() has accurate, server-sourced data instead
    // of relying solely on its own hardcoded ROLE_PERMISSIONS fallback map.
    const roleDoc = user.role === 'super_admin'
      ? null
      : await Role.findOne({ name: user.role, status: 'active' }).select('permissions');
    const permissions = user.role === 'super_admin'
      ? Object.values(require('../config/constants').PERMISSIONS)
      : (roleDoc ? roleDoc.permissions : []);

    logger.info(`User authenticated: ${user.email}`);

    return {
      user: { ...user.toJSON(), permissions },
      accessToken,
      refreshToken
    };
  } catch (error) {
    logger.error('Error authenticating user:', error);
    throw error;
  }
}

  /**
   * Refresh access token
   */
  async refreshAccessToken(refreshToken) {
    try {
      // Verify refresh token
      const decoded = TokenUtils.verifyRefreshToken(refreshToken);
      
      // Find user with this refresh token
      const user = await User.findOne({
        _id: decoded.id,
        refreshToken: refreshToken
      });

      if (!user) {
        throw new AppError('Invalid refresh token', HTTP_STATUS.UNAUTHORIZED, 'INVALID_REFRESH_TOKEN');
      }

      // Generate new tokens
      const payload = {
        id: user._id,
        email: user.email,
        username: user.username,
        role: user.role,
        organization: user.organization
      };

      const newAccessToken = TokenUtils.generateAccessToken(payload);
      const newRefreshToken = TokenUtils.generateRefreshToken(payload);

      // Update refresh token
      user.refreshToken = newRefreshToken;
      await user.save();

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken
      };
    } catch (error) {
      logger.error('Error refreshing access token:', error);
      throw error;
    }
  }

  /**
   * Logout user
   */
  async logoutUser(userId) {
    try {
      await User.findByIdAndUpdate(userId, {
        refreshToken: null
      });

      logger.info(`User logged out: ${userId}`);

      return { success: true, message: 'Logged out successfully' };
    } catch (error) {
      logger.error('Error logging out user:', error);
      throw error;
    }
  }

  /**
   * Change user password
   */
  async changePassword(userId, oldPassword, newPassword) {
    try {
      const user = await User.findById(userId).select('+password');
      
      if (!user) {
        throw new AppError('User not found', HTTP_STATUS.NOT_FOUND, 'USER_NOT_FOUND');
      }

      // Verify old password
      const isPasswordValid = await user.comparePassword(oldPassword);
      if (!isPasswordValid) {
        throw new AppError('Current password is incorrect', HTTP_STATUS.UNAUTHORIZED, 'INVALID_PASSWORD');
      }

      // Validate new password
      const passwordValidation = PasswordUtils.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        throw new AppError(
          'Password does not meet strength requirements',
          HTTP_STATUS.BAD_REQUEST,
          'WEAK_PASSWORD',
          { errors: passwordValidation.errors }
        );
      }

      // Update password
      user.password = await PasswordUtils.hash(newPassword);
      user.updatedAt = new Date();
      await user.save();

      logger.info(`Password changed for user: ${user.email}`);

      return { success: true, message: 'Password changed successfully' };
    } catch (error) {
      logger.error('Error changing password:', error);
      throw error;
    }
  }

  /**
   * Reset password (for administrators)
   */
  async resetPassword(userId, newPassword, resetBy) {
    try {
      const user = await User.findById(userId);
      
      if (!user) {
        throw new AppError('User not found', HTTP_STATUS.NOT_FOUND, 'USER_NOT_FOUND');
      }

      // Validate new password
      const passwordValidation = PasswordUtils.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        throw new AppError(
          'Password does not meet strength requirements',
          HTTP_STATUS.BAD_REQUEST,
          'WEAK_PASSWORD',
          { errors: passwordValidation.errors }
        );
      }

      // Update password
      user.password = await PasswordUtils.hash(newPassword);
      user.updatedBy = resetBy;
      user.updatedAt = new Date();
      user.loginAttempts = 0;
      user.lockUntil = null;
      user.refreshToken = null;
      await user.save();

      logger.info(`Password reset for user: ${user.email} by ${resetBy}`);

      return { success: true, message: 'Password reset successfully' };
    } catch (error) {
      logger.error('Error resetting password:', error);
      throw error;
    }
  }

  /**
   * Initiate password reset request
   */
  async initiatePasswordReset(email) {
    try {
      const user = await User.findOne({ email: email.toLowerCase() });
      
      if (!user) {
        // Don't reveal that user doesn't exist for security
        return { success: true, message: 'If an account exists, password reset email has been sent' };
      }

      // Generate reset token
      const resetToken = TokenUtils.generatePasswordResetToken({
        id: user._id,
        email: user.email
      });

      // Save reset token to user
      user.passwordResetToken = resetToken;
      user.passwordResetExpires = new Date(Date.now() + 3600000); // 1 hour
      await user.save();

      // TODO: Send email with reset link
      // This will be implemented when email service is added

      logger.info(`Password reset initiated for user: ${user.email}`);

      return { success: true, message: 'Password reset email has been sent' };
    } catch (error) {
      logger.error('Error initiating password reset:', error);
      throw error;
    }
  }

  /**
   * Complete password reset
   */
  async completePasswordReset(token, newPassword) {
    try {
      // Verify token
      const decoded = TokenUtils.verifyPasswordResetToken(token);
      
      // Find user with this token
      const user = await User.findOne({
        _id: decoded.id,
        passwordResetToken: token,
        passwordResetExpires: { $gt: new Date() }
      });

      if (!user) {
        throw new AppError('Invalid or expired reset token', HTTP_STATUS.BAD_REQUEST, 'INVALID_RESET_TOKEN');
      }

      // Validate new password
      const passwordValidation = PasswordUtils.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        throw new AppError(
          'Password does not meet strength requirements',
          HTTP_STATUS.BAD_REQUEST,
          'WEAK_PASSWORD',
          { errors: passwordValidation.errors }
        );
      }

      // Update password
      user.password = await PasswordUtils.hash(newPassword);
      user.passwordResetToken = null;
      user.passwordResetExpires = null;
      user.loginAttempts = 0;
      user.lockUntil = null;
      user.refreshToken = null;
      await user.save();

      logger.info(`Password reset completed for user: ${user.email}`);

      return { success: true, message: 'Password reset successfully' };
    } catch (error) {
      logger.error('Error completing password reset:', error);
      throw error;
    }
  }
}

module.exports = new UserService();