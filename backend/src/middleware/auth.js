const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { AppError } = require('./errorHandler');
const { HTTP_STATUS } = require('../config/constants');
const logger = require('../config/logger');
const Role = require('../models/Role'); 

/**
 * Protect routes - verify JWT token
 */
const protect = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      throw new AppError(
        'You are not logged in. Please log in to access this resource.',
        HTTP_STATUS.UNAUTHORIZED,
        'NO_TOKEN'
      );
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      const user = await User.findById(decoded.id)
        .select('+password')
        .populate('organization', 'name code');

      if (!user) {
        throw new AppError(
          'The user belonging to this token no longer exists.',
          HTTP_STATUS.UNAUTHORIZED,
          'USER_NOT_FOUND'
        );
      }

      if (user.status !== 'active') {
        throw new AppError(
          'Your account is not active. Please contact support.',
          HTTP_STATUS.UNAUTHORIZED,
          'ACCOUNT_INACTIVE'
        );
      }

      if (user.isLocked()) {
        throw new AppError(
          'Your account is locked due to multiple failed login attempts.',
          HTTP_STATUS.UNAUTHORIZED,
          'ACCOUNT_LOCKED'
        );
      }

      // Attach the permission set for this user's role so authorize()
      // has something real to check. Without this, every non-super-admin
      // is denied every permission-gated route regardless of their role.
      if (user.role === 'super_admin') {
        // Bypassed explicitly in authorize() anyway, but keep this
        // consistent in case anything else reads req.user.permissions directly.
        const { PERMISSIONS } = require('../config/constants');
        user.permissions = Object.values(PERMISSIONS);
      } else {
        const roleDoc = await Role.findOne({ name: user.role, status: 'active' }).select('permissions');
        user.permissions = roleDoc ? roleDoc.permissions : [];
      }

      req.user = user;
      next();
    } catch (error) {
      if (error.name === 'JsonWebTokenError') {
        throw new AppError('Invalid token. Please log in again.', HTTP_STATUS.UNAUTHORIZED, 'INVALID_TOKEN');
      } else if (error.name === 'TokenExpiredError') {
        throw new AppError('Token expired. Please log in again.', HTTP_STATUS.UNAUTHORIZED, 'TOKEN_EXPIRED');
      }
      throw error;
    }
  } catch (error) {
    next(error);
  }
};

/**
 * Authorize routes - check user permissions
 * @param {...string} permissions - Required permissions
 */
const authorize = (...permissions) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        throw new AppError(
          'You are not authorized to access this resource.',
          HTTP_STATUS.FORBIDDEN,
          'NOT_AUTHORIZED'
        );
      }

      // Super admin has all permissions
      if (req.user.role === 'super_admin') {
        return next();
      }

      // Check if user has any of the required permissions
      const hasPermission = permissions.some(permission => 
        req.user.permissions && req.user.permissions.includes(permission)
      );

      if (!hasPermission) {
        throw new AppError(
          'You do not have permission to perform this action.',
          HTTP_STATUS.FORBIDDEN,
          'INSUFFICIENT_PERMISSIONS'
        );
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Authorize by role
 * @param {...string} roles - Allowed roles
 */
const authorizeRole = (...roles) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        throw new AppError(
          'You are not authorized to access this resource.',
          HTTP_STATUS.FORBIDDEN,
          'NOT_AUTHORIZED'
        );
      }

      if (!roles.includes(req.user.role)) {
        throw new AppError(
          'You do not have permission to perform this action.',
          HTTP_STATUS.FORBIDDEN,
          'INSUFFICIENT_PERMISSIONS'
        );
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Restrict to own user or admin
 */
const restrictToOwnUser = (req, res, next) => {
  try {
    const userId = req.params.id || req.params.userId;
    
    if (!userId) {
      return next();
    }

    // Allow if user is accessing their own data or is admin
    if (req.user._id.toString() === userId || req.user.role === 'super_admin') {
      return next();
    }

    throw new AppError(
      'You are not authorized to access this resource.',
      HTTP_STATUS.FORBIDDEN,
      'NOT_AUTHORIZED'
    );
  } catch (error) {
    next(error);
  }
};

module.exports = {
  protect,
  authorize,
  authorizeRole,
  restrictToOwnUser
};