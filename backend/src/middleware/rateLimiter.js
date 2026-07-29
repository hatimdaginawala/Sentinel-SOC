const rateLimit = require('express-rate-limit');
const { HTTP_STATUS } = require('../config/constants');

/**
 * General rate limiter for all routes
 */
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100000, // Limit each IP to 100000 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests, please try again later.',
    errorCode: 'RATE_LIMIT_EXCEEDED',
    retryAfter: 60 * 15 // 15 minutes in seconds
  },
  statusCode: HTTP_STATUS.TOO_MANY_REQUESTS,
  handler: (req, res, next, options) => {
    res.status(options.statusCode).json(options.message);
  },
  keyGenerator: (req) => {
    // Use user ID if authenticated, otherwise use IP
    return req.user?.id || req.ip;
  }
});

/**
 * Strict rate limiter for authentication routes
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 login attempts per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many login attempts, please try again later.',
    errorCode: 'AUTH_RATE_LIMIT_EXCEEDED',
    retryAfter: 60 * 15
  },
  statusCode: HTTP_STATUS.TOO_MANY_REQUESTS
});

/**
 * Strict rate limiter for sensitive operations
 */
const sensitiveOperationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 sensitive operations per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many sensitive operations, please try again later.',
    errorCode: 'SENSITIVE_OPERATION_LIMIT_EXCEEDED',
    retryAfter: 60 * 60
  },
  statusCode: HTTP_STATUS.TOO_MANY_REQUESTS
});

module.exports = {
  generalLimiter,
  authLimiter,
  sensitiveOperationLimiter
};