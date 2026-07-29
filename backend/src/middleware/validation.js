const { validationResult } = require('express-validator');
const { HTTP_STATUS } = require('../config/constants');

/**
 * Validate request middleware
 */
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => ({
      field: error.path,
      message: error.msg,
      value: error.value
    }));

    return res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      message: 'Validation failed',
      errorCode: 'VALIDATION_ERROR',
      errors: errorMessages
    });
  }
  
  next();
};

/**
 * Sanitize request body
 */
const sanitizeRequest = (req, res, next) => {
  // Remove any potentially dangerous characters
  const sanitize = (value) => {
    if (typeof value === 'string') {
      // Remove script tags and dangerous content
      return value
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .trim();
    }
    if (Array.isArray(value)) {
      return value.map(item => sanitize(item));
    }
    if (typeof value === 'object' && value !== null) {
      const sanitized = {};
      for (const key of Object.keys(value)) {
        sanitized[key] = sanitize(value[key]);
      }
      return sanitized;
    }
    return value;
  };

  if (req.body) {
    req.body = sanitize(req.body);
  }

  if (req.query) {
    req.query = sanitize(req.query);
  }

  if (req.params) {
    req.params = sanitize(req.params);
  }

  next();
};

module.exports = {
  validateRequest,
  sanitizeRequest
};