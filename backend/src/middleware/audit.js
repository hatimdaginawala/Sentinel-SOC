// middleware/audit.js
const AuditLogService = require('../services/auditLogService');
const { asyncHandler } = require('./errorHandler');

/**
 * Audit middleware for automatic logging of CRUD operations
 */
const audit = (resource, actionMap) => {
  return asyncHandler(async (req, res, next) => {
    // Store original send method
    const originalSend = res.send;
    
    // Override send method to capture response
    res.send = function(data) {
      // Only log if request was successful
      if (res.statusCode >= 200 && res.statusCode < 300) {
        const user = req.user;
        const action = actionMap[req.method] || 'unknown';
        const resourceId = req.params.id || req.params.resourceId;
        const resourceName = req.body?.name || req.body?.title || resourceId;
        
        // Log the action
        AuditLogService.createAuditLog({
          organization: user?.organization,
          user: user?._id,
          action: action,
          resource: resource,
          resourceId: resourceId,
          resourceName: resourceName,
          changes: {
            before: req.body,
            after: data
          },
          status: 'success',
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
          performedBy: user?._id
        }).catch(err => console.error('Audit log error:', err));
      }
      
      // Call original send
      return originalSend.call(this, data);
    };
    
    next();
  });
};

/**
 * Authentication audit middleware
 */
const authAudit = (action) => {
  return asyncHandler(async (req, res, next) => {
    // Store original send
    const originalSend = res.send;
    
    res.send = function(data) {
      try {
        const parsedData = typeof data === 'string' ? JSON.parse(data) : data;
        const user = req.user || parsedData?.data?.user;
        const status = res.statusCode >= 200 && res.statusCode < 300 ? 'success' : 'failure';
        
        if (user) {
          AuditLogService.createAuditLog({
            organization: user.organization,
            user: user._id,
            action: action,
            resource: 'authentication',
            resourceName: user.email,
            status: status,
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
            severity: status === 'success' ? 'info' : 'medium',
            performedBy: user._id
          }).catch(err => console.error('Audit log error:', err));
        }
      } catch (e) {
        // If response wasn't JSON, ignore
      }
      
      return originalSend.call(this, data);
    };
    
    next();
  });
};

module.exports = { audit, authAudit };