// middleware/audit.js
const AuditLogService = require('../services/auditLogService');

/**
 * Automatic Audit Middleware - Logs all authenticated API requests
 */
function auditMiddleware() {
  return async (req, res, next) => {
    // Skip audit for certain paths
    const skipPaths = ['/health', '/api/v1/logs/ingest', '/api/v1/auth/login', '/api/v1/auth/refresh'];
    if (skipPaths.some(path => req.path.startsWith(path))) {
      return next();
    }

    // Only log authenticated requests
    if (!req.user) {
      return next();
    }

    // Store original send
    const originalSend = res.send;
    
    // Override send method
    res.send = function(data) {
      // Only log successful requests (2xx status codes)
      if (res.statusCode >= 200 && res.statusCode < 300) {
        // Determine action and resource
        const action = determineAction(req, res);
        const resource = determineResource(req);
        const resourceId = getResourceId(req);
        const resourceName = getResourceName(req, data);
        
        // Build audit log data
        const auditData = {
          organization: req.user.organization,
          user: req.user._id,
          action: action,
          resource: resource,
          resourceId: resourceId,
          resourceName: resourceName || 'N/A',
          status: 'success',
          ipAddress: req.ip || req.connection?.remoteAddress || '0.0.0.0',
          userAgent: req.get('user-agent') || 'Unknown',
          severity: determineSeverity(action, resource),
          performedBy: req.user._id,
          details: {
            method: req.method,
            url: req.originalUrl,
            statusCode: res.statusCode,
            timestamp: new Date().toISOString()
          }
        };

        // Log asynchronously
        setImmediate(() => {
          AuditLogService.createAuditLog(auditData)
            .catch(err => console.error('❌ Audit log error:', err.message));
        });
      }
      
      return originalSend.call(this, data);
    };
    
    next();
  };
}

/**
 * Determine action from request
 */
function determineAction(req, res) {
  const method = req.method;
  const path = req.path;
  
  // ============================================
  // AUTHENTICATION ACTIONS
  // ============================================
  if (path.includes('/auth/logout')) return 'logout';
  if (path.includes('/auth/change-password')) return 'password_changed';
  if (path.includes('/auth/forgot-password')) return 'password_reset';
  if (path.includes('/auth/reset-password')) return 'password_reset';
  
  // ============================================
  // USER ACTIONS
  // ============================================
  if (path.includes('/users')) {
    if (method === 'POST') {
      if (path.includes('/reset-password')) return 'password_reset';
      return 'user_created';
    }
    if (method === 'PUT' || method === 'PATCH') {
      if (path.includes('/reset-password')) return 'password_reset';
      if (path.includes('/activate')) return 'user_activated';
      if (path.includes('/deactivate')) return 'user_deactivated';
      if (path.includes('/lock')) return 'user_locked';
      return 'user_updated';
    }
    if (method === 'DELETE') {
      if (path.includes('/permanent')) return 'user_deleted';
      return 'user_deleted';
    }
  }
  
  // ============================================
  // ROLE ACTIONS
  // ============================================
  if (path.includes('/roles')) {
    if (method === 'POST') {
      if (path.includes('/initialize')) return 'system_configured';
      return 'role_created';
    }
    if (method === 'PUT') return 'role_updated';
    if (method === 'DELETE') {
      if (path.includes('/permanent')) return 'role_deleted';
      return 'role_deleted';
    }
    if (path.includes('/assign')) return 'role_assigned';
    if (path.includes('/revoke')) return 'role_revoked';
  }
  
  // ============================================
  // ORGANIZATION ACTIONS
  // ============================================
  if (path.includes('/organizations')) {
    if (method === 'POST') return 'org_created';
    if (method === 'PUT') return 'org_updated';
    if (method === 'DELETE') {
      if (path.includes('/permanent')) return 'org_deleted';
      return 'org_deleted';
    }
  }
  
  // ============================================
  // ASSET ACTIONS
  // ============================================
  if (path.includes('/assets')) {
    if (method === 'POST') {
      if (path.includes('/bulk')) return 'asset_created';
      return 'asset_created';
    }
    if (method === 'PUT') {
      if (path.includes('/update-risk')) return 'asset_updated';
      if (path.includes('/activate')) return 'asset_activated';
      if (path.includes('/decommission')) return 'asset_decommissioned';
      return 'asset_updated';
    }
    if (method === 'DELETE') {
      if (path.includes('/permanent')) return 'asset_deleted';
      return 'asset_deleted';
    }
  }
  
  // ============================================
  // LOG SOURCE ACTIONS
  // ============================================
  if (path.includes('/log-sources')) {
    if (method === 'POST') {
      return 'log_source_created';
    }
    if (method === 'PUT' || method === 'PATCH') {
      if (path.includes('/heartbeat')) return 'log_source_updated';
      if (path.includes('/status')) return 'log_source_updated';
      if (path.includes('/regenerate-token')) return 'log_source_updated';
      return 'log_source_updated';
    }
    if (method === 'DELETE') {
      if (path.includes('/permanent')) return 'log_source_deleted';
      return 'log_source_deleted';
    }
  }
  
  // ============================================
  // ALERT ACTIONS
  // ============================================
  if (path.includes('/alerts')) {
    if (method === 'POST') {
      if (path.includes('/from-log')) return 'alert_created';
      if (path.includes('/batch')) return 'alert_created';
      if (path.includes('/generate')) return 'alert_created';
      return 'alert_created';
    }
    if (method === 'PUT') {
      if (path.includes('/assign')) return 'alert_assigned';
      if (path.includes('/resolve')) return 'alert_resolved';
      if (path.includes('/close')) return 'alert_closed';
      if (path.includes('/escalate')) return 'alert_escalated';
      if (path.includes('/note')) return 'alert_updated';
      return 'alert_updated';
    }
    if (method === 'DELETE') {
      if (path.includes('/permanent')) return 'alert_deleted';
      return 'alert_deleted';
    }
    if (path.includes('/assign')) return 'alert_assigned';
    if (path.includes('/resolve')) return 'alert_resolved';
    if (path.includes('/escalate')) return 'alert_escalated';
    if (method === 'PATCH') {
      if (path.includes('/status')) return 'alert_updated';
      return 'alert_updated';
    }
  }
  
  // ============================================
  // INCIDENT ACTIONS
  // ============================================
  if (path.includes('/incidents')) {
    if (method === 'POST') {
      if (path.includes('/from-alerts')) return 'incident_created';
      if (path.includes('/batch')) return 'incident_created';
      return 'incident_created';
    }
    if (method === 'PUT') {
      if (path.includes('/assign')) return 'incident_assigned';
      if (path.includes('/resolve')) return 'incident_resolved';
      if (path.includes('/close')) return 'incident_closed';
      if (path.includes('/reopen')) return 'incident_reopened';
      if (path.includes('/escalate')) return 'incident_escalated';
      if (path.includes('/note')) return 'incident_updated';
      if (path.includes('/evidence')) return 'incident_updated';
      if (path.includes('/timeline')) return 'incident_updated';
      if (path.includes('/affected-asset')) return 'incident_updated';
      if (path.includes('/containment')) return 'incident_updated';
      if (path.includes('/status')) return 'incident_updated';
      return 'incident_updated';
    }
    if (method === 'DELETE') {
      if (path.includes('/permanent')) return 'incident_deleted';
      return 'incident_deleted';
    }
    if (path.includes('/assign')) return 'incident_assigned';
    if (path.includes('/resolve')) return 'incident_resolved';
    if (path.includes('/escalate')) return 'incident_escalated';
    if (method === 'PATCH') {
      if (path.includes('/status')) return 'incident_updated';
      return 'incident_updated';
    }
  }
  
  // ============================================
  // IOC ACTIONS
  // ============================================
  if (path.includes('/iocs')) {
    if (method === 'POST') {
      if (path.includes('/bulk')) return 'ioc_created';
      if (path.includes('/import')) return 'ioc_created';
      return 'ioc_created';
    }
    if (method === 'PUT') {
      if (path.includes('/link-incident')) return 'ioc_linked';
      if (path.includes('/link-alert')) return 'ioc_linked';
      if (path.includes('/expire')) return 'ioc_updated';
      if (path.includes('/reactivate')) return 'ioc_updated';
      return 'ioc_updated';
    }
    if (method === 'DELETE') {
      if (path.includes('/permanent')) return 'ioc_deleted';
      return 'ioc_deleted';
    }
  }
  
  // ============================================
  // THREAT RULE ACTIONS
  // ============================================
  if (path.includes('/threat-rules')) {
    if (method === 'POST') {
      if (path.includes('/import')) return 'rule_created';
      if (path.includes('/validate-condition')) return 'rule_updated';
      if (path.includes('/process-log')) return 'rule_triggered';
      return 'rule_created';
    }
    if (method === 'PUT') return 'rule_updated';
    if (method === 'DELETE') {
      if (path.includes('/permanent')) return 'rule_deleted';
      return 'rule_deleted';
    }
    if (method === 'PATCH') {
      if (path.includes('/toggle')) {
        return req.body?.enabled ? 'rule_enabled' : 'rule_disabled';
      }
      return 'rule_updated';
    }
    if (path.includes('/clone')) return 'rule_created';
    if (path.includes('/toggle')) {
      return req.body?.enabled ? 'rule_enabled' : 'rule_disabled';
    }
  }
  
  // ============================================
  // REPORT ACTIONS
  // ============================================
  if (path.includes('/reports')) {
    if (method === 'POST') {
      if (path.includes('/schedule')) return 'report_scheduled';
      return 'report_created';
    }
    if (method === 'PUT') {
      if (path.includes('/schedule')) return 'report_scheduled';
      if (path.includes('/unschedule')) return 'report_updated';
      return 'report_updated';
    }
    if (method === 'DELETE') {
      if (path.includes('/permanent')) return 'report_deleted';
      return 'report_deleted';
    }
    if (path.includes('/generate')) return 'report_generated';
    if (path.includes('/download')) return 'report_downloaded';
    if (path.includes('/unschedule')) return 'report_updated';
  }
  
  // ============================================
  // SETTINGS ACTIONS
  // ============================================
  if (path.includes('/settings')) {
    if (method === 'PUT' || method === 'PATCH') {
      if (path.includes('/reset')) return 'settings_updated';
      if (path.includes('/whitelist')) return 'settings_updated';
      if (path.includes('/webhooks')) return 'settings_updated';
      if (path.includes('/validate-smtp')) return 'settings_updated';
      if (path.includes('/validate-slack')) return 'settings_updated';
      return 'settings_updated';
    }
    if (method === 'POST') {
      if (path.includes('/reset')) return 'settings_updated';
      if (path.includes('/whitelist')) return 'settings_updated';
      if (path.includes('/webhooks')) return 'settings_updated';
      if (path.includes('/validate')) return 'settings_updated';
      return 'settings_updated';
    }
    if (method === 'DELETE') {
      if (path.includes('/whitelist')) return 'settings_updated';
      if (path.includes('/webhooks')) return 'settings_updated';
      return 'settings_updated';
    }
  }
  
  // ============================================
  // AUDIT LOG ACTIONS
  // ============================================
  if (path.includes('/audit-logs')) {
    if (method === 'POST' && path.includes('/cleanup')) return 'audit_log_cleaned';
  }
  
  // ============================================
  // DEFAULT - VIEW actions for GET requests
  // ============================================
  if (method === 'GET') return 'view';
  
  return 'unknown';
}

/**
 * Determine resource from request
 */
function determineResource(req) {
  const path = req.path;
  
  if (path.includes('/auth')) return 'authentication';
  if (path.includes('/users')) return 'user';
  if (path.includes('/roles')) return 'role';
  if (path.includes('/organizations')) return 'organization';
  if (path.includes('/assets')) return 'asset';
  if (path.includes('/log-sources')) return 'log_source';
  if (path.includes('/logs')) return 'log';
  if (path.includes('/alerts')) return 'alert';
  if (path.includes('/incidents')) return 'incident';
  if (path.includes('/iocs')) return 'ioc';
  if (path.includes('/threat-rules')) return 'threat_rule';
  if (path.includes('/reports')) return 'report';
  if (path.includes('/settings')) return 'settings';
  if (path.includes('/audit-logs')) return 'audit_log';
  
  return 'system';
}

/**
 * Get resource ID from request
 */
function getResourceId(req) {
  // Check params
  if (req.params.id) return req.params.id;
  if (req.params.userId) return req.params.userId;
  if (req.params.organizationId) return req.params.organizationId;
  if (req.params.assetId) return req.params.assetId;
  if (req.params.incidentId) return req.params.incidentId;
  if (req.params.alertId) return req.params.alertId;
  if (req.params.iocId) return req.params.iocId;
  if (req.params.ruleId) return req.params.ruleId;
  if (req.params.reportId) return req.params.reportId;
  
  // Check body for ID
  if (req.body && req.body.id) return req.body.id;
  if (req.body && req.body._id) return req.body._id;
  
  return null;
}

/**
 * Get resource name from request or response
 */
function getResourceName(req, responseData) {
  // Try to get from response data
  try {
    const parsedData = typeof responseData === 'string' ? JSON.parse(responseData) : responseData;
    if (parsedData?.data?.name) return parsedData.data.name;
    if (parsedData?.data?.title) return parsedData.data.title;
    if (parsedData?.data?.email) return parsedData.data.email;
    if (parsedData?.data?.username) return parsedData.data.username;
    if (parsedData?.data?.value) return parsedData.data.value;
  } catch (e) {}
  
  // Try from request body
  if (req.body?.name) return req.body.name;
  if (req.body?.title) return req.body.title;
  if (req.body?.email) return req.body.email;
  if (req.body?.username) return req.body.username;
  if (req.body?.value) return req.body.value;
  
  return null;
}

/**
 * Determine severity based on action and resource
 */
function determineSeverity(action, resource) {
  const highSeverityActions = [
    'user_deleted', 'role_deleted', 'org_deleted', 'asset_deleted',
    'user_locked', 'login_failed', 'alert_escalated', 'incident_escalated',
    'rule_deleted', 'ioc_deleted'
  ];
  const highSeverityResources = ['organization', 'user', 'role', 'system'];
  
  if (highSeverityActions.includes(action)) return 'high';
  if (highSeverityResources.includes(resource)) return 'medium';
  
  return 'info';
}

module.exports = auditMiddleware;