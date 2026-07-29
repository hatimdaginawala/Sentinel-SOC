/**
 * Application constants
 */
module.exports = {
  // User Roles
  ROLES: {
    SUPER_ADMIN: 'super_admin',
    SECURITY_ADMIN: 'security_admin',
    SOC_ANALYST: 'soc_analyst',
    INCIDENT_RESPONDER: 'incident_responder',
    AUDITOR: 'auditor'
  },

  // Permissions
  PERMISSIONS: {
    // User Management
    MANAGE_USERS: 'manage_users',
    VIEW_USERS: 'view_users',
    
    // Organization Management
    MANAGE_ORGANIZATIONS: 'manage_organizations',
    VIEW_ORGANIZATIONS: 'view_organizations',
    
    // Asset Management
    MANAGE_ASSETS: 'manage_assets',
    VIEW_ASSETS: 'view_assets',
    
    // Log Management
    MANAGE_LOGS: 'manage_logs',
    VIEW_LOGS: 'view_logs',
    
    // Alert Management
    MANAGE_ALERTS: 'manage_alerts',
    VIEW_ALERTS: 'view_alerts',
    
    // Incident Management
    MANAGE_INCIDENTS: 'manage_incidents',
    VIEW_INCIDENTS: 'view_incidents',
    RESPOND_INCIDENTS: 'respond_incidents',
    
    // Report Management
    MANAGE_REPORTS: 'manage_reports',
    VIEW_REPORTS: 'view_reports',
    GENERATE_REPORTS: 'generate_reports',
    
    // System Configuration
    CONFIGURE_SYSTEM: 'configure_system',
    VIEW_SETTINGS: 'view_settings',
    
    // Audit
    VIEW_AUDIT_LOGS: 'view_audit_logs',
    
    // Threat Intelligence
    MANAGE_THREAT_RULES: 'manage_threat_rules',
    VIEW_THREAT_RULES: 'view_threat_rules',
    
    // IOC Management
    MANAGE_IOCS: 'manage_iocs',
    VIEW_IOCS: 'view_iocs'
  },

  // Alert Severity Levels
  SEVERITY: {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    INFO: 'info'
  },

  // Incident Status
  INCIDENT_STATUS: {
    NEW: 'new',
    INVESTIGATING: 'investigating',
    IN_PROGRESS: 'in_progress',
    RESOLVED: 'resolved',
    CLOSED: 'closed'
  },

  // Alert Status
  ALERT_STATUS: {
    ACTIVE: 'active',
    INVESTIGATING: 'investigating',
    RESOLVED: 'resolved',
    SUPPRESSED: 'suppressed'
  },

  // Asset Types
  ASSET_TYPES: {
    SERVER: 'server',
    WORKSTATION: 'workstation',
    FIREWALL: 'firewall',
    ROUTER: 'router',
    SWITCH: 'switch',
    CLOUD_SERVER: 'cloud_server',
    WEB_APPLICATION: 'web_application',
    DATABASE: 'database',
    NETWORK_DEVICE: 'network_device',
    SECURITY_APPLIANCE: 'security_appliance'
  },

  // Log Source Types
  LOG_SOURCE_TYPES: {
    WINDOWS: 'windows',
    LINUX: 'linux',
    APACHE: 'apache',
    NGINX: 'nginx',
    PFSENSE: 'pfsense',
    SURICATA: 'suricata',
    SNORT: 'snort',
    ZEEK: 'zeek',
    WAZUH: 'wazuh',
    CUSTOM: 'custom'
  },

  // Event Categories
  EVENT_CATEGORIES: {
    AUTHENTICATION: 'authentication',
    NETWORK: 'network',
    SYSTEM: 'system',
    APPLICATION: 'application',
    DATABASE: 'database',
    WEB: 'web',
    MALWARE: 'malware',
    POLICY: 'policy'
  },

  // Detection Rule Types
  RULE_TYPES: {
    SIGNATURE: 'signature',
    BEHAVIORAL: 'behavioral',
    ANOMALY: 'anomaly',
    STATISTICAL: 'statistical'
  },

  // Notification Channels
  NOTIFICATION_CHANNELS: {
    EMAIL: 'email',
    IN_APP: 'in_app',
    SLACK: 'slack',
    TEAMS: 'teams'
  },

  // Report Types
  REPORT_TYPES: {
    DAILY: 'daily',
    WEEKLY: 'weekly',
    MONTHLY: 'monthly',
    EXECUTIVE: 'executive',
    INCIDENT: 'incident',
    RISK: 'risk',
    COMPLIANCE: 'compliance'
  },

  // Report Formats
  REPORT_FORMATS: {
    PDF: 'pdf',
    EXCEL: 'excel',
    CSV: 'csv'
  },

  // Event Types for Detection
  THREAT_TYPES: {
    BRUTE_FORCE: 'brute_force',
    SQL_INJECTION: 'sql_injection',
    XSS: 'xss',
    COMMAND_INJECTION: 'command_injection',
    RCE: 'rce',
    REVERSE_SHELL: 'reverse_shell',
    PORT_SCAN: 'port_scan',
    MALWARE_COMMUNICATION: 'malware_communication',
    DNS_TUNNELING: 'dns_tunneling',
    DATA_EXFILTRATION: 'data_exfiltration',
    DOS_ATTACK: 'dos_attack',
    PRIVILEGE_ESCALATION: 'privilege_escalation',
    SUSPICIOUS_POWERSHELL: 'suspicious_powershell',
    UNAUTHORIZED_ACCESS: 'unauthorized_access',
    BEACONING: 'beaconing'
  },

  // Default Pagination
  DEFAULT_PAGE: 1,
  DEFAULT_LIMIT: 20,
  MAX_LIMIT: 100,

  // HTTP Status Codes
  HTTP_STATUS: {
    OK: 200,
    CREATED: 201,
    ACCEPTED: 202,
    NO_CONTENT: 204,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    METHOD_NOT_ALLOWED: 405,
    CONFLICT: 409,
    UNPROCESSABLE_ENTITY: 422,
    TOO_MANY_REQUESTS: 429,
    INTERNAL_SERVER_ERROR: 500,
    SERVICE_UNAVAILABLE: 503
  },

  // Environment
  ENVIRONMENTS: {
    DEVELOPMENT: 'development',
    TESTING: 'testing',
    STAGING: 'staging',
    PRODUCTION: 'production'
  }
};