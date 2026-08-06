const express = require('express');
const router = express.Router();
const AlertController = require('../controllers/alertController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS, SEVERITY, ALERT_STATUS } = require('../config/constants');

console.log(' Setting up alert routes...');

// Validation rules
const createAlertFromLogValidation = [
  body('logId')
    .isMongoId()
    .withMessage('Invalid log ID'),
  body('alertData')
    .optional()
    .isObject()
    .withMessage('Alert data must be an object'),
  body('alertData.title')
    .optional()
    .isLength({ min: 3, max: 200 })
    .withMessage('Title must be between 3 and 200 characters'),
  body('alertData.description')
    .optional()
    .isLength({ min: 3, max: 500 })
    .withMessage('Description must be between 3 and 500 characters'),
  body('alertData.severity')
    .optional()
    .isIn(Object.values(SEVERITY))
    .withMessage(`Severity must be one of: ${Object.values(SEVERITY).join(', ')}`),
  body('alertData.category')
    .optional()
    .isIn(['authentication', 'network', 'system', 'application', 'database', 'web', 'malware', 'policy', 'access', 'error', 'ids', 'firewall'])
    .withMessage('Invalid category'),
  body('alertData.threatType')
    .optional()
    .isIn(['brute_force', 'sql_injection', 'xss', 'command_injection', 'rce', 'reverse_shell', 'port_scan', 'malware_communication', 'dns_tunneling', 'data_exfiltration', 'dos_attack', 'privilege_escalation', 'suspicious_powershell', 'unauthorized_access', 'beaconing', 'ddos', 'malware', 'phishing', 'ransomware'])
    .withMessage('Invalid threat type'),
  body('alertData.confidence')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Confidence must be between 0 and 100')
];

const batchCreateAlertsValidation = [
  body('logIds')
    .isArray()
    .withMessage('logIds must be an array')
    .custom((logIds) => {
      if (logIds.length === 0) {
        throw new Error('At least one log ID is required');
      }
      return true;
    }),
  body('alertData')
    .optional()
    .isObject()
    .withMessage('Alert data must be an object')
];

const alertIdValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid alert ID')
];

const assignAlertValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid alert ID'),
  body('userId')
    .isMongoId()
    .withMessage('Invalid user ID')
];

const updateStatusValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid alert ID'),
  body('status')
    .isIn(Object.values(ALERT_STATUS))
    .withMessage(`Status must be one of: ${Object.values(ALERT_STATUS).join(', ')}`),
  body('note')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Note cannot exceed 500 characters')
];

const addNoteValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid alert ID'),
  body('note')
    .isLength({ min: 3, max: 500 })
    .withMessage('Note must be between 3 and 500 characters')
];

const escalateAlertValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid alert ID'),
  body('escalateTo')
    .isMongoId()
    .withMessage('Invalid user ID'),
  body('reason')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Reason cannot exceed 500 characters')
];

const resolveAlertValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid alert ID'),
  body('resolutionStatus')
    .isIn(['unresolved', 'mitigated', 'false_positive', 'accepted_risk', 'remediated', 'contained'])
    .withMessage('Invalid resolution status'),
  body('notes')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Notes cannot exceed 500 characters')
];

const generateAlertValidation = [
  body('logId')
    .isMongoId()
    .withMessage('Invalid log ID'),
  body('threatType')
    .isIn(['brute_force', 'sql_injection', 'xss', 'command_injection', 'rce', 'reverse_shell', 'port_scan', 'malware_communication', 'dns_tunneling', 'data_exfiltration', 'dos_attack', 'privilege_escalation', 'suspicious_powershell', 'unauthorized_access', 'beaconing', 'ddos', 'malware', 'phishing', 'ransomware'])
    .withMessage('Invalid threat type'),
  body('severity')
    .optional()
    .isIn(Object.values(SEVERITY))
    .withMessage(`Severity must be one of: ${Object.values(SEVERITY).join(', ')}`)
];

const batchGenerateValidation = [
  body('logIds')
    .isArray()
    .withMessage('logIds must be an array')
    .custom((logIds) => {
      if (logIds.length === 0) {
        throw new Error('At least one log ID is required');
      }
      return true;
    }),
  body('threatType')
    .isIn(['brute_force', 'sql_injection', 'xss', 'command_injection', 'rce', 'reverse_shell', 'port_scan', 'malware_communication', 'dns_tunneling', 'data_exfiltration', 'dos_attack', 'privilege_escalation', 'suspicious_powershell', 'unauthorized_access', 'beaconing', 'ddos', 'malware', 'phishing', 'ransomware'])
    .withMessage('Invalid threat type'),
  body('severity')
    .optional()
    .isIn(Object.values(SEVERITY))
    .withMessage(`Severity must be one of: ${Object.values(SEVERITY).join(', ')}`)
];

// All routes require authentication
router.use(protect);

// Public (authenticated) routes
router.get('/alerts/categories', AlertController.getAlertCategories);
router.get('/alerts/threat-types', AlertController.getThreatTypes);
router.get('/alerts/resolution-statuses', AlertController.getResolutionStatuses);
router.get('/alerts/severities', AlertController.getSeverityLevels);
router.get('/alerts/statuses', AlertController.getAlertStatuses);
router.get('/alerts/assigned-to-me', AlertController.getAlertsAssignedToMe);
router.get('/alerts/high-priority', AlertController.getHighPriorityAlerts);

// Alert management routes
router.get('/alerts/statistics',
  AlertController.getAlertStatistics
);

router.get('/alerts/search',
  query('query').isLength({ min: 1 }).withMessage('Search query is required').trim(),
  validateRequest,
  AlertController.searchAlerts
);

router.get('/alerts',
  AlertController.getAlerts
);

router.get('/alerts/organization/:organizationId',
  param('organizationId').isMongoId().withMessage('Invalid organization ID'),
  validateRequest,
  AlertController.getAlertsByOrganization
);

router.get('/alerts/:id',
  alertIdValidation,
  validateRequest,
  AlertController.getAlertById
);

// Admin only routes
router.post('/alerts/from-log',
  authorize(PERMISSIONS.MANAGE_ALERTS),
  createAlertFromLogValidation,
  validateRequest,
  sanitizeRequest,
  AlertController.createAlertFromLog
);

router.post('/alerts/batch',
  authorize(PERMISSIONS.MANAGE_ALERTS),
  batchCreateAlertsValidation,
  validateRequest,
  sanitizeRequest,
  AlertController.batchCreateAlerts
);

router.post('/alerts/generate',
  authorize(PERMISSIONS.MANAGE_ALERTS),
  generateAlertValidation,
  validateRequest,
  sanitizeRequest,
  AlertController.generateAlertFromLog
);

router.post('/alerts/batch-generate',
  authorize(PERMISSIONS.MANAGE_ALERTS),
  batchGenerateValidation,
  validateRequest,
  sanitizeRequest,
  AlertController.batchGenerateAlerts
);

router.put('/alerts/:id',
  authorize(PERMISSIONS.MANAGE_ALERTS),
  alertIdValidation,
  validateRequest,
  sanitizeRequest,
  AlertController.updateAlert
);

router.post('/alerts/:id/assign',
  authorize(PERMISSIONS.MANAGE_ALERTS),
  assignAlertValidation,
  validateRequest,
  sanitizeRequest,
  AlertController.assignAlert
);

router.patch('/alerts/:id/status',
  authorize(PERMISSIONS.MANAGE_ALERTS),
  updateStatusValidation,
  validateRequest,
  sanitizeRequest,
  AlertController.updateAlertStatus
);

router.post('/alerts/:id/note',
  authorize(PERMISSIONS.MANAGE_ALERTS),
  addNoteValidation,
  validateRequest,
  sanitizeRequest,
  AlertController.addNote
);

router.post('/alerts/:id/escalate',
  authorize(PERMISSIONS.MANAGE_ALERTS),
  escalateAlertValidation,
  validateRequest,
  sanitizeRequest,
  AlertController.escalateAlert
);

router.post('/alerts/:id/resolve',
  authorize(PERMISSIONS.MANAGE_ALERTS),
  resolveAlertValidation,
  validateRequest,
  sanitizeRequest,
  AlertController.resolveAlert
);

router.delete('/alerts/:id',
  authorize(PERMISSIONS.MANAGE_ALERTS),
  alertIdValidation,
  validateRequest,
  AlertController.deleteAlert
);

console.log(' Alert routes configured');

module.exports = router;