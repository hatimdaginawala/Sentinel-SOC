const express = require('express');
const router = express.Router();
const ThreatRuleController = require('../controllers/threatRuleController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS, SEVERITY, RULE_TYPES } = require('../config/constants');

console.log('🔧 Setting up threat rule routes...');

// Validation rules
const createRuleValidation = [
  body('organization')
    .isMongoId()
    .withMessage('Invalid organization ID'),
  body('name')
    .isLength({ min: 3, max: 100 })
    .withMessage('Rule name must be between 3 and 100 characters')
    .trim(),
  body('description')
    .isLength({ min: 3, max: 500 })
    .withMessage('Description must be between 3 and 500 characters')
    .trim(),
  body('type')
    .isIn(Object.values(RULE_TYPES))
    .withMessage(`Type must be one of: ${Object.values(RULE_TYPES).join(', ')}`),
  body('severity')
    .isIn(Object.values(SEVERITY))
    .withMessage(`Severity must be one of: ${Object.values(SEVERITY).join(', ')}`),
  body('category')
    .isIn(['authentication', 'network', 'system', 'application', 'database', 'web', 'malware', 'policy', 'access', 'error', 'ids', 'firewall'])
    .withMessage('Invalid category'),
  body('threatType')
    .optional()
    .isIn(['brute_force', 'sql_injection', 'xss', 'command_injection', 'rce',
           'reverse_shell', 'port_scan', 'malware_communication', 'dns_tunneling',
           'data_exfiltration', 'dos_attack', 'privilege_escalation',
           'suspicious_powershell', 'unauthorized_access', 'beaconing',
           'ddos', 'malware', 'phishing', 'ransomware'])
    .withMessage('Invalid threat type'),
  body('condition')
    .isObject()
    .withMessage('Condition must be an object'),
  body('actions')
    .optional()
    .isArray()
    .withMessage('Actions must be an array'),
  body('enabled')
    .optional()
    .isBoolean()
    .withMessage('Enabled must be a boolean'),
  body('priority')
    .optional()
    .isInt({ min: 1, max: 10 })
    .withMessage('Priority must be between 1 and 10'),
  body('cooldown')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Cooldown must be a positive integer'),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array'),
  body('references')
    .optional()
    .isArray()
    .withMessage('References must be an array')
];

const updateRuleValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid rule ID'),
  body('name')
    .optional()
    .isLength({ min: 3, max: 100 })
    .withMessage('Rule name must be between 3 and 100 characters')
    .trim(),
  body('description')
    .optional()
    .isLength({ min: 3, max: 500 })
    .withMessage('Description must be between 3 and 500 characters')
    .trim(),
  body('type')
    .optional()
    .isIn(Object.values(RULE_TYPES))
    .withMessage(`Type must be one of: ${Object.values(RULE_TYPES).join(', ')}`),
  body('severity')
    .optional()
    .isIn(Object.values(SEVERITY))
    .withMessage(`Severity must be one of: ${Object.values(SEVERITY).join(', ')}`),
  body('category')
    .optional()
    .isIn(['authentication', 'network', 'system', 'application', 'database', 'web', 'malware', 'policy', 'access', 'error', 'ids', 'firewall'])
    .withMessage('Invalid category'),
  body('condition')
    .optional()
    .isObject()
    .withMessage('Condition must be an object'),
  body('actions')
    .optional()
    .isArray()
    .withMessage('Actions must be an array'),
  body('enabled')
    .optional()
    .isBoolean()
    .withMessage('Enabled must be a boolean'),
  body('priority')
    .optional()
    .isInt({ min: 1, max: 10 })
    .withMessage('Priority must be between 1 and 10'),
  body('cooldown')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Cooldown must be a positive integer')
];

const ruleIdValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid rule ID')
];

const toggleValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid rule ID'),
  body('enabled')
    .isBoolean()
    .withMessage('Enabled must be a boolean')
];

const cloneValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid rule ID'),
  body('name')
    .optional()
    .isLength({ min: 3, max: 100 })
    .withMessage('Rule name must be between 3 and 100 characters')
    .trim()
];

const searchValidation = [
  query('query')
    .isLength({ min: 1 })
    .withMessage('Search query is required')
    .trim()
];

const validateConditionValidation = [
  body('condition')
    .isObject()
    .withMessage('Condition must be an object')
];

const processLogValidation = [
  body('log')
    .isObject()
    .withMessage('Log must be an object'),
  body('organizationId')
    .optional()
    .isMongoId()
    .withMessage('Invalid organization ID')
];

const importValidation = [
  body('rules')
    .isArray()
    .withMessage('Rules must be an array')
    .custom((rules) => {
      if (rules.length === 0) {
        throw new Error('At least one rule is required');
      }
      return true;
    }),
  body('organizationId')
    .isMongoId()
    .withMessage('Invalid organization ID')
];

// All routes require authentication
router.use(protect);

// Public (authenticated) routes
router.get('/threat-rules/types', ThreatRuleController.getRuleTypes);
router.get('/threat-rules/categories', ThreatRuleController.getCategories);
router.get('/threat-rules/threat-types', ThreatRuleController.getThreatTypes);
router.get('/threat-rules/action-types', ThreatRuleController.getActionTypes);
router.get('/threat-rules/mitre-tactics', ThreatRuleController.getMitreTactics);
router.get('/threat-rules/enabled', ThreatRuleController.getEnabledRules);

// Rule management routes
router.get('/threat-rules/statistics',
  ThreatRuleController.getRuleStatistics
);

router.get('/threat-rules/search',
  searchValidation,
  validateRequest,
  ThreatRuleController.searchRules
);

router.get('/threat-rules/export',
  ThreatRuleController.exportRules
);

router.get('/threat-rules/threat-type/:threatType',
  param('threatType').isIn(['brute_force', 'sql_injection', 'xss', 'command_injection', 'rce',
                             'reverse_shell', 'port_scan', 'malware_communication', 'dns_tunneling',
                             'data_exfiltration', 'dos_attack', 'privilege_escalation',
                             'suspicious_powershell', 'unauthorized_access', 'beaconing',
                             'ddos', 'malware', 'phishing', 'ransomware'])
    .withMessage('Invalid threat type'),
  validateRequest,
  ThreatRuleController.getRulesByThreatType
);

router.get('/threat-rules/category/:category',
  param('category').isIn(['authentication', 'network', 'system', 'application', 'database', 'web', 'malware', 'policy', 'access', 'error', 'ids', 'firewall'])
    .withMessage('Invalid category'),
  validateRequest,
  ThreatRuleController.getRulesByCategory
);

router.get('/threat-rules/:id',
  ruleIdValidation,
  validateRequest,
  ThreatRuleController.getRuleById
);

router.get('/threat-rules',
  ThreatRuleController.getRules
);

// Admin only routes
router.post('/threat-rules',
  authorize(PERMISSIONS.MANAGE_THREAT_RULES),
  createRuleValidation,
  validateRequest,
  sanitizeRequest,
  ThreatRuleController.createRule
);

router.post('/threat-rules/import',
  authorize(PERMISSIONS.MANAGE_THREAT_RULES),
  importValidation,
  validateRequest,
  sanitizeRequest,
  ThreatRuleController.bulkImportRules
);

router.post('/threat-rules/validate-condition',
  authorize(PERMISSIONS.MANAGE_THREAT_RULES),
  validateConditionValidation,
  validateRequest,
  ThreatRuleController.validateCondition
);

router.post('/threat-rules/process-log',
  authorize(PERMISSIONS.MANAGE_THREAT_RULES),
  processLogValidation,
  validateRequest,
  sanitizeRequest,
  ThreatRuleController.processLogAgainstRules
);

router.put('/threat-rules/:id',
  authorize(PERMISSIONS.MANAGE_THREAT_RULES),
  updateRuleValidation,
  validateRequest,
  sanitizeRequest,
  ThreatRuleController.updateRule
);

router.delete('/threat-rules/:id',
  authorize(PERMISSIONS.MANAGE_THREAT_RULES),
  ruleIdValidation,
  validateRequest,
  ThreatRuleController.deleteRule
);

router.patch('/threat-rules/:id/toggle',
  authorize(PERMISSIONS.MANAGE_THREAT_RULES),
  toggleValidation,
  validateRequest,
  sanitizeRequest,
  ThreatRuleController.toggleRule
);

router.post('/threat-rules/:id/clone',
  authorize(PERMISSIONS.MANAGE_THREAT_RULES),
  cloneValidation,
  validateRequest,
  sanitizeRequest,
  ThreatRuleController.cloneRule
);

console.log('✅ Threat rule routes configured');

module.exports = router;