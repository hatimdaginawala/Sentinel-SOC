const express = require('express');
const router = express.Router();
const SettingsController = require('../controllers/settingsController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS } = require('../config/constants');

console.log('🔧 Setting up settings routes...');

// Validation rules
const updateSettingsValidation = [
  body('general')
    .optional()
    .isObject()
    .withMessage('General settings must be an object'),
  body('security')
    .optional()
    .isObject()
    .withMessage('Security settings must be an object'),
  body('notifications')
    .optional()
    .isObject()
    .withMessage('Notification settings must be an object'),
  body('retention')
    .optional()
    .isObject()
    .withMessage('Retention settings must be an object'),
  body('detection')
    .optional()
    .isObject()
    .withMessage('Detection settings must be an object'),
  body('dashboard')
    .optional()
    .isObject()
    .withMessage('Dashboard settings must be an object'),
  body('logging')
    .optional()
    .isObject()
    .withMessage('Logging settings must be an object')
];

const updateSettingValidation = [
  param('path')
    .isLength({ min: 1 })
    .withMessage('Setting path is required')
    .trim(),
  body('value')
    .exists()
    .withMessage('Value is required')
];

const getSettingValidation = [
  param('path')
    .isLength({ min: 1 })
    .withMessage('Setting path is required')
    .trim()
];

const updateSecurityValidation = [
  body('passwordPolicy')
    .optional()
    .isObject()
    .withMessage('Password policy must be an object'),
  body('session')
    .optional()
    .isObject()
    .withMessage('Session settings must be an object'),
  body('api')
    .optional()
    .isObject()
    .withMessage('API settings must be an object'),
  body('ipWhitelist')
    .optional()
    .isArray()
    .withMessage('IP whitelist must be an array'),
  body('ipBlacklist')
    .optional()
    .isArray()
    .withMessage('IP blacklist must be an array'),
  body('cors')
    .optional()
    .isObject()
    .withMessage('CORS settings must be an object')
];

const updateNotificationValidation = [
  body('email')
    .optional()
    .isObject()
    .withMessage('Email settings must be an object'),
  body('slack')
    .optional()
    .isObject()
    .withMessage('Slack settings must be an object'),
  body('teams')
    .optional()
    .isObject()
    .withMessage('Teams settings must be an object'),
  body('webhooks')
    .optional()
    .isArray()
    .withMessage('Webhooks must be an array')
];

const updateRetentionValidation = [
  body('logs')
    .optional()
    .isObject()
    .withMessage('Log retention must be an object'),
  body('alerts')
    .optional()
    .isObject()
    .withMessage('Alert retention must be an object'),
  body('incidents')
    .optional()
    .isObject()
    .withMessage('Incident retention must be an object'),
  body('auditLogs')
    .optional()
    .isObject()
    .withMessage('Audit log retention must be an object'),
  body('reports')
    .optional()
    .isObject()
    .withMessage('Report retention must be an object')
];

const addWhitelistValidation = [
  body('ip')
    .isIP()
    .withMessage('Invalid IP address')
    .trim()
];

const removeWhitelistValidation = [
  param('ip')
    .isIP()
    .withMessage('Invalid IP address')
    .trim()
];

const addWebhookValidation = [
  body('name')
    .isLength({ min: 1, max: 100 })
    .withMessage('Webhook name must be between 1 and 100 characters')
    .trim(),
  body('url')
    .isURL()
    .withMessage('Invalid webhook URL')
    .trim(),
  body('events')
    .isArray()
    .withMessage('Events must be an array'),
  body('headers')
    .optional()
    .isObject()
    .withMessage('Headers must be an object')
];

const validateSMTPValidation = [
  body('smtpHost')
    .isLength({ min: 1 })
    .withMessage('SMTP host is required')
    .trim(),
  body('smtpPort')
    .isInt({ min: 1, max: 65535 })
    .withMessage('SMTP port must be between 1 and 65535'),
  body('smtpUser')
    .isLength({ min: 1 })
    .withMessage('SMTP user is required')
    .trim(),
  body('smtpPass')
    .isLength({ min: 1 })
    .withMessage('SMTP password is required')
    .trim()
];

const validateSlackValidation = [
  body('webhookUrl')
    .isURL()
    .withMessage('Invalid Slack webhook URL')
    .trim()
];

const updateDashboardValidation = [
  body('refreshInterval')
    .optional()
    .isInt({ min: 5, max: 300 })
    .withMessage('Refresh interval must be between 5 and 300 seconds'),
  body('defaultView')
    .optional()
    .isIn(['overview', 'alerts', 'incidents', 'assets', 'threats'])
    .withMessage('Invalid default view'),
  body('widgets')
    .optional()
    .isArray()
    .withMessage('Widgets must be an array'),
  body('customColors')
    .optional()
    .isObject()
    .withMessage('Custom colors must be an object')
];

const updateLoggingValidation = [
  body('level')
    .optional()
    .isIn(['debug', 'info', 'warning', 'error'])
    .withMessage('Invalid log level'),
  body('includeSensitiveData')
    .optional()
    .isBoolean()
    .withMessage('Include sensitive data must be a boolean'),
  body('retention')
    .optional()
    .isInt({ min: 1, max: 365 })
    .withMessage('Retention must be between 1 and 365 days')
];

const featureValidation = [
  param('featurePath')
    .isLength({ min: 1 })
    .withMessage('Feature path is required')
    .trim()
];

// All routes require authentication and CONFIGURE_SYSTEM permission
router.use(protect);
router.use(authorize(PERMISSIONS.CONFIGURE_SYSTEM));

// Settings management routes
router.get('/settings',
  SettingsController.getSettings
);

router.put('/settings',
  updateSettingsValidation,
  validateRequest,
  sanitizeRequest,
  SettingsController.updateSettings
);

router.post('/settings/reset',
  SettingsController.resetSettings
);

// Setting path operations
router.get('/settings/:path',
  getSettingValidation,
  validateRequest,
  SettingsController.getSetting
);

router.patch('/settings/:path',
  updateSettingValidation,
  validateRequest,
  sanitizeRequest,
  SettingsController.updateSetting
);

// Security settings
router.get('/settings/security',
  SettingsController.getSecuritySettings
);

router.put('/settings/security',
  updateSecurityValidation,
  validateRequest,
  sanitizeRequest,
  SettingsController.updateSecuritySettings
);

// Notification settings
router.get('/settings/notifications',
  SettingsController.getNotificationSettings
);

router.put('/settings/notifications',
  updateNotificationValidation,
  validateRequest,
  sanitizeRequest,
  SettingsController.updateNotificationSettings
);

// Retention settings
router.get('/settings/retention',
  SettingsController.getRetentionSettings
);

router.put('/settings/retention',
  updateRetentionValidation,
  validateRequest,
  sanitizeRequest,
  SettingsController.updateRetentionSettings
);

// General settings
router.get('/settings/general',
  SettingsController.getGeneralSettings
);

// Dashboard settings
router.get('/settings/dashboard',
  SettingsController.getDashboardSettings
);

router.put('/settings/dashboard',
  updateDashboardValidation,
  validateRequest,
  sanitizeRequest,
  SettingsController.updateDashboardSettings
);

// Logging settings
router.put('/settings/logging',
  updateLoggingValidation,
  validateRequest,
  sanitizeRequest,
  SettingsController.updateLoggingSettings
);

// IP Whitelist
router.post('/settings/whitelist',
  addWhitelistValidation,
  validateRequest,
  sanitizeRequest,
  SettingsController.addIPToWhitelist
);

router.delete('/settings/whitelist/:ip',
  removeWhitelistValidation,
  validateRequest,
  SettingsController.removeIPFromWhitelist
);

// Webhooks
router.post('/settings/webhooks',
  addWebhookValidation,
  validateRequest,
  sanitizeRequest,
  SettingsController.addWebhook
);

router.delete('/settings/webhooks/:webhookId',
  param('webhookId').isInt({ min: 0 }).withMessage('Invalid webhook ID'),
  validateRequest,
  SettingsController.removeWebhook
);

// Validation endpoints
router.post('/settings/validate-smtp',
  validateSMTPValidation,
  validateRequest,
  sanitizeRequest,
  SettingsController.validateSMTP
);

router.post('/settings/validate-slack',
  validateSlackValidation,
  validateRequest,
  sanitizeRequest,
  SettingsController.validateSlack
);

// Feature check
router.get('/settings/feature/:featurePath',
  featureValidation,
  validateRequest,
  SettingsController.isFeatureEnabled
);

console.log('✅ Settings routes configured');

module.exports = router;