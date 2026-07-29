const express = require('express');
const router = express.Router();
const LogSourceController = require('../controllers/logSourceController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS } = require('../config/constants');

console.log('🔧 Setting up log source routes...');

// Validation rules
const createLogSourceValidation = [
  body('organization')
    .isMongoId()
    .withMessage('Invalid organization ID'),
  body('asset')
    .isMongoId()
    .withMessage('Invalid asset ID'),
  body('sourceName')
    .isLength({ min: 2, max: 100 })
    .withMessage('Source name must be between 2 and 100 characters')
    .trim(),
  body('sourceType')
    .isIn(['Windows', 'Linux', 'Apache', 'Nginx', 'IIS', 'pfSense', 'Suricata', 'Snort', 'Zeek', 'Node Application', 'Custom'])
    .withMessage('Invalid source type'),
  body('hostname')
    .optional()
    .isLength({ max: 255 })
    .withMessage('Hostname cannot exceed 255 characters')
    .trim(),
  body('ipAddress')
    .optional()
    .isIP()
    .withMessage('Invalid IP address')
    .trim(),
  body('operatingSystem')
    .optional()
    .trim(),
  body('status')
    .optional()
    .isIn(['Online', 'Offline', 'Pending', 'Error'])
    .withMessage('Invalid status'),
  body('protocol')
    .optional()
    .isIn(['REST', 'Syslog', 'Agent'])
    .withMessage('Invalid protocol'),
  body('description')
    .optional()
    .trim(),
  body('metadata')
    .optional()
    .isObject()
    .withMessage('Metadata must be an object'),
  body('configuration')
    .optional()
    .isObject()
    .withMessage('Configuration must be an object'),
  body('configuration.logLevel')
    .optional()
    .isIn(['debug', 'info', 'warning', 'error'])
    .withMessage('Invalid log level'),
  body('configuration.batchSize')
    .optional()
    .isInt({ min: 1, max: 10000 })
    .withMessage('Batch size must be between 1 and 10000'),
  body('configuration.flushInterval')
    .optional()
    .isInt({ min: 1, max: 3600 })
    .withMessage('Flush interval must be between 1 and 3600 seconds'),
  body('configuration.enabled')
    .optional()
    .isBoolean()
    .withMessage('Enabled must be a boolean')
];

const updateLogSourceValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid log source ID'),
  body('sourceName')
    .optional()
    .isLength({ min: 2, max: 100 })
    .withMessage('Source name must be between 2 and 100 characters')
    .trim(),
  body('sourceType')
    .optional()
    .isIn(['Windows', 'Linux', 'Apache', 'Nginx', 'IIS', 'pfSense', 'Suricata', 'Snort', 'Zeek', 'Node Application', 'Custom'])
    .withMessage('Invalid source type'),
  body('hostname')
    .optional()
    .isLength({ max: 255 })
    .withMessage('Hostname cannot exceed 255 characters')
    .trim(),
  body('ipAddress')
    .optional()
    .isIP()
    .withMessage('Invalid IP address')
    .trim(),
  body('operatingSystem')
    .optional()
    .trim(),
  body('status')
    .optional()
    .isIn(['Online', 'Offline', 'Pending', 'Error'])
    .withMessage('Invalid status'),
  body('protocol')
    .optional()
    .isIn(['REST', 'Syslog', 'Agent'])
    .withMessage('Invalid protocol'),
  body('description')
    .optional()
    .trim(),
  body('metadata')
    .optional()
    .isObject()
    .withMessage('Metadata must be an object'),
  body('configuration')
    .optional()
    .isObject()
    .withMessage('Configuration must be an object')
];

const logSourceIdValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid log source ID')
];

const organizationIdValidation = [
  param('organizationId')
    .isMongoId()
    .withMessage('Invalid organization ID')
];

const statusUpdateValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid log source ID'),
  body('status')
    .isIn(['Online', 'Offline', 'Pending', 'Error'])
    .withMessage('Invalid status')
];

const searchValidation = [
  query('query')
    .isLength({ min: 1 })
    .withMessage('Search query is required')
    .trim()
];

// All routes require authentication
router.use(protect);

// Public (authenticated) routes - available to all authenticated users
router.get('/log-sources/types', LogSourceController.getSourceTypes);
router.get('/log-sources/protocols', LogSourceController.getProtocols);
router.get('/log-sources/statuses', LogSourceController.getStatuses);
router.get('/log-sources/online', LogSourceController.getOnlineSources);

// Log source management routes
router.get('/log-sources/search',
  searchValidation,
  validateRequest,
  LogSourceController.searchLogSources
);

router.get('/log-sources/statistics',
  LogSourceController.getLogSourceStatistics
);

router.get('/log-sources/organization/:organizationId',
  authorize(PERMISSIONS.VIEW_ASSETS),
  organizationIdValidation,
  validateRequest,
  LogSourceController.getLogSourcesByOrganization
);

router.get('/log-sources/:id',
  authorize(PERMISSIONS.VIEW_ASSETS),
  logSourceIdValidation,
  validateRequest,
  LogSourceController.getLogSourceById
);

// Admin only routes
router.post('/log-sources',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  createLogSourceValidation,
  validateRequest,
  sanitizeRequest,
  LogSourceController.createLogSource
);

router.get('/log-sources',
  authorize(PERMISSIONS.VIEW_ASSETS),
  LogSourceController.getAllLogSources
);

router.put('/log-sources/:id',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  updateLogSourceValidation,
  validateRequest,
  sanitizeRequest,
  LogSourceController.updateLogSource
);

router.patch('/log-sources/:id/status',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  statusUpdateValidation,
  validateRequest,
  sanitizeRequest,
  LogSourceController.updateStatus
);

router.patch('/log-sources/:id/heartbeat',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  logSourceIdValidation,
  validateRequest,
  LogSourceController.updateHeartbeat
);

router.post('/log-sources/:id/regenerate-token',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  logSourceIdValidation,
  validateRequest,
  LogSourceController.regenerateToken
);

router.delete('/log-sources/:id',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  logSourceIdValidation,
  validateRequest,
  LogSourceController.deleteLogSource
);

router.delete('/log-sources/:id/permanent',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  logSourceIdValidation,
  validateRequest,
  LogSourceController.hardDeleteLogSource
);

router.post('/log-sources/check-heartbeats',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  LogSourceController.checkStaleHeartbeats
);

console.log('✅ Log source routes configured');

module.exports = router;