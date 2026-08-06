const express = require('express');
const router = express.Router();
const LogController = require('../controllers/logController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS } = require('../config/constants');

console.log(' Setting up log routes...');

// ============================================
// PUBLIC ROUTES - DEFINED FIRST (BEFORE protect)
// ============================================

console.log(' Registering PUBLIC routes...');

// Public test route
router.get('/logs/public-test', (req, res) => {
  res.json({ 
    success: true, 
    message: 'This endpoint is public!',
    timestamp: new Date().toISOString()
  });
});

// Public ingestion endpoint
router.post('/logs/ingest',
  [
    body('sourceId').isMongoId().withMessage('Invalid log source ID'),
    body('authToken').isLength({ min: 1 }).withMessage('Authentication token is required'),
    body('log').isObject().withMessage('Log data must be an object')
  ],
  validateRequest,
  sanitizeRequest,
  LogController.ingestLog
);

console.log(' Public routes registered:');
console.log('   GET  /logs/public-test');
console.log('   POST /logs/ingest');

// ============================================
// PROTECTED ROUTES - DEFINED AFTER protect
// ============================================

console.log('Setting up protected routes...');
router.use(protect);

// Validation rules
const getLogsValidation = [
  query('organization')
    .optional()
    .isMongoId()
    .withMessage('Invalid organization ID'),
  query('asset')
    .optional()
    .isMongoId()
    .withMessage('Invalid asset ID'),
  query('logSource')
    .optional()
    .isMongoId()
    .withMessage('Invalid log source ID'),
  query('eventCategory')
    .optional()
    .isIn(['authentication', 'network', 'system', 'application', 'database', 'web', 'malware', 'policy', 'access', 'error'])
    .withMessage('Invalid event category'),
  query('severity')
    .optional()
    .isIn(['critical', 'high', 'medium', 'low', 'info'])
    .withMessage('Invalid severity'),
  query('status')
    .optional()
    .isIn(['processed', 'failed', 'pending'])
    .withMessage('Invalid status'),
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Invalid start date format'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('Invalid end date format'),
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('sourceIP')
    .optional()
    .isIP()
    .withMessage('Invalid source IP address')
    .trim(),
  query('destinationIP')
    .optional()
    .isIP()
    .withMessage('Invalid destination IP address')
    .trim(),
  query('username')
    .optional()
    .trim()
];

const logIdValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid log ID')
];

const organizationIdValidation = [
  param('organizationId')
    .isMongoId()
    .withMessage('Invalid organization ID')
];

const logSourceIdValidation = [
  param('logSourceId')
    .isMongoId()
    .withMessage('Invalid log source ID')
];

const cleanupValidation = [
  body('retentionDays')
    .optional()
    .isInt({ min: 1, max: 365 })
    .withMessage('Retention days must be between 1 and 365')
];

// Protected routes
router.get('/logs/categories', LogController.getEventCategories);
router.get('/logs/severities', LogController.getSeverities);
router.get('/logs/statuses', LogController.getStatuses);
router.get('/logs/statistics', LogController.getLogStatistics);
router.get('/logs',
  getLogsValidation,
  validateRequest,
  LogController.getLogs
);
router.get('/logs/:id',
  logIdValidation,
  validateRequest,
  LogController.getLogById
);
router.get('/logs/organization/:organizationId',
  authorize(PERMISSIONS.VIEW_LOGS),
  organizationIdValidation,
  validateRequest,
  LogController.getLogsByOrganization
);
router.get('/logs/source/:logSourceId',
  authorize(PERMISSIONS.VIEW_LOGS),
  logSourceIdValidation,
  validateRequest,
  LogController.getLogsByLogSource
);

// Admin only routes
router.delete('/logs/:id',
  authorize(PERMISSIONS.MANAGE_LOGS),
  logIdValidation,
  validateRequest,
  LogController.deleteLog
);
router.post('/logs/cleanup',
  authorize(PERMISSIONS.MANAGE_LOGS),
  cleanupValidation,
  validateRequest,
  sanitizeRequest,
  LogController.deleteOldLogs
);

console.log(' Log routes configured');

module.exports = router;