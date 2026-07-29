const express = require('express');
const router = express.Router();
const IOCController = require('../controllers/iocController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS } = require('../config/constants');

console.log('🔧 Setting up IOC routes...');

// Validation rules
const createIOCValidation = [
  body('organization')
    .isMongoId()
    .withMessage('Invalid organization ID'),
  body('type')
    .isIn(['ip', 'domain', 'url', 'email', 'file_hash', 'file_path',
           'registry_key', 'process', 'service', 'user_agent',
           'cve', 'campaign', 'exploit', 'signature', 'pattern'])
    .withMessage('Invalid IOC type'),
  body('value')
    .isLength({ min: 1, max: 500 })
    .withMessage('Value must be between 1 and 500 characters')
    .trim(),
  body('indicator')
    .optional()
    .isLength({ min: 1, max: 500 })
    .withMessage('Indicator must be between 1 and 500 characters')
    .trim(),
  body('description')
    .optional()
    .isLength({ max: 1000 })
    .withMessage('Description cannot exceed 1000 characters')
    .trim(),
  body('severity')
    .optional()
    .isIn(['critical', 'high', 'medium', 'low', 'info'])
    .withMessage('Invalid severity'),
  body('confidence')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Confidence must be between 0 and 100'),
  body('source')
    .optional()
    .isIn(['internal', 'external', 'threat_intelligence', 'community', 'automated', 'manual'])
    .withMessage('Invalid source'),
  body('threatType')
    .optional()
    .isIn(['malware', 'ransomware', 'phishing', 'spam', 'botnet', 'trojan',
           'worm', 'virus', 'adware', 'spyware', 'rootkit', 'backdoor',
           'exploit', 'vulnerability', 'apt', 'scanner', 'c2', 'proxy'])
    .withMessage('Invalid threat type'),
  body('status')
    .optional()
    .isIn(['active', 'inactive', 'investigating', 'false_positive', 'archived'])
    .withMessage('Invalid status'),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array'),
  body('expiresAt')
    .optional()
    .isISO8601()
    .withMessage('Invalid date format')
    .toDate()
];

const bulkCreateValidation = [
  body()
    .isArray()
    .withMessage('Request body must be an array of IOCs')
    .custom((iocs) => {
      if (iocs.length === 0) {
        throw new Error('At least one IOC is required');
      }
      return true;
    })
];

const iocIdValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid IOC ID')
];

const linkIncidentValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid IOC ID'),
  body('incidentId')
    .isMongoId()
    .withMessage('Invalid incident ID')
];

const linkAlertValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid IOC ID'),
  body('alertId')
    .isMongoId()
    .withMessage('Invalid alert ID')
];

const linkIOCsToIncidentValidation = [
  body('iocIds')
    .isArray()
    .withMessage('iocIds must be an array')
    .custom((iocIds) => {
      if (iocIds.length === 0) {
        throw new Error('At least one IOC ID is required');
      }
      return true;
    }),
  body('incidentId')
    .isMongoId()
    .withMessage('Invalid incident ID')
];

const searchValidation = [
  query('query')
    .isLength({ min: 1 })
    .withMessage('Search query is required')
    .trim()
];

const checkMatchesValidation = [
  body('value')
    .isLength({ min: 1 })
    .withMessage('Value is required')
    .trim(),
  body('organizationId')
    .optional()
    .isMongoId()
    .withMessage('Invalid organization ID')
];

const importValidation = [
  body('feedData')
    .isArray()
    .withMessage('feedData must be an array')
    .custom((feedData) => {
      if (feedData.length === 0) {
        throw new Error('At least one feed item is required');
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
router.get('/iocs/types', IOCController.getIOCTypes);
router.get('/iocs/statuses', IOCController.getIOCStatuses);
router.get('/iocs/sources', IOCController.getIOCSources);
router.get('/iocs/threat-types', IOCController.getThreatTypes);
router.get('/iocs/severities', IOCController.getSeverityLevels);
router.get('/iocs/active', IOCController.getActiveIOCs);

// IOC management routes
router.get('/iocs/statistics',
  IOCController.getIOCStatistics
);

router.get('/iocs/search',
  searchValidation,
  validateRequest,
  IOCController.searchIOCs
);

router.get('/iocs/export',
  IOCController.exportIOCs
);

router.get('/iocs/find',
  query('type').isIn(['ip', 'domain', 'url', 'email', 'file_hash', 'file_path',
                       'registry_key', 'process', 'service', 'user_agent',
                       'cve', 'campaign', 'exploit', 'signature', 'pattern'])
    .withMessage('Invalid IOC type'),
  query('value').isLength({ min: 1 }).withMessage('Value is required'),
  validateRequest,
  IOCController.findIOCByValue
);

router.get('/iocs/incident/:incidentId',
  param('incidentId').isMongoId().withMessage('Invalid incident ID'),
  validateRequest,
  IOCController.getIOCsByIncident
);

router.get('/iocs/organization/:organizationId',
  param('organizationId').isMongoId().withMessage('Invalid organization ID'),
  validateRequest,
  IOCController.getIOCsByOrganization
);

router.get('/iocs/:id',
  iocIdValidation,
  validateRequest,
  IOCController.getIOCById
);

router.get('/iocs',
  IOCController.getIOCs
);

// Admin only routes
router.post('/iocs',
  authorize(PERMISSIONS.MANAGE_IOCS),
  createIOCValidation,
  validateRequest,
  sanitizeRequest,
  IOCController.createIOC
);

router.post('/iocs/bulk',
  authorize(PERMISSIONS.MANAGE_IOCS),
  bulkCreateValidation,
  validateRequest,
  sanitizeRequest,
  IOCController.bulkCreateIOCs
);

router.post('/iocs/import',
  authorize(PERMISSIONS.MANAGE_IOCS),
  importValidation,
  validateRequest,
  sanitizeRequest,
  IOCController.importFromFeed
);

router.put('/iocs/:id',
  authorize(PERMISSIONS.MANAGE_IOCS),
  iocIdValidation,
  validateRequest,
  sanitizeRequest,
  IOCController.updateIOC
);

router.delete('/iocs/:id',
  authorize(PERMISSIONS.MANAGE_IOCS),
  iocIdValidation,
  validateRequest,
  IOCController.deleteIOC
);

router.post('/iocs/:id/occurrence',
  authorize(PERMISSIONS.MANAGE_IOCS),
  iocIdValidation,
  validateRequest,
  sanitizeRequest,
  IOCController.recordOccurrence
);

router.post('/iocs/:id/link-incident',
  authorize(PERMISSIONS.MANAGE_IOCS),
  linkIncidentValidation,
  validateRequest,
  sanitizeRequest,
  IOCController.linkToIncident
);

router.post('/iocs/:id/link-alert',
  authorize(PERMISSIONS.MANAGE_IOCS),
  linkAlertValidation,
  validateRequest,
  sanitizeRequest,
  IOCController.linkToAlert
);

router.post('/iocs/link-to-incident',
  authorize(PERMISSIONS.MANAGE_IOCS),
  linkIOCsToIncidentValidation,
  validateRequest,
  sanitizeRequest,
  IOCController.linkIOCsToIncident
);

router.post('/iocs/check-matches',
  authorize(PERMISSIONS.MANAGE_IOCS),
  checkMatchesValidation,
  validateRequest,
  sanitizeRequest,
  IOCController.checkMatches
);

router.post('/iocs/:id/expire',
  authorize(PERMISSIONS.MANAGE_IOCS),
  iocIdValidation,
  validateRequest,
  IOCController.expireIOC
);

router.post('/iocs/:id/reactivate',
  authorize(PERMISSIONS.MANAGE_IOCS),
  iocIdValidation,
  validateRequest,
  IOCController.reactivateIOC
);

console.log('✅ IOC routes configured');

module.exports = router;