const express = require('express');
const router = express.Router();
const IncidentController = require('../controllers/incidentController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS, SEVERITY, INCIDENT_STATUS } = require('../config/constants');

console.log(' Setting up incident routes...');

// Validation rules
const createIncidentValidation = [
  body('organization')
    .isMongoId()
    .withMessage('Invalid organization ID'),
  body('title')
    .isLength({ min: 3, max: 200 })
    .withMessage('Title must be between 3 and 200 characters')
    .trim(),
  body('description')
    .isLength({ min: 3, max: 1000 })
    .withMessage('Description must be between 3 and 1000 characters')
    .trim(),
  body('severity')
    .isIn(Object.values(SEVERITY))
    .withMessage(`Severity must be one of: ${Object.values(SEVERITY).join(', ')}`),
  body('category')
    .isIn(['malware', 'ransomware', 'phishing', 'data_breach', 'dos', 'insider_threat',
           'unauthorized_access', 'system_compromise', 'data_loss', 'policy_violation',
           'network_intrusion', 'web_attack', 'physical_security', 'other'])
    .withMessage('Invalid category'),
  body('alerts')
    .optional()
    .isArray()
    .withMessage('Alerts must be an array'),
  body('assignedTo')
    .optional()
    .isMongoId()
    .withMessage('Invalid user ID'),
  body('detectionSource')
    .optional()
    .isIn(['automated', 'manual', 'external', 'user_report'])
    .withMessage('Invalid detection source'),
  body('discoveredAt')
    .optional()
    .isISO8601()
    .withMessage('Invalid date format')
    .toDate()
];

const createFromAlertsValidation = [
  body('alertIds')
    .isArray()
    .withMessage('alertIds must be an array')
    .custom((alertIds) => {
      if (alertIds.length === 0) {
        throw new Error('At least one alert ID is required');
      }
      return true;
    }),
  body('incidentData')
    .optional()
    .isObject()
    .withMessage('Incident data must be an object')
];

const incidentIdValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid incident ID')
];

const assignIncidentValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid incident ID'),
  body('userId')
    .isMongoId()
    .withMessage('Invalid user ID')
];

const updateStatusValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid incident ID'),
  body('status')
    .isIn(Object.values(INCIDENT_STATUS))
    .withMessage(`Status must be one of: ${Object.values(INCIDENT_STATUS).join(', ')}`),
  body('note')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Note cannot exceed 500 characters')
];

const timelineValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid incident ID'),
  body('action')
    .isIn(['created', 'assigned', 'investigating', 'in_progress', 'escalated', 
           'resolved', 'closed', 'reopened', 'commented', 'evidence_added', 
           'status_changed', 'severity_changed'])
    .withMessage('Invalid action'),
  body('note')
    .isLength({ min: 3, max: 500 })
    .withMessage('Note must be between 3 and 500 characters'),
  body('metadata')
    .optional()
    .isObject()
    .withMessage('Metadata must be an object')
];

const evidenceValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid incident ID'),
  body('type')
    .isIn(['log', 'alert', 'file', 'screenshot', 'network_pcap', 'memory_dump',
           'disk_image', 'email', 'link', 'note', 'other'])
    .withMessage('Invalid evidence type'),
  body('title')
    .isLength({ min: 3, max: 100 })
    .withMessage('Title must be between 3 and 100 characters')
    .trim(),
  body('description')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Description cannot exceed 500 characters'),
  body('reference')
    .optional()
    .trim(),
  body('fileUrl')
    .optional()
    .isURL()
    .withMessage('Invalid file URL'),
  body('hash')
    .optional()
    .isLength({ min: 32, max: 128 })
    .withMessage('Invalid hash format')
];

const affectedAssetValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid incident ID'),
  body('assetId')
    .isMongoId()
    .withMessage('Invalid asset ID'),
  body('impact')
    .optional()
    .isIn(['compromised', 'affected', 'investigating', 'cleared'])
    .withMessage('Invalid impact status'),
  body('notes')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Notes cannot exceed 500 characters')
];

const containmentValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid incident ID'),
  body('measure')
    .isLength({ min: 3, max: 500 })
    .withMessage('Measure must be between 3 and 500 characters'),
  body('effectiveness')
    .optional()
    .isIn(['effective', 'partially_effective', 'ineffective'])
    .withMessage('Invalid effectiveness level')
];

const escalateIncidentValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid incident ID'),
  body('escalateTo')
    .isMongoId()
    .withMessage('Invalid user ID'),
  body('reason')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Reason cannot exceed 500 characters')
];

const resolveIncidentValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid incident ID'),
  body('resolutionStatus')
    .isIn(['mitigated', 'contained', 'eradicated', 'recovered', 'accepted', 'false_positive'])
    .withMessage('Invalid resolution status'),
  body('summary')
    .optional()
    .isLength({ max: 1000 })
    .withMessage('Summary cannot exceed 1000 characters'),
  body('steps')
    .optional()
    .isArray()
    .withMessage('Steps must be an array'),
  body('lessonsLearned')
    .optional()
    .isLength({ max: 1000 })
    .withMessage('Lessons learned cannot exceed 1000 characters')
];

const closeIncidentValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid incident ID'),
  body('note')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Note cannot exceed 500 characters')
];

const reopenIncidentValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid incident ID'),
  body('reason')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Reason cannot exceed 500 characters')
];

const searchValidation = [
  query('query')
    .isLength({ min: 1 })
    .withMessage('Search query is required')
    .trim()
];

const dateRangeValidation = [
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Invalid start date format'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('Invalid end date format')
];

// All routes require authentication
router.use(protect);

// Public (authenticated) routes
router.get('/incidents/categories', IncidentController.getIncidentCategories);
router.get('/incidents/resolution-statuses', IncidentController.getResolutionStatuses);
router.get('/incidents/detection-sources', IncidentController.getDetectionSources);
router.get('/incidents/containment-effectiveness', IncidentController.getContainmentEffectiveness);
router.get('/incidents/severities', IncidentController.getSeverityLevels);
router.get('/incidents/statuses', IncidentController.getIncidentStatuses);
router.get('/incidents/assigned-to-me', IncidentController.getIncidentsAssignedToMe);
router.get('/incidents/open-count', IncidentController.getOpenIncidentsCount);

// Incident management routes
router.get('/incidents/statistics',
  IncidentController.getIncidentStatistics
);

router.get('/incidents/search',
  searchValidation,
  validateRequest,
  IncidentController.searchIncidents
);

router.get('/incidents/date-range',
  dateRangeValidation,
  validateRequest,
  IncidentController.getIncidentsByDateRange
);

router.get('/incidents',
  IncidentController.getIncidents
);

router.get('/incidents/organization/:organizationId',
  param('organizationId').isMongoId().withMessage('Invalid organization ID'),
  validateRequest,
  IncidentController.getIncidentsByOrganization
);

router.get('/incidents/:id',
  incidentIdValidation,
  validateRequest,
  IncidentController.getIncidentById
);

// Admin only routes
router.post('/incidents',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  createIncidentValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.createIncident
);

router.post('/incidents/from-alerts',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  createFromAlertsValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.createIncidentFromAlerts
);

router.put('/incidents/:id',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  incidentIdValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.updateIncident
);

router.post('/incidents/:id/assign',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  assignIncidentValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.assignIncident
);

router.patch('/incidents/:id/status',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  updateStatusValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.updateIncidentStatus
);

router.post('/incidents/:id/timeline',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  timelineValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.addTimeline
);

router.post('/incidents/:id/evidence',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  evidenceValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.addEvidence
);

router.post('/incidents/:id/affected-asset',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  affectedAssetValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.addAffectedAsset
);

router.post('/incidents/:id/containment',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  containmentValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.addContainmentMeasure
);

router.post('/incidents/:id/escalate',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  escalateIncidentValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.escalateIncident
);

router.post('/incidents/:id/resolve',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  resolveIncidentValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.resolveIncident
);

router.post('/incidents/:id/close',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  closeIncidentValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.closeIncident
);

router.post('/incidents/:id/reopen',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  reopenIncidentValidation,
  validateRequest,
  sanitizeRequest,
  IncidentController.reopenIncident
);

router.delete('/incidents/:id',
  authorize(PERMISSIONS.MANAGE_INCIDENTS),
  incidentIdValidation,
  validateRequest,
  IncidentController.deleteIncident
);

console.log(' Incident routes configured');

module.exports = router;