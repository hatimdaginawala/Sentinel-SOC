const express = require('express');
const router = express.Router();
const ReportController = require('../controllers/reportController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS, REPORT_TYPES, REPORT_FORMATS, SEVERITY } = require('../config/constants');

console.log(' Setting up report routes...');

// Validation rules
const createReportValidation = [
  body('organization')
    .isMongoId()
    .withMessage('Invalid organization ID'),
  body('title')
    .optional()
    .isLength({ min: 3, max: 200 })
    .withMessage('Title must be between 3 and 200 characters')
    .trim(),
  body('description')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Description cannot exceed 500 characters')
    .trim(),
  body('type')
    .isIn(Object.values(REPORT_TYPES))
    .withMessage(`Type must be one of: ${Object.values(REPORT_TYPES).join(', ')}`),
  body('format')
    .optional()
    .isIn(Object.values(REPORT_FORMATS))
    .withMessage(`Format must be one of: ${Object.values(REPORT_FORMATS).join(', ')}`),
  body('filters.startDate')
    .isISO8601()
    .withMessage('Invalid start date format')
    .toDate(),
  body('filters.endDate')
    .isISO8601()
    .withMessage('Invalid end date format')
    .toDate(),
  body('filters.severity')
    .optional()
    .isArray()
    .withMessage('Severity must be an array'),
  body('filters.status')
    .optional()
    .isArray()
    .withMessage('Status must be an array'),
  body('filters.categories')
    .optional()
    .isArray()
    .withMessage('Categories must be an array'),
  body('filters.threatTypes')
    .optional()
    .isArray()
    .withMessage('Threat types must be an array'),
  body('filters.assignedTo')
    .optional()
    .isMongoId()
    .withMessage('Invalid user ID'),
  body('filters.includeResolved')
    .optional()
    .isBoolean()
    .withMessage('Include resolved must be a boolean'),
  body('filters.includeClosed')
    .optional()
    .isBoolean()
    .withMessage('Include closed must be a boolean')
];

const updateReportValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid report ID'),
  body('title')
    .optional()
    .isLength({ min: 3, max: 200 })
    .withMessage('Title must be between 3 and 200 characters')
    .trim(),
  body('description')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Description cannot exceed 500 characters')
    .trim(),
  body('filters')
    .optional()
    .isObject()
    .withMessage('Filters must be an object')
];

const reportIdValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid report ID')
];

const scheduleValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid report ID'),
  body('frequency')
    .isIn(['daily', 'weekly', 'monthly', 'quarterly'])
    .withMessage('Invalid frequency'),
  body('time')
    .matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/)
    .withMessage('Invalid time format (HH:MM)'),
  body('dayOfWeek')
    .optional()
    .isInt({ min: 0, max: 6 })
    .withMessage('Day of week must be between 0 and 6'),
  body('dayOfMonth')
    .optional()
    .isInt({ min: 1, max: 31 })
    .withMessage('Day of month must be between 1 and 31'),
  body('recipients')
    .optional()
    .isArray()
    .withMessage('Recipients must be an array')
];

const searchValidation = [
  query('search')
    .optional()
    .trim()
];

// All routes require authentication
router.use(protect);

// Public (authenticated) routes
router.get('/reports/types', ReportController.getReportTypes);
router.get('/reports/formats', ReportController.getReportFormats);
router.get('/reports/statuses', ReportController.getReportStatuses);
router.get('/reports/frequencies', ReportController.getScheduledFrequencies);
router.get('/reports/scheduled', ReportController.getScheduledReports);

// Report management routes
router.get('/reports/statistics',
  ReportController.getReportStatistics
);

router.get('/reports',
  searchValidation,
  validateRequest,
  ReportController.getReports
);

router.get('/reports/:id',
  reportIdValidation,
  validateRequest,
  ReportController.getReportById
);

// Admin only routes
router.post('/reports',
  authorize(PERMISSIONS.MANAGE_REPORTS),

  ReportController.createReport
);

router.put('/reports/:id',
  authorize(PERMISSIONS.MANAGE_REPORTS),
  updateReportValidation,
  validateRequest,
  sanitizeRequest,
  ReportController.updateReport
);

router.delete('/reports/:id',
  authorize(PERMISSIONS.MANAGE_REPORTS),
  reportIdValidation,
  validateRequest,
  ReportController.deleteReport
);

router.post('/reports/:id/generate',
  authorize(PERMISSIONS.MANAGE_REPORTS),
  reportIdValidation,
  validateRequest,
  ReportController.generateReport
);

router.post('/reports/:id/schedule',
  authorize(PERMISSIONS.MANAGE_REPORTS),
  scheduleValidation,
  validateRequest,
  sanitizeRequest,
  ReportController.scheduleReport
);

router.post('/reports/:id/unschedule',
  authorize(PERMISSIONS.MANAGE_REPORTS),
  reportIdValidation,
  validateRequest,
  ReportController.unscheduleReport
);

console.log(' Report routes configured');

module.exports = router;