const express = require('express');
const router = express.Router();
const OrganizationController = require('../controllers/organizationController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS } = require('../config/constants');

console.log('📦 organizationRoutes.js is being loaded!');

// Test routes (no authentication required)
router.get('/test', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Organization routes are working!',
    timestamp: new Date().toISOString()
  });
});

// Test route with authentication
router.get('/test-auth', protect, (req, res) => {
  res.json({ 
    success: true, 
    message: 'Organization routes with auth are working!',
    user: req.user.email,
    timestamp: new Date().toISOString()
  });
});

// ============================================
// PROTECTED ROUTES - All routes below require authentication
// ============================================
router.use(protect);

// GET / - Get all organizations (Main route that's failing)
router.get('/', 
  authorize(PERMISSIONS.VIEW_ORGANIZATIONS),
  OrganizationController.getOrganizations
);

// GET /active - Get active organizations
router.get('/active', 
  OrganizationController.getActiveOrganizations
);

// GET /statistics - Get organization statistics
router.get('/statistics',
  authorize(PERMISSIONS.VIEW_ORGANIZATIONS),
  OrganizationController.getOrganizationStatistics
);

// GET /subscriptions/expiring - Get expiring subscriptions
router.get('/subscriptions/expiring',
  authorize(PERMISSIONS.VIEW_ORGANIZATIONS),
  query('days')
    .optional()
    .isInt({ min: 1, max: 365 })
    .withMessage('Days must be between 1 and 365'),
  validateRequest,
  OrganizationController.getExpiringSubscriptions
);

// GET /subscriptions/expired - Get expired subscriptions
router.get('/subscriptions/expired',
  authorize(PERMISSIONS.VIEW_ORGANIZATIONS),
  OrganizationController.getExpiredSubscriptions
);

// GET /:id - Get organization by ID
router.get('/:id',
  authorize(PERMISSIONS.VIEW_ORGANIZATIONS),
  param('id').isMongoId().withMessage('Invalid organization ID'),
  validateRequest,
  OrganizationController.getOrganizationById
);

// GET /code/:code - Get organization by code
router.get('/code/:code',
  authorize(PERMISSIONS.VIEW_ORGANIZATIONS),
  param('code').isLength({ min: 2, max: 10 }).withMessage('Invalid organization code'),
  validateRequest,
  OrganizationController.getOrganizationByCode
);

// GET /:id/usage - Get organization usage
router.get('/:id/usage',
  authorize(PERMISSIONS.VIEW_ORGANIZATIONS),
  param('id').isMongoId().withMessage('Invalid organization ID'),
  validateRequest,
  OrganizationController.getOrganizationUsage
);

// GET /:id/capacity/users - Check user capacity
router.get('/:id/capacity/users',
  authorize(PERMISSIONS.VIEW_ORGANIZATIONS),
  param('id').isMongoId().withMessage('Invalid organization ID'),
  query('additional').optional().isInt({ min: 1 }).withMessage('Additional count must be a positive integer'),
  validateRequest,
  OrganizationController.checkUserCapacity
);

// GET /:id/capacity/assets - Check asset capacity
router.get('/:id/capacity/assets',
  authorize(PERMISSIONS.VIEW_ORGANIZATIONS),
  param('id').isMongoId().withMessage('Invalid organization ID'),
  query('additional').optional().isInt({ min: 1 }).withMessage('Additional count must be a positive integer'),
  validateRequest,
  OrganizationController.checkAssetCapacity
);

// POST / - Create organization
router.post('/',
  authorize(PERMISSIONS.MANAGE_ORGANIZATIONS),
  [
    body('name').isLength({ min: 2, max: 100 }).withMessage('Organization name must be between 2 and 100 characters').trim(),
    body('code').optional().isLength({ min: 2, max: 10 }).withMessage('Organization code must be between 2 and 10 characters').matches(/^[A-Z0-9]+$/).withMessage('Organization code can only contain uppercase letters and numbers').trim().toUpperCase(),
    body('description').optional().isLength({ max: 500 }).withMessage('Description cannot exceed 500 characters').trim(),
    body('industry').optional().isIn(['technology', 'finance', 'healthcare', 'government', 'education', 'retail', 'manufacturing', 'energy', 'telecommunications', 'other']).withMessage('Invalid industry'),
    body('size').optional().isIn(['small', 'medium', 'large', 'enterprise']).withMessage('Invalid organization size'),
    body('website').optional().isURL().withMessage('Invalid website URL').trim(),
    body('status').optional().isIn(['active', 'inactive', 'suspended', 'pending']).withMessage('Invalid status'),
    body('subscription.plan').optional().isIn(['free', 'basic', 'professional', 'enterprise']).withMessage('Invalid subscription plan')
  ],
  validateRequest,
  sanitizeRequest,
  OrganizationController.createOrganization
);

// PUT /:id - Update organization
router.put('/:id',
  authorize(PERMISSIONS.MANAGE_ORGANIZATIONS),
  [
    param('id').isMongoId().withMessage('Invalid organization ID'),
    body('name').optional().isLength({ min: 2, max: 100 }).withMessage('Organization name must be between 2 and 100 characters').trim(),
    body('code').optional().isLength({ min: 2, max: 10 }).withMessage('Organization code must be between 2 and 10 characters').matches(/^[A-Z0-9]+$/).withMessage('Organization code can only contain uppercase letters and numbers').trim().toUpperCase(),
    body('description').optional().isLength({ max: 500 }).withMessage('Description cannot exceed 500 characters').trim(),
    body('status').optional().isIn(['active', 'inactive', 'suspended', 'pending']).withMessage('Invalid status')
  ],
  validateRequest,
  sanitizeRequest,
  OrganizationController.updateOrganization
);

// PUT /:id/subscription - Update subscription
router.put('/:id/subscription',
  authorize(PERMISSIONS.MANAGE_ORGANIZATIONS),
  [
    param('id').isMongoId().withMessage('Invalid organization ID'),
    body('plan').optional().isIn(['free', 'basic', 'professional', 'enterprise']).withMessage('Invalid subscription plan'),
    body('endDate').optional().isISO8601().withMessage('Invalid date format').toDate(),
    body('isActive').optional().isBoolean().withMessage('isActive must be a boolean')
  ],
  validateRequest,
  sanitizeRequest,
  OrganizationController.updateSubscription
);

// DELETE /:id - Soft delete organization
router.delete('/:id',
  authorize(PERMISSIONS.MANAGE_ORGANIZATIONS),
  param('id').isMongoId().withMessage('Invalid organization ID'),
  validateRequest,
  OrganizationController.deleteOrganization
);

// DELETE /:id/permanent - Hard delete organization
router.delete('/:id/permanent',
  authorize(PERMISSIONS.MANAGE_ORGANIZATIONS),
  param('id').isMongoId().withMessage('Invalid organization ID'),
  validateRequest,
  OrganizationController.hardDeleteOrganization
);

console.log('✅ Organization routes configured');

module.exports = router;