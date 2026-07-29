const express = require('express');
const router = express.Router();
const AssetController = require('../controllers/assetController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS, ASSET_TYPES } = require('../config/constants');

console.log('🔧 Setting up asset routes...');

// Validation rules
const createAssetValidation = [
  body('name')
    .isLength({ min: 2, max: 100 })
    .withMessage('Asset name must be between 2 and 100 characters')
    .trim(),
  body('type')
    .isIn(Object.values(ASSET_TYPES))
    .withMessage(`Asset type must be one of: ${Object.values(ASSET_TYPES).join(', ')}`),
  body('organization')
    .isMongoId()
    .withMessage('Invalid organization ID'),
  body('ipAddress')
    .optional()
    .isIP()
    .withMessage('Invalid IP address')
    .trim(),
  body('hostname')
    .optional()
    .isLength({ max: 255 })
    .withMessage('Hostname cannot exceed 255 characters')
    .trim(),
  body('operatingSystem')
    .optional()
    .trim(),
  body('status')
    .optional()
    .isIn(['active', 'inactive', 'maintenance', 'decommissioned', 'compromised'])
    .withMessage('Invalid status'),
  body('criticality')
    .optional()
    .isIn(['low', 'medium', 'high', 'critical'])
    .withMessage('Invalid criticality'),
  body('location')
    .optional()
    .trim(),
  body('department')
    .optional()
    .trim(),
  body('owner')
    .optional()
    .trim(),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array')
];

// Test routes
router.get('/test', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Asset routes are working!',
    timestamp: new Date().toISOString()
  });
});

router.get('/test-auth', protect, (req, res) => {
  res.json({ 
    success: true, 
    message: 'Asset routes with auth are working!',
    user: req.user.email,
    timestamp: new Date().toISOString()
  });
});

// All routes below require authentication
router.use(protect);

// Public (authenticated) routes
router.get('/types', AssetController.getAssetTypes);
router.get('/criticalities', AssetController.getAssetCriticalities);
router.get('/statuses', AssetController.getAssetStatuses);

// Asset management routes
router.get('/search',
  query('query').isLength({ min: 1 }).withMessage('Search query is required').trim(),
  validateRequest,
  AssetController.searchAssets
);

router.get('/vulnerabilities',
  AssetController.getAssetsWithVulnerabilities
);

router.get('/needing-patching',
  AssetController.getAssetsNeedingPatching
);

router.get('/statistics',
  AssetController.getAssetStatistics
);

router.get('/type/:type',
  param('type').isIn(Object.values(ASSET_TYPES)).withMessage('Invalid asset type'),
  validateRequest,
  AssetController.getAssetsByType
);

router.get('/criticality/:criticality',
  param('criticality').isIn(['low', 'medium', 'high', 'critical']).withMessage('Invalid criticality'),
  validateRequest,
  AssetController.getAssetsByCriticality
);

// Main GET route
router.get('/',
  authorize(PERMISSIONS.VIEW_ASSETS),
  AssetController.getAllAssets
);

router.get('/organization/:organizationId',
  authorize(PERMISSIONS.VIEW_ASSETS),
  param('organizationId').isMongoId().withMessage('Invalid organization ID'),
  validateRequest,
  AssetController.getAssetsByOrganization
);

router.get('/:id',
  authorize(PERMISSIONS.VIEW_ASSETS),
  param('id').isMongoId().withMessage('Invalid asset ID'),
  validateRequest,
  AssetController.getAssetById
);

// Admin only routes
router.post('/',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  createAssetValidation,
  validateRequest,
  sanitizeRequest,
  AssetController.createAsset
);

router.post('/bulk',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  body().isArray().withMessage('Request body must be an array of assets'),
  validateRequest,
  sanitizeRequest,
  AssetController.bulkCreateAssets
);

router.put('/:id',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  param('id').isMongoId().withMessage('Invalid asset ID'),
  validateRequest,
  sanitizeRequest,
  AssetController.updateAsset
);

router.post('/:id/update-risk',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  param('id').isMongoId().withMessage('Invalid asset ID'),
  validateRequest,
  AssetController.updateAssetRiskScore
);

router.delete('/:id',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  param('id').isMongoId().withMessage('Invalid asset ID'),
  validateRequest,
  AssetController.deleteAsset
);

router.delete('/:id/permanent',
  authorize(PERMISSIONS.MANAGE_ASSETS),
  param('id').isMongoId().withMessage('Invalid asset ID'),
  validateRequest,
  AssetController.hardDeleteAsset
);

console.log('✅ Asset routes configured');

module.exports = router;