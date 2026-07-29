const express = require('express');
const router = express.Router();
const RoleController = require('../controllers/roleController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS, ROLES } = require('../config/constants');

// Validation rules
const createRoleValidation = [
  body('name')
    .isIn(Object.values(ROLES))
    .withMessage(`Role name must be one of: ${Object.values(ROLES).join(', ')}`)
    .trim(),
  body('displayName')
    .isLength({ min: 2, max: 50 })
    .withMessage('Display name must be between 2 and 50 characters')
    .trim(),
  body('description')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Description cannot exceed 500 characters')
    .trim(),
  body('permissions')
    .optional()
    .isArray()
    .withMessage('Permissions must be an array')
    .custom((permissions) => {
      if (permissions && permissions.length > 0) {
        const validPermissions = Object.values(PERMISSIONS);
        const invalidPermissions = permissions.filter(p => !validPermissions.includes(p));
        if (invalidPermissions.length > 0) {
          throw new Error(`Invalid permissions: ${invalidPermissions.join(', ')}`);
        }
      }
      return true;
    }),
  body('priority')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Priority must be between 0 and 100'),
  body('status')
    .optional()
    .isIn(['active', 'inactive'])
    .withMessage('Status must be active or inactive')
];

const updateRoleValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid role ID'),
  body('name')
    .optional()
    .isIn(Object.values(ROLES))
    .withMessage(`Role name must be one of: ${Object.values(ROLES).join(', ')}`)
    .trim(),
  body('displayName')
    .optional()
    .isLength({ min: 2, max: 50 })
    .withMessage('Display name must be between 2 and 50 characters')
    .trim(),
  body('description')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Description cannot exceed 500 characters')
    .trim(),
  body('permissions')
    .optional()
    .isArray()
    .withMessage('Permissions must be an array')
    .custom((permissions) => {
      if (permissions && permissions.length > 0) {
        const validPermissions = Object.values(PERMISSIONS);
        const invalidPermissions = permissions.filter(p => !validPermissions.includes(p));
        if (invalidPermissions.length > 0) {
          throw new Error(`Invalid permissions: ${invalidPermissions.join(', ')}`);
        }
      }
      return true;
    }),
  body('priority')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Priority must be between 0 and 100'),
  body('status')
    .optional()
    .isIn(['active', 'inactive'])
    .withMessage('Status must be active or inactive')
];

const roleIdValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid role ID')
];

const permissionValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid role ID'),
  param('permission')
    .isIn(Object.values(PERMISSIONS))
    .withMessage(`Invalid permission. Must be one of: ${Object.values(PERMISSIONS).join(', ')}`)
];

// All routes require authentication
router.use(protect);

// Public (authenticated) routes - available to all authenticated users
router.get('/roles/active', RoleController.getActiveRoles);
router.get('/roles/permissions', RoleController.getAllPermissions);
router.get('/roles/permissions/categories', RoleController.getPermissionsByCategory);
router.get('/roles/hierarchy', RoleController.getRoleHierarchy);

// Admin only routes
router.post('/roles/initialize',
  authorize(PERMISSIONS.CONFIGURE_SYSTEM),
  RoleController.initializeSystemRoles
);

router.post('/roles',
  authorize(PERMISSIONS.MANAGE_USERS),
  createRoleValidation,
  validateRequest,
  sanitizeRequest,
  RoleController.createRole
);

router.get('/roles',
  authorize(PERMISSIONS.VIEW_USERS),
  RoleController.getRoles
);

router.get('/roles/statistics',
  authorize(PERMISSIONS.VIEW_USERS),
  RoleController.getRoleStatistics
);

router.get('/roles/:id',
  authorize(PERMISSIONS.VIEW_USERS),
  roleIdValidation,
  validateRequest,
  RoleController.getRoleById
);

router.put('/roles/:id',
  authorize(PERMISSIONS.MANAGE_USERS),
  updateRoleValidation,
  validateRequest,
  sanitizeRequest,
  RoleController.updateRole
);

router.delete('/roles/:id',
  authorize(PERMISSIONS.MANAGE_USERS),
  roleIdValidation,
  validateRequest,
  RoleController.deleteRole
);

router.delete('/roles/:id/permanent',
  authorize(PERMISSIONS.MANAGE_USERS),
  roleIdValidation,
  validateRequest,
  RoleController.hardDeleteRole
);

router.get('/roles/:id/permission/:permission',
  authorize(PERMISSIONS.VIEW_USERS),
  permissionValidation,
  validateRequest,
  RoleController.checkRolePermission
);

module.exports = router;