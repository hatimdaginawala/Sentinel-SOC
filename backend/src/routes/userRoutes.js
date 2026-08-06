const express = require('express');
const router = express.Router();
const UserController = require('../controllers/userController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { ROLES, PERMISSIONS } = require('../config/constants');

console.log(' Setting up user routes...');

// Validation rules
const createUserValidation = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail()
    .trim(),
  body('username')
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores')
    .trim(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]/)
    .withMessage('Password must contain at least one special character'),
  body('firstName')
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters')
    .trim(),
  body('lastName')
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters')
    .trim(),
  body('role')
    .isIn(Object.values(ROLES))
    .withMessage(`Role must be one of: ${Object.values(ROLES).join(', ')}`),
  body('organization')
    .isMongoId()
    .withMessage('Invalid organization ID'),
  body('status')
    .optional()
    .isIn(['active', 'inactive', 'pending'])
    .withMessage('Status must be active, inactive, or pending')
];

const updateUserValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid user ID'),
  body('email')
    .optional()
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail()
    .trim(),
  body('username')
    .optional()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores')
    .trim(),
  body('firstName')
    .optional()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters')
    .trim(),
  body('lastName')
    .optional()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters')
    .trim(),
  body('role')
    .optional()
    .isIn(Object.values(ROLES))
    .withMessage(`Role must be one of: ${Object.values(ROLES).join(', ')}`),
  body('status')
    .optional()
    .isIn(['active', 'inactive', 'pending', 'locked'])
    .withMessage('Status must be active, inactive, pending, or locked')
];

const userIdValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid user ID')
];

const loginValidation = [
  body('identifier')
    .isLength({ min: 1 })
    .withMessage('Email or username is required')
    .trim(),
  body('password')
    .isLength({ min: 1 })
    .withMessage('Password is required')
];

const changePasswordValidation = [
  body('oldPassword')
    .isLength({ min: 1 })
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters long')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]/)
    .withMessage('Password must contain at least one special character')
];

const resetPasswordValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid user ID'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters long')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]/)
    .withMessage('Password must contain at least one special character')
];

const forgotPasswordValidation = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail()
    .trim()
];

const completeResetValidation = [
  body('token')
    .isLength({ min: 1 })
    .withMessage('Reset token is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters long')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]/)
    .withMessage('Password must contain at least one special character')
];

const refreshTokenValidation = [
  body('refreshToken')
    .isLength({ min: 1 })
    .withMessage('Refresh token is required')
];

// ============================================
// PUBLIC ROUTES - NO AUTHENTICATION REQUIRED
// These routes are defined BEFORE protect middleware
// ============================================
router.post('/login', loginValidation, validateRequest, sanitizeRequest, UserController.login);
router.post('/refresh', refreshTokenValidation, validateRequest, sanitizeRequest, UserController.refreshToken);
router.post('/forgot-password', forgotPasswordValidation, validateRequest, sanitizeRequest, UserController.initiatePasswordReset);
router.post('/reset-password', completeResetValidation, validateRequest, sanitizeRequest, UserController.completePasswordReset);

// ============================================
// PROTECTED ROUTES - AUTHENTICATION REQUIRED
// All routes below this line require authentication
// ============================================
router.use(protect);

// Current user routes
router.get('/me', UserController.getCurrentUser);
router.post('/change-password', changePasswordValidation, validateRequest, sanitizeRequest, UserController.changePassword);
router.post('/logout', UserController.logout);

// Admin only routes
router.post('/',
  authorize(PERMISSIONS.MANAGE_USERS),
  createUserValidation,
  validateRequest,
  sanitizeRequest,
  UserController.createUser
);

router.get('/',
  authorize(PERMISSIONS.VIEW_USERS),
  UserController.getUsers
);

router.get('/:id',
  authorize(PERMISSIONS.VIEW_USERS),
  userIdValidation,
  validateRequest,
  UserController.getUserById
);

router.put('/:id',
  authorize(PERMISSIONS.MANAGE_USERS),
  updateUserValidation,
  validateRequest,
  sanitizeRequest,
  UserController.updateUser
);

router.delete('/:id',
  authorize(PERMISSIONS.MANAGE_USERS),
  userIdValidation,
  validateRequest,
  UserController.deleteUser
);

router.delete('/:id/permanent',
  authorize(PERMISSIONS.MANAGE_USERS),
  userIdValidation,
  validateRequest,
  UserController.hardDeleteUser
);

router.post('/:id/reset-password',
  authorize(PERMISSIONS.MANAGE_USERS),
  resetPasswordValidation,
  validateRequest,
  sanitizeRequest,
  UserController.resetPassword
);

console.log(' User routes configured');

module.exports = router;