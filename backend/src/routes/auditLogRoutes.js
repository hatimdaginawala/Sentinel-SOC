// routes/auditLogRoutes.js
const express = require('express');
const router = express.Router();
const AuditLogController = require('../controllers/auditLogController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS } = require('../config/constants');

console.log('🔧 Setting up audit log routes...');

// Validation rules
const auditLogIdValidation = [
  param('id').isMongoId().withMessage('Invalid audit log ID')
];

const userValidation = [
  param('userId').isMongoId().withMessage('Invalid user ID')
];

const ipValidation = [
  param('ipAddress').isIP().withMessage('Invalid IP address').trim()
];

const trailValidation = [
  param('resource')
    .isIn(['user', 'role', 'organization', 'asset', 'log', 'alert', 'incident', 'ioc', 'threat_rule', 'report', 'settings', 'system', 'authentication'])
    .withMessage('Invalid resource type'),
  param('resourceId').isLength({ min: 1 }).withMessage('Resource ID is required').trim()
];

const searchValidation = [
  query('query').isLength({ min: 1 }).withMessage('Search query is required').trim()
];

const cleanupValidation = [
  body('retentionDays').optional().isInt({ min: 1, max: 365 }).withMessage('Retention days must be between 1 and 365')
];

// All routes require authentication and VIEW_AUDIT_LOGS permission
router.use(protect);
router.use(authorize(PERMISSIONS.VIEW_AUDIT_LOGS));

// Public (authenticated) routes - dropdown options
router.get('/audit-logs/actions', AuditLogController.getActions);
router.get('/audit-logs/resources', AuditLogController.getResources);
router.get('/audit-logs/statuses', AuditLogController.getStatuses);
router.get('/audit-logs/severities', AuditLogController.getSeverityLevels);

// Audit log management routes
router.get('/audit-logs/statistics', AuditLogController.getAuditStatistics);
router.get('/audit-logs/search', searchValidation, validateRequest, AuditLogController.searchAuditLogs);
router.get('/audit-logs/export', AuditLogController.exportAuditLogs);
router.get('/audit-logs/trail/:resource/:resourceId', trailValidation, validateRequest, AuditLogController.getAuditTrail);
router.get('/audit-logs/user/:userId', userValidation, validateRequest, AuditLogController.getAuditLogsByUser);
router.get('/audit-logs/ip/:ipAddress', ipValidation, validateRequest, AuditLogController.getAuditLogsByIP);
router.get('/audit-logs/:id', auditLogIdValidation, validateRequest, AuditLogController.getAuditLogById);
router.get('/audit-logs', AuditLogController.getAuditLogs);

// Admin only routes (MANAGE_AUDIT_LOGS permission)
router.post('/audit-logs/cleanup',
  authorize(PERMISSIONS.MANAGE_AUDIT_LOGS),
  cleanupValidation,
  validateRequest,
  sanitizeRequest,
  AuditLogController.cleanupOldLogs
);

console.log('✅ Audit log routes configured');

module.exports = router;