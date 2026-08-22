// src/routes/logRoutes.js

const express = require('express');
const router = express.Router();
const LogController = require('../controllers/logController');
const { validateRequest, sanitizeRequest } = require('../middleware/validation');
const { protect, authorize } = require('../middleware/auth');
const { body, param, query } = require('express-validator');
const { PERMISSIONS } = require('../config/constants');

console.log(' Setting up log routes...');

// ============================================
// ✅ PUBLIC ROUTES - MUST BE FIRST
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

// ✅ CRITICAL: /logs/ingest MUST be BEFORE router.use(protect)
router.post('/logs/ingest',
  [
    body('sourceId').isMongoId().withMessage('Invalid log source ID'),
    body('authToken').isString().withMessage('Auth token is required'),
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
// ✅ PROTECTED ROUTES - ONLY AFTER THIS LINE
// ============================================

console.log('Setting up protected routes...');

// ✅ THIS APPLIES TO ALL ROUTES BELOW THIS LINE
router.use(protect);

// Protected routes - require authentication
router.get('/logs/categories', LogController.getEventCategories);
router.get('/logs/severities', LogController.getSeverities);
router.get('/logs/statuses', LogController.getStatuses);
router.get('/logs/statistics', LogController.getLogStatistics);
router.get('/logs', LogController.getLogs);
router.get('/logs/:id', LogController.getLogById);
router.get('/logs/organization/:organizationId', authorize(PERMISSIONS.VIEW_LOGS), LogController.getLogsByOrganization);
router.get('/logs/source/:logSourceId', authorize(PERMISSIONS.VIEW_LOGS), LogController.getLogsByLogSource);
router.delete('/logs/:id', authorize(PERMISSIONS.MANAGE_LOGS), LogController.deleteLog);
router.post('/logs/cleanup', authorize(PERMISSIONS.MANAGE_LOGS), LogController.deleteOldLogs);

console.log(' Log routes configured');

module.exports = router;