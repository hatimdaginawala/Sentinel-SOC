// routes/securityControlRoutes.js

const express = require('express');
const router = express.Router();
const controlController = require('../controllers/securityControlController');
const { protect } = require('../middleware/auth');

// All routes require authentication
// router.use(protect);

// Statistics endpoint
router.get('/stats', controlController.getControlStats);

// Dropdown endpoints
router.get('/priority-levels', controlController.getPriorityLevels);
router.get('/statuses', controlController.getStatuses);
router.get('/control-statuses', controlController.getControlStatuses);
router.get('/compliance-frameworks', controlController.getComplianceFrameworks);
router.get('/risk-levels', controlController.getRiskLevels);

// Main CRUD routes
router.route('/')
  .get(controlController.getControls)
  .post(controlController.createControl);

// Individual control routes
router.route('/:id')
  .get(controlController.getControl)
  .put(controlController.updateControl)
  .delete(controlController.deleteControl);

// Add items to control
router.post('/:id/recommended-controls', controlController.addRecommendedControl);
router.put('/:id/recommended-controls/:index', controlController.updateRecommendedControlStatus);
router.post('/:id/mitigations', controlController.addMitigation);
router.post('/:id/analyst-actions', controlController.addAnalystAction);

module.exports = router;