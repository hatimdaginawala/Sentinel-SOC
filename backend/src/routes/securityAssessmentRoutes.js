// routes/securityAssessmentRoutes.js

const express = require('express');
const router = express.Router();
const assessmentController = require('../controllers/securityAssessmentController');
const { protect } = require('../middleware/auth');

// All routes require authentication
router.use(protect);

// Statistics endpoint
router.get('/stats', assessmentController.getAssessmentStats);

// Dropdown endpoints
router.get('/risk-levels', assessmentController.getRiskLevels);
router.get('/statuses', assessmentController.getStatuses);

// Main CRUD routes
router.route('/')
  .get(assessmentController.getAssessments)
  .post(assessmentController.createAssessment);

// Individual assessment routes
router.route('/:id')
  .get(assessmentController.getAssessment)
  .put(assessmentController.updateAssessment)
  .delete(assessmentController.deleteAssessment);

// Link routes
router.post('/:id/link-threats', assessmentController.linkThreats);
router.post('/:id/link-incidents', assessmentController.linkIncidents);
router.post('/:id/link-assets', assessmentController.linkAssets);

// Status and calculation routes
router.patch('/:id/status', assessmentController.updateStatus);
router.post('/:id/calculate-risk', assessmentController.calculateRisk);

module.exports = router;