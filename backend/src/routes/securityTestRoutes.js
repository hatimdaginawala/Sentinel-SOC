// src/routes/securityTestRoutes.js

const express = require('express');
const router = express.Router();
const testController = require('../controllers/securityTestController');
const { protect } = require('../middleware/auth');

// All routes require authentication
router.use(protect);

// Statistics endpoint
router.get('/stats', testController.getTestStats);

// Main CRUD routes
router.route('/')
  .get(testController.getTests)
  .post(testController.createTest);

// Individual test routes
router.route('/:id')
  .get(testController.getTest)
  .put(testController.updateTest)
  .delete(testController.deleteTest);

// Test execution routes
router.post('/:id/run', testController.runTest);
router.post('/:id/cancel', testController.cancelTest);

module.exports = router;