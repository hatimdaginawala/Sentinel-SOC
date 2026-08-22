// routes/simulatorRoutes.js

const express = require('express');
const router = express.Router();
const simulatorController = require('../controllers/simulatorController');
const { protect, authorize } = require('../middleware/auth');

// All routes require authentication
router.use(protect);

// Initialize simulators
router.post('/simulators/initialize', 
  authorize('manage_assets'), 
  simulatorController.initializeSimulators
);

// Start/Stop all simulators
router.post('/simulators/start-all', 
  authorize('manage_assets'), 
  simulatorController.startAllSimulators
);
router.post('/simulators/stop-all', 
  authorize('manage_assets'), 
  simulatorController.stopAllSimulators
);

// Get status and stats
router.get('/simulators/status', 
  simulatorController.getSimulatorStatus
);
router.get('/simulators/stats', 
  simulatorController.getSimulatorStats
);

// Individual simulator control
router.post('/simulators/:id/start', 
  authorize('manage_assets'), 
  simulatorController.startSimulator
);
router.post('/simulators/:id/stop', 
  authorize('manage_assets'), 
  simulatorController.stopSimulator
);

module.exports = router;