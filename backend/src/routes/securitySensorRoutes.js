// routes/securitySensorRoutes.js

const express = require('express');
const router = express.Router();
const sensorController = require('../controllers/securitySensorController');
const { protect } = require('../middleware/auth');

// All routes require authentication
router.use(protect);

// Statistics endpoint
router.get('/stats', sensorController.getSensorStats);

// Dropdown endpoints
router.get('/types', sensorController.getTypes);
router.get('/statuses', sensorController.getStatuses);

// Main CRUD routes
router.route('/')
  .get(sensorController.getSensors)
  .post(sensorController.createSensor);

// Individual sensor routes
router.route('/:id')
  .get(sensorController.getSensor)
  .put(sensorController.updateSensor)
  .delete(sensorController.deleteSensor);

// Sensor operations
router.post('/:id/heartbeat', sensorController.updateHeartbeat);

module.exports = router;