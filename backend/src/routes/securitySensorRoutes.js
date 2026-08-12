const express = require('express');
const router = express.Router();
const sensorController = require('../controllers/securitySensorController');
const { protect } = require('../middleware/auth');

router.use(protect);

router.route('/')
  .get(sensorController.getSensors)
  .post(sensorController.createSensor);

router.route('/:id')
  .get(sensorController.getSensor)
  .put(sensorController.updateSensor)
  .delete(sensorController.deleteSensor);

module.exports = router;
