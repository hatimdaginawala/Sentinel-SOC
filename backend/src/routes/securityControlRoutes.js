const express = require('express');
const router = express.Router();
const controlController = require('../controllers/securityControlController');
const { protect } = require('../middleware/auth');

router.use(protect);

router.route('/')
  .get(controlController.getControls)
  .post(controlController.createControl);

router.route('/:id')
  .get(controlController.getControl)
  .put(controlController.updateControl)
  .delete(controlController.deleteControl);

module.exports = router;
