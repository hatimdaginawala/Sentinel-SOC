const express = require('express');
const router = express.Router();
const testController = require('../controllers/securityTestController');
const { protect } = require('../middleware/auth');

router.use(protect);

router.route('/')
  .get(testController.getTests)
  .post(testController.createTest);

router.route('/:id')
  .get(testController.getTest)
  .delete(testController.deleteTest);

router.post('/:id/run', testController.runTest);

module.exports = router;
