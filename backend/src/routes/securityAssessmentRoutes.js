const express = require('express');
const router = express.Router();
const assessmentController = require('../controllers/securityAssessmentController');
const { protect } = require('../middleware/auth');

router.use(protect);

router.route('/')
  .get(assessmentController.getAssessments)
  .post(assessmentController.createAssessment);

router.route('/:id')
  .get(assessmentController.getAssessment)
  .delete(assessmentController.deleteAssessment);

module.exports = router;
