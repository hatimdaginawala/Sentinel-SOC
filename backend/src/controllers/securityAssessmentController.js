const SecurityAssessment = require('../models/SecurityAssessment');
const { AppError } = require('../middleware/errorHandler');

exports.getAssessments = async (req, res, next) => {
  try {
    const assessments = await SecurityAssessment.find({ organization: req.user.organization })
      .populate('threatsDetected')
      .populate('affectedAssets');
    res.status(200).json({ status: 'success', results: assessments.length, data: assessments });
  } catch (error) {
    next(error);
  }
};

exports.createAssessment = async (req, res, next) => {
  try {
    const newAssessment = await SecurityAssessment.create({
      ...req.body,
      organization: req.user.organization,
      createdBy: req.user._id
    });
    res.status(201).json({ status: 'success', data: newAssessment });
  } catch (error) {
    next(error);
  }
};

exports.getAssessment = async (req, res, next) => {
  try {
    const assessment = await SecurityAssessment.findOne({ _id: req.params.id, organization: req.user.organization })
      .populate('threatsDetected')
      .populate('incidents')
      .populate('affectedAssets');
    if (!assessment) return next(new AppError('Assessment not found', 404));
    res.status(200).json({ status: 'success', data: assessment });
  } catch (error) {
    next(error);
  }
};

exports.deleteAssessment = async (req, res, next) => {
  try {
    const assessment = await SecurityAssessment.findOneAndDelete({ _id: req.params.id, organization: req.user.organization });
    if (!assessment) return next(new AppError('Assessment not found', 404));
    res.status(204).json({ status: 'success', data: null });
  } catch (error) {
    next(error);
  }
};
