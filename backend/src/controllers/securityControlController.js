const SecurityControl = require('../models/SecurityControl');
const { AppError } = require('../middleware/errorHandler');

exports.getControls = async (req, res, next) => {
  try {
    const controls = await SecurityControl.find({ organization: req.user.organization })
      .populate('threatRule');
    res.status(200).json({ status: 'success', results: controls.length, data: controls });
  } catch (error) {
    next(error);
  }
};

exports.createControl = async (req, res, next) => {
  try {
    const newControl = await SecurityControl.create({
      ...req.body,
      organization: req.user.organization,
      createdBy: req.user._id
    });
    res.status(201).json({ status: 'success', data: newControl });
  } catch (error) {
    next(error);
  }
};

exports.getControl = async (req, res, next) => {
  try {
    const control = await SecurityControl.findOne({ _id: req.params.id, organization: req.user.organization })
      .populate('threatRule');
    if (!control) return next(new AppError('Control not found', 404));
    res.status(200).json({ status: 'success', data: control });
  } catch (error) {
    next(error);
  }
};

exports.updateControl = async (req, res, next) => {
  try {
    const control = await SecurityControl.findOneAndUpdate(
      { _id: req.params.id, organization: req.user.organization },
      { ...req.body, updatedBy: req.user._id },
      { new: true, runValidators: true }
    );
    if (!control) return next(new AppError('Control not found', 404));
    res.status(200).json({ status: 'success', data: control });
  } catch (error) {
    next(error);
  }
};

exports.deleteControl = async (req, res, next) => {
  try {
    const control = await SecurityControl.findOneAndDelete({ _id: req.params.id, organization: req.user.organization });
    if (!control) return next(new AppError('Control not found', 404));
    res.status(204).json({ status: 'success', data: null });
  } catch (error) {
    next(error);
  }
};
