const SecuritySensor = require('../models/SecuritySensor');
const { AppError } = require('../middleware/errorHandler');

exports.getSensors = async (req, res, next) => {
  try {
    const sensors = await SecuritySensor.find({ organization: req.user.organization })
      .populate('asset');
    res.status(200).json({ status: 'success', results: sensors.length, data: sensors });
  } catch (error) {
    next(error);
  }
};

exports.createSensor = async (req, res, next) => {
  try {
    const newSensor = await SecuritySensor.create({
      ...req.body,
      organization: req.user.organization,
      createdBy: req.user._id
    });
    res.status(201).json({ status: 'success', data: newSensor });
  } catch (error) {
    next(error);
  }
};

exports.getSensor = async (req, res, next) => {
  try {
    const sensor = await SecuritySensor.findOne({ _id: req.params.id, organization: req.user.organization })
      .populate('asset');
    if (!sensor) return next(new AppError('Sensor not found', 404));
    res.status(200).json({ status: 'success', data: sensor });
  } catch (error) {
    next(error);
  }
};

exports.updateSensor = async (req, res, next) => {
  try {
    const sensor = await SecuritySensor.findOneAndUpdate(
      { _id: req.params.id, organization: req.user.organization },
      { ...req.body, updatedBy: req.user._id },
      { new: true, runValidators: true }
    );
    if (!sensor) return next(new AppError('Sensor not found', 404));
    res.status(200).json({ status: 'success', data: sensor });
  } catch (error) {
    next(error);
  }
};

exports.deleteSensor = async (req, res, next) => {
  try {
    const sensor = await SecuritySensor.findOneAndDelete({ _id: req.params.id, organization: req.user.organization });
    if (!sensor) return next(new AppError('Sensor not found', 404));
    res.status(204).json({ status: 'success', data: null });
  } catch (error) {
    next(error);
  }
};
