// controllers/simulatorController.js

const SimulatorService = require('../services/simulatorService');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');

/**
 * Initialize simulators for the organization
 */
exports.initializeSimulators = async (req, res, next) => {
  try {
    const simulators = await SimulatorService.initializeSimulators(
      req.user.organization,
      req.user._id
    );
    
    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: 'Simulators initialized successfully',
      data: simulators
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Start a specific simulator
 */
exports.startSimulator = async (req, res, next) => {
  try {
    const { id } = req.params;
    
    // Verify simulator belongs to the user's organization
    const simulator = await SimulatorService.startSimulator(id, req.user._id);
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: 'Simulator started successfully',
      data: simulator
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Start all simulators for the organization
 */
exports.startAllSimulators = async (req, res, next) => {
  try {
    const started = await SimulatorService.startAllSimulators(
      req.user.organization,
      req.user._id
    );
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: `${started.length} simulators started`,
      data: started
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Stop a specific simulator
 */
exports.stopSimulator = async (req, res, next) => {
  try {
    const { id } = req.params;
    const simulator = await SimulatorService.stopSimulator(id, req.user._id);
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: 'Simulator stopped successfully',
      data: simulator
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Stop all simulators for the organization
 */
exports.stopAllSimulators = async (req, res, next) => {
  try {
    const stopped = await SimulatorService.stopAllSimulators(
      req.user.organization,
      req.user._id
    );
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: `${stopped.length} simulators stopped`,
      data: stopped
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get simulator status
 */
exports.getSimulatorStatus = async (req, res, next) => {
  try {
    const status = await SimulatorService.getSimulatorStatus(req.user.organization);
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: status
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get simulator statistics
 */
exports.getSimulatorStats = async (req, res, next) => {
  try {
    const stats = await SimulatorService.getSimulatorStats(req.user.organization);
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: stats
    });
  } catch (error) {
    next(error);
  }
};