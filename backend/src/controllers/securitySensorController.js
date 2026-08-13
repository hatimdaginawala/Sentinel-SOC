// controllers/securitySensorController.js

const SecuritySensor = require('../models/SecuritySensor');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');

/**
 * Get all security sensors with filtering and pagination
 */
exports.getSensors = async (req, res, next) => {
  try {
    const {
      type,
      status,
      networkZone,
      search,
      tags,
      healthScoreMin,
      healthScoreMax,
      page = 1,
      limit = 20,
      sort = '-createdAt'
    } = req.query;

    // Build query
    const query = { organization: req.user.organization };

    if (type && type !== 'all') query.type = type;
    if (status && status !== 'all') query.status = status;
    if (networkZone && networkZone !== 'all') query.networkZone = networkZone;
    if (tags && tags.length > 0) query.tags = { $in: tags.split(',') };
    if (healthScoreMin) query.healthScore = { $gte: parseInt(healthScoreMin) };
    if (healthScoreMax) {
      query.healthScore = { ...query.healthScore, $lte: parseInt(healthScoreMax) };
    }

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { type: { $regex: search, $options: 'i' } },
        { networkZone: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const skip = (page - 1) * limit;

    const [sensors, total] = await Promise.all([
      SecuritySensor.find(query)
        .populate('asset', 'name hostname ipAddress type')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      SecuritySensor.countDocuments(query)
    ]);

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: sensors,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Create a new security sensor
 */
exports.createSensor = async (req, res, next) => {
  try {
    const {
      name,
      type,
      description,
      networkZone,
      ipAddress,
      port,
      asset,
      capabilities,
      tags,
      status,
      configuration
    } = req.body;

    if (!name) {
      throw new AppError('Sensor name is required', HTTP_STATUS.BAD_REQUEST, 'NAME_REQUIRED');
    }

    if (!type) {
      throw new AppError('Sensor type is required', HTTP_STATUS.BAD_REQUEST, 'TYPE_REQUIRED');
    }

    const sensorData = {
      name,
      type,
      description: description || '',
      networkZone: networkZone || 'Unassigned',
      ipAddress: ipAddress || '',
      port: port || null,
      asset: asset || null,
      capabilities: capabilities || [],
      tags: tags || [],
      status: status || 'Pending',
      configuration: configuration || {},
      organization: req.user.organization,
      createdBy: req.user._id,
      updatedBy: req.user._id
    };

    const newSensor = new SecuritySensor(sensorData);
    await newSensor.save();

    // Populate for response
    await newSensor.populate('asset', 'name hostname ipAddress');
    await newSensor.populate('createdBy', 'username email firstName lastName');

    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: 'Security sensor created successfully',
      data: newSensor
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get a single security sensor by ID
 */
exports.getSensor = async (req, res, next) => {
  try {
    const sensor = await SecuritySensor.findById(req.params.id)
      .populate('asset', 'name hostname ipAddress type criticality')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName');

    if (!sensor) {
      throw new AppError('Security sensor not found', HTTP_STATUS.NOT_FOUND, 'SENSOR_NOT_FOUND');
    }

    // Allow Super Admin to access any sensor, but check org for other roles
    const isSuperAdmin = req.user.role === 'super_admin';
    
    // If not Super Admin, check organization access
    if (!isSuperAdmin && sensor.organization.toString() !== req.user.organization.toString()) {
      throw new AppError('Access denied - Sensor belongs to a different organization', HTTP_STATUS.FORBIDDEN, 'ACCESS_DENIED');
    }

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: sensor
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update a security sensor
 */
exports.updateSensor = async (req, res, next) => {
  try {
    const {
      name,
      type,
      description,
      networkZone,
      ipAddress,
      port,
      asset,
      status,
      capabilities,
      tags,
      configuration
    } = req.body;

    const sensor = await SecuritySensor.findById(req.params.id);

    if (!sensor) {
      throw new AppError('Security sensor not found', HTTP_STATUS.NOT_FOUND, 'SENSOR_NOT_FOUND');
    }

    // Allow Super Admin to update any sensor, but check org for other roles
    const isSuperAdmin = req.user.role === 'super_admin';
    
    if (!isSuperAdmin && sensor.organization.toString() !== req.user.organization.toString()) {
      throw new AppError('Access denied - Sensor belongs to a different organization', HTTP_STATUS.FORBIDDEN, 'ACCESS_DENIED');
    }

    // Update fields
    if (name) sensor.name = name;
    if (type) sensor.type = type;
    if (description !== undefined) sensor.description = description;
    if (networkZone !== undefined) sensor.networkZone = networkZone;
    if (ipAddress !== undefined) sensor.ipAddress = ipAddress;
    if (port !== undefined) sensor.port = port;
    if (asset !== undefined) sensor.asset = asset;
    if (status) sensor.status = status;
    if (capabilities) sensor.capabilities = capabilities;
    if (tags) sensor.tags = tags;
    if (configuration !== undefined) sensor.configuration = configuration;
    sensor.updatedBy = req.user._id;

    await sensor.save();

    // Populate for response
    await sensor.populate('asset', 'name hostname ipAddress');
    await sensor.populate('createdBy', 'username email firstName lastName');
    await sensor.populate('updatedBy', 'username email firstName lastName');

    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: 'Security sensor updated successfully',
      data: sensor
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Delete a security sensor
 */
exports.deleteSensor = async (req, res, next) => {
  try {
    const sensor = await SecuritySensor.findById(req.params.id);

    if (!sensor) {
      throw new AppError('Security sensor not found', HTTP_STATUS.NOT_FOUND, 'SENSOR_NOT_FOUND');
    }

    // Allow Super Admin to delete any sensor, but check org for other roles
    const isSuperAdmin = req.user.role === 'super_admin';
    
    if (!isSuperAdmin && sensor.organization.toString() !== req.user.organization.toString()) {
      throw new AppError('Access denied - Sensor belongs to a different organization', HTTP_STATUS.FORBIDDEN, 'ACCESS_DENIED');
    }

    await sensor.deleteOne();

    res.status(HTTP_STATUS.NO_CONTENT).json({
      success: true,
      message: 'Security sensor deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update sensor heartbeat
 */
exports.updateHeartbeat = async (req, res, next) => {
  try {
    const sensor = await SecuritySensor.findById(req.params.id);

    if (!sensor) {
      throw new AppError('Security sensor not found', HTTP_STATUS.NOT_FOUND, 'SENSOR_NOT_FOUND');
    }

    // Allow Super Admin to update any sensor
    const isSuperAdmin = req.user.role === 'super_admin';
    
    if (!isSuperAdmin && sensor.organization.toString() !== req.user.organization.toString()) {
      throw new AppError('Access denied', HTTP_STATUS.FORBIDDEN, 'ACCESS_DENIED');
    }

    sensor.lastHeartbeat = new Date();
    sensor.status = 'Active';
    sensor.healthScore = Math.min(100, (sensor.healthScore || 0) + 10);
    await sensor.save();

    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: 'Heartbeat updated successfully',
      data: {
        lastHeartbeat: sensor.lastHeartbeat,
        status: sensor.status,
        healthScore: sensor.healthScore
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get sensor statistics
 */
exports.getSensorStats = async (req, res, next) => {
  try {
    const match = { organization: req.user.organization };

    const stats = await SecuritySensor.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          active: {
            $sum: { $cond: [{ $eq: ['$status', 'Active'] }, 1, 0] }
          },
          inactive: {
            $sum: { $cond: [{ $eq: ['$status', 'Inactive'] }, 1, 0] }
          },
          error: {
            $sum: { $cond: [{ $eq: ['$status', 'Error'] }, 1, 0] }
          },
          pending: {
            $sum: { $cond: [{ $eq: ['$status', 'Pending'] }, 1, 0] }
          },
          avgHealthScore: { $avg: '$healthScore' }
        }
      }
    ]);

    // Get breakdown by type
    const typeStats = await SecuritySensor.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: {
        summary: stats[0] || {
          total: 0,
          active: 0,
          inactive: 0,
          error: 0,
          pending: 0,
          avgHealthScore: 0
        },
        typeBreakdown: typeStats
      }
    });
  } catch (error) {
    next(error);
  }
};

// Add this function to get sensor types for dropdown
exports.getTypes = async (req, res, next) => {
  try {
    const types = ['Suricata', 'Zeek', 'Firewall', 'Host Collector', 'Wazuh', 'Snort', 'Custom', 'Other'];
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: types.map(type => ({ value: type, label: type }))
    });
  } catch (error) {
    next(error);
  }
};

// Add this function to get sensor statuses for dropdown
exports.getStatuses = async (req, res, next) => {
  try {
    const statuses = ['Active', 'Inactive', 'Error', 'Pending', 'Degraded'];
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: statuses.map(status => ({ value: status, label: status }))
    });
  } catch (error) {
    next(error);
  }
};