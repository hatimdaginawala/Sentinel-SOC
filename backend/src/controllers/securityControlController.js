// controllers/securityControlController.js

const SecurityControl = require('../models/SecurityControl');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');

/**
 * Get all security controls with filtering and pagination
 */
exports.getControls = async (req, res, next) => {
  try {
    const {
      threatRule,
      threatName,
      status,
      riskLevel,
      search,
      tags,
      complianceFrameworks,
      page = 1,
      limit = 20,
      sort = '-createdAt'
    } = req.query;

    const result = await SecurityControl.getControls({
      organization: req.user.organization,
      threatRule,
      threatName,
      status,
      riskLevel,
      search,
      tags: tags ? tags.split(',') : [],
      complianceFrameworks: complianceFrameworks ? complianceFrameworks.split(',') : [],
      page: parseInt(page),
      limit: parseInt(limit),
      sort
    });

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: result.controls,
      pagination: result.pagination
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Create a new security control
 */
exports.createControl = async (req, res, next) => {
  try {
    const {
      threatRule,
      threatName,
      description,
      securityImpact,
      riskLevel,
      recommendedControls,
      mitigations,
      analystActions,
      complianceFrameworks,
      tags,
      references
    } = req.body;

    if (!threatRule) {
      throw new AppError('Threat rule is required', HTTP_STATUS.BAD_REQUEST, 'THREAT_RULE_REQUIRED');
    }

    if (!threatName) {
      throw new AppError('Threat name is required', HTTP_STATUS.BAD_REQUEST, 'THREAT_NAME_REQUIRED');
    }

    const controlData = {
      organization: req.user.organization,
      threatRule,
      threatName,
      description: description || '',
      securityImpact: securityImpact || '',
      riskLevel: riskLevel || 'Medium',
      recommendedControls: recommendedControls || [],
      mitigations: mitigations || [],
      analystActions: analystActions || [],
      complianceFrameworks: complianceFrameworks || [],
      tags: tags || [],
      references: references || [],
      createdBy: req.user._id,
      updatedBy: req.user._id
    };

    const newControl = new SecurityControl(controlData);
    await newControl.save();

    // Populate for response
    await newControl.populate('threatRule', 'name severity category');
    await newControl.populate('createdBy', 'username email firstName lastName');

    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: 'Security control created successfully',
      data: newControl
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get a single security control by ID
 */
exports.getControl = async (req, res, next) => {
  try {
    const control = await SecurityControl.getControlWithPopulated(req.params.id);

    if (!control) {
      throw new AppError('Security control not found', HTTP_STATUS.NOT_FOUND, 'CONTROL_NOT_FOUND');
    }

    // Check organization access
    if (control.organization._id.toString() !== req.user.organization.toString()) {
      throw new AppError('Access denied', HTTP_STATUS.FORBIDDEN, 'ACCESS_DENIED');
    }

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: control
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update a security control
 */
exports.updateControl = async (req, res, next) => {
  try {
    const {
      threatName,
      description,
      securityImpact,
      riskLevel,
      recommendedControls,
      mitigations,
      analystActions,
      complianceFrameworks,
      tags,
      references,
      status
    } = req.body;

    const control = await SecurityControl.findOne({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!control) {
      throw new AppError('Security control not found', HTTP_STATUS.NOT_FOUND, 'CONTROL_NOT_FOUND');
    }

    // Update fields
    if (threatName) control.threatName = threatName;
    if (description !== undefined) control.description = description;
    if (securityImpact !== undefined) control.securityImpact = securityImpact;
    if (riskLevel) control.riskLevel = riskLevel;
    if (recommendedControls) control.recommendedControls = recommendedControls;
    if (mitigations) control.mitigations = mitigations;
    if (analystActions) control.analystActions = analystActions;
    if (complianceFrameworks) control.complianceFrameworks = complianceFrameworks;
    if (tags) control.tags = tags;
    if (references) control.references = references;
    if (status) {
      // Validate status transition
      const validTransitions = {
        'Draft': ['Active'],
        'Active': ['Deprecated', 'Archived'],
        'Deprecated': ['Archived'],
        'Archived': ['Active']
      };
      if (validTransitions[control.status] && !validTransitions[control.status].includes(status)) {
        throw new AppError(
          `Invalid status transition from ${control.status} to ${status}`,
          HTTP_STATUS.BAD_REQUEST,
          'INVALID_STATUS_TRANSITION'
        );
      }
      control.status = status;
    }
    control.updatedBy = req.user._id;

    await control.save();

    // Populate for response
    await control.populate('threatRule', 'name severity category');
    await control.populate('createdBy', 'username email firstName lastName');
    await control.populate('updatedBy', 'username email firstName lastName');

    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: 'Security control updated successfully',
      data: control
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Delete a security control
 */
exports.deleteControl = async (req, res, next) => {
  try {
    const control = await SecurityControl.findOneAndDelete({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!control) {
      throw new AppError('Security control not found', HTTP_STATUS.NOT_FOUND, 'CONTROL_NOT_FOUND');
    }

    res.status(HTTP_STATUS.NO_CONTENT).json({
      success: true,
      message: 'Security control deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get control statistics
 */
exports.getControlStats = async (req, res, next) => {
  try {
    const stats = await SecurityControl.getStatistics(req.user.organization);

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: stats
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Add a recommended control to an existing security control
 */
exports.addRecommendedControl = async (req, res, next) => {
  try {
    const { name, description, priority } = req.body;

    if (!name) {
      throw new AppError('Control name is required', HTTP_STATUS.BAD_REQUEST, 'NAME_REQUIRED');
    }

    const control = await SecurityControl.findOne({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!control) {
      throw new AppError('Security control not found', HTTP_STATUS.NOT_FOUND, 'CONTROL_NOT_FOUND');
    }

    const newControl = {
      name,
      description: description || '',
      priority: priority || 'Medium'
    };

    control.recommendedControls.push(newControl);
    control.updatedBy = req.user._id;
    await control.save();

    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: 'Recommended control added successfully',
      data: control
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update a recommended control status
 */
exports.updateRecommendedControlStatus = async (req, res, next) => {
  try {
    const { controlIndex, status, notes } = req.body;

    if (controlIndex === undefined) {
      throw new AppError('Control index is required', HTTP_STATUS.BAD_REQUEST, 'INDEX_REQUIRED');
    }

    const control = await SecurityControl.findOne({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!control) {
      throw new AppError('Security control not found', HTTP_STATUS.NOT_FOUND, 'CONTROL_NOT_FOUND');
    }

    if (controlIndex >= control.recommendedControls.length) {
      throw new AppError('Control not found', HTTP_STATUS.NOT_FOUND, 'CONTROL_NOT_FOUND');
    }

    const ctrl = control.recommendedControls[controlIndex];
    if (status) {
      const validStatuses = ['Pending', 'In Progress', 'Implemented', 'Verified', 'Not Applicable'];
      if (!validStatuses.includes(status)) {
        throw new AppError('Invalid status', HTTP_STATUS.BAD_REQUEST, 'INVALID_STATUS');
      }
      ctrl.status = status;
      
      if (status === 'Implemented' || status === 'Verified') {
        ctrl.implementationDate = new Date();
        ctrl.implementedBy = req.user._id;
      }
      if (status === 'Verified') {
        ctrl.verifiedBy = req.user._id;
        ctrl.verifiedAt = new Date();
      }
    }
    if (notes) ctrl.notes = notes;

    control.updatedBy = req.user._id;
    await control.save();

    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: 'Control status updated successfully',
      data: control
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Add a mitigation to an existing security control
 */
exports.addMitigation = async (req, res, next) => {
  try {
    const { name, description, priority } = req.body;

    if (!name) {
      throw new AppError('Mitigation name is required', HTTP_STATUS.BAD_REQUEST, 'NAME_REQUIRED');
    }

    const control = await SecurityControl.findOne({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!control) {
      throw new AppError('Security control not found', HTTP_STATUS.NOT_FOUND, 'CONTROL_NOT_FOUND');
    }

    const newMitigation = {
      name,
      description: description || '',
      priority: priority || 'Medium'
    };

    control.mitigations.push(newMitigation);
    control.updatedBy = req.user._id;
    await control.save();

    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: 'Mitigation added successfully',
      data: control
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Add an analyst action to an existing security control
 */
exports.addAnalystAction = async (req, res, next) => {
  try {
    const { name, description, priority } = req.body;

    if (!name) {
      throw new AppError('Action name is required', HTTP_STATUS.BAD_REQUEST, 'NAME_REQUIRED');
    }

    const control = await SecurityControl.findOne({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!control) {
      throw new AppError('Security control not found', HTTP_STATUS.NOT_FOUND, 'CONTROL_NOT_FOUND');
    }

    const newAction = {
      name,
      description: description || '',
      priority: priority || 'Medium'
    };

    control.analystActions.push(newAction);
    control.updatedBy = req.user._id;
    await control.save();

    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: 'Analyst action added successfully',
      data: control
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get priority levels for dropdown
 */
exports.getPriorityLevels = async (req, res, next) => {
  try {
    const levels = await SecurityControl.getPriorityLevels();
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: levels
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get statuses for dropdown
 */
exports.getStatuses = async (req, res, next) => {
  try {
    const statuses = await SecurityControl.getStatuses();
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: statuses
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get control statuses for dropdown
 */
exports.getControlStatuses = async (req, res, next) => {
  try {
    const statuses = await SecurityControl.getControlStatuses();
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: statuses
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get compliance frameworks for dropdown
 */
exports.getComplianceFrameworks = async (req, res, next) => {
  try {
    const frameworks = await SecurityControl.getComplianceFrameworks();
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: frameworks
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get risk levels for dropdown
 */
exports.getRiskLevels = async (req, res, next) => {
  try {
    const levels = await SecurityControl.getRiskLevels();
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: levels
    });
  } catch (error) {
    next(error);
  }
};