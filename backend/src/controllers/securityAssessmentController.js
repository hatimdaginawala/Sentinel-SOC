// controllers/securityAssessmentController.js

const SecurityAssessment = require('../models/SecurityAssessment');
const Alert = require('../models/Alert');
const Incident = require('../models/Incident');
const Asset = require('../models/Asset');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');

/**
 * Get all security assessments with filtering and pagination
 */
exports.getAssessments = async (req, res, next) => {
  try {
    const {
      riskLevel,
      status,
      search,
      startDate,
      endDate,
      tags,
      page = 1,
      limit = 20,
      sort = '-createdAt'
    } = req.query;

    const result = await SecurityAssessment.getAssessments({
      organization: req.user.organization,
      riskLevel,
      status,
      search,
      startDate,
      endDate,
      tags: tags ? tags.split(',') : [],
      page: parseInt(page),
      limit: parseInt(limit),
      sort
    });

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: result.assessments,
      pagination: result.pagination
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Create a new security assessment
 */
exports.createAssessment = async (req, res, next) => {
  try {
    const { title, description, date, assessmentPeriod, tags } = req.body;

    if (!title) {
      throw new AppError('Assessment title is required', HTTP_STATUS.BAD_REQUEST, 'TITLE_REQUIRED');
    }

    const assessmentData = {
      title,
      description: description || '',
      date: date || new Date(),
      organization: req.user.organization,
      createdBy: req.user._id,
      updatedBy: req.user._id,
      tags: tags || []
    };

    // Set assessment period
    if (assessmentPeriod) {
      assessmentData.assessmentPeriod = {
        startDate: assessmentPeriod.startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        endDate: assessmentPeriod.endDate || new Date()
      };
    }

    const newAssessment = new SecurityAssessment(assessmentData);
    await newAssessment.save();

    // Populate for response
    await newAssessment.populate('createdBy', 'username email firstName lastName');

    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: 'Security assessment created successfully',
      data: newAssessment
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get a single security assessment by ID
 */
exports.getAssessment = async (req, res, next) => {
  try {
    const assessment = await SecurityAssessment.getAssessmentWithPopulated(req.params.id);

    if (!assessment) {
      throw new AppError('Assessment not found', HTTP_STATUS.NOT_FOUND, 'ASSESSMENT_NOT_FOUND');
    }

    // Check organization access
    if (assessment.organization._id.toString() !== req.user.organization.toString()) {
      throw new AppError('Access denied', HTTP_STATUS.FORBIDDEN, 'ACCESS_DENIED');
    }

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: assessment
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update a security assessment
 */
exports.updateAssessment = async (req, res, next) => {
  try {
    const { 
      title, 
      description, 
      date, 
      assessmentPeriod, 
      riskLevel, 
      securityWeaknesses,
      recommendedControls,
      mitigations,
      status,
      summary,
      tags,
      nextReviewDate
    } = req.body;

    const assessment = await SecurityAssessment.findOne({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!assessment) {
      throw new AppError('Assessment not found', HTTP_STATUS.NOT_FOUND, 'ASSESSMENT_NOT_FOUND');
    }

    // Update fields
    if (title) assessment.title = title;
    if (description !== undefined) assessment.description = description;
    if (date) assessment.date = date;
    if (assessmentPeriod) {
      assessment.assessmentPeriod = {
        startDate: assessmentPeriod.startDate || assessment.assessmentPeriod.startDate,
        endDate: assessmentPeriod.endDate || assessment.assessmentPeriod.endDate
      };
    }
    if (riskLevel) assessment.riskLevel = riskLevel;
    if (securityWeaknesses) assessment.securityWeaknesses = securityWeaknesses;
    if (recommendedControls) assessment.recommendedControls = recommendedControls;
    if (mitigations) assessment.mitigations = mitigations;
    if (status) assessment.status = status;
    if (summary !== undefined) assessment.summary = summary;
    if (tags) assessment.tags = tags;
    if (nextReviewDate) assessment.nextReviewDate = nextReviewDate;
    assessment.updatedBy = req.user._id;

    await assessment.save();

    // Populate for response
    await assessment.populate('createdBy', 'username email firstName lastName');
    await assessment.populate('updatedBy', 'username email firstName lastName');
    await assessment.populate('threatsDetected', 'title severity status');
    await assessment.populate('incidents', 'title severity status');
    await assessment.populate('affectedAssets', 'name hostname ipAddress');

    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: 'Assessment updated successfully',
      data: assessment
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Delete a security assessment
 */
exports.deleteAssessment = async (req, res, next) => {
  try {
    const assessment = await SecurityAssessment.findOneAndDelete({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!assessment) {
      throw new AppError('Assessment not found', HTTP_STATUS.NOT_FOUND, 'ASSESSMENT_NOT_FOUND');
    }

    res.status(HTTP_STATUS.NO_CONTENT).json({
      success: true,
      message: 'Assessment deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get assessment statistics
 */
exports.getAssessmentStats = async (req, res, next) => {
  try {
    const stats = await SecurityAssessment.getStatistics(req.user.organization);

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: stats
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Link threats (alerts) to assessment
 */
exports.linkThreats = async (req, res, next) => {
  try {
    const { alertIds } = req.body;

    if (!alertIds || !Array.isArray(alertIds) || alertIds.length === 0) {
      throw new AppError('At least one alert ID is required', HTTP_STATUS.BAD_REQUEST, 'ALERT_IDS_REQUIRED');
    }

    const assessment = await SecurityAssessment.findOne({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!assessment) {
      throw new AppError('Assessment not found', HTTP_STATUS.NOT_FOUND, 'ASSESSMENT_NOT_FOUND');
    }

    // Verify alerts exist and belong to the organization
    const alerts = await Alert.find({
      _id: { $in: alertIds },
      organization: req.user.organization
    });

    if (alerts.length !== alertIds.length) {
      throw new AppError('Some alerts not found or do not belong to your organization', HTTP_STATUS.BAD_REQUEST, 'INVALID_ALERTS');
    }

    await assessment.linkThreats(alertIds);
    await assessment.calculateRiskLevel();

    await assessment.populate('threatsDetected', 'title severity status');

    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: 'Threats linked successfully',
      data: assessment
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Link incidents to assessment
 */
exports.linkIncidents = async (req, res, next) => {
  try {
    const { incidentIds } = req.body;

    if (!incidentIds || !Array.isArray(incidentIds) || incidentIds.length === 0) {
      throw new AppError('At least one incident ID is required', HTTP_STATUS.BAD_REQUEST, 'INCIDENT_IDS_REQUIRED');
    }

    const assessment = await SecurityAssessment.findOne({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!assessment) {
      throw new AppError('Assessment not found', HTTP_STATUS.NOT_FOUND, 'ASSESSMENT_NOT_FOUND');
    }

    // Verify incidents exist and belong to the organization
    const incidents = await Incident.find({
      _id: { $in: incidentIds },
      organization: req.user.organization
    });

    if (incidents.length !== incidentIds.length) {
      throw new AppError('Some incidents not found or do not belong to your organization', HTTP_STATUS.BAD_REQUEST, 'INVALID_INCIDENTS');
    }

    await assessment.linkIncidents(incidentIds);
    await assessment.calculateRiskLevel();

    await assessment.populate('incidents', 'title severity status');

    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: 'Incidents linked successfully',
      data: assessment
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Link assets to assessment
 */
exports.linkAssets = async (req, res, next) => {
  try {
    const { assetIds } = req.body;

    if (!assetIds || !Array.isArray(assetIds) || assetIds.length === 0) {
      throw new AppError('At least one asset ID is required', HTTP_STATUS.BAD_REQUEST, 'ASSET_IDS_REQUIRED');
    }

    const assessment = await SecurityAssessment.findOne({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!assessment) {
      throw new AppError('Assessment not found', HTTP_STATUS.NOT_FOUND, 'ASSESSMENT_NOT_FOUND');
    }

    // Verify assets exist and belong to the organization
    const assets = await Asset.find({
      _id: { $in: assetIds },
      organization: req.user.organization
    });

    if (assets.length !== assetIds.length) {
      throw new AppError('Some assets not found or do not belong to your organization', HTTP_STATUS.BAD_REQUEST, 'INVALID_ASSETS');
    }

    await assessment.linkAssets(assetIds);

    await assessment.populate('affectedAssets', 'name hostname ipAddress');

    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: 'Assets linked successfully',
      data: assessment
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update assessment status
 */
exports.updateStatus = async (req, res, next) => {
  try {
    const { status } = req.body;

    if (!status) {
      throw new AppError('Status is required', HTTP_STATUS.BAD_REQUEST, 'STATUS_REQUIRED');
    }

    const assessment = await SecurityAssessment.findOne({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!assessment) {
      throw new AppError('Assessment not found', HTTP_STATUS.NOT_FOUND, 'ASSESSMENT_NOT_FOUND');
    }

    await assessment.updateStatus(status, req.user._id);

    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: `Assessment status updated to ${status}`,
      data: assessment
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Calculate risk level for assessment
 */
exports.calculateRisk = async (req, res, next) => {
  try {
    const assessment = await SecurityAssessment.findOne({
      _id: req.params.id,
      organization: req.user.organization
    });

    if (!assessment) {
      throw new AppError('Assessment not found', HTTP_STATUS.NOT_FOUND, 'ASSESSMENT_NOT_FOUND');
    }

    await assessment.calculateRiskLevel();

    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: 'Risk level calculated successfully',
      data: {
        riskLevel: assessment.riskLevel,
        riskScore: assessment.riskScore
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get assessment types for dropdown
 */
exports.getRiskLevels = async (req, res, next) => {
  try {
    const levels = await SecurityAssessment.getRiskLevels();
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: levels
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get assessment statuses for dropdown
 */
exports.getStatuses = async (req, res, next) => {
  try {
    const statuses = await SecurityAssessment.getStatuses();
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: statuses
    });
  } catch (error) {
    next(error);
  }
};