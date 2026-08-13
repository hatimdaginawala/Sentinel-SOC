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

    const query = { organization: req.user.organization };

    if (riskLevel && riskLevel !== 'all') query.riskLevel = riskLevel;
    if (status && status !== 'all') query.status = status;

    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    if (tags) {
      const tagArray = tags.split(',').map(t => t.trim());
      query.tags = { $in: tagArray };
    }

    const skip = (page - 1) * limit;

    const [assessments, total] = await Promise.all([
      SecurityAssessment.find(query)
        .populate('organization', 'name code')
        .populate('threatsDetected', 'title severity status')
        .populate('incidents', 'title severity status')
        .populate('affectedAssets', 'name hostname ipAddress type')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName')
        .populate('reviewedBy', 'username email firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      SecurityAssessment.countDocuments(query)
    ]);

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: assessments,
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
 * Create a new security assessment
 */
exports.createAssessment = async (req, res, next) => {
  try {
    const { title, description, date, assessmentPeriod, tags, riskLevel } = req.body;

    if (!title) {
      throw new AppError('Assessment title is required', HTTP_STATUS.BAD_REQUEST, 'TITLE_REQUIRED');
    }

    const assessmentData = {
      title,
      description: description || '',
      date: date || new Date(),
      riskLevel: riskLevel || 'Medium',
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
    const assessment = await SecurityAssessment.findOne({
      _id: req.params.id,
      organization: req.user.organization
    })
      .populate('organization', 'name code')
      .populate('threatsDetected', 'title severity status sourceIP createdAt')
      .populate('incidents', 'title severity status description createdAt')
      .populate('affectedAssets', 'name hostname ipAddress type criticality status')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName')
      .populate('reviewedBy', 'username email firstName lastName')
      .populate('recommendedControls.implementedBy', 'username email firstName lastName')
      .populate('mitigations.implementedBy', 'username email firstName lastName');

    if (!assessment) {
      throw new AppError('Assessment not found', HTTP_STATUS.NOT_FOUND, 'ASSESSMENT_NOT_FOUND');
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
    if (status) {
      // Validate status transition
      const validTransitions = {
        'Draft': ['In Progress', 'Review'],
        'In Progress': ['Review', 'Final'],
        'Review': ['Final', 'In Progress'],
        'Final': ['Draft', 'Review']
      };
      if (validTransitions[assessment.status] && !validTransitions[assessment.status].includes(status)) {
        throw new AppError(`Invalid status transition from ${assessment.status} to ${status}`, HTTP_STATUS.BAD_REQUEST, 'INVALID_STATUS_TRANSITION');
      }
      assessment.status = status;
      
      if (status === 'Final') {
        assessment.reviewedAt = new Date();
        assessment.reviewedBy = req.user._id;
      }
    }
    if (summary !== undefined) assessment.summary = summary;
    if (tags) assessment.tags = tags;
    if (nextReviewDate) assessment.nextReviewDate = nextReviewDate;
    assessment.updatedBy = req.user._id;

    // Auto-calculate risk score based on risk level
    const riskScoreMap = {
      'Low': 2,
      'Medium': 5,
      'High': 8,
      'Critical': 10
    };
    assessment.riskScore = riskScoreMap[assessment.riskLevel] || 5;

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
    const match = { organization: req.user.organization };

    const stats = await SecurityAssessment.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          draft: {
            $sum: { $cond: [{ $eq: ['$status', 'Draft'] }, 1, 0] }
          },
          inProgress: {
            $sum: { $cond: [{ $eq: ['$status', 'In Progress'] }, 1, 0] }
          },
          review: {
            $sum: { $cond: [{ $eq: ['$status', 'Review'] }, 1, 0] }
          },
          final: {
            $sum: { $cond: [{ $eq: ['$status', 'Final'] }, 1, 0] }
          },
          critical: {
            $sum: { $cond: [{ $eq: ['$riskLevel', 'Critical'] }, 1, 0] }
          },
          high: {
            $sum: { $cond: [{ $eq: ['$riskLevel', 'High'] }, 1, 0] }
          },
          medium: {
            $sum: { $cond: [{ $eq: ['$riskLevel', 'Medium'] }, 1, 0] }
          },
          low: {
            $sum: { $cond: [{ $eq: ['$riskLevel', 'Low'] }, 1, 0] }
          },
          avgRiskScore: { $avg: '$riskScore' }
        }
      }
    ]);

    // Get breakdown by risk level
    const riskStats = await SecurityAssessment.aggregate([
      { $match: match },
      {
        $group: {
          _id: '$riskLevel',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Get total linked entities
    const linkedStats = await SecurityAssessment.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          totalThreats: { $sum: { $size: '$threatsDetected' } },
          totalIncidents: { $sum: { $size: '$incidents' } },
          totalAssets: { $sum: { $size: '$affectedAssets' } },
          totalWeaknesses: { $sum: { $size: '$securityWeaknesses' } },
          totalControls: { $sum: { $size: '$recommendedControls' } },
          totalMitigations: { $sum: { $size: '$mitigations' } }
        }
      }
    ]);

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: {
        summary: stats[0] || {
          total: 0,
          draft: 0,
          inProgress: 0,
          review: 0,
          final: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          avgRiskScore: 0
        },
        riskBreakdown: riskStats,
        linked: linkedStats[0] || {
          totalThreats: 0,
          totalIncidents: 0,
          totalAssets: 0,
          totalWeaknesses: 0,
          totalControls: 0,
          totalMitigations: 0
        }
      }
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

    // Link alerts
    for (const alertId of alertIds) {
      if (!assessment.threatsDetected.includes(alertId)) {
        assessment.threatsDetected.push(alertId);
      }
    }

    // Recalculate risk
    await assessment.calculateRiskLevel();
    assessment.updatedBy = req.user._id;
    await assessment.save();

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

    // Link incidents
    for (const incidentId of incidentIds) {
      if (!assessment.incidents.includes(incidentId)) {
        assessment.incidents.push(incidentId);
      }
    }

    // Recalculate risk
    await assessment.calculateRiskLevel();
    assessment.updatedBy = req.user._id;
    await assessment.save();

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

    // Link assets
    for (const assetId of assetIds) {
      if (!assessment.affectedAssets.includes(assetId)) {
        assessment.affectedAssets.push(assetId);
      }
    }

    assessment.updatedBy = req.user._id;
    await assessment.save();

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

    // Validate status transition
    const validTransitions = {
      'Draft': ['In Progress', 'Review'],
      'In Progress': ['Review', 'Final'],
      'Review': ['Final', 'In Progress'],
      'Final': ['Draft', 'Review']
    };

    if (validTransitions[assessment.status] && !validTransitions[assessment.status].includes(status)) {
      throw new AppError(
        `Invalid status transition from ${assessment.status} to ${status}`,
        HTTP_STATUS.BAD_REQUEST,
        'INVALID_STATUS_TRANSITION'
      );
    }

    assessment.status = status;
    assessment.updatedBy = req.user._id;

    if (status === 'Final') {
      assessment.reviewedAt = new Date();
      assessment.reviewedBy = req.user._id;
    }

    await assessment.save();

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
 * Get risk levels for dropdown
 */
exports.getRiskLevels = async (req, res, next) => {
  try {
    const levels = ['Low', 'Medium', 'High', 'Critical'].map(level => ({
      value: level,
      label: level
    }));
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
    const statuses = ['Draft', 'In Progress', 'Review', 'Final'].map(status => ({
      value: status,
      label: status
    }));
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: statuses
    });
  } catch (error) {
    next(error);
  }
};