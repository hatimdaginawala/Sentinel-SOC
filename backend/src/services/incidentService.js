const Incident = require('../models/Incident');
const Alert = require('../models/Alert');
const User = require('../models/User');
const Organization = require('../models/Organization');
const Asset = require('../models/Asset');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS, SEVERITY, INCIDENT_STATUS } = require('../config/constants');
const logger = require('../config/logger');

class IncidentService {
  /**
   * Create a new incident
   */
  async createIncident(incidentData, createdBy) {
    try {
      // Validate organization
      const organization = await Organization.findById(incidentData.organization);
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Validate alerts if provided
      if (incidentData.alerts && incidentData.alerts.length > 0) {
        const alerts = await Alert.find({ _id: { $in: incidentData.alerts } });
        if (alerts.length !== incidentData.alerts.length) {
          throw new AppError('One or more alerts not found', HTTP_STATUS.NOT_FOUND, 'ALERTS_NOT_FOUND');
        }
      }

      // Set discoveredAt if not provided
      if (!incidentData.discoveredAt) {
        incidentData.discoveredAt = new Date();
      }

      // Create incident
      const incident = new Incident({
        ...incidentData,
        createdBy: createdBy
      });

      await incident.save();

      logger.info(`Incident created: ${incident.title} (${incident.severity}) by ${createdBy}`);

      // If alerts are linked, update them
      if (incident.alerts && incident.alerts.length > 0) {
        await Alert.updateMany(
          { _id: { $in: incident.alerts } },
          { $set: { status: 'investigating' } }
        );
      }

      return await Incident.getIncidentWithPopulated(incident._id);
    } catch (error) {
      logger.error('Error creating incident:', error);
      throw error;
    }
  }

  /**
   * Create incident from alerts
   */
  async createIncidentFromAlerts(alertIds, incidentData, createdBy) {
    try {
      // Get alerts
      const alerts = await Alert.find({ _id: { $in: alertIds } });
      if (alerts.length === 0) {
        throw new AppError('No valid alerts found', HTTP_STATUS.NOT_FOUND, 'ALERTS_NOT_FOUND');
      }

      // Determine severity from alerts
      const maxSeverity = alerts.reduce((max, alert) => {
        const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
        return severityOrder.indexOf(alert.severity) > severityOrder.indexOf(max) ? alert.severity : max;
      }, 'low');

      // Determine category from alerts
      const categories = alerts.map(a => a.category);
      const mostCommonCategory = categories.reduce((acc, curr) => {
        acc[curr] = (acc[curr] || 0) + 1;
        return acc;
      }, {});
      const category = Object.keys(mostCommonCategory).reduce((a, b) => 
        mostCommonCategory[a] > mostCommonCategory[b] ? a : b
      );

      // Create incident data
      const incidentDataWithDefaults = {
        organization: incidentData.organization || alerts[0].organization,
        title: incidentData.title || `Security Incident - ${category} (${alerts.length} alerts)`,
        description: incidentData.description || `Security incident involving ${alerts.length} alerts`,
        severity: incidentData.severity || maxSeverity,
        category: incidentData.category || category,
        alerts: alertIds,
        detectionSource: incidentData.detectionSource || 'automated',
        discoveredAt: incidentData.discoveredAt || new Date(),
        ...incidentData
      };

      return await this.createIncident(incidentDataWithDefaults, createdBy);
    } catch (error) {
      logger.error('Error creating incident from alerts:', error);
      throw error;
    }
  }

  /**
   * Get incident by ID
   */
  async getIncidentById(incidentId) {
    try {
      const incident = await Incident.getIncidentWithPopulated(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      return incident;
    } catch (error) {
      logger.error('Error getting incident:', error);
      throw error;
    }
  }

  /**
   * Get incidents with pagination and filtering
   */
  async getIncidents(filters = {}) {
    try {
      const result = await Incident.getIncidents(filters);
      return result;
    } catch (error) {
      logger.error('Error getting incidents:', error);
      throw error;
    }
  }

  /**
   * Get incidents by organization
   */
  async getIncidentsByOrganization(organizationId, options = {}) {
    try {
      const result = await Incident.findByOrganization(organizationId, options);
      return result;
    } catch (error) {
      logger.error('Error getting incidents by organization:', error);
      throw error;
    }
  }

  /**
   * Get incidents assigned to user
   */
  async getIncidentsAssignedToUser(userId, options = {}) {
    try {
      const result = await Incident.findByAssignedUser(userId, options);
      return result;
    } catch (error) {
      logger.error('Error getting incidents assigned to user:', error);
      throw error;
    }
  }

  /**
   * Get incident statistics
   */
  async getIncidentStatistics(organizationId = null, timeRange = '30d') {
    try {
      const stats = await Incident.getStatistics(organizationId, timeRange);
      return stats;
    } catch (error) {
      logger.error('Error getting incident statistics:', error);
      throw error;
    }
  }

  /**
   * Update incident
   */
  async updateIncident(incidentId, updateData, updatedBy) {
    try {
      const incident = await Incident.findById(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      // Validate alerts if being updated
      if (updateData.alerts) {
        const alerts = await Alert.find({ _id: { $in: updateData.alerts } });
        if (alerts.length !== updateData.alerts.length) {
          throw new AppError('One or more alerts not found', HTTP_STATUS.NOT_FOUND, 'ALERTS_NOT_FOUND');
        }
      }

      // Update incident
      const updatedIncident = await Incident.findByIdAndUpdate(
        incidentId,
        {
          ...updateData,
          updatedBy: updatedBy,
          updatedAt: new Date()
        },
        {
          new: true,
          runValidators: true
        }
      )
      .populate('organization', 'name code')
      .populate('assignedTo', 'username email firstName lastName')
      .populate('createdBy', 'username email')
      .populate('updatedBy', 'username email');

      logger.info(`Incident updated: ${updatedIncident.title} by ${updatedBy}`);

      return await Incident.getIncidentWithPopulated(updatedIncident._id);
    } catch (error) {
      logger.error('Error updating incident:', error);
      throw error;
    }
  }

  /**
   * Assign incident to user
   */
  async assignIncident(incidentId, userId, assignedBy) {
    try {
      const incident = await Incident.findById(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      const user = await User.findById(userId);
      if (!user) {
        throw new AppError('User not found', HTTP_STATUS.NOT_FOUND, 'USER_NOT_FOUND');
      }

      await incident.assignTo(userId, assignedBy);

      logger.info(`Incident ${incidentId} assigned to user ${userId} by ${assignedBy}`);

      return await Incident.getIncidentWithPopulated(incident._id);
    } catch (error) {
      logger.error('Error assigning incident:', error);
      throw error;
    }
  }

  /**
   * Update incident status
   */
  async updateIncidentStatus(incidentId, newStatus, userId, note = '') {
    try {
      const incident = await Incident.findById(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      await incident.updateStatus(newStatus, userId, note);

      logger.info(`Incident ${incidentId} status updated to ${newStatus} by ${userId}`);

      return await Incident.getIncidentWithPopulated(incident._id);
    } catch (error) {
      logger.error('Error updating incident status:', error);
      throw error;
    }
  }

  /**
   * Add timeline entry to incident
   */
  async addTimeline(incidentId, action, note, userId, metadata = {}) {
    try {
      const incident = await Incident.findById(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      await incident.addTimeline(action, note, userId, metadata);

      logger.info(`Timeline entry added to incident ${incidentId} by ${userId}`);

      return await Incident.getIncidentWithPopulated(incident._id);
    } catch (error) {
      logger.error('Error adding timeline entry:', error);
      throw error;
    }
  }

  /**
   * Add evidence to incident
   */
  async addEvidence(incidentId, evidenceData, uploadedBy) {
    try {
      const incident = await Incident.findById(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      await incident.addEvidence(evidenceData, uploadedBy);

      logger.info(`Evidence added to incident ${incidentId} by ${uploadedBy}`);

      return await Incident.getIncidentWithPopulated(incident._id);
    } catch (error) {
      logger.error('Error adding evidence:', error);
      throw error;
    }
  }

  /**
   * Add affected asset to incident
   */
  async addAffectedAsset(incidentId, assetId, impact = 'affected', notes = '') {
    try {
      const incident = await Incident.findById(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      const asset = await Asset.findById(assetId);
      if (!asset) {
        throw new AppError('Asset not found', HTTP_STATUS.NOT_FOUND, 'ASSET_NOT_FOUND');
      }

      await incident.addAffectedAsset(assetId, impact, notes);

      logger.info(`Affected asset ${assetId} added to incident ${incidentId}`);

      return await Incident.getIncidentWithPopulated(incident._id);
    } catch (error) {
      logger.error('Error adding affected asset:', error);
      throw error;
    }
  }

  /**
   * Add containment measure
   */
  async addContainmentMeasure(incidentId, measure, implementedBy, effectiveness = 'effective') {
    try {
      const incident = await Incident.findById(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      await incident.addContainmentMeasure(measure, implementedBy, effectiveness);

      logger.info(`Containment measure added to incident ${incidentId}`);

      return await Incident.getIncidentWithPopulated(incident._id);
    } catch (error) {
      logger.error('Error adding containment measure:', error);
      throw error;
    }
  }

  /**
   * Escalate incident
   */
  async escalateIncident(incidentId, userId, escalateTo, reason = '') {
    try {
      const incident = await Incident.findById(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      const targetUser = await User.findById(escalateTo);
      if (!targetUser) {
        throw new AppError('Target user not found', HTTP_STATUS.NOT_FOUND, 'USER_NOT_FOUND');
      }

      await incident.escalate(userId, escalateTo, reason);

      logger.info(`Incident ${incidentId} escalated to ${escalateTo} by ${userId}`);

      return await Incident.getIncidentWithPopulated(incident._id);
    } catch (error) {
      logger.error('Error escalating incident:', error);
      throw error;
    }
  }

  /**
   * Resolve incident
   */
  async resolveIncident(incidentId, userId, resolutionStatus, summary = '', steps = [], lessonsLearned = '') {
    try {
      const incident = await Incident.findById(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      await incident.resolve(userId, resolutionStatus, summary, steps, lessonsLearned);

      logger.info(`Incident ${incidentId} resolved by ${userId}`);

      return await Incident.getIncidentWithPopulated(incident._id);
    } catch (error) {
      logger.error('Error resolving incident:', error);
      throw error;
    }
  }

  /**
   * Close incident
   */
  async closeIncident(incidentId, userId, note = '') {
    try {
      const incident = await Incident.findById(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      await incident.close(userId, note);

      logger.info(`Incident ${incidentId} closed by ${userId}`);

      return await Incident.getIncidentWithPopulated(incident._id);
    } catch (error) {
      logger.error('Error closing incident:', error);
      throw error;
    }
  }

  /**
   * Reopen incident
   */
  async reopenIncident(incidentId, userId, reason = '') {
    try {
      const incident = await Incident.findById(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      await incident.reopen(userId, reason);

      logger.info(`Incident ${incidentId} reopened by ${userId}`);

      return await Incident.getIncidentWithPopulated(incident._id);
    } catch (error) {
      logger.error('Error reopening incident:', error);
      throw error;
    }
  }

  /**
   * Delete incident
   */
  async deleteIncident(incidentId, deletedBy) {
    try {
      const incident = await Incident.findById(incidentId);
      
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      await incident.remove();

      logger.info(`Incident deleted: ${incidentId} by ${deletedBy}`);

      return { success: true, message: 'Incident deleted successfully' };
    } catch (error) {
      logger.error('Error deleting incident:', error);
      throw error;
    }
  }

  /**
   * Search incidents
   */
  async searchIncidents(query, organizationId = null, options = {}) {
    try {
      const result = await Incident.searchIncidents(query, organizationId, options);
      return result;
    } catch (error) {
      logger.error('Error searching incidents:', error);
      throw error;
    }
  }

  /**
   * Get incident categories for dropdown
   */
  getIncidentCategories() {
    return Incident.getCategories();
  }

  /**
   * Get resolution statuses for dropdown
   */
  getResolutionStatuses() {
    return Incident.getResolutionStatuses();
  }

  /**
   * Get detection sources for dropdown
   */
  getDetectionSources() {
    return Incident.getDetectionSources();
  }

  /**
   * Get containment effectiveness levels
   */
  getContainmentEffectiveness() {
    return Incident.getContainmentEffectiveness();
  }

  /**
   * Get severity levels for dropdown
   */
  getSeverityLevels() {
    return Object.values(SEVERITY).map(severity => ({
      value: severity,
      label: severity.charAt(0).toUpperCase() + severity.slice(1)
    }));
  }

  /**
   * Get incident statuses for dropdown
   */
  getIncidentStatuses() {
    return Object.values(INCIDENT_STATUS).map(status => ({
      value: status,
      label: status.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  }

  /**
   * Get open incidents count
   */
  async getOpenIncidentsCount(organizationId = null) {
    try {
      const query = { 
        status: { $in: ['new', 'investigating', 'in_progress'] }
      };
      if (organizationId) query.organization = organizationId;
      
      return await Incident.countDocuments(query);
    } catch (error) {
      logger.error('Error getting open incidents count:', error);
      throw error;
    }
  }

  /**
   * Get incidents by date range
   */
  async getIncidentsByDateRange(organizationId = null, startDate, endDate) {
    try {
      const query = {};
      if (organizationId) query.organization = organizationId;
      if (startDate || endDate) {
        query.createdAt = {};
        if (startDate) query.createdAt.$gte = new Date(startDate);
        if (endDate) query.createdAt.$lte = new Date(endDate);
      }
      
      return await Incident.find(query)
        .populate('organization', 'name code')
        .populate('assignedTo', 'username email')
        .sort({ createdAt: -1 });
    } catch (error) {
      logger.error('Error getting incidents by date range:', error);
      throw error;
    }
  }
}

module.exports = new IncidentService();