const IOC = require('../models/IOC');
const Organization = require('../models/Organization');
const Incident = require('../models/Incident');
const Alert = require('../models/Alert');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');
const logger = require('../config/logger');

class IOCService {
  /**
   * Create a new IOC
   */
  async createIOC(iocData, createdBy) {
    try {
      // Validate organization
      const organization = await Organization.findById(iocData.organization);
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Check if IOC already exists
      const existingIOC = await IOC.findOne({
        value: iocData.value,
        type: iocData.type,
        organization: iocData.organization
      });

      if (existingIOC) {
        throw new AppError(
          'IOC with this value and type already exists',
          HTTP_STATUS.CONFLICT,
          'IOC_EXISTS'
        );
      }

      // Create IOC
      const ioc = new IOC({
        ...iocData,
        createdBy: createdBy
      });

      await ioc.save();

      logger.info(`IOC created: ${ioc.indicator} (${ioc.type}) by ${createdBy}`);

      return await this.getIOCById(ioc._id);
    } catch (error) {
      logger.error('Error creating IOC:', error);
      throw error;
    }
  }

  /**
   * Bulk create IOCs
   */
  async bulkCreateIOCs(iocsData, createdBy) {
    try {
      const created = [];
      const errors = [];

      for (const iocData of iocsData) {
        try {
          const ioc = await this.createIOC(iocData, createdBy);
          created.push(ioc);
        } catch (error) {
          errors.push({
            data: iocData,
            error: error.message
          });
        }
      }

      return {
        created,
        errors,
        total: iocsData.length,
        successful: created.length,
        failed: errors.length
      };
    } catch (error) {
      logger.error('Error bulk creating IOCs:', error);
      throw error;
    }
  }

  /**
   * Get IOC by ID
   */
  async getIOCById(iocId) {
    try {
      const ioc = await IOC.findById(iocId)
        .populate('organization', 'name code')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName')
        .populate('relatedIOCs', 'type value indicator severity status')
        .populate('incidents', 'title severity status')
        .populate('alerts', 'title severity status');

      if (!ioc) {
        throw new AppError('IOC not found', HTTP_STATUS.NOT_FOUND, 'IOC_NOT_FOUND');
      }

      return ioc;
    } catch (error) {
      logger.error('Error getting IOC:', error);
      throw error;
    }
  }

  /**
   * Get IOCs with pagination and filtering
   */
  async getIOCs(filters = {}) {
    try {
      const result = await IOC.getIOCs(filters);
      return result;
    } catch (error) {
      logger.error('Error getting IOCs:', error);
      throw error;
    }
  }

  /**
   * Get IOCs by organization
   */
  async getIOCsByOrganization(organizationId, options = {}) {
    try {
      const { limit = 50, page = 1, sort = '-createdAt' } = options;
      const skip = (page - 1) * limit;

      const [iocs, total] = await Promise.all([
        IOC.find({ organization: organizationId })
          .populate('createdBy', 'username email')
          .populate('incidents', 'title severity status')
          .sort(sort)
          .skip(skip)
          .limit(limit),
        IOC.countDocuments({ organization: organizationId })
      ]);

      return {
        iocs,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting IOCs by organization:', error);
      throw error;
    }
  }

  /**
   * Get active IOCs
   */
  async getActiveIOCs(organizationId = null) {
    try {
      const iocs = await IOC.getActiveIOCs(organizationId);
      return iocs;
    } catch (error) {
      logger.error('Error getting active IOCs:', error);
      throw error;
    }
  }

  /**
   * Get IOC statistics
   */
  async getIOCStatistics(organizationId = null) {
    try {
      const stats = await IOC.getStatistics(organizationId);
      return stats;
    } catch (error) {
      logger.error('Error getting IOC statistics:', error);
      throw error;
    }
  }

  /**
   * Update IOC
   */
  async updateIOC(iocId, updateData, updatedBy) {
    try {
      const ioc = await IOC.findById(iocId);

      if (!ioc) {
        throw new AppError('IOC not found', HTTP_STATUS.NOT_FOUND, 'IOC_NOT_FOUND');
      }

      // Check if value/type conflict
      if (updateData.value || updateData.type) {
        const existingIOC = await IOC.findOne({
          value: updateData.value || ioc.value,
          type: updateData.type || ioc.type,
          organization: ioc.organization,
          _id: { $ne: iocId }
        });

        if (existingIOC) {
          throw new AppError(
            'IOC with this value and type already exists',
            HTTP_STATUS.CONFLICT,
            'IOC_EXISTS'
          );
        }
      }

      // Update IOC
      const updatedIOC = await IOC.findByIdAndUpdate(
        iocId,
        {
          ...updateData,
          updatedBy: updatedBy,
          lastUpdated: new Date()
        },
        {
          new: true,
          runValidators: true
        }
      )
      .populate('organization', 'name code')
      .populate('createdBy', 'username email')
      .populate('updatedBy', 'username email');

      logger.info(`IOC updated: ${updatedIOC.indicator} by ${updatedBy}`);

      return updatedIOC;
    } catch (error) {
      logger.error('Error updating IOC:', error);
      throw error;
    }
  }

  /**
   * Delete IOC
   */
  async deleteIOC(iocId, deletedBy) {
    try {
      const ioc = await IOC.findById(iocId);

      if (!ioc) {
        throw new AppError('IOC not found', HTTP_STATUS.NOT_FOUND, 'IOC_NOT_FOUND');
      }

      await ioc.remove();

      logger.info(`IOC deleted: ${iocId} by ${deletedBy}`);

      return { success: true, message: 'IOC deleted successfully' };
    } catch (error) {
      logger.error('Error deleting IOC:', error);
      throw error;
    }
  }

  /**
   * Record occurrence for IOC
   */
  async recordOccurrence(iocId, sourceIP = null) {
    try {
      const ioc = await IOC.findById(iocId);

      if (!ioc) {
        throw new AppError('IOC not found', HTTP_STATUS.NOT_FOUND, 'IOC_NOT_FOUND');
      }

      await ioc.recordOccurrence(sourceIP);

      logger.debug(`Occurrence recorded for IOC: ${ioc.indicator}`);

      return ioc;
    } catch (error) {
      logger.error('Error recording IOC occurrence:', error);
      throw error;
    }
  }

  /**
   * Link IOC to incident
   */
  async linkToIncident(iocId, incidentId) {
    try {
      const ioc = await IOC.findById(iocId);
      if (!ioc) {
        throw new AppError('IOC not found', HTTP_STATUS.NOT_FOUND, 'IOC_NOT_FOUND');
      }

      const incident = await Incident.findById(incidentId);
      if (!incident) {
        throw new AppError('Incident not found', HTTP_STATUS.NOT_FOUND, 'INCIDENT_NOT_FOUND');
      }

      await ioc.linkToIncident(incidentId);

      logger.info(`IOC ${iocId} linked to incident ${incidentId}`);

      return await this.getIOCById(iocId);
    } catch (error) {
      logger.error('Error linking IOC to incident:', error);
      throw error;
    }
  }

  /**
   * Link IOC to alert
   */
  async linkToAlert(iocId, alertId) {
    try {
      const ioc = await IOC.findById(iocId);
      if (!ioc) {
        throw new AppError('IOC not found', HTTP_STATUS.NOT_FOUND, 'IOC_NOT_FOUND');
      }

      const alert = await Alert.findById(alertId);
      if (!alert) {
        throw new AppError('Alert not found', HTTP_STATUS.NOT_FOUND, 'ALERT_NOT_FOUND');
      }

      await ioc.linkToAlert(alertId);

      logger.info(`IOC ${iocId} linked to alert ${alertId}`);

      return await this.getIOCById(iocId);
    } catch (error) {
      logger.error('Error linking IOC to alert:', error);
      throw error;
    }
  }

  /**
   * Link IOCs to incident
   */
  async linkIOCsToIncident(iocIds, incidentId) {
    try {
      const results = [];
      for (const iocId of iocIds) {
        try {
          const result = await this.linkToIncident(iocId, incidentId);
          results.push({ iocId, success: true });
        } catch (error) {
          results.push({ iocId, success: false, error: error.message });
        }
      }
      return results;
    } catch (error) {
      logger.error('Error linking IOCs to incident:', error);
      throw error;
    }
  }

  /**
   * Get IOCs by incident
   */
  async getIOCsByIncident(incidentId) {
    try {
      const iocs = await IOC.findByIncident(incidentId);
      return iocs;
    } catch (error) {
      logger.error('Error getting IOCs by incident:', error);
      throw error;
    }
  }

  /**
   * Search IOCs
   */
  async searchIOCs(query, organizationId = null, options = {}) {
    try {
      const result = await IOC.searchIOCs(query, organizationId, options);
      return result;
    } catch (error) {
      logger.error('Error searching IOCs:', error);
      throw error;
    }
  }

  /**
   * Find IOC by value
   */
  async findIOCByValue(type, value, organizationId = null) {
    try {
      const ioc = await IOC.findByValue(type, value, organizationId);
      return ioc;
    } catch (error) {
      logger.error('Error finding IOC by value:', error);
      throw error;
    }
  }

  /**
   * Check if value matches any IOC
   */
  async checkMatches(value, organizationId = null) {
    try {
      const query = { status: 'active' };
      if (organizationId) query.organization = organizationId;

      const iocs = await IOC.find(query);
      const matches = [];

      for (const ioc of iocs) {
        if (ioc.matches(value)) {
          matches.push(ioc);
        }
      }

      return matches;
    } catch (error) {
      logger.error('Error checking IOC matches:', error);
      throw error;
    }
  }

  /**
   * Expire IOC
   */
  async expireIOC(iocId) {
    try {
      const ioc = await IOC.findById(iocId);
      if (!ioc) {
        throw new AppError('IOC not found', HTTP_STATUS.NOT_FOUND, 'IOC_NOT_FOUND');
      }

      await ioc.expire();

      logger.info(`IOC expired: ${ioc.indicator}`);

      return await this.getIOCById(iocId);
    } catch (error) {
      logger.error('Error expiring IOC:', error);
      throw error;
    }
  }

  /**
   * Reactivate IOC
   */
  async reactivateIOC(iocId) {
    try {
      const ioc = await IOC.findById(iocId);
      if (!ioc) {
        throw new AppError('IOC not found', HTTP_STATUS.NOT_FOUND, 'IOC_NOT_FOUND');
      }

      await ioc.reactivate();

      logger.info(`IOC reactivated: ${ioc.indicator}`);

      return await this.getIOCById(iocId);
    } catch (error) {
      logger.error('Error reactivating IOC:', error);
      throw error;
    }
  }

  /**
   * Get IOC types for dropdown
   */
  getIOCTypes() {
    return IOC.getTypes();
  }

  /**
   * Get IOC statuses for dropdown
   */
  getIOCStatuses() {
    return IOC.getStatuses();
  }

  /**
   * Get IOC sources for dropdown
   */
  getIOCSources() {
    return IOC.getSources();
  }

  /**
   * Get threat types for dropdown
   */
  getThreatTypes() {
    return IOC.getThreatTypes();
  }

  /**
   * Get severity levels for dropdown
   */
  getSeverityLevels() {
    return IOC.getSeverityLevels();
  }

  /**
   * Import IOCs from threat intelligence feed
   */
  async importFromFeed(feedData, organizationId, createdBy) {
    try {
      const imported = [];
      const errors = [];

      for (const item of feedData) {
        try {
          const iocData = {
            organization: organizationId,
            type: item.type,
            value: item.value,
            indicator: item.indicator || item.value,
            description: item.description || '',
            severity: item.severity || 'medium',
            confidence: item.confidence || 70,
            source: 'threat_intelligence',
            sourceReference: item.sourceReference || '',
            threatType: item.threatType,
            tags: item.tags || [],
            firstSeen: item.firstSeen ? new Date(item.firstSeen) : new Date(),
            expiresAt: item.expiresAt ? new Date(item.expiresAt) : null
          };

          const ioc = await this.createIOC(iocData, createdBy);
          imported.push(ioc);
        } catch (error) {
          errors.push({
            item,
            error: error.message
          });
        }
      }

      return {
        imported,
        errors,
        total: feedData.length,
        successful: imported.length,
        failed: errors.length
      };
    } catch (error) {
      logger.error('Error importing IOCs from feed:', error);
      throw error;
    }
  }

  /**
   * Export IOCs
   */
  async exportIOCs(filters = {}) {
    try {
      const { iocs } = await IOC.getIOCs({ ...filters, limit: 1000 });
      
      return iocs.map(ioc => ({
        type: ioc.type,
        value: ioc.value,
        indicator: ioc.indicator,
        description: ioc.description,
        severity: ioc.severity,
        confidence: ioc.confidence,
        threatType: ioc.threatType,
        tags: ioc.tags,
        firstSeen: ioc.firstSeen,
        lastSeen: ioc.lastSeen,
        status: ioc.status
      }));
    } catch (error) {
      logger.error('Error exporting IOCs:', error);
      throw error;
    }
  }
}

module.exports = new IOCService();