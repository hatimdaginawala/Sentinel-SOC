const LogSource = require('../models/LogSource');
const Organization = require('../models/Organization');
const Asset = require('../models/Asset');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');
const logger = require('../config/logger');
const crypto = require('crypto');

class LogSourceService {
  /**
   * Create a new log source
   */
  async createLogSource(sourceData, createdBy) {
    try {
      // Check if organization exists
      const organization = await Organization.findById(sourceData.organization);
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Check if asset exists
      const asset = await Asset.findById(sourceData.asset);
      if (!asset) {
        throw new AppError('Asset not found', HTTP_STATUS.NOT_FOUND, 'ASSET_NOT_FOUND');
      }

      // Check if source name already exists in organization
      const existingSource = await LogSource.findOne({
        sourceName: sourceData.sourceName,
        organization: sourceData.organization
      });
      if (existingSource) {
        throw new AppError(
          'Log source with this name already exists in the organization',
          HTTP_STATUS.CONFLICT,
          'LOG_SOURCE_EXISTS'
        );
      }

      // Generate authentication token
      const authToken = crypto.randomBytes(32).toString('hex');

      // Create log source
      const logSource = new LogSource({
        ...sourceData,
        authenticationToken: authToken,
        createdBy: createdBy
      });

      await logSource.save();

      logger.info(`Log source created: ${logSource.sourceName} (${logSource.sourceType}) by ${createdBy}`);

      return await LogSource.getWithPopulated(logSource._id);
    } catch (error) {
      logger.error('Error creating log source:', error);
      throw error;
    }
  }

  /**
   * Get log source by ID
   */
  async getLogSourceById(sourceId) {
    try {
      const logSource = await LogSource.getWithPopulated(sourceId);
      
      if (!logSource) {
        throw new AppError('Log source not found', HTTP_STATUS.NOT_FOUND, 'LOG_SOURCE_NOT_FOUND');
      }

      return logSource;
    } catch (error) {
      logger.error('Error getting log source:', error);
      throw error;
    }
  }

  /**
   * Get log sources by organization
   */
  async getLogSourcesByOrganization(organizationId, filters = {}) {
    try {
      const {
        status,
        sourceType,
        search,
        page = 1,
        limit = 20,
        sort = '-createdAt'
      } = filters;

      const query = { organization: organizationId };

      if (status && status !== 'all') {
        query.status = status;
      }

      if (sourceType && sourceType !== 'all') {
        query.sourceType = sourceType;
      }

      if (search) {
        query.$or = [
          { sourceName: { $regex: search, $options: 'i' } },
          { hostname: { $regex: search, $options: 'i' } },
          { ipAddress: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } }
        ];
      }

      const skip = (page - 1) * limit;

      const [sources, total] = await Promise.all([
        LogSource.find(query)
          .populate('asset', 'name hostname ipAddress type criticality')
          .populate('createdBy', 'username email firstName lastName')
          .populate('updatedBy', 'username email firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        LogSource.countDocuments(query)
      ]);

      return {
        sources,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting log sources by organization:', error);
      throw error;
    }
  }

  /**
   * Get all log sources (admin only)
   */
  async getAllLogSources(filters = {}) {
    try {
      const {
        organization,
        status,
        sourceType,
        search,
        page = 1,
        limit = 20,
        sort = '-createdAt'
      } = filters;

      const query = {};

      if (organization && organization !== 'all') {
        query.organization = organization;
      }

      if (status && status !== 'all') {
        query.status = status;
      }

      if (sourceType && sourceType !== 'all') {
        query.sourceType = sourceType;
      }

      if (search) {
        query.$or = [
          { sourceName: { $regex: search, $options: 'i' } },
          { hostname: { $regex: search, $options: 'i' } },
          { ipAddress: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } }
        ];
      }

      const skip = (page - 1) * limit;

      const [sources, total] = await Promise.all([
        LogSource.find(query)
          .populate('organization', 'name code')
          .populate('asset', 'name hostname ipAddress type criticality')
          .populate('createdBy', 'username email firstName lastName')
          .populate('updatedBy', 'username email firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        LogSource.countDocuments(query)
      ]);

      return {
        sources,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting all log sources:', error);
      throw error;
    }
  }

  /**
   * Update log source
   */
  async updateLogSource(sourceId, updateData, updatedBy) {
    try {
      const logSource = await LogSource.findById(sourceId);
      
      if (!logSource) {
        throw new AppError('Log source not found', HTTP_STATUS.NOT_FOUND, 'LOG_SOURCE_NOT_FOUND');
      }

      // Check if source name is being changed and validate uniqueness
      if (updateData.sourceName && updateData.sourceName !== logSource.sourceName) {
        const existingSource = await LogSource.findOne({
          sourceName: updateData.sourceName,
          organization: logSource.organization,
          _id: { $ne: sourceId }
        });
        if (existingSource) {
          throw new AppError(
            'Log source with this name already exists in the organization',
            HTTP_STATUS.CONFLICT,
            'LOG_SOURCE_EXISTS'
          );
        }
      }

      // Check if asset exists if being changed
      if (updateData.asset && updateData.asset !== logSource.asset) {
        const asset = await Asset.findById(updateData.asset);
        if (!asset) {
          throw new AppError('Asset not found', HTTP_STATUS.NOT_FOUND, 'ASSET_NOT_FOUND');
        }
      }

      // Update log source
      const updatedSource = await LogSource.findByIdAndUpdate(
        sourceId,
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
      .populate('asset', 'name hostname ipAddress type criticality')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName');

      logger.info(`Log source updated: ${updatedSource.sourceName} by ${updatedBy}`);

      return updatedSource;
    } catch (error) {
      logger.error('Error updating log source:', error);
      throw error;
    }
  }

  /**
   * Update log source status
   */
  async updateStatus(sourceId, status, updatedBy) {
    try {
      const logSource = await LogSource.findById(sourceId);
      
      if (!logSource) {
        throw new AppError('Log source not found', HTTP_STATUS.NOT_FOUND, 'LOG_SOURCE_NOT_FOUND');
      }

      logSource.status = status;
      logSource.updatedBy = updatedBy;
      logSource.updatedAt = new Date();
      await logSource.save();

      logger.info(`Log source status updated: ${logSource.sourceName} -> ${status} by ${updatedBy}`);

      return await LogSource.getWithPopulated(logSource._id);
    } catch (error) {
      logger.error('Error updating log source status:', error);
      throw error;
    }
  }

  /**
   * Update heartbeat
   */
  async updateHeartbeat(sourceId) {
    try {
      const logSource = await LogSource.findById(sourceId);
      
      if (!logSource) {
        throw new AppError('Log source not found', HTTP_STATUS.NOT_FOUND, 'LOG_SOURCE_NOT_FOUND');
      }

      await logSource.updateHeartbeat();

      logger.debug(`Heartbeat updated for log source: ${logSource.sourceName}`);

      return {
        success: true,
        message: 'Heartbeat updated successfully',
        lastHeartbeat: logSource.lastHeartbeat
      };
    } catch (error) {
      logger.error('Error updating heartbeat:', error);
      throw error;
    }
  }

  /**
   * Regenerate authentication token
   */
  async regenerateToken(sourceId, updatedBy) {
    try {
      const logSource = await LogSource.findById(sourceId);
      
      if (!logSource) {
        throw new AppError('Log source not found', HTTP_STATUS.NOT_FOUND, 'LOG_SOURCE_NOT_FOUND');
      }

      const newToken = await logSource.regenerateToken();
      logSource.updatedBy = updatedBy;
      await logSource.save();

      logger.info(`Authentication token regenerated for log source: ${logSource.sourceName} by ${updatedBy}`);

      return {
        success: true,
        authenticationToken: newToken,
        message: 'Authentication token regenerated successfully'
      };
    } catch (error) {
      logger.error('Error regenerating token:', error);
      throw error;
    }
  }

  /**
   * Delete log source (soft delete by setting status to Offline)
   */
  async deleteLogSource(sourceId, deletedBy) {
    try {
      const logSource = await LogSource.findById(sourceId);
      
      if (!logSource) {
        throw new AppError('Log source not found', HTTP_STATUS.NOT_FOUND, 'LOG_SOURCE_NOT_FOUND');
      }

      // Soft delete by setting status to Offline
      logSource.status = 'Offline';
      logSource.updatedBy = deletedBy;
      logSource.updatedAt = new Date();
      await logSource.save();

      logger.info(`Log source deleted (soft): ${logSource.sourceName} by ${deletedBy}`);

      return { success: true, message: 'Log source deleted successfully' };
    } catch (error) {
      logger.error('Error deleting log source:', error);
      throw error;
    }
  }

  /**
   * Hard delete log source (permanent)
   */
  async hardDeleteLogSource(sourceId, deletedBy) {
    try {
      const logSource = await LogSource.findById(sourceId);
      
      if (!logSource) {
        throw new AppError('Log source not found', HTTP_STATUS.NOT_FOUND, 'LOG_SOURCE_NOT_FOUND');
      }

      // Check if logs exist for this source
      const Log = require('../models/Log');
      const logCount = await Log.countDocuments({ logSource: sourceId });
      if (logCount > 0) {
        throw new AppError(
          `Cannot delete log source. It has ${logCount} log(s) associated`,
          HTTP_STATUS.CONFLICT,
          'LOG_SOURCE_HAS_LOGS'
        );
      }

      await logSource.remove();

      logger.info(`Log source hard deleted: ${logSource.sourceName} by ${deletedBy}`);

      return { success: true, message: 'Log source permanently deleted' };
    } catch (error) {
      logger.error('Error hard deleting log source:', error);
      throw error;
    }
  }

  /**
   * Get log source statistics
   */
  async getLogSourceStatistics(organizationId = null) {
    try {
      const stats = await LogSource.getStatistics(organizationId);
      return stats;
    } catch (error) {
      logger.error('Error getting log source statistics:', error);
      throw error;
    }
  }

  /**
   * Search log sources
   */
  async searchLogSources(query, organizationId = null, options = {}) {
    try {
      const result = await LogSource.searchSources(query, organizationId, options);
      return result;
    } catch (error) {
      logger.error('Error searching log sources:', error);
      throw error;
    }
  }

  /**
   * Get online log sources
   */
  async getOnlineSources() {
    try {
      const sources = await LogSource.findOnline();
      return sources;
    } catch (error) {
      logger.error('Error getting online log sources:', error);
      throw error;
    }
  }

  /**
   * Check stale heartbeats and update status
   */
  async checkStaleHeartbeats(thresholdMinutes = 5) {
    try {
      const staleSources = await LogSource.findStaleHeartbeats(thresholdMinutes);
      
      const updated = [];
      for (const source of staleSources) {
        if (source.status === 'Online') {
          source.status = 'Offline';
          await source.save();
          updated.push(source.sourceName);
        }
      }

      if (updated.length > 0) {
        logger.warn(`Marked ${updated.length} log sources as offline due to stale heartbeat: ${updated.join(', ')}`);
      }

      return {
        staleCount: staleSources.length,
        updated: updated
      };
    } catch (error) {
      logger.error('Error checking stale heartbeats:', error);
      throw error;
    }
  }

  /**
   * Validate log source authentication
   */
  async validateSource(sourceId, token) {
    try {
      const logSource = await LogSource.findById(sourceId).select('+authenticationToken');
      
      if (!logSource) {
        throw new AppError('Log source not found', HTTP_STATUS.NOT_FOUND, 'LOG_SOURCE_NOT_FOUND');
      }

      // Check if source is active
      if (!logSource.isActive()) {
        throw new AppError('Log source is not active', HTTP_STATUS.FORBIDDEN, 'LOG_SOURCE_INACTIVE');
      }

      // Validate token
      if (!logSource.validateToken(token)) {
        throw new AppError('Invalid authentication token', HTTP_STATUS.UNAUTHORIZED, 'INVALID_TOKEN');
      }

      // Update heartbeat
      await logSource.updateHeartbeat();

      return {
        valid: true,
        source: logSource
      };
    } catch (error) {
      logger.error('Error validating log source:', error);
      throw error;
    }
  }

  /**
   * Get source types (for dropdowns)
   */
  getSourceTypes() {
    return LogSource.getSourceTypes();
  }

  /**
   * Get protocols (for dropdowns)
   */
  getProtocols() {
    return LogSource.getProtocols();
  }

  /**
   * Get statuses (for dropdowns)
   */
  getStatuses() {
    return LogSource.getStatuses();
  }
}

module.exports = new LogSourceService();