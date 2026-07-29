const Asset = require('../models/Asset');
const Organization = require('../models/Organization');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');
const logger = require('../config/logger');

class AssetService {
  /**
   * Create a new asset
   */
  async createAsset(assetData, createdBy) {
    try {
      // Check if organization exists
      const organization = await Organization.findById(assetData.organization);
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Check if asset name already exists in organization
      const existingAsset = await Asset.findOne({
        name: assetData.name,
        organization: assetData.organization
      });
      if (existingAsset) {
        throw new AppError(
          'Asset with this name already exists in the organization',
          HTTP_STATUS.CONFLICT,
          'ASSET_EXISTS'
        );
      }

      // Set default monitoring
      if (!assetData.monitoring) {
        assetData.monitoring = {
          enabled: true,
          healthStatus: 'healthy'
        };
      }

      // Set default security
      if (!assetData.security) {
        assetData.security = {
          vulnerabilityCount: 0,
          riskScore: 0,
          complianceStatus: 'unknown'
        };
      }

      // Create asset
      const asset = new Asset({
        ...assetData,
        createdBy: createdBy
      });

      await asset.save();

      logger.info(`Asset created: ${asset.name} (${asset.type}) by ${createdBy}`);

      return await Asset.getAssetWithPopulated(asset._id);
    } catch (error) {
      logger.error('Error creating asset:', error);
      throw error;
    }
  }

  /**
   * Get asset by ID
   */
  async getAssetById(assetId) {
    try {
      const asset = await Asset.getAssetWithPopulated(assetId);
      
      if (!asset) {
        throw new AppError('Asset not found', HTTP_STATUS.NOT_FOUND, 'ASSET_NOT_FOUND');
      }

      return asset;
    } catch (error) {
      logger.error('Error getting asset:', error);
      throw error;
    }
  }

  /**
   * Get assets by organization with pagination and filtering
   */
  async getAssetsByOrganization(organizationId, filters = {}) {
    try {
      const {
        status,
        type,
        criticality,
        search,
        page = 1,
        limit = 20,
        sort = '-updatedAt'
      } = filters;

      const query = { organization: organizationId };

      if (status && status !== 'all') {
        query.status = status;
      }

      if (type && type !== 'all') {
        query.type = type;
      }

      if (criticality && criticality !== 'all') {
        query.criticality = criticality;
      }

      if (search) {
        query.$or = [
          { name: { $regex: search, $options: 'i' } },
          { hostname: { $regex: search, $options: 'i' } },
          { ipAddress: { $regex: search, $options: 'i' } },
          { location: { $regex: search, $options: 'i' } },
          { department: { $regex: search, $options: 'i' } },
          { owner: { $regex: search, $options: 'i' } },
          { tags: { $in: [new RegExp(search, 'i')] } }
        ];
      }

      const skip = (page - 1) * limit;

      const [assets, total] = await Promise.all([
        Asset.find(query)
          .populate('createdBy', 'username email firstName lastName')
          .populate('updatedBy', 'username email firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        Asset.countDocuments(query)
      ]);

      return {
        assets,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting assets by organization:', error);
      throw error;
    }
  }

  /**
   * Get all assets (admin only)
   */
  async getAllAssets(filters = {}) {
    try {
      const {
        organization,
        status,
        type,
        criticality,
        search,
        page = 1,
        limit = 20,
        sort = '-updatedAt'
      } = filters;

      const query = {};

      if (organization && organization !== 'all') {
        query.organization = organization;
      }

      if (status && status !== 'all') {
        query.status = status;
      }

      if (type && type !== 'all') {
        query.type = type;
      }

      if (criticality && criticality !== 'all') {
        query.criticality = criticality;
      }

      if (search) {
        query.$or = [
          { name: { $regex: search, $options: 'i' } },
          { hostname: { $regex: search, $options: 'i' } },
          { ipAddress: { $regex: search, $options: 'i' } },
          { location: { $regex: search, $options: 'i' } },
          { department: { $regex: search, $options: 'i' } },
          { owner: { $regex: search, $options: 'i' } },
          { tags: { $in: [new RegExp(search, 'i')] } }
        ];
      }

      const skip = (page - 1) * limit;

      const [assets, total] = await Promise.all([
        Asset.find(query)
          .populate('organization', 'name code')
          .populate('createdBy', 'username email firstName lastName')
          .populate('updatedBy', 'username email firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        Asset.countDocuments(query)
      ]);

      return {
        assets,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting all assets:', error);
      throw error;
    }
  }

  /**
   * Update asset
   */
  async updateAsset(assetId, updateData, updatedBy) {
    try {
      const asset = await Asset.findById(assetId);
      
      if (!asset) {
        throw new AppError('Asset not found', HTTP_STATUS.NOT_FOUND, 'ASSET_NOT_FOUND');
      }

      // Check if name is being changed and validate uniqueness
      if (updateData.name && updateData.name !== asset.name) {
        const existingAsset = await Asset.findOne({
          name: updateData.name,
          organization: asset.organization,
          _id: { $ne: assetId }
        });
        if (existingAsset) {
          throw new AppError(
            'Asset with this name already exists in the organization',
            HTTP_STATUS.CONFLICT,
            'ASSET_EXISTS'
          );
        }
      }

      // Update asset
      const updatedAsset = await Asset.findByIdAndUpdate(
        assetId,
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
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName');

      logger.info(`Asset updated: ${updatedAsset.name} by ${updatedBy}`);

      return updatedAsset;
    } catch (error) {
      logger.error('Error updating asset:', error);
      throw error;
    }
  }

  /**
   * Update asset risk score
   */
  async updateAssetRiskScore(assetId) {
    try {
      const asset = await Asset.findById(assetId);
      
      if (!asset) {
        throw new AppError('Asset not found', HTTP_STATUS.NOT_FOUND, 'ASSET_NOT_FOUND');
      }

      const newScore = await asset.updateRiskScore();
      
      logger.info(`Asset risk score updated: ${asset.name} - ${newScore}`);

      return {
        asset: asset.name,
        riskScore: newScore
      };
    } catch (error) {
      logger.error('Error updating asset risk score:', error);
      throw error;
    }
  }

  /**
   * Delete asset (soft delete)
   */
  async deleteAsset(assetId, deletedBy) {
    try {
      const asset = await Asset.findById(assetId);
      
      if (!asset) {
        throw new AppError('Asset not found', HTTP_STATUS.NOT_FOUND, 'ASSET_NOT_FOUND');
      }

      // Soft delete by setting status to inactive
      asset.status = 'inactive';
      asset.updatedBy = deletedBy;
      asset.updatedAt = new Date();
      await asset.save();

      logger.info(`Asset deleted (soft): ${asset.name} by ${deletedBy}`);

      return { success: true, message: 'Asset deleted successfully' };
    } catch (error) {
      logger.error('Error deleting asset:', error);
      throw error;
    }
  }

  /**
   * Hard delete asset (permanent)
   */
  async hardDeleteAsset(assetId, deletedBy) {
    try {
      const asset = await Asset.findById(assetId);
      
      if (!asset) {
        throw new AppError('Asset not found', HTTP_STATUS.NOT_FOUND, 'ASSET_NOT_FOUND');
      }

      await asset.remove();

      logger.info(`Asset hard deleted: ${asset.name} by ${deletedBy}`);

      return { success: true, message: 'Asset permanently deleted' };
    } catch (error) {
      logger.error('Error hard deleting asset:', error);
      throw error;
    }
  }

  /**
   * Get asset statistics
   */
  async getAssetStatistics(organizationId = null) {
    try {
      const stats = await Asset.getStatistics(organizationId);
      return stats;
    } catch (error) {
      logger.error('Error getting asset statistics:', error);
      throw error;
    }
  }

  /**
   * Get assets by type
   */
  async getAssetsByType(type, organizationId = null) {
    try {
      const assets = await Asset.findByType(type, organizationId);
      return assets;
    } catch (error) {
      logger.error('Error getting assets by type:', error);
      throw error;
    }
  }

  /**
   * Get assets by criticality
   */
  async getAssetsByCriticality(criticality, organizationId = null) {
    try {
      const assets = await Asset.findByCriticality(criticality, organizationId);
      return assets;
    } catch (error) {
      logger.error('Error getting assets by criticality:', error);
      throw error;
    }
  }

  /**
   * Get assets with vulnerabilities
   */
  async getAssetsWithVulnerabilities(organizationId = null) {
    try {
      const assets = await Asset.findWithVulnerabilities(organizationId);
      return assets;
    } catch (error) {
      logger.error('Error getting assets with vulnerabilities:', error);
      throw error;
    }
  }

  /**
   * Get assets needing patching
   */
  async getAssetsNeedingPatching(organizationId = null) {
    try {
      const assets = await Asset.findNeedingPatching(organizationId);
      return assets;
    } catch (error) {
      logger.error('Error getting assets needing patching:', error);
      throw error;
    }
  }

  /**
   * Search assets
   */
  async searchAssets(query, organizationId = null, options = {}) {
    try {
      const result = await Asset.searchAssets(query, organizationId, options);
      return result;
    } catch (error) {
      logger.error('Error searching assets:', error);
      throw error;
    }
  }

  /**
   * Bulk create assets
   */
  async bulkCreateAssets(assetsData, createdBy) {
    try {
      const createdAssets = [];
      const errors = [];

      for (const assetData of assetsData) {
        try {
          // Check if organization exists
          const organization = await Organization.findById(assetData.organization);
          if (!organization) {
            errors.push({
              asset: assetData,
              error: 'Organization not found'
            });
            continue;
          }

          // Check if asset already exists
          const existingAsset = await Asset.findOne({
            name: assetData.name,
            organization: assetData.organization
          });

          if (existingAsset) {
            errors.push({
              asset: assetData,
              error: 'Asset already exists in organization'
            });
            continue;
          }

          const asset = new Asset({
            ...assetData,
            createdBy: createdBy
          });

          await asset.save();
          createdAssets.push(asset);
        } catch (error) {
          errors.push({
            asset: assetData,
            error: error.message
          });
        }
      }

      logger.info(`Bulk assets created: ${createdAssets.length} successful, ${errors.length} failed`);

      return {
        created: createdAssets,
        errors: errors,
        total: assetsData.length,
        successful: createdAssets.length,
        failed: errors.length
      };
    } catch (error) {
      logger.error('Error bulk creating assets:', error);
      throw error;
    }
  }

  /**
   * Get asset types (for dropdowns)
   */
  getAssetTypes() {
    const { ASSET_TYPES } = require('../config/constants');
    return Object.values(ASSET_TYPES).map(type => ({
      value: type,
      label: type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));
  }

  /**
   * Get asset criticalities (for dropdowns)
   */
  getAssetCriticalities() {
    return ['low', 'medium', 'high', 'critical'].map(value => ({
      value,
      label: value.charAt(0).toUpperCase() + value.slice(1)
    }));
  }

  /**
   * Get asset statuses (for dropdowns)
   */
  getAssetStatuses() {
    return ['active', 'inactive', 'maintenance', 'decommissioned', 'compromised'].map(value => ({
      value,
      label: value.charAt(0).toUpperCase() + value.slice(1)
    }));
  }
}

module.exports = new AssetService();