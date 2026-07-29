const Organization = require('../models/Organization');
const User = require('../models/User');
const Asset = require('../models/Asset');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');
const logger = require('../config/logger');

class OrganizationService {
  /**
   * Create a new organization
   */
  async createOrganization(orgData, createdBy) {
    try {
      // Check if organization name already exists
      const existingOrg = await Organization.findOne({ 
        name: orgData.name 
      });
      if (existingOrg) {
        throw new AppError(
          'Organization with this name already exists',
          HTTP_STATUS.CONFLICT,
          'ORGANIZATION_EXISTS'
        );
      }

      // Check if code is provided and unique
      if (orgData.code) {
        const existingCode = await Organization.findOne({ 
          code: orgData.code.toUpperCase() 
        });
        if (existingCode) {
          throw new AppError(
            'Organization with this code already exists',
            HTTP_STATUS.CONFLICT,
            'ORGANIZATION_CODE_EXISTS'
          );
        }
      }

      // Generate code if not provided
      if (!orgData.code) {
        const baseCode = orgData.name.substring(0, 3).toUpperCase();
        let code = baseCode;
        let counter = 1;
        let exists = true;
        
        while (exists) {
          const existing = await Organization.findOne({ code });
          if (!existing) {
            exists = false;
          } else {
            code = `${baseCode}${counter}`;
            counter++;
          }
        }
        orgData.code = code;
      }

      // Set subscription defaults
      if (!orgData.subscription) {
        orgData.subscription = {
          plan: 'free',
          startDate: new Date(),
          isActive: true
        };
      }

      // Create organization
      const organization = new Organization({
        ...orgData,
        createdBy: createdBy
      });

      await organization.save();

      logger.info(`Organization created: ${organization.name} (${organization.code}) by ${createdBy}`);

      return await Organization.getOrganizationWithPopulated(organization._id);
    } catch (error) {
      logger.error('Error creating organization:', error);
      throw error;
    }
  }

  /**
   * Get organization by ID
   */
  async getOrganizationById(orgId) {
    try {
      const organization = await Organization.getOrganizationWithPopulated(orgId);
      
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      return organization;
    } catch (error) {
      logger.error('Error getting organization:', error);
      throw error;
    }
  }

  /**
   * Get organization by code
   */
  async getOrganizationByCode(code) {
    try {
      const organization = await Organization.findOne({ 
        code: code.toUpperCase() 
      })
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName');
      
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      return organization;
    } catch (error) {
      logger.error('Error getting organization by code:', error);
      throw error;
    }
  }

  /**
   * Get all organizations with pagination and filtering
   */
  async getOrganizations(filters = {}, options = {}) {
    try {
      const {
        search,
        status,
        industry,
        plan,
        page = 1,
        limit = 20,
        sort = '-createdAt'
      } = filters;

      const query = {};

      // Apply filters
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: 'i' } },
          { code: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } },
          { 'address.city': { $regex: search, $options: 'i' } },
          { 'address.country': { $regex: search, $options: 'i' } }
        ];
      }

      if (status && status !== 'all') {
        query.status = status;
      }

      if (industry && industry !== 'all') {
        query.industry = industry;
      }

      if (plan && plan !== 'all') {
        query['subscription.plan'] = plan;
      }

      const skip = (page - 1) * limit;

      const [organizations, total] = await Promise.all([
        Organization.find(query)
          .populate('createdBy', 'username email firstName lastName')
          .populate('updatedBy', 'username email firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        Organization.countDocuments(query)
      ]);

      return {
        organizations,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting organizations:', error);
      throw error;
    }
  }

  /**
   * Get active organizations (for dropdowns)
   */
  async getActiveOrganizations() {
    try {
      const organizations = await Organization.find({ 
        status: 'active',
        'subscription.isActive': true
      })
      .sort({ name: 1 })
      .select('name code industry size');
      
      return organizations;
    } catch (error) {
      logger.error('Error getting active organizations:', error);
      throw error;
    }
  }

  /**
   * Update organization
   */
  async updateOrganization(orgId, updateData, updatedBy) {
    try {
      const organization = await Organization.findById(orgId);
      
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Check if name is being changed and validate uniqueness
      if (updateData.name && updateData.name !== organization.name) {
        const existingOrg = await Organization.findOne({ 
          name: updateData.name,
          _id: { $ne: orgId }
        });
        if (existingOrg) {
          throw new AppError(
            'Organization with this name already exists',
            HTTP_STATUS.CONFLICT,
            'ORGANIZATION_EXISTS'
          );
        }
      }

      // Check if code is being changed and validate uniqueness
      if (updateData.code && updateData.code !== organization.code) {
        const existingCode = await Organization.findOne({ 
          code: updateData.code.toUpperCase(),
          _id: { $ne: orgId }
        });
        if (existingCode) {
          throw new AppError(
            'Organization with this code already exists',
            HTTP_STATUS.CONFLICT,
            'ORGANIZATION_CODE_EXISTS'
          );
        }
      }

      // Update organization
      const updatedOrg = await Organization.findByIdAndUpdate(
        orgId,
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
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName');

      logger.info(`Organization updated: ${updatedOrg.name} (${updatedOrg.code}) by ${updatedBy}`);

      return updatedOrg;
    } catch (error) {
      logger.error('Error updating organization:', error);
      throw error;
    }
  }

  /**
   * Delete organization (soft delete)
   */
  async deleteOrganization(orgId, deletedBy) {
    try {
      const organization = await Organization.findById(orgId);
      
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Check if organization has users
      const userCount = await User.countDocuments({ organization: orgId });
      if (userCount > 0) {
        throw new AppError(
          `Cannot delete organization. It has ${userCount} user(s) assigned`,
          HTTP_STATUS.CONFLICT,
          'ORGANIZATION_HAS_USERS'
        );
      }

      // Check if organization has assets
      const assetCount = await Asset.countDocuments({ organization: orgId });
      if (assetCount > 0) {
        throw new AppError(
          `Cannot delete organization. It has ${assetCount} asset(s) assigned`,
          HTTP_STATUS.CONFLICT,
          'ORGANIZATION_HAS_ASSETS'
        );
      }

      // Soft delete by setting status to inactive
      organization.status = 'inactive';
      organization.updatedBy = deletedBy;
      organization.updatedAt = new Date();
      await organization.save();

      logger.info(`Organization deleted (soft): ${organization.name} (${organization.code}) by ${deletedBy}`);

      return { success: true, message: 'Organization deleted successfully' };
    } catch (error) {
      logger.error('Error deleting organization:', error);
      throw error;
    }
  }

  /**
   * Hard delete organization (permanent)
   */
  async hardDeleteOrganization(orgId, deletedBy) {
    try {
      const organization = await Organization.findById(orgId);
      
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Check if organization has users
      const userCount = await User.countDocuments({ organization: orgId });
      if (userCount > 0) {
        throw new AppError(
          `Cannot delete organization. It has ${userCount} user(s) assigned`,
          HTTP_STATUS.CONFLICT,
          'ORGANIZATION_HAS_USERS'
        );
      }

      // Check if organization has assets
      const assetCount = await Asset.countDocuments({ organization: orgId });
      if (assetCount > 0) {
        throw new AppError(
          `Cannot delete organization. It has ${assetCount} asset(s) assigned`,
          HTTP_STATUS.CONFLICT,
          'ORGANIZATION_HAS_ASSETS'
        );
      }

      await organization.remove();

      logger.info(`Organization hard deleted: ${organization.name} (${organization.code}) by ${deletedBy}`);

      return { success: true, message: 'Organization permanently deleted' };
    } catch (error) {
      logger.error('Error hard deleting organization:', error);
      throw error;
    }
  }

  /**
   * Get organization statistics
   */
  async getOrganizationStatistics() {
    try {
      const stats = await Organization.getOrganizationStatistics();
      return stats;
    } catch (error) {
      logger.error('Error getting organization statistics:', error);
      throw error;
    }
  }

  /**
   * Get organization usage statistics
   */
  async getOrganizationUsage(orgId) {
    try {
      const usage = await Organization.getUsageStatistics(orgId);
      if (!usage) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Get actual counts from other services
      const userCount = await User.countDocuments({ 
        organization: orgId,
        status: 'active'
      });
      
      const assetCount = await Asset.countDocuments({ 
        organization: orgId,
        status: 'active'
      });

      return {
        ...usage,
        userCount,
        assetCount,
        userUtilization: Math.round((userCount / usage.limits.maxUsers) * 100),
        assetUtilization: Math.round((assetCount / usage.limits.maxAssets) * 100)
      };
    } catch (error) {
      logger.error('Error getting organization usage:', error);
      throw error;
    }
  }

  /**
   * Update organization subscription
   */
  async updateSubscription(orgId, subscriptionData, updatedBy) {
    try {
      const organization = await Organization.findById(orgId);
      
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Update subscription
      organization.subscription = {
        ...organization.subscription,
        ...subscriptionData,
        updatedAt: new Date()
      };
      organization.updatedBy = updatedBy;
      organization.updatedAt = new Date();
      
      await organization.save();

      logger.info(`Subscription updated for organization: ${organization.name} by ${updatedBy}`);

      return organization;
    } catch (error) {
      logger.error('Error updating subscription:', error);
      throw error;
    }
  }

  /**
   * Get organizations with expiring subscriptions
   */
  async getExpiringSubscriptions(daysThreshold = 30) {
    try {
      const organizations = await Organization.getExpiringSubscriptions(daysThreshold);
      return organizations;
    } catch (error) {
      logger.error('Error getting expiring subscriptions:', error);
      throw error;
    }
  }

  /**
   * Get organizations with expired subscriptions
   */
  async getExpiredSubscriptions() {
    try {
      const organizations = await Organization.getExpiredSubscriptions();
      return organizations;
    } catch (error) {
      logger.error('Error getting expired subscriptions:', error);
      throw error;
    }
  }

  /**
   * Check if organization can add more users
   */
  async canAddUsers(orgId, additionalUsers = 1) {
    try {
      const organization = await Organization.findById(orgId);
      
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      const currentUsers = await User.countDocuments({ 
        organization: orgId,
        status: 'active'
      });

      const newTotal = currentUsers + additionalUsers;
      const canAdd = newTotal <= organization.settings.maxUsers;

      return {
        canAdd,
        currentUsers,
        maxUsers: organization.settings.maxUsers,
        available: organization.settings.maxUsers - currentUsers,
        wouldExceed: newTotal > organization.settings.maxUsers
      };
    } catch (error) {
      logger.error('Error checking user capacity:', error);
      throw error;
    }
  }

  /**
   * Check if organization can add more assets
   */
  async canAddAssets(orgId, additionalAssets = 1) {
    try {
      const organization = await Organization.findById(orgId);
      
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      const currentAssets = await Asset.countDocuments({ 
        organization: orgId,
        status: 'active'
      });

      const newTotal = currentAssets + additionalAssets;
      const canAdd = newTotal <= organization.settings.maxAssets;

      return {
        canAdd,
        currentAssets,
        maxAssets: organization.settings.maxAssets,
        available: organization.settings.maxAssets - currentAssets,
        wouldExceed: newTotal > organization.settings.maxAssets
      };
    } catch (error) {
      logger.error('Error checking asset capacity:', error);
      throw error;
    }
  }
}

module.exports = new OrganizationService();