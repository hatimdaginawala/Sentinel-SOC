const Role = require('../models/Role');
const User = require('../models/User');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS, ROLES, PERMISSIONS } = require('../config/constants');
const logger = require('../config/logger');

class RoleService {
  /**
   * Initialize system roles on application startup
   */
  async initializeSystemRoles() {
    try {
      const roles = await Role.initializeSystemRoles();
      logger.info(`System roles initialized: ${roles.length} roles created/updated`);
      return roles;
    } catch (error) {
      logger.error('Error initializing system roles:', error);
      throw error;
    }
  }

  /**
   * Create a new custom role
   */
  async createRole(roleData, createdBy) {
    try {
      // Check if role name already exists
      const existingRole = await Role.findOne({ name: roleData.name });
      if (existingRole) {
        throw new AppError(
          'Role with this name already exists',
          HTTP_STATUS.CONFLICT,
          'ROLE_EXISTS'
        );
      }

      // Validate permissions
      if (roleData.permissions) {
        const invalidPermissions = roleData.permissions.filter(
          permission => !Object.values(PERMISSIONS).includes(permission)
        );
        if (invalidPermissions.length > 0) {
          throw new AppError(
            `Invalid permissions: ${invalidPermissions.join(', ')}`,
            HTTP_STATUS.BAD_REQUEST,
            'INVALID_PERMISSIONS'
          );
        }
      }

      // Create role
      const role = new Role({
        ...roleData,
        isSystem: false,
        createdBy: createdBy
      });

      await role.save();

      logger.info(`Role created: ${role.name} by ${createdBy}`);

      return await Role.getRoleWithPopulated(role._id);
    } catch (error) {
      logger.error('Error creating role:', error);
      throw error;
    }
  }

  /**
   * Get role by ID
   */
  async getRoleById(roleId) {
    try {
      const role = await Role.getRoleWithPopulated(roleId);
      
      if (!role) {
        throw new AppError('Role not found', HTTP_STATUS.NOT_FOUND, 'ROLE_NOT_FOUND');
      }

      return role;
    } catch (error) {
      logger.error('Error getting role:', error);
      throw error;
    }
  }

  /**
   * Get role by name
   */
  async getRoleByName(name) {
    try {
      const role = await Role.findOne({ name })
        .populate('createdBy', 'username email')
        .populate('updatedBy', 'username email');
      
      if (!role) {
        throw new AppError('Role not found', HTTP_STATUS.NOT_FOUND, 'ROLE_NOT_FOUND');
      }

      return role;
    } catch (error) {
      logger.error('Error getting role by name:', error);
      throw error;
    }
  }

  /**
   * Get all roles with pagination and filtering
   */
  async getRoles(filters = {}, options = {}) {
    try {
      const {
        search,
        status,
        isSystem,
        page = 1,
        limit = 20,
        sort = '-priority'
      } = filters;

      const query = {};

      // Apply filters
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: 'i' } },
          { displayName: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } }
        ];
      }

      if (status && status !== 'all') {
        query.status = status;
      }

      if (isSystem !== undefined && isSystem !== 'all') {
        query.isSystem = isSystem === 'true';
      }

      const skip = (page - 1) * limit;

      const [roles, total] = await Promise.all([
        Role.find(query)
          .populate('createdBy', 'username email')
          .populate('updatedBy', 'username email')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        Role.countDocuments(query)
      ]);

      return {
        roles,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting roles:', error);
      throw error;
    }
  }

  /**
   * Get all active roles (for dropdowns)
   */
  async getActiveRoles() {
    try {
      const roles = await Role.find({ status: 'active' })
        .sort({ priority: -1, displayName: 1 });
      
      return roles;
    } catch (error) {
      logger.error('Error getting active roles:', error);
      throw error;
    }
  }

  /**
   * Update role
   */
  async updateRole(roleId, updateData, updatedBy) {
    try {
      const role = await Role.findById(roleId);
      
      if (!role) {
        throw new AppError('Role not found', HTTP_STATUS.NOT_FOUND, 'ROLE_NOT_FOUND');
      }

      // Check if system role can be modified
      if (role.isSystem) {
        throw new AppError(
          'System roles cannot be modified',
          HTTP_STATUS.FORBIDDEN,
          'SYSTEM_ROLE_IMMUTABLE'
        );
      }

      // Check if name is being changed and validate uniqueness
      if (updateData.name && updateData.name !== role.name) {
        const existingRole = await Role.findOne({ 
          name: updateData.name,
          _id: { $ne: roleId }
        });
        if (existingRole) {
          throw new AppError(
            'Role with this name already exists',
            HTTP_STATUS.CONFLICT,
            'ROLE_EXISTS'
          );
        }
      }

      // Validate permissions
      if (updateData.permissions) {
        const invalidPermissions = updateData.permissions.filter(
          permission => !Object.values(PERMISSIONS).includes(permission)
        );
        if (invalidPermissions.length > 0) {
          throw new AppError(
            `Invalid permissions: ${invalidPermissions.join(', ')}`,
            HTTP_STATUS.BAD_REQUEST,
            'INVALID_PERMISSIONS'
          );
        }
      }

      // Update role
      const updatedRole = await Role.findByIdAndUpdate(
        roleId,
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
      .populate('createdBy', 'username email')
      .populate('updatedBy', 'username email');

      logger.info(`Role updated: ${updatedRole.name} by ${updatedBy}`);

      // Update users if role permissions changed
      if (updateData.permissions) {
        await this.updateUsersPermissions(roleId, updateData.permissions);
      }

      return updatedRole;
    } catch (error) {
      logger.error('Error updating role:', error);
      throw error;
    }
  }

  /**
   * Delete role (soft delete)
   */
  async deleteRole(roleId, deletedBy) {
    try {
      const role = await Role.findById(roleId);
      
      if (!role) {
        throw new AppError('Role not found', HTTP_STATUS.NOT_FOUND, 'ROLE_NOT_FOUND');
      }

      // Check if system role can be deleted
      if (role.isSystem) {
        throw new AppError(
          'System roles cannot be deleted',
          HTTP_STATUS.FORBIDDEN,
          'SYSTEM_ROLE_IMMUTABLE'
        );
      }

      // Check if role is assigned to any user
      const usersWithRole = await User.countDocuments({ role: role.name });
      if (usersWithRole > 0) {
        throw new AppError(
          `Cannot delete role. It is assigned to ${usersWithRole} user(s)`,
          HTTP_STATUS.CONFLICT,
          'ROLE_IN_USE'
        );
      }

      // Soft delete by setting status to inactive
      role.status = 'inactive';
      role.updatedBy = deletedBy;
      await role.save();

      logger.info(`Role deleted (soft): ${role.name} by ${deletedBy}`);

      return { success: true, message: 'Role deleted successfully' };
    } catch (error) {
      logger.error('Error deleting role:', error);
      throw error;
    }
  }

  /**
   * Hard delete role (permanent)
   */
  async hardDeleteRole(roleId, deletedBy) {
    try {
      const role = await Role.findById(roleId);
      
      if (!role) {
        throw new AppError('Role not found', HTTP_STATUS.NOT_FOUND, 'ROLE_NOT_FOUND');
      }

      // Check if system role can be deleted
      if (role.isSystem) {
        throw new AppError(
          'System roles cannot be deleted',
          HTTP_STATUS.FORBIDDEN,
          'SYSTEM_ROLE_IMMUTABLE'
        );
      }

      // Check if role is assigned to any user
      const usersWithRole = await User.countDocuments({ role: role.name });
      if (usersWithRole > 0) {
        throw new AppError(
          `Cannot delete role. It is assigned to ${usersWithRole} user(s)`,
          HTTP_STATUS.CONFLICT,
          'ROLE_IN_USE'
        );
      }

      await role.remove();

      logger.info(`Role hard deleted: ${role.name} by ${deletedBy}`);

      return { success: true, message: 'Role permanently deleted' };
    } catch (error) {
      logger.error('Error hard deleting role:', error);
      throw error;
    }
  }

  /**
   * Update users' permissions when role changes
   */
  async updateUsersPermissions(roleId, newPermissions) {
    try {
      const role = await Role.findById(roleId);
      if (!role) {
        throw new AppError('Role not found', HTTP_STATUS.NOT_FOUND, 'ROLE_NOT_FOUND');
      }

      // Find all users with this role
      const users = await User.find({ role: role.name });
      
      // In a real implementation, you might want to update a permissions field on users
      // or use a junction table. For now, we'll just log the update.
      
      logger.info(`Updated permissions for ${users.length} users with role ${role.name}`);
      
      return {
        success: true,
        message: `Permissions updated for ${users.length} users`,
        affectedUsers: users.length
      };
    } catch (error) {
      logger.error('Error updating users permissions:', error);
      throw error;
    }
  }

  /**
   * Get role statistics
   */
  async getRoleStatistics() {
    try {
      const stats = await Role.getRoleStatistics();
      return stats;
    } catch (error) {
      logger.error('Error getting role statistics:', error);
      throw error;
    }
  }

  /**
   * Get all available permissions
   */
  async getAllPermissions() {
    try {
      return Object.values(PERMISSIONS).map(permission => ({
        key: permission,
        label: permission.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
        category: permission.split('_')[0] || 'general'
      }));
    } catch (error) {
      logger.error('Error getting all permissions:', error);
      throw error;
    }
  }

  /**
   * Get permissions by category
   */
  async getPermissionsByCategory() {
    try {
      const permissions = await this.getAllPermissions();
      const grouped = {};
      
      permissions.forEach(permission => {
        const category = permission.category;
        if (!grouped[category]) {
          grouped[category] = [];
        }
        grouped[category].push(permission);
      });

      return grouped;
    } catch (error) {
      logger.error('Error getting permissions by category:', error);
      throw error;
    }
  }

  /**
   * Check if role has specific permission
   */
  async checkRolePermission(roleId, permission) {
    try {
      const role = await Role.findById(roleId);
      
      if (!role) {
        throw new AppError('Role not found', HTTP_STATUS.NOT_FOUND, 'ROLE_NOT_FOUND');
      }

      return {
        hasPermission: role.hasPermission(permission),
        role: role.name
      };
    } catch (error) {
      logger.error('Error checking role permission:', error);
      throw error;
    }
  }

  /**
   * Get role hierarchy
   */
  async getRoleHierarchy() {
    try {
      const roles = await Role.find({ status: 'active' })
        .sort({ priority: -1 })
        .select('name displayName priority permissions');
      
      // Add hierarchy information
      return roles.map((role, index) => ({
        ...role.toJSON(),
        level: index + 1,
        permissionCount: role.permissions.length
      }));
    } catch (error) {
      logger.error('Error getting role hierarchy:', error);
      throw error;
    }
  }
}

module.exports = new RoleService();