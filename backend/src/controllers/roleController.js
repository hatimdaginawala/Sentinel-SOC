const RoleService = require('../services/roleService');
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');

class RoleController {
  /**
   * Initialize system roles
   * POST /api/v1/roles/initialize
   */
  initializeSystemRoles = asyncHandler(async (req, res) => {
    const roles = await RoleService.initializeSystemRoles();

    ResponseHandler.success(
      res, 
      { roles, count: roles.length }, 
      'System roles initialized successfully'
    );
  });

  /**
   * Create a new role
   * POST /api/v1/roles
   */
  createRole = asyncHandler(async (req, res) => {
    const roleData = req.body;
    const createdBy = req.user.id;

    const role = await RoleService.createRole(roleData, createdBy);

    ResponseHandler.created(res, role, 'Role created successfully');
  });

  /**
   * Get role by ID
   * GET /api/v1/roles/:id
   */
  getRoleById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const role = await RoleService.getRoleById(id);

    ResponseHandler.success(res, role, 'Role retrieved successfully');
  });

  /**
   * Get all roles with pagination
   * GET /api/v1/roles
   */
  getRoles = asyncHandler(async (req, res) => {
    const filters = {
      search: req.query.search,
      status: req.query.status,
      isSystem: req.query.isSystem,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await RoleService.getRoles(filters);

    ResponseHandler.paginated(
      res,
      result.roles,
      result.pagination,
      'Roles retrieved successfully'
    );
  });

  /**
   * Get all active roles (for dropdowns)
   * GET /api/v1/roles/active
   */
  getActiveRoles = asyncHandler(async (req, res) => {
    const roles = await RoleService.getActiveRoles();

    ResponseHandler.success(res, roles, 'Active roles retrieved successfully');
  });

  /**
   * Update role
   * PUT /api/v1/roles/:id
   */
  updateRole = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;
    const updatedBy = req.user.id;

    const role = await RoleService.updateRole(id, updateData, updatedBy);

    ResponseHandler.success(res, role, 'Role updated successfully');
  });

  /**
   * Delete role (soft delete)
   * DELETE /api/v1/roles/:id
   */
  deleteRole = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await RoleService.deleteRole(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Hard delete role (permanent)
   * DELETE /api/v1/roles/:id/permanent
   */
  hardDeleteRole = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await RoleService.hardDeleteRole(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Get role statistics
   * GET /api/v1/roles/statistics
   */
  getRoleStatistics = asyncHandler(async (req, res) => {
    const stats = await RoleService.getRoleStatistics();

    ResponseHandler.success(res, stats, 'Role statistics retrieved successfully');
  });

  /**
   * Get all available permissions
   * GET /api/v1/roles/permissions
   */
  getAllPermissions = asyncHandler(async (req, res) => {
    const permissions = await RoleService.getAllPermissions();

    ResponseHandler.success(res, permissions, 'Permissions retrieved successfully');
  });

  /**
   * Get permissions by category
   * GET /api/v1/roles/permissions/categories
   */
  getPermissionsByCategory = asyncHandler(async (req, res) => {
    const groupedPermissions = await RoleService.getPermissionsByCategory();

    ResponseHandler.success(
      res, 
      groupedPermissions, 
      'Permissions by category retrieved successfully'
    );
  });

  /**
   * Check role permission
   * GET /api/v1/roles/:id/permission/:permission
   */
  checkRolePermission = asyncHandler(async (req, res) => {
    const { id, permission } = req.params;
    const result = await RoleService.checkRolePermission(id, permission);

    ResponseHandler.success(res, result, 'Permission check completed');
  });

  /**
   * Get role hierarchy
   * GET /api/v1/roles/hierarchy
   */
  getRoleHierarchy = asyncHandler(async (req, res) => {
    const hierarchy = await RoleService.getRoleHierarchy();

    ResponseHandler.success(res, hierarchy, 'Role hierarchy retrieved successfully');
  });
}

module.exports = new RoleController();