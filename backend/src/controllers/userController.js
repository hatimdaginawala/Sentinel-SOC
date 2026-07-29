const UserService = require('../services/userService');
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');

class UserController {
  /**
   * Create a new user
   * POST /api/v1/users
   */
  createUser = asyncHandler(async (req, res) => {
    const userData = req.body;
    const createdBy = req.user.id;

    const user = await UserService.createUser(userData, createdBy);

    ResponseHandler.created(res, user, 'User created successfully');
  });

  /**
   * Get current user profile
   * GET /api/v1/users/me
   */
  getCurrentUser = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const user = await UserService.getUserById(userId);

    ResponseHandler.success(res, user, 'User profile retrieved successfully');
  });

  /**
   * Get user by ID
   * GET /api/v1/users/:id
   */
  getUserById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const user = await UserService.getUserById(id);

    ResponseHandler.success(res, user, 'User retrieved successfully');
  });

  /**
   * Get all users with pagination
   * GET /api/v1/users
   */
  getUsers = asyncHandler(async (req, res) => {
    const filters = {
      search: req.query.search,
      role: req.query.role,
      status: req.query.status,
      organization: req.query.organization,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await UserService.getUsers(filters);

    ResponseHandler.paginated(
      res,
      result.users,
      result.pagination,
      'Users retrieved successfully'
    );
  });

  /**
   * Update user
   * PUT /api/v1/users/:id
   */
  updateUser = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;
    const updatedBy = req.user.id;

    const user = await UserService.updateUser(id, updateData, updatedBy);

    ResponseHandler.success(res, user, 'User updated successfully');
  });

  /**
   * Delete user (soft delete)
   * DELETE /api/v1/users/:id
   */
  deleteUser = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await UserService.deleteUser(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Hard delete user (permanent)
   * DELETE /api/v1/users/:id/permanent
   */
  hardDeleteUser = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await UserService.hardDeleteUser(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Change password
   * POST /api/v1/users/change-password
   */
  changePassword = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { oldPassword, newPassword } = req.body;

    const result = await UserService.changePassword(userId, oldPassword, newPassword);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Reset password (admin only)
   * POST /api/v1/users/:id/reset-password
   */
  resetPassword = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { newPassword } = req.body;
    const resetBy = req.user.id;

    const result = await UserService.resetPassword(id, newPassword, resetBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Initiate password reset request
   * POST /api/v1/users/forgot-password
   */
  initiatePasswordReset = asyncHandler(async (req, res) => {
    const { email } = req.body;

    const result = await UserService.initiatePasswordReset(email);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Complete password reset
   * POST /api/v1/users/reset-password
   */
  completePasswordReset = asyncHandler(async (req, res) => {
    const { token, newPassword } = req.body;

    const result = await UserService.completePasswordReset(token, newPassword);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Authenticate user
   * POST /api/v1/auth/login
   */
  login = asyncHandler(async (req, res) => {
    const { identifier, password } = req.body;

    const result = await UserService.authenticateUser(identifier, password);

    ResponseHandler.success(res, result, 'Login successful');
  });

  /**
   * Refresh access token
   * POST /api/v1/auth/refresh
   */
  refreshToken = asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;

    const result = await UserService.refreshAccessToken(refreshToken);

    ResponseHandler.success(res, result, 'Token refreshed successfully');
  });

  /**
   * Logout user
   * POST /api/v1/auth/logout
   */
  logout = asyncHandler(async (req, res) => {
    const userId = req.user.id;

    const result = await UserService.logoutUser(userId);

    ResponseHandler.success(res, null, result.message);
  });
}

module.exports = new UserController();