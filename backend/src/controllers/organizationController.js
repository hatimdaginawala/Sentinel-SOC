const OrganizationService = require('../services/organizationService');
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');

class OrganizationController {
  /**
   * Create a new organization
   * POST /api/v1/organizations
   */
  createOrganization = asyncHandler(async (req, res) => {
    const orgData = req.body;
    const createdBy = req.user.id;

    const organization = await OrganizationService.createOrganization(orgData, createdBy);

    ResponseHandler.created(res, organization, 'Organization created successfully');
  });

  /**
   * Get organization by ID
   * GET /api/v1/organizations/:id
   */
  getOrganizationById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const organization = await OrganizationService.getOrganizationById(id);

    ResponseHandler.success(res, organization, 'Organization retrieved successfully');
  });

  /**
   * Get organization by code
   * GET /api/v1/organizations/code/:code
   */
  getOrganizationByCode = asyncHandler(async (req, res) => {
    const { code } = req.params;
    const organization = await OrganizationService.getOrganizationByCode(code);

    ResponseHandler.success(res, organization, 'Organization retrieved successfully');
  });

  /**
   * Get all organizations with pagination
   * GET /api/v1/organizations
   */
  getOrganizations = asyncHandler(async (req, res) => {
    const filters = {
      search: req.query.search,
      status: req.query.status,
      industry: req.query.industry,
      plan: req.query.plan,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await OrganizationService.getOrganizations(filters);

    ResponseHandler.paginated(
      res,
      result.organizations,
      result.pagination,
      'Organizations retrieved successfully'
    );
  });

  /**
   * Get active organizations (for dropdowns)
   * GET /api/v1/organizations/active
   */
  getActiveOrganizations = asyncHandler(async (req, res) => {
    const organizations = await OrganizationService.getActiveOrganizations();

    ResponseHandler.success(res, organizations, 'Active organizations retrieved successfully');
  });

  /**
   * Update organization
   * PUT /api/v1/organizations/:id
   */
  updateOrganization = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;
    const updatedBy = req.user.id;

    const organization = await OrganizationService.updateOrganization(id, updateData, updatedBy);

    ResponseHandler.success(res, organization, 'Organization updated successfully');
  });

  /**
   * Delete organization (soft delete)
   * DELETE /api/v1/organizations/:id
   */
  deleteOrganization = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await OrganizationService.deleteOrganization(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Hard delete organization (permanent)
   * DELETE /api/v1/organizations/:id/permanent
   */
  hardDeleteOrganization = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await OrganizationService.hardDeleteOrganization(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Get organization statistics
   * GET /api/v1/organizations/statistics
   */
  getOrganizationStatistics = asyncHandler(async (req, res) => {
    const stats = await OrganizationService.getOrganizationStatistics();

    ResponseHandler.success(res, stats, 'Organization statistics retrieved successfully');
  });

  /**
   * Get organization usage statistics
   * GET /api/v1/organizations/:id/usage
   */
  getOrganizationUsage = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const usage = await OrganizationService.getOrganizationUsage(id);

    ResponseHandler.success(res, usage, 'Organization usage retrieved successfully');
  });

  /**
   * Update organization subscription
   * PUT /api/v1/organizations/:id/subscription
   */
  updateSubscription = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const subscriptionData = req.body;
    const updatedBy = req.user.id;

    const organization = await OrganizationService.updateSubscription(id, subscriptionData, updatedBy);

    ResponseHandler.success(res, organization, 'Subscription updated successfully');
  });

  /**
   * Get organizations with expiring subscriptions
   * GET /api/v1/organizations/subscriptions/expiring
   */
  getExpiringSubscriptions = asyncHandler(async (req, res) => {
    const daysThreshold = req.query.days || 30;
    const organizations = await OrganizationService.getExpiringSubscriptions(parseInt(daysThreshold));

    ResponseHandler.success(
      res, 
      organizations, 
      `Organizations with subscriptions expiring in ${daysThreshold} days`
    );
  });

  /**
   * Get organizations with expired subscriptions
   * GET /api/v1/organizations/subscriptions/expired
   */
  getExpiredSubscriptions = asyncHandler(async (req, res) => {
    const organizations = await OrganizationService.getExpiredSubscriptions();

    ResponseHandler.success(res, organizations, 'Organizations with expired subscriptions');
  });

  /**
   * Check if organization can add more users
   * GET /api/v1/organizations/:id/capacity/users
   */
  checkUserCapacity = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const additionalUsers = parseInt(req.query.additional) || 1;
    
    const capacity = await OrganizationService.canAddUsers(id, additionalUsers);

    ResponseHandler.success(res, capacity, 'User capacity checked successfully');
  });

  /**
   * Check if organization can add more assets
   * GET /api/v1/organizations/:id/capacity/assets
   */
  checkAssetCapacity = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const additionalAssets = parseInt(req.query.additional) || 1;
    
    const capacity = await OrganizationService.canAddAssets(id, additionalAssets);

    ResponseHandler.success(res, capacity, 'Asset capacity checked successfully');
  });
}

module.exports = new OrganizationController();