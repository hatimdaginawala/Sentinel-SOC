const AssetService = require('../services/assetService');
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');

class AssetController {
  /**
   * Create a new asset
   * POST /api/v1/assets
   */
  createAsset = asyncHandler(async (req, res) => {
    const assetData = req.body;
    const createdBy = req.user.id;

    const asset = await AssetService.createAsset(assetData, createdBy);

    ResponseHandler.created(res, asset, 'Asset created successfully');
  });

  /**
   * Get asset by ID
   * GET /api/v1/assets/:id
   */
  getAssetById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const asset = await AssetService.getAssetById(id);

    ResponseHandler.success(res, asset, 'Asset retrieved successfully');
  });

  /**
   * Get assets by organization
   * GET /api/v1/assets/organization/:organizationId
   */
  getAssetsByOrganization = asyncHandler(async (req, res) => {
    const { organizationId } = req.params;
    const filters = {
      status: req.query.status,
      type: req.query.type,
      criticality: req.query.criticality,
      search: req.query.search,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await AssetService.getAssetsByOrganization(organizationId, filters);

    ResponseHandler.paginated(
      res,
      result.assets,
      result.pagination,
      'Assets retrieved successfully'
    );
  });

  /**
   * Get all assets (admin)
   * GET /api/v1/assets
   */
  getAllAssets = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization,
      status: req.query.status,
      type: req.query.type,
      criticality: req.query.criticality,
      search: req.query.search,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await AssetService.getAllAssets(filters);

    ResponseHandler.paginated(
      res,
      result.assets,
      result.pagination,
      'Assets retrieved successfully'
    );
  });

  /**
   * Update asset
   * PUT /api/v1/assets/:id
   */
  updateAsset = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;
    const updatedBy = req.user.id;

    const asset = await AssetService.updateAsset(id, updateData, updatedBy);

    ResponseHandler.success(res, asset, 'Asset updated successfully');
  });

  /**
   * Update asset risk score
   * POST /api/v1/assets/:id/update-risk
   */
  updateAssetRiskScore = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const result = await AssetService.updateAssetRiskScore(id);

    ResponseHandler.success(res, result, 'Asset risk score updated successfully');
  });

  /**
   * Delete asset (soft delete)
   * DELETE /api/v1/assets/:id
   */
  deleteAsset = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await AssetService.deleteAsset(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Hard delete asset (permanent)
   * DELETE /api/v1/assets/:id/permanent
   */
  hardDeleteAsset = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await AssetService.hardDeleteAsset(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Get asset statistics
   * GET /api/v1/assets/statistics
   */
  getAssetStatistics = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const stats = await AssetService.getAssetStatistics(organizationId);

    ResponseHandler.success(res, stats, 'Asset statistics retrieved successfully');
  });

  /**
   * Get assets by type
   * GET /api/v1/assets/type/:type
   */
  getAssetsByType = asyncHandler(async (req, res) => {
    const { type } = req.params;
    const organizationId = req.query.organizationId || null;
    const assets = await AssetService.getAssetsByType(type, organizationId);

    ResponseHandler.success(res, assets, 'Assets by type retrieved successfully');
  });

  /**
   * Get assets by criticality
   * GET /api/v1/assets/criticality/:criticality
   */
  getAssetsByCriticality = asyncHandler(async (req, res) => {
    const { criticality } = req.params;
    const organizationId = req.query.organizationId || null;
    const assets = await AssetService.getAssetsByCriticality(criticality, organizationId);

    ResponseHandler.success(res, assets, 'Assets by criticality retrieved successfully');
  });

  /**
   * Get assets with vulnerabilities
   * GET /api/v1/assets/vulnerabilities
   */
  getAssetsWithVulnerabilities = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const assets = await AssetService.getAssetsWithVulnerabilities(organizationId);

    ResponseHandler.success(res, assets, 'Assets with vulnerabilities retrieved successfully');
  });

  /**
   * Get assets needing patching
   * GET /api/v1/assets/needing-patching
   */
  getAssetsNeedingPatching = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const assets = await AssetService.getAssetsNeedingPatching(organizationId);

    ResponseHandler.success(res, assets, 'Assets needing patching retrieved successfully');
  });

  /**
   * Search assets
   * GET /api/v1/assets/search
   */
  searchAssets = asyncHandler(async (req, res) => {
    const { query, organizationId, page, limit, sort } = req.query;
    const result = await AssetService.searchAssets(
      query,
      organizationId || null,
      { page, limit, sort }
    );

    ResponseHandler.paginated(
      res,
      result.assets,
      result.pagination,
      'Assets searched successfully'
    );
  });

  /**
   * Bulk create assets
   * POST /api/v1/assets/bulk
   */
  bulkCreateAssets = asyncHandler(async (req, res) => {
    const assetsData = req.body;
    const createdBy = req.user.id;

    const result = await AssetService.bulkCreateAssets(assetsData, createdBy);

    ResponseHandler.created(res, result, 'Bulk assets creation completed');
  });

  /**
   * Get asset types (for dropdowns)
   * GET /api/v1/assets/types
   */
  getAssetTypes = asyncHandler(async (req, res) => {
    const types = AssetService.getAssetTypes();

    ResponseHandler.success(res, types, 'Asset types retrieved successfully');
  });

  /**
   * Get asset criticalities (for dropdowns)
   * GET /api/v1/assets/criticalities
   */
  getAssetCriticalities = asyncHandler(async (req, res) => {
    const criticalities = AssetService.getAssetCriticalities();

    ResponseHandler.success(res, criticalities, 'Asset criticalities retrieved successfully');
  });

  /**
   * Get asset statuses (for dropdowns)
   * GET /api/v1/assets/statuses
   */
  getAssetStatuses = asyncHandler(async (req, res) => {
    const statuses = AssetService.getAssetStatuses();

    ResponseHandler.success(res, statuses, 'Asset statuses retrieved successfully');
  });
}

module.exports = new AssetController();