const LogSourceService = require('../services/logSourceService');
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');

class LogSourceController {
  /**
   * Create a new log source
   * POST /api/log-sources
   */
  createLogSource = asyncHandler(async (req, res) => {
    const sourceData = req.body;
    const createdBy = req.user.id;

    const logSource = await LogSourceService.createLogSource(sourceData, createdBy);

    ResponseHandler.created(res, logSource, 'Log source created successfully');
  });

  /**
   * Get log source by ID
   * GET /api/log-sources/:id
   */
  getLogSourceById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const logSource = await LogSourceService.getLogSourceById(id);

    ResponseHandler.success(res, logSource, 'Log source retrieved successfully');
  });

  /**
   * Get log sources by organization
   * GET /api/log-sources/organization/:organizationId
   */
  getLogSourcesByOrganization = asyncHandler(async (req, res) => {
    const { organizationId } = req.params;
    const filters = {
      status: req.query.status,
      sourceType: req.query.sourceType,
      search: req.query.search,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await LogSourceService.getLogSourcesByOrganization(organizationId, filters);

    ResponseHandler.paginated(
      res,
      result.sources,
      result.pagination,
      'Log sources retrieved successfully'
    );
  });

  /**
   * Get all log sources (admin)
   * GET /api/log-sources
   */
  getAllLogSources = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization,
      status: req.query.status,
      sourceType: req.query.sourceType,
      search: req.query.search,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await LogSourceService.getAllLogSources(filters);

    ResponseHandler.paginated(
      res,
      result.sources,
      result.pagination,
      'Log sources retrieved successfully'
    );
  });

  /**
   * Update log source
   * PUT /api/log-sources/:id
   */
  updateLogSource = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;
    const updatedBy = req.user.id;

    const logSource = await LogSourceService.updateLogSource(id, updateData, updatedBy);

    ResponseHandler.success(res, logSource, 'Log source updated successfully');
  });

  /**
   * Update log source status
   * PATCH /api/log-sources/:id/status
   */
  updateStatus = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    const updatedBy = req.user.id;

    const logSource = await LogSourceService.updateStatus(id, status, updatedBy);

    ResponseHandler.success(res, logSource, 'Log source status updated successfully');
  });

  /**
   * Update heartbeat
   * PATCH /api/log-sources/:id/heartbeat
   */
  updateHeartbeat = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const result = await LogSourceService.updateHeartbeat(id);

    ResponseHandler.success(res, result, 'Heartbeat updated successfully');
  });

  /**
   * Regenerate authentication token
   * POST /api/log-sources/:id/regenerate-token
   */
  regenerateToken = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updatedBy = req.user.id;

    const result = await LogSourceService.regenerateToken(id, updatedBy);

    ResponseHandler.success(res, result, 'Authentication token regenerated successfully');
  });

  /**
   * Delete log source (soft delete)
   * DELETE /api/log-sources/:id
   */
  deleteLogSource = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await LogSourceService.deleteLogSource(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Hard delete log source (permanent)
   * DELETE /api/log-sources/:id/permanent
   */
  hardDeleteLogSource = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await LogSourceService.hardDeleteLogSource(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Get log source statistics
   * GET /api/log-sources/statistics
   */
  getLogSourceStatistics = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const stats = await LogSourceService.getLogSourceStatistics(organizationId);

    ResponseHandler.success(res, stats, 'Log source statistics retrieved successfully');
  });

  /**
   * Search log sources
   * GET /api/log-sources/search
   */
  searchLogSources = asyncHandler(async (req, res) => {
    const { query, organizationId, page, limit, sort } = req.query;
    const result = await LogSourceService.searchLogSources(
      query,
      organizationId || null,
      { page, limit, sort }
    );

    ResponseHandler.paginated(
      res,
      result.sources,
      result.pagination,
      'Log sources searched successfully'
    );
  });

  /**
   * Get online log sources
   * GET /api/log-sources/online
   */
  getOnlineSources = asyncHandler(async (req, res) => {
    const sources = await LogSourceService.getOnlineSources();

    ResponseHandler.success(res, sources, 'Online log sources retrieved successfully');
  });

  /**
   * Check stale heartbeats
   * POST /api/log-sources/check-heartbeats
   */
  checkStaleHeartbeats = asyncHandler(async (req, res) => {
    const { thresholdMinutes } = req.body;
    const result = await LogSourceService.checkStaleHeartbeats(thresholdMinutes || 5);

    ResponseHandler.success(res, result, 'Heartbeat check completed');
  });

  /**
   * Get source types (for dropdowns)
   * GET /api/log-sources/types
   */
  getSourceTypes = asyncHandler(async (req, res) => {
    const types = LogSourceService.getSourceTypes();

    ResponseHandler.success(res, types, 'Source types retrieved successfully');
  });

  /**
   * Get protocols (for dropdowns)
   * GET /api/log-sources/protocols
   */
  getProtocols = asyncHandler(async (req, res) => {
    const protocols = LogSourceService.getProtocols();

    ResponseHandler.success(res, protocols, 'Protocols retrieved successfully');
  });

  /**
   * Get statuses (for dropdowns)
   * GET /api/log-sources/statuses
   */
  getStatuses = asyncHandler(async (req, res) => {
    const statuses = LogSourceService.getStatuses();

    ResponseHandler.success(res, statuses, 'Statuses retrieved successfully');
  });
}

module.exports = new LogSourceController();