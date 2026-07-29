const LogService = require('../services/logService');
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');
const AutomationService = require('../services/automationService');

class LogController {
  /**
   * Ingest a log from a log source (No authentication required)
   * POST /api/logs/ingest
   */
   ingestLog = asyncHandler(async (req, res) => {
    const { sourceId, authToken, log } = req.body;

    if (!sourceId || !authToken || !log) {
      return ResponseHandler.badRequest(res, 'Missing required fields: sourceId, authToken, log');
    }

    // Step 1: Validate and store the log
    const result = await LogService.ingestLog(sourceId, authToken, log);

    // Step 2: Process through automation pipeline
    // This runs asynchronously to not block the response
    setImmediate(async () => {
      try {
        const automationResult = await AutomationService.processLog(result);
        console.log('✅ Automation completed:', {
          alerts: automationResult?.alerts?.length || 0,
          incidents: automationResult?.incidents?.length || 0,
          iocs: automationResult?.matchedIOCs?.length || 0
        });
      } catch (error) {
        console.error('❌ Automation error:', error);
      }
    });

    ResponseHandler.created(res, result, 'Log ingested successfully');
  });

  /**
   * Get logs with pagination and filtering
   * GET /api/logs
   */
  getLogs = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization,
      asset: req.query.asset,
      logSource: req.query.logSource,
      eventCategory: req.query.eventCategory,
      eventType: req.query.eventType,
      severity: req.query.severity,
      status: req.query.status,
      search: req.query.search,
      startDate: req.query.startDate,
      endDate: req.query.endDate,
      sourceIP: req.query.sourceIP,
      destinationIP: req.query.destinationIP,
      username: req.query.username,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await LogService.getLogs(filters);

    ResponseHandler.paginated(
      res,
      result.logs,
      result.pagination,
      'Logs retrieved successfully'
    );
  });

  /**
   * Get log by ID
   * GET /api/logs/:id
   */
  getLogById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const log = await LogService.getLogById(id);

    ResponseHandler.success(res, log, 'Log retrieved successfully');
  });

  /**
   * Get logs by organization
   * GET /api/logs/organization/:organizationId
   */
  getLogsByOrganization = asyncHandler(async (req, res) => {
    const { organizationId } = req.params;
    const options = {
      limit: req.query.limit || 100,
      page: req.query.page || 1,
      sort: req.query.sort || '-eventTime'
    };

    const result = await LogService.getLogsByOrganization(organizationId, options);

    ResponseHandler.paginated(
      res,
      result.logs,
      result.pagination,
      'Logs retrieved successfully'
    );
  });

  /**
   * Get logs by log source
   * GET /api/logs/source/:logSourceId
   */
  getLogsByLogSource = asyncHandler(async (req, res) => {
    const { logSourceId } = req.params;
    const options = {
      limit: req.query.limit || 100,
      page: req.query.page || 1,
      sort: req.query.sort || '-eventTime'
    };

    const result = await LogService.getLogsByLogSource(logSourceId, options);

    ResponseHandler.paginated(
      res,
      result.logs,
      result.pagination,
      'Logs retrieved successfully'
    );
  });

  /**
   * Get log statistics
   * GET /api/logs/statistics
   */
  getLogStatistics = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const timeRange = req.query.timeRange || '24h';
    const stats = await LogService.getLogStatistics(organizationId, timeRange);

    ResponseHandler.success(res, stats, 'Log statistics retrieved successfully');
  });

  /**
   * Delete log
   * DELETE /api/logs/:id
   */
  deleteLog = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await LogService.deleteLog(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Delete old logs
   * POST /api/logs/cleanup
   */
  deleteOldLogs = asyncHandler(async (req, res) => {
    const { retentionDays } = req.body;
    const result = await LogService.deleteOldLogs(retentionDays || 90);

    ResponseHandler.success(res, result, 'Old logs deleted successfully');
  });

  /**
   * Get event categories (for dropdowns)
   * GET /api/logs/categories
   */
  getEventCategories = asyncHandler(async (req, res) => {
    const categories = LogService.getEventCategories();

    ResponseHandler.success(res, categories, 'Event categories retrieved successfully');
  });

  /**
   * Get severities (for dropdowns)
   * GET /api/logs/severities
   */
  getSeverities = asyncHandler(async (req, res) => {
    const severities = LogService.getSeverities();

    ResponseHandler.success(res, severities, 'Severities retrieved successfully');
  });

  /**
   * Get statuses (for dropdowns)
   * GET /api/logs/statuses
   */
  getStatuses = asyncHandler(async (req, res) => {
    const statuses = LogService.getStatuses();

    ResponseHandler.success(res, statuses, 'Statuses retrieved successfully');
  });
}

module.exports = new LogController();