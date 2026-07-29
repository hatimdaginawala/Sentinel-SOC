const AuditLogService = require('../services/auditLogService');
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');

class AuditLogController {
  /**
   * Get audit log by ID
   * GET /api/v1/audit-logs/:id
   */
  getAuditLogById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const log = await AuditLogService.getAuditLogById(id);

    ResponseHandler.success(res, log, 'Audit log retrieved successfully');
  });

  /**
   * Get audit logs with pagination and filtering
   * GET /api/v1/audit-logs
   */
  getAuditLogs = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization,
      user: req.query.user,
      action: req.query.action,
      resource: req.query.resource,
      resourceId: req.query.resourceId,
      status: req.query.status,
      severity: req.query.severity,
      search: req.query.search,
      startDate: req.query.startDate,
      endDate: req.query.endDate,
      ipAddress: req.query.ipAddress,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await AuditLogService.getAuditLogs(filters);

    ResponseHandler.paginated(
      res,
      result.logs,
      result.pagination,
      'Audit logs retrieved successfully'
    );
  });

  /**
   * Get audit log statistics
   * GET /api/v1/audit-logs/statistics
   */
  getAuditStatistics = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const timeRange = req.query.timeRange || '24h';
    const stats = await AuditLogService.getAuditStatistics(organizationId, timeRange);

    ResponseHandler.success(res, stats, 'Audit statistics retrieved successfully');
  });

  /**
   * Get audit logs by user
   * GET /api/v1/audit-logs/user/:userId
   */
  getAuditLogsByUser = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const options = {
      limit: req.query.limit || 50,
      page: req.query.page || 1,
      sort: req.query.sort || '-createdAt'
    };

    const result = await AuditLogService.getAuditLogsByUser(userId, options);

    ResponseHandler.paginated(
      res,
      result.logs,
      result.pagination,
      'Audit logs by user retrieved successfully'
    );
  });

  /**
   * Get audit logs by IP
   * GET /api/v1/audit-logs/ip/:ipAddress
   */
  getAuditLogsByIP = asyncHandler(async (req, res) => {
    const { ipAddress } = req.params;
    const options = {
      limit: req.query.limit || 50,
      page: req.query.page || 1,
      sort: req.query.sort || '-createdAt'
    };

    const result = await AuditLogService.getAuditLogsByIP(ipAddress, options);

    ResponseHandler.paginated(
      res,
      result.logs,
      result.pagination,
      'Audit logs by IP retrieved successfully'
    );
  });

  /**
   * Get audit trail for resource
   * GET /api/v1/audit-logs/trail/:resource/:resourceId
   */
  getAuditTrail = asyncHandler(async (req, res) => {
    const { resource, resourceId } = req.params;
    const organizationId = req.query.organizationId || null;

    const logs = await AuditLogService.getAuditTrail(resource, resourceId, organizationId);

    ResponseHandler.success(res, logs, 'Audit trail retrieved successfully');
  });

  /**
   * Search audit logs
   * GET /api/v1/audit-logs/search
   */
  searchAuditLogs = asyncHandler(async (req, res) => {
    const { query, organizationId, page, limit, sort } = req.query;

    const result = await AuditLogService.searchAuditLogs(
      query,
      organizationId || null,
      { page, limit, sort }
    );

    ResponseHandler.paginated(
      res,
      result.logs,
      result.pagination,
      'Audit logs searched successfully'
    );
  });

  /**
   * Export audit logs
   * GET /api/v1/audit-logs/export
   */
  exportAuditLogs = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization,
      user: req.query.user,
      action: req.query.action,
      resource: req.query.resource,
      status: req.query.status,
      severity: req.query.severity,
      startDate: req.query.startDate,
      endDate: req.query.endDate
    };

    const logs = await AuditLogService.exportAuditLogs(filters);

    ResponseHandler.success(res, logs, 'Audit logs exported successfully');
  });

  /**
   * Clean up old audit logs
   * POST /api/v1/audit-logs/cleanup
   */
  cleanupOldLogs = asyncHandler(async (req, res) => {
    const { retentionDays } = req.body;
    const result = await AuditLogService.cleanupOldLogs(retentionDays || 90);

    ResponseHandler.success(res, result, 'Audit logs cleaned up successfully');
  });

  /**
   * Get actions for dropdown
   * GET /api/v1/audit-logs/actions
   */
  getActions = asyncHandler(async (req, res) => {
    const actions = AuditLogService.getActions();

    ResponseHandler.success(res, actions, 'Actions retrieved successfully');
  });

  /**
   * Get resources for dropdown
   * GET /api/v1/audit-logs/resources
   */
  getResources = asyncHandler(async (req, res) => {
    const resources = AuditLogService.getResources();

    ResponseHandler.success(res, resources, 'Resources retrieved successfully');
  });

  /**
   * Get statuses for dropdown
   * GET /api/v1/audit-logs/statuses
   */
  getStatuses = asyncHandler(async (req, res) => {
    const statuses = AuditLogService.getStatuses();

    ResponseHandler.success(res, statuses, 'Statuses retrieved successfully');
  });

  /**
   * Get severity levels for dropdown
   * GET /api/v1/audit-logs/severities
   */
  getSeverityLevels = asyncHandler(async (req, res) => {
    const severities = AuditLogService.getSeverityLevels();

    ResponseHandler.success(res, severities, 'Severity levels retrieved successfully');
  });
}

module.exports = new AuditLogController();