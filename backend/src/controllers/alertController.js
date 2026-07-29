const AlertService = require('../services/alertService');
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');

class AlertController {
  /**
   * Create alert from log
   * POST /api/v1/alerts/from-log
   */
  createAlertFromLog = asyncHandler(async (req, res) => {
    const { logId, alertData } = req.body;
    const createdBy = req.user.id;

    const alert = await AlertService.createAlertFromLog(logId, alertData, createdBy);

    ResponseHandler.created(res, alert, 'Alert created successfully');
  });

  /**
   * Create multiple alerts from logs
   * POST /api/v1/alerts/batch
   */
  batchCreateAlerts = asyncHandler(async (req, res) => {
    const { logIds, alertData } = req.body;
    const createdBy = req.user.id;

    const result = await AlertService.createAlertsFromLogs(logIds, alertData, createdBy);

    ResponseHandler.created(res, result, 'Batch alert creation completed');
  });

  /**
   * Get alert by ID
   * GET /api/v1/alerts/:id
   */
  getAlertById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const alert = await AlertService.getAlertById(id);

    ResponseHandler.success(res, alert, 'Alert retrieved successfully');
  });

  /**
   * Get alerts with pagination and filtering
   * GET /api/v1/alerts
   */
  getAlerts = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization,
      asset: req.query.asset,
      logSource: req.query.logSource,
      severity: req.query.severity,
      status: req.query.status,
      category: req.query.category,
      threatType: req.query.threatType,
      assignedTo: req.query.assignedTo,
      search: req.query.search,
      startDate: req.query.startDate,
      endDate: req.query.endDate,
      isEscalated: req.query.isEscalated,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await AlertService.getAlerts(filters);

    ResponseHandler.paginated(
      res,
      result.alerts,
      result.pagination,
      'Alerts retrieved successfully'
    );
  });

  /**
   * Get alerts by organization
   * GET /api/v1/alerts/organization/:organizationId
   */
  getAlertsByOrganization = asyncHandler(async (req, res) => {
    const { organizationId } = req.params;
    const options = {
      limit: req.query.limit || 50,
      page: req.query.page || 1,
      sort: req.query.sort || '-createdAt'
    };

    const result = await AlertService.getAlertsByOrganization(organizationId, options);

    ResponseHandler.paginated(
      res,
      result.alerts,
      result.pagination,
      'Alerts retrieved successfully'
    );
  });

  /**
   * Get alerts assigned to current user
   * GET /api/v1/alerts/assigned-to-me
   */
  getAlertsAssignedToMe = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const options = {
      limit: req.query.limit || 50,
      page: req.query.page || 1,
      sort: req.query.sort || '-createdAt'
    };

    const result = await AlertService.getAlertsAssignedToUser(userId, options);

    ResponseHandler.paginated(
      res,
      result.alerts,
      result.pagination,
      'Assigned alerts retrieved successfully'
    );
  });

  /**
   * Get high priority alerts
   * GET /api/v1/alerts/high-priority
   */
  getHighPriorityAlerts = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const alerts = await AlertService.getHighPriorityAlerts(organizationId);

    ResponseHandler.success(res, alerts, 'High priority alerts retrieved successfully');
  });

  /**
   * Get alert statistics
   * GET /api/v1/alerts/statistics
   */
  getAlertStatistics = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const timeRange = req.query.timeRange || '24h';
    const stats = await AlertService.getAlertStatistics(organizationId, timeRange);

    ResponseHandler.success(res, stats, 'Alert statistics retrieved successfully');
  });

  /**
   * Update alert
   * PUT /api/v1/alerts/:id
   */
  updateAlert = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;
    const updatedBy = req.user.id;

    const alert = await AlertService.updateAlert(id, updateData, updatedBy);

    ResponseHandler.success(res, alert, 'Alert updated successfully');
  });

  /**
   * Assign alert to user
   * POST /api/v1/alerts/:id/assign
   */
  assignAlert = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { userId } = req.body;
    const assignedBy = req.user.id;

    const alert = await AlertService.assignAlert(id, userId, assignedBy);

    ResponseHandler.success(res, alert, 'Alert assigned successfully');
  });

  /**
   * Update alert status
   * PATCH /api/v1/alerts/:id/status
   */
  updateAlertStatus = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { status, note } = req.body;
    const userId = req.user.id;

    const alert = await AlertService.updateAlertStatus(id, status, userId, note);

    ResponseHandler.success(res, alert, 'Alert status updated successfully');
  });

  /**
   * Add note to alert
   * POST /api/v1/alerts/:id/note
   */
  addNote = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { note } = req.body;
    const userId = req.user.id;

    const alert = await AlertService.addNote(id, note, userId);

    ResponseHandler.success(res, alert, 'Note added successfully');
  });

  /**
   * Escalate alert
   * POST /api/v1/alerts/:id/escalate
   */
  escalateAlert = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { escalateTo, reason } = req.body;
    const userId = req.user.id;

    const alert = await AlertService.escalateAlert(id, userId, escalateTo, reason);

    ResponseHandler.success(res, alert, 'Alert escalated successfully');
  });

  /**
   * Resolve alert
   * POST /api/v1/alerts/:id/resolve
   */
  resolveAlert = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { resolutionStatus, notes } = req.body;
    const userId = req.user.id;

    const alert = await AlertService.resolveAlert(id, userId, resolutionStatus, notes);

    ResponseHandler.success(res, alert, 'Alert resolved successfully');
  });

  /**
   * Delete alert
   * DELETE /api/v1/alerts/:id
   */
  deleteAlert = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await AlertService.deleteAlert(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Search alerts
   * GET /api/v1/alerts/search
   */
  searchAlerts = asyncHandler(async (req, res) => {
    const { query, organizationId, page, limit, sort } = req.query;
    const result = await AlertService.searchAlerts(
      query,
      organizationId || null,
      { page, limit, sort }
    );

    ResponseHandler.paginated(
      res,
      result.alerts,
      result.pagination,
      'Alerts searched successfully'
    );
  });

  /**
   * Generate alert from log (automatic detection)
   * POST /api/v1/alerts/generate
   */
  generateAlertFromLog = asyncHandler(async (req, res) => {
    const { logId, threatType, severity } = req.body;
    const createdBy = req.user.id;

    const alert = await AlertService.generateAlertFromLog(logId, threatType, severity, createdBy);

    ResponseHandler.created(res, alert, 'Alert generated successfully');
  });

  /**
   * Batch generate alerts
   * POST /api/v1/alerts/batch-generate
   */
  batchGenerateAlerts = asyncHandler(async (req, res) => {
    const { logIds, threatType, severity } = req.body;
    const createdBy = req.user.id;

    // Get logs
    const Log = require('../models/Log');
    const logs = await Log.find({ _id: { $in: logIds } });
    
    const result = await AlertService.batchGenerateAlerts(logs, threatType, severity, createdBy);

    ResponseHandler.created(res, result, 'Batch alert generation completed');
  });

  /**
   * Get alert categories
   * GET /api/v1/alerts/categories
   */
  getAlertCategories = asyncHandler(async (req, res) => {
    const categories = AlertService.getAlertCategories();

    ResponseHandler.success(res, categories, 'Alert categories retrieved successfully');
  });

  /**
   * Get threat types
   * GET /api/v1/alerts/threat-types
   */
  getThreatTypes = asyncHandler(async (req, res) => {
    const threatTypes = AlertService.getThreatTypes();

    ResponseHandler.success(res, threatTypes, 'Threat types retrieved successfully');
  });

  /**
   * Get resolution statuses
   * GET /api/v1/alerts/resolution-statuses
   */
  getResolutionStatuses = asyncHandler(async (req, res) => {
    const statuses = AlertService.getResolutionStatuses();

    ResponseHandler.success(res, statuses, 'Resolution statuses retrieved successfully');
  });

  /**
   * Get severity levels
   * GET /api/v1/alerts/severities
   */
  getSeverityLevels = asyncHandler(async (req, res) => {
    const severities = AlertService.getSeverityLevels();

    ResponseHandler.success(res, severities, 'Severity levels retrieved successfully');
  });

  /**
   * Get alert statuses
   * GET /api/v1/alerts/statuses
   */
  getAlertStatuses = asyncHandler(async (req, res) => {
    const statuses = AlertService.getAlertStatuses();

    ResponseHandler.success(res, statuses, 'Alert statuses retrieved successfully');
  });
}

module.exports = new AlertController();