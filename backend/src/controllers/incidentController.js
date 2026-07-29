const IncidentService = require('../services/incidentService');
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');

class IncidentController {
  /**
   * Create a new incident
   * POST /api/v1/incidents
   */
  createIncident = asyncHandler(async (req, res) => {
    const incidentData = req.body;
    const createdBy = req.user.id;

    const incident = await IncidentService.createIncident(incidentData, createdBy);

    ResponseHandler.created(res, incident, 'Incident created successfully');
  });

  /**
   * Create incident from alerts
   * POST /api/v1/incidents/from-alerts
   */
  createIncidentFromAlerts = asyncHandler(async (req, res) => {
    const { alertIds, incidentData } = req.body;
    const createdBy = req.user.id;

    const incident = await IncidentService.createIncidentFromAlerts(alertIds, incidentData, createdBy);

    ResponseHandler.created(res, incident, 'Incident created from alerts successfully');
  });

  /**
   * Get incident by ID
   * GET /api/v1/incidents/:id
   */
  getIncidentById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const incident = await IncidentService.getIncidentById(id);

    ResponseHandler.success(res, incident, 'Incident retrieved successfully');
  });

  /**
   * Get incidents with pagination and filtering
   * GET /api/v1/incidents
   */
  getIncidents = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization,
      severity: req.query.severity,
      status: req.query.status,
      category: req.query.category,
      assignedTo: req.query.assignedTo,
      search: req.query.search,
      startDate: req.query.startDate,
      endDate: req.query.endDate,
      isEscalated: req.query.isEscalated,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await IncidentService.getIncidents(filters);

    ResponseHandler.paginated(
      res,
      result.incidents,
      result.pagination,
      'Incidents retrieved successfully'
    );
  });

  /**
   * Get incidents by organization
   * GET /api/v1/incidents/organization/:organizationId
   */
  getIncidentsByOrganization = asyncHandler(async (req, res) => {
    const { organizationId } = req.params;
    const options = {
      limit: req.query.limit || 50,
      page: req.query.page || 1,
      sort: req.query.sort || '-createdAt'
    };

    const result = await IncidentService.getIncidentsByOrganization(organizationId, options);

    ResponseHandler.paginated(
      res,
      result.incidents,
      result.pagination,
      'Incidents retrieved successfully'
    );
  });

  /**
   * Get incidents assigned to current user
   * GET /api/v1/incidents/assigned-to-me
   */
  getIncidentsAssignedToMe = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const options = {
      limit: req.query.limit || 50,
      page: req.query.page || 1,
      sort: req.query.sort || '-createdAt'
    };

    const result = await IncidentService.getIncidentsAssignedToUser(userId, options);

    ResponseHandler.paginated(
      res,
      result.incidents,
      result.pagination,
      'Assigned incidents retrieved successfully'
    );
  });

  /**
   * Get incident statistics
   * GET /api/v1/incidents/statistics
   */
  getIncidentStatistics = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const timeRange = req.query.timeRange || '30d';
    const stats = await IncidentService.getIncidentStatistics(organizationId, timeRange);

    ResponseHandler.success(res, stats, 'Incident statistics retrieved successfully');
  });

  /**
   * Get open incidents count
   * GET /api/v1/incidents/open-count
   */
  getOpenIncidentsCount = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const count = await IncidentService.getOpenIncidentsCount(organizationId);

    ResponseHandler.success(res, { count }, 'Open incidents count retrieved successfully');
  });

  /**
   * Update incident
   * PUT /api/v1/incidents/:id
   */
  updateIncident = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;
    const updatedBy = req.user.id;

    const incident = await IncidentService.updateIncident(id, updateData, updatedBy);

    ResponseHandler.success(res, incident, 'Incident updated successfully');
  });

  /**
   * Assign incident to user
   * POST /api/v1/incidents/:id/assign
   */
  assignIncident = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { userId } = req.body;
    const assignedBy = req.user.id;

    const incident = await IncidentService.assignIncident(id, userId, assignedBy);

    ResponseHandler.success(res, incident, 'Incident assigned successfully');
  });

  /**
   * Update incident status
   * PATCH /api/v1/incidents/:id/status
   */
  updateIncidentStatus = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { status, note } = req.body;
    const userId = req.user.id;

    const incident = await IncidentService.updateIncidentStatus(id, status, userId, note);

    ResponseHandler.success(res, incident, 'Incident status updated successfully');
  });

  /**
   * Add timeline entry
   * POST /api/v1/incidents/:id/timeline
   */
  addTimeline = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { action, note, metadata } = req.body;
    const userId = req.user.id;

    const incident = await IncidentService.addTimeline(id, action, note, userId, metadata);

    ResponseHandler.success(res, incident, 'Timeline entry added successfully');
  });

  /**
   * Add evidence to incident
   * POST /api/v1/incidents/:id/evidence
   */
  addEvidence = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const evidenceData = req.body;
    const uploadedBy = req.user.id;

    const incident = await IncidentService.addEvidence(id, evidenceData, uploadedBy);

    ResponseHandler.success(res, incident, 'Evidence added successfully');
  });

  /**
   * Add affected asset
   * POST /api/v1/incidents/:id/affected-asset
   */
  addAffectedAsset = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { assetId, impact, notes } = req.body;

    const incident = await IncidentService.addAffectedAsset(id, assetId, impact, notes);

    ResponseHandler.success(res, incident, 'Affected asset added successfully');
  });

  /**
   * Add containment measure
   * POST /api/v1/incidents/:id/containment
   */
  addContainmentMeasure = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { measure, effectiveness } = req.body;
    const implementedBy = req.user.id;

    const incident = await IncidentService.addContainmentMeasure(id, measure, implementedBy, effectiveness);

    ResponseHandler.success(res, incident, 'Containment measure added successfully');
  });

  /**
   * Escalate incident
   * POST /api/v1/incidents/:id/escalate
   */
  escalateIncident = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { escalateTo, reason } = req.body;
    const userId = req.user.id;

    const incident = await IncidentService.escalateIncident(id, userId, escalateTo, reason);

    ResponseHandler.success(res, incident, 'Incident escalated successfully');
  });

  /**
   * Resolve incident
   * POST /api/v1/incidents/:id/resolve
   */
  resolveIncident = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { resolutionStatus, summary, steps, lessonsLearned } = req.body;
    const userId = req.user.id;

    const incident = await IncidentService.resolveIncident(id, userId, resolutionStatus, summary, steps, lessonsLearned);

    ResponseHandler.success(res, incident, 'Incident resolved successfully');
  });

  /**
   * Close incident
   * POST /api/v1/incidents/:id/close
   */
  closeIncident = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { note } = req.body;
    const userId = req.user.id;

    const incident = await IncidentService.closeIncident(id, userId, note);

    ResponseHandler.success(res, incident, 'Incident closed successfully');
  });

  /**
   * Reopen incident
   * POST /api/v1/incidents/:id/reopen
   */
  reopenIncident = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;
    const userId = req.user.id;

    const incident = await IncidentService.reopenIncident(id, userId, reason);

    ResponseHandler.success(res, incident, 'Incident reopened successfully');
  });

  /**
   * Delete incident
   * DELETE /api/v1/incidents/:id
   */
  deleteIncident = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await IncidentService.deleteIncident(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Search incidents
   * GET /api/v1/incidents/search
   */
  searchIncidents = asyncHandler(async (req, res) => {
    const { query, organizationId, page, limit, sort } = req.query;
    const result = await IncidentService.searchIncidents(
      query,
      organizationId || null,
      { page, limit, sort }
    );

    ResponseHandler.paginated(
      res,
      result.incidents,
      result.pagination,
      'Incidents searched successfully'
    );
  });

  /**
   * Get incident categories
   * GET /api/v1/incidents/categories
   */
  getIncidentCategories = asyncHandler(async (req, res) => {
    const categories = IncidentService.getIncidentCategories();

    ResponseHandler.success(res, categories, 'Incident categories retrieved successfully');
  });

  /**
   * Get resolution statuses
   * GET /api/v1/incidents/resolution-statuses
   */
  getResolutionStatuses = asyncHandler(async (req, res) => {
    const statuses = IncidentService.getResolutionStatuses();

    ResponseHandler.success(res, statuses, 'Resolution statuses retrieved successfully');
  });

  /**
   * Get detection sources
   * GET /api/v1/incidents/detection-sources
   */
  getDetectionSources = asyncHandler(async (req, res) => {
    const sources = IncidentService.getDetectionSources();

    ResponseHandler.success(res, sources, 'Detection sources retrieved successfully');
  });

  /**
   * Get containment effectiveness levels
   * GET /api/v1/incidents/containment-effectiveness
   */
  getContainmentEffectiveness = asyncHandler(async (req, res) => {
    const levels = IncidentService.getContainmentEffectiveness();

    ResponseHandler.success(res, levels, 'Containment effectiveness levels retrieved successfully');
  });

  /**
   * Get severity levels
   * GET /api/v1/incidents/severities
   */
  getSeverityLevels = asyncHandler(async (req, res) => {
    const severities = IncidentService.getSeverityLevels();

    ResponseHandler.success(res, severities, 'Severity levels retrieved successfully');
  });

  /**
   * Get incident statuses
   * GET /api/v1/incidents/statuses
   */
  getIncidentStatuses = asyncHandler(async (req, res) => {
    const statuses = IncidentService.getIncidentStatuses();

    ResponseHandler.success(res, statuses, 'Incident statuses retrieved successfully');
  });

  /**
   * Get incidents by date range
   * GET /api/v1/incidents/date-range
   */
  getIncidentsByDateRange = asyncHandler(async (req, res) => {
    const { organizationId, startDate, endDate } = req.query;
    const incidents = await IncidentService.getIncidentsByDateRange(
      organizationId || null,
      startDate,
      endDate
    );

    ResponseHandler.success(res, incidents, 'Incidents by date range retrieved successfully');
  });
}

module.exports = new IncidentController();