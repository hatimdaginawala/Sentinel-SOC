const IOCService = require('../services/iocService');
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');

class IOCController {
  /**
   * Create a new IOC
   * POST /api/v1/iocs
   */
  createIOC = asyncHandler(async (req, res) => {
    const iocData = req.body;
    const createdBy = req.user.id;

    const ioc = await IOCService.createIOC(iocData, createdBy);

    ResponseHandler.created(res, ioc, 'IOC created successfully');
  });

  /**
   * Bulk create IOCs
   * POST /api/v1/iocs/bulk
   */
  bulkCreateIOCs = asyncHandler(async (req, res) => {
    const iocsData = req.body;
    const createdBy = req.user.id;

    const result = await IOCService.bulkCreateIOCs(iocsData, createdBy);

    ResponseHandler.created(res, result, 'Bulk IOC creation completed');
  });

  /**
   * Get IOC by ID
   * GET /api/v1/iocs/:id
   */
  getIOCById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const ioc = await IOCService.getIOCById(id);

    ResponseHandler.success(res, ioc, 'IOC retrieved successfully');
  });

  /**
   * Get IOCs with pagination and filtering
   * GET /api/v1/iocs
   */
  getIOCs = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization,
      type: req.query.type,
      status: req.query.status,
      severity: req.query.severity,
      threatType: req.query.threatType,
      source: req.query.source,
      search: req.query.search,
      tags: req.query.tags ? req.query.tags.split(',') : [],
      startDate: req.query.startDate,
      endDate: req.query.endDate,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await IOCService.getIOCs(filters);

    ResponseHandler.paginated(
      res,
      result.iocs,
      result.pagination,
      'IOCs retrieved successfully'
    );
  });

  /**
   * Get IOCs by organization
   * GET /api/v1/iocs/organization/:organizationId
   */
  getIOCsByOrganization = asyncHandler(async (req, res) => {
    const { organizationId } = req.params;
    const options = {
      limit: req.query.limit || 50,
      page: req.query.page || 1,
      sort: req.query.sort || '-createdAt'
    };

    const result = await IOCService.getIOCsByOrganization(organizationId, options);

    ResponseHandler.paginated(
      res,
      result.iocs,
      result.pagination,
      'IOCs retrieved successfully'
    );
  });

  /**
   * Get active IOCs
   * GET /api/v1/iocs/active
   */
  getActiveIOCs = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const iocs = await IOCService.getActiveIOCs(organizationId);

    ResponseHandler.success(res, iocs, 'Active IOCs retrieved successfully');
  });

  /**
   * Get IOC statistics
   * GET /api/v1/iocs/statistics
   */
  getIOCStatistics = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const stats = await IOCService.getIOCStatistics(organizationId);

    ResponseHandler.success(res, stats, 'IOC statistics retrieved successfully');
  });

  /**
   * Get IOCs by incident
   * GET /api/v1/iocs/incident/:incidentId
   */
  getIOCsByIncident = asyncHandler(async (req, res) => {
    const { incidentId } = req.params;
    const iocs = await IOCService.getIOCsByIncident(incidentId);

    ResponseHandler.success(res, iocs, 'IOCs by incident retrieved successfully');
  });

  /**
   * Update IOC
   * PUT /api/v1/iocs/:id
   */
  updateIOC = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;
    const updatedBy = req.user.id;

    const ioc = await IOCService.updateIOC(id, updateData, updatedBy);

    ResponseHandler.success(res, ioc, 'IOC updated successfully');
  });

  /**
   * Delete IOC
   * DELETE /api/v1/iocs/:id
   */
  deleteIOC = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await IOCService.deleteIOC(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Record occurrence for IOC
   * POST /api/v1/iocs/:id/occurrence
   */
  recordOccurrence = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { sourceIP } = req.body;

    const ioc = await IOCService.recordOccurrence(id, sourceIP);

    ResponseHandler.success(res, ioc, 'Occurrence recorded successfully');
  });

  /**
   * Link IOC to incident
   * POST /api/v1/iocs/:id/link-incident
   */
  linkToIncident = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { incidentId } = req.body;

    const ioc = await IOCService.linkToIncident(id, incidentId);

    ResponseHandler.success(res, ioc, 'IOC linked to incident successfully');
  });

  /**
   * Link IOC to alert
   * POST /api/v1/iocs/:id/link-alert
   */
  linkToAlert = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { alertId } = req.body;

    const ioc = await IOCService.linkToAlert(id, alertId);

    ResponseHandler.success(res, ioc, 'IOC linked to alert successfully');
  });

  /**
   * Link multiple IOCs to incident
   * POST /api/v1/iocs/link-to-incident
   */
  linkIOCsToIncident = asyncHandler(async (req, res) => {
    const { iocIds, incidentId } = req.body;

    const results = await IOCService.linkIOCsToIncident(iocIds, incidentId);

    ResponseHandler.success(res, results, 'IOCs linked to incident successfully');
  });

  /**
   * Search IOCs
   * GET /api/v1/iocs/search
   */
  searchIOCs = asyncHandler(async (req, res) => {
    const { query, organizationId, page, limit, sort } = req.query;
    const result = await IOCService.searchIOCs(
      query,
      organizationId || null,
      { page, limit, sort }
    );

    ResponseHandler.paginated(
      res,
      result.iocs,
      result.pagination,
      'IOCs searched successfully'
    );
  });

  /**
   * Check if value matches any IOC
   * POST /api/v1/iocs/check-matches
   */
  checkMatches = asyncHandler(async (req, res) => {
    const { value, organizationId } = req.body;

    const matches = await IOCService.checkMatches(value, organizationId || null);

    ResponseHandler.success(res, {
      value,
      matches: matches.length,
      matchedIOCs: matches.map(ioc => ({
        id: ioc._id,
        type: ioc.type,
        indicator: ioc.indicator,
        severity: ioc.severity,
        confidence: ioc.confidence
      }))
    }, 'Match check completed');
  });

  /**
   * Find IOC by value
   * GET /api/v1/iocs/find
   */
  findIOCByValue = asyncHandler(async (req, res) => {
    const { type, value, organizationId } = req.query;

    const ioc = await IOCService.findIOCByValue(type, value, organizationId || null);

    if (ioc) {
      ResponseHandler.success(res, ioc, 'IOC found');
    } else {
      ResponseHandler.success(res, null, 'IOC not found');
    }
  });

  /**
   * Expire IOC
   * POST /api/v1/iocs/:id/expire
   */
  expireIOC = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const ioc = await IOCService.expireIOC(id);

    ResponseHandler.success(res, ioc, 'IOC expired successfully');
  });

  /**
   * Reactivate IOC
   * POST /api/v1/iocs/:id/reactivate
   */
  reactivateIOC = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const ioc = await IOCService.reactivateIOC(id);

    ResponseHandler.success(res, ioc, 'IOC reactivated successfully');
  });

  /**
   * Import IOCs from threat intelligence feed
   * POST /api/v1/iocs/import
   */
  importFromFeed = asyncHandler(async (req, res) => {
    const { feedData, organizationId } = req.body;
    const createdBy = req.user.id;

    const result = await IOCService.importFromFeed(feedData, organizationId, createdBy);

    ResponseHandler.created(res, result, 'IOCs imported successfully');
  });

  /**
   * Export IOCs
   * GET /api/v1/iocs/export
   */
  exportIOCs = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization,
      type: req.query.type,
      status: req.query.status,
      severity: req.query.severity,
      threatType: req.query.threatType
    };

    const iocs = await IOCService.exportIOCs(filters);

    ResponseHandler.success(res, iocs, 'IOCs exported successfully');
  });

  /**
   * Get IOC types
   * GET /api/v1/iocs/types
   */
  getIOCTypes = asyncHandler(async (req, res) => {
    const types = IOCService.getIOCTypes();

    ResponseHandler.success(res, types, 'IOC types retrieved successfully');
  });

  /**
   * Get IOC statuses
   * GET /api/v1/iocs/statuses
   */
  getIOCStatuses = asyncHandler(async (req, res) => {
    const statuses = IOCService.getIOCStatuses();

    ResponseHandler.success(res, statuses, 'IOC statuses retrieved successfully');
  });

  /**
   * Get IOC sources
   * GET /api/v1/iocs/sources
   */
  getIOCSources = asyncHandler(async (req, res) => {
    const sources = IOCService.getIOCSources();

    ResponseHandler.success(res, sources, 'IOC sources retrieved successfully');
  });

  /**
   * Get threat types
   * GET /api/v1/iocs/threat-types
   */
  getThreatTypes = asyncHandler(async (req, res) => {
    const threatTypes = IOCService.getThreatTypes();

    ResponseHandler.success(res, threatTypes, 'Threat types retrieved successfully');
  });

  /**
   * Get severity levels
   * GET /api/v1/iocs/severities
   */
  getSeverityLevels = asyncHandler(async (req, res) => {
    const severities = IOCService.getSeverityLevels();

    ResponseHandler.success(res, severities, 'Severity levels retrieved successfully');
  });
}

module.exports = new IOCController();