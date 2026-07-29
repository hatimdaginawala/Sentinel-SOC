const ReportService = require('../services/reportService');
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');

class ReportController {
  /**
   * Create a new report
   * POST /api/v1/reports
   */
  createReport = asyncHandler(async (req, res) => {
    const reportData = req.body;
    const createdBy = req.user.id;

    const report = await ReportService.createReport(reportData, createdBy);

    ResponseHandler.created(res, report, 'Report created successfully');
  });

  /**
   * Get report by ID
   * GET /api/v1/reports/:id
   */
  getReportById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const report = await ReportService.getReportById(id);

    ResponseHandler.success(res, report, 'Report retrieved successfully');
  });

  /**
   * Get reports with pagination and filtering
   * GET /api/v1/reports
   */
  getReports = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization,
      type: req.query.type,
      status: req.query.status,
      format: req.query.format,
      search: req.query.search,
      startDate: req.query.startDate,
      endDate: req.query.endDate,
      scheduledOnly: req.query.scheduledOnly,
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await ReportService.getReports(filters);

    ResponseHandler.paginated(
      res,
      result.reports,
      result.pagination,
      'Reports retrieved successfully'
    );
  });

  /**
   * Get report statistics
   * GET /api/v1/reports/statistics
   */
  getReportStatistics = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const stats = await ReportService.getReportStatistics(organizationId);

    ResponseHandler.success(res, stats, 'Report statistics retrieved successfully');
  });

  /**
   * Update report
   * PUT /api/v1/reports/:id
   */
  updateReport = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;
    const updatedBy = req.user.id;

    const report = await ReportService.updateReport(id, updateData, updatedBy);

    ResponseHandler.success(res, report, 'Report updated successfully');
  });

  /**
   * Delete report
   * DELETE /api/v1/reports/:id
   */
  deleteReport = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await ReportService.deleteReport(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Generate report
   * POST /api/v1/reports/:id/generate
   */
  generateReport = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const report = await ReportService.generateReportData(id);

    ResponseHandler.success(res, report, 'Report generation started successfully');
  });

  /**
   * Schedule report
   * POST /api/v1/reports/:id/schedule
   */
  scheduleReport = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const scheduleData = req.body;
    const updatedBy = req.user.id;

    const report = await ReportService.scheduleReport(id, scheduleData, updatedBy);

    ResponseHandler.success(res, report, 'Report scheduled successfully');
  });

  /**
   * Unschedule report
   * POST /api/v1/reports/:id/unschedule
   */
  unscheduleReport = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updatedBy = req.user.id;

    const report = await ReportService.unscheduleReport(id, updatedBy);

    ResponseHandler.success(res, report, 'Report unscheduled successfully');
  });

  /**
   * Get scheduled reports
   * GET /api/v1/reports/scheduled
   */
  getScheduledReports = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const reports = await ReportService.getScheduledReports(organizationId);

    ResponseHandler.success(res, reports, 'Scheduled reports retrieved successfully');
  });

  /**
   * Get report types
   * GET /api/v1/reports/types
   */
  getReportTypes = asyncHandler(async (req, res) => {
    const types = ReportService.getReportTypes();

    ResponseHandler.success(res, types, 'Report types retrieved successfully');
  });

  /**
   * Get report formats
   * GET /api/v1/reports/formats
   */
  getReportFormats = asyncHandler(async (req, res) => {
    const formats = ReportService.getReportFormats();

    ResponseHandler.success(res, formats, 'Report formats retrieved successfully');
  });

  /**
   * Get report statuses
   * GET /api/v1/reports/statuses
   */
  getReportStatuses = asyncHandler(async (req, res) => {
    const statuses = ReportService.getReportStatuses();

    ResponseHandler.success(res, statuses, 'Report statuses retrieved successfully');
  });

  /**
   * Get scheduled frequencies
   * GET /api/v1/reports/frequencies
   */
  getScheduledFrequencies = asyncHandler(async (req, res) => {
    const frequencies = ReportService.getScheduledFrequencies();

    ResponseHandler.success(res, frequencies, 'Scheduled frequencies retrieved successfully');
  });
}

module.exports = new ReportController();