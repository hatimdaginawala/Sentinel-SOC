const ThreatRuleService = require('../services/threatRuleService');
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');

class ThreatRuleController {
  /**
   * Create a new threat rule
   * POST /api/v1/threat-rules
   */
  createRule = asyncHandler(async (req, res) => {
    const ruleData = req.body;
    const createdBy = req.user.id;

    const rule = await ThreatRuleService.createRule(ruleData, createdBy);

    ResponseHandler.created(res, rule, 'Threat rule created successfully');
  });

  /**
   * Get rule by ID
   * GET /api/v1/threat-rules/:id
   */
  getRuleById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const rule = await ThreatRuleService.getRuleById(id);

    ResponseHandler.success(res, rule, 'Threat rule retrieved successfully');
  });

  /**
   * Get rules with pagination and filtering
   * GET /api/v1/threat-rules
   */
  getRules = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization,
      type: req.query.type,
      severity: req.query.severity,
      category: req.query.category,
      threatType: req.query.threatType,
      enabled: req.query.enabled,
      search: req.query.search,
      tags: req.query.tags ? req.query.tags.split(',') : [],
      page: req.query.page,
      limit: req.query.limit,
      sort: req.query.sort
    };

    const result = await ThreatRuleService.getRules(filters);

    ResponseHandler.paginated(
      res,
      result.rules,
      result.pagination,
      'Threat rules retrieved successfully'
    );
  });

  /**
   * Get enabled rules
   * GET /api/v1/threat-rules/enabled
   */
  getEnabledRules = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const rules = await ThreatRuleService.getEnabledRules(organizationId);

    ResponseHandler.success(res, rules, 'Enabled threat rules retrieved successfully');
  });

  /**
   * Get rules by threat type
   * GET /api/v1/threat-rules/threat-type/:threatType
   */
  getRulesByThreatType = asyncHandler(async (req, res) => {
    const { threatType } = req.params;
    const organizationId = req.query.organizationId || null;
    const rules = await ThreatRuleService.getRulesByThreatType(threatType, organizationId);

    ResponseHandler.success(res, rules, 'Threat rules by threat type retrieved successfully');
  });

  /**
   * Get rules by category
   * GET /api/v1/threat-rules/category/:category
   */
  getRulesByCategory = asyncHandler(async (req, res) => {
    const { category } = req.params;
    const organizationId = req.query.organizationId || null;
    const rules = await ThreatRuleService.getRulesByCategory(category, organizationId);

    ResponseHandler.success(res, rules, 'Threat rules by category retrieved successfully');
  });

  /**
   * Get rule statistics
   * GET /api/v1/threat-rules/statistics
   */
  getRuleStatistics = asyncHandler(async (req, res) => {
    const organizationId = req.query.organizationId || null;
    const stats = await ThreatRuleService.getRuleStatistics(organizationId);

    ResponseHandler.success(res, stats, 'Threat rule statistics retrieved successfully');
  });

  /**
   * Update rule
   * PUT /api/v1/threat-rules/:id
   */
  updateRule = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;
    const updatedBy = req.user.id;

    const rule = await ThreatRuleService.updateRule(id, updateData, updatedBy);

    ResponseHandler.success(res, rule, 'Threat rule updated successfully');
  });

  /**
   * Delete rule
   * DELETE /api/v1/threat-rules/:id
   */
  deleteRule = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const deletedBy = req.user.id;

    const result = await ThreatRuleService.deleteRule(id, deletedBy);

    ResponseHandler.success(res, null, result.message);
  });

  /**
   * Enable/disable rule
   * PATCH /api/v1/threat-rules/:id/toggle
   */
  toggleRule = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { enabled } = req.body;
    const updatedBy = req.user.id;

    const rule = await ThreatRuleService.toggleRule(id, enabled, updatedBy);

    ResponseHandler.success(res, rule, `Rule ${enabled ? 'enabled' : 'disabled'} successfully`);
  });

  /**
   * Clone rule
   * POST /api/v1/threat-rules/:id/clone
   */
  cloneRule = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { name } = req.body;
    const createdBy = req.user.id;

    const rule = await ThreatRuleService.cloneRule(id, name, createdBy);

    ResponseHandler.created(res, rule, 'Rule cloned successfully');
  });

  /**
   * Search rules
   * GET /api/v1/threat-rules/search
   */
  searchRules = asyncHandler(async (req, res) => {
    const { query, organizationId, page, limit, sort } = req.query;
    const result = await ThreatRuleService.searchRules(
      query,
      organizationId || null,
      { page, limit, sort }
    );

    ResponseHandler.paginated(
      res,
      result.rules,
      result.pagination,
      'Threat rules searched successfully'
    );
  });

  /**
   * Validate rule condition
   * POST /api/v1/threat-rules/validate-condition
   */
  validateCondition = asyncHandler(async (req, res) => {
    const { condition } = req.body;

    const result = ThreatRuleService.validateCondition(condition);

    if (result.valid) {
      ResponseHandler.success(res, { valid: true }, 'Condition is valid');
    } else {
      ResponseHandler.badRequest(res, result.error, { valid: false, error: result.error });
    }
  });

  /**
   * Process log against rules
   * POST /api/v1/threat-rules/process-log
   */
  processLogAgainstRules = asyncHandler(async (req, res) => {
    const { log, organizationId } = req.body;

    const triggeredRules = await ThreatRuleService.processLogAgainstRules(log, organizationId);

    ResponseHandler.success(
      res,
      {
        triggered: triggeredRules.length,
        rules: triggeredRules
      },
      'Log processed against rules successfully'
    );
  });

  /**
   * Bulk import rules
   * POST /api/v1/threat-rules/import
   */
  bulkImportRules = asyncHandler(async (req, res) => {
    const { rules, organizationId } = req.body;
    const createdBy = req.user.id;

    const result = await ThreatRuleService.bulkImportRules(rules, organizationId, createdBy);

    ResponseHandler.created(res, result, 'Rules imported successfully');
  });

  /**
   * Export rules
   * GET /api/v1/threat-rules/export
   */
  exportRules = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization,
      type: req.query.type,
      severity: req.query.severity,
      category: req.query.category,
      threatType: req.query.threatType,
      enabled: req.query.enabled
    };

    const rules = await ThreatRuleService.exportRules(filters);

    ResponseHandler.success(res, rules, 'Rules exported successfully');
  });

  /**
   * Get rule types
   * GET /api/v1/threat-rules/types
   */
  getRuleTypes = asyncHandler(async (req, res) => {
    const types = ThreatRuleService.getRuleTypes();

    ResponseHandler.success(res, types, 'Rule types retrieved successfully');
  });

  /**
   * Get categories
   * GET /api/v1/threat-rules/categories
   */
  getCategories = asyncHandler(async (req, res) => {
    const categories = ThreatRuleService.getCategories();

    ResponseHandler.success(res, categories, 'Categories retrieved successfully');
  });

  /**
   * Get threat types
   * GET /api/v1/threat-rules/threat-types
   */
  getThreatTypes = asyncHandler(async (req, res) => {
    const threatTypes = ThreatRuleService.getThreatTypes();

    ResponseHandler.success(res, threatTypes, 'Threat types retrieved successfully');
  });

  /**
   * Get action types
   * GET /api/v1/threat-rules/action-types
   */
  getActionTypes = asyncHandler(async (req, res) => {
    const actionTypes = ThreatRuleService.getActionTypes();

    ResponseHandler.success(res, actionTypes, 'Action types retrieved successfully');
  });

  /**
   * Get MITRE tactics
   * GET /api/v1/threat-rules/mitre-tactics
   */
  getMitreTactics = asyncHandler(async (req, res) => {
    const tactics = ThreatRuleService.getMitreTactics();

    ResponseHandler.success(res, tactics, 'MITRE ATT&CK tactics retrieved successfully');
  });
}

module.exports = new ThreatRuleController();