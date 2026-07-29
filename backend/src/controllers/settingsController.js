const SettingsService = require("../services/settingsService");
const ResponseHandler = require('../utils/responseHandler');
const { asyncHandler } = require('../middleware/errorHandler');

class SettingsController {
  /**
   * Get settings by organization
   * GET /api/v1/settings
   */
  getSettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const settings = await SettingsService.getSettings(organizationId);

    ResponseHandler.success(res, settings, 'Settings retrieved successfully');
  });

  /**
   * Update settings
   * PUT /api/v1/settings
   */
  updateSettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const updateData = req.body;
    const updatedBy = req.user.id;

    const settings = await SettingsService.updateSettings(organizationId, updateData, updatedBy);

    ResponseHandler.success(res, settings, 'Settings updated successfully');
  });

  /**
   * Update specific setting by path
   * PATCH /api/v1/settings/:path
   */
  updateSetting = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const { path } = req.params;
    const { value } = req.body;
    const updatedBy = req.user.id;

    const settings = await SettingsService.updateSetting(organizationId, path, value, updatedBy);

    ResponseHandler.success(res, settings, 'Setting updated successfully');
  });

  /**
   * Get specific setting by path
   * GET /api/v1/settings/:path
   */
  getSetting = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const { path } = req.params;

    const value = await SettingsService.getSetting(organizationId, path);

    ResponseHandler.success(res, { path, value }, 'Setting retrieved successfully');
  });

  /**
   * Get security settings
   * GET /api/v1/settings/security
   */
  getSecuritySettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const settings = await SettingsService.getSecuritySettings(organizationId);

    ResponseHandler.success(res, settings, 'Security settings retrieved successfully');
  });

  /**
   * Update security settings
   * PUT /api/v1/settings/security
   */
  updateSecuritySettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const securityData = req.body;
    const updatedBy = req.user.id;

    const settings = await SettingsService.updateSecuritySettings(organizationId, securityData, updatedBy);

    ResponseHandler.success(res, settings, 'Security settings updated successfully');
  });

  /**
   * Get notification settings
   * GET /api/v1/settings/notifications
   */
  getNotificationSettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const settings = await SettingsService.getNotificationSettings(organizationId);

    ResponseHandler.success(res, settings, 'Notification settings retrieved successfully');
  });

  /**
   * Update notification settings
   * PUT /api/v1/settings/notifications
   */
  updateNotificationSettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const notificationData = req.body;
    const updatedBy = req.user.id;

    const settings = await SettingsService.updateNotificationSettings(organizationId, notificationData, updatedBy);

    ResponseHandler.success(res, settings, 'Notification settings updated successfully');
  });

  /**
   * Get retention settings
   * GET /api/v1/settings/retention
   */
  getRetentionSettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const settings = await SettingsService.getRetentionSettings(organizationId);

    ResponseHandler.success(res, settings, 'Retention settings retrieved successfully');
  });

  /**
   * Update retention settings
   * PUT /api/v1/settings/retention
   */
  updateRetentionSettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const retentionData = req.body;
    const updatedBy = req.user.id;

    const settings = await SettingsService.updateRetentionSettings(organizationId, retentionData, updatedBy);

    ResponseHandler.success(res, settings, 'Retention settings updated successfully');
  });

  /**
   * Reset settings to default
   * POST /api/v1/settings/reset
   */
  resetSettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const updatedBy = req.user.id;

    const settings = await SettingsService.resetSettings(organizationId, updatedBy);

    ResponseHandler.success(res, settings, 'Settings reset to default successfully');
  });

  /**
   * Add IP to whitelist
   * POST /api/v1/settings/whitelist
   */
  addIPToWhitelist = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const { ip } = req.body;
    const updatedBy = req.user.id;

    const settings = await SettingsService.addIPToWhitelist(organizationId, ip, updatedBy);

    ResponseHandler.success(res, settings, 'IP added to whitelist successfully');
  });

  /**
   * Remove IP from whitelist
   * DELETE /api/v1/settings/whitelist/:ip
   */
  removeIPFromWhitelist = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const { ip } = req.params;
    const updatedBy = req.user.id;

    const settings = await SettingsService.removeIPFromWhitelist(organizationId, ip, updatedBy);

    ResponseHandler.success(res, settings, 'IP removed from whitelist successfully');
  });

  /**
   * Add webhook
   * POST /api/v1/settings/webhooks
   */
  addWebhook = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const webhookData = req.body;
    const updatedBy = req.user.id;

    const settings = await SettingsService.addWebhook(organizationId, webhookData, updatedBy);

    ResponseHandler.created(res, settings, 'Webhook added successfully');
  });

  /**
   * Remove webhook
   * DELETE /api/v1/settings/webhooks/:webhookId
   */
  removeWebhook = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const { webhookId } = req.params;
    const updatedBy = req.user.id;

    const settings = await SettingsService.removeWebhook(organizationId, parseInt(webhookId), updatedBy);

    ResponseHandler.success(res, settings, 'Webhook removed successfully');
  });

  /**
   * Validate SMTP settings
   * POST /api/v1/settings/validate-smtp
   */
  validateSMTP = asyncHandler(async (req, res) => {
    const smtpData = req.body;
    const result = await SettingsService.validateSMTPSettings(smtpData);

    if (result.valid) {
      ResponseHandler.success(res, result, 'SMTP settings are valid');
    } else {
      ResponseHandler.badRequest(res, result.message);
    }
  });

  /**
   * Validate Slack webhook
   * POST /api/v1/settings/validate-slack
   */
  validateSlack = asyncHandler(async (req, res) => {
    const { webhookUrl } = req.body;
    const result = await SettingsService.validateSlackWebhook(webhookUrl);

    if (result.valid) {
      ResponseHandler.success(res, result, 'Slack webhook is valid');
    } else {
      ResponseHandler.badRequest(res, result.message);
    }
  });

  /**
   * Get general settings
   * GET /api/v1/settings/general
   */
  getGeneralSettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const settings = await SettingsService.getGeneralSettings(organizationId);

    ResponseHandler.success(res, settings, 'General settings retrieved successfully');
  });

  /**
   * Get dashboard settings
   * GET /api/v1/settings/dashboard
   */
  getDashboardSettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const settings = await SettingsService.getDashboardSettings(organizationId);

    ResponseHandler.success(res, settings, 'Dashboard settings retrieved successfully');
  });

  /**
   * Update dashboard settings
   * PUT /api/v1/settings/dashboard
   */
  updateDashboardSettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const dashboardData = req.body;
    const updatedBy = req.user.id;

    const settings = await SettingsService.updateDashboardSettings(organizationId, dashboardData, updatedBy);

    ResponseHandler.success(res, settings, 'Dashboard settings updated successfully');
  });

  /**
   * Update logging settings
   * PUT /api/v1/settings/logging
   */
  updateLoggingSettings = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const loggingData = req.body;
    const updatedBy = req.user.id;

    const settings = await SettingsService.updateLoggingSettings(organizationId, loggingData, updatedBy);

    ResponseHandler.success(res, settings, 'Logging settings updated successfully');
  });

  /**
   * Check if feature is enabled
   * GET /api/v1/settings/feature/:featurePath
   */
  isFeatureEnabled = asyncHandler(async (req, res) => {
    const organizationId = req.user.organization;
    const { featurePath } = req.params;

    const enabled = await SettingsService.isFeatureEnabled(organizationId, featurePath);

    ResponseHandler.success(res, { featurePath, enabled }, 'Feature status retrieved successfully');
  });
}

module.exports = new SettingsController();