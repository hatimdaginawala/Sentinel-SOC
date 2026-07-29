const Settings = require('../models/Settings');
const Organization = require('../models/Organization');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS } = require('../config/constants');
const logger = require('../config/logger');

class SettingsService {
  /**
   * Get settings by organization
   */
  async getSettings(organizationId) {
    try {
      const settings = await Settings.getOrCreate(organizationId);
      return settings;
    } catch (error) {
      logger.error('Error getting settings:', error);
      throw error;
    }
  }

  /**
   * Update settings
   */
  async updateSettings(organizationId, updateData, updatedBy) {
    try {
      const settings = await Settings.findOne({ organization: organizationId });
      
      if (!settings) {
        throw new AppError('Settings not found', HTTP_STATUS.NOT_FOUND, 'SETTINGS_NOT_FOUND');
      }

      // Validate organization exists
      const organization = await Organization.findById(organizationId);
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Update settings
      const updatedSettings = await Settings.findByIdAndUpdate(
        settings._id,
        {
          ...updateData,
          updatedBy: updatedBy,
          updatedAt: new Date()
        },
        {
          new: true,
          runValidators: true
        }
      );

      logger.info(`Settings updated for organization: ${organizationId} by ${updatedBy}`);

      return updatedSettings;
    } catch (error) {
      logger.error('Error updating settings:', error);
      throw error;
    }
  }

  /**
   * Update specific setting by path
   */
  async updateSetting(organizationId, path, value, updatedBy) {
    try {
      const settings = await Settings.findOne({ organization: organizationId });
      
      if (!settings) {
        throw new AppError('Settings not found', HTTP_STATUS.NOT_FOUND, 'SETTINGS_NOT_FOUND');
      }

      await settings.updateSetting(path, value, updatedBy);

      logger.info(`Setting ${path} updated for organization ${organizationId} by ${updatedBy}`);

      return settings;
    } catch (error) {
      logger.error('Error updating setting:', error);
      throw error;
    }
  }

  /**
   * Get specific setting by path
   */
  async getSetting(organizationId, path) {
    try {
      const value = await Settings.getSettingValue(organizationId, path);
      return value;
    } catch (error) {
      logger.error('Error getting setting:', error);
      throw error;
    }
  }

  /**
   * Get security settings
   */
  async getSecuritySettings(organizationId) {
    try {
      const settings = await this.getSettings(organizationId);
      return settings.getSecuritySettings();
    } catch (error) {
      logger.error('Error getting security settings:', error);
      throw error;
    }
  }

  /**
   * Get notification settings
   */
  async getNotificationSettings(organizationId) {
    try {
      const settings = await this.getSettings(organizationId);
      return settings.getNotificationSettings();
    } catch (error) {
      logger.error('Error getting notification settings:', error);
      throw error;
    }
  }

  /**
   * Get retention settings
   */
  async getRetentionSettings(organizationId) {
    try {
      const settings = await this.getSettings(organizationId);
      return settings.getRetentionSettings();
    } catch (error) {
      logger.error('Error getting retention settings:', error);
      throw error;
    }
  }

  /**
   * Check if feature is enabled
   */
  async isFeatureEnabled(organizationId, featurePath) {
    try {
      const settings = await this.getSettings(organizationId);
      return settings.isFeatureEnabled(featurePath);
    } catch (error) {
      logger.error('Error checking feature enabled:', error);
      return false;
    }
  }

  /**
   * Update security settings
   */
  async updateSecuritySettings(organizationId, securityData, updatedBy) {
    try {
      const settings = await this.getSettings(organizationId);
      
      // Validate password policy
      if (securityData.passwordPolicy) {
        const policy = securityData.passwordPolicy;
        if (policy.minLength < 6 || policy.minLength > 30) {
          throw new AppError('Password min length must be between 6 and 30', HTTP_STATUS.BAD_REQUEST);
        }
        if (policy.maxLoginAttempts < 1 || policy.maxLoginAttempts > 20) {
          throw new AppError('Max login attempts must be between 1 and 20', HTTP_STATUS.BAD_REQUEST);
        }
        if (policy.lockoutDuration < 5 || policy.lockoutDuration > 1440) {
          throw new AppError('Lockout duration must be between 5 and 1440 minutes', HTTP_STATUS.BAD_REQUEST);
        }
      }

      settings.security = {
        ...settings.security,
        ...securityData
      };
      settings.updatedBy = updatedBy;
      await settings.save();

      logger.info(`Security settings updated for organization ${organizationId} by ${updatedBy}`);

      return settings;
    } catch (error) {
      logger.error('Error updating security settings:', error);
      throw error;
    }
  }

  /**
   * Update notification settings
   */
  async updateNotificationSettings(organizationId, notificationData, updatedBy) {
    try {
      const settings = await this.getSettings(organizationId);
      
      settings.notifications = {
        ...settings.notifications,
        ...notificationData
      };
      settings.updatedBy = updatedBy;
      await settings.save();

      logger.info(`Notification settings updated for organization ${organizationId} by ${updatedBy}`);

      return settings;
    } catch (error) {
      logger.error('Error updating notification settings:', error);
      throw error;
    }
  }

  /**
   * Update retention settings
   */
  async updateRetentionSettings(organizationId, retentionData, updatedBy) {
    try {
      const settings = await this.getSettings(organizationId);
      
      // Validate retention days
      const maxRetention = 365 * 3; // 3 years max
      for (const [key, value] of Object.entries(retentionData)) {
        if (value && value.days && (value.days < 1 || value.days > maxRetention)) {
          throw new AppError(`Retention days for ${key} must be between 1 and ${maxRetention}`, HTTP_STATUS.BAD_REQUEST);
        }
      }

      settings.retention = {
        ...settings.retention,
        ...retentionData
      };
      settings.updatedBy = updatedBy;
      await settings.save();

      logger.info(`Retention settings updated for organization ${organizationId} by ${updatedBy}`);

      return settings;
    } catch (error) {
      logger.error('Error updating retention settings:', error);
      throw error;
    }
  }

  /**
   * Reset settings to default
   */
  async resetSettings(organizationId, updatedBy) {
    try {
      const settings = await Settings.findOne({ organization: organizationId });
      
      if (!settings) {
        throw new AppError('Settings not found', HTTP_STATUS.NOT_FOUND, 'SETTINGS_NOT_FOUND');
      }

      const defaultSettings = Settings.getDefaultSettings();
      
      // Reset all settings to default
      Object.keys(defaultSettings).forEach(key => {
        settings[key] = defaultSettings[key];
      });
      
      settings.updatedBy = updatedBy;
      await settings.save();

      logger.info(`Settings reset to default for organization ${organizationId} by ${updatedBy}`);

      return settings;
    } catch (error) {
      logger.error('Error resetting settings:', error);
      throw error;
    }
  }

  /**
   * Add IP to whitelist
   */
  async addIPToWhitelist(organizationId, ip, updatedBy) {
    try {
      const settings = await this.getSettings(organizationId);
      
      if (!settings.security.ipWhitelist.includes(ip)) {
        settings.security.ipWhitelist.push(ip);
        settings.updatedBy = updatedBy;
        await settings.save();
      }

      logger.info(`IP ${ip} added to whitelist for organization ${organizationId} by ${updatedBy}`);

      return settings;
    } catch (error) {
      logger.error('Error adding IP to whitelist:', error);
      throw error;
    }
  }

  /**
   * Remove IP from whitelist
   */
  async removeIPFromWhitelist(organizationId, ip, updatedBy) {
    try {
      const settings = await this.getSettings(organizationId);
      
      settings.security.ipWhitelist = settings.security.ipWhitelist.filter(
        item => item !== ip
      );
      settings.updatedBy = updatedBy;
      await settings.save();

      logger.info(`IP ${ip} removed from whitelist for organization ${organizationId} by ${updatedBy}`);

      return settings;
    } catch (error) {
      logger.error('Error removing IP from whitelist:', error);
      throw error;
    }
  }

  /**
   * Add webhook
   */
  async addWebhook(organizationId, webhookData, updatedBy) {
    try {
      const settings = await this.getSettings(organizationId);
      
      settings.notifications.webhooks.push({
        ...webhookData,
        active: true
      });
      settings.updatedBy = updatedBy;
      await settings.save();

      logger.info(`Webhook added for organization ${organizationId} by ${updatedBy}`);

      return settings;
    } catch (error) {
      logger.error('Error adding webhook:', error);
      throw error;
    }
  }

  /**
   * Remove webhook
   */
  async removeWebhook(organizationId, webhookId, updatedBy) {
    try {
      const settings = await this.getSettings(organizationId);
      
      settings.notifications.webhooks = settings.notifications.webhooks.filter(
        (_, index) => index !== webhookId
      );
      settings.updatedBy = updatedBy;
      await settings.save();

      logger.info(`Webhook removed for organization ${organizationId} by ${updatedBy}`);

      return settings;
    } catch (error) {
      logger.error('Error removing webhook:', error);
      throw error;
    }
  }

  /**
   * Validate SMTP settings
   */
  async validateSMTPSettings(smtpData) {
    try {
      const nodemailer = require('nodemailer');
      
      const transporter = nodemailer.createTransport({
        host: smtpData.smtpHost,
        port: smtpData.smtpPort,
        secure: smtpData.smtpSecure,
        auth: {
          user: smtpData.smtpUser,
          pass: smtpData.smtpPass
        }
      });

      await transporter.verify();
      
      return { valid: true, message: 'SMTP settings are valid' };
    } catch (error) {
      return { valid: false, message: error.message };
    }
  }

  /**
   * Validate Slack webhook
   */
  async validateSlackWebhook(webhookUrl) {
    try {
      const axios = require('axios');
      
      const response = await axios.post(webhookUrl, {
        text: 'Test message from SentinelSOC - Settings validation'
      }, {
        timeout: 5000
      });

      return { valid: response.status === 200, message: 'Slack webhook is valid' };
    } catch (error) {
      return { valid: false, message: error.message };
    }
  }

  /**
   * Get general settings
   */
  async getGeneralSettings(organizationId) {
    try {
      const settings = await this.getSettings(organizationId);
      return settings.general;
    } catch (error) {
      logger.error('Error getting general settings:', error);
      throw error;
    }
  }

  /**
   * Get dashboard settings
   */
  async getDashboardSettings(organizationId) {
    try {
      const settings = await this.getSettings(organizationId);
      return settings.dashboard;
    } catch (error) {
      logger.error('Error getting dashboard settings:', error);
      throw error;
    }
  }

  /**
   * Update dashboard settings
   */
  async updateDashboardSettings(organizationId, dashboardData, updatedBy) {
    try {
      const settings = await this.getSettings(organizationId);
      
      settings.dashboard = {
        ...settings.dashboard,
        ...dashboardData
      };
      settings.updatedBy = updatedBy;
      await settings.save();

      logger.info(`Dashboard settings updated for organization ${organizationId} by ${updatedBy}`);

      return settings;
    } catch (error) {
      logger.error('Error updating dashboard settings:', error);
      throw error;
    }
  }

  /**
   * Update logging settings
   */
  async updateLoggingSettings(organizationId, loggingData, updatedBy) {
    try {
      const settings = await this.getSettings(organizationId);
      
      settings.logging = {
        ...settings.logging,
        ...loggingData
      };
      settings.updatedBy = updatedBy;
      await settings.save();

      logger.info(`Logging settings updated for organization ${organizationId} by ${updatedBy}`);

      return settings;
    } catch (error) {
      logger.error('Error updating logging settings:', error);
      throw error;
    }
  }
}

module.exports = new SettingsService();