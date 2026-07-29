const ThreatRule = require('../models/ThreatRule');
const Organization = require('../models/Organization');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS, RULE_TYPES } = require('../config/constants');
const logger = require('../config/logger');

class ThreatRuleService {
  /**
   * Create a new threat rule
   */
  async createRule(ruleData, createdBy) {
    try {
      // Validate organization
      const organization = await Organization.findById(ruleData.organization);
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Check if rule name already exists
      const existingRule = await ThreatRule.findOne({
        name: ruleData.name,
        organization: ruleData.organization
      });
      if (existingRule) {
        throw new AppError(
          'Rule with this name already exists',
          HTTP_STATUS.CONFLICT,
          'RULE_EXISTS'
        );
      }

      // Validate condition structure
      if (!ruleData.condition || Object.keys(ruleData.condition).length === 0) {
        throw new AppError(
          'Rule condition is required',
          HTTP_STATUS.BAD_REQUEST,
          'CONDITION_REQUIRED'
        );
      }

      // Create rule
      const rule = new ThreatRule({
        ...ruleData,
        createdBy: createdBy
      });

      await rule.save();

      logger.info(`Threat rule created: ${rule.name} (${rule.type}) by ${createdBy}`);

      return await ThreatRule.getRuleWithPopulated(rule._id);
    } catch (error) {
      logger.error('Error creating threat rule:', error);
      throw error;
    }
  }

  /**
   * Get rule by ID
   */
  async getRuleById(ruleId) {
    try {
      const rule = await ThreatRule.getRuleWithPopulated(ruleId);

      if (!rule) {
        throw new AppError('Rule not found', HTTP_STATUS.NOT_FOUND, 'RULE_NOT_FOUND');
      }

      return rule;
    } catch (error) {
      logger.error('Error getting rule:', error);
      throw error;
    }
  }

  /**
   * Get rules with pagination and filtering
   */
  async getRules(filters = {}) {
    try {
      const result = await ThreatRule.getRules(filters);
      return result;
    } catch (error) {
      logger.error('Error getting rules:', error);
      throw error;
    }
  }

  /**
   * Get enabled rules
   */
  async getEnabledRules(organizationId = null) {
    try {
      const rules = await ThreatRule.getEnabledRules(organizationId);
      return rules;
    } catch (error) {
      logger.error('Error getting enabled rules:', error);
      throw error;
    }
  }

  /**
   * Get rules by threat type
   */
  async getRulesByThreatType(threatType, organizationId = null) {
    try {
      const rules = await ThreatRule.findByThreatType(threatType, organizationId);
      return rules;
    } catch (error) {
      logger.error('Error getting rules by threat type:', error);
      throw error;
    }
  }

  /**
   * Get rules by category
   */
  async getRulesByCategory(category, organizationId = null) {
    try {
      const rules = await ThreatRule.findByCategory(category, organizationId);
      return rules;
    } catch (error) {
      logger.error('Error getting rules by category:', error);
      throw error;
    }
  }

  /**
   * Get rule statistics
   */
  async getRuleStatistics(organizationId = null) {
    try {
      const stats = await ThreatRule.getStatistics(organizationId);
      return stats;
    } catch (error) {
      logger.error('Error getting rule statistics:', error);
      throw error;
    }
  }

  /**
   * Update rule
   */
  async updateRule(ruleId, updateData, updatedBy) {
    try {
      const rule = await ThreatRule.findById(ruleId);

      if (!rule) {
        throw new AppError('Rule not found', HTTP_STATUS.NOT_FOUND, 'RULE_NOT_FOUND');
      }

      // Check if name is being changed and validate uniqueness
      if (updateData.name && updateData.name !== rule.name) {
        const existingRule = await ThreatRule.findOne({
          name: updateData.name,
          organization: rule.organization,
          _id: { $ne: ruleId }
        });
        if (existingRule) {
          throw new AppError(
            'Rule with this name already exists',
            HTTP_STATUS.CONFLICT,
            'RULE_EXISTS'
          );
        }
      }

      // Update rule
      const updatedRule = await ThreatRule.findByIdAndUpdate(
        ruleId,
        {
          ...updateData,
          updatedBy: updatedBy,
          updatedAt: new Date()
        },
        {
          new: true,
          runValidators: true
        }
      )
      .populate('organization', 'name code')
      .populate('createdBy', 'username email')
      .populate('updatedBy', 'username email');

      logger.info(`Threat rule updated: ${updatedRule.name} by ${updatedBy}`);

      return updatedRule;
    } catch (error) {
      logger.error('Error updating rule:', error);
      throw error;
    }
  }

  /**
   * Delete rule
   */
  async deleteRule(ruleId, deletedBy) {
    try {
      const rule = await ThreatRule.findById(ruleId);

      if (!rule) {
        throw new AppError('Rule not found', HTTP_STATUS.NOT_FOUND, 'RULE_NOT_FOUND');
      }

      await rule.remove();

      logger.info(`Threat rule deleted: ${ruleId} by ${deletedBy}`);

      return { success: true, message: 'Rule deleted successfully' };
    } catch (error) {
      logger.error('Error deleting rule:', error);
      throw error;
    }
  }

  /**
   * Enable/disable rule
   */
  async toggleRule(ruleId, enabled, updatedBy) {
    try {
      const rule = await ThreatRule.findById(ruleId);

      if (!rule) {
        throw new AppError('Rule not found', HTTP_STATUS.NOT_FOUND, 'RULE_NOT_FOUND');
      }

      rule.enabled = enabled;
      rule.updatedBy = updatedBy;
      await rule.save();

      logger.info(`Threat rule ${enabled ? 'enabled' : 'disabled'}: ${rule.name} by ${updatedBy}`);

      return await ThreatRule.getRuleWithPopulated(rule._id);
    } catch (error) {
      logger.error('Error toggling rule:', error);
      throw error;
    }
  }

  /**
   * Clone rule
   */
  async cloneRule(ruleId, newName, createdBy) {
    try {
      const rule = await ThreatRule.findById(ruleId);

      if (!rule) {
        throw new AppError('Rule not found', HTTP_STATUS.NOT_FOUND, 'RULE_NOT_FOUND');
      }

      const clonedRule = await rule.clone(newName, createdBy);

      logger.info(`Threat rule cloned: ${rule.name} -> ${clonedRule.name} by ${createdBy}`);

      return await ThreatRule.getRuleWithPopulated(clonedRule._id);
    } catch (error) {
      logger.error('Error cloning rule:', error);
      throw error;
    }
  }

  /**
   * Search rules
   */
  async searchRules(query, organizationId = null, options = {}) {
    try {
      const result = await ThreatRule.searchRules(query, organizationId, options);
      return result;
    } catch (error) {
      logger.error('Error searching rules:', error);
      throw error;
    }
  }

  /**
   * Record rule trigger
   */
  async recordTrigger(ruleId, log) {
    try {
      const rule = await ThreatRule.findById(ruleId);

      if (!rule) {
        throw new AppError('Rule not found', HTTP_STATUS.NOT_FOUND, 'RULE_NOT_FOUND');
      }

      await rule.recordTrigger(log);

      logger.debug(`Rule triggered: ${rule.name}`);

      return rule;
    } catch (error) {
      logger.error('Error recording rule trigger:', error);
      throw error;
    }
  }

  /**
   * Process logs against rules
   */
  async processLogAgainstRules(log, organizationId = null) {
    try {
      const rules = await this.getEnabledRules(organizationId);
      const triggeredRules = [];

      for (const rule of rules) {
        if (rule.shouldTrigger(log)) {
          // Record trigger
          await rule.recordTrigger(log);
          
          // Collect actions
          const actions = rule.actions.map(action => ({
            ruleId: rule._id,
            ruleName: rule.name,
            action: action.type,
            configuration: action.configuration
          }));

          triggeredRules.push({
            rule: rule,
            actions: actions
          });
        }
      }

      return triggeredRules;
    } catch (error) {
      logger.error('Error processing logs against rules:', error);
      throw error;
    }
  }

  /**
   * Validate rule condition
   */
  validateCondition(condition) {
    try {
      // Check if condition has valid structure
      if (!condition || typeof condition !== 'object') {
        return { valid: false, error: 'Condition must be an object' };
      }

      // Check for valid operators
      const validOperators = ['$and', '$or', '$not', '$eq', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', '$regex', '$contains', '$startsWith', '$endsWith'];
      
      const validateNode = (node, path = '') => {
        if (typeof node !== 'object' || node === null) return true;
        
        for (const [key, value] of Object.entries(node)) {
          if (key.startsWith('$')) {
            if (!validOperators.includes(key)) {
              return { valid: false, error: `Invalid operator: ${key}` };
            }
          }
        }
        return true;
      };

      const result = validateNode(condition);
      if (result !== true) {
        return result;
      }

      return { valid: true };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  /**
   * Get rule types for dropdown
   */
  getRuleTypes() {
    return ThreatRule.getRuleTypes();
  }

  /**
   * Get categories for dropdown
   */
  getCategories() {
    return ThreatRule.getCategories();
  }

  /**
   * Get threat types for dropdown
   */
  getThreatTypes() {
    return ThreatRule.getThreatTypes();
  }

  /**
   * Get action types for dropdown
   */
  getActionTypes() {
    return ThreatRule.getActionTypes();
  }

  /**
   * Get MITRE tactics for dropdown
   */
  getMitreTactics() {
    return ThreatRule.getMitreTactics();
  }

  /**
   * Bulk import rules
   */
  async bulkImportRules(rulesData, organizationId, createdBy) {
    try {
      const imported = [];
      const errors = [];

      for (const ruleData of rulesData) {
        try {
          const rule = await this.createRule({
            ...ruleData,
            organization: organizationId
          }, createdBy);
          imported.push(rule);
        } catch (error) {
          errors.push({
            data: ruleData,
            error: error.message
          });
        }
      }

      return {
        imported,
        errors,
        total: rulesData.length,
        successful: imported.length,
        failed: errors.length
      };
    } catch (error) {
      logger.error('Error bulk importing rules:', error);
      throw error;
    }
  }

  /**
   * Export rules
   */
  async exportRules(filters = {}) {
    try {
      const { rules } = await ThreatRule.getRules({ ...filters, limit: 1000 });
      
      return rules.map(rule => ({
        name: rule.name,
        description: rule.description,
        type: rule.type,
        severity: rule.severity,
        category: rule.category,
        threatType: rule.threatType,
        condition: rule.condition,
        actions: rule.actions,
        enabled: rule.enabled,
        priority: rule.priority,
        cooldown: rule.cooldown,
        suppression: rule.suppression,
        tags: rule.tags,
        references: rule.references,
        mitreAttack: rule.mitreAttack
      }));
    } catch (error) {
      logger.error('Error exporting rules:', error);
      throw error;
    }
  }
}

module.exports = new ThreatRuleService();