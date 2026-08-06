// services/schedulerService.js
const cron = require('node-cron');
const AutomationService = require('./automationService');
const ReportService = require('./reportService');
const IOCService = require('./iocService');
const logger = require('../config/logger');

class SchedulerService {
  constructor() {
    this.jobs = [];
  }

  /**
   * Initialize all scheduled jobs
   */
  initialize() {
    // Job 1: Process pending logs every minute
    this.jobs.push(
      cron.schedule('*/1 * * * *', async () => {
        try {
          await this.processPendingLogs();
        } catch (error) {
          logger.error('Error processing pending logs:', error);
        }
      })
    );

    // Job 2: Generate scheduled reports every hour
    this.jobs.push(
      cron.schedule('0 * * * *', async () => {
        try {
          await AutomationService.checkReportSchedules();
        } catch (error) {
          logger.error('Error generating scheduled reports:', error);
        }
      })
    );

    // Job 3: Clean up old data daily at 2 AM
    this.jobs.push(
      cron.schedule('0 2 * * *', async () => {
        try {
          await this.cleanupOldData();
        } catch (error) {
          logger.error('Error cleaning up old data:', error);
        }
      })
    );

    // Job 4: Update threat intelligence every 6 hours
    this.jobs.push(
      cron.schedule('0 */6 * * *', async () => {
        try {
          await this.updateThreatIntelligence();
        } catch (error) {
          logger.error('Error updating threat intelligence:', error);
        }
      })
    );

    // Job 5: Auto-resolve stale incidents every 30 minutes
    this.jobs.push(
      cron.schedule('*/30 * * * *', async () => {
        try {
          await this.autoResolveStaleIncidents();
        } catch (error) {
          logger.error('Error auto-resolving stale incidents:', error);
        }
      })
    );

    logger.info(' Scheduler initialized with 5 jobs');
    return this.jobs;
  }

  /**
   * Process pending logs
   */
  async processPendingLogs() {
    const Log = require('../models/Log');
    const pendingLogs = await Log.find({ status: 'pending' }).limit(100);
    
    for (const log of pendingLogs) {
      await AutomationService.processLog(log);
    }
    
    if (pendingLogs.length > 0) {
      logger.info(`Processed ${pendingLogs.length} pending logs`);
    }
  }

  /**
   * Clean up old data based on retention settings
   */
  async cleanupOldData() {
    const Settings = require('../models/Settings');
    const settings = await Settings.findOne({});
    
    if (!settings) return;

    const retention = settings.retention;
    
    // Clean up logs
    if (retention.logs.enabled) {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retention.logs.days);
      await Log.deleteMany({ createdAt: { $lt: cutoffDate } });
    }
    
    // Clean up alerts
    if (retention.alerts.enabled) {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retention.alerts.days);
      await Alert.deleteMany({ 
        status: 'closed',
        createdAt: { $lt: cutoffDate } 
      });
    }
    
    // Clean up audit logs
    if (retention.auditLogs.enabled) {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retention.auditLogs.days);
      await AuditLog.deleteMany({ createdAt: { $lt: cutoffDate } });
    }
    
    logger.info(' Cleaned up old data');
  }

  /**
   * Auto-resolve stale incidents
   */
  async autoResolveStaleIncidents() {
    const Incident = require('../models/Incident');
    const Settings = require('../models/Settings');
    
    const settings = await Settings.findOne({});
    if (!settings) return;

    const timeout = settings.detection?.alerts?.autoResolution?.timeout || 24;
    const cutoffDate = new Date();
    cutoffDate.setHours(cutoffDate.getHours() - timeout);

    const staleIncidents = await Incident.find({
      status: { $in: ['new', 'investigating', 'in_progress'] },
      createdAt: { $lt: cutoffDate }
    });

    for (const incident of staleIncidents) {
      // Check if alerts are resolved
      const unresolvedAlerts = await Alert.find({
        _id: { $in: incident.alerts },
        status: { $ne: 'resolved' }
      });

      if (unresolvedAlerts.length === 0) {
        await IncidentService.resolveIncident(
          incident._id,
          null,
          'contained',
          'Auto-resolved after timeout with all alerts resolved',
          [],
          'Automated resolution'
        );
      } else {
        await IncidentService.escalateIncident(
          incident._id,
          null,
          null,
          `Auto-escalated after ${timeout} hours timeout`
        );
      }
    }
  }

  /**
   * Update threat intelligence
   */
  async updateThreatIntelligence() {
    // Fetch external threat feeds
    // Update IOCs
    // Update threat rules
    logger.info(' Updated threat intelligence');
  }

  /**
   * Stop all scheduled jobs
   */
  stopAll() {
    for (const job of this.jobs) {
      job.stop();
    }
    logger.info(' All scheduled jobs stopped');
  }
}

module.exports = new SchedulerService();