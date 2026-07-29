const Report = require('../models/Report');
const Organization = require('../models/Organization');
const Alert = require('../models/Alert');
const Incident = require('../models/Incident');
const Log = require('../models/Log');
const { AppError } = require('../middleware/errorHandler');
const { HTTP_STATUS, REPORT_TYPES, REPORT_FORMATS } = require('../config/constants');
const logger = require('../config/logger');
const PDFKit = require('pdfkit');
const ExcelJS = require('exceljs');
const fs = require('fs');
const path = require('path');

class ReportService {
  /**
   * Create a new report
   */
  async createReport(reportData, createdBy) {
    try {
      // Validate organization
      const organization = await Organization.findById(reportData.organization);
      if (!organization) {
        throw new AppError('Organization not found', HTTP_STATUS.NOT_FOUND, 'ORGANIZATION_NOT_FOUND');
      }

      // Validate date range
      if (reportData.filters.startDate > reportData.filters.endDate) {
        throw new AppError('Start date must be before end date', HTTP_STATUS.BAD_REQUEST, 'INVALID_DATE_RANGE');
      }

      // Create report
      const report = new Report({
        ...reportData,
        createdBy: createdBy,
        generatedBy: createdBy
      });

      await report.save();

      logger.info(`Report created: ${report.title} (${report.type}) by ${createdBy}`);

      return await this.getReportById(report._id);
    } catch (error) {
      logger.error('Error creating report:', error);
      throw error;
    }
  }

  /**
   * Get report by ID
   */
  async getReportById(reportId) {
    try {
      const report = await Report.findById(reportId)
        .populate('organization', 'name code')
        .populate('generatedBy', 'username email firstName lastName')
        .populate('createdBy', 'username email firstName lastName')
        .populate('updatedBy', 'username email firstName lastName');

      if (!report) {
        throw new AppError('Report not found', HTTP_STATUS.NOT_FOUND, 'REPORT_NOT_FOUND');
      }

      return report;
    } catch (error) {
      logger.error('Error getting report:', error);
      throw error;
    }
  }

  /**
   * Get reports with pagination and filtering
   */
  async getReports(filters = {}) {
    try {
      const result = await Report.getReports(filters);
      return result;
    } catch (error) {
      logger.error('Error getting reports:', error);
      throw error;
    }
  }

  /**
   * Get report statistics
   */
  async getReportStatistics(organizationId = null) {
    try {
      const stats = await Report.getStatistics(organizationId);
      return stats;
    } catch (error) {
      logger.error('Error getting report statistics:', error);
      throw error;
    }
  }

  /**
   * Update report
   */
  async updateReport(reportId, updateData, updatedBy) {
    try {
      const report = await Report.findById(reportId);

      if (!report) {
        throw new AppError('Report not found', HTTP_STATUS.NOT_FOUND, 'REPORT_NOT_FOUND');
      }

      // Can't update completed reports
      if (report.status === 'completed') {
        throw new AppError('Cannot update a completed report', HTTP_STATUS.BAD_REQUEST, 'REPORT_COMPLETED');
      }

      // Update report
      const updatedReport = await Report.findByIdAndUpdate(
        reportId,
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
      .populate('generatedBy', 'username email')
      .populate('createdBy', 'username email')
      .populate('updatedBy', 'username email');

      logger.info(`Report updated: ${updatedReport.title} by ${updatedBy}`);

      return updatedReport;
    } catch (error) {
      logger.error('Error updating report:', error);
      throw error;
    }
  }

  /**
   * Delete report
   */
  async deleteReport(reportId, deletedBy) {
    try {
      const report = await Report.findById(reportId);

      if (!report) {
        throw new AppError('Report not found', HTTP_STATUS.NOT_FOUND, 'REPORT_NOT_FOUND');
      }

      // Delete file if exists
      if (report.filePath && fs.existsSync(report.filePath)) {
        fs.unlinkSync(report.filePath);
      }

      await report.remove();

      logger.info(`Report deleted: ${reportId} by ${deletedBy}`);

      return { success: true, message: 'Report deleted successfully' };
    } catch (error) {
      logger.error('Error deleting report:', error);
      throw error;
    }
  }

  /**
   * Generate report data
   */
  async generateReportData(reportId) {
    try {
      const report = await Report.findById(reportId);

      if (!report) {
        throw new AppError('Report not found', HTTP_STATUS.NOT_FOUND, 'REPORT_NOT_FOUND');
      }

      await report.markProcessing();

      const filters = report.filters;
      const data = await this.collectReportData(report.type, filters);

      await report.updateData(data);
      await report.markCompleted({
        url: null,
        name: `${report.title}.${report.format}`,
        size: 0,
        path: null
      });

      logger.info(`Report data generated: ${report.title}`);

      return await this.getReportById(reportId);
    } catch (error) {
      logger.error('Error generating report data:', error);
      const report = await Report.findById(reportId);
      if (report) {
        await report.markFailed(error.message);
      }
      throw error;
    }
  }

  /**
   * Collect report data based on type
   */
  async collectReportData(type, filters) {
    const startDate = new Date(filters.startDate);
    const endDate = new Date(filters.endDate);

    switch (type) {
      case REPORT_TYPES.DAILY:
        return await this.collectDailyReportData(filters);
      case REPORT_TYPES.WEEKLY:
        return await this.collectWeeklyReportData(filters);
      case REPORT_TYPES.MONTHLY:
        return await this.collectMonthlyReportData(filters);
      case REPORT_TYPES.EXECUTIVE:
        return await this.collectExecutiveReportData(filters);
      case REPORT_TYPES.INCIDENT:
        return await this.collectIncidentReportData(filters);
      case REPORT_TYPES.RISK:
        return await this.collectRiskReportData(filters);
      case REPORT_TYPES.COMPLIANCE:
        return await this.collectComplianceReportData(filters);
      default:
        return await this.collectGeneralReportData(filters);
    }
  }

  /**
   * Collect daily report data
   */
  async collectDailyReportData(filters) {
    const startDate = new Date(filters.startDate);
    const endDate = new Date(filters.endDate);

    const [alerts, incidents, logs] = await Promise.all([
      Alert.find({
        organization: filters.organization || { $exists: true },
        createdAt: { $gte: startDate, $lte: endDate }
      }),
      Incident.find({
        organization: filters.organization || { $exists: true },
        createdAt: { $gte: startDate, $lte: endDate }
      }),
      Log.find({
        organization: filters.organization || { $exists: true },
        eventTime: { $gte: startDate, $lte: endDate }
      })
    ]);

    return {
      summary: {
        total: alerts.length + incidents.length,
        alerts: alerts.length,
        incidents: incidents.length,
        logs: logs.length,
        critical: alerts.filter(a => a.severity === 'critical').length,
        high: alerts.filter(a => a.severity === 'high').length,
        medium: alerts.filter(a => a.severity === 'medium').length,
        low: alerts.filter(a => a.severity === 'low').length
      },
      alerts: alerts.slice(0, 50),
      incidents: incidents.slice(0, 20)
    };
  }

  /**
   * Collect weekly report data
   */
  async collectWeeklyReportData(filters) {
    const baseData = await this.collectDailyReportData(filters);
    
    // Group by day
    const alerts = await Alert.find({
      organization: filters.organization || { $exists: true },
      createdAt: { $gte: new Date(filters.startDate), $lte: new Date(filters.endDate) }
    });

    const dailyStats = {};
    alerts.forEach(alert => {
      const day = alert.createdAt.toISOString().split('T')[0];
      if (!dailyStats[day]) dailyStats[day] = { total: 0, critical: 0, high: 0 };
      dailyStats[day].total++;
      if (alert.severity === 'critical') dailyStats[day].critical++;
      if (alert.severity === 'high') dailyStats[day].high++;
    });

    return {
      ...baseData,
      dailyStats: Object.entries(dailyStats).map(([date, stats]) => ({
        date,
        ...stats
      }))
    };
  }

  /**
   * Collect monthly report data
   */
  async collectMonthlyReportData(filters) {
    const baseData = await this.collectWeeklyReportData(filters);
    
    // Additional monthly statistics
    const alerts = await Alert.find({
      organization: filters.organization || { $exists: true },
      createdAt: { $gte: new Date(filters.startDate), $lte: new Date(filters.endDate) }
    });

    // Top threat types
    const threatTypes = {};
    alerts.forEach(alert => {
      if (alert.threatType) {
        threatTypes[alert.threatType] = (threatTypes[alert.threatType] || 0) + 1;
      }
    });

    return {
      ...baseData,
      topThreatTypes: Object.entries(threatTypes)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([name, count]) => ({ name, count })),
      monthlySummary: {
        totalAlerts: alerts.length,
        avgDailyAlerts: Math.round(alerts.length / 30),
        peakDay: baseData.dailyStats?.reduce((max, day) => 
          day.total > max.total ? day : max, { total: 0 }
        )
      }
    };
  }

  /**
   * Collect executive report data
   */
  async collectExecutiveReportData(filters) {
    const [alerts, incidents, logs] = await Promise.all([
      Alert.find({
        organization: filters.organization || { $exists: true },
        createdAt: { $gte: new Date(filters.startDate), $lte: new Date(filters.endDate) }
      }),
      Incident.find({
        organization: filters.organization || { $exists: true },
        createdAt: { $gte: new Date(filters.startDate), $lte: new Date(filters.endDate) }
      }),
      Log.countDocuments({
        organization: filters.organization || { $exists: true },
        eventTime: { $gte: new Date(filters.startDate), $lte: new Date(filters.endDate) }
      })
    ]);

    // Calculate MTTR
    const resolvedIncidents = incidents.filter(i => i.resolution?.resolvedAt);
    const avgMTTR = resolvedIncidents.length > 0
      ? resolvedIncidents.reduce((sum, i) => 
          sum + (i.resolution.resolvedAt - i.createdAt), 0) / resolvedIncidents.length
      : 0;

    // Top affected assets
    const assets = {};
    alerts.forEach(alert => {
      if (alert.asset) {
        const key = alert.asset.toString();
        assets[key] = (assets[key] || 0) + 1;
      }
    });

    return {
      executiveSummary: {
        totalAlerts: alerts.length,
        criticalAlerts: alerts.filter(a => a.severity === 'critical').length,
        highAlerts: alerts.filter(a => a.severity === 'high').length,
        totalIncidents: incidents.length,
        openIncidents: incidents.filter(i => 
          ['new', 'investigating', 'in_progress'].includes(i.status)
        ).length,
        resolvedIncidents: incidents.filter(i => i.status === 'resolved').length,
        totalLogs: logs,
        avgMTTR: Math.round(avgMTTR / (1000 * 60 * 60)) // hours
      },
      topAffectedAssets: Object.entries(assets)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([id, count]) => ({ assetId: id, count })),
      severityTrend: {
        critical: alerts.filter(a => a.severity === 'critical').length,
        high: alerts.filter(a => a.severity === 'high').length,
        medium: alerts.filter(a => a.severity === 'medium').length,
        low: alerts.filter(a => a.severity === 'low').length
      },
      keyMetrics: {
        alertsPerDay: Math.round(alerts.length / 30),
        incidentResolutionRate: incidents.length > 0
          ? Math.round((resolvedIncidents.length / incidents.length) * 100)
          : 0,
        averageSeverity: alerts.length > 0
          ? (alerts.reduce((sum, a) => {
              const scores = { critical: 4, high: 3, medium: 2, low: 1 };
              return sum + (scores[a.severity] || 0);
            }, 0) / alerts.length).toFixed(1)
          : 0
      }
    };
  }

  /**
   * Collect incident report data
   */
  async collectIncidentReportData(filters) {
    const incidents = await Incident.find({
      organization: filters.organization || { $exists: true },
      createdAt: { $gte: new Date(filters.startDate), $lte: new Date(filters.endDate) }
    }).populate('assignedTo', 'username email');

    const categories = {};
    const statuses = {};
    const severities = {};
    const assignees = {};

    incidents.forEach(incident => {
      categories[incident.category] = (categories[incident.category] || 0) + 1;
      statuses[incident.status] = (statuses[incident.status] || 0) + 1;
      severities[incident.severity] = (severities[incident.severity] || 0) + 1;
      if (incident.assignedTo) {
        const key = incident.assignedTo.username;
        assignees[key] = (assignees[key] || 0) + 1;
      }
    });

    return {
      summary: {
        total: incidents.length,
        byCategory: categories,
        byStatus: statuses,
        bySeverity: severities,
        byAssignee: assignees,
        avgResolutionTime: incidents
          .filter(i => i.resolution?.resolvedAt)
          .reduce((sum, i) => sum + (i.resolution.resolvedAt - i.createdAt), 0) / 
          (incidents.filter(i => i.resolution?.resolvedAt).length || 1)
      },
      incidents: incidents.map(i => ({
        title: i.title,
        severity: i.severity,
        status: i.status,
        category: i.category,
        assignedTo: i.assignedTo?.username || 'Unassigned',
        createdAt: i.createdAt,
        resolvedAt: i.resolution?.resolvedAt
      }))
    };
  }

  /**
   * Collect risk report data
   */
  async collectRiskReportData(filters) {
    const [alerts, incidents] = await Promise.all([
      Alert.find({
        organization: filters.organization || { $exists: true },
        createdAt: { $gte: new Date(filters.startDate), $lte: new Date(filters.endDate) }
      }),
      Incident.find({
        organization: filters.organization || { $exists: true },
        createdAt: { $gte: new Date(filters.startDate), $lte: new Date(filters.endDate) }
      })
    ]);

    const riskScore = {
      total: 0,
      bySeverity: {
        critical: alerts.filter(a => a.severity === 'critical').length * 10,
        high: alerts.filter(a => a.severity === 'high').length * 7,
        medium: alerts.filter(a => a.severity === 'medium').length * 4,
        low: alerts.filter(a => a.severity === 'low').length * 2
      },
      byCategory: {},
      trends: {}
    };

    // Calculate total risk score
    riskScore.total = Object.values(riskScore.bySeverity).reduce((a, b) => a + b, 0);

    // Risk by category
    alerts.forEach(alert => {
      if (alert.category) {
        riskScore.byCategory[alert.category] = (riskScore.byCategory[alert.category] || 0) + 
          (alert.severity === 'critical' ? 10 : 
           alert.severity === 'high' ? 7 : 
           alert.severity === 'medium' ? 4 : 2);
      }
    });

    return {
      riskScore,
      alertsCount: alerts.length,
      incidentsCount: incidents.length,
      riskAssessment: {
        overall: riskScore.total > 100 ? 'High' : 
                 riskScore.total > 50 ? 'Medium' : 'Low',
        recommendations: this.generateRiskRecommendations(riskScore, alerts, incidents)
      }
    };
  }

  /**
   * Collect compliance report data
   */
  async collectComplianceReportData(filters) {
    // This is a placeholder - implement based on compliance requirements
    return {
      complianceStatus: {
        overall: 'Compliant',
        checks: [
          { name: 'Log Retention', status: 'Pass', details: 'All logs retained for 90 days' },
          { name: 'Access Control', status: 'Pass', details: 'RBAC properly configured' },
          { name: 'Encryption', status: 'Warning', details: 'Some data not encrypted at rest' }
        ],
        violations: []
      },
      regulations: {
        gdpr: { status: 'Compliant', lastAudit: new Date() },
        hipaa: { status: 'Warning', lastAudit: new Date() },
        pci: { status: 'Compliant', lastAudit: new Date() },
        soc2: { status: 'Compliant', lastAudit: new Date() }
      }
    };
  }

  /**
   * Collect general report data
   */
  async collectGeneralReportData(filters) {
    const [alerts, incidents, logs] = await Promise.all([
      Alert.find({
        organization: filters.organization || { $exists: true },
        createdAt: { $gte: new Date(filters.startDate), $lte: new Date(filters.endDate) }
      }),
      Incident.find({
        organization: filters.organization || { $exists: true },
        createdAt: { $gte: new Date(filters.startDate), $lte: new Date(filters.endDate) }
      }),
      Log.countDocuments({
        organization: filters.organization || { $exists: true },
        eventTime: { $gte: new Date(filters.startDate), $lte: new Date(filters.endDate) }
      })
    ]);

    return {
      summary: {
        totalAlerts: alerts.length,
        totalIncidents: incidents.length,
        totalLogs: logs,
        criticalAlerts: alerts.filter(a => a.severity === 'critical').length,
        highAlerts: alerts.filter(a => a.severity === 'high').length,
        openIncidents: incidents.filter(i => 
          ['new', 'investigating', 'in_progress'].includes(i.status)
        ).length,
        resolvedIncidents: incidents.filter(i => i.status === 'resolved').length
      }
    };
  }

  /**
   * Generate risk recommendations
   */
  generateRiskRecommendations(riskScore, alerts, incidents) {
    const recommendations = [];

    if (riskScore.total > 100) {
      recommendations.push('High risk detected - consider immediate security review');
    }

    if (alerts.filter(a => a.severity === 'critical').length > 5) {
      recommendations.push('Multiple critical alerts - investigate and prioritize remediation');
    }

    if (incidents.filter(i => i.status === 'new').length > 3) {
      recommendations.push('Multiple unassigned incidents - consider assigning more resources');
    }

    return recommendations.length > 0 ? recommendations : ['Current risk level is acceptable - continue monitoring'];
  }

  /**
   * Get report types for dropdown
   */
  getReportTypes() {
    return Report.getReportTypes();
  }

  /**
   * Get report formats for dropdown
   */
  getReportFormats() {
    return Report.getReportFormats();
  }

  /**
   * Get report statuses for dropdown
   */
  getReportStatuses() {
    return Report.getReportStatuses();
  }

  /**
   * Get scheduled frequencies for dropdown
   */
  getScheduledFrequencies() {
    return Report.getScheduledFrequencies();
  }

  /**
   * Schedule report generation
   */
  async scheduleReport(reportId, scheduleData, updatedBy) {
    try {
      const report = await Report.findById(reportId);

      if (!report) {
        throw new AppError('Report not found', HTTP_STATUS.NOT_FOUND, 'REPORT_NOT_FOUND');
      }

      report.scheduled = {
        enabled: true,
        frequency: scheduleData.frequency,
        time: scheduleData.time,
        dayOfWeek: scheduleData.dayOfWeek,
        dayOfMonth: scheduleData.dayOfMonth,
        recipients: scheduleData.recipients || [],
        nextRun: this.calculateNextRun(scheduleData)
      };
      report.updatedBy = updatedBy;

      await report.save();

      logger.info(`Report scheduled: ${report.title} by ${updatedBy}`);

      return await this.getReportById(reportId);
    } catch (error) {
      logger.error('Error scheduling report:', error);
      throw error;
    }
  }

  /**
   * Calculate next run time for scheduled report
   */
  calculateNextRun(scheduleData) {
    const now = new Date();
    const [hours, minutes] = (scheduleData.time || '09:00').split(':').map(Number);
    const nextRun = new Date(now);
    nextRun.setHours(hours, minutes, 0, 0);

    switch (scheduleData.frequency) {
      case 'daily':
        if (nextRun <= now) nextRun.setDate(nextRun.getDate() + 1);
        break;
      case 'weekly':
        const targetDay = scheduleData.dayOfWeek || 1;
        while (nextRun.getDay() !== targetDay) {
          nextRun.setDate(nextRun.getDate() + 1);
        }
        if (nextRun <= now) nextRun.setDate(nextRun.getDate() + 7);
        break;
      case 'monthly':
        const targetDate = scheduleData.dayOfMonth || 1;
        nextRun.setDate(targetDate);
        if (nextRun <= now) nextRun.setMonth(nextRun.getMonth() + 1);
        break;
      case 'quarterly':
        nextRun.setMonth(Math.floor(now.getMonth() / 3) * 3 + 3);
        if (nextRun <= now) nextRun.setMonth(nextRun.getMonth() + 3);
        break;
    }

    return nextRun;
  }

  /**
   * Unschedule report
   */
  async unscheduleReport(reportId, updatedBy) {
    try {
      const report = await Report.findById(reportId);

      if (!report) {
        throw new AppError('Report not found', HTTP_STATUS.NOT_FOUND, 'REPORT_NOT_FOUND');
      }

      report.scheduled.enabled = false;
      report.updatedBy = updatedBy;
      await report.save();

      logger.info(`Report unscheduled: ${report.title} by ${updatedBy}`);

      return await this.getReportById(reportId);
    } catch (error) {
      logger.error('Error unscheduling report:', error);
      throw error;
    }
  }

  /**
   * Get scheduled reports
   */
  async getScheduledReports(organizationId = null) {
    try {
      const reports = await Report.getScheduledReports(organizationId);
      return reports;
    } catch (error) {
      logger.error('Error getting scheduled reports:', error);
      throw error;
    }
  }
}

module.exports = new ReportService();