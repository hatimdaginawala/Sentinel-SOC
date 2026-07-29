/**
 * SentinelSOC Dashboard Controller
 */
const Dashboard = {
  charts: {},

  async init() {
    // Check authentication
    if (!Auth.checkAuth()) return;

    // Load metrics
    await this.refreshMetrics();

    // Set interval to refresh metrics every 60s
    setInterval(() => this.refreshMetrics(), 60000);

    // Bind real-time socket events
    window.addEventListener('newalert', (e) => {
      console.log('Dashboard received live alert:', e.detail);
      this.handleLiveAlert(e.detail);
    });

    window.addEventListener('newlog', (e) => {
      this.handleLiveLog(e.detail);
    });
  },

  async refreshMetrics() {
    const orgId = localStorage.getItem('currentOrgId') || '';
    
    try {
      // Show generic spinner or skeleton loading states
      this.toggleLoading(true);

      // Fetch assets, alerts, incidents, and log statistics
      const [assetsRes, alertsRes, incidentsRes, statsRes] = await Promise.all([
        API.get(`/assets?organization=${orgId}`).catch(() => ({ data: { assets: [] } })),
        API.get(`/alerts?organization=${orgId}&status=active`).catch(() => ({ data: { alerts: [] } })),
        API.get(`/incidents?organization=${orgId}`).catch(() => ({ data: { incidents: [] } })),
        API.get(`/logs/statistics?organizationId=${orgId}`).catch(() => ({ data: null }))
      ]);

      const assets = assetsRes.data?.items || assetsRes.data?.assets || (Array.isArray(assetsRes.data) ? assetsRes.data : []);
      const alerts = alertsRes.data?.items || alertsRes.data?.alerts || (Array.isArray(alertsRes.data) ? alertsRes.data : []);
      const incidents = incidentsRes.data?.items || incidentsRes.data?.incidents || (Array.isArray(incidentsRes.data) ? incidentsRes.data : []);
      const stats = statsRes.data || null;

      // 1. Calculate values
      const assetsOnline = assets.filter(a => a.status === 'Online' || a.status === 'active').length;
      const assetsTotal = assets.length;
      
      const criticalCount = alerts.filter(a => a.severity === 'critical').length;
      const highCount = alerts.filter(a => a.severity === 'high').length;
      const mediumCount = alerts.filter(a => a.severity === 'medium').length;
      const lowCount = alerts.filter(a => a.severity === 'low').length;

      // 2. Compute dynamic threat & risk scores
      // Threat Score = (critical * 25) + (high * 10) + (medium * 3)
      const threatScore = Math.min(100, (criticalCount * 25) + (highCount * 10) + (mediumCount * 3));
      // Risk Score = (active incidents * 15) + (critical * 5)
      const activeIncidents = incidents.filter(i => i.status !== 'resolved' && i.status !== 'closed');
      const riskScore = Math.min(100, (activeIncidents.length * 15) + (criticalCount * 5));

      // 3. Update dashboard KPI cards
      this.updateKPICard('threat-score', threatScore, `${this.getThreatLevel(threatScore)} RISK`);
      this.updateKPICard('risk-score', riskScore, `Security Posture: ${100 - riskScore}%`);
      this.updateKPICard('active-alerts', alerts.length, `Critical: ${criticalCount}, High: ${highCount}`);
      this.updateKPICard('assets-online', `${assetsOnline}/${assetsTotal}`, `${assetsTotal - assetsOnline} Offline`);
      
      // Logs/Min calculation
      let totalLogs = 0;
      if (stats && stats.summary) {
        totalLogs = stats.summary.total;
      }
      const logsPerMin = Math.round(totalLogs / 1440) || 0; // Average logs per minute in last 24h
      this.updateKPICard('logs-per-minute', logsPerMin, `Total: ${totalLogs.toLocaleString()}`);

      // 4. Update progress indicators
      this.updateGauge('threat-score', threatScore);
      this.updateGauge('risk-score', riskScore);

      // 5. Render charts
      if (stats) {
        this.renderCharts(stats, alerts);
      }

      // 6. Load tables & feeds
      this.renderRecentThreats(alerts.slice(0, 10));
      this.renderRecentIncidents(activeIncidents.slice(0, 5));

    } catch (error) {
      console.error('Failed to load dashboard metrics:', error);
    } finally {
      this.toggleLoading(false);
    }
  },

  updateKPICard(id, value, subtext) {
    const card = document.getElementById(`kpi-${id}`);
    if (!card) return;

    const valEl = card.querySelector('.kpi-value');
    const subEl = card.querySelector('.kpi-subtext');

    if (valEl) valEl.textContent = value;
    if (subEl) subEl.innerHTML = subtext;
  },

  updateGauge(id, score) {
    const card = document.getElementById(`kpi-${id}`);
    if (!card) return;

    const progress = card.querySelector('.metric-progress-bar');
    if (progress) {
      progress.style.width = `${score}%`;
    }

    // Set semantic colors on the card wrapper
    card.className = 'card kpi-card'; // Reset
    if (score >= 75) {
      card.classList.add('threat-critical');
    } else if (score >= 50) {
      card.classList.add('threat-high');
    } else if (score >= 25) {
      card.classList.add('threat-medium');
    } else {
      card.classList.add('threat-low');
    }
  },

  getThreatLevel(score) {
    if (score >= 75) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 25) return 'MEDIUM';
    return 'LOW';
  },

  toggleLoading(isLoading) {
    const loader = document.getElementById('dashboard-loader');
    if (loader) {
      loader.style.display = isLoading ? 'flex' : 'none';
    }
  },

  renderCharts(stats, alerts) {
    // Destroy previous charts if they exist
    if (this.charts.timeline) this.charts.timeline.destroy();
    if (this.charts.categories) this.charts.categories.destroy();
    if (this.charts.severities) this.charts.severities.destroy();

    // 1. Timeline Chart (Logs volume over time)
    const timelineData = stats.timeline || [];
    const timelineLabels = timelineData.map(t => `${t._id.hour}:00`);
    const timelineCounts = timelineData.map(t => t.count);
    this.charts.timeline = Charts.createLineChart(
      'chart-logs-timeline',
      'Ingested Logs',
      timelineLabels.length ? timelineLabels : ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
      timelineCounts.length ? timelineCounts : [0, 0, 0, 0, 0, 0]
    );

    // 2. Categories Chart (Logs category breakdown)
    const catData = stats.categoryBreakdown || [];
    const catLabels = catData.map(c => c._id);
    const catCounts = catData.map(c => c.count);
    this.charts.categories = Charts.createBarChart(
      'chart-logs-categories',
      'Event Category Count',
      catLabels.length ? catLabels : ['Auth', 'System', 'Network'],
      catCounts.length ? catCounts : [0, 0, 0]
    );

    // 3. Severities Chart (Alert severity distribution)
    const criticalCount = alerts.filter(a => a.severity === 'critical').length;
    const highCount = alerts.filter(a => a.severity === 'high').length;
    const mediumCount = alerts.filter(a => a.severity === 'medium').length;
    const lowCount = alerts.filter(a => a.severity === 'low').length;

    this.charts.severities = Charts.createDoughnutChart(
      'chart-alerts-severities',
      ['Critical', 'High', 'Medium', 'Low'],
      [criticalCount, highCount, mediumCount, lowCount]
    );
  },

  renderRecentThreats(threats) {
    const container = document.getElementById('recent-threats-list');
    if (!container) return;

    if (threats.length === 0) {
      container.innerHTML = `<div class="p-4 text-center text-muted">No recent threats detected</div>`;
      return;
    }

    let html = '';
    threats.forEach(t => {
      html += `
        <div class="threat-item ${t.severity}">
          <div class="threat-details">
            <span class="threat-name">${Utils.escapeHTML(t.title)}</span>
            <span class="threat-meta">
              <span>Source: ${Utils.escapeHTML(t.sourceIP || 'Internal')}</span>
              <span>Category: ${Utils.escapeHTML(t.category || 'Threat')}</span>
            </span>
          </div>
          <span class="threat-time">${Utils.formatRelativeTime(t.createdAt)}</span>
        </div>
      `;
    });

    container.innerHTML = html;
  },

  renderRecentIncidents(incidents) {
    const container = document.getElementById('recent-incidents-list');
    if (!container) return;

    if (incidents.length === 0) {
      container.innerHTML = `<div class="p-4 text-center text-muted">No active incidents</div>`;
      return;
    }

    let html = '';
    incidents.forEach(inc => {
      let severityBadge = '';
      if (inc.severity === 'critical') severityBadge = 'badge-critical';
      else if (inc.severity === 'high') severityBadge = 'badge-high';
      else if (inc.severity === 'medium') severityBadge = 'badge-medium';
      else severityBadge = 'badge-low';

      html += `
        <div class="activity-item">
          <div class="activity-icon"><i class="fa-solid fa-ticket"></i></div>
          <div class="activity-content">
            <span class="activity-msg">
              <strong>${Utils.escapeHTML(inc.title)}</strong> [Status: ${inc.status}]
            </span>
            <span class="activity-time">${Utils.formatRelativeTime(inc.createdAt)}</span>
          </div>
        </div>
      `;
    });

    container.innerHTML = html;
  },

  handleLiveAlert(alert) {
    // Append to live alert feed and refresh numbers
    this.refreshMetrics();
  },

  handleLiveLog(log) {
    const feed = document.getElementById('live-logs-feed');
    if (!feed) return;

    const row = document.createElement('div');
    row.className = `activity-item ${log.severity === 'critical' || log.severity === 'high' ? 'danger' : ''}`;
    row.innerHTML = `
      <div class="activity-icon"><i class="fa-solid fa-file-lines"></i></div>
      <div class="activity-content">
        <span class="activity-msg">
          <strong>${Utils.escapeHTML(log.eventType)}</strong> (${log.severity}) - ${Utils.escapeHTML(log.message)}
        </span>
        <span class="activity-time">${Utils.formatRelativeTime(log.eventTime)}</span>
      </div>
    `;

    feed.prepend(row);

    // Keep max 20 rows
    if (feed.children.length > 20) {
      feed.removeChild(feed.lastChild);
    }
  }
};

window.Dashboard = Dashboard;
