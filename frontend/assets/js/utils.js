/**
 * SentinelSOC Shared Utilities
 */
const Utils = {
  /**
   * Format datetime ISO strings into readable local dates
   */
  formatDate(dateString) {
    if (!dateString) return 'N/A';
    try {
      const date = new Date(dateString);
      return date.toLocaleString();
    } catch (e) {
      return dateString;
    }
  },

  /**
   * Return time duration relative to now
   */
  formatRelativeTime(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHr = Math.floor(diffMin / 60);
    const diffDays = Math.floor(diffHr / 24);

    if (diffSec < 60) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHr < 24) return `${diffHr}h ago`;
    return `${diffDays}d ago`;
  },

  /**
   * Safely escape HTML characters to prevent XSS
   */
  escapeHTML(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  },

  /**
   * Return severity CSS badge class
   */
  getSeverityBadgeClass(severity) {
    if (!severity) return 'badge-info';
    switch (severity.toLowerCase()) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      case 'low': return 'badge-low';
      case 'info': return 'badge-info';
      default: return 'badge-info';
    }
  },

  /**
   * Return asset type icon class for FontAwesome
   */
  getAssetTypeIcon(type) {
    if (!type) return 'fa-server';
    switch (type.toLowerCase()) {
      case 'server': return 'fa-server';
      case 'workstation': return 'fa-laptop';
      case 'firewall': return 'fa-shield-halved';
      case 'router': return 'fa-route';
      case 'switch': return 'fa-network-wired';
      case 'cloud_server': return 'fa-cloud';
      case 'web_application': return 'fa-globe';
      case 'database': return 'fa-database';
      case 'security_appliance': return 'fa-lock';
      default: return 'fa-cube';
    }
  },

  /**
   * Get log source type badge styling
   */
  getLogSourceIcon(type) {
    if (!type) return 'fa-file-lines';
    switch (type.toLowerCase()) {
      case 'windows': return 'fa-windows';
      case 'linux': return 'fa-linux';
      case 'apache':
      case 'nginx': return 'fa-server';
      case 'pfsense':
      case 'firewall': return 'fa-shield-halved';
      case 'suricata':
      case 'snort': return 'fa-bug';
      default: return 'fa-terminal';
    }
  }
};

window.Utils = Utils;
