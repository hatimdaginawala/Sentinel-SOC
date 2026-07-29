/**
 * SentinelSOC Notifications Drawer Handler
 */
const Notifications = {
  notifications: [],

  init() {
    this.bindDrawer();
    this.loadNotifications();
    
    // Listen for new alerts via socket to add to notification list
    window.addEventListener('newalert', (e) => {
      this.addNotification(e.detail);
    });
  },

  bindDrawer() {
    const btn = document.getElementById('navbar-notifications-btn');
    const drawer = document.getElementById('notifications-drawer');
    const closeBtn = document.getElementById('notifications-close-btn');

    if (btn && drawer) {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        drawer.classList.toggle('active');
      });
    }

    if (closeBtn && drawer) {
      closeBtn.addEventListener('click', () => {
        drawer.classList.remove('active');
      });
    }

    // Close on click outside
    document.addEventListener('click', (e) => {
      if (drawer && drawer.classList.contains('active')) {
        if (!drawer.contains(e.target) && !btn.contains(e.target)) {
          drawer.classList.remove('active');
        }
      }
    });
  },

  async loadNotifications() {
    try {
      // Use active alerts as the core system notifications list
      const response = await API.get('/alerts?status=active&limit=10');
      if (response.success && response.data) {
        const alerts = response.data.items || response.data.alerts || (Array.isArray(response.data) ? response.data : []);
        this.notifications = alerts;
        this.renderNotifications();
      }
    } catch (error) {
      console.error('Failed to load notifications:', error);
    }
  },

  addNotification(alert) {
    // Add to top of stack
    this.notifications.unshift(alert);
    // Keep max 15
    if (this.notifications.length > 15) {
      this.notifications.pop();
    }
    this.renderNotifications();
  },

  renderNotifications() {
    const listEl = document.getElementById('notifications-list');
    const countEl = document.getElementById('notifications-count-badge');
    const indicatorEl = document.getElementById('notifications-badge-dot');

    if (!listEl) return;

    const unreadCount = this.notifications.filter(n => n.status === 'active').length;

    // Update count labels
    if (countEl) {
      countEl.textContent = unreadCount;
      countEl.style.display = unreadCount > 0 ? 'inline-block' : 'none';
    }
    if (indicatorEl) {
      indicatorEl.style.display = unreadCount > 0 ? 'block' : 'none';
    }

    if (this.notifications.length === 0) {
      listEl.innerHTML = `
        <div class="p-4 text-center text-muted">
          <i class="fa-solid fa-bell-slash mb-2" style="font-size: var(--font-xl)"></i>
          <p class="m-0">No active alerts at this time</p>
        </div>
      `;
      return;
    }

    let html = '';
    this.notifications.forEach(n => {
      const isUnread = n.status === 'active';
      const severityClass = Utils.getSeverityBadgeClass(n.severity);
      
      html += `
        <div class="notification-item ${isUnread ? 'unread' : ''}" data-id="${n._id}">
          <div class="d-flex justify-between align-center mb-1">
            <span class="badge ${severityClass}">${n.severity}</span>
            <span class="notification-time">${Utils.formatRelativeTime(n.createdAt)}</span>
          </div>
          <div class="notification-title">${Utils.escapeHTML(n.title)}</div>
          <div class="notification-desc">${Utils.escapeHTML(n.message || '')}</div>
          ${isUnread ? `
            <div class="d-flex justify-end mt-2">
              <button class="btn btn-secondary btn-sm ack-btn" onclick="Notifications.acknowledge('${n._id}')">Acknowledge</button>
            </div>
          ` : ''}
        </div>
      `;
    });

    listEl.innerHTML = html;
  },

  async acknowledge(alertId) {
    try {
      // Mark alert as investigating or resolved in the backend
      const response = await API.patch(`/alerts/${alertId}/status`, { status: 'investigating' });
      if (response.success) {
        // Update local state
        this.notifications = this.notifications.map(n => {
          if (n._id === alertId) {
            n.status = 'investigating';
          }
          return n;
        });
        this.renderNotifications();
        
        // Notify other widgets
        window.dispatchEvent(new CustomEvent('alertacknowledged', { detail: { alertId } }));
      }
    } catch (error) {
      Swal.fire('Error', error.message || 'Failed to acknowledge alert', 'error');
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  if (Auth.getCurrentUser()) {
    Notifications.init();
  }
});

window.Notifications = Notifications;
