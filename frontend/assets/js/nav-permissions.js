/**
 * nav-permissions.js
 *
 * Hides sidebar navigation links the current user doesn't have permission
 * to view. This runs client-side purely for UX (so users don't see links
 * that 403 when clicked) — it is NOT a security boundary. The backend's
 * `authorize(PERMISSIONS.X)` middleware on each route remains the actual
 * enforcement; this script just keeps the UI honest with that.
 *
 * Include this AFTER auth.js and sidebar.js on every authenticated page:
 *   <script src="/assets/js/auth.js"></script>
 *   <script src="/assets/js/sidebar.js"></script>
 *   <script src="/assets/js/nav-permissions.js"></script>
 */
(function () {
  // Map each sidebar page to the permission required to view it.
  const NAV_PERMISSION_MAP = {
    '/pages/dashboard.html': null, // always visible to any authenticated user
    '/pages/organizations.html': 'view_organizations',
    '/pages/users.html': 'view_users',
    '/pages/roles.html': 'view_users',
    '/pages/assets.html': 'view_assets',
    '/pages/log-sources.html': 'view_assets',
    '/pages/logs.html': 'view_logs',
    '/pages/threat-rules.html': 'view_threat_rules',
    '/pages/alerts.html': 'view_alerts',
    '/pages/incidents.html': 'view_incidents',
    '/pages/iocs.html': 'view_iocs',
    '/pages/reports.html': 'view_reports',
    '/pages/audit-logs.html': 'view_audit_logs',
    '/pages/settings.html': 'view_settings',
    '/pages/network-topology.html': 'view_assets',
    '/pages/security-testing.html': 'view_alerts',
    '/pages/security-assessment.html': 'view_reports'
  };

  function applyNavPermissions() {
    if (typeof Auth === 'undefined' || typeof Auth.hasPermission !== 'function') {
      console.warn('nav-permissions.js: Auth.hasPermission not available, skipping nav filtering.');
      return;
    }

    const navItems = document.querySelectorAll('.sidebar-nav .sidebar-item');

    navItems.forEach(item => {
      const link = item.querySelector('.sidebar-link');
      if (!link) return;

      let pathname;
      try {
        pathname = new URL(link.getAttribute('href'), window.location.origin).pathname;
      } catch (e) {
        return;
      }

      const requiredPermission = NAV_PERMISSION_MAP[pathname];

      if (requiredPermission === undefined || requiredPermission === null) {
        return;
      }

      const allowed = Auth.hasPermission(requiredPermission);
      item.style.display = allowed ? '' : 'none';
    });

    // Hide organization selector for non-super-admin users
    const orgSelector = document.querySelector('.org-selector');
    if (orgSelector && !Auth.isSuperAdmin()) {
      orgSelector.style.display = 'none';
    }
  }

  document.addEventListener('DOMContentLoaded', applyNavPermissions);

  window.applyNavPermissions = applyNavPermissions;
})();