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
  // Keys match the `pathname` of the link's href (case-sensitive, no query string).
  // A page with an empty/missing entry (like dashboard) is always shown.
  const NAV_PERMISSION_MAP = {
    '/pages/dashboard.html': null, // always visible to any authenticated user
    '/pages/organizations.html': 'view_organizations',
    '/pages/users.html': 'view_users',
    '/pages/roles.html': 'view_users', // roles live under user management
    '/pages/assets.html': 'view_assets',
    '/pages/log-sources.html': 'view_assets', // log-sources.html itself calls enforcePermission('view_assets')
    '/pages/logs.html': 'view_logs',
    '/pages/threat-rules.html': 'view_threat_rules',
    '/pages/alerts.html': 'view_alerts',
    '/pages/incidents.html': 'view_incidents',
    '/pages/iocs.html': 'view_iocs',
    '/pages/reports.html': 'view_reports',
    '/pages/audit-logs.html': 'view_audit_logs',
    '/pages/settings.html': 'view_settings'
  };

  function applyNavPermissions() {
    if (typeof Auth === 'undefined' || typeof Auth.hasPermission !== 'function') {
      // Auth not ready yet — don't hide anything rather than guess wrong.
      console.warn('nav-permissions.js: Auth.hasPermission not available, skipping nav filtering.');
      return;
    }

    const navItems = document.querySelectorAll('.sidebar-nav .sidebar-item');

    navItems.forEach(item => {
      const link = item.querySelector('.sidebar-link');
      if (!link) return;

      let pathname;
      try {
        // Resolves relative hrefs against the current origin so this works
        // regardless of how the href is written in the HTML.
        pathname = new URL(link.getAttribute('href'), window.location.origin).pathname;
      } catch (e) {
        return; // malformed href, leave it alone
      }

      const requiredPermission = NAV_PERMISSION_MAP[pathname];

      // undefined = page not in the map at all -> leave visible (fail-open on
      // *display only*; the backend route still enforces real access).
      // null = explicitly no permission required (e.g. dashboard) -> visible.
      if (requiredPermission === undefined || requiredPermission === null) {
        return;
      }

      const allowed = Auth.hasPermission(requiredPermission);
      item.style.display = allowed ? '' : 'none';
    });
  }

  // Auth state (token/permissions) is typically parsed synchronously from
  // localStorage/JWT by auth.js before this runs. If your auth.js does
  // anything async (e.g. fetches /users/me), call applyNavPermissions()
  // again inside that callback instead of relying solely on DOMContentLoaded.
  document.addEventListener('DOMContentLoaded', applyNavPermissions);

  // Exposed so other scripts (e.g. a "switch organization" flow that might
  // change effective permissions) can re-run filtering without a page reload.
  window.applyNavPermissions = applyNavPermissions;
})();