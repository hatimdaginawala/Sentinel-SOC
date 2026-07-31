/**
 * SentinelSOC Authentication Service
 */
const Auth = {
  // Roles list
  ROLES: {
    SUPER_ADMIN: 'super_admin',
    SECURITY_ADMIN: 'security_admin',
    SOC_ANALYST: 'soc_analyst',
    INCIDENT_RESPONDER: 'incident_responder',
    AUDITOR: 'auditor'
  },

  // Role permissions mapping for client-side checks
  ROLE_PERMISSIONS: {
    super_admin: ['*'], // Access to everything
    security_admin: [
      'view_assets', 'manage_assets',
      'view_logs', 'manage_logs',
      'view_alerts', 'manage_alerts',
      'view_incidents', 'manage_incidents', 'respond_incidents',
      'view_threat_rules', 'manage_threat_rules',
      'view_iocs', 'manage_iocs',
      'view_reports', 'manage_reports', 'generate_reports',
      'view_settings', 'configure_system',
      'view_users', 'view_organizations'
    ],
    soc_analyst: [
      'view_users',
      'view_organizations',
      'view_assets',
      'view_logs',
      'view_alerts', 'manage_alerts',
      'view_incidents', 'respond_incidents',
      'view_threat_rules',
      'view_iocs',
      'view_reports', 'generate_reports',
      'view_audit_logs'
    ],
    incident_responder: [
      'view_assets',
      'view_alerts', 'manage_alerts',
      'view_incidents', 'respond_incidents'
    ],
    auditor: [
      'view_users',
      'view_organizations',
      'view_assets',
      'view_logs',
      'view_alerts',
      'view_incidents',
      'view_threat_rules',
      'view_iocs',
      'view_reports',
      'view_audit_logs',
      'view_settings'
    ]
  },

  /**
   * Perform login using username/email and password
   */
  async login(identifier, password) {
    try {
      const response = await API.post('/auth/login', { identifier, password });
      if (response.success && response.data) {
        const { user, accessToken, refreshToken } = response.data;
        API.setTokens(accessToken, refreshToken);
        localStorage.setItem('currentUser', JSON.stringify(user));
        return { success: true, user };
      }
      return { success: false, message: response.message || 'Login failed' };
    } catch (error) {
      return { success: false, message: error.message || 'Network error occurred' };
    }
  },

  /**
   * Log out from session
   */
  async logout() {
    try {
      await API.post('/auth/logout').catch(() => {});
    } finally {
      API.clearTokens();
      window.location.href = '/pages/login.html';
    }
  },

  /**
   * Get cached user profile information
   */
  getCurrentUser() {
    const userStr = localStorage.getItem('currentUser');
    if (!userStr) return null;
    try {
      return JSON.parse(userStr);
    } catch (e) {
      return null;
    }
  },

  /**
   * Fetch latest profile from server
   */
  async fetchProfile() {
    try {
      const response = await API.get('/users/me');
      if (response.success && response.data) {
        localStorage.setItem('currentUser', JSON.stringify(response.data));
        return response.data;
      }
      return null;
    } catch (e) {
      return null;
    }
  },

  /**
   * Validate if user is logged in, redirect to login if not
   */
  checkAuth() {
    const user = this.getCurrentUser();
    const token = API.getAccessToken();
    const isLoginPage = window.location.pathname.endsWith('login.html');

    if (!user || !token) {
      if (!isLoginPage) {
        window.location.href = '/pages/login.html';
      }
      return false;
    }

    if (isLoginPage) {
      window.location.href = '/pages/dashboard.html';
      return false;
    }

    return true;
  },

  /**
   * Check if user has role
   */
  hasRole(role) {
    const user = this.getCurrentUser();
    return user && user.role === role;
  },

  /**
   * Check if user has permission
   */
hasPermission(permission) {
  const user = this.getCurrentUser();
  if (!user || !user.role) return false;

  if (user.role === this.ROLES.SUPER_ADMIN) return true;

  // Prefer permissions the server actually computed from the Role collection —
  // this is the source of truth the backend's authorize() middleware also uses.
  if (Array.isArray(user.permissions)) {
    return user.permissions.includes(permission) || user.permissions.includes('*');
  }

  // Fallback for sessions cached before this change shipped.
  const allowedPermissions = this.ROLE_PERMISSIONS[user.role] || [];
  return allowedPermissions.includes(permission) || allowedPermissions.includes('*');
},
  /**
   * Enforce permission, redirect to 403 page if not authorized
   */
  enforcePermission(permission) {
    if (!this.checkAuth()) return false;
    if (!this.hasPermission(permission)) {
      window.location.href = '/pages/403.html';
      return false;
    }
    return true;
  }
};

window.Auth = Auth;
