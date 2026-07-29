/**
 * SentinelSOC Centralized REST API client
 */
const API_BASE_URL = `${window.location.origin}/api/v1`;

const API = {
  getAccessToken() {
    return localStorage.getItem('accessToken');
  },

  getRefreshToken() {
    return localStorage.getItem('refreshToken');
  },

  setTokens(accessToken, refreshToken) {
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
  },

  clearTokens() {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('currentUser');
  },

  /**
   * Safe fetch with authorization header injection
   */
  async request(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
    
    // Set headers
    const headers = new Headers(options.headers || {});
    const token = this.getAccessToken();
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    const config = {
      ...options,
      headers
    };

    try {
      let response = await fetch(url, config);

      // Handle 401 Unauthorized by trying to refresh the token
      if (response.status === 401 && this.getRefreshToken()) {
        const refreshed = await this.refreshTokens();
        if (refreshed) {
          // Retry the original request
          headers.set('Authorization', `Bearer ${this.getAccessToken()}`);
          response = await fetch(url, config);
        } else {
          // Token expired or invalid, force logout
          this.handleSessionExpired();
          throw new Error('Session expired. Please log in again.');
        }
      }

      // Parse JSON response
      const data = await response.json().catch(() => ({}));
      
      if (!response.ok) {
        throw {
          status: response.status,
          message: data.message || 'An error occurred during API request',
          errors: data.errors
        };
      }

      return data;
    } catch (error) {
      console.error(`API Error on ${url}:`, error);
      throw error;
    }
  },

  /**
   * Call refresh token endpoint to obtain a new access token
   */
  async refreshTokens() {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) return false;

    try {
      const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken })
      });

      if (!response.ok) {
        return false;
      }

      const data = await response.json();
      if (data.success && data.data) {
        this.setTokens(data.data.accessToken, data.data.refreshToken);
        return true;
      }
      return false;
    } catch (e) {
      return false;
    }
  },

  handleSessionExpired() {
    this.clearTokens();
    if (!window.location.pathname.endsWith('login.html')) {
      window.location.href = '/pages/login.html';
    }
  },

  // HTTP Helper Methods
  get(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'GET' });
  },

  post(endpoint, body, options = {}) {
    return this.request(endpoint, {
      ...options,
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined
    });
  },

  put(endpoint, body, options = {}) {
    return this.request(endpoint, {
      ...options,
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined
    });
  },

  patch(endpoint, body, options = {}) {
    return this.request(endpoint, {
      ...options,
      method: 'PATCH',
      body: body ? JSON.stringify(body) : undefined
    });
  },

  delete(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'DELETE' });
  }
};

window.API = API;
