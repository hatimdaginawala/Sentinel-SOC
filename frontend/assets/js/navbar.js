/**
 * SentinelSOC Navbar Controller
 */
const Navbar = {
  async init() {
    this.updateUserProfile();
    this.startClock();
    this.bindProfileMenu();
    await this.loadOrganizations();
    this.bindGlobalSearch();
  },

  updateUserProfile() {
    const user = Auth.getCurrentUser();
    if (!user) return;

    const nameElements = document.querySelectorAll('.navbar .user-name');
    nameElements.forEach(el => {
      el.textContent = `${user.firstName} ${user.lastName}`;
    });

    const roleElements = document.querySelectorAll('.navbar .user-role');
    roleElements.forEach(el => {
      el.textContent = user.role.replace('_', ' ');
    });

    const avatarElements = document.querySelectorAll('.navbar .user-avatar');
    avatarElements.forEach(el => {
      const initials = `${user.firstName[0] || ''}${user.lastName[0] || ''}`.toUpperCase();
      el.textContent = initials || 'U';
    });

    const emailElements = document.querySelectorAll('.profile-dropdown-email');
    emailElements.forEach(el => {
      el.textContent = user.email;
    });
  },

  startClock() {
    const clockEl = document.getElementById('navbar-clock');
    if (!clockEl) return;

    const updateTime = () => {
      const now = new Date();
      const pad = (n) => String(n).padStart(2, '0');
      const yyyy = now.getFullYear();
      const mm = pad(now.getMonth() + 1);
      const dd = pad(now.getDate());
      const hh = pad(now.getHours());
      const min = pad(now.getMinutes());
      const ss = pad(now.getSeconds());
      
      clockEl.textContent = `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
    };

    updateTime();
    setInterval(updateTime, 1000);
  },

  bindProfileMenu() {
    const trigger = document.getElementById('profile-menu-trigger');
    const dropdown = document.getElementById('profile-dropdown-menu');

    if (trigger && dropdown) {
      trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
      });

      document.addEventListener('click', () => {
        dropdown.style.display = 'none';
      });
    }

    const logoutBtn = document.getElementById('profile-logout-btn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        await Auth.logout();
      });
    }
  },

  async loadOrganizations() {
    const select = document.getElementById('navbar-org-selector');
    if (!select) return;

    try {
      const response = await API.get('/organizations');
      if (response.success && response.data) {
        const orgs = response.data.items || (Array.isArray(response.data) ? response.data : []);
        const isSuperAdmin = Auth.isSuperAdmin();
        const userOrgId = Auth.getUserOrganizationId();
        
        select.innerHTML = '';
        
        // Filter organizations based on user's role
        const accessibleOrgs = isSuperAdmin ? orgs : orgs.filter(org => org._id === userOrgId);
        
        if (accessibleOrgs.length === 0) {
          select.innerHTML = '<option value="">No organizations available</option>';
          return;
        }

        accessibleOrgs.forEach(org => {
          const opt = document.createElement('option');
          opt.value = org._id;
          opt.textContent = org.name;
          select.appendChild(opt);
        });

        // Set selected organization
        let currentOrgId = localStorage.getItem('currentOrgId');
        
        // Validate that the currentOrgId is accessible
        if (currentOrgId && !accessibleOrgs.some(org => org._id === currentOrgId)) {
          // If not accessible, fall back to user's organization
          currentOrgId = userOrgId || (accessibleOrgs[0] ? accessibleOrgs[0]._id : '');
        }
        
        if (!currentOrgId) {
          currentOrgId = userOrgId || (accessibleOrgs[0] ? accessibleOrgs[0]._id : '');
          if (currentOrgId) {
            localStorage.setItem('currentOrgId', currentOrgId);
          }
        }

        if (currentOrgId) {
          select.value = currentOrgId;
        }

        // Add change listener with organization validation
        select.addEventListener('change', (e) => {
          const selectedOrgId = e.target.value;
          
          // Validate that the user can access this organization
          if (!Auth.canAccessOrganization(selectedOrgId)) {
            Swal.fire({
              title: 'Access Denied',
              text: 'You do not have permission to access this organization.',
              icon: 'error',
              confirmButtonText: 'OK'
            });
            // Revert to previous selection
            e.target.value = localStorage.getItem('currentOrgId');
            return;
          }
          
          localStorage.setItem('currentOrgId', selectedOrgId);
          // Notify page to reload organizational data
          window.dispatchEvent(new CustomEvent('orgchanged', { detail: { organizationId: selectedOrgId } }));
          // Simple reload ensures consistency
          window.location.reload();
        });

        // Hide the organization selector for non-super-admin users with only one org
        if (!isSuperAdmin && accessibleOrgs.length <= 1) {
          select.style.display = 'none';
          const orgSelector = select.closest('.org-selector');
          if (orgSelector) {
            orgSelector.style.display = 'none';
          }
        }
      }
    } catch (error) {
      console.error('Failed to load organizations in navbar:', error);
    }
  },

  bindGlobalSearch() {
    const input = document.getElementById('navbar-search-input');
    const dropdown = document.getElementById('search-results-dropdown');

    if (!input || !dropdown) return;

    let debounceTimeout;

    input.addEventListener('input', () => {
      clearTimeout(debounceTimeout);
      const query = input.value.trim();

      if (query.length < 2) {
        dropdown.style.display = 'none';
        return;
      }

      debounceTimeout = setTimeout(async () => {
        try {
          const orgId = localStorage.getItem('currentOrgId') || '';
          
          // Perform parallel lookups on search-supported endpoints with organization filter
          const [alertsRes, incidentsRes, assetsRes] = await Promise.all([
            API.get(`/alerts?organization=${orgId}&search=${encodeURIComponent(query)}&limit=3`).catch(() => ({ data: [] })),
            API.get(`/incidents?organization=${orgId}&search=${encodeURIComponent(query)}&limit=3`).catch(() => ({ data: [] })),
            API.get(`/assets?organization=${orgId}&search=${encodeURIComponent(query)}&limit=3`).catch(() => ({ data: [] }))
          ]);

          const alerts = alertsRes.data?.alerts || alertsRes.data || [];
          const incidents = incidentsRes.data?.incidents || incidentsRes.data || [];
          const assets = assetsRes.data?.assets || assetsRes.data || [];

          if (alerts.length === 0 && incidents.length === 0 && assets.length === 0) {
            dropdown.innerHTML = `
              <div class="search-results-section">
                <div class="search-section-title">No matching events or assets found</div>
              </div>
            `;
            dropdown.style.display = 'block';
            return;
          }

          let html = '';

          if (assets.length > 0) {
            html += `<div class="search-results-section"><div class="search-section-title">Assets</div>`;
            assets.forEach(asset => {
              html += `
                <a href="/pages/assets.html" class="search-result-item">
                  <i class="fa-solid fa-server mr-2"></i> ${Utils.escapeHTML(asset.name)} (${Utils.escapeHTML(asset.ipAddress)})
                </a>
              `;
            });
            html += `</div>`;
          }

          if (alerts.length > 0) {
            html += `<div class="search-results-section"><div class="search-section-title">Alerts</div>`;
            alerts.forEach(alert => {
              html += `
                <a href="/pages/alerts.html" class="search-result-item">
                  <i class="fa-solid fa-triangle-exclamation mr-2 text-warning"></i> ${Utils.escapeHTML(alert.title)}
                </a>
              `;
            });
            html += `</div>`;
          }

          if (incidents.length > 0) {
            html += `<div class="search-results-section"><div class="search-section-title">Incidents</div>`;
            incidents.forEach(inc => {
              html += `
                <a href="/pages/incidents.html" class="search-result-item">
                  <i class="fa-solid fa-ticket mr-2 text-danger"></i> ${Utils.escapeHTML(inc.title)} [${Utils.escapeHTML(inc.status)}]
                </a>
              `;
            });
            html += `</div>`;
          }

          dropdown.innerHTML = html;
          dropdown.style.display = 'block';
        } catch (err) {
          console.error(err);
        }
      }, 300);
    });

    // Close search dropdown on click outside
    document.addEventListener('click', (e) => {
      if (!input.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.style.display = 'none';
      }
    });
  }
};

document.addEventListener('DOMContentLoaded', () => {
  if (Auth.getCurrentUser()) {
    Navbar.init();
  }
});

window.Navbar = Navbar;