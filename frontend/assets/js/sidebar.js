/**
 * SentinelSOC Sidebar Controller
 */
const Sidebar = {
  init() {
    const container = document.querySelector('.app-container');
    const toggleBtn = document.getElementById('sidebar-toggle-btn');
    
    // Read and apply saved state
    const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
    if (isCollapsed && container) {
      container.classList.add('sidebar-collapsed');
    }

    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        if (container) {
          container.classList.toggle('sidebar-collapsed');
          localStorage.setItem('sidebarCollapsed', container.classList.contains('sidebar-collapsed'));
        }
      });
    }

    // Bind submenus
    const hasSubmenus = document.querySelectorAll('.sidebar-item-has-submenu');
    hasSubmenus.forEach(item => {
      const link = item.querySelector('.sidebar-link');
      if (link) {
        link.addEventListener('click', (e) => {
          e.preventDefault();
          
          // If sidebar is collapsed, expand it first
          if (container && container.classList.contains('sidebar-collapsed')) {
            container.classList.remove('sidebar-collapsed');
            localStorage.setItem('sidebarCollapsed', 'false');
          }
          
          item.classList.toggle('expanded');
        });
      }
    });

    this.highlightActiveLink();
  },

  highlightActiveLink() {
    const path = window.location.pathname;
    const filename = path.substring(path.lastIndexOf('/') + 1);
    
    const links = document.querySelectorAll('.sidebar-link');
    links.forEach(link => {
      const href = link.getAttribute('href');
      if (!href) return;
      
      const linkFile = href.substring(href.lastIndexOf('/') + 1);
      
      if (filename === linkFile && linkFile !== '') {
        const item = link.closest('.sidebar-item');
        if (item) {
          item.classList.add('active');
          
          // If in a submenu, expand parent item
          const parentItem = item.closest('.sidebar-item-has-submenu');
          if (parentItem) {
            parentItem.classList.add('expanded');
          }
        }
      }
    });
  }
};

document.addEventListener('DOMContentLoaded', () => {
  Sidebar.init();
});

window.Sidebar = Sidebar;
