/**
 * SentinelSOC Theme Controller
 */
const Theme = {
  init() {
    const savedTheme = localStorage.getItem('theme') || 'dark'; // default to dark per enterprise SOC recommendation
    this.setTheme(savedTheme);
  },

  toggle() {
    const currentTheme = document.body.classList.contains('dark-theme') ? 'dark' : 'light';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    this.setTheme(newTheme);
    
    // Trigger event for charts or other listeners to update
    window.dispatchEvent(new CustomEvent('themechanged', { detail: { theme: newTheme } }));
  },

  setTheme(theme) {
    if (theme === 'dark') {
      document.body.classList.add('dark-theme');
      localStorage.setItem('theme', 'dark');
      this.updateToggleButton(true);
    } else {
      document.body.classList.remove('dark-theme');
      localStorage.setItem('theme', 'light');
      this.updateToggleButton(false);
    }
  },

  updateToggleButton(isDark) {
    const toggleBtn = document.getElementById('theme-toggle-btn');
    if (!toggleBtn) return;
    
    const icon = toggleBtn.querySelector('i');
    if (icon) {
      if (isDark) {
        icon.className = 'fa-regular fa-sun';
      } else {
        icon.className = 'fa-regular fa-moon';
      }
    }
  }
};

// Initialize theme immediately to prevent layout flash
document.addEventListener('DOMContentLoaded', () => {
  Theme.init();
  const toggleBtn = document.getElementById('theme-toggle-btn');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => Theme.toggle());
  }
});

window.Theme = Theme;
