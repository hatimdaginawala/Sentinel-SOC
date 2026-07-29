/**
 * SentinelSOC Chart.js Integration Helper
 */
const Charts = {
  // Theme colors
  colors: {
    primary: '#2F855A',
    success: '#2E7D32',
    warning: '#ED8936',
    danger: '#C53030',
    info: '#2563EB',
    muted: '#9CA3AF',
    
    // Theme modes overrides
    lightGrid: '#E5E7EB',
    darkGrid: '#374151',
    lightText: '#6B7280',
    darkText: '#9CA3AF'
  },

  /**
   * Determine current theme configurations
   */
  getThemeConfig() {
    const isDark = document.body.classList.contains('dark-theme');
    return {
      textColor: isDark ? this.colors.darkText : this.colors.lightText,
      gridColor: isDark ? this.colors.darkGrid : this.colors.lightGrid
    };
  },

  /**
   * Line Chart template config
   */
  createLineChart(canvasId, label, labels, data, options = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const theme = this.getThemeConfig();

    const config = {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: label,
          data: data,
          borderColor: this.colors.primary,
          backgroundColor: 'rgba(47, 133, 90, 0.05)',
          fill: true,
          tension: 0.3,
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: {
              color: theme.textColor,
              font: { family: 'Inter' }
            }
          }
        },
        scales: {
          x: {
            grid: { color: theme.gridColor },
            ticks: { color: theme.textColor }
          },
          y: {
            grid: { color: theme.gridColor },
            ticks: { color: theme.textColor }
          }
        },
        ...options
      }
    };

    const chart = new Chart(ctx, config);

    // Dynamic theme adjustment listener
    window.addEventListener('themechanged', (e) => {
      const updatedTheme = this.getThemeConfig();
      chart.options.plugins.legend.labels.color = updatedTheme.textColor;
      chart.options.scales.x.grid.color = updatedTheme.gridColor;
      chart.options.scales.x.ticks.color = updatedTheme.textColor;
      chart.options.scales.y.grid.color = updatedTheme.gridColor;
      chart.options.scales.y.ticks.color = updatedTheme.textColor;
      chart.update();
    });

    return chart;
  },

  /**
   * Doughnut Chart template
   */
  createDoughnutChart(canvasId, labels, data, colors = [], options = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const theme = this.getThemeConfig();
    const bgColors = colors.length ? colors : [this.colors.danger, this.colors.warning, this.colors.info, this.colors.success];

    const config = {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: bgColors,
          borderWidth: 1,
          borderColor: 'transparent'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: theme.textColor,
              font: { family: 'Inter' }
            }
          }
        },
        ...options
      }
    };

    const chart = new Chart(ctx, config);

    window.addEventListener('themechanged', (e) => {
      const updatedTheme = this.getThemeConfig();
      chart.options.plugins.legend.labels.color = updatedTheme.textColor;
      chart.update();
    });

    return chart;
  },

  /**
   * Bar Chart template config
   */
  createBarChart(canvasId, label, labels, data, options = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const theme = this.getThemeConfig();

    const config = {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: label,
          data: data,
          backgroundColor: this.colors.primary,
          borderWidth: 0,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: {
              color: theme.textColor,
              font: { family: 'Inter' }
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: theme.textColor }
          },
          y: {
            grid: { color: theme.gridColor },
            ticks: { color: theme.textColor }
          }
        },
        ...options
      }
    };

    const chart = new Chart(ctx, config);

    window.addEventListener('themechanged', (e) => {
      const updatedTheme = this.getThemeConfig();
      chart.options.plugins.legend.labels.color = updatedTheme.textColor;
      chart.options.scales.x.ticks.color = updatedTheme.textColor;
      chart.options.scales.y.grid.color = updatedTheme.gridColor;
      chart.options.scales.y.ticks.color = updatedTheme.textColor;
      chart.update();
    });

    return chart;
  }
};

window.Charts = Charts;
