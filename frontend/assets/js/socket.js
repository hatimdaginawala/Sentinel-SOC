/**
 * SentinelSOC Real-time Socket.io Client
 */
const Socket = {
  socket: null,

  init() {
    const token = API.getAccessToken();
    if (!token) return;

    // Connect to same host serving the API
    this.socket = io(window.location.origin, {
      auth: {
        token
      },
      autoConnect: true,
      reconnection: true
    });

    this.socket.on('connect', () => {
      console.log(`📡 Socket.io connected! ID: ${this.socket.id}`);
    });

    this.socket.on('disconnect', () => {
      console.log('📡 Socket.io disconnected');
    });

    // Real-time alerts
    this.socket.on('alert', (alert) => {
      console.log('🔔 New Alert Received:', alert);
      
      // Dispatch custom event for dashboard/alert screens
      window.dispatchEvent(new CustomEvent('newalert', { detail: alert }));

      // Display a SweetAlert toast notification for high/critical alerts
      if (alert.severity === 'critical' || alert.severity === 'high') {
        Swal.fire({
          toast: true,
          position: 'top-end',
          showConfirmButton: false,
          timer: 6000,
          timerProgressBar: true,
          icon: 'warning',
          title: `CRITICAL ALERT: ${alert.title}`,
          text: alert.message || 'Suspicious behavior detected',
          customClass: {
            popup: 'toast-notification'
          },
          didOpen: (toast) => {
            toast.addEventListener('mouseenter', Swal.stopTimer);
            toast.addEventListener('mouseleave', Swal.resumeTimer);
            toast.addEventListener('click', () => {
              window.location.href = '/pages/alerts.html';
            });
          }
        });
      }
    });

    // Real-time incidents
    this.socket.on('incident', (incident) => {
      console.log('🎫 New Incident Received:', incident);
      window.dispatchEvent(new CustomEvent('newincident', { detail: incident }));
    });

    // Real-time logs
    this.socket.on('log', (log) => {
      window.dispatchEvent(new CustomEvent('newlog', { detail: log }));
    });
  },

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  if (Auth.getCurrentUser()) {
    Socket.init();
  }
});

window.Socket = Socket;
