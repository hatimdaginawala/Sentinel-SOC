// config.js
const dotenv = require('dotenv');
const path = require('path');

// Load .env from the same directory
dotenv.config({ path: path.join(__dirname, '.env') });

// Export configuration for each simulator type
module.exports = {
  windows: {
    API_URL: process.env.API_URL || 'http://localhost:5000/api/v1/logs/ingest',
    SOURCE_ID: process.env.WINDOWS_SOURCE_ID || '',
    AUTH_TOKEN: process.env.WINDOWS_AUTH_TOKEN || ''
  },
  linux: {
    API_URL: process.env.API_URL || 'http://localhost:5000/api/v1/logs/ingest',
    SOURCE_ID: process.env.LINUX_SOURCE_ID || '',
    AUTH_TOKEN: process.env.LINUX_AUTH_TOKEN || ''
  },
  apache: {
    API_URL: process.env.API_URL || 'http://localhost:5000/api/v1/logs/ingest',
    SOURCE_ID: process.env.APACHE_SOURCE_ID || '',
    AUTH_TOKEN: process.env.APACHE_AUTH_TOKEN || ''
  },
  nginx: {
    API_URL: process.env.API_URL || 'http://localhost:5000/api/v1/logs/ingest',
    SOURCE_ID: process.env.NGINX_SOURCE_ID || '',
    AUTH_TOKEN: process.env.NGINX_AUTH_TOKEN || ''
  },
  suricata: {
    API_URL: process.env.API_URL || 'http://localhost:5000/api/v1/logs/ingest',
    SOURCE_ID: process.env.SURICATA_SOURCE_ID || '',
    AUTH_TOKEN: process.env.SURICATA_AUTH_TOKEN || ''
  },
  snort: {
    API_URL: process.env.API_URL || 'http://localhost:5000/api/v1/logs/ingest',
    SOURCE_ID: process.env.SNORT_SOURCE_ID || '',
    AUTH_TOKEN: process.env.SNORT_AUTH_TOKEN || ''
  },
  firewall: {
    API_URL: process.env.API_URL || 'http://localhost:5000/api/v1/logs/ingest',
    SOURCE_ID: process.env.FIREWALL_SOURCE_ID || '',
    AUTH_TOKEN: process.env.FIREWALL_AUTH_TOKEN || ''
  }
};