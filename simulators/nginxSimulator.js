/**
 * Nginx HTTP Server Log Simulator
 * Simulates Nginx web server and reverse proxy logs
 * Sends logs to SentinelSOC ingestion endpoint
 */

const axios = require('axios');
const { faker } = require('@faker-js/faker');
const crypto = require('crypto');
// Add this at the very top of each simulator file
require('dotenv').config();

// Rest of the code...

// Configuration
// Configuration
const CONFIG = {
  API_URL: process.env.API_URL || 'http://localhost:5000/api/v1/logs/ingest',
  SOURCE_ID: process.env.NGINX_SOURCE_ID || '',
  AUTH_TOKEN: process.env.NGINX_AUTH_TOKEN || '',
  INTERVAL_MIN: 2000,
  INTERVAL_MAX: 4000,
  RUN_FOREVER: true
};
// Nginx log patterns
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT'];
const HTTP_STATUS = {
  '2xx': [200, 201, 204, 206],
  '3xx': [301, 302, 304, 307, 308],
  '4xx': [400, 401, 403, 404, 405, 408, 413, 429, 451],
  '5xx': [500, 501, 502, 503, 504, 505, 511]
};

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0',
  'Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/120.0 Firefox/120.0',
  'curl/7.68.0', 'Wget/1.20.3', 'python-requests/2.31.0', 'Go-http-client/1.1'
];

const PATHS = [
  '/', '/index.html', '/about', '/contact', '/products', '/services',
  '/api/users', '/api/products', '/api/orders', '/api/auth',
  '/login', '/register', '/dashboard', '/profile', '/settings',
  '/admin', '/wp-admin', '/wp-login', '/phpmyadmin', '/cpanel',
  '/assets', '/images', '/css', '/js', '/fonts',
  '/blog', '/docs', '/help', '/support', '/api/v1', '/api/v2',
  '/health', '/status', '/metrics', '/debug', '/info'
];

const HOSTNAMES = [
  'nginx-01', 'nginx-02', 'web-srv-01', 'web-srv-02',
  'lb-01', 'lb-02', 'proxy-01', 'proxy-02',
  'app-srv-01', 'app-srv-02', 'api-gateway-01'
];

const IPS = [
  '192.168.1.40', '192.168.1.41', '192.168.1.42', '192.168.1.43',
  '10.0.0.40', '10.0.0.41', '10.0.0.42', '10.0.0.43',
  '172.16.0.40', '172.16.0.41', '172.16.0.42'
];

const NGINX_HOSTNAMES = [
  'www.example.com', 'api.example.com', 'blog.example.com',
  'admin.example.com', 'cdn.example.com', 'static.example.com'
];

const UPSTREAMS = [
  'backend-01:8080', 'backend-02:8080', 'backend-03:8080',
  'app-01:3000', 'app-02:3000', 'api-01:5000', 'api-02:5000'
];

// Common error messages
const ERROR_MESSAGES = {
  '500': 'Internal Server Error',
  '502': 'Bad Gateway - Upstream server error',
  '503': 'Service Unavailable',
  '504': 'Gateway Timeout - Upstream timeout',
  '404': 'Not Found - Requested resource does not exist',
  '403': 'Access Denied - Insufficient permissions',
  '429': 'Too Many Requests - Rate limit exceeded'
};

/**
 * Generate a random item from an array
 */
function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

/**
 * Generate random IP address
 */
function randomIP() {
  return `${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`;
}

/**
 * Generate random HTTP status code
 */
function randomStatus() {
  const statusType = Math.random() > 0.7 ? '4xx' : (Math.random() > 0.9 ? '5xx' : (Math.random() > 0.5 ? '2xx' : '3xx'));
  const statusCodes = HTTP_STATUS[statusType];
  return randomItem(statusCodes);
}

/**
 * Generate Nginx access log
 */
function generateNginxLog() {
  const hostname = randomItem(HOSTNAMES);
  const ip = randomIP();
  const method = randomItem(HTTP_METHODS);
  const path = randomItem(PATHS);
  const status = randomStatus();
  const userAgent = randomItem(USER_AGENTS);
  const bytes = Math.floor(Math.random() * 100000);
  const serverName = randomItem(NGINX_HOSTNAMES);
  const upstream = Math.random() > 0.5 ? randomItem(UPSTREAMS) : '-';
  const referer = Math.random() > 0.5 ? `http://${randomItem(NGINX_HOSTNAMES)}${randomItem(PATHS)}` : '-';
  
  let severity = 'info';
  let eventType = 'Access';
  let message = `${method} ${path} - ${status}`;

  // Check for reverse proxy errors
  let isProxyError = false;
  if (status >= 500 && upstream !== '-') {
    isProxyError = true;
    const errorMsg = ERROR_MESSAGES[status] || 'Proxy Error';
    message = `Reverse proxy error: ${errorMsg} - Upstream: ${upstream}`;
    severity = status === 500 ? 'high' : 'critical';
    eventType = 'Reverse Proxy Error';
  }

  // Check for suspicious activity
  let isSuspicious = false;
  let attackType = null;

  // SQL Injection detection
  if (Math.random() < 0.04 && path.includes('?')) {
    const payloads = ["' OR '1'='1", "' UNION SELECT", "'; DROP TABLE", "' AND 1=1--"];
    const payload = randomItem(payloads);
    isSuspicious = true;
    attackType = 'SQL Injection Attempt';
    severity = 'critical';
    eventType = 'SQL Injection';
    message = `SQL Injection attempt on ${path}`;
  }

  // XSS detection
  if (Math.random() < 0.02 && path.includes('?')) {
    const payloads = ["<script>", "<img src=x onerror=", "<svg onload="];
    const payload = randomItem(payloads);
    isSuspicious = true;
    attackType = 'XSS Attack';
    severity = 'critical';
    eventType = 'XSS';
    message = `XSS attempt on ${path}`;
  }

  // DDoS detection (many concurrent requests)
  if (Math.random() < 0.01) {
    isSuspicious = true;
    attackType = 'Potential DDoS';
    severity = 'high';
    eventType = 'DDoS Attempt';
    message = `Potential DDoS: High request rate from ${ip}`;
  }

  // Path traversal
  if (Math.random() < 0.02 && path.includes('..')) {
    isSuspicious = true;
    attackType = 'Path Traversal';
    severity = 'high';
    eventType = 'Path Traversal';
    message = `Path traversal attempt on ${path}`;
  }

  // 404 errors for scanning
  if (status === 404 && Math.random() < 0.2) {
    severity = 'medium';
    eventType = '404 Not Found';
    message = `404 Not Found: ${path}`;
  }

  const log = {
    hostname: hostname,
    serverName: serverName,
    ipAddress: ip,
    sourceIP: ip,
    method: method,
    path: path,
    status: status,
    userAgent: userAgent,
    referer: referer,
    bytes: bytes,
    upstream: upstream,
    eventType: eventType,
    severity: severity,
    message: message,
    eventTime: new Date().toISOString(),
    responseTime: Math.floor(Math.random() * 2000) + 10,
    isSuspicious: isSuspicious,
    attackType: attackType,
    isProxyError: isProxyError,
    upstreamResponseTime: isProxyError ? null : Math.floor(Math.random() * 1000) + 50
  };

  if (isSuspicious) {
    log.message = `[SECURITY] ${attackType}: ${path}`;
    log.severity = 'critical';
  }

  return log;
}

/**
 * Generate a pattern of Nginx events
 */
function generatePatternedEvents() {
  const patterns = [
    // Pattern 1: Health check pattern
    () => {
      const events = [];
      const ip = randomIP();
      
      // Health check requests
      for (let i = 0; i < 3; i++) {
        const event = generateNginxLog();
        event.sourceIP = ip;
        event.ipAddress = ip;
        event.path = '/health';
        event.method = 'GET';
        event.status = 200;
        event.message = `Health check ${i+1}/3 - OK`;
        events.push(event);
      }
      return events;
    },
    
    // Pattern 2: Rate limiting triggered
    () => {
      const events = [];
      const ip = randomIP();
      const count = Math.floor(Math.random() * 10) + 5;
      
      for (let i = 0; i < count; i++) {
        const event = generateNginxLog();
        event.sourceIP = ip;
        event.ipAddress = ip;
        event.path = '/api/endpoint';
        event.method = 'GET';
        event.status = i < count - 3 ? 200 : 429;
        event.message = i < count - 3 ? 
          `Request ${i+1}/${count}` : 
          `Rate limited ${i+1}/${count} - 429 Too Many Requests`;
        if (event.status === 429) {
          event.severity = 'medium';
        }
        events.push(event);
      }
      return events;
    },
    
    // Pattern 3: Reverse proxy cascade failure
    () => {
      const events = [];
      const upstream = randomItem(UPSTREAMS);
      
      // Failed health checks
      for (let i = 0; i < 3; i++) {
        const event = generateNginxLog();
        event.path = '/health';
        event.method = 'GET';
        event.status = 502;
        event.upstream = upstream;
        event.message = `Health check failed - Upstream: ${upstream}`;
        event.isProxyError = true;
        event.severity = 'critical';
        event.eventType = 'Reverse Proxy Error';
        events.push(event);
      }
      
      // User requests failing
      for (let i = 0; i < 2; i++) {
        const event = generateNginxLog();
        event.path = randomItem(['/api/users', '/api/products', '/api/orders']);
        event.method = 'GET';
        event.status = 503;
        event.upstream = upstream;
        event.message = `Service unavailable - Upstream: ${upstream}`;
        event.isProxyError = true;
        event.severity = 'critical';
        event.eventType = 'Reverse Proxy Error';
        events.push(event);
      }
      
      return events;
    },
    
    // Pattern 4: API abuse / scraping
    () => {
      const events = [];
      const ip = randomIP();
      const count = Math.floor(Math.random() * 6) + 3;
      
      for (let i = 0; i < count; i++) {
        const event = generateNginxLog();
        event.sourceIP = ip;
        event.ipAddress = ip;
        event.path = randomItem(['/api/users', '/api/products', '/api/orders', '/api/v1/data']);
        event.method = 'GET';
        event.status = 200;
        event.message = `API scraping attempt ${i+1}/${count}`;
        event.isSuspicious = true;
        event.attackType = 'API Abuse';
        event.severity = 'medium';
        events.push(event);
      }
      return events;
    }
  ];

  const pattern = randomItem(patterns);
  return pattern();
}

/**
 * Send logs to SentinelSOC
 */
async function sendLogs(logs) {
  try {
    const payload = {
      sourceId: CONFIG.SOURCE_ID,
      authToken: CONFIG.AUTH_TOKEN,
      log: Array.isArray(logs) ? logs[0] : logs
    };

    const response = await axios.post(CONFIG.API_URL, payload, {
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });

    const logCount = Array.isArray(logs) ? logs.length : 1;
    console.log(`✅ Sent ${logCount} Nginx event(s) - Status: ${response.status}`);
    return response.data;
  } catch (error) {
    if (error.response) {
      console.error(`❌ Server responded with error: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
    } else if (error.request) {
      console.error('❌ No response from server. Is the API running?');
    } else {
      console.error(`❌ Error sending logs: ${error.message}`);
    }
    return null;
  }
}

/**
 * Main simulation loop
 */
async function runSimulator() {
  console.log('🔄 Nginx HTTP Server/Proxy Log Simulator');
  console.log(`📡 API URL: ${CONFIG.API_URL}`);
  console.log(`🆔 Source ID: ${CONFIG.SOURCE_ID}`);
  console.log('🔑 Auth Token: ' + (CONFIG.AUTH_TOKEN ? '***' : 'MISSING!'));
  console.log('⏱️  Interval: ' + CONFIG.INTERVAL_MIN + '-' + CONFIG.INTERVAL_MAX + 'ms');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  // Validate configuration
  if (!CONFIG.SOURCE_ID || !CONFIG.AUTH_TOKEN) {
    console.error('❌ ERROR: SOURCE_ID and AUTH_TOKEN must be set in environment variables or config');
    console.log('\n💡 To fix this, set the following environment variables:');
    console.log('  export SOURCE_ID=your_log_source_id');
    console.log('  export AUTH_TOKEN=your_authentication_token');
    process.exit(1);
  }

  let eventCount = 0;
  let patternCount = 0;

  while (CONFIG.RUN_FOREVER) {
    try {
      // Randomly generate patterns (20% chance) or single events
      let logs;
      if (Math.random() < 0.2) {
        logs = generatePatternedEvents();
        patternCount++;
        console.log(`🎯 Pattern ${patternCount} - Generated ${logs.length} correlated events`);
      } else {
        logs = generateNginxLog();
        eventCount++;
        const status = logs.status;
        const path = logs.path;
        const upstream = logs.upstream !== '-' ? ` (upstream: ${logs.upstream})` : '';
        console.log(`📋 Event ${eventCount} - ${logs.method} ${path} - ${status}${upstream} (${logs.sourceIP})`);
        if (logs.isSuspicious) {
          console.log(`   ⚠️  ${logs.attackType} detected!`);
        }
        if (logs.isProxyError) {
          console.log(`   🔴 Proxy error detected!`);
        }
      }

      // Send logs
      await sendLogs(logs);

      // Random interval between 2-4 seconds
      const interval = Math.floor(Math.random() * (CONFIG.INTERVAL_MAX - CONFIG.INTERVAL_MIN + 1)) + CONFIG.INTERVAL_MIN;
      await new Promise(resolve => setTimeout(resolve, interval));

    } catch (error) {
      console.error(`❌ Error in simulation loop: ${error.message}`);
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
}

/**
 * Handle graceful shutdown
 */
function handleShutdown() {
  console.log('\n🛑 Shutting down Nginx simulator...');
  CONFIG.RUN_FOREVER = false;
  process.exit(0);
}

// Setup signal handlers
process.on('SIGINT', handleShutdown);
process.on('SIGTERM', handleShutdown);

// Run the simulator
if (require.main === module) {
  runSimulator().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

module.exports = { runSimulator, generateNginxLog, sendLogs };