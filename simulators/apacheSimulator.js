/**
 * Apache HTTP Server Log Simulator
 * Simulates Apache web server access and error logs
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
  API_URL: process.env.API_URL || 'http://localhost:3000/api/v1/logs/ingest',
  SOURCE_ID: process.env.APACHE_SOURCE_ID || '',
  AUTH_TOKEN: process.env.APACHE_AUTH_TOKEN || '',
  INTERVAL_MIN: 2000,
  INTERVAL_MAX: 4000,
  RUN_FOREVER: true
};

// Apache log patterns
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'];
const HTTP_STATUS = {
  '2xx': [200, 201, 204, 206],
  '3xx': [301, 302, 304, 307],
  '4xx': [400, 401, 403, 404, 405, 408, 429, 451],
  '5xx': [500, 501, 502, 503, 504, 505]
};

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0',
  'curl/7.68.0', 'Wget/1.20.3', 'python-requests/2.31.0', 'Go-http-client/1.1'
];

const PATHS = [
  '/', '/index.html', '/about', '/contact', '/products', '/services',
  '/api/users', '/api/products', '/api/orders', '/api/auth',
  '/login', '/register', '/dashboard', '/profile', '/settings',
  '/wp-admin', '/wp-login', '/admin', '/phpmyadmin', '/cpanel',
  '/images', '/css', '/js', '/fonts', '/uploads',
  '/blog', '/blog/post-1', '/blog/post-2', '/blog/category/technology',
  '/downloads', '/docs', '/help', '/support', '/faq'
];

const HOSTNAMES = [
  'web-srv-01', 'web-srv-02', 'app-srv-01', 'app-srv-02',
  'apache-01', 'apache-02', 'www-01', 'www-02',
  'public-01', 'public-02', 'internal-01'
];

const IPS = [
  '192.168.1.30', '192.168.1.31', '192.168.1.32', '192.168.1.33',
  '10.0.0.30', '10.0.0.31', '10.0.0.32', '10.0.0.33',
  '172.16.0.30', '172.16.0.31', '172.16.0.32'
];

const APACHE_HOSTNAMES = [
  'www.example.com', 'api.example.com', 'blog.example.com',
  'admin.example.com', 'staging.example.com', 'dev.example.com'
];

// SQL injection patterns
const SQL_PAYLOADS = [
  "' OR '1'='1", "' UNION SELECT * FROM users--", "' AND 1=1--",
  "'; DROP TABLE users--", "' OR 1=1;--", "' AND (SELECT * FROM users WHERE '1'='1')--"
];

// XSS payloads
const XSS_PAYLOADS = [
  "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
  "<svg onload=alert(1)>", "<iframe src='javascript:alert(1)'>",
  "<body onload=alert('XSS')>"
];

// Command injection payloads
const CMD_PAYLOADS = [
  "; ls -la", "; whoami", "; cat /etc/passwd", "| netstat -an",
  "; id", "; uname -a", "; ps aux"
];

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
 * Generate Apache access log
 */
function generateApacheLog() {
  const hostname = randomItem(HOSTNAMES);
  const ip = randomIP();
  const method = randomItem(HTTP_METHODS);
  const path = randomItem(PATHS);
  const status = randomStatus();
  const userAgent = randomItem(USER_AGENTS);
  const bytes = Math.floor(Math.random() * 100000);
  const referer = Math.random() > 0.5 ? `http://${randomItem(APACHE_HOSTNAMES)}${randomItem(PATHS)}` : '-';
  const serverName = randomItem(APACHE_HOSTNAMES);
  
  let severity = 'info';
  let eventType = 'Access';
  let message = `${method} ${path} - ${status}`;

  // Check for suspicious activity
  let isSuspicious = false;
  let attackType = null;

  // SQL Injection detection
  if (Math.random() < 0.05 && path.includes('?')) {
    const payload = randomItem(SQL_PAYLOADS);
    path += payload;
    isSuspicious = true;
    attackType = 'SQL Injection Attempt';
    severity = 'critical';
    eventType = 'SQL Injection';
    message = `SQL Injection attempt on ${path}`;
  }

  // XSS detection
  if (Math.random() < 0.03 && path.includes('?')) {
    const payload = randomItem(XSS_PAYLOADS);
    path += payload;
    isSuspicious = true;
    attackType = 'XSS Attack';
    severity = 'critical';
    eventType = 'XSS';
    message = `XSS attempt on ${path}`;
  }

  // Command Injection detection
  if (Math.random() < 0.02 && path.includes('?')) {
    const payload = randomItem(CMD_PAYLOADS);
    path += payload;
    isSuspicious = true;
    attackType = 'Command Injection';
    severity = 'critical';
    eventType = 'Command Injection';
    message = `Command injection attempt on ${path}`;
  }

  // Directory traversal detection
  if (Math.random() < 0.02 && path.includes('..')) {
    isSuspicious = true;
    attackType = 'Directory Traversal';
    severity = 'high';
    eventType = 'Directory Traversal';
    message = `Directory traversal attempt on ${path}`;
  }

  // 404 errors
  if (status === 404) {
    if (Math.random() < 0.3) {
      severity = 'medium';
      eventType = '404 Not Found';
      message = `404 Not Found: ${path}`;
    }
  }

  // 403 errors
  if (status === 403) {
    severity = 'high';
    eventType = 'Access Denied';
    message = `Access denied: ${path}`;
  }

  // 500 errors
  if (status >= 500) {
    severity = 'high';
    eventType = 'Server Error';
    message = `Server error ${status} on ${path}`;
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
    eventType: eventType,
    severity: severity,
    message: message,
    eventTime: new Date().toISOString(),
    responseTime: Math.floor(Math.random() * 2000) + 10,
    isSuspicious: isSuspicious,
    attackType: attackType
  };

  if (isSuspicious) {
    log.message = `[SECURITY] ${attackType}: ${path}`;
    log.severity = 'critical';
  }

  return log;
}

/**
 * Generate a pattern of Apache events
 */
function generatePatternedEvents() {
  const patterns = [
    // Pattern 1: DDoS/Slashdot effect
    () => {
      const events = [];
      const ip = randomIP();
      const count = Math.floor(Math.random() * 8) + 3;
      
      for (let i = 0; i < count; i++) {
        const event = generateApacheLog();
        event.sourceIP = ip;
        event.ipAddress = ip;
        event.status = 200;
        event.path = randomItem(PATHS);
        event.message = `${event.method} ${event.path} - 200 (Fast consecutive request ${i+1}/${count})`;
        events.push(event);
      }
      return events;
    },
    
    // Pattern 2: Scanning/probing
    () => {
      const events = [];
      const ip = randomIP();
      const paths = ['/admin', '/wp-admin', '/phpmyadmin', '/cpanel', '/login', '/config.php'];
      
      for (const path of paths) {
        const event = generateApacheLog();
        event.sourceIP = ip;
        event.ipAddress = ip;
        event.path = path;
        event.status = Math.random() > 0.5 ? 403 : 404;
        event.message = `Scanning attempt - ${path} - ${event.status}`;
        event.isSuspicious = true;
        event.attackType = 'Port/Path Scanning';
        event.severity = 'high';
        events.push(event);
      }
      return events;
    },
    
    // Pattern 3: Failed logins
    () => {
      const events = [];
      const ip = randomIP();
      const count = Math.floor(Math.random() * 5) + 2;
      
      for (let i = 0; i < count; i++) {
        const event = generateApacheLog();
        event.sourceIP = ip;
        event.ipAddress = ip;
        event.path = randomItem(['/login', '/admin/login', '/wp-login']);
        event.method = 'POST';
        event.status = 401;
        event.message = `Login failure attempt ${i+1}/${count} from ${ip}`;
        event.isSuspicious = true;
        event.attackType = 'Brute Force Login';
        event.severity = 'high';
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
    console.log(` Sent ${logCount} Apache event(s) - Status: ${response.status}`);
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
  console.log('🌐 Apache HTTP Server Log Simulator');
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
        logs = generateApacheLog();
        eventCount++;
        const status = logs.status;
        const path = logs.path;
        console.log(`📋 Event ${eventCount} - ${logs.method} ${path} - ${status} (${logs.sourceIP})`);
        if (logs.isSuspicious) {
          console.log(`   ⚠️  ${logs.attackType} detected!`);
        }
      }

      // Send logs
      await sendLogs(logs);

      // Random interval between 2-4 seconds
      const interval = Math.floor(Math.random() * (CONFIG.INTERVAL_MAX - CONFIG.INTERVAL_MIN + 1)) + CONFIG.INTERVAL_MIN;
      await new Promise(resolve => setTimeout(resolve, interval));

    } catch (error) {
      console.error(`❌ Error in simulation loop: ${error.message}`);
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  }
}

/**
 * Handle graceful shutdown
 */
function handleShutdown() {
  console.log('\n🛑 Shutting down Apache simulator...');
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

module.exports = { runSimulator, generateApacheLog, sendLogs };