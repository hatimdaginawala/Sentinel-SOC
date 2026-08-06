/**
 * Snort IDS Event Log Simulator
 * Simulates Snort intrusion detection events
 * Sends logs to SentinelSOC ingestion endpoint
 */

require('dotenv').config();

const axios = require('axios');
const { faker } = require('@faker-js/faker');
const crypto = require('crypto');

// Load configuration
const config = require('./config');

// Use Snort configuration
const CONFIG = {
  API_URL: process.env.API_URL || 'http://localhost:3000/api/v1/logs/ingest',
  SOURCE_ID: process.env.SNORT_SOURCE_ID || '',
  AUTH_TOKEN: process.env.SNORT_AUTH_TOKEN || '',
  INTERVAL_MIN: 3000,
  INTERVAL_MAX: 6000,
  RUN_FOREVER: true
};
// Snort rule definitions
const SNORT_RULES = {
  PORT_SCAN: {
    sid: 1000001,
    name: 'Port Scan Detected',
    category: 'ATTACK',
    severity: 'high',
    msg: 'Port scanning activity detected from source',
    classification: 'Attempted Information Leak'
  },
  DDOS: {
    sid: 1000002,
    name: 'DDoS Attack',
    category: 'ATTACK',
    severity: 'critical',
    msg: 'Denial of Service attack detected',
    classification: 'Denial of Service'
  },
  SUSPICIOUS_TRAFFIC: {
    sid: 1000003,
    name: 'Suspicious Network Traffic',
    category: 'SUSPICIOUS',
    severity: 'medium',
    msg: 'Suspicious traffic pattern detected',
    classification: 'Suspicious Activity'
  },
  MALWARE: {
    sid: 1000004,
    name: 'Malware Communication',
    category: 'MALWARE',
    severity: 'critical',
    msg: 'Malware communication detected',
    classification: 'Malware Communication'
  },
  SQL_INJECTION: {
    sid: 1000005,
    name: 'SQL Injection Attempt',
    category: 'WEB_ATTACK',
    severity: 'critical',
    msg: 'SQL injection attempt detected in HTTP request',
    classification: 'Web Application Attack'
  },
  XSS: {
    sid: 1000006,
    name: 'XSS Attack Attempt',
    category: 'WEB_ATTACK',
    severity: 'high',
    msg: 'Cross-site scripting attack detected',
    classification: 'Web Application Attack'
  },
  BUFFER_OVERFLOW: {
    sid: 1000007,
    name: 'Buffer Overflow Attempt',
    category: 'EXPLOIT',
    severity: 'critical',
    msg: 'Buffer overflow attempt detected',
    classification: 'Attempted Privilege Escalation'
  },
  DNS_AMPLIFICATION: {
    sid: 1000008,
    name: 'DNS Amplification Attack',
    category: 'ATTACK',
    severity: 'high',
    msg: 'DNS amplification attack detected',
    classification: 'Denial of Service'
  },
  SNMP_ATTACK: {
    sid: 1000009,
    name: 'SNMP Attack Detected',
    category: 'ATTACK',
    severity: 'medium',
    msg: 'SNMP attack attempt detected',
    classification: 'Suspicious Activity'
  },
  SSH_BRUTE_FORCE: {
    sid: 1000010,
    name: 'SSH Brute Force Attack',
    category: 'AUTHENTICATION',
    severity: 'high',
    msg: 'SSH brute force attack detected',
    classification: 'Suspicious Activity'
  }
};

// Common IP addresses
const IPS = [
  '192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13',
  '10.0.0.10', '10.0.0.11', '10.0.0.12', '10.0.0.13',
  '172.16.0.10', '172.16.0.11', '172.16.0.12',
  '45.33.22.11', '89.45.67.23', '123.45.67.89', '67.89.12.34'
];

const MALICIOUS_IPS = [
  '185.130.5.10', '194.28.114.22', '212.102.40.15', '185.220.101.23',
  '107.189.15.45', '194.28.114.88', '212.102.40.33', '185.220.101.67'
];

// Common ports
const PORTS = [80, 443, 22, 21, 25, 53, 143, 993, 995, 3306, 5432, 27017, 161, 162];

// Malicious domains
const MALICIOUS_DOMAINS = [
  'evil-domain.com', 'malware.c2', 'bad-site.org', 'phishing.net',
  'ransomware.cc', 'exploit-kit.ru', 'trojan.delivery.cn', 'botnet.com'
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
 * Generate random port
 */
function randomPort() {
  return randomItem(PORTS) || Math.floor(Math.random() * 65535) + 1024;
}

/**
 * Generate Snort alert
 */
function generateSnortAlert() {
  const ruleKeys = Object.keys(SNORT_RULES);
  const key = randomItem(ruleKeys);
  const rule = SNORT_RULES[key];
  
  const srcIP = randomIP();
  const destIP = randomIP();
  const srcPort = randomPort();
  const destPort = randomPort();
  const protocol = randomItem(['TCP', 'UDP', 'ICMP', 'IP']);
  
  // Build alert message
  let alertMessage = `${rule.msg}`;
  
  // Add specific details based on rule type
  if (key === 'PORT_SCAN') {
    const scannedPorts = [22, 80, 443, 3306, 5432];
    alertMessage += ` - Scanned Ports: ${scannedPorts.slice(0, Math.floor(Math.random() * 3) + 2).join(', ')}`;
  } else if (key === 'DDOS') {
    alertMessage += ` - ${Math.floor(Math.random() * 10000) + 1000} packets in 60s`;
  } else if (key === 'MALWARE') {
    alertMessage += ` - Domain: ${randomItem(MALICIOUS_DOMAINS)}`;
  } else if (key === 'SQL_INJECTION') {
    const payloads = ["' OR '1'='1", "' UNION SELECT * FROM users--", "'; DROP TABLE users--"];
    alertMessage += ` - Payload: ${randomItem(payloads)}`;
  } else if (key === 'XSS') {
    const payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"];
    alertMessage += ` - Payload: ${randomItem(payloads)}`;
  } else if (key === 'SSH_BRUTE_FORCE') {
    alertMessage += ` - ${Math.floor(Math.random() * 100) + 10} attempts from ${srcIP}`;
  }

  const alert = {
    rule: {
      sid: rule.sid,
      name: rule.name,
      category: rule.category,
      severity: rule.severity,
      msg: alertMessage,
      classification: rule.classification,
      priority: Math.random() > 0.7 ? 1 : (Math.random() > 0.4 ? 2 : 3)
    },
    source: {
      ip: srcIP,
      port: srcPort
    },
    dest: {
      ip: destIP,
      port: destPort
    },
    protocol: protocol,
    ttl: Math.floor(Math.random() * 128) + 64,
    packet: {
      length: Math.floor(Math.random() * 1500) + 64,
      payload: crypto.randomBytes(64).toString('hex')
    },
    action: randomItem(['alert', 'drop', 'reject', 'log']),
    timestamp: new Date().toISOString()
  };

  // Add HTTP details for web attacks
  if (key === 'SQL_INJECTION' || key === 'XSS') {
    alert.http = {
      host: randomItem(['www.example.com', 'api.example.com']),
      uri: randomItem(['/login', '/search', '/query', '/api/users']),
      method: randomItem(['GET', 'POST']),
      user_agent: randomItem([
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
        'curl/7.68.0', 'python-requests/2.31.0'
      ])
    };
  }

  return alert;
}

/**
 * Generate pattern of Snort alerts
 */
function generatePatternedAlerts() {
  const patterns = [
    // Pattern 1: Port scan followed by exploitation
    () => {
      const alerts = [];
      const targetIP = randomIP();
      
      // Port scan
      const scan = generateSnortAlert();
      const scanKey = 'PORT_SCAN';
      const scanRule = SNORT_RULES[scanKey];
      scan.rule = scanRule;
      scan.dest.ip = targetIP;
      scan.msg = `Port scan detected targeting ${targetIP}`;
      alerts.push(scan);
      
      // Exploit attempt
      const exploit = generateSnortAlert();
      const exploitKey = randomItem(['SQL_INJECTION', 'XSS', 'BUFFER_OVERFLOW']);
      const exploitRule = SNORT_RULES[exploitKey];
      exploit.rule = exploitRule;
      exploit.dest.ip = targetIP;
      exploit.msg = `${exploitRule.name} detected targeting ${targetIP}`;
      alerts.push(exploit);
      
      return alerts;
    },
    
    // Pattern 2: Multiple failed SSH attempts
    () => {
      const alerts = [];
      const srcIP = randomIP();
      const targetIP = randomIP();
      const count = Math.floor(Math.random() * 5) + 3;
      
      for (let i = 0; i < count; i++) {
        const ssh = generateSnortAlert();
        const sshKey = 'SSH_BRUTE_FORCE';
        const sshRule = SNORT_RULES[sshKey];
        ssh.rule = sshRule;
        ssh.source.ip = srcIP;
        ssh.dest.ip = targetIP;
        ssh.msg = `SSH brute force attempt ${i+1}/${count} from ${srcIP}`;
        ssh.dest.port = 22;
        alerts.push(ssh);
      }
      
      return alerts;
    },
    
    // Pattern 3: Malware communication
    () => {
      const alerts = [];
      
      // DNS query to malicious domain
      const dns = generateSnortAlert();
      const malwareKey = 'MALWARE';
      const malwareRule = SNORT_RULES[malwareKey];
      dns.rule = malwareRule;
      dns.msg = `Malware communication - DNS query to ${randomItem(MALICIOUS_DOMAINS)}`;
      alerts.push(dns);
      
      // Suspicious traffic
      const suspicious = generateSnortAlert();
      const susKey = 'SUSPICIOUS_TRAFFIC';
      const susRule = SNORT_RULES[susKey];
      suspicious.rule = susRule;
      suspicious.msg = `Suspicious traffic to known malicious IP: ${randomItem(MALICIOUS_IPS)}`;
      alerts.push(suspicious);
      
      return alerts;
    }
  ];

  const pattern = randomItem(patterns);
  return pattern();
}

/**
 * Send alerts to SentinelSOC
 */
/**
 * Send alerts to SentinelSOC
 */
async function sendAlerts(alerts) {
  try {
    // Format the alert for the API
    let logData;
    
    if (Array.isArray(alerts)) {
      // For multiple alerts, send the first one
      logData = formatAlertForAPI(alerts[0]);
    } else {
      logData = formatAlertForAPI(alerts);
    }

    const payload = {
      sourceId: CONFIG.SOURCE_ID,
      authToken: CONFIG.AUTH_TOKEN,
      log: logData
    };

    const response = await axios.post(CONFIG.API_URL, payload, {
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });

    const alertCount = Array.isArray(alerts) ? alerts.length : 1;
    console.log(` Sent ${alertCount} Snort alert(s) - Status: ${response.status}`);
    return response.data;
  } catch (error) {
    if (error.response) {
      console.error(`❌ Server responded with error: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
    } else if (error.request) {
      console.error('❌ No response from server. Is the API running?');
    } else {
      console.error(`❌ Error sending alerts: ${error.message}`);
    }
    return null;
  }
}

/**
 * Format Snort alert for the API
 */
function formatAlertForAPI(alert) {
  return {
    eventType: alert.rule.name || 'Snort Alert',
    eventCategory: alert.rule.category || 'security',
    severity: alert.rule.severity || 'high',
    message: alert.rule.msg || alert.msg || 'Snort alert detected',
    sourceIP: alert.source.ip || '',
    destinationIP: alert.dest.ip || '',
    destinationPort: alert.dest.port || 0,
    protocol: alert.protocol || 'TCP',
    hostname: '',
    rawLog: alert,
    normalizedData: {
      rule: alert.rule,
      action: alert.action,
      ttl: alert.ttl
    },
    eventTime: alert.timestamp || new Date().toISOString()
  };
}

/**
 * Main simulation loop
 */
async function runSimulator() {
  console.log('🛡️ Snort IDS Alert Simulator');
  console.log(`📡 API URL: ${CONFIG.API_URL}`);
  console.log(`🆔 Source ID: ${CONFIG.SOURCE_ID}`);
  console.log('🔑 Auth Token: ' + (CONFIG.AUTH_TOKEN ? '***' : 'MISSING!'));
  console.log('⏱️  Interval: ' + CONFIG.INTERVAL_MIN + '-' + CONFIG.INTERVAL_MAX + 'ms');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  // Validate configuration
  if (!CONFIG.SOURCE_ID || !CONFIG.AUTH_TOKEN) {
    console.error('❌ ERROR: SOURCE_ID and AUTH_TOKEN must be set in environment variables or config');
    console.log('\n💡 To fix this, set the following environment variables:');
    console.log('  export SNORT_SOURCE_ID=your_log_source_id');
    console.log('  export SNORT_AUTH_TOKEN=your_authentication_token');
    process.exit(1);
  }

  let alertCount = 0;
  let patternCount = 0;

  while (CONFIG.RUN_FOREVER) {
    try {
      // Randomly generate patterns (25% chance) or single alerts
      let alerts;
      if (Math.random() < 0.25) {
        alerts = generatePatternedAlerts();
        patternCount++;
        console.log(`🎯 Pattern ${patternCount} - Generated ${alerts.length} correlated alerts`);
      } else {
        alerts = generateSnortAlert();
        alertCount++;
        console.log(`📋 Alert ${alertCount} - ${alerts.rule.name} (SID: ${alerts.rule.sid})`);
        console.log(`   From: ${alerts.source.ip}:${alerts.source.port} -> ${alerts.dest.ip}:${alerts.dest.port}`);
      }

      // Send alerts
      await sendAlerts(alerts);

      // Random interval between 3-6 seconds
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
  console.log('\n🛑 Shutting down Snort simulator...');
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

module.exports = { runSimulator, generateSnortAlert, sendAlerts };