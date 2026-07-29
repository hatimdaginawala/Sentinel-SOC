/**
 * Suricata IDS/IPS Event Log Simulator
 * Simulates Suricata intrusion detection and prevention events
 * Sends logs to SentinelSOC ingestion endpoint
 */

require('dotenv').config();

const axios = require('axios');
const { faker } = require('@faker-js/faker');
const crypto = require('crypto');

// Load configuration
const config = require('./config');

// Use Suricata configuration
const CONFIG = {
  API_URL: process.env.API_URL || 'http://localhost:3000/api/v1/logs/ingest',
  SOURCE_ID: process.env.SURICATA_SOURCE_ID || '',
  AUTH_TOKEN: process.env.SURICATA_AUTH_TOKEN || '',
  INTERVAL_MIN: 3000,
  INTERVAL_MAX: 7000,
  RUN_FOREVER: true
};

// Suricata alert signatures
const SURICATA_SIGNATURES = {
  SQL_INJECTION: {
    sid: 2100001,
    name: 'SQL Injection Attempt',
    category: 'WEB_ATTACK',
    severity: 'critical',
    msg: 'SQL injection attempt detected in URI',
    reference: 'url,www.owasp.org/index.php/SQL_Injection'
  },
  XSS: {
    sid: 2100002,
    name: 'Cross-Site Scripting Attack',
    category: 'WEB_ATTACK',
    severity: 'critical',
    msg: 'XSS attack detected in URI',
    reference: 'url,www.owasp.org/index.php/Cross-site_Scripting_(XSS)'
  },
  COMMAND_INJECTION: {
    sid: 2100003,
    name: 'Command Injection Attempt',
    category: 'WEB_ATTACK',
    severity: 'critical',
    msg: 'Command injection attempt detected',
    reference: 'url,www.owasp.org/index.php/Command_Injection'
  },
  MALWARE: {
    sid: 2100004,
    name: 'Malware Communication Detected',
    category: 'MALWARE',
    severity: 'critical',
    msg: 'Malware communication detected to known C2 server',
    reference: 'url,www.virustotal.com'
  },
  PORT_SCAN: {
    sid: 2100005,
    name: 'Port Scan Detected',
    category: 'ATTACK',
    severity: 'high',
    msg: 'Port scanning activity detected',
    reference: 'url,en.wikipedia.org/wiki/Port_scanner'
  },
  DDOS: {
    sid: 2100006,
    name: 'Potential DDoS Attack',
    category: 'ATTACK',
    severity: 'critical',
    msg: 'Potential DDoS attack pattern detected',
    reference: 'url,en.wikipedia.org/wiki/Denial-of-service_attack'
  },
  SHELLCODE: {
    sid: 2100007,
    name: 'Shellcode Detection',
    category: 'MALWARE',
    severity: 'critical',
    msg: 'Shellcode detected in network traffic',
    reference: 'url,en.wikipedia.org/wiki/Shellcode'
  },
  PRIVILEGE_ESCALATION: {
    sid: 2100008,
    name: 'Privilege Escalation Attempt',
    category: 'ATTACK',
    severity: 'high',
    msg: 'Privilege escalation attempt detected',
    reference: 'url,en.wikipedia.org/wiki/Privilege_escalation'
  },
  DNS_TUNNELING: {
    sid: 2100009,
    name: 'DNS Tunneling Detected',
    category: 'MALWARE',
    severity: 'high',
    msg: 'DNS tunneling activity detected',
    reference: 'url,en.wikipedia.org/wiki/DNS_tunneling'
  },
  FILE_DOWNLOAD: {
    sid: 2100010,
    name: 'Suspicious File Download',
    category: 'MALWARE',
    severity: 'medium',
    msg: 'Suspicious file download detected',
    reference: 'url,www.virustotal.com'
  }
};

// Common IP addresses
const IPS = [
  '192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13',
  '10.0.0.10', '10.0.0.11', '10.0.0.12', '10.0.0.13',
  '172.16.0.10', '172.16.0.11', '172.16.0.12',
  '45.33.22.11', '89.45.67.23', '123.45.67.89', '67.89.12.34'
];

// Common ports
const PORTS = [80, 443, 22, 21, 25, 53, 143, 993, 995, 3306, 5432, 27017];

// Malicious domains for malware signatures
const MALICIOUS_DOMAINS = [
  'malware-c2.net', 'bad-domain.com', 'evil-server.org', 'phishing-site.biz',
  'ransomware-distribution.cc', 'exploit-kit.ru', 'trojan-delivery.cn'
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
 * Generate Suricata alert
 */
function generateSuricataAlert() {
  const signatureKeys = Object.keys(SURICATA_SIGNATURES);
  const key = randomItem(signatureKeys);
  const signature = SURICATA_SIGNATURES[key];
  
  const srcIP = randomIP();
  const destIP = randomIP();
  const srcPort = randomPort();
  const destPort = randomPort();
  const protocol = randomItem(['TCP', 'UDP', 'ICMP']);
  
  // Build alert message
  let alertMessage = `${signature.msg}`;
  
  // Add specific details based on signature type
  if (key === 'SQL_INJECTION') {
    const sqlPayloads = ["' OR '1'='1", "' UNION SELECT * FROM users--", "'; DROP TABLE users--"];
    alertMessage += ` - Payload: ${randomItem(sqlPayloads)}`;
  } else if (key === 'XSS') {
    const xssPayloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"];
    alertMessage += ` - Payload: ${randomItem(xssPayloads)}`;
  } else if (key === 'MALWARE') {
    alertMessage += ` - Domain: ${randomItem(MALICIOUS_DOMAINS)}`;
  } else if (key === 'PORT_SCAN') {
    const ports = [22, 80, 443, 3306, 5432];
    alertMessage += ` - Scanned Ports: ${ports.slice(0, Math.floor(Math.random() * 3) + 2).join(', ')}`;
  } else if (key === 'DDOS') {
    alertMessage += ` - ${Math.floor(Math.random() * 1000) + 100} packets/sec`;
  }

  const alert = {
    signature: {
      sid: signature.sid,
      name: signature.name,
      category: signature.category,
      severity: signature.severity,
      msg: alertMessage,
      reference: signature.reference
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
    app_proto: randomItem(['http', 'https', 'dns', 'smtp', 'ftp']),
    flow: randomItem(['to_server', 'to_client']),
    payload: {
      raw: crypto.randomBytes(32).toString('hex'),
      length: Math.floor(Math.random() * 256) + 16
    },
    action: randomItem(['alert', 'drop', 'reject']),
    timestamp: new Date().toISOString()
  };

  // Add HTTP details for web attacks
  if (key === 'SQL_INJECTION' || key === 'XSS' || key === 'COMMAND_INJECTION') {
    alert.http = {
      hostname: randomItem(['www.example.com', 'api.example.com', 'admin.example.com']),
      uri: randomItem(['/login', '/search', '/query', '/api/users', '/admin']),
      method: randomItem(['GET', 'POST']),
      user_agent: randomItem([
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
        'curl/7.68.0', 'Wget/1.20.3',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36'
      ])
    };
  }

  return alert;
}

/**
 * Generate pattern of Suricata alerts
 */
function generatePatternedAlerts() {
  const patterns = [
    // Pattern 1: Port scan followed by exploit attempt
    () => {
      const alerts = [];
      const targetIP = randomIP();
      
      // Port scan
      const scan = generateSuricataAlert();
      const scanKey = Object.keys(SURICATA_SIGNATURES)[4]; // PORT_SCAN
      const scanSig = SURICATA_SIGNATURES[scanKey];
      scan.signature = scanSig;
      scan.dest.ip = targetIP;
      scan.msg = `Port scan detected targeting ${targetIP}`;
      alerts.push(scan);
      
      // Exploit attempt
      const exploit = generateSuricataAlert();
      const exploitKey = randomItem(['SQL_INJECTION', 'XSS', 'COMMAND_INJECTION']);
      const exploitSig = SURICATA_SIGNATURES[exploitKey];
      exploit.signature = exploitSig;
      exploit.dest.ip = targetIP;
      exploit.msg = `${exploitSig.name} detected targeting ${targetIP}`;
      alerts.push(exploit);
      
      return alerts;
    },
    
    // Pattern 2: Malware communication sequence
    () => {
      const alerts = [];
      
      // Initial malware detection
      const malware = generateSuricataAlert();
      const malwareKey = 'MALWARE';
      const malwareSig = SURICATA_SIGNATURES[malwareKey];
      malware.signature = malwareSig;
      malware.msg = `${malwareSig.msg} - Domain: ${randomItem(MALICIOUS_DOMAINS)}`;
      alerts.push(malware);
      
      // Data exfiltration attempt
      const exfil = generateSuricataAlert();
      const exfilSig = SURICATA_SIGNATURES['DNS_TUNNELING'];
      exfil.signature = exfilSig;
      exfil.msg = `Possible data exfiltration via DNS tunneling detected`;
      alerts.push(exfil);
      
      return alerts;
    },
    
    // Pattern 3: DDoS attack pattern
    () => {
      const alerts = [];
      const targetIP = randomIP();
      const count = Math.floor(Math.random() * 4) + 3;
      
      for (let i = 0; i < count; i++) {
        const ddos = generateSuricataAlert();
        const ddosKey = 'DDOS';
        const ddosSig = SURICATA_SIGNATURES[ddosKey];
        ddos.signature = ddosSig;
        ddos.dest.ip = targetIP;
        ddos.source.ip = randomIP();
        ddos.msg = `DDoS attack detected against ${targetIP} - Wave ${i+1}`;
        alerts.push(ddos);
      }
      
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
      // For multiple alerts, send the first one (or you could loop)
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
    console.log(`✅ Sent ${alertCount} Suricata alert(s) - Status: ${response.status}`);
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
 * Format Suricata alert for the API
 */
function formatAlertForAPI(alert) {
  return {
    eventType: alert.signature.name || 'Suricata Alert',
    eventCategory: alert.signature.category || 'security',
    severity: alert.signature.severity || 'high',
    message: alert.signature.msg || alert.msg || 'Suricata alert detected',
    sourceIP: alert.source.ip || '',
    destinationIP: alert.dest.ip || '',
    destinationPort: alert.dest.port || 0,
    protocol: alert.protocol || 'TCP',
    hostname: alert.http?.hostname || '',
    rawLog: alert,
    normalizedData: {
      signature: alert.signature,
      action: alert.action,
      flow: alert.flow
    },
    eventTime: alert.timestamp || new Date().toISOString()
  };
}
/**
 * Main simulation loop
 */
async function runSimulator() {
  console.log('🛡️ Suricata IDS/IPS Alert Simulator');
  console.log(`📡 API URL: ${CONFIG.API_URL}`);
  console.log(`🆔 Source ID: ${CONFIG.SOURCE_ID}`);
  console.log('🔑 Auth Token: ' + (CONFIG.AUTH_TOKEN ? '***' : 'MISSING!'));
  console.log('⏱️  Interval: ' + CONFIG.INTERVAL_MIN + '-' + CONFIG.INTERVAL_MAX + 'ms');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  // Validate configuration
  if (!CONFIG.SOURCE_ID || !CONFIG.AUTH_TOKEN) {
    console.error('❌ ERROR: SOURCE_ID and AUTH_TOKEN must be set in environment variables or config');
    console.log('\n💡 To fix this, set the following environment variables:');
    console.log('  export SURICATA_SOURCE_ID=your_log_source_id');
    console.log('  export SURICATA_AUTH_TOKEN=your_authentication_token');
    process.exit(1);
  }

  let alertCount = 0;
  let patternCount = 0;

  while (CONFIG.RUN_FOREVER) {
    try {
      // Randomly generate patterns (30% chance) or single alerts
      let alerts;
      if (Math.random() < 0.3) {
        alerts = generatePatternedAlerts();
        patternCount++;
        console.log(`🎯 Pattern ${patternCount} - Generated ${alerts.length} correlated alerts`);
      } else {
        alerts = generateSuricataAlert();
        alertCount++;
        console.log(`📋 Alert ${alertCount} - ${alerts.signature.name} (Severity: ${alerts.signature.severity})`);
        console.log(`   From: ${alerts.source.ip}:${alerts.source.port} -> ${alerts.dest.ip}:${alerts.dest.port}`);
      }

      // Send alerts
      await sendAlerts(alerts);

      // Random interval between 3-7 seconds
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
  console.log('\n🛑 Shutting down Suricata simulator...');
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

module.exports = { runSimulator, generateSuricataAlert, sendAlerts };