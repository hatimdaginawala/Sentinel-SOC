/**
 * Firewall (pfSense) Log Simulator
 * Simulates firewall/pfSense events including connections, blocks, and NAT
 * Sends logs to SentinelSOC ingestion endpoint
 */

require('dotenv').config();

const axios = require('axios');
const { faker } = require('@faker-js/faker');
const crypto = require('crypto');

// Load configuration
const config = require('./config');

// Use Firewall configuration
// In firewallSimulator.js, update the CONFIG section
const CONFIG = {
  API_URL: process.env.API_URL || 'http://localhost:5000/api/v1/logs/ingest',
  SOURCE_ID: process.env.PFSENSE_SOURCE_ID || process.env.FIREWALL_SOURCE_ID || '',
  AUTH_TOKEN: process.env.PFSENSE_AUTH_TOKEN || process.env.FIREWALL_AUTH_TOKEN || '',
  INTERVAL_MIN: 2000,
  INTERVAL_MAX: 5000,
  RUN_FOREVER: true
};

// Firewall event types
const FIREWALL_EVENTS = {
  CONNECTION_ALLOWED: {
    action: 'pass',
    reason: 'Allowed by rule',
    severity: 'info',
    eventType: 'Connection Allowed'
  },
  CONNECTION_BLOCKED: {
    action: 'block',
    reason: 'Blocked by rule',
    severity: 'medium',
    eventType: 'Connection Blocked'
  },
  REJECTED: {
    action: 'reject',
    reason: 'Rejected by rule',
    severity: 'high',
    eventType: 'Connection Rejected'
  },
  NAT_RULE: {
    action: 'pass',
    reason: 'NAT rule applied',
    severity: 'info',
    eventType: 'NAT Connection'
  },
  PORT_FORWARD: {
    action: 'pass',
    reason: 'Port forward',
    severity: 'info',
    eventType: 'Port Forward'
  },
  BLOCKED_PACKET: {
    action: 'block',
    reason: 'Blocked packet',
    severity: 'high',
    eventType: 'Packet Blocked'
  },
  INVALID_TRAFFIC: {
    action: 'block',
    reason: 'Invalid traffic',
    severity: 'medium',
    eventType: 'Invalid Traffic'
  },
  FLOOD_ATTACK: {
    action: 'block',
    reason: 'Flood attack detected',
    severity: 'critical',
    eventType: 'Flood Attack Blocked'
  }
};

// Common IP addresses
const INTERNAL_IPS = [
  '192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13',
  '192.168.1.20', '192.168.1.21', '192.168.1.22', '192.168.1.23',
  '10.0.0.10', '10.0.0.11', '10.0.0.12', '10.0.0.13',
  '172.16.0.10', '172.16.0.11', '172.16.0.12'
];

const EXTERNAL_IPS = [
  '8.8.8.8', '1.1.1.1', '208.67.222.222', '208.67.220.220',
  '45.33.22.11', '89.45.67.23', '123.45.67.89', '67.89.12.34',
  '185.130.5.10', '194.28.114.22', '212.102.40.15', '185.220.101.23'
];

const MALICIOUS_IPS = [
  '185.130.5.10', '194.28.114.22', '212.102.40.15', '185.220.101.23',
  '107.189.15.45', '194.28.114.88', '212.102.40.33', '185.220.101.67'
];

// Common ports
const PORTS = [80, 443, 22, 21, 25, 53, 143, 993, 995, 3306, 5432, 27017, 3389, 445, 139];

// Interface names
const INTERFACES = ['WAN', 'LAN', 'DMZ', 'VPN', 'WLAN', 'OPT1', 'OPT2'];

// Protocols
const PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'IP', 'IGMP'];

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
 * Generate firewall event
 */
function generateFirewallEvent() {
  const eventKeys = Object.keys(FIREWALL_EVENTS);
  const key = randomItem(eventKeys);
  const eventType = FIREWALL_EVENTS[key];
  
  const srcIP = Math.random() > 0.3 ? randomItem(INTERNAL_IPS) : randomIP();
  const destIP = Math.random() > 0.3 ? randomItem(EXTERNAL_IPS) : randomIP();
  const srcPort = randomPort();
  const destPort = randomPort();
  const protocol = randomItem(PROTOCOLS);
  const interface_name = randomItem(INTERFACES);
  
  // For malicious traffic, use known malicious IPs
  let isMalicious = false;
  let threatType = null;
  
  if (Math.random() < 0.15) {
    isMalicious = true;
    threatType = randomItem(['Port Scan', 'DDoS Attempt', 'Malware C2', 'Brute Force', 'Exploit Attempt']);
    eventType.severity = 'critical';
    eventType.reason = `Malicious traffic detected - ${threatType}`;
  }

  // Build message
  let message = `${eventType.action.toUpperCase()}: ${eventType.eventType}`;
  message += ` - ${srcIP}:${srcPort} -> ${destIP}:${destPort} (${protocol})`;
  message += ` - ${eventType.reason}`;
  
  if (isMalicious) {
    message += ` - 🚨 ${threatType} detected!`;
  }

  const log = {
    action: eventType.action,
    eventType: eventType.eventType,
    severity: eventType.severity,
    sourceIP: srcIP,
    sourcePort: srcPort,
    destinationIP: destIP,
    destinationPort: destPort,
    protocol: protocol,
    interface: interface_name,
    direction: srcIP.startsWith('192.168.') || srcIP.startsWith('10.') || srcIP.startsWith('172.16.') ? 'out' : 'in',
    message: message,
    reason: eventType.reason,
    isMalicious: isMalicious,
    threatType: threatType,
    packetSize: Math.floor(Math.random() * 1500) + 64,
    timestamp: new Date().toISOString(),
    rule: `${Math.floor(Math.random() * 100)}_${Math.floor(Math.random() * 100)}`,
    nat: Math.random() > 0.5 ? {
      src_ip: srcIP,
      src_port: srcPort,
      dest_ip: destIP,
      dest_port: destPort
    } : null,
    tcp_flags: protocol === 'TCP' ? {
      syn: Math.random() > 0.5,
      ack: Math.random() > 0.5,
      rst: Math.random() > 0.8,
      fin: Math.random() > 0.7
    } : null
  };

  return log;
}

/**
 * Generate pattern of firewall events
 */
function generatePatternedEvents() {
  const patterns = [
    // Pattern 1: Port scan from external IP
    () => {
      const events = [];
      const srcIP = randomItem(MALICIOUS_IPS);
      const targetIP = randomItem(INTERNAL_IPS);
      const ports = [22, 80, 443, 3306, 5432, 3389, 445];
      
      for (const port of ports) {
        const event = generateFirewallEvent();
        event.sourceIP = srcIP;
        event.destinationIP = targetIP;
        event.destinationPort = port;
        event.action = 'block';
        event.eventType = 'Connection Blocked';
        event.severity = 'high';
        event.isMalicious = true;
        event.threatType = 'Port Scan';
        event.message = `BLOCK: Port Scan - ${srcIP}:${randomPort()} -> ${targetIP}:${port} (TCP) - Port scan detected`;
        events.push(event);
      }
      
      return events;
    },
    
    // Pattern 2: DDoS attack pattern
    () => {
      const events = [];
      const targetIP = randomItem(INTERNAL_IPS);
      const count = Math.floor(Math.random() * 8) + 5;
      
      for (let i = 0; i < count; i++) {
        const event = generateFirewallEvent();
        event.sourceIP = randomItem(MALICIOUS_IPS);
        event.destinationIP = targetIP;
        event.destinationPort = 80;
        event.action = 'block';
        event.eventType = 'Flood Attack Blocked';
        event.severity = 'critical';
        event.isMalicious = true;
        event.threatType = 'DDoS Attempt';
        event.message = `BLOCK: DDoS Attempt - ${event.sourceIP}:${event.sourcePort} -> ${targetIP}:80 (TCP) - Wave ${i+1}/${count}`;
        events.push(event);
      }
      
      return events;
    },
    
    // Pattern 3: Malware communication with block
    () => {
      const events = [];
      const internalIP = randomItem(INTERNAL_IPS);
      const maliciousIP = randomItem(MALICIOUS_IPS);
      
      // Allow connection to malicious IP
      const allow = generateFirewallEvent();
      allow.sourceIP = internalIP;
      allow.destinationIP = maliciousIP;
      allow.action = 'pass';
      allow.eventType = 'Connection Allowed';
      allow.severity = 'info';
      allow.message = `PASS: ${internalIP}:${allow.sourcePort} -> ${maliciousIP}:${allow.destinationPort} - Outbound connection`;
      events.push(allow);
      
      // Then block subsequent traffic
      const block = generateFirewallEvent();
      block.sourceIP = internalIP;
      block.destinationIP = maliciousIP;
      block.action = 'block';
      block.eventType = 'Connection Blocked';
      block.severity = 'critical';
      block.isMalicious = true;
      block.threatType = 'Malware C2';
      block.message = `BLOCK: Malware C2 Communication - ${internalIP}:${block.sourcePort} -> ${maliciousIP}:${block.destinationPort} - Known malicious IP`;
      events.push(block);
      
      return events;
    },
    
    // Pattern 4: VPN connection and traffic
    () => {
      const events = [];
      const vpnIP = `10.8.0.${Math.floor(Math.random() * 254) + 2}`;
      const destIP = randomItem(INTERNAL_IPS);
      
      // VPN connection
      const vpn = generateFirewallEvent();
      vpn.sourceIP = vpnIP;
      vpn.destinationIP = destIP;
      vpn.interface = 'VPN';
      vpn.action = 'pass';
      vpn.eventType = 'Connection Allowed';
      vpn.severity = 'info';
      vpn.message = `PASS: VPN Connection - ${vpnIP}:${vpn.sourcePort} -> ${destIP}:${vpn.destinationPort} - VPN tunnel established`;
      events.push(vpn);
      
      // Subsequent traffic through VPN
      for (let i = 0; i < 2; i++) {
        const traffic = generateFirewallEvent();
        traffic.sourceIP = vpnIP;
        traffic.destinationIP = destIP;
        traffic.interface = 'VPN';
        traffic.action = 'pass';
        traffic.eventType = 'Connection Allowed';
        traffic.severity = 'info';
        traffic.message = `PASS: VPN Traffic - ${vpnIP}:${traffic.sourcePort} -> ${destIP}:${traffic.destinationPort} - VPN tunnel`;
        events.push(traffic);
      }
      
      return events;
    }
  ];

  const pattern = randomItem(patterns);
  return pattern();
}

/**
 * Send events to SentinelSOC
 */
async function sendEvents(events) {
  try {
    const payload = {
      sourceId: CONFIG.SOURCE_ID,
      authToken: CONFIG.AUTH_TOKEN,
      log: Array.isArray(events) ? events[0] : events
    };

    const response = await axios.post(CONFIG.API_URL, payload, {
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });

    const eventCount = Array.isArray(events) ? events.length : 1;
    console.log(`✅ Sent ${eventCount} firewall event(s) - Status: ${response.status}`);
    return response.data;
  } catch (error) {
    if (error.response) {
      console.error(`❌ Server responded with error: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
    } else if (error.request) {
      console.error('❌ No response from server. Is the API running?');
    } else {
      console.error(`❌ Error sending events: ${error.message}`);
    }
    return null;
  }
}

/**
 * Main simulation loop
 */
async function runSimulator() {
  console.log('🔥 Firewall (pfSense) Log Simulator');
  console.log(`📡 API URL: ${CONFIG.API_URL}`);
  console.log(`🆔 Source ID: ${CONFIG.SOURCE_ID}`);
  console.log('🔑 Auth Token: ' + (CONFIG.AUTH_TOKEN ? '***' : 'MISSING!'));
  console.log('⏱️  Interval: ' + CONFIG.INTERVAL_MIN + '-' + CONFIG.INTERVAL_MAX + 'ms');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  // Validate configuration
  if (!CONFIG.SOURCE_ID || !CONFIG.AUTH_TOKEN) {
    console.error('❌ ERROR: SOURCE_ID and AUTH_TOKEN must be set in environment variables or config');
    console.log('\n💡 To fix this, set the following environment variables:');
    console.log('  export FIREWALL_SOURCE_ID=your_log_source_id');
    console.log('  export FIREWALL_AUTH_TOKEN=your_authentication_token');
    process.exit(1);
  }

  let eventCount = 0;
  let patternCount = 0;

  while (CONFIG.RUN_FOREVER) {
    try {
      // Randomly generate patterns (25% chance) or single events
      let events;
      if (Math.random() < 0.25) {
        events = generatePatternedEvents();
        patternCount++;
        console.log(`🎯 Pattern ${patternCount} - Generated ${events.length} correlated events`);
      } else {
        events = generateFirewallEvent();
        eventCount++;
        const action = events.action.toUpperCase();
        const threat = events.isMalicious ? ' 🚨' : '';
        console.log(`📋 Event ${eventCount} - ${action}: ${events.eventType} - ${events.sourceIP}:${events.sourcePort} -> ${events.destinationIP}:${events.destinationPort}${threat}`);
        if (events.isMalicious) {
          console.log(`   ⚠️  ${events.threatType} detected!`);
        }
      }

      // Send events
      await sendEvents(events);

      // Random interval between 2-5 seconds
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
  console.log('\n🛑 Shutting down Firewall simulator...');
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

module.exports = { runSimulator, generateFirewallEvent, sendEvents };