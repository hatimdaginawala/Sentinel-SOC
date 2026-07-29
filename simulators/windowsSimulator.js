/**
 * Windows Event Log Simulator
 * Simulates Windows security and system events
 * Sends logs to SentinelSOC ingestion endpoint
 */

const axios = require('axios');
const { faker } = require('@faker-js/faker');
const crypto = require('crypto');
// Add this at the very top of each simulator file
require('dotenv').config();

// Rest of the code...
// Configuration

const CONFIG = {
  API_URL: process.env.API_URL || 'http://localhost:5000/api/v1/logs/ingest',
  SOURCE_ID: process.env.WINDOWS_SOURCE_ID || '',
  AUTH_TOKEN: process.env.WINDOWS_AUTH_TOKEN || '',
  INTERVAL_MIN: 2000,
  INTERVAL_MAX: 5000,
  RUN_FOREVER: true
};
// Windows Event Types
const WINDOWS_EVENTS = {
  SECURITY: {
    '4624': 'Successful Login',
    '4625': 'Failed Login',
    '4634': 'Logoff',
    '4647': 'User Initiated Logoff',
    '4740': 'Account Locked',
    '4720': 'User Created',
    '4722': 'User Enabled',
    '4723': 'Password Changed',
    '4724': 'Password Reset',
    '4725': 'User Disabled',
    '4726': 'User Deleted',
    '4732': 'Member Added',
    '4733': 'Member Removed',
    '4767': 'User Unlocked',
    '4771': 'Kerberos Pre-Authentication Failed',
    '4776': 'Credential Validation'
  },
  SYSTEM: {
    '41': 'System Reboot',
    '6005': 'Event Log Started',
    '6006': 'Event Log Stopped',
    '6008': 'Unexpected Shutdown',
    '7000': 'Service Start Failed',
    '7009': 'Service Timeout',
    '7036': 'Service State Change'
  },
  APPLICATION: {
    '1000': 'Application Error',
    '1001': 'Application Hang',
    '1026': '.NET Runtime Error',
    '1028': '.NET Runtime Warning',
    '1030': '.NET Runtime Info'
  }
};

// Common Windows usernames
const USERS = [
  'Administrator', 'SYSTEM', 'NETWORK SERVICE', 'LOCAL SERVICE',
  'John.Doe', 'Jane.Smith', 'Bob.Johnson', 'Alice.Williams',
  'Charlie.Brown', 'Diana.Ross', 'Edward.Smith', 'Fiona.Clark'
];

// Common Windows hostnames
const HOSTNAMES = [
  'WIN-SRV-01', 'WIN-SRV-02', 'WIN-SRV-03', 'WIN-WKS-01',
  'WIN-WKS-02', 'WIN-WKS-03', 'DC-01', 'DC-02',
  'APP-SRV-01', 'APP-SRV-02', 'DB-SRV-01'
];

// Common IP addresses
const IPS = [
  '192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13',
  '10.0.0.10', '10.0.0.11', '10.0.0.12', '10.0.0.13',
  '172.16.0.10', '172.16.0.11', '172.16.0.12'
];

// Common processes
const PROCESSES = [
  'svchost.exe', 'services.exe', 'lsass.exe', 'winlogon.exe',
  'explorer.exe', 'taskhost.exe', 'spoolsv.exe', 'sqlserver.exe',
  'w3wp.exe', 'chrome.exe', 'firefox.exe', 'outlook.exe',
  'Word.exe', 'Excel.exe', 'PowerShell.exe', 'cmd.exe'
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
  return Math.floor(Math.random() * 65535) + 1024;
}

/**
 * Generate a Windows Event Log
 */
function generateWindowsEvent() {
  const eventType = Math.random() > 0.3 ? 'SECURITY' : (Math.random() > 0.5 ? 'SYSTEM' : 'APPLICATION');
  const events = WINDOWS_EVENTS[eventType];
  const eventIds = Object.keys(events);
  const eventId = randomItem(eventIds);
  const eventName = events[eventId];
  
  const username = Math.random() > 0.3 ? randomItem(USERS) : randomItem(['SYSTEM', 'NETWORK SERVICE']);
  const hostname = randomItem(HOSTNAMES);
  const sourceIP = randomIP();
  const destIP = randomIP();
  const processName = randomItem(PROCESSES);
  
  // Determine severity based on event ID
  let severity = 'info';
  if (eventId === '4625' || eventId === '4740' || eventId === '4771' || eventId === '4776') {
    severity = 'high';
  } else if (eventId === '4725' || eventId === '4726' || eventId === '6008' || eventId === '41') {
    severity = 'medium';
  } else if (eventId === '4624' || eventId === '4720') {
    severity = 'low';
  }

  // Build message
  let message = `Event ${eventId}: ${eventName}`;
  if (eventType === 'SECURITY') {
    message = `[Security] ${eventName} - User: ${username}`;
    if (eventId === '4625') {
      message += ` - Source IP: ${sourceIP}`;
    }
    if (eventId === '4740') {
      message += ` - Account Locked: ${username}`;
    }
  } else if (eventType === 'SYSTEM') {
    message = `[System] ${eventName}`;
    if (eventId === '41' || eventId === '6008') {
      message += ` - Unexpected shutdown on ${hostname}`;
    }
  } else {
    message = `[Application] ${eventName}`;
    if (eventId === '1000' || eventId === '1001') {
      message += ` - Process: ${processName}`;
    }
  }

  // Create the log
  const log = {
    eventId: eventId,
    eventName: eventName,
    eventType: eventType,
    hostname: hostname,
    username: username,
    ipAddress: sourceIP,
    sourceIP: sourceIP,
    destinationIP: Math.random() > 0.5 ? destIP : '',
    destinationPort: Math.random() > 0.5 ? randomPort() : 0,
    processName: processName,
    message: message,
    severity: severity,
    eventTime: new Date().toISOString(),
    logonType: Math.random() > 0.5 ? 2 : (Math.random() > 0.5 ? 3 : 10),
    workstation: Math.random() > 0.5 ? randomItem(['WORKSTATION-01', 'WORKSTATION-02', 'WORKSTATION-03']) : '',
    domain: Math.random() > 0.5 ? 'DOMAIN.local' : 'WORKGROUP',
    status: eventId === '4625' ? 'failure' : (eventId === '4740' ? 'locked' : 'success')
  };

  return log;
}

/**
 * Generate realistic Windows log patterns with variations
 */
function generatePatternedEvent() {
  const patterns = [
    // Pattern 1: Multiple failed logins from same IP
    () => {
      const ip = randomIP();
      const events = [];
      const count = Math.floor(Math.random() * 5) + 2;
      for (let i = 0; i < count; i++) {
        const event = generateWindowsEvent();
        event.eventId = '4625';
        event.eventName = 'Failed Login';
        event.sourceIP = ip;
        event.message = `[Security] Failed Login - User: ${randomItem(USERS)} - Source IP: ${ip} - Attempt ${i+1}/${count}`;
        event.severity = 'high';
        events.push(event);
      }
      return events;
    },
    
    // Pattern 2: Account lockout sequence
    () => {
      const user = randomItem(USERS);
      const events = [];
      const count = Math.floor(Math.random() * 3) + 1;
      for (let i = 0; i < count; i++) {
        const event = generateWindowsEvent();
        event.eventId = '4625';
        event.eventName = 'Failed Login';
        event.username = user;
        event.message = `[Security] Failed Login - User: ${user} - Source IP: ${randomIP()}`;
        event.severity = 'high';
        events.push(event);
      }
      // Add lockout event
      const lockout = generateWindowsEvent();
      lockout.eventId = '4740';
      lockout.eventName = 'Account Locked';
      lockout.username = user;
      lockout.message = `[Security] Account Locked - User: ${user}`;
      lockout.severity = 'critical';
      events.push(lockout);
      return events;
    },
    
    // Pattern 3: Successful admin login
    () => {
      const event = generateWindowsEvent();
      event.eventId = '4624';
      event.eventName = 'Successful Login';
      event.username = randomItem(['Administrator', 'John.Doe', 'Jane.Smith']);
      event.message = `[Security] Successful Login - User: ${event.username} - Source IP: ${randomIP()}`;
      event.severity = 'low';
      return [event];
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
    console.log(`✅ Sent ${logCount} Windows event(s) - Status: ${response.status}`);
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
  console.log('🪟 Windows Event Log Simulator');
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
    console.log('\nOr create the log source via the API and copy the token.');
    process.exit(1);
  }

  let eventCount = 0;
  let patternCount = 0;

  while (CONFIG.RUN_FOREVER) {
    try {
      // Randomly generate patterns (30% chance) or single events
      let logs;
      if (Math.random() < 0.3) {
        logs = generatePatternedEvent();
        patternCount++;
        console.log(`🎯 Pattern ${patternCount} - Generated ${logs.length} correlated events`);
      } else {
        logs = generateWindowsEvent();
        eventCount++;
        console.log(`📋 Event ${eventCount} - ${logs.eventId}: ${logs.eventName} - ${logs.hostname}`);
      }

      // Send logs
      await sendLogs(logs);

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
  console.log('\n🛑 Shutting down Windows simulator...');
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

module.exports = { runSimulator, generateWindowsEvent, sendLogs };