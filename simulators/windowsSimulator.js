/**
 * Windows Event Log Simulator
 * Simulates Windows security and system events
 * Sends logs to SentinelSOC ingestion endpoint
 */

require('dotenv').config();

const axios = require('axios');
const { faker } = require('@faker-js/faker');
const crypto = require('crypto');

// Load configuration
const config = require('./config');

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

// Common IP addresses for different organizations
const ORG_IPS = {
  acme: ['192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13'],
  gfi: ['10.0.0.10', '10.0.0.11', '10.0.0.12', '10.0.0.13'],
  hcs: ['172.16.0.10', '172.16.0.11', '172.16.0.12', '172.16.0.13']
};

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
 * Generate random IP address for an organization
 */
function randomIP(org) {
  const ips = ORG_IPS[org] || ['192.168.1.100', '192.168.1.101'];
  return randomItem(ips);
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
function generateWindowsEvent(org) {
  const eventType = Math.random() > 0.3 ? 'SECURITY' : (Math.random() > 0.5 ? 'SYSTEM' : 'APPLICATION');
  const events = WINDOWS_EVENTS[eventType];
  const eventIds = Object.keys(events);
  const eventId = randomItem(eventIds);
  const eventName = events[eventId];
  
  const username = Math.random() > 0.3 ? randomItem(USERS) : randomItem(['SYSTEM', 'NETWORK SERVICE']);
  const hostname = randomItem(HOSTNAMES);
  const sourceIP = randomIP(org);
  const destIP = randomIP(org);
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

  return { log, organization: org };
}

/**
 * Generate realistic Windows log patterns with variations
 */
function generatePatternedEvent(org) {
  const patterns = [
    // Pattern 1: Multiple failed logins from same IP
    () => {
      const ip = randomIP(org);
      const events = [];
      const count = Math.floor(Math.random() * 5) + 2;
      for (let i = 0; i < count; i++) {
        const { log } = generateWindowsEvent(org);
        log.eventId = '4625';
        log.eventName = 'Failed Login';
        log.sourceIP = ip;
        log.message = `[Security] Failed Login - User: ${randomItem(USERS)} - Source IP: ${ip} - Attempt ${i+1}/${count}`;
        log.severity = 'high';
        events.push(log);
      }
      return { events, organization: org };
    },
    
    // Pattern 2: Account lockout sequence
    () => {
      const user = randomItem(USERS);
      const events = [];
      const count = Math.floor(Math.random() * 3) + 1;
      for (let i = 0; i < count; i++) {
        const { log } = generateWindowsEvent(org);
        log.eventId = '4625';
        log.eventName = 'Failed Login';
        log.username = user;
        log.message = `[Security] Failed Login - User: ${user} - Source IP: ${randomIP(org)}`;
        log.severity = 'high';
        events.push(log);
      }
      // Add lockout event
      const { log: lockoutLog } = generateWindowsEvent(org);
      lockoutLog.eventId = '4740';
      lockoutLog.eventName = 'Account Locked';
      lockoutLog.username = user;
      lockoutLog.message = `[Security] Account Locked - User: ${user}`;
      lockoutLog.severity = 'critical';
      events.push(lockoutLog);
      return { events, organization: org };
    },
    
    // Pattern 3: Successful admin login
    () => {
      const { log } = generateWindowsEvent(org);
      log.eventId = '4624';
      log.eventName = 'Successful Login';
      log.username = randomItem(['Administrator', 'John.Doe', 'Jane.Smith']);
      log.message = `[Security] Successful Login - User: ${log.username} - Source IP: ${randomIP(org)}`;
      log.severity = 'low';
      return { events: [log], organization: org };
    }
  ];

  const pattern = randomItem(patterns);
  return pattern();
}

/**
 * Send logs to SentinelSOC
 */
async function sendLogs(logs, sourceId, authToken) {
  try {
    // Send each log individually
    for (const log of logs) {
      const payload = {
        sourceId: sourceId,
        authToken: authToken,
        log: log
      };

      const response = await axios.post(config.DEFAULT_API_URL, payload, {
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: 10000
      });

      console.log(`✅ Sent 1 Windows event(s) - Status: ${response.status}`);
    }
    return true;
  } catch (error) {
    if (error.response) {
      console.error(`❌ Server responded with error: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
    } else if (error.request) {
      console.error('❌ No response from server. Is the API running?');
    } else {
      console.error(`❌ Error sending logs: ${error.message}`);
    }
    return false;
  }
}

/**
 * Main simulation loop
 */
async function runSimulator() {
  console.log('🪟 Windows Event Log Simulator (Multi-Organization)');
  console.log(`📡 API URL: ${config.DEFAULT_API_URL}`);
  console.log('⏱️  Interval: 2000-3000ms');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  let eventCount = 0;
  let patternCount = 0;

  while (true) {
    try {
      // Get random organization for this event
      const org = config.getRandomOrganization();
      
      // Get the Windows source for this organization
      const source = config.getRandomSourceForOrg(org, 'windows');
      
      if (!source) {
        console.log(`⚠️ No Windows source found for organization: ${org}`);
        await new Promise(resolve => setTimeout(resolve, 3000));
        continue;
      }

      // Randomly generate patterns (30% chance) or single events
      let result;
      let isPattern = false;
      
      if (Math.random() < 0.3) {
        result = generatePatternedEvent(org);
        isPattern = true;
        patternCount++;
        console.log(`🎯 Pattern ${patternCount} - Generated ${result.events.length} correlated events for ${org}`);
      } else {
        const { log } = generateWindowsEvent(org);
        result = { events: [log], organization: org };
        eventCount++;
        console.log(`📋 Event ${eventCount} - ${log.eventId}: ${log.eventName} - ${log.hostname} (${org})`);
      }

      // Send logs
      await sendLogs(result.events, source.sourceId, source.authToken);

      // Random interval between 2-3 seconds
      const interval = Math.floor(Math.random() * 1000) + 2000;
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

module.exports = { runSimulator };