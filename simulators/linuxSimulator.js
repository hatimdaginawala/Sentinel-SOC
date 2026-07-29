/**
 * Linux Event Log Simulator
 * Simulates Linux system and security events
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
  SOURCE_ID: process.env.LINUX_SOURCE_ID || '',
  AUTH_TOKEN: process.env.LINUX_AUTH_TOKEN || '',
  INTERVAL_MIN: 2000,
  INTERVAL_MAX: 3000,
  RUN_FOREVER: true
};

// Linux event types
const LINUX_EVENTS = {
  SSH: {
    'sshd': 'SSH Login',
    'sshd_failed': 'SSH Failed Login',
    'sshd_disconnect': 'SSH Disconnect'
  },
  SUDO: {
    'sudo_session': 'sudo Session Open',
    'sudo_session_closed': 'sudo Session Closed',
    'sudo_command': 'sudo Command Executed'
  },
  SYSTEM: {
    'system_boot': 'System Boot',
    'system_shutdown': 'System Shutdown',
    'kernel_panic': 'Kernel Panic',
    'service_start': 'Service Started',
    'service_stop': 'Service Stopped',
    'service_fail': 'Service Failed'
  },
  AUTH: {
    'useradd': 'User Created',
    'userdel': 'User Deleted',
    'passwd_change': 'Password Changed',
    'groupadd': 'Group Created',
    'groupdel': 'Group Deleted'
  }
};

// Common Linux usernames
const USERS = [
  'root', 'ubuntu', 'debian', 'centos', 'john', 'jane',
  'admin', 'developer', 'sysadmin', 'test', 'guest',
  'alice', 'bob', 'charlie', 'diana'
];

// Common Linux hostnames
const HOSTNAMES = [
  'linux-srv-01', 'linux-srv-02', 'linux-srv-03',
  'web-srv-01', 'web-srv-02', 'db-srv-01',
  'app-srv-01', 'app-srv-02', 'dev-01', 'dev-02',
  'ubuntu-20-04', 'centos-8', 'debian-11'
];

// Common IP addresses
const IPS = [
  '192.168.1.20', '192.168.1.21', '192.168.1.22', '192.168.1.23',
  '10.0.0.20', '10.0.0.21', '10.0.0.22', '10.0.0.23',
  '172.16.0.20', '172.16.0.21', '172.16.0.22'
];

// Common processes
const PROCESSES = [
  'sshd', 'sudo', 'systemd', 'kerneld', 'cron',
  'httpd', 'nginx', 'mysqld', 'postgres', 'docker',
  'python', 'node', 'java', 'bash', 'zsh'
];

// Common commands executed with sudo
const SUDO_COMMANDS = [
  'apt-get update', 'yum update', 'systemctl restart', 'service restart',
  'useradd', 'usermod', 'passwd', 'chmod', 'chown',
  'docker run', 'docker stop', 'kubectl', 'helm',
  'mysql', 'psql', 'mongod', 'redis-cli'
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
 * Generate a Linux event
 */
function generateLinuxEvent() {
  const eventCategory = Math.random() > 0.3 ? 'SSH' : (Math.random() > 0.5 ? 'SUDO' : (Math.random() > 0.5 ? 'SYSTEM' : 'AUTH'));
  const events = LINUX_EVENTS[eventCategory];
  const eventKeys = Object.keys(events);
  const eventKey = randomItem(eventKeys);
  const eventName = events[eventKey];
  
  const username = eventCategory === 'SSH' ? randomItem(USERS) : 
                   (eventCategory === 'SUDO' ? randomItem(USERS) : 
                   (Math.random() > 0.5 ? 'root' : randomItem(USERS)));
  
  const hostname = randomItem(HOSTNAMES);
  const sourceIP = randomIP();
  const processName = randomItem(PROCESSES);
  
  // Determine severity
  let severity = 'info';
  if (eventKey === 'sshd_failed' || eventKey === 'kernel_panic') {
    severity = 'high';
  } else if (eventKey === 'sudo_command') {
    severity = 'low';
  } else if (eventKey === 'service_fail' || eventKey === 'userdel') {
    severity = 'medium';
  }

  // Build message
  let message = `[${eventCategory}] ${eventName}`;
  if (eventCategory === 'SSH') {
    if (eventKey === 'sshd') {
      message += ` - User: ${username} from ${sourceIP}`;
    } else if (eventKey === 'sshd_failed') {
      message += ` - Failed login attempt for ${username} from ${sourceIP}`;
      severity = 'high';
    }
  } else if (eventCategory === 'SUDO') {
    if (eventKey === 'sudo_command') {
      const command = randomItem(SUDO_COMMANDS);
      message += ` - User: ${username} executed: ${command}`;
    } else {
      message += ` - User: ${username}`;
    }
  } else if (eventCategory === 'SYSTEM') {
    if (eventKey === 'kernel_panic') {
      message += ` - Kernel panic on ${hostname}`;
    } else if (eventKey === 'service_fail') {
      const service = randomItem(['httpd', 'nginx', 'mysqld', 'postgres', 'docker']);
      message += ` - Service ${service} failed to start`;
    } else {
      message += ` - ${hostname}`;
    }
  } else {
    message += ` - User: ${username}`;
  }

  const log = {
    eventType: eventKey,
    eventName: eventName,
    eventCategory: eventCategory,
    hostname: hostname,
    username: username,
    ipAddress: sourceIP,
    sourceIP: eventCategory === 'SSH' ? sourceIP : '',
    destinationIP: eventCategory === 'SSH' ? randomIP() : '',
    destinationPort: eventCategory === 'SSH' ? 22 : (Math.random() > 0.5 ? randomPort() : 0),
    processName: processName,
    pid: Math.floor(Math.random() * 10000) + 1000,
    message: message,
    severity: severity,
    eventTime: new Date().toISOString(),
    tty: Math.random() > 0.5 ? 'pts/' + Math.floor(Math.random() * 10) : 'tty' + Math.floor(Math.random() * 10),
    shell: randomItem(['/bin/bash', '/bin/zsh', '/bin/sh', '/bin/csh'])
  };

  if (eventCategory === 'SSH' && eventKey === 'sshd_failed') {
    log.failures = Math.floor(Math.random() * 5) + 1;
  }

  return log;
}

/**
 * Generate a pattern of related Linux events
 */
function generatePatternedEvents() {
  const patterns = [
    // Pattern 1: Multiple failed SSH attempts then successful login
    () => {
      const username = randomItem(USERS);
      const sourceIP = randomIP();
      const events = [];
      const attempts = Math.floor(Math.random() * 4) + 2;
      
      for (let i = 0; i < attempts; i++) {
        const event = generateLinuxEvent();
        event.eventKey = 'sshd_failed';
        event.eventName = 'SSH Failed Login';
        event.username = username;
        event.sourceIP = sourceIP;
        event.message = `[SSH] Failed login attempt for ${username} from ${sourceIP} (attempt ${i+1}/${attempts})`;
        event.severity = 'high';
        events.push(event);
      }
      
      // Add successful login
      const success = generateLinuxEvent();
      success.eventKey = 'sshd';
      success.eventName = 'SSH Login';
      success.username = username;
      success.sourceIP = sourceIP;
      success.message = `[SSH] Successful login for ${username} from ${sourceIP}`;
      success.severity = 'low';
      events.push(success);
      
      return events;
    },
    
    // Pattern 2: sudo command escalation
    () => {
      const username = randomItem(USERS.filter(u => u !== 'root'));
      const events = [];
      
      // Add sudo session open
      const session = generateLinuxEvent();
      session.eventKey = 'sudo_session';
      session.eventName = 'sudo Session Open';
      session.username = username;
      session.message = `[SUDO] sudo session opened by ${username}`;
      session.severity = 'low';
      events.push(session);
      
      // Add sudo commands
      const numCommands = Math.floor(Math.random() * 3) + 1;
      for (let i = 0; i < numCommands; i++) {
        const cmd = generateLinuxEvent();
        cmd.eventKey = 'sudo_command';
        cmd.eventName = 'sudo Command Executed';
        cmd.username = username;
        cmd.message = `[SUDO] ${username} executed: ${randomItem(SUDO_COMMANDS)}`;
        cmd.severity = 'low';
        events.push(cmd);
      }
      
      // Add session close
      const close = generateLinuxEvent();
      close.eventKey = 'sudo_session_closed';
      close.eventName = 'sudo Session Closed';
      close.username = username;
      close.message = `[SUDO] sudo session closed by ${username}`;
      close.severity = 'info';
      events.push(close);
      
      return events;
    },
    
    // Pattern 3: Service failure and restart
    () => {
      const service = randomItem(['httpd', 'nginx', 'mysqld', 'postgres']);
      const events = [];
      
      // Service failure
      const failure = generateLinuxEvent();
      failure.eventKey = 'service_fail';
      failure.eventName = 'Service Failed';
      failure.message = `[SYSTEM] Service ${service} failed to start`;
      failure.severity = 'high';
      events.push(failure);
      
      // Service restart attempt
      const restart = generateLinuxEvent();
      restart.eventKey = 'service_start';
      restart.eventName = 'Service Started';
      restart.message = `[SYSTEM] Attempting to restart ${service}`;
      restart.severity = 'medium';
      events.push(restart);
      
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
    console.log(`✅ Sent ${logCount} Linux event(s) - Status: ${response.status}`);
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
  console.log('🐧 Linux Event Log Simulator');
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
      // Randomly generate patterns (25% chance) or single events
      let logs;
      if (Math.random() < 0.25) {
        logs = generatePatternedEvents();
        patternCount++;
        console.log(`🎯 Pattern ${patternCount} - Generated ${logs.length} correlated events`);
      } else {
        logs = generateLinuxEvent();
        eventCount++;
        console.log(`📋 Event ${eventCount} - ${logs.eventName} - ${logs.hostname} (${logs.username})`);
      }

      // Send logs
      await sendLogs(logs);

      // Random interval between 2-5 seconds
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
  console.log('\n🛑 Shutting down Linux simulator...');
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

module.exports = { runSimulator, generateLinuxEvent, sendLogs };