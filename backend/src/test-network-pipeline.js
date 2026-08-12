const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');

// Load env vars
dotenv.config({ path: path.join(__dirname, '.env') });

// Connect to DB
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/sentinel-soc', {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
};

// Import Models
const Organization = require('./models/Organization');
const Asset = require('./models/Asset');
const SecuritySensor = require('./models/SecuritySensor');
const User = require('./models/User');
const LogSource = require('./models/LogSource');
const ThreatRule = require('./models/ThreatRule');
const SecurityTest = require('./models/SecurityTest');
const Log = require('./models/Log');
const Alert = require('./models/Alert');
const Incident = require('./models/Incident');
const Settings = require('./models/Settings');

// Import Services
const LogService = require('./services/logService');
const AutomationService = require('./services/automationService');

const logService = LogService;
const automationService = AutomationService;

const runTests = async () => {
  await connectDB();
  console.log('\n========================================');
  console.log('SentinelSOC Network Defense Test');
  console.log('========================================\n');

  try {
    // 1. Setup Data
    let org = await Organization.findOne({ name: 'Test Org' });
    if (!org) {
      org = await Organization.create({
        name: 'Test Org',
        code: 'TESTORG',
        contactEmail: 'test@example.com',
        contactPhone: '1234567890'
      });
    }

    let sysUser = await User.findOne({ email: 'system@sentinelsoc.local' });
    if (!sysUser) {
      sysUser = await User.create({
        firstName: 'System',
        lastName: 'Account',
        username: 'system_admin',
        email: 'system@sentinelsoc.local',
        password: 'password123',
        organization: org._id,
        role: 'super_admin',
        status: 'active'
      });
    }
    process.env.SYSTEM_USER_ID = sysUser._id.toString();

    let settings = await Settings.findOne({ organization: org._id });
    if (!settings) {
      settings = await Settings.create({
        organization: org._id,
        detection: { alerts: { deduplication: { threshold: 1 } } }
      });
    } else {
      settings.detection = { alerts: { deduplication: { threshold: 1 } } };
      await settings.save();
    }

    // Clean up previous test state
    await Log.deleteMany({ organization: org._id });
    await Alert.deleteMany({ organization: org._id });
    await Incident.deleteMany({ organization: org._id });
    await SecurityTest.deleteMany({ organization: org._id });
    await ThreatRule.deleteMany({ organization: org._id });

    let asset = await Asset.findOne({ name: 'Test Server', organization: org._id });
    if (!asset) {
      asset = await Asset.create({
        organization: org._id,
        name: 'Test Server',
        type: 'server',
        ipAddress: '10.0.0.10',
        criticality: 'high',
        status: 'active'
      });
    }

    let logSourceSuricata = await LogSource.findOne({ sourceName: 'Test Suricata Sensor', organization: org._id });
    if (!logSourceSuricata) {
      logSourceSuricata = await LogSource.create({
        organization: org._id,
        asset: asset._id,
        sourceName: 'Test Suricata Sensor',
        sourceType: 'Suricata',
        ipAddress: '10.0.0.10',
        status: 'Online',
        authenticationToken: 'test-token-123',
        retentionDays: 30
      });
    }
    
    // Add ThreatRules
    let rulePortScan = await ThreatRule.findOne({ name: 'Port Scan Detection' });
    if (!rulePortScan) {
      rulePortScan = await ThreatRule.create({
        name: 'Port Scan Detection',
        description: 'Detects port scans',
        organization: org._id,
        type: 'signature',
        category: 'network',
        threatType: 'port_scan',
        severity: 'high',
        enabled: true,
        condition: { eventType: { $regex: 'Port Scan' } },
        action: { createAlert: true, createIncident: true, severity: 'high' }
      });
    }
    
    let ruleBruteForce = await ThreatRule.findOne({ name: 'Brute Force Detection', organization: org._id });
    if (!ruleBruteForce) {
      ruleBruteForce = await ThreatRule.create({
        name: 'Brute Force Detection',
        description: 'Detects brute force attacks',
        organization: org._id,
        type: 'signature',
        category: 'authentication',
        threatType: 'brute_force',
        severity: 'high',
        enabled: true,
        condition: { eventType: { $regex: 'brute|failed' } },
        action: { createAlert: true, createIncident: true, severity: 'high' }
      });
    }

    let ruleSuspicious = await ThreatRule.findOne({ name: 'Suspicious Connection Detection', organization: org._id });
    if (!ruleSuspicious) {
      ruleSuspicious = await ThreatRule.create({
        name: 'Suspicious Connection Detection',
        description: 'Detects suspicious outbound connections',
        organization: org._id,
        type: 'signature',
        category: 'network',
        threatType: 'malware_communication',
        severity: 'medium',
        enabled: true,
        condition: { eventType: { $regex: 'suspicious' } },
        action: { createAlert: true, createIncident: true, severity: 'medium' }
      });
    }

    // Run Scenarios
    await runScenario('Port Scan Detection', 'port_scan', logSourceSuricata, org, rulePortScan, {
      eventTime: new Date(),
      eventType: 'Port Scan Alert',
      message: 'Detected NMAP Port Scan',
      sourceIP: '192.168.1.100',
      destinationIP: '10.0.0.5',
      destinationPort: 80,
      protocol: 'TCP',
      alert: { signature: 'Port Scan', severity: 2 }
    });

    await runScenario('Brute Force Detection', 'brute_force', logSourceSuricata, org, ruleBruteForce, {
      eventTime: new Date(),
      eventType: 'failed login',
      message: 'Failed SSH Login',
      sourceIP: '192.168.1.100',
      destinationIP: '10.0.0.5',
      destinationPort: 22,
      protocol: 'TCP'
    });

    await runScenario('Suspicious Connection', 'suspicious_traffic', logSourceSuricata, org, ruleSuspicious, {
      eventTime: new Date(),
      eventType: 'suspicious connection',
      message: 'Suspicious outbound connection',
      sourceIP: '10.0.0.5',
      destinationIP: '1.2.3.4',
      destinationPort: 4444,
      protocol: 'TCP'
    });

  } catch (err) {
    console.error('Test Setup Failed:', err);
  } finally {
    mongoose.connection.close();
    console.log('========================================');
    console.log('FINAL RESULT: DONE');
    console.log('========================================');
  }
};

async function runScenario(scenarioName, testType, logSource, org, rule, rawPayload) {
  console.log(`\n[${scenarioName}]`);
  
  let result = {
    logGenerated: false,
    logIngested: false,
    detectionTriggered: false,
    alertCreated: false,
    incidentCreated: false,
    evidenceRecorded: false
  };

  const test = await SecurityTest.create({
    organization: org._id,
    name: scenarioName,
    description: `Automated test for ${scenarioName}`,
    testType: testType,
    status: 'PENDING',
    expectedDetection: rule._id,
    payload: rawPayload
  });

  try {
    rawPayload.isTestEvent = true;
    rawPayload.securityTestId = test._id;
    
    result.logGenerated = true;
    
    // Simulate ingestLog internals (bypassing token validation)
    const normalizedLog = logService.normalizeLog(rawPayload, logSource);
    normalizedLog.isTestEvent = true;
    normalizedLog.securityTestId = test._id;
    
    const log = new Log(normalizedLog);
    await log.save();
    
    result.logIngested = true;

    // Run Detection Engine
    const autoResult = await automationService.processLog(log);
    if (autoResult && autoResult.matchedRules.length > 0) {
      result.detectionTriggered = true;
      if (autoResult.alerts.length > 0) {
        result.alertCreated = true;
        // Verify Alert
        const alert = autoResult.alerts[0];
        if (autoResult.incidents && autoResult.incidents.length > 0) {
          result.incidentCreated = true;
          const incident = autoResult.incidents[0];
          // Check that evidence log exists
          const logExists = await Log.findById(log._id);
          if (logExists && logExists.isTestEvent && logExists.securityTestId.toString() === test._id.toString()) {
            result.evidenceRecorded = true;
          }
        }
      }
    }

  } catch (err) {
    console.error(`  Error during scenario: ${err.message}`);
  }

  // Determine PASS/FAIL
  const allPassed = Object.values(result).every(val => val === true);
  
  test.status = allPassed ? 'PASS' : 'FAIL';
  test.actualResult = JSON.stringify(result);
  await test.save();

  console.log(`    Log Generated:       ${result.logGenerated ? 'PASS' : 'FAIL'}`);
  console.log(`    Log Ingested:        ${result.logIngested ? 'PASS' : 'FAIL'}`);
  console.log(`    Detection Triggered: ${result.detectionTriggered ? 'PASS' : 'FAIL'}`);
  console.log(`    Alert Created:       ${result.alertCreated ? 'PASS' : 'FAIL'}`);
  console.log(`    Incident Created:    ${result.incidentCreated ? 'PASS' : 'FAIL'}`);
  console.log(`    Evidence Recorded:   ${result.evidenceRecorded ? 'PASS' : 'FAIL'}`);
  console.log(`    RESULT: ${allPassed ? 'PASS' : 'FAIL'}`);
}

runTests();
