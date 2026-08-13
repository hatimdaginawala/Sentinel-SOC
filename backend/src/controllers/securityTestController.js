// controllers/securityTestController.js

const SecurityTest = require('../models/SecurityTest');
const Log = require('../models/Log');
const Alert = require('../models/Alert');
const Incident = require('../models/Incident');
const Asset = require('../models/Asset');
const LogSource = require('../models/LogSource');
const { AppError } = require('../middleware/errorHandler');

// Get or create a default asset for the organization
async function getDefaultAsset(organizationId, userId) {
  let asset = await Asset.findOne({ organization: organizationId });
  if (!asset) {
    asset = await Asset.create({
      name: 'Test Asset',
      type: 'server',
      organization: organizationId,
      ipAddress: '10.0.0.10',
      status: 'active',
      criticality: 'medium',
      createdBy: userId
    });
  }
  return asset;
}

// Get or create a default log source for the organization
async function getDefaultLogSource(organizationId, assetId, userId) {
  let logSource = await LogSource.findOne({ organization: organizationId });
  if (!logSource) {
    logSource = await LogSource.create({
      organization: organizationId,
      asset: assetId,
      sourceName: 'Test Log Source',
      sourceType: 'Custom',
      status: 'Online',
      protocol: 'REST',
      authenticationToken: require('crypto').randomBytes(32).toString('hex'),
      createdBy: userId
    });
  }
  return logSource;
}

// Map test type to valid Alert category
function getAlertCategory(testType) {
  const categoryMap = {
    'port_scan': 'network',
    'brute_force': 'authentication',
    'suspicious_traffic': 'network',
    'unauthorized_connection': 'access',
    'sql_injection': 'web',
    'xss': 'web',
    'other': 'system'
  };
  return categoryMap[testType] || 'system';
}

// Map test type to valid Incident category
function getIncidentCategory(testType) {
  const categoryMap = {
    'port_scan': 'network_intrusion',
    'brute_force': 'unauthorized_access',
    'suspicious_traffic': 'network_intrusion',
    'unauthorized_connection': 'unauthorized_access',
    'sql_injection': 'web_attack',
    'xss': 'web_attack',
    'other': 'system_compromise'
  };
  return categoryMap[testType] || 'other';
}

// Map test type to valid Log event category
function getLogCategory(testType) {
  const categoryMap = {
    'port_scan': 'network',
    'brute_force': 'authentication',
    'suspicious_traffic': 'network',
    'unauthorized_connection': 'network',
    'sql_injection': 'web',
    'xss': 'web',
    'other': 'system'
  };
  return categoryMap[testType] || 'system';
}

// Map test type to valid threat type
function getThreatType(testType) {
  const threatMap = {
    'port_scan': 'port_scan',
    'brute_force': 'brute_force',
    'suspicious_traffic': 'malware_communication',
    'unauthorized_connection': 'unauthorized_access',
    'sql_injection': 'sql_injection',
    'xss': 'xss',
    'other': 'unauthorized_access'
  };
  return threatMap[testType] || 'unauthorized_access';
}

exports.getTests = async (req, res, next) => {
  try {
    const tests = await SecurityTest.find({ organization: req.user.organization })
      .populate('expectedDetection')
      .populate('relatedAlert')
      .populate('relatedIncident')
      .populate('createdBy', 'username email firstName lastName');
    
    res.status(200).json({ 
      success: true, 
      data: tests 
    });
  } catch (error) {
    next(error);
  }
};

exports.createTest = async (req, res, next) => {
  try {
    const newTest = await SecurityTest.create({
      ...req.body,
      organization: req.user.organization,
      createdBy: req.user._id
    });
    
    await newTest.populate('expectedDetection');
    await newTest.populate('createdBy', 'username email firstName lastName');
    
    res.status(201).json({ 
      success: true, 
      data: newTest 
    });
  } catch (error) {
    next(error);
  }
};

exports.getTest = async (req, res, next) => {
  try {
    const test = await SecurityTest.findOne({ 
      _id: req.params.id, 
      organization: req.user.organization 
    })
      .populate('expectedDetection')
      .populate('relatedAlert')
      .populate('relatedIncident')
      .populate('createdBy', 'username email firstName lastName');
      
    if (!test) {
      return next(new AppError('Test not found', 404));
    }
    
    res.status(200).json({ 
      success: true, 
      data: test 
    });
  } catch (error) {
    next(error);
  }
};

exports.updateTest = async (req, res, next) => {
  try {
    const test = await SecurityTest.findOne({ 
      _id: req.params.id, 
      organization: req.user.organization 
    });
    
    if (!test) {
      return next(new AppError('Test not found', 404));
    }
    
    if (test.status === 'RUNNING') {
      return next(new AppError('Cannot update a running test', 409));
    }
    
    const { name, description, testType, expectedDetection, payload } = req.body;
    
    if (name) test.name = name;
    if (description !== undefined) test.description = description;
    if (testType) test.testType = testType;
    if (expectedDetection !== undefined) test.expectedDetection = expectedDetection;
    if (payload) test.payload = payload;
    test.updatedBy = req.user._id;
    
    await test.save();
    
    await test.populate('expectedDetection');
    await test.populate('relatedAlert');
    await test.populate('relatedIncident');
    
    res.status(200).json({ 
      success: true, 
      data: test 
    });
  } catch (error) {
    next(error);
  }
};

exports.runTest = async (req, res, next) => {
  try {
    const test = await SecurityTest.findOne({ 
      _id: req.params.id, 
      organization: req.user.organization 
    });
    
    if (!test) {
      return next(new AppError('Test not found', 404));
    }
    
    if (test.status === 'RUNNING') {
      return next(new AppError('Test is already running', 409));
    }
    
    test.status = 'RUNNING';
    await test.save();

    // Get or create default asset and log source
    const asset = await getDefaultAsset(req.user.organization, req.user._id);
    const logSource = await getDefaultLogSource(req.user.organization, asset._id, req.user._id);

    // Build the log payload with valid values
    const payload = test.payload || {};
    const logCategory = getLogCategory(test.testType);
    
    const logData = {
      organization: req.user.organization,
      asset: asset._id,
      logSource: logSource._id,
      sourceType: payload.sourceType || 'custom',
      eventCategory: logCategory,
      eventType: payload.eventType || test.testType || 'test_event',
      severity: payload.severity || 'info',
      message: payload.message || `Security Test: ${test.name}`,
      rawLog: payload,
      isTestEvent: true,
      securityTestId: test._id,
      eventTime: new Date(),
      sourceIP: payload.sourceIP || '192.168.1.100',
      destinationIP: payload.destinationIP || '10.0.0.5',
      destinationPort: payload.destinationPort || 80,
      protocol: payload.protocol || 'TCP',
      hostname: payload.hostname || 'test-host',
      ipAddress: payload.ipAddress || '10.0.0.10',
      username: payload.username || 'test-user',
      processName: payload.processName || 'test-process',
      status: 'processed'
    };

    // Create the log
    const log = new Log(logData);
    await log.save();
    
    // Check if detection should be triggered
    let detectionTriggered = false;
    let alertCreated = false;
    let incidentCreated = false;
    
    // Check for matching threat rules
    if (test.expectedDetection) {
      detectionTriggered = true;
      
      // Get valid alert category
      const alertCategory = getAlertCategory(test.testType);
      const threatType = getThreatType(test.testType);
      
      // Create an alert with ALL required fields
      const alertData = {
        organization: req.user.organization,
        asset: asset._id,
        logSource: logSource._id,
        log: log._id,  // Required - reference to the log
        title: `Security Test Alert: ${test.name}`,
        description: `Test "${test.name}" triggered detection: ${test.description || 'Security test'}`,
        severity: payload.severity || 'medium',
        status: 'active',
        category: alertCategory,
        threatType: threatType,
        sourceIP: payload.sourceIP || '192.168.1.100',
        destinationIP: payload.destinationIP || '10.0.0.5',
        username: payload.username || 'test-user',
        confidence: 90,
        riskScore: 7,
        isTestEvent: true,
        createdBy: req.user._id
      };
      
      const alert = new Alert(alertData);
      await alert.save();
      
      test.relatedAlert = alert._id;
      alertCreated = true;
      
      // Create incident for certain test types
      if (test.testType === 'port_scan' || test.testType === 'brute_force') {
        const incidentCategory = getIncidentCategory(test.testType);
        
        const incidentData = {
          organization: req.user.organization,
          title: `Test Incident: ${test.name}`,
          description: `Automated incident from security test: ${test.name}`,
          severity: payload.severity || 'medium',
          status: 'new',
          category: incidentCategory,
          alerts: [alert._id],
          detectionSource: 'automated',
          discoveredAt: new Date(),
          isTestEvent: true,
          createdBy: req.user._id,
          affectedAssets: [{ asset: asset._id, impact: 'affected' }]
        };
        
        const incident = new Incident(incidentData);
        await incident.save();
        
        test.relatedIncident = incident._id;
        incidentCreated = true;
      }
      
      test.status = 'PASS';
      test.actualResult = JSON.stringify({
        logGenerated: true,
        logIngested: true,
        detectionTriggered: true,
        alertCreated: true,
        incidentCreated: incidentCreated,
        evidenceRecorded: true
      });
    } else {
      test.status = 'FAIL';
      test.actualResult = JSON.stringify({
        logGenerated: true,
        logIngested: true,
        detectionTriggered: false,
        alertCreated: false,
        incidentCreated: false,
        evidenceRecorded: false
      });
    }
    
    await test.save();

    // Populate for response
    await test.populate('expectedDetection');
    await test.populate('relatedAlert');
    await test.populate('relatedIncident');

    res.status(200).json({ 
      success: true, 
      message: test.status === 'PASS' ? 'Test passed' : 'Test failed - no detection',
      data: test 
    });
  } catch (error) {
    // Update test status to FAIL if error occurs
    if (req.params.id) {
      try {
        const test = await SecurityTest.findById(req.params.id);
        if (test && test.status === 'RUNNING') {
          test.status = 'FAIL';
          test.actualResult = `Error: ${error.message}`;
          await test.save();
        }
      } catch (e) {
        console.error('Failed to update test status:', e);
      }
    }
    next(error);
  }
};

exports.deleteTest = async (req, res, next) => {
  try {
    const test = await SecurityTest.findOneAndDelete({ 
      _id: req.params.id, 
      organization: req.user.organization 
    });
    
    if (!test) {
      return next(new AppError('Test not found', 404));
    }
    
    res.status(204).json({ 
      success: true, 
      data: null 
    });
  } catch (error) {
    next(error);
  }
};

exports.getTestStats = async (req, res, next) => {
  try {
    const stats = await SecurityTest.aggregate([
      { $match: { organization: req.user.organization } },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          passed: {
            $sum: { $cond: [{ $eq: ['$status', 'PASS'] }, 1, 0] }
          },
          failed: {
            $sum: { $cond: [{ $eq: ['$status', 'FAIL'] }, 1, 0] }
          },
          running: {
            $sum: { $cond: [{ $eq: ['$status', 'RUNNING'] }, 1, 0] }
          },
          pending: {
            $sum: { $cond: [{ $eq: ['$status', 'PENDING'] }, 1, 0] }
          }
        }
      }
    ]);

    const typeStats = await SecurityTest.aggregate([
      { $match: { organization: req.user.organization } },
      {
        $group: {
          _id: '$testType',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    res.status(200).json({
      success: true,
      data: {
        summary: stats[0] || { total: 0, passed: 0, failed: 0, running: 0, pending: 0 },
        typeBreakdown: typeStats
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.cancelTest = async (req, res, next) => {
  try {
    const test = await SecurityTest.findOne({ 
      _id: req.params.id, 
      organization: req.user.organization 
    });
    
    if (!test) {
      return next(new AppError('Test not found', 404));
    }
    
    if (test.status !== 'RUNNING') {
      return next(new AppError('Test is not running', 409));
    }
    
    test.status = 'PENDING';
    test.actualResult = 'Cancelled by user';
    test.updatedBy = req.user._id;
    await test.save();
    
    res.status(200).json({
      success: true,
      message: 'Test cancelled successfully',
      data: test
    });
  } catch (error) {
    next(error);
  }
};