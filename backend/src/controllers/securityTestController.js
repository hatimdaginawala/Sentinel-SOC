const SecurityTest = require('../models/SecurityTest');
const Log = require('../models/Log');
const { AppError } = require('../middleware/errorHandler');

exports.getTests = async (req, res, next) => {
  try {
    const tests = await SecurityTest.find({ organization: req.user.organization })
      .populate('expectedDetection')
      .populate('relatedAlert')
      .populate('relatedIncident');
    res.status(200).json({ status: 'success', results: tests.length, data: tests });
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
    res.status(201).json({ status: 'success', data: newTest });
  } catch (error) {
    next(error);
  }
};

exports.getTest = async (req, res, next) => {
  try {
    const test = await SecurityTest.findOne({ _id: req.params.id, organization: req.user.organization })
      .populate('expectedDetection')
      .populate('relatedAlert')
      .populate('relatedIncident');
    if (!test) return next(new AppError('Test not found', 404));
    res.status(200).json({ status: 'success', data: test });
  } catch (error) {
    next(error);
  }
};

exports.runTest = async (req, res, next) => {
  try {
    const test = await SecurityTest.findOne({ _id: req.params.id, organization: req.user.organization });
    if (!test) return next(new AppError('Test not found', 404));
    
    test.status = 'RUNNING';
    await test.save();

    // Inject the payload into the Log collection to trigger detection
    const payload = test.payload || {};
    const logData = {
      organization: req.user.organization,
      asset: payload.assetId || null,
      logSource: payload.logSourceId || null,
      sourceType: payload.sourceType || 'custom',
      eventCategory: payload.eventCategory || 'network',
      eventType: payload.eventType || 'test_event',
      severity: payload.severity || 'info',
      message: payload.message || 'Security Test Event',
      rawLog: payload,
      isTestEvent: true,
      securityTestId: test._id,
      eventTime: new Date()
    };
    
    // Attempt parsing if it's suricata or zeek
    let logObj = logData;
    if (logData.sourceType === 'suricata') {
      const SuricataParser = require('../utils/SuricataParser');
      const parsed = SuricataParser.parse(payload, logData.organization, logData.asset, logData.logSource);
      if (parsed) logObj = { ...parsed, isTestEvent: true, securityTestId: test._id };
    } else if (logData.sourceType === 'zeek') {
      const ZeekParser = require('../utils/ZeekParser');
      const parsed = ZeekParser.parse(payload, payload.event_type || 'unknown', logData.organization, logData.asset, logData.logSource);
      if (parsed) logObj = { ...parsed, isTestEvent: true, securityTestId: test._id };
    }

    const log = new Log(logObj);
    await log.save();
    
    // In a real system, the detection engine would run asynchronously.
    // We update the status here to simulate the run.
    test.actualResult = 'Log injected, waiting for detection engine...';
    test.status = 'PENDING';
    await test.save();

    res.status(200).json({ status: 'success', message: 'Test running', data: test });
  } catch (error) {
    next(error);
  }
};

exports.deleteTest = async (req, res, next) => {
  try {
    const test = await SecurityTest.findOneAndDelete({ _id: req.params.id, organization: req.user.organization });
    if (!test) return next(new AppError('Test not found', 404));
    res.status(204).json({ status: 'success', data: null });
  } catch (error) {
    next(error);
  }
};
