// middleware/automation.js
const AutomationService = require('../services/automationService');
const { asyncHandler } = require('./errorHandler');

/**
 * Middleware to process logs through automation pipeline
 */
const processLogAutomatically = asyncHandler(async (req, res, next) => {
  // Store the original send method
  const originalSend = res.send;
  
  res.send = function(data) {
    // Check if this was a successful log ingestion
    if (res.statusCode === 201) {
      try {
        const parsedData = typeof data === 'string' ? JSON.parse(data) : data;
        const log = parsedData?.data;
        
        if (log && log._id) {
          // Process the log through automation pipeline
          AutomationService.processLog(log)
            .then(result => {
              console.log('✅ Automation pipeline completed:', {
                alerts: result?.alerts?.length || 0,
                incidents: result?.incidents?.length || 0,
                iocs: result?.matchedIOCs?.length || 0
              });
            })
            .catch(error => {
              console.error('❌ Automation pipeline error:', error);
            });
        }
      } catch (error) {
        console.error('❌ Failed to parse response for automation:', error);
      }
    }
    
    return originalSend.call(this, data);
  };
  
  next();
});

module.exports = { processLogAutomatically };