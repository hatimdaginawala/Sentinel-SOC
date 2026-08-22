// services/simulatorService.js

const SimulatorConfig = require('../models/SimulatorConfig');
const SimulatorEvent = require('../models/SimulatorEvent');
const LogSource = require('../models/LogSource');
const { AppError } = require('../middleware/errorHandler');

// Active simulator instances
const activeSimulators = new Map();

class SimulatorService {
  /**
   * Initialize simulators for an organization
   */
  async initializeSimulators(organizationId, userId) {
    // Check if simulators already exist
    const existing = await SimulatorConfig.find({ organization: organizationId });
    if (existing.length > 0) {
      return existing;
    }

    // Get log sources for this organization
    const sources = await LogSource.find({ organization: organizationId });

    const simulatorTypes = ['windows', 'linux', 'apache', 'nginx', 'suricata', 'snort', 'firewall'];
    const created = [];

    for (const type of simulatorTypes) {
      // Find matching log source
      const source = sources.find(s => 
        s.sourceType.toLowerCase() === type || 
        (type === 'firewall' && s.sourceType === 'pfSense')
      );
      
      if (source) {
        const config = new SimulatorConfig({
          organization: organizationId,
          name: `${type.charAt(0).toUpperCase() + type.slice(1)} Simulator`,
          type: type,
          sourceId: source._id,
          authToken: source.authenticationToken,
          configuration: {
            interval: 2000,
            batchSize: 1,
            enabled: true
          },
          stats: {
            eventsGenerated: 0,
            eventsSent: 0,
            eventsFailed: 0
          },
          createdBy: userId,
          updatedBy: userId
        });
        await config.save();
        created.push(config);
      }
    }

    return created;
  }

  /**
   * Start a simulator
   */
  async startSimulator(configId, userId) {
    const config = await SimulatorConfig.findById(configId);
    if (!config) {
      throw new AppError('Simulator configuration not found', 404);
    }

    if (config.status === 'running') {
      throw new AppError('Simulator is already running', 409);
    }

    // Update status
    config.status = 'running';
    config.stats.startTime = new Date();
    config.updatedBy = userId;
    await config.save();

    // Start the simulator in background
    this.runSimulator(config);

    return config;
  }

  /**
   * Start all simulators for an organization
   */
  async startAllSimulators(organizationId, userId) {
    const configs = await SimulatorConfig.find({ 
      organization: organizationId,
      status: { $ne: 'running' }
    });

    const started = [];
    for (const config of configs) {
      try {
        const result = await this.startSimulator(config._id, userId);
        started.push(result);
      } catch (error) {
        console.error(`Failed to start simulator ${config.name}:`, error.message);
      }
    }

    return started;
  }

  /**
   * Stop a simulator
   */
  async stopSimulator(configId, userId) {
    const config = await SimulatorConfig.findById(configId);
    if (!config) {
      throw new AppError('Simulator configuration not found', 404);
    }

    // Stop the running instance
    const active = activeSimulators.get(configId.toString());
    if (active) {
      clearTimeout(active.timeout);
      clearInterval(active.interval);
      activeSimulators.delete(configId.toString());
    }

    // Update status
    config.status = 'stopped';
    config.stats.stopTime = new Date();
    config.updatedBy = userId;
    await config.save();

    return config;
  }

  /**
   * Stop all simulators for an organization
   */
  async stopAllSimulators(organizationId, userId) {
    const configs = await SimulatorConfig.find({ 
      organization: organizationId,
      status: 'running'
    });

    const stopped = [];
    for (const config of configs) {
      try {
        const result = await this.stopSimulator(config._id, userId);
        stopped.push(result);
      } catch (error) {
        console.error(`Failed to stop simulator ${config.name}:`, error.message);
      }
    }

    return stopped;
  }

  /**
   * Get simulator status
   */
  async getSimulatorStatus(organizationId) {
    const configs = await SimulatorConfig.find({ organization: organizationId })
      .populate('sourceId', 'sourceName sourceType');

    return configs.map(config => ({
      id: config._id,
      name: config.name,
      type: config.type,
      status: config.status,
      stats: config.stats,
      configuration: config.configuration,
      source: {
        id: config.sourceId?._id,
        name: config.sourceId?.sourceName,
        type: config.sourceId?.sourceType
      },
      lastUpdated: config.updatedAt
    }));
  }

  /**
   * Get simulator statistics
   */
  async getSimulatorStats(organizationId) {
    const configs = await SimulatorConfig.find({ organization: organizationId });

    const totalEvents = configs.reduce((sum, c) => sum + (c.stats?.eventsGenerated || 0), 0);
    const totalSent = configs.reduce((sum, c) => sum + (c.stats?.eventsSent || 0), 0);
    const totalFailed = configs.reduce((sum, c) => sum + (c.stats?.eventsFailed || 0), 0);
    const running = configs.filter(c => c.status === 'running').length;
    const total = configs.length;

    // Recent events (last 100)
    const recentEvents = await SimulatorEvent.find({ organization: organizationId })
      .sort({ createdAt: -1 })
      .limit(100)
      .populate('simulator', 'name type');

    return {
      summary: {
        totalSimulators: total,
        running: running,
        stopped: total - running,
        totalEvents,
        totalSent,
        totalFailed,
        successRate: totalEvents > 0 ? Math.round((totalSent / totalEvents) * 100) : 0
      },
      recentEvents: recentEvents,
      simulators: configs
    };
  }

  /**
   * Generate event based on simulator type - THIS IS THE KEY FIX
   */
  generateEvent(type) {
    const events = {
      windows: {
        eventType: 'Windows Security Event',
        eventCategory: 'system',
        severity: 'info',
        message: 'Windows event from simulator',
        sourceIP: this.generateRandomIP(),
        hostname: `WIN-SRV-${Math.floor(Math.random() * 10) + 1}`,
        username: ['Administrator', 'jsmith', 'bjohnson', 'system'][Math.floor(Math.random() * 4)],
        rawLog: {
          eventId: [4624, 4625, 4720, 4726, 4740][Math.floor(Math.random() * 5)],
          logonType: Math.floor(Math.random() * 10) + 2
        }
      },
      linux: {
        eventType: 'Linux System Event',
        eventCategory: 'system',
        severity: 'info',
        message: 'Linux event from simulator',
        sourceIP: this.generateRandomIP(),
        hostname: `LINUX-SRV-${Math.floor(Math.random() * 10) + 1}`,
        username: ['root', 'ubuntu', 'debian', 'admin'][Math.floor(Math.random() * 4)],
        rawLog: {
          pid: Math.floor(Math.random() * 9000) + 1000,
          tty: 'pts/0',
          command: ['ls', 'cd', 'ps', 'top', 'systemctl'][Math.floor(Math.random() * 5)]
        }
      },
      apache: {
        eventType: 'Apache HTTP Event',
        eventCategory: 'web',
        severity: 'info',
        message: 'Apache web server event from simulator',
        sourceIP: this.generateRandomIP(),
        destinationIP: this.generateRandomIP(),
        rawLog: {
          method: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'][Math.floor(Math.random() * 5)],
          uri: ['/index.html', '/api/users', '/login.php', '/dashboard', '/products'][Math.floor(Math.random() * 5)],
          status: [200, 201, 301, 302, 400, 403, 404, 500][Math.floor(Math.random() * 8)]
        }
      },
      nginx: {
        eventType: 'Nginx Proxy Event',
        eventCategory: 'web',
        severity: 'info',
        message: 'Nginx web server event from simulator',
        sourceIP: this.generateRandomIP(),
        destinationIP: this.generateRandomIP(),
        rawLog: {
          method: ['GET', 'POST', 'PUT', 'DELETE', 'HEAD'][Math.floor(Math.random() * 5)],
          uri: ['/', '/api/v1', '/static/css', '/js/app.js', '/images/logo.png'][Math.floor(Math.random() * 5)],
          status: [200, 301, 302, 400, 404, 502, 503][Math.floor(Math.random() * 7)],
          upstream: `backend-${Math.floor(Math.random() * 3) + 1}:8080`
        }
      },
      suricata: {
        eventType: 'Suricata IDS Alert',
        eventCategory: 'ids',
        severity: 'high',
        message: 'Suricata IDS alert from simulator',
        sourceIP: this.generateRandomIP(),
        destinationIP: this.generateRandomIP(),
        rawLog: {
          signature: ['SQL Injection Attempt', 'Port Scan', 'Malware Communication', 'DDoS Pattern', 'Command Injection'][Math.floor(Math.random() * 5)],
          severity: [1, 2, 3][Math.floor(Math.random() * 3)],
          sid: Math.floor(Math.random() * 9000000) + 1000000
        }
      },
      snort: {
        eventType: 'Snort IDS Alert',
        eventCategory: 'ids',
        severity: 'high',
        message: 'Snort IDS alert from simulator',
        sourceIP: this.generateRandomIP(),
        destinationIP: this.generateRandomIP(),
        rawLog: {
          sid: Math.floor(Math.random() * 9000000) + 1000000,
          msg: ['Port Scan Detected', 'Suspicious Traffic', 'Malware Communication', 'SQL Injection'][Math.floor(Math.random() * 4)],
          priority: Math.floor(Math.random() * 4) + 1
        }
      },
      firewall: {
        eventType: 'Firewall Event',
        eventCategory: 'network',
        severity: 'medium',
        message: 'Firewall event from simulator',
        sourceIP: this.generateRandomIP(),
        destinationIP: this.generateRandomIP(),
        destinationPort: [22, 80, 443, 3306, 5432, 27017][Math.floor(Math.random() * 6)],
        rawLog: {
          action: ['block', 'allow', 'reject', 'drop'][Math.floor(Math.random() * 4)],
          interface: ['WAN', 'LAN', 'DMZ', 'VPN'][Math.floor(Math.random() * 4)],
          rule: `rule_${Math.floor(Math.random() * 100) + 1}`
        }
      }
    };

    return events[type] || events.linux;
  }

  /**
   * Generate random IP address
   */
  generateRandomIP() {
    return `${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`;
  }

  /**
   * Send event to ingestion API
   */
  async sendEvent(config, eventData) {
    try {
      // Build the API URL correctly - FIXED: no double /api/v1
      const apiUrl = process.env.API_URL || 'http://localhost:3000';
      const ingestEndpoint = `${apiUrl}/api/v1/logs/ingest`;
      
      const payload = {
        sourceId: config.sourceId.toString(),
        authToken: config.authToken,
        log: {
          ...eventData,
          eventTime: new Date().toISOString(),
          isTestEvent: true,
          securityTestId: null
        }
      };

      console.log(`📤 Sending ${config.type} event to ${ingestEndpoint}`);

      const response = await fetch(ingestEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.message || `API responded with status ${response.status}`);
      }

      // Record the event
      await SimulatorEvent.create({
        simulator: config._id,
        organization: config.organization,
        eventType: eventData.eventType || 'unknown',
        severity: eventData.severity || 'info',
        payload: eventData,
        status: 'sent',
        response: {
          statusCode: response.status,
          message: result.message || 'Success',
          timestamp: new Date()
        },
        sentAt: new Date()
      });

      console.log(`✅ Sent ${config.type} event successfully`);
      return true;
    } catch (error) {
      console.error(`❌ Failed to send ${config.type} event:`, error.message);

      // Record failed event
      await SimulatorEvent.create({
        simulator: config._id,
        organization: config.organization,
        eventType: eventData?.eventType || 'unknown',
        severity: eventData?.severity || 'info',
        payload: eventData || {},
        status: 'failed',
        response: {
          statusCode: 500,
          message: error.message,
          timestamp: new Date()
        }
      });

      return false;
    }
  }

  /**
   * Run a simulator instance (background)
   */
  async runSimulator(config) {
    const configId = config._id.toString();
    
    // Update status to running
    config.status = 'running';
    config.stats.startTime = new Date();
    await config.save();

    const interval = config.configuration?.interval || 2000;

    // Run the simulator loop
    const runLoop = async () => {
      try {
        // Generate event based on simulator type
        const eventData = this.generateEvent(config.type);
        
        if (eventData) {
          // Send the event to ingestion API
          const sent = await this.sendEvent(config, eventData);
          
          // Update stats
          config.stats.eventsGenerated = (config.stats.eventsGenerated || 0) + 1;
          if (sent) {
            config.stats.eventsSent = (config.stats.eventsSent || 0) + 1;
          } else {
            config.stats.eventsFailed = (config.stats.eventsFailed || 0) + 1;
          }
          config.stats.lastEventTime = new Date();
          await config.save();
        }

        // Check if still running
        if (config.status === 'running') {
          // Schedule next event
          const timeout = setTimeout(runLoop, interval);
          activeSimulators.set(configId, { timeout, interval: runLoop, configId });
        }
      } catch (error) {
        console.error(`Error in simulator ${config.type}:`, error.message);
        // Continue running if error
        if (config.status === 'running') {
          const timeout = setTimeout(runLoop, interval * 2);
          activeSimulators.set(configId, { timeout, interval: runLoop, configId });
        }
      }
    };

    // Start the loop
    console.log(`🚀 Starting ${config.type} simulator...`);
    const timeout = setTimeout(runLoop, 1000);
    activeSimulators.set(configId, { timeout, interval: runLoop, configId });
  }
}

module.exports = new SimulatorService();