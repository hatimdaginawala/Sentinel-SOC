const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const dotenv = require('dotenv');
const http = require('http');
const socketIO = require('socket.io');

// Load environment variables
dotenv.config();

// Import configurations
const logger = require('./config/logger');
const database = require('./config/database');

// Import middleware
const { generalLimiter, authLimiter } = require('./middleware/rateLimiter');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');

// Import routes
const userRoutes = require('./routes/userRoutes');
const roleRoutes = require('./routes/roleRoutes');
const organizationRoutes = require('./routes/organizationRoutes');
const assetRoutes = require('./routes/assetRoutes');
const logSourceRoutes = require('./routes/logSourceRoutes');
const logRoutes = require('./routes/logRoutes');
const alertRoutes = require('./routes/alertRoutes');
const incidentRoutes = require('./routes/incidentRoutes');
const iocRoutes = require('./routes/iocRoutes');
const threatRuleRoutes = require('./routes/threatRuleRoutes');
const reportRoutes = require('./routes/reportRoutes');
const auditLogRoutes = require('./routes/auditLogRoutes');
const settingsRoutes = require('./routes/settingsRoutes');
const networkTopologyRoutes = require('./routes/networkTopologyRoutes');
const securitySensorRoutes = require('./routes/securitySensorRoutes');
const securityControlRoutes = require('./routes/securityControlRoutes');
const securityTestRoutes = require('./routes/securityTestRoutes');
const securityAssessmentRoutes = require('./routes/securityAssessmentRoutes');

// Import audit middleware
const audit = require('./middleware/audit');

console.log(' Starting SentinelSOC server...');

// Initialize express app
const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
  }
});

// Socket.io connection handling
io.on('connection', (socket) => {
  logger.info(`New client connected: ${socket.id}`);

  socket.on('disconnect', () => {
    logger.info(`Client disconnected: ${socket.id}`);
  });

  socket.on('error', (error) => {
    logger.error(`Socket error: ${error.message}`);
  });
});

// Make io accessible to routes
app.set('io', io);

// Security middleware
// Security middleware - UPDATED CSP for vis-network
// Security middleware - UPDATED CSP for vis-network and other resources
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: [
        "'self'", 
        "'unsafe-inline'", 
        'https://cdnjs.cloudflare.com', 
        'https://cdn.jsdelivr.net', 
        'https://cdn.datatables.net', 
        'https://fonts.googleapis.com',
        'https://unpkg.com'
      ],
      scriptSrc: [
        "'self'", 
        "'unsafe-inline'", 
        'https://cdnjs.cloudflare.com', 
        'https://cdn.jsdelivr.net', 
        'https://cdn.socket.io', 
        'https://cdn.datatables.net', 
        'https://code.jquery.com',
        'https://unpkg.com',
        'https://cdnjs.cloudflare.com/ajax/libs/vis-network',
        'https://visjs.github.io',
        'blob:',
        'data:'
      ],
      imgSrc: ["'self'", 'data:', 'https:', 'blob:'],
      connectSrc: ["'self'", 'ws:', 'wss:', 'http:', 'https:'],
      fontSrc: ["'self'", 'https://cdnjs.cloudflare.com', 'https://fonts.gstatic.com', 'data:', 'https://unpkg.com'],
      scriptSrcAttr: ["'unsafe-inline'"],
    },
  },
}));
// Add this after the static files middleware
// Favicon route to prevent 404 errors
app.get('/favicon.ico', (req, res) => {
  // Try to serve from frontend assets, or return 204 No Content
  const faviconPath = path.join(frontendPath, 'assets/images/favicon.ico');
  res.sendFile(faviconPath, { 
    root: '.',
    dotfiles: 'deny',
    headers: {
      'Cache-Control': 'public, max-age=86400'
    }
  }, (err) => {
    if (err) {
      // If favicon doesn't exist, return 204 No Content (silent success)
      res.status(204).end();
    }
  });
});
// CORS configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
  optionsSuccessStatus: 200
}));

// Body parser middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware
app.use(morgan('combined', { 
  stream: { 
    write: (message) => logger.info(message.trim()) 
  } 
}));

// Rate limiting
app.use('/api', generalLimiter);
app.use('/api/v1/auth', authLimiter);

// Static files
const frontendPath = path.join(__dirname, '../../frontend');
app.use('/assets', express.static(path.join(frontendPath, 'assets')));
app.use('/pages', express.static(path.join(frontendPath, 'pages')));

// Health check endpoint
app.get('/health', (req, res) => {
  const dbStatus = database.getConnectionStatus();
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: dbStatus,
    environment: process.env.NODE_ENV
  });
});

// API routes
const API_PREFIX = process.env.API_PREFIX || '/api/v1';

// ============================================
// MOUNT AUTH ROUTES FIRST (NO AUDIT)
// ============================================
console.log(' Mounting auth routes...');
app.use(`${API_PREFIX}/auth`, userRoutes);

// ============================================
// APPLY AUDIT MIDDLEWARE HERE
// All routes after this point will be audited
// ============================================
console.log(' Applying audit middleware...');
app.use(audit());
console.log(' Audit middleware applied');

// ============================================
// MOUNT ALL OTHER ROUTES (WILL BE AUDITED)
// ============================================
console.log(' Mounting protected routes...');

// User management routes
app.use(`${API_PREFIX}/users`, userRoutes);

// Role management routes
app.use(`${API_PREFIX}`, roleRoutes);

// Organization management routes
app.use(`${API_PREFIX}/organizations`, organizationRoutes);

// Asset management routes
app.use(`${API_PREFIX}/assets`, assetRoutes);

// Log management routes
app.use(`${API_PREFIX}`, logRoutes);

// Log Source management routes
app.use(`${API_PREFIX}`, logSourceRoutes);

// Alert management routes
app.use(`${API_PREFIX}`, alertRoutes);

// Incident management routes
app.use(`${API_PREFIX}`, incidentRoutes);

// IOC management routes
app.use(`${API_PREFIX}`, iocRoutes);

// Threat rule management routes
app.use(`${API_PREFIX}`, threatRuleRoutes);

// Report management routes
app.use(`${API_PREFIX}`, reportRoutes);

// Audit log routes
app.use(`${API_PREFIX}`, auditLogRoutes);

// Settings routes
app.use(`${API_PREFIX}`, settingsRoutes);

// Network Defense routes
app.use(`${API_PREFIX}/network-topology`, networkTopologyRoutes);
app.use(`${API_PREFIX}/security-sensors`, securitySensorRoutes);
app.use(`${API_PREFIX}/security-controls`, securityControlRoutes);
app.use(`${API_PREFIX}/security-tests`, securityTestRoutes);
app.use(`${API_PREFIX}/security-assessments`, securityAssessmentRoutes);

console.log(' All routes mounted');

// Root route
app.get('/', (req, res) => {
  if (req.headers.accept && req.headers.accept.includes('text/html')) {
    return res.redirect('/pages/login.html');
  }
  res.json({
    name: 'SentinelSOC',
    version: '1.0.0',
    status: 'operational',
    health: '/health',
    endpoints: {
      auth: `${API_PREFIX}/auth`,
      users: `${API_PREFIX}/users`,
      roles: `${API_PREFIX}/roles`,
      organizations: `${API_PREFIX}/organizations`,
      assets: `${API_PREFIX}/assets`,
      alerts: `${API_PREFIX}/alerts`,
      incidents: `${API_PREFIX}/incidents`,
      iocs: `${API_PREFIX}/iocs`,
      threatRules: `${API_PREFIX}/threat-rules`,
      reports: `${API_PREFIX}/reports`,
      auditLogs: `${API_PREFIX}/audit-logs`,
      logSources: `${API_PREFIX}/log-sources`,
      logs: `${API_PREFIX}/logs`,
      settings: `${API_PREFIX}/settings`
    }
  });
});

// 404 handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

// Database connection and server startup
const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    console.log(' Connecting to MongoDB...');
    await database.connect();
    console.log(' MongoDB connected');
    
    // Initialize system roles
    try {
      console.log(' Initializing system roles...');
      const RoleService = require('./services/roleService');
      await RoleService.initializeSystemRoles();
      console.log(' System roles initialized');
    } catch (roleError) {
      console.warn(' Role initialization failed:', roleError.message);
    }
    
    // Start server
    server.listen(PORT, () => {
      console.log(`\n SentinelSOC server running on port ${PORT}`);
      console.log(` Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(` API URL: http://localhost:${PORT}${API_PREFIX}`);
      console.log(` Health check: http://localhost:${PORT}/health`);
      
      console.log('\n Available API Endpoints:');
      console.log(`   POST ${API_PREFIX}/auth/login (NO AUDIT)`);
      console.log(`   POST ${API_PREFIX}/auth/refresh (NO AUDIT)`);
      console.log(`   GET  ${API_PREFIX}/organizations (AUDITED)`);
      console.log(`   GET  ${API_PREFIX}/assets (AUDITED)`);
      console.log(`   GET  ${API_PREFIX}/log-sources (AUDITED)`);
      console.log(`   POST ${API_PREFIX}/logs/ingest (NO AUDIT)`);
      console.log(`   GET  ${API_PREFIX}/alerts (AUDITED)`);
      console.log(`   GET  ${API_PREFIX}/incidents (AUDITED)`);
      console.log(`   GET  ${API_PREFIX}/threat-rules (AUDITED)`);
      console.log(`   GET  ${API_PREFIX}/reports (AUDITED)`);
      console.log(`   GET  ${API_PREFIX}/audit-logs (AUDITED)`);
      console.log(`   GET  ${API_PREFIX}/logs (AUDITED)`);
      console.log(`   GET  ${API_PREFIX}/iocs (AUDITED)`);
      console.log(`   GET  ${API_PREFIX}/settings (AUDITED)`);
      console.log('\n Server is ready!');
    });

    // Graceful shutdown
    const shutdown = async () => {
      console.log(' Received shutdown signal');
      server.close(async () => {
        console.log(' HTTP server closed');
        await database.disconnect();
        console.log(' Shutdown complete');
        process.exit(0);
      });
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);

  } catch (error) {
    console.error(' Failed to start server:', error);
    console.error(error.stack);
    process.exit(1);
  }
}

// Handle unhandled rejections
process.on('unhandledRejection', (error) => {
  console.error(' Unhandled Rejection:', error);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error(' Uncaught Exception:', error);
  process.exit(1);
});

// Start the server
if (require.main === module) {
  console.log(' Starting server...');
  startServer();
}

module.exports = { app, server, io };