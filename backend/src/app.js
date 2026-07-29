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
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com', 'https://cdn.jsdelivr.net'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'https://cdnjs.cloudflare.com', 'data:'],
    },
  },
}));

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
// MOUNT ALL ROUTES
// ============================================
console.log('🔧 Mounting routes...');

// Auth routes (handled by userRoutes for login/register)
app.use(`${API_PREFIX}/auth`, userRoutes);

// User management routes
app.use(`${API_PREFIX}/users`, userRoutes);

// Role management routes
app.use(`${API_PREFIX}/roles`, roleRoutes);

// Organization management routes
app.use(`${API_PREFIX}/organizations`, organizationRoutes);

// Asset management routes
app.use(`${API_PREFIX}/assets`, assetRoutes);

// Alert management routes
app.use(`${API_PREFIX}/alerts`, alertRoutes);
  
// Incident management routes
app.use(`${API_PREFIX}/incidents`, incidentRoutes);
// IOC management routes
app.use(`${API_PREFIX}/iocs`, iocRoutes);
// Logging routes
app.use(`${API_PREFIX}`, logRoutes);
app.use(`${API_PREFIX}`, logSourceRoutes);

console.log('✅ All routes mounted');

// Root route
app.get('/', (req, res) => {
  res.json({
    name: 'SentinelSOC',
    version: '1.0.0',
    status: 'operational',
    documentation: `${API_PREFIX}/docs`,
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
      logSources: `${API_PREFIX}/log-sources`,
      logs: `${API_PREFIX}/logs`
    }
  });
});

// 404 handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

// Database connection and server startup
const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    // Connect to MongoDB
    await database.connect();
    
    // Initialize system roles
    try {
      const RoleService = require('./services/roleService');
      await RoleService.initializeSystemRoles();
    } catch (roleError) {
      logger.warn('⚠️ Role initialization failed, but continuing server startup:', roleError.message);
    }
    
    // Start server
    server.listen(PORT, () => {
      logger.info(`🚀 SentinelSOC server running on port ${PORT}`);
      logger.info(`📡 Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`🔗 API URL: http://localhost:${PORT}${API_PREFIX}`);
      logger.info(`💚 Health check: http://localhost:${PORT}/health`);
      
      // Log available endpoints
      console.log('\n📋 Available API Endpoints:');
      console.log(`   POST ${API_PREFIX}/auth/login`);
      console.log(`   GET  ${API_PREFIX}/organizations`);
      console.log(`   GET  ${API_PREFIX}/assets`);
      console.log(`   GET  ${API_PREFIX}/log-sources`);
      console.log(`   POST ${API_PREFIX}/logs/ingest`);
      console.log(`   GET  ${API_PREFIX}/logs`);
      console.log(`   GET  ${API_PREFIX}/iocs`);
    });

    // Graceful shutdown
    const shutdown = async () => {
      logger.info('🔄 Received shutdown signal');
      server.close(async () => {
        logger.info('📴 HTTP server closed');
        await database.disconnect();
        logger.info('👋 Shutdown complete');
        process.exit(0);
      });
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);

  } catch (error) {
    logger.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Handle unhandled rejections
process.on('unhandledRejection', (error) => {
  logger.error('Unhandled Rejection:', error);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

// Start the server
if (require.main === module) {
  startServer();
}

module.exports = { app, server, io };