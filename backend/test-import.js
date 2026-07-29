console.log('Testing imports...');

try {
  console.log('Loading dotenv...');
  require('dotenv').config();
  console.log('✅ dotenv loaded');
  
  console.log('Loading express...');
  const express = require('express');
  console.log('✅ express loaded');
  
  console.log('Loading config/logger...');
  const logger = require('./src/config/logger');
  console.log('✅ logger loaded');
  
  console.log('Loading config/database...');
  const database = require('./src/config/database');
  console.log('✅ database loaded');
  
  console.log('Loading middleware/rateLimiter...');
  const { generalLimiter, authLimiter } = require('./src/middleware/rateLimiter');
  console.log('✅ rateLimiter loaded');
  
  console.log('Loading middleware/errorHandler...');
  const { errorHandler, notFoundHandler } = require('./src/middleware/errorHandler');
  console.log('✅ errorHandler loaded');
  
  console.log('Loading middleware/auth...');
  const { protect, authorize } = require('./src/middleware/auth');
  console.log('✅ auth loaded');
  
  console.log('Loading middleware/validation...');
  const { validateRequest, sanitizeRequest } = require('./src/middleware/validation');
  console.log('✅ validation loaded');
  
  console.log('Loading models/User...');
  const User = require('./src/models/User');
  console.log('✅ User model loaded');
  
  console.log('Loading models/Role...');
  const Role = require('./src/models/Role');
  console.log('✅ Role model loaded');
  
  console.log('Loading models/Organization...');
  const Organization = require('./src/models/Organization');
  console.log('✅ Organization model loaded');
  
  console.log('Loading services/userService...');
  const userService = require('./src/services/userService');
  console.log('✅ userService loaded');
  
  console.log('Loading services/roleService...');
  const roleService = require('./src/services/roleService');
  console.log('✅ roleService loaded');
  
  console.log('Loading services/organizationService...');
  const organizationService = require('./src/services/organizationService');
  console.log('✅ organizationService loaded');
  
  console.log('Loading controllers/userController...');
  const userController = require('./src/controllers/userController');
  console.log('✅ userController loaded');
  
  console.log('Loading controllers/roleController...');
  const roleController = require('./src/controllers/roleController');
  console.log('✅ roleController loaded');
  
  console.log('Loading controllers/organizationController...');
  const organizationController = require('./src/controllers/organizationController');
  console.log('✅ organizationController loaded');
  
  console.log('Loading routes/userRoutes...');
  const userRoutes = require('./src/routes/userRoutes');
  console.log('✅ userRoutes loaded');
  
  console.log('Loading routes/roleRoutes...');
  const roleRoutes = require('./src/routes/roleRoutes');
  console.log('✅ roleRoutes loaded');
  
  console.log('Loading routes/organizationRoutes...');
  const organizationRoutes = require('./src/routes/organizationRoutes');
  console.log('✅ organizationRoutes loaded');
  
  console.log('✅ All imports successful!');
  console.log('🎉 Everything is working correctly!');
} catch (error) {
  console.error(`❌ Error loading module: ${error.message}`);
  console.error(`📁 File: ${error.stack.split('\n')[1]}`);
  console.error(error.stack);
}