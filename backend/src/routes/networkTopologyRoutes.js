const express = require('express');
const router = express.Router();
const topologyController = require('../controllers/networkTopologyController');
const { protect } = require('../middleware/auth');

// All routes require authentication
router.use(protect);

// Main topology routes
router.route('/')
  .get(topologyController.getTopology)
  .post(topologyController.updateTopology)
  .put(topologyController.updateTopology)
  .delete(topologyController.deleteTopology);

// Statistics endpoint
router.get('/stats', topologyController.getTopologyStats);

// Bulk import
router.post('/import', topologyController.bulkImport);

// Node management
router.post('/nodes', topologyController.addNode);
router.delete('/nodes/:nodeId', topologyController.removeNode);

module.exports = router;