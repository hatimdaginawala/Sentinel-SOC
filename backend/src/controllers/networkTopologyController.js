const mongoose = require('mongoose');
const NetworkTopology = require('../models/NetworkTopology');

/**
 * Get network topology for the current organization
 */
exports.getTopology = async (req, res, next) => {
  try {
    let topology = await NetworkTopology.findOne({ organization: req.user.organization })
      .populate('nodes.asset')
      .populate('nodes.securitySensor')
      .populate('createdBy', 'username email firstName lastName')
      .populate('updatedBy', 'username email firstName lastName');
    
    if (!topology) {
      topology = new NetworkTopology({
        organization: req.user.organization,
        nodes: [],
        edges: [],
        createdBy: req.user._id,
        updatedBy: req.user._id
      });
      await topology.save();
    }
    
    res.status(200).json({
      success: true,
      data: topology
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Create or update network topology
 */
exports.updateTopology = async (req, res, next) => {
  try {
    const { nodes, edges, name, description } = req.body;
    
    // Validate input
    if (nodes !== undefined && !Array.isArray(nodes)) {
      return res.status(400).json({
        success: false,
        message: 'Nodes must be an array'
      });
    }
    
    if (edges !== undefined && !Array.isArray(edges)) {
      return res.status(400).json({
        success: false,
        message: 'Edges must be an array'
      });
    }

    // Validate each node has required fields
    const validGroups = ['internet', 'firewall', 'router', 'dmz', 'server', 'workstation', 'sensor', 'switch', 'other'];
    
    if (nodes) {
      for (const node of nodes) {
        if (!node.id || !node.label) {
          return res.status(400).json({
            success: false,
            message: 'Each node must have an id and label'
          });
        }
        if (node.group && !validGroups.includes(node.group)) {
          return res.status(400).json({
            success: false,
            message: `Invalid group value: ${node.group}. Must be one of: ${validGroups.join(', ')}`
          });
        }
      }
    }

    // Validate edges
    if (edges) {
      for (const edge of edges) {
        if (!edge.from || !edge.to) {
          return res.status(400).json({
            success: false,
            message: 'Each edge must have from and to'
          });
        }
      }
    }

    // Find existing topology or create new one
    let topology = await NetworkTopology.findOne({ organization: req.user.organization });
    
    if (!topology) {
      topology = new NetworkTopology({
        organization: req.user.organization,
        nodes: nodes || [],
        edges: edges || [],
        name: name || 'Default Network Topology',
        description: description || '',
        createdBy: req.user._id,
        updatedBy: req.user._id
      });
    } else {
      if (nodes !== undefined) topology.nodes = nodes;
      if (edges !== undefined) topology.edges = edges;
      if (name) topology.name = name;
      if (description !== undefined) topology.description = description;
      topology.updatedBy = req.user._id;
    }
    
    await topology.save();
    
    // Populate references for response
    await topology.populate('nodes.asset');
    await topology.populate('nodes.securitySensor');
    await topology.populate('createdBy', 'username email firstName lastName');
    await topology.populate('updatedBy', 'username email firstName lastName');
    
    res.status(200).json({
      success: true,
      message: topology.isNew ? 'Network topology created successfully' : 'Network topology updated successfully',
      data: topology
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Delete/Clear network topology
 */
exports.deleteTopology = async (req, res, next) => {
  try {
    const topology = await NetworkTopology.findOne({ 
      organization: req.user.organization 
    });
    
    if (!topology) {
      return res.status(404).json({
        success: false,
        message: 'Network topology not found'
      });
    }
    
    topology.nodes = [];
    topology.edges = [];
    topology.updatedBy = req.user._id;
    await topology.save();
    
    res.status(200).json({
      success: true,
      message: 'Network topology cleared successfully',
      data: topology
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get topology statistics
 */
exports.getTopologyStats = async (req, res, next) => {
  try {
    const topology = await NetworkTopology.findOne({ 
      organization: req.user.organization 
    });
    
    if (!topology) {
      return res.status(200).json({
        success: true,
        data: {
          totalNodes: 0,
          totalEdges: 0,
          groups: {},
          zones: {},
          assets: 0,
          sensors: 0
        }
      });
    }
    
    const stats = {
      totalNodes: topology.nodes.length,
      totalEdges: topology.edges.length,
      groups: {},
      zones: {},
      assets: 0,
      sensors: 0
    };

    topology.nodes.forEach(node => {
      stats.groups[node.group || 'other'] = (stats.groups[node.group || 'other'] || 0) + 1;
      const zone = node.zone || 'Unassigned';
      stats.zones[zone] = (stats.zones[zone] || 0) + 1;
      if (node.asset) stats.assets++;
      if (node.securitySensor) stats.sensors++;
    });
    
    res.status(200).json({
      success: true,
      data: stats
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Add a single node to topology
 */
exports.addNode = async (req, res, next) => {
  try {
    const { node } = req.body;
    
    if (!node || !node.id || !node.label) {
      return res.status(400).json({
        success: false,
        message: 'Node must have id and label'
      });
    }

    const validGroups = ['internet', 'firewall', 'router', 'dmz', 'server', 'workstation', 'sensor', 'switch', 'other'];
    if (node.group && !validGroups.includes(node.group)) {
      return res.status(400).json({
        success: false,
        message: `Invalid group value: ${node.group}`
      });
    }

    let topology = await NetworkTopology.findOne({ organization: req.user.organization });
    
    if (!topology) {
      topology = new NetworkTopology({
        organization: req.user.organization,
        nodes: [],
        edges: [],
        createdBy: req.user._id,
        updatedBy: req.user._id
      });
    }
    
    if (topology.nodes.some(n => n.id === node.id)) {
      return res.status(409).json({
        success: false,
        message: `Node with ID "${node.id}" already exists`
      });
    }
    
    topology.nodes.push(node);
    topology.updatedBy = req.user._id;
    await topology.save();
    
    await topology.populate('nodes.asset');
    await topology.populate('nodes.securitySensor');
    
    res.status(201).json({
      success: true,
      message: 'Node added successfully',
      data: topology
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Remove a node and its associated edges
 */
exports.removeNode = async (req, res, next) => {
  try {
    const { nodeId } = req.params;
    
    const topology = await NetworkTopology.findOne({ 
      organization: req.user.organization 
    });
    
    if (!topology) {
      return res.status(404).json({
        success: false,
        message: 'Network topology not found'
      });
    }
    
    topology.nodes = topology.nodes.filter(n => n.id !== nodeId);
    topology.edges = topology.edges.filter(e => e.from !== nodeId && e.to !== nodeId);
    topology.updatedBy = req.user._id;
    await topology.save();
    
    res.status(200).json({
      success: true,
      message: 'Node and associated edges removed successfully',
      data: topology
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Bulk import nodes and edges
 */
exports.bulkImport = async (req, res, next) => {
  try {
    const { nodes, edges } = req.body;
    
    if (!nodes || !Array.isArray(nodes) || nodes.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'At least one node is required'
      });
    }

    const validGroups = ['internet', 'firewall', 'router', 'dmz', 'server', 'workstation', 'sensor', 'switch', 'other'];
    
    for (const node of nodes) {
      if (!node.id || !node.label) {
        return res.status(400).json({
          success: false,
          message: 'Each node must have an id and label'
        });
      }
      if (node.group && !validGroups.includes(node.group)) {
        return res.status(400).json({
          success: false,
          message: `Invalid group value: ${node.group}`
        });
      }
    }

    let topology = await NetworkTopology.findOne({ organization: req.user.organization });
    
    if (!topology) {
      topology = new NetworkTopology({
        organization: req.user.organization,
        nodes: [],
        edges: [],
        createdBy: req.user._id,
        updatedBy: req.user._id
      });
    }
    
    topology.nodes = [];
    topology.edges = [];
    
    for (const node of nodes) {
      if (!topology.nodes.some(n => n.id === node.id)) {
        topology.nodes.push(node);
      }
    }
    
    if (edges && Array.isArray(edges)) {
      for (const edge of edges) {
        if (edge.from && edge.to) {
          const duplicate = topology.edges.some(e => e.from === edge.from && e.to === edge.to);
          if (!duplicate) {
            topology.edges.push(edge);
          }
        }
      }
    }
    
    topology.updatedBy = req.user._id;
    await topology.save();
    
    await topology.populate('nodes.asset');
    await topology.populate('nodes.securitySensor');
    
    res.status(200).json({
      success: true,
      message: `Successfully imported ${topology.nodes.length} nodes and ${topology.edges.length} edges`,
      data: topology
    });
  } catch (error) {
    next(error);
  }
};