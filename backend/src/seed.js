/**
 * Database Seed Script - Complete
 * Populates the database with comprehensive test data for all modules including Network Defense
 * 
 * Run: node src/seed.js
 */

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const crypto = require('crypto');

// Load environment variables
dotenv.config();

// Import models
const User = require('./models/User');
const Organization = require('./models/Organization');
const Asset = require('./models/Asset');
const LogSource = require('./models/LogSource');
const Log = require('./models/Log');
const Alert = require('./models/Alert');
const Incident = require('./models/Incident');
const IOC = require('./models/IOC');
const ThreatRule = require('./models/ThreatRule');
const Report = require('./models/Report');
const AuditLog = require('./models/AuditLog');
const Settings = require('./models/Settings');
const Role = require('./models/Role');

// NEW: Network Defense Models
const NetworkTopology = require('./models/NetworkTopology');
const SecuritySensor = require('./models/SecuritySensor');
const SecurityControl = require('./models/SecurityControl');
const SecurityTest = require('./models/SecurityTest');
const SecurityAssessment = require('./models/SecurityAssessment');

const { ROLES, ASSET_TYPES, SEVERITY, ALERT_STATUS, INCIDENT_STATUS, RULE_TYPES } = require('./config/constants');

// Import logger
const logger = require('./config/logger');

// Helper functions
function randomIP() {
  return `${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`;
}

function randomDate(start, end) {
  return new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
}

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateId() {
  return crypto.randomBytes(8).toString('hex');
}

// Seed data
const seedData = {
  // Organizations
  organizations: [
    {
      name: 'Acme Corporation',
      code: 'ACME',
      description: 'Global technology solutions provider',
      industry: 'technology',
      size: 'enterprise',
      website: 'https://acme.com',
      address: {
        street: '123 Tech Park',
        city: 'San Francisco',
        state: 'CA',
        country: 'USA',
        postalCode: '94105'
      },
      contactInfo: {
        email: 'security@acme.com',
        phone: '+1-555-0100'
      },
      settings: {
        maxUsers: 100,
        maxAssets: 1000,
        maxLogsPerDay: 1000000,
        retentionPeriod: 90,
        timezone: 'America/Los_Angeles',
        features: {
          threatIntelligence: true,
          incidentResponse: true,
          complianceReporting: true,
          aiDetection: true,
          customRules: true
        },
        notificationPreferences: {
          email: true,
          slack: true,
          teams: false,
          sms: false
        }
      },
      status: 'active',
      subscription: {
        plan: 'enterprise',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2025-01-01'),
        isActive: true
      }
    },
    {
      name: 'Global Finance Inc',
      code: 'GFI',
      description: 'International financial services',
      industry: 'finance',
      size: 'large',
      website: 'https://globalfinance.com',
      address: {
        street: '456 Wall Street',
        city: 'New York',
        state: 'NY',
        country: 'USA',
        postalCode: '10005'
      },
      contactInfo: {
        email: 'security@gfi.com',
        phone: '+1-555-0200'
      },
      settings: {
        maxUsers: 50,
        maxAssets: 500,
        maxLogsPerDay: 500000,
        retentionPeriod: 120,
        timezone: 'America/New_York',
        features: {
          threatIntelligence: true,
          incidentResponse: true,
          complianceReporting: true,
          aiDetection: false,
          customRules: true
        },
        notificationPreferences: {
          email: true,
          slack: false,
          teams: true,
          sms: true
        }
      },
      status: 'active',
      subscription: {
        plan: 'professional',
        startDate: new Date('2024-06-01'),
        endDate: new Date('2025-06-01'),
        isActive: true
      }
    },
    {
      name: 'Healthcare Systems',
      code: 'HCS',
      description: 'Healthcare technology and services',
      industry: 'healthcare',
      size: 'medium',
      website: 'https://healthcaresys.com',
      address: {
        street: '789 Medical Drive',
        city: 'Boston',
        state: 'MA',
        country: 'USA',
        postalCode: '02118'
      },
      contactInfo: {
        email: 'security@hcs.com',
        phone: '+1-555-0300'
      },
      settings: {
        maxUsers: 75,
        maxAssets: 750,
        maxLogsPerDay: 750000,
        retentionPeriod: 180,
        timezone: 'America/New_York',
        features: {
          threatIntelligence: true,
          incidentResponse: true,
          complianceReporting: true,
          aiDetection: false,
          customRules: true
        },
        notificationPreferences: {
          email: true,
          slack: false,
          teams: false,
          sms: false
        }
      },
      status: 'active',
      subscription: {
        plan: 'professional',
        startDate: new Date('2024-03-01'),
        endDate: new Date('2025-03-01'),
        isActive: true
      }
    }
  ],

  // Users
  users: [
    {
      email: 'superadmin@sentinel-soc.com',
      username: 'superadmin',
      password: 'SuperAdmin@2024!',
      firstName: 'Super',
      lastName: 'Admin',
      role: ROLES.SUPER_ADMIN,
      organizationName: 'Acme Corporation',
      status: 'active'
    },
    {
      email: 'securityadmin@acme.com',
      username: 'secadmin',
      password: 'Security@2024!',
      firstName: 'John',
      lastName: 'Smith',
      role: ROLES.SECURITY_ADMIN,
      organizationName: 'Acme Corporation',
      status: 'active'
    },
    {
      email: 'analyst@acme.com',
      username: 'analyst1',
      password: 'Analyst@2024!',
      firstName: 'Jane',
      lastName: 'Doe',
      role: ROLES.SOC_ANALYST,
      organizationName: 'Acme Corporation',
      status: 'active'
    },
    {
      email: 'responder@acme.com',
      username: 'responder1',
      password: 'Responder@2024!',
      firstName: 'Bob',
      lastName: 'Johnson',
      role: ROLES.INCIDENT_RESPONDER,
      organizationName: 'Acme Corporation',
      status: 'active'
    },
    {
      email: 'auditor@acme.com',
      username: 'auditor1',
      password: 'Auditor@2024!',
      firstName: 'Alice',
      lastName: 'Williams',
      role: ROLES.AUDITOR,
      organizationName: 'Acme Corporation',
      status: 'active'
    },
    {
      email: 'securityadmin@gfi.com',
      username: 'secadmin_gfi',
      password: 'Security@2024!',
      firstName: 'Michael',
      lastName: 'Brown',
      role: ROLES.SECURITY_ADMIN,
      organizationName: 'Global Finance Inc',
      status: 'active'
    },
    {
      email: 'analyst@gfi.com',
      username: 'analyst_gfi',
      password: 'Analyst@2024!',
      firstName: 'Sarah',
      lastName: 'Davis',
      role: ROLES.SOC_ANALYST,
      organizationName: 'Global Finance Inc',
      status: 'active'
    },
    {
      email: 'analyst@hcs.com',
      username: 'analyst_hcs',
      password: 'Analyst@2024!',
      firstName: 'David',
      lastName: 'Miller',
      role: ROLES.SOC_ANALYST,
      organizationName: 'Healthcare Systems',
      status: 'active'
    }
  ],

  // Assets
  assets: [
    // Acme Corporation Assets
    {
      name: 'ACME-Web-Server-01',
      type: ASSET_TYPES.SERVER,
      hostname: 'web-srv-01.acme.com',
      ipAddress: '192.168.1.10',
      operatingSystem: 'Ubuntu 22.04 LTS',
      osVersion: '22.04',
      status: 'active',
      criticality: 'high',
      location: 'Data Center A',
      department: 'Engineering',
      owner: 'John Smith',
      organizationName: 'Acme Corporation',
      tags: ['production', 'web', 'public-facing'],
      hardware: {
        cpu: 'Intel Xeon E5-2680 v4',
        memory: '64GB DDR4',
        storage: '2TB SSD RAID 10',
        model: 'Dell PowerEdge R730',
        manufacturer: 'Dell'
      },
      network: {
        macAddress: '00:1A:2B:3C:4D:5E',
        dnsName: 'web-srv-01.acme.com',
        subnet: '192.168.1.0/24',
        gateway: '192.168.1.1'
      },
      security: {
        firewallEnabled: true,
        antivirusInstalled: true,
        antivirusStatus: 'active',
        lastPatchDate: new Date('2024-11-15'),
        vulnerabilityCount: 2,
        riskScore: 3.5,
        complianceStatus: 'compliant'
      },
      monitoring: {
        enabled: true,
        agentInstalled: true,
        agentVersion: '3.2.1',
        lastSeen: new Date(),
        healthStatus: 'healthy'
      }
    },
    {
      name: 'ACME-DB-Server-01',
      type: ASSET_TYPES.DATABASE,
      hostname: 'db-srv-01.acme.com',
      ipAddress: '192.168.1.20',
      operatingSystem: 'Windows Server 2022',
      osVersion: '2022',
      status: 'active',
      criticality: 'critical',
      location: 'Data Center A',
      department: 'Engineering',
      owner: 'John Smith',
      organizationName: 'Acme Corporation',
      tags: ['production', 'database', 'critical'],
      hardware: {
        cpu: 'Intel Xeon Gold 6226R',
        memory: '128GB DDR4',
        storage: '4TB SSD RAID 10',
        model: 'Dell PowerEdge R740',
        manufacturer: 'Dell'
      },
      network: {
        macAddress: '00:1A:2B:3C:4D:5F',
        dnsName: 'db-srv-01.acme.com',
        subnet: '192.168.1.0/24',
        gateway: '192.168.1.1'
      },
      security: {
        firewallEnabled: true,
        antivirusInstalled: true,
        antivirusStatus: 'active',
        lastPatchDate: new Date('2024-11-10'),
        vulnerabilityCount: 1,
        riskScore: 4.0,
        complianceStatus: 'compliant'
      },
      monitoring: {
        enabled: true,
        agentInstalled: true,
        agentVersion: '3.2.1',
        lastSeen: new Date(),
        healthStatus: 'healthy'
      }
    },
    {
      name: 'ACME-Firewall-01',
      type: ASSET_TYPES.FIREWALL,
      hostname: 'fw-01.acme.com',
      ipAddress: '192.168.1.1',
      operatingSystem: 'pfSense 2.7.0',
      osVersion: '2.7.0',
      status: 'active',
      criticality: 'critical',
      location: 'Data Center A',
      department: 'Network Security',
      owner: 'John Smith',
      organizationName: 'Acme Corporation',
      tags: ['production', 'firewall', 'security'],
      hardware: {
        cpu: 'Intel Xeon D-1521',
        memory: '32GB DDR4',
        storage: '512GB SSD',
        model: 'Netgate XG-7100',
        manufacturer: 'Netgate'
      },
      network: {
        macAddress: '00:1A:2B:3C:4D:60',
        dnsName: 'fw-01.acme.com',
        subnet: '192.168.1.0/24',
        gateway: '192.168.1.1'
      },
      security: {
        firewallEnabled: true,
        antivirusInstalled: false,
        antivirusStatus: 'unknown',
        lastPatchDate: new Date('2024-11-20'),
        vulnerabilityCount: 0,
        riskScore: 1.0,
        complianceStatus: 'compliant'
      },
      monitoring: {
        enabled: true,
        agentInstalled: true,
        agentVersion: '3.2.1',
        lastSeen: new Date(),
        healthStatus: 'healthy'
      }
    },
    {
      name: 'ACME-Web-App-01',
      type: ASSET_TYPES.WEB_APPLICATION,
      hostname: 'app.acme.com',
      ipAddress: '192.168.1.30',
      operatingSystem: 'CentOS 8',
      osVersion: '8.5',
      status: 'active',
      criticality: 'high',
      location: 'Data Center A',
      department: 'Engineering',
      owner: 'Jane Doe',
      organizationName: 'Acme Corporation',
      tags: ['production', 'application', 'user-facing'],
      hardware: {
        cpu: 'Intel Xeon E5-2650 v4',
        memory: '32GB DDR4',
        storage: '1TB SSD',
        model: 'Dell PowerEdge R730',
        manufacturer: 'Dell'
      },
      network: {
        macAddress: '00:1A:2B:3C:4D:61',
        dnsName: 'app.acme.com',
        subnet: '192.168.1.0/24',
        gateway: '192.168.1.1'
      },
      security: {
        firewallEnabled: true,
        antivirusInstalled: true,
        antivirusStatus: 'active',
        lastPatchDate: new Date('2024-11-18'),
        vulnerabilityCount: 3,
        riskScore: 4.5,
        complianceStatus: 'non-compliant'
      },
      monitoring: {
        enabled: true,
        agentInstalled: true,
        agentVersion: '3.2.1',
        lastSeen: new Date(),
        healthStatus: 'warning'
      }
    },
    // Global Finance Inc Assets
    {
      name: 'GFI-Web-Server-01',
      type: ASSET_TYPES.SERVER,
      hostname: 'web-srv-01.gfi.com',
      ipAddress: '10.0.0.10',
      operatingSystem: 'Red Hat Enterprise Linux 9',
      osVersion: '9.2',
      status: 'active',
      criticality: 'high',
      location: 'Data Center B',
      department: 'IT',
      owner: 'Michael Brown',
      organizationName: 'Global Finance Inc',
      tags: ['production', 'web', 'financial'],
      hardware: {
        cpu: 'Intel Xeon Platinum 8280',
        memory: '128GB DDR4',
        storage: '4TB NVMe SSD',
        model: 'HPE ProLiant DL380',
        manufacturer: 'HPE'
      },
      network: {
        macAddress: '00:1A:2B:3C:4D:70',
        dnsName: 'web-srv-01.gfi.com',
        subnet: '10.0.0.0/24',
        gateway: '10.0.0.1'
      },
      security: {
        firewallEnabled: true,
        antivirusInstalled: true,
        antivirusStatus: 'active',
        lastPatchDate: new Date('2024-11-16'),
        vulnerabilityCount: 1,
        riskScore: 2.5,
        complianceStatus: 'compliant'
      },
      monitoring: {
        enabled: true,
        agentInstalled: true,
        agentVersion: '3.2.0',
        lastSeen: new Date(),
        healthStatus: 'healthy'
      }
    },
    {
      name: 'GFI-DB-Server-01',
      type: ASSET_TYPES.DATABASE,
      hostname: 'db-srv-01.gfi.com',
      ipAddress: '10.0.0.20',
      operatingSystem: 'Windows Server 2019',
      osVersion: '2019',
      status: 'active',
      criticality: 'critical',
      location: 'Data Center B',
      department: 'IT',
      owner: 'Michael Brown',
      organizationName: 'Global Finance Inc',
      tags: ['production', 'database', 'financial-data'],
      hardware: {
        cpu: 'Intel Xeon Gold 6248R',
        memory: '256GB DDR4',
        storage: '8TB SSD RAID 10',
        model: 'HPE ProLiant DL380',
        manufacturer: 'HPE'
      },
      network: {
        macAddress: '00:1A:2B:3C:4D:71',
        dnsName: 'db-srv-01.gfi.com',
        subnet: '10.0.0.0/24',
        gateway: '10.0.0.1'
      },
      security: {
        firewallEnabled: true,
        antivirusInstalled: true,
        antivirusStatus: 'active',
        lastPatchDate: new Date('2024-11-12'),
        vulnerabilityCount: 2,
        riskScore: 4.0,
        complianceStatus: 'compliant'
      },
      monitoring: {
        enabled: true,
        agentInstalled: true,
        agentVersion: '3.2.0',
        lastSeen: new Date(),
        healthStatus: 'healthy'
      }
    },
    // Healthcare Systems Assets
    {
      name: 'HCS-Web-Server-01',
      type: ASSET_TYPES.SERVER,
      hostname: 'web-srv-01.hcs.com',
      ipAddress: '172.16.0.10',
      operatingSystem: 'Ubuntu 20.04 LTS',
      osVersion: '20.04',
      status: 'active',
      criticality: 'high',
      location: 'Data Center C',
      department: 'Healthcare IT',
      owner: 'Alice Williams',
      organizationName: 'Healthcare Systems',
      tags: ['production', 'web', 'healthcare'],
      hardware: {
        cpu: 'AMD EPYC 7402',
        memory: '64GB DDR4',
        storage: '2TB SSD',
        model: 'Supermicro SuperServer',
        manufacturer: 'Supermicro'
      },
      network: {
        macAddress: '00:1A:2B:3C:4D:80',
        dnsName: 'web-srv-01.hcs.com',
        subnet: '172.16.0.0/24',
        gateway: '172.16.0.1'
      },
      security: {
        firewallEnabled: true,
        antivirusInstalled: true,
        antivirusStatus: 'active',
        lastPatchDate: new Date('2024-11-19'),
        vulnerabilityCount: 4,
        riskScore: 5.5,
        complianceStatus: 'non-compliant'
      },
      monitoring: {
        enabled: true,
        agentInstalled: true,
        agentVersion: '3.1.5',
        lastSeen: new Date(),
        healthStatus: 'warning'
      }
    }
  ],

  // NEW: Network Topology Data
  networkTopologies: [
    {
      name: 'Acme Corporation Network Architecture',
      description: 'Production network topology for Acme Corporation',
      organizationName: 'Acme Corporation',
      nodes: [
        { id: 'internet', label: 'Internet', group: 'internet', zone: 'External' },
        { id: 'firewall', label: 'Edge Firewall', group: 'firewall', zone: 'Perimeter' },
        { id: 'dmz-router', label: 'DMZ Router', group: 'router', zone: 'DMZ' },
        { id: 'core-router', label: 'Core Router', group: 'router', zone: 'Internal LAN' },
        { id: 'web-server', label: 'DMZ Web Server', group: 'server', zone: 'DMZ' },
        { id: 'db-server', label: 'Database Server', group: 'server', zone: 'Internal LAN' },
        { id: 'workstation', label: 'Staff Workstation', group: 'workstation', zone: 'Internal LAN' },
        { id: 'suricata', label: 'Suricata IDS', group: 'sensor', zone: 'DMZ' },
        { id: 'zeek', label: 'Zeek Monitor', group: 'sensor', zone: 'Internal LAN' },
        { id: 'sentinel-soc', label: 'SentinelSOC Core', group: 'server', zone: 'Management' }
      ],
      edges: [
        { from: 'internet', to: 'firewall' },
        { from: 'firewall', to: 'dmz-router' },
        { from: 'firewall', to: 'core-router' },
        { from: 'dmz-router', to: 'web-server' },
        { from: 'dmz-router', to: 'suricata' },
        { from: 'core-router', to: 'db-server' },
        { from: 'core-router', to: 'workstation' },
        { from: 'core-router', to: 'zeek' },
        { from: 'suricata', to: 'sentinel-soc' },
        { from: 'zeek', to: 'sentinel-soc' }
      ]
    },
    {
      name: 'Global Finance Network',
      description: 'Financial network topology for Global Finance Inc',
      organizationName: 'Global Finance Inc',
      nodes: [
        { id: 'internet', label: 'Internet', group: 'internet', zone: 'External' },
        { id: 'firewall', label: 'Financial Firewall', group: 'firewall', zone: 'Perimeter' },
        { id: 'core-router', label: 'Core Router', group: 'router', zone: 'Internal LAN' },
        { id: 'web-server', label: 'Financial Web Server', group: 'server', zone: 'Internal LAN' },
        { id: 'db-server', label: 'Financial Database', group: 'server', zone: 'Internal LAN' },
        { id: 'workstation', label: 'Financial Workstation', group: 'workstation', zone: 'Internal LAN' },
        { id: 'suricata', label: 'Suricata IDS', group: 'sensor', zone: 'Internal LAN' },
        { id: 'sentinel-soc', label: 'SentinelSOC Core', group: 'server', zone: 'Management' }
      ],
      edges: [
        { from: 'internet', to: 'firewall' },
        { from: 'firewall', to: 'core-router' },
        { from: 'core-router', to: 'web-server' },
        { from: 'core-router', to: 'db-server' },
        { from: 'core-router', to: 'workstation' },
        { from: 'core-router', to: 'suricata' },
        { from: 'suricata', to: 'sentinel-soc' }
      ]
    }
  ],

  // NEW: Security Sensors
  securitySensors: [
    {
      name: 'Suricata-IDS-DMZ-01',
      type: 'Suricata',
      description: 'Primary Suricata IDS monitoring DMZ traffic',
      networkZone: 'DMZ',
      ipAddress: '192.168.1.100',
      port: 5632,
      status: 'Active',
      healthScore: 95,
      capabilities: ['ids', 'network_monitoring', 'threat_detection'],
      tags: ['production', 'dmz', 'ids'],
      organizationName: 'Acme Corporation',
      eventsReceived: 15234,
      eventsForwarded: 14892,
      alertsGenerated: 234,
      lastHeartbeat: new Date(),
      version: '6.0.0',
      configuration: {
        interface: 'eth0',
        ruleset: 'emerging-threats',
        alertLevel: 'high',
        threads: 4
      }
    },
    {
      name: 'Zeek-Monitor-Internal-01',
      type: 'Zeek',
      description: 'Zeek network monitor for internal LAN traffic analysis',
      networkZone: 'Internal LAN',
      ipAddress: '192.168.1.101',
      port: 5432,
      status: 'Active',
      healthScore: 92,
      capabilities: ['network_monitoring', 'dns_monitoring', 'http_monitoring', 'tls_monitoring'],
      tags: ['production', 'internal', 'monitoring'],
      organizationName: 'Acme Corporation',
      eventsReceived: 45234,
      eventsForwarded: 44500,
      alertsGenerated: 89,
      lastHeartbeat: new Date(),
      version: '5.2.0',
      configuration: {
        interface: 'eth1',
        capture: 'full',
        protocols: ['dns', 'http', 'ssl', 'conn']
      }
    },
    {
      name: 'Firewall-Edge-01',
      type: 'Firewall',
      description: 'Edge firewall monitoring with logging',
      networkZone: 'Perimeter',
      ipAddress: '192.168.1.1',
      port: 443,
      status: 'Active',
      healthScore: 98,
      capabilities: ['ips', 'log_collection', 'threat_detection'],
      tags: ['production', 'firewall', 'edge'],
      organizationName: 'Acme Corporation',
      eventsReceived: 89234,
      eventsForwarded: 87123,
      alertsGenerated: 567,
      lastHeartbeat: new Date(),
      version: '2.7.0',
      configuration: {
        logging: 'full',
        blockStrategy: 'default',
        interface: 'wan'
      }
    },
    {
      name: 'Suricata-IDS-Finance-01',
      type: 'Suricata',
      description: 'Suricata IDS for financial network',
      networkZone: 'Internal LAN',
      ipAddress: '10.0.0.50',
      port: 5632,
      status: 'Active',
      healthScore: 88,
      capabilities: ['ids', 'network_monitoring'],
      tags: ['production', 'finance', 'ids'],
      organizationName: 'Global Finance Inc',
      eventsReceived: 8234,
      eventsForwarded: 7892,
      alertsGenerated: 134,
      lastHeartbeat: new Date(),
      version: '6.0.0',
      configuration: {
        interface: 'eth0',
        ruleset: 'financial',
        alertLevel: 'medium'
      }
    },
    {
      name: 'Host-Collector-HCS-01',
      type: 'Host Collector',
      description: 'Host collector for healthcare systems',
      networkZone: 'Management',
      ipAddress: '172.16.0.50',
      port: 4567,
      status: 'Active',
      healthScore: 85,
      capabilities: ['host_monitoring', 'log_collection'],
      tags: ['production', 'healthcare', 'host'],
      organizationName: 'Healthcare Systems',
      eventsReceived: 5234,
      eventsForwarded: 5123,
      alertsGenerated: 45,
      lastHeartbeat: new Date(),
      version: '3.1.5',
      configuration: {
        monitoring: 'full',
        interval: 60
      }
    }
  ],

  // NEW: Security Controls
  securityControls: [
    {
      threatName: 'SSH Brute Force Attack',
      description: 'Addressing SSH brute force attacks on Linux servers',
      securityImpact: 'Unauthorized access to critical servers, potential data breach',
      riskLevel: 'High',
      recommendedControls: [
        { name: 'Enable fail2ban', description: 'Install and configure fail2ban to block IPs after multiple failures', priority: 'High', status: 'Implemented' },
        { name: 'Implement rate limiting', description: 'Configure rate limiting for SSH connections using iptables or firewalld', priority: 'Medium', status: 'In Progress' },
        { name: 'Use SSH key authentication', description: 'Disable password authentication and use SSH keys only', priority: 'High', status: 'Pending' }
      ],
      mitigations: [
        { name: 'Block IP after 5 attempts', description: 'Automatically block source IPs after 5 failed SSH attempts', priority: 'High', status: 'Implemented' },
        { name: 'Monitor SSH logs', description: 'Regularly review SSH authentication logs for patterns', priority: 'Medium', status: 'Pending' }
      ],
      analystActions: [
        { name: 'Review SSH logs', description: 'Check for successful breaches from blocked IPs', priority: 'High' },
        { name: 'Rotate compromised credentials', description: 'If any breach detected, rotate affected user credentials', priority: 'Critical' }
      ],
      complianceFrameworks: ['NIST', 'ISO27001'],
      tags: ['ssh', 'brute_force', 'authentication'],
      organizationName: 'Acme Corporation'
    },
    {
      threatName: 'SQL Injection Attack',
      description: 'Preventing SQL injection attacks on web applications',
      securityImpact: 'Potential data exfiltration, database compromise',
      riskLevel: 'Critical',
      recommendedControls: [
        { name: 'Use parameterized queries', description: 'Implement parameterized queries for all database interactions', priority: 'Critical', status: 'In Progress' },
        { name: 'Web Application Firewall', description: 'Deploy WAF to filter malicious SQL patterns', priority: 'High', status: 'Pending' },
        { name: 'Input validation', description: 'Implement strict input validation on all user inputs', priority: 'High', status: 'Implemented' }
      ],
      mitigations: [
        { name: 'Database firewall', description: 'Implement database firewall to block suspicious queries', priority: 'High', status: 'Pending' },
        { name: 'Regular code reviews', description: 'Conduct regular code reviews for SQL injection vulnerabilities', priority: 'Medium', status: 'In Progress' }
      ],
      analystActions: [
        { name: 'Review application logs', description: 'Check for SQL injection attempts in web server logs', priority: 'High' },
        { name: 'Monitor database access', description: 'Monitor for unauthorized database queries', priority: 'High' }
      ],
      complianceFrameworks: ['NIST', 'ISO27001', 'PCI-DSS'],
      tags: ['sql_injection', 'web_attack', 'database'],
      organizationName: 'Acme Corporation'
    },
    {
      threatName: 'Malware Communication',
      description: 'Detecting and preventing malware C2 communication',
      securityImpact: 'System compromise, data exfiltration, lateral movement',
      riskLevel: 'Critical',
      recommendedControls: [
        { name: 'Network segmentation', description: 'Implement network segmentation to limit malware spread', priority: 'High', status: 'Implemented' },
        { name: 'DNS filtering', description: 'Implement DNS filtering to block known malicious domains', priority: 'High', status: 'Pending' },
        { name: 'Endpoint detection', description: 'Deploy endpoint detection and response (EDR) solutions', priority: 'Critical', status: 'In Progress' }
      ],
      mitigations: [
        { name: 'Network monitoring', description: 'Monitor for unusual outbound connections', priority: 'High', status: 'Implemented' },
        { name: 'IOC blocking', description: 'Block known C2 IPs and domains at the firewall', priority: 'High', status: 'Pending' }
      ],
      analystActions: [
        { name: 'Investigate outbound traffic', description: 'Investigate any unusual outbound traffic patterns', priority: 'High' },
        { name: 'Update IOCs', description: 'Regularly update C2 IP and domain lists', priority: 'Medium' }
      ],
      complianceFrameworks: ['NIST', 'ISO27001'],
      tags: ['malware', 'c2', 'network'],
      organizationName: 'Acme Corporation'
    }
  ],

  // NEW: Security Tests
  securityTests: [
    {
      name: 'Port Scan Detection Test',
      description: 'Validates that Suricata detects port scanning activity',
      testType: 'port_scan',
      status: 'PASS',
      actualResult: JSON.stringify({
        logGenerated: true,
        logIngested: true,
        detectionTriggered: true,
        alertCreated: true,
        incidentCreated: true,
        evidenceRecorded: true
      }),
      payload: {
        eventType: 'port_scan',
        sourceIP: '192.168.1.200',
        destinationIP: '192.168.1.10',
        destinationPort: 80,
        protocol: 'TCP',
        message: 'Port scan detected from 192.168.1.200'
      },
      organizationName: 'Acme Corporation'
    },
    {
      name: 'Brute Force Detection Test',
      description: 'Validates that brute force attacks are detected',
      testType: 'brute_force',
      status: 'PASS',
      actualResult: JSON.stringify({
        logGenerated: true,
        logIngested: true,
        detectionTriggered: true,
        alertCreated: true,
        incidentCreated: false,
        evidenceRecorded: true
      }),
      payload: {
        eventType: 'brute_force',
        sourceIP: '192.168.1.201',
        destinationIP: '192.168.1.20',
        destinationPort: 22,
        protocol: 'TCP',
        message: 'Brute force attack detected from 192.168.1.201'
      },
      organizationName: 'Acme Corporation'
    },
    {
      name: 'Suspicious Connection Test',
      description: 'Validates detection of suspicious outbound connections',
      testType: 'suspicious_traffic',
      status: 'PASS',
      actualResult: JSON.stringify({
        logGenerated: true,
        logIngested: true,
        detectionTriggered: true,
        alertCreated: true,
        incidentCreated: false,
        evidenceRecorded: true
      }),
      payload: {
        eventType: 'suspicious_traffic',
        sourceIP: '192.168.1.30',
        destinationIP: '185.130.5.10',
        destinationPort: 4444,
        protocol: 'TCP',
        message: 'Suspicious connection to malicious C2 server'
      },
      organizationName: 'Acme Corporation'
    },
    {
      name: 'SQL Injection Detection Test',
      description: 'Validates SQL injection detection capabilities',
      testType: 'sql_injection',
      status: 'PENDING',
      payload: {
        eventType: 'sql_injection',
        sourceIP: '45.33.22.11',
        destinationIP: '192.168.1.10',
        destinationPort: 443,
        protocol: 'TCP',
        message: "SQL injection attempt: ' OR '1'='1",
        payload: "' OR '1'='1"
      },
      organizationName: 'Acme Corporation'
    },
    {
      name: 'XSS Detection Test',
      description: 'Validates XSS detection capabilities',
      testType: 'xss',
      status: 'PENDING',
      payload: {
        eventType: 'xss',
        sourceIP: '89.45.67.23',
        destinationIP: '192.168.1.10',
        destinationPort: 443,
        protocol: 'TCP',
        message: "XSS attempt: <script>alert('xss')</script>",
        payload: "<script>alert('xss')</script>"
      },
      organizationName: 'Acme Corporation'
    }
  ],

  // NEW: Security Assessments
  securityAssessments: [
    {
      title: 'Q4 2024 Security Posture Review',
      description: 'Comprehensive security assessment for Q4 2024 covering all assets and threats',
      date: new Date('2024-12-15'),
      riskLevel: 'High',
      status: 'Final',
      assessmentPeriod: {
        startDate: new Date('2024-10-01'),
        endDate: new Date('2024-12-15')
      },
      securityWeaknesses: [
        'Outdated SSL/TLS configurations on web servers',
        'No rate limiting on authentication endpoints',
        'Default credentials still present on some IoT devices',
        'No regular vulnerability scanning in place',
        'Missing backup encryption'
      ],
      recommendedControls: [
        { name: 'Update SSL/TLS configurations', description: 'Disable outdated protocols and implement TLS 1.3', priority: 'High' },
        { name: 'Implement rate limiting', description: 'Add rate limiting to authentication endpoints', priority: 'High' },
        { name: 'Credentials management', description: 'Audit and remove default credentials', priority: 'Critical' },
        { name: 'Regular vulnerability scanning', description: 'Implement weekly automated vulnerability scans', priority: 'Medium' }
      ],
      mitigations: [
        { name: 'Deploy WAF', description: 'Implement Web Application Firewall', priority: 'High' },
        { name: 'Implement IP blocking', description: 'Block malicious IPs at firewall', priority: 'Medium' }
      ],
      summary: 'Acme Corporation demonstrates a solid security foundation but requires immediate attention to high-risk vulnerabilities. Critical findings include the presence of default credentials and outdated SSL configurations. Recommended actions should prioritize credential management and encryption upgrades.',
      tags: ['quarterly', 'compliance', 'high_risk'],
      organizationName: 'Acme Corporation',
      nextReviewDate: new Date('2025-03-15')
    },
    {
      title: 'Financial Security Assessment - Q4',
      description: 'Security assessment for Global Finance Inc focusing on financial data protection',
      date: new Date('2024-11-30'),
      riskLevel: 'Medium',
      status: 'Review',
      assessmentPeriod: {
        startDate: new Date('2024-09-01'),
        endDate: new Date('2024-11-30')
      },
      securityWeaknesses: [
        'Inadequate logging for financial transactions',
        'No segmentation between production and development networks',
        'Missing encryption for database backups'
      ],
      recommendedControls: [
        { name: 'Implement comprehensive logging', description: 'Add detailed logging for all financial transactions', priority: 'High' },
        { name: 'Network segmentation', description: 'Implement VLANs to separate development from production', priority: 'Medium' },
        { name: 'Encrypt backups', description: 'Implement encryption for all database backups', priority: 'High' }
      ],
      mitigations: [
        { name: 'Log monitoring', description: 'Implement real-time log monitoring for financial systems', priority: 'High' }
      ],
      summary: 'Global Finance Inc requires improvements in logging and network segmentation. The identified weaknesses pose moderate risk to financial data integrity. Priority should be given to implementing comprehensive transaction logging and securing backups.',
      tags: ['quarterly', 'finance', 'compliance'],
      organizationName: 'Global Finance Inc',
      nextReviewDate: new Date('2025-02-28')
    },
    {
      title: 'Healthcare Compliance Assessment',
      description: 'HIPAA compliance assessment for Healthcare Systems',
      date: new Date('2024-11-01'),
      riskLevel: 'Critical',
      status: 'In Progress',
      assessmentPeriod: {
        startDate: new Date('2024-08-01'),
        endDate: new Date('2024-11-01')
      },
      securityWeaknesses: [
        'No encryption for patient data at rest',
        'Weak access controls for medical records',
        'Missing audit logs for data access',
        'No data loss prevention controls'
      ],
      recommendedControls: [
        { name: 'Encrypt patient data', description: 'Implement encryption for all patient data at rest', priority: 'Critical' },
        { name: 'Implement RBAC', description: 'Role-based access control for medical records', priority: 'High' },
        { name: 'Enable audit logging', description: 'Implement detailed audit logs for all data access', priority: 'High' },
        { name: 'Deploy DLP', description: 'Implement Data Loss Prevention controls', priority: 'High' }
      ],
      mitigations: [
        { name: 'Access monitoring', description: 'Monitor all access to patient records', priority: 'High' },
        { name: 'Regular audits', description: 'Conduct regular compliance audits', priority: 'Medium' }
      ],
      summary: 'Healthcare Systems has critical compliance gaps requiring immediate attention. The lack of encryption for patient data and weak access controls pose significant risk. Remediation must prioritize encryption and access control implementation to ensure HIPAA compliance.',
      tags: ['healthcare', 'hipaa', 'compliance'],
      organizationName: 'Healthcare Systems',
      nextReviewDate: new Date('2025-02-01')
    }
  ],

  // Log Sources (unchanged)
  logSources: [
    {
      sourceName: 'ACME-Windows-Server-01',
      sourceType: 'Windows',
      hostname: 'win-srv-01.acme.com',
      ipAddress: '192.168.1.50',
      operatingSystem: 'Windows Server 2022',
      protocol: 'REST',
      status: 'Online',
      description: 'Windows domain controller and file server',
      organizationName: 'Acme Corporation',
      assetHostname: 'db-srv-01.acme.com',
      configuration: {
        logLevel: 'info',
        batchSize: 100,
        flushInterval: 60,
        enabled: true
      }
    },
    {
      sourceName: 'ACME-Linux-Server-01',
      sourceType: 'Linux',
      hostname: 'lin-srv-01.acme.com',
      ipAddress: '192.168.1.60',
      operatingSystem: 'Ubuntu 22.04 LTS',
      protocol: 'REST',
      status: 'Online',
      description: 'Linux application server',
      organizationName: 'Acme Corporation',
      assetHostname: 'web-srv-01.acme.com',
      configuration: {
        logLevel: 'info',
        batchSize: 100,
        flushInterval: 60,
        enabled: true
      }
    },
    {
      sourceName: 'ACME-Apache-Web-01',
      sourceType: 'Apache',
      hostname: 'web-srv-01.acme.com',
      ipAddress: '192.168.1.10',
      operatingSystem: 'Ubuntu 22.04 LTS',
      protocol: 'REST',
      status: 'Online',
      description: 'Apache web server for Acme website',
      organizationName: 'Acme Corporation',
      assetHostname: 'web-srv-01.acme.com',
      configuration: {
        logLevel: 'info',
        batchSize: 100,
        flushInterval: 60,
        enabled: true
      }
    },
    {
      sourceName: 'ACME-Nginx-Proxy-01',
      sourceType: 'Nginx',
      hostname: 'nginx-proxy-01.acme.com',
      ipAddress: '192.168.1.70',
      operatingSystem: 'CentOS 8',
      protocol: 'REST',
      status: 'Online',
      description: 'Nginx reverse proxy and load balancer',
      organizationName: 'Acme Corporation',
      assetHostname: 'web-srv-01.acme.com',
      configuration: {
        logLevel: 'info',
        batchSize: 100,
        flushInterval: 60,
        enabled: true
      }
    },
    {
      sourceName: 'ACME-Suricata-IDS-01',
      sourceType: 'Suricata',
      hostname: 'ids-01.acme.com',
      ipAddress: '192.168.1.80',
      operatingSystem: 'Ubuntu 22.04 LTS',
      protocol: 'REST',
      status: 'Online',
      description: 'Suricata IDS/IPS for network monitoring',
      organizationName: 'Acme Corporation',
      assetHostname: 'fw-01.acme.com',
      configuration: {
        logLevel: 'debug',
        batchSize: 100,
        flushInterval: 30,
        enabled: true
      }
    },
    {
      sourceName: 'ACME-Snort-IDS-01',
      sourceType: 'Snort',
      hostname: 'snort-01.acme.com',
      ipAddress: '192.168.1.90',
      operatingSystem: 'CentOS 8',
      protocol: 'REST',
      status: 'Online',
      description: 'Snort IDS for network intrusion detection',
      organizationName: 'Acme Corporation',
      assetHostname: 'fw-01.acme.com',
      configuration: {
        logLevel: 'debug',
        batchSize: 100,
        flushInterval: 30,
        enabled: true
      }
    },
    {
      sourceName: 'ACME-Firewall-01',
      sourceType: 'pfSense',
      hostname: 'fw-01.acme.com',
      ipAddress: '192.168.1.1',
      operatingSystem: 'pfSense 2.7.0',
      protocol: 'REST',
      status: 'Online',
      description: 'Main firewall and network gateway',
      organizationName: 'Acme Corporation',
      assetHostname: 'fw-01.acme.com',
      configuration: {
        logLevel: 'info',
        batchSize: 100,
        flushInterval: 60,
        enabled: true
      }
    },
    {
      sourceName: 'GFI-Windows-Server-01',
      sourceType: 'Windows',
      hostname: 'win-srv-01.gfi.com',
      ipAddress: '10.0.0.30',
      operatingSystem: 'Windows Server 2022',
      protocol: 'REST',
      status: 'Online',
      description: 'Windows domain controller for GFI',
      organizationName: 'Global Finance Inc',
      assetHostname: 'db-srv-01.gfi.com',
      configuration: {
        logLevel: 'info',
        batchSize: 100,
        flushInterval: 60,
        enabled: true
      }
    },
    {
      sourceName: 'GFI-Linux-Server-01',
      sourceType: 'Linux',
      hostname: 'lin-srv-01.gfi.com',
      ipAddress: '10.0.0.40',
      operatingSystem: 'Red Hat Enterprise Linux 9',
      protocol: 'REST',
      status: 'Online',
      description: 'Financial application server',
      organizationName: 'Global Finance Inc',
      assetHostname: 'web-srv-01.gfi.com',
      configuration: {
        logLevel: 'info',
        batchSize: 100,
        flushInterval: 60,
        enabled: true
      }
    },
    {
      sourceName: 'HCS-Windows-Server-01',
      sourceType: 'Windows',
      hostname: 'win-srv-01.hcs.com',
      ipAddress: '172.16.0.20',
      operatingSystem: 'Windows Server 2022',
      protocol: 'REST',
      status: 'Online',
      description: 'Healthcare application server',
      organizationName: 'Healthcare Systems',
      assetHostname: 'web-srv-01.hcs.com',
      configuration: {
        logLevel: 'info',
        batchSize: 100,
        flushInterval: 60,
        enabled: true
      }
    }
  ],

  // Logs (sample security events)
  logs: [
    // Windows Security Events
    {
      sourceType: 'Windows',
      eventCategory: 'authentication',
      eventType: 'Failed Login',
      severity: 'high',
      message: 'Failed login attempt for user Administrator from IP 192.168.1.100',
      username: 'Administrator',
      sourceIP: '192.168.1.100',
      rawLog: {
        eventId: 4625,
        logonType: 3,
        workstation: 'WORKSTATION-01',
        domain: 'ACME.local'
      }
    },
    {
      sourceType: 'Windows',
      eventCategory: 'authentication',
      eventType: 'Successful Login',
      severity: 'low',
      message: 'Successful login for user jsmith from IP 192.168.1.101',
      username: 'jsmith',
      sourceIP: '192.168.1.101',
      rawLog: {
        eventId: 4624,
        logonType: 10,
        workstation: 'WORKSTATION-02',
        domain: 'ACME.local'
      }
    },
    // Linux Events
    {
      sourceType: 'Linux',
      eventCategory: 'authentication',
      eventType: 'SSH Login',
      severity: 'info',
      message: 'SSH login successful for user root from 10.0.0.50',
      username: 'root',
      sourceIP: '10.0.0.50',
      rawLog: {
        pid: 12345,
        tty: 'pts/0',
        shell: '/bin/bash'
      }
    },
    {
      sourceType: 'Linux',
      eventCategory: 'authentication',
      eventType: 'SSH Failed Login',
      severity: 'high',
      message: 'SSH login failed for user invalid from 10.0.0.51',
      username: 'invalid',
      sourceIP: '10.0.0.51',
      rawLog: {
        pid: 12346,
        failures: 3
      }
    },
    // Apache Events
    {
      sourceType: 'Apache',
      eventCategory: 'web',
      eventType: 'SQL Injection Attempt',
      severity: 'critical',
      message: 'SQL injection attempt detected on /login.php',
      sourceIP: '45.33.22.11',
      destinationIP: '192.168.1.10',
      rawLog: {
        method: 'POST',
        uri: '/login.php',
        status: 403,
        payload: "' OR '1'='1",
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
      }
    },
    // Suricata Events
    {
      sourceType: 'Suricata',
      eventCategory: 'malware',
      eventType: 'Malware Communication',
      severity: 'critical',
      message: 'Malware communication detected to known C2 server evil-domain.com',
      sourceIP: '192.168.1.30',
      destinationIP: '185.130.5.10',
      rawLog: {
        signature: {
          sid: 2100004,
          name: 'Malware Communication Detected',
          category: 'MALWARE',
          severity: 'critical',
          msg: 'Malware communication detected to known C2 server'
        },
        flow: 'to_server',
        app_proto: 'dns'
      }
    },
    // Firewall Events
    {
      sourceType: 'pfSense',
      eventCategory: 'network',
      eventType: 'Connection Blocked',
      severity: 'medium',
      message: 'Blocked connection from 212.102.40.15 to 192.168.1.10:443',
      sourceIP: '212.102.40.15',
      destinationIP: '192.168.1.10',
      destinationPort: 443,
      protocol: 'TCP',
      rawLog: {
        action: 'block',
        interface: 'WAN',
        direction: 'in',
        rule: 'default_deny'
      }
    }
  ],

  // Alerts
  alerts: [
    {
      title: 'Brute Force Attack Detected',
      description: 'Multiple failed login attempts detected from IP 192.168.1.100',
      severity: 'high',
      category: 'authentication',
      threatType: 'brute_force',
      sourceIP: '192.168.1.100',
      confidence: 85,
      tags: ['brute_force', 'authentication'],
      status: 'active'
    },
    {
      title: 'SQL Injection Attempt',
      description: 'SQL injection attempt detected on web application at /login.php',
      severity: 'critical',
      category: 'web',
      threatType: 'sql_injection',
      sourceIP: '45.33.22.11',
      destinationIP: '192.168.1.10',
      confidence: 90,
      tags: ['web_attack', 'sql_injection'],
      status: 'investigating'
    },
    {
      title: 'Malware Communication Detected',
      description: 'Malware communication to known C2 server evil-domain.com from internal host',
      severity: 'critical',
      category: 'malware',
      threatType: 'malware_communication',
      sourceIP: '192.168.1.30',
      destinationIP: '185.130.5.10',
      confidence: 95,
      tags: ['malware', 'c2'],
      status: 'active'
    }
  ],

  // Incidents
  incidents: [
    {
      title: 'Ransomware Outbreak Investigation',
      description: 'Multiple systems showing signs of ransomware infection with .encrypted file extensions',
      severity: 'critical',
      category: 'ransomware',
      status: 'investigating',
      detectionSource: 'automated',
      tags: ['ransomware', 'critical_incident'],
      containmentMeasures: [
        {
          measure: 'Isolated affected systems from network',
          effectiveness: 'effective'
        }
      ]
    },
    {
      title: 'Phishing Campaign Investigation',
      description: 'Multiple employees received phishing emails with malicious links',
      severity: 'high',
      category: 'phishing',
      status: 'investigating',
      detectionSource: 'user_report',
      tags: ['phishing', 'social_engineering']
    }
  ],

  // IOCs
  iocs: [
    {
      type: 'ip',
      value: '185.130.5.10',
      indicator: '185.130.5.10',
      description: 'Known C2 server for Emotet malware',
      severity: 'critical',
      confidence: 95,
      source: 'threat_intelligence',
      threatType: 'malware',
      tags: ['c2', 'emotet', 'malware']
    },
    {
      type: 'domain',
      value: 'evil-domain.com',
      indicator: 'evil-domain.com',
      description: 'Malicious domain used for C2 communications',
      severity: 'critical',
      confidence: 90,
      source: 'threat_intelligence',
      threatType: 'c2',
      tags: ['c2', 'malware']
    },
    {
      type: 'file_hash',
      value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      indicator: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      description: 'Known ransomware file hash',
      severity: 'critical',
      confidence: 95,
      source: 'threat_intelligence',
      threatType: 'ransomware',
      tags: ['ransomware', 'file_hash']
    }
  ],

  // Threat Rules
  threatRules: [
    {
      name: 'Brute Force Detection',
      description: 'Detects multiple failed login attempts from the same IP',
      type: RULE_TYPES.SIGNATURE,
      severity: 'high',
      category: 'authentication',
      threatType: 'brute_force',
      condition: {
        eventCategory: 'authentication',
        eventType: 'Failed Login'
      },
      actions: [
        {
          type: 'alert',
          configuration: {
            priority: 'high',
            notify: true
          }
        }
      ],
      enabled: true,
      priority: 8,
      cooldown: 60,
      tags: ['brute_force', 'authentication']
    },
    {
      name: 'SQL Injection Detection',
      description: 'Detects SQL injection attempts in web requests',
      type: RULE_TYPES.SIGNATURE,
      severity: 'critical',
      category: 'web',
      threatType: 'sql_injection',
      condition: {
        eventCategory: 'web',
        message: { $regex: '.*(OR|UNION|SELECT|DROP).*' }
      },
      actions: [
        {
          type: 'alert',
          configuration: {
            priority: 'critical',
            notify: true
          }
        }
      ],
      enabled: true,
      priority: 10,
      cooldown: 30,
      tags: ['web_attack', 'sql_injection']
    },
    {
      name: 'Malware Communication Detection',
      description: 'Detects communication with known malicious domains',
      type: RULE_TYPES.SIGNATURE,
      severity: 'critical',
      category: 'malware',
      threatType: 'malware_communication',
      condition: {
        eventCategory: 'malware',
        threatType: 'malware_communication'
      },
      actions: [
        {
          type: 'alert',
          configuration: {
            priority: 'critical',
            notify: true
          }
        }
      ],
      enabled: true,
      priority: 10,
      cooldown: 0,
      tags: ['malware', 'c2']
    },
    {
      name: 'Port Scan Detection',
      description: 'Detects port scanning activity from external sources',
      type: RULE_TYPES.SIGNATURE,
      severity: 'high',
      category: 'network',
      threatType: 'port_scan',
      condition: {
        eventCategory: 'network',
        eventType: 'Port Scan'
      },
      actions: [
        {
          type: 'alert',
          configuration: {
            priority: 'high',
            notify: true
          }
        }
      ],
      enabled: true,
      priority: 6,
      cooldown: 300,
      tags: ['reconnaissance', 'port_scan']
    }
  ],

  // Reports
  reports: [
    {
      title: 'Daily Security Report - Acme Corporation',
      description: 'Daily summary of security events and alerts',
      type: 'daily',
      format: 'pdf',
      status: 'completed',
      filters: {
        startDate: new Date(Date.now() - 24 * 60 * 60 * 1000),
        endDate: new Date(),
        severity: ['critical', 'high', 'medium']
      },
      data: {
        summary: {
          total: 156,
          critical: 5,
          high: 23,
          medium: 45,
          low: 83,
          byStatus: {
            active: 12,
            investigating: 8,
            resolved: 136
          }
        },
        categories: [
          { name: 'authentication', count: 45 },
          { name: 'network', count: 38 },
          { name: 'web', count: 32 },
          { name: 'system', count: 41 }
        ]
      },
      tags: ['daily', 'security']
    }
  ],

  // Audit Logs
  auditLogs: [
    {
      action: 'login',
      resource: 'authentication',
      resourceName: 'superadmin@sentinel-soc.com',
      status: 'success',
      severity: 'info',
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0 Chrome/120.0.0.0'
    },
    {
      action: 'user_created',
      resource: 'user',
      resourceName: 'jsmith',
      status: 'success',
      severity: 'medium',
      ipAddress: '192.168.1.101'
    },
    {
      action: 'alert_created',
      resource: 'alert',
      resourceName: 'SQL Injection Attempt',
      status: 'success',
      severity: 'info',
      ipAddress: '192.168.1.102'
    },
    {
      action: 'incident_created',
      resource: 'incident',
      resourceName: 'Ransomware Outbreak Investigation',
      status: 'success',
      severity: 'info',
      ipAddress: '192.168.1.103'
    }
  ]
};

/**
 * Main seed function
 */
async function seedDatabase() {
  try {
    console.log('🚀 Starting database seed...');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

    // Get MongoDB URI
    let mongoURI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/sentinel_soc';
    
    console.log(`📡 Connecting to MongoDB at: ${mongoURI}`);
    
    // Connect with IPv4 preference
    await mongoose.connect(mongoURI, {
      serverSelectionTimeoutMS: 3000,
      socketTimeoutMS: 45000,
      family: 4
    });
    
    console.log('✅ Connected to MongoDB');

    // Clear existing data
    console.log('🧹 Clearing existing data...');
    await Organization.deleteMany({});
    await User.deleteMany({});
    await Asset.deleteMany({});
    await LogSource.deleteMany({});
    await Log.deleteMany({});
    await Alert.deleteMany({});
    await Incident.deleteMany({});
    await IOC.deleteMany({});
    await ThreatRule.deleteMany({});
    await Report.deleteMany({});
    await AuditLog.deleteMany({});
    await Settings.deleteMany({});
    
    // Clear NEW modules
    await NetworkTopology.deleteMany({});
    await SecuritySensor.deleteMany({});
    await SecurityControl.deleteMany({});
    await SecurityTest.deleteMany({});
    await SecurityAssessment.deleteMany({});
    console.log('✅ Data cleared');

    // Seed Organizations
    console.log('\n🏢 Seeding Organizations...');
    const createdOrgs = [];
    for (const orgData of seedData.organizations) {
      const org = new Organization(orgData);
      await org.save();
      createdOrgs.push(org);
      console.log(`  ✅ Created: ${org.name} (${org.code})`);
    }

    // Seed Users
    console.log('\n👤 Seeding Users...');
    const createdUsers = [];
    for (const userData of seedData.users) {
      const org = createdOrgs.find(o => o.name === userData.organizationName);
      if (!org) {
        console.log(`  ⚠️ Organization not found for ${userData.email}, skipping...`);
        continue;
      }

      const user = new User({
        ...userData,
        organization: org._id,
        createdBy: null
      });
      await user.save();
      createdUsers.push(user);
      console.log(`  ✅ Created: ${user.email} (${user.role}) - ${org.name}`);
    }

    // Update superadmin to be createdBy for other users
    const superadmin = createdUsers.find(u => u.role === ROLES.SUPER_ADMIN);
    if (superadmin) {
      for (const user of createdUsers) {
        if (user._id.toString() !== superadmin._id.toString()) {
          user.createdBy = superadmin._id;
          await user.save();
        }
      }
    }

    // Seed Assets
    console.log('\n🖥️ Seeding Assets...');
    const createdAssets = [];
    const assetMap = {};
    for (const assetData of seedData.assets) {
      const org = createdOrgs.find(o => o.name === assetData.organizationName);
      if (!org) {
        console.log(`  ⚠️ Organization not found for ${assetData.name}, skipping...`);
        continue;
      }

      const asset = new Asset({
        ...assetData,
        organization: org._id,
        createdBy: superadmin?._id
      });
      await asset.save();
      createdAssets.push(asset);
      assetMap[assetData.hostname] = asset._id;
      console.log(`  ✅ Created: ${asset.name} (${asset.type}) - ${org.name}`);
    }

    // Seed Log Sources
    console.log('\n📊 Seeding Log Sources...');
    const createdSources = [];
    for (const sourceData of seedData.logSources) {
      const org = createdOrgs.find(o => o.name === sourceData.organizationName);
      if (!org) {
        console.log(`  ⚠️ Organization not found for ${sourceData.sourceName}, skipping...`);
        continue;
      }

      const assetId = assetMap[sourceData.assetHostname];
      if (!assetId) {
        console.log(`  ⚠️ Asset not found for ${sourceData.assetHostname}, skipping...`);
        continue;
      }

      const source = new LogSource({
        ...sourceData,
        organization: org._id,
        asset: assetId,
        authenticationToken: generateToken(),
        createdBy: superadmin?._id
      });
      await source.save();
      createdSources.push(source);
      console.log(`  ✅ Created: ${source.sourceName} (${source.sourceType}) - ${org.name}`);
    }

    // Seed Logs
    console.log('\n📝 Seeding Logs...');
    const createdLogs = [];
    for (const logData of seedData.logs) {
      const org = createdOrgs[0];
      const asset = createdAssets[0];
      const source = createdSources.find(s => 
        s.organization.toString() === org._id.toString() && 
        s.sourceType === logData.sourceType
      );

      if (!source) {
        console.log(`  ⚠️ Source not found for ${logData.sourceType}, skipping...`);
        continue;
      }

      const log = new Log({
        ...logData,
        organization: org._id,
        asset: asset?._id,
        logSource: source._id,
        hostname: source.hostname,
        ipAddress: source.ipAddress,
        eventTime: randomDate(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), new Date()),
        ingestionTime: new Date(),
        rawLog: logData.rawLog || {}
      });
      await log.save();
      createdLogs.push(log);
      console.log(`  ✅ Created: ${log.eventType} - ${log.sourceType}`);
    }

    // Seed Alerts
    console.log('\n🔔 Seeding Alerts...');
    const createdAlerts = [];
    for (const alertData of seedData.alerts) {
      const org = createdOrgs[0];
      const asset = createdAssets[0];
      const source = createdSources[0];
      const log = createdLogs[0];

      const alert = new Alert({
        ...alertData,
        organization: org._id,
        asset: asset?._id,
        logSource: source?._id,
        log: log?._id,
        createdBy: superadmin?._id,
        riskScore: alertData.severity === 'critical' ? 8 : 
                   alertData.severity === 'high' ? 6 : 
                   alertData.severity === 'medium' ? 4 : 2
      });
      await alert.save();
      createdAlerts.push(alert);
      console.log(`  ✅ Created: ${alert.title} (${alert.severity})`);
    }

    // Seed Incidents
    console.log('\n🎫 Seeding Incidents...');
    const createdIncidents = [];
    for (const incidentData of seedData.incidents) {
      const org = createdOrgs[0];
      
      const incident = new Incident({
        ...incidentData,
        organization: org._id,
        createdBy: superadmin?._id,
        discoveredAt: randomDate(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), new Date()),
        alerts: createdAlerts.slice(0, 2).map(a => a._id)
      });
      await incident.save();
      createdIncidents.push(incident);
      console.log(`  ✅ Created: ${incident.title} (${incident.severity})`);
    }

    // Seed IOCs
    console.log('\n🔍 Seeding IOCs...');
    for (const iocData of seedData.iocs) {
      const org = createdOrgs[0];
      
      const ioc = new IOC({
        ...iocData,
        organization: org._id,
        createdBy: superadmin?._id,
        firstSeen: randomDate(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), new Date())
      });
      await ioc.save();
      console.log(`  ✅ Created: ${ioc.indicator} (${ioc.type})`);
    }

    // Seed Threat Rules
    console.log('\n📋 Seeding Threat Rules...');
    const createdRules = [];
    for (const ruleData of seedData.threatRules) {
      const org = createdOrgs[0];
      
      const rule = new ThreatRule({
        ...ruleData,
        organization: org._id,
        createdBy: superadmin?._id
      });
      await rule.save();
      createdRules.push(rule);
      console.log(`  ✅ Created: ${rule.name} (${rule.type})`);
    }

    // NEW: Seed Network Topologies
    console.log('\n🌐 Seeding Network Topologies...');
    for (const topologyData of seedData.networkTopologies) {
      const org = createdOrgs.find(o => o.name === topologyData.organizationName);
      if (!org) {
        console.log(`  ⚠️ Organization not found for ${topologyData.name}, skipping...`);
        continue;
      }

      const topology = new NetworkTopology({
        ...topologyData,
        organization: org._id,
        createdBy: superadmin?._id,
        updatedBy: superadmin?._id
      });
      await topology.save();
      console.log(`  ✅ Created: ${topology.name} - ${org.name}`);
    }

    // NEW: Seed Security Sensors
    console.log('\n📡 Seeding Security Sensors...');
    const createdSensors = [];
    for (const sensorData of seedData.securitySensors) {
      const org = createdOrgs.find(o => o.name === sensorData.organizationName);
      if (!org) {
        console.log(`  ⚠️ Organization not found for ${sensorData.name}, skipping...`);
        continue;
      }

      const sensor = new SecuritySensor({
        ...sensorData,
        organization: org._id,
        createdBy: superadmin?._id,
        updatedBy: superadmin?._id
      });
      await sensor.save();
      createdSensors.push(sensor);
      console.log(`  ✅ Created: ${sensor.name} (${sensor.type}) - ${org.name}`);
    }

    // NEW: Seed Security Controls
// NEW: Seed Security Controls
console.log('\n🛡️ Seeding Security Controls...');
// First, get all created threat rules for mapping
const allThreatRules = await ThreatRule.find({});
console.log(`  Found ${allThreatRules.length} threat rules for mapping`);

for (const controlData of seedData.securityControls) {
  const org = createdOrgs.find(o => o.name === controlData.organizationName);
  if (!org) {
    console.log(`  ⚠️ Organization not found for ${controlData.threatName}, skipping...`);
    continue;
  }

  // Find matching threat rule - more flexible mapping
  let threatRule = null;
  
  // Try exact match first
  const threatTypeMap = {
    'SSH Brute Force Attack': 'brute_force',
    'Brute Force Attack': 'brute_force',
    'SQL Injection Attack': 'sql_injection',
    'Malware Communication': 'malware_communication',
    'Port Scan Detection': 'port_scan'
  };
  
  const mappedType = threatTypeMap[controlData.threatName];
  if (mappedType) {
    threatRule = allThreatRules.find(r => r.threatType === mappedType);
  }
  
  // If not found by mapped type, try partial match
  if (!threatRule) {
    const searchTerms = controlData.threatName.toLowerCase().split(' ');
    threatRule = allThreatRules.find(r => {
      const ruleName = r.name.toLowerCase();
      return searchTerms.some(term => ruleName.includes(term) && term.length > 3);
    });
  }
  
  // If still not found, try to find by category
  if (!threatRule) {
    const categoryMap = {
      'SSH Brute Force Attack': 'authentication',
      'SQL Injection Attack': 'web',
      'Malware Communication': 'malware'
    };
    const category = categoryMap[controlData.threatName];
    if (category) {
      threatRule = allThreatRules.find(r => r.category === category);
    }
  }

  const control = new SecurityControl({
    ...controlData,
    organization: org._id,
    threatRule: threatRule?._id || null,
    createdBy: superadmin?._id,
    updatedBy: superadmin?._id
  });
  
  try {
    await control.save();
    console.log(`  ✅ Created: ${control.threatName} - ${org.name}${threatRule ? ` (linked to: ${threatRule.name})` : ' (no rule linked)'}`);
  } catch (error) {
    console.log(`  ⚠️ Failed to create ${controlData.threatName}: ${error.message}`);
  }
}

    // NEW: Seed Security Tests
    console.log('\n🧪 Seeding Security Tests...');
    for (const testData of seedData.securityTests) {
      const org = createdOrgs.find(o => o.name === testData.organizationName);
      if (!org) {
        console.log(`  ⚠️ Organization not found for ${testData.name}, skipping...`);
        continue;
      }

      // Find matching threat rule for expected detection
      const threatRule = createdRules.find(r => 
        r.threatType === testData.testType
      );

      const test = new SecurityTest({
        ...testData,
        organization: org._id,
        expectedDetection: threatRule?._id || null,
        createdBy: superadmin?._id
      });
      await test.save();
      console.log(`  ✅ Created: ${test.name} (${test.testType}) - ${org.name}`);
    }

    // NEW: Seed Security Assessments
    console.log('\n📋 Seeding Security Assessments...');
    for (const assessmentData of seedData.securityAssessments) {
      const org = createdOrgs.find(o => o.name === assessmentData.organizationName);
      if (!org) {
        console.log(`  ⚠️ Organization not found for ${assessmentData.title}, skipping...`);
        continue;
      }

      // Link some alerts and incidents to the assessment
      const alerts = createdAlerts.slice(0, 2).map(a => a._id);
      const incidents = createdIncidents.slice(0, 1).map(i => i._id);
      const assets = createdAssets.slice(0, 2).map(a => a._id);

      const assessment = new SecurityAssessment({
        ...assessmentData,
        organization: org._id,
        threatsDetected: alerts,
        incidents: incidents,
        affectedAssets: assets,
        createdBy: superadmin?._id
      });
      await assessment.save();
      console.log(`  ✅ Created: ${assessment.title} (${assessment.riskLevel}) - ${org.name}`);
    }

    // Seed Reports
    console.log('\n📄 Seeding Reports...');
    for (const reportData of seedData.reports) {
      const org = createdOrgs[0];
      
      const report = new Report({
        ...reportData,
        organization: org._id,
        createdBy: superadmin?._id,
        generatedBy: superadmin?._id,
        generatedAt: new Date()
      });
      await report.save();
      console.log(`  ✅ Created: ${report.title} (${report.type})`);
    }

    // Seed Audit Logs
    console.log('\n📜 Seeding Audit Logs...');
    for (const auditLogData of seedData.auditLogs) {
      const org = createdOrgs[0];
      const user = createdUsers[0];
      
      const auditLog = new AuditLog({
        ...auditLogData,
        organization: org._id,
        user: user?._id,
        performedBy: user?._id
      });
      await auditLog.save();
      console.log(`  ✅ Created: ${auditLog.action} - ${auditLog.resource}`);
    }

    // Print summary
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('✅ Database seeding completed successfully!');
    console.log('📊 Summary:');
    console.log(`  Organizations: ${createdOrgs.length}`);
    console.log(`  Users: ${createdUsers.length}`);
    console.log(`  Assets: ${createdAssets.length}`);
    console.log(`  Log Sources: ${createdSources.length}`);
    console.log(`  Logs: ${createdLogs.length}`);
    console.log(`  Alerts: ${createdAlerts.length}`);
    console.log(`  Incidents: ${createdIncidents.length}`);
    console.log(`  IOCs: ${seedData.iocs.length}`);
    console.log(`  Threat Rules: ${seedData.threatRules.length}`);
    console.log(`  Reports: ${seedData.reports.length}`);
    console.log(`  Audit Logs: ${seedData.auditLogs.length}`);
    console.log(`\n🆕 NEW Modules:`);
    console.log(`  Network Topologies: ${seedData.networkTopologies.length}`);
    console.log(`  Security Sensors: ${seedData.securitySensors.length}`);
    console.log(`  Security Controls: ${seedData.securityControls.length}`);
    console.log(`  Security Tests: ${seedData.securityTests.length}`);
    console.log(`  Security Assessments: ${seedData.securityAssessments.length}`);

    // Print log source authentication tokens for simulators
    console.log('\n🔑 Log Source Authentication Tokens for Simulators:');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    for (const source of createdSources) {
      if (['Windows', 'Linux', 'Apache', 'Nginx', 'Suricata', 'Snort', 'pfSense'].includes(source.sourceType)) {
        const type = source.sourceType.toUpperCase() === 'PFSENSE' ? 'FIREWALL' : source.sourceType.toUpperCase();
        console.log(`${type}_SOURCE_ID=${source._id}`);
        console.log(`${type}_AUTH_TOKEN=${source.authenticationToken}`);
        console.log('---');
      }
    }

    // Print login credentials
    console.log('\n🔐 Login Credentials:');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('Super Admin: superadmin@sentinel-soc.com / SuperAdmin@2024!');
    console.log('Security Admin: securityadmin@acme.com / Security@2024!');
    console.log('Analyst: analyst@acme.com / Analyst@2024!');
    console.log('Responder: responder@acme.com / Responder@2024!');
    console.log('Auditor: auditor@acme.com / Auditor@2024!');

    // Close connection
    await mongoose.disconnect();
    console.log('\n🔌 Disconnected from MongoDB');

  } catch (error) {
    console.error('❌ Error seeding database:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

// Run the seed script
if (require.main === module) {
  seedDatabase();
}

module.exports = { seedDatabase };