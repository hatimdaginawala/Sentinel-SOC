/**
 * Database Seed Script - Complete
 * Populates the database with comprehensive test data for all modules
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

  // Log Sources
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
    {
      sourceType: 'Windows',
      eventCategory: 'system',
      eventType: 'Account Locked',
      severity: 'high',
      message: 'Account locked for user admin after 5 failed attempts',
      username: 'admin',
      sourceIP: '192.168.1.102',
      rawLog: {
        eventId: 4740,
        lockoutDuration: 30,
        attempts: 5
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
    {
      sourceType: 'Linux',
      eventCategory: 'access',
      eventType: 'sudo Execution',
      severity: 'low',
      message: 'User jsmith executed sudo command: systemctl restart apache2',
      username: 'jsmith',
      sourceIP: '192.168.1.101',
      rawLog: {
        pid: 12347,
        command: 'systemctl restart apache2',
        tty: 'pts/1'
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
    {
      sourceType: 'Apache',
      eventCategory: 'web',
      eventType: '404 Not Found',
      severity: 'medium',
      message: '404 Not Found: /wp-admin (probing attempt)',
      sourceIP: '89.45.67.23',
      destinationIP: '192.168.1.10',
      rawLog: {
        method: 'GET',
        uri: '/wp-admin',
        status: 404,
        referer: '-'
      }
    },
    // Nginx Events
    {
      sourceType: 'Nginx',
      eventCategory: 'web',
      eventType: 'Reverse Proxy Error',
      severity: 'high',
      message: '502 Bad Gateway from upstream server backend-01:8080',
      sourceIP: '192.168.1.101',
      destinationIP: '192.168.1.70',
      rawLog: {
        method: 'GET',
        uri: '/api/users',
        status: 502,
        upstream: 'backend-01:8080',
        upstream_response_time: 3.456
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
    // Snort Events
    {
      sourceType: 'Snort',
      eventCategory: 'network',
      eventType: 'Port Scan',
      severity: 'high',
      message: 'Port scan detected from 185.130.5.10 targeting multiple ports',
      sourceIP: '185.130.5.10',
      destinationIP: '192.168.1.10',
      rawLog: {
        rule: {
          sid: 1000001,
          name: 'Port Scan Detected',
          category: 'ATTACK',
          severity: 'high',
          msg: 'Port scanning activity detected from source'
        },
        protocol: 'TCP',
        scanned_ports: [22, 80, 443, 3306, 5432]
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
    },
    {
      title: 'Port Scan Detected',
      description: 'Port scan detected from external IP 185.130.5.10',
      severity: 'high',
      category: 'network',
      threatType: 'port_scan',
      sourceIP: '185.130.5.10',
      destinationIP: '192.168.1.10',
      confidence: 80,
      tags: ['port_scan', 'reconnaissance'],
      status: 'active'
    },
    {
      title: 'Suspicious PowerShell Activity',
      description: 'PowerShell execution with suspicious parameters detected',
      severity: 'high',
      category: 'system',
      threatType: 'suspicious_powershell',
      sourceIP: '192.168.1.101',
      confidence: 75,
      tags: ['powershell', 'suspicious'],
      status: 'investigating'
    },
    {
      title: 'DDoS Attack Pattern Detected',
      description: 'Potential DDoS attack pattern detected from multiple sources',
      severity: 'critical',
      category: 'network',
      threatType: 'ddos',
      sourceIP: '212.102.40.15',
      destinationIP: '192.168.1.10',
      confidence: 70,
      tags: ['ddos', 'attack'],
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
      affectedAssets: [
        { impact: 'compromised', notes: 'Files encrypted' }
      ],
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
      tags: ['phishing', 'social_engineering'],
      affectedUsers: [
        { impact: 'affected' }
      ]
    },
    {
      title: 'Data Breach Investigation',
      description: 'Sensitive customer data potentially exfiltrated through unauthorized access',
      severity: 'critical',
      category: 'data_breach',
      status: 'in_progress',
      detectionSource: 'automated',
      tags: ['data_breach', 'pci'],
      affectedAssets: [
        { impact: 'compromised' }
      ]
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
      type: 'ip',
      value: '212.102.40.15',
      indicator: '212.102.40.15',
      description: 'Known IP associated with DDoS botnet',
      severity: 'high',
      confidence: 85,
      source: 'threat_intelligence',
      threatType: 'botnet',
      tags: ['ddos', 'botnet']
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
    },
    {
      type: 'email',
      value: 'phishing@malicious.com',
      indicator: 'phishing@malicious.com',
      description: 'Email address used in phishing campaigns',
      severity: 'high',
      confidence: 80,
      source: 'community',
      threatType: 'phishing',
      tags: ['phishing', 'email']
    },
    {
      type: 'url',
      value: 'https://malicious-payload.com/download.exe',
      indicator: 'https://malicious-payload.com/download.exe',
      description: 'Known malicious payload URL',
      severity: 'critical',
      confidence: 90,
      source: 'threat_intelligence',
      threatType: 'malware',
      tags: ['malware', 'payload']
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
        eventType: 'Failed Login',
        $or: [
          { sourceIP: { $regex: '.*' } },
          { username: { $regex: '.*' } }
        ]
      },
      actions: [
        {
          type: 'alert',
          configuration: {
            priority: 'high',
            notify: true
          }
        },
        {
          type: 'block',
          configuration: {
            duration: 300,
            source: 'sourceIP'
          }
        }
      ],
      enabled: true,
      priority: 8,
      cooldown: 60,
      suppression: {
        enabled: true,
        threshold: 5,
        duration: 300
      },
      tags: ['brute_force', 'authentication'],
      references: ['https://owasp.org/brute-force']
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
        $or: [
          { message: { $regex: '.*(OR|UNION|SELECT|DROP).*' } },
          { rawLog: { $regex: '.*(OR|UNION|SELECT|DROP).*' } }
        ]
      },
      actions: [
        {
          type: 'alert',
          configuration: {
            priority: 'critical',
            notify: true
          }
        },
        {
          type: 'block',
          configuration: {
            duration: 600,
            source: 'sourceIP'
          }
        }
      ],
      enabled: true,
      priority: 10,
      cooldown: 30,
      tags: ['web_attack', 'sql_injection'],
      references: ['https://owasp.org/sql-injection']
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
        },
        {
          type: 'isolate',
          configuration: {
            duration: 3600,
            target: 'asset'
          }
        }
      ],
      enabled: true,
      priority: 10,
      cooldown: 0,
      tags: ['malware', 'c2'],
      references: ['https://www.mandiant.com/malware']
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
      tags: ['reconnaissance', 'port_scan'],
      references: ['https://en.wikipedia.org/wiki/Port_scanner']
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
    console.log('🌱 Starting database seed...');
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

    // Clear existing data (comment out if you want to keep existing data)
    console.log('🗑️ Clearing existing data...');
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
    console.log('✅ Data cleared');

    // Seed Organizations
    console.log('\n📋 Seeding Organizations...');
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
    console.log('\n💻 Seeding Assets...');
    const createdAssets = [];
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
      console.log(`  ✅ Created: ${asset.name} (${asset.type}) - ${org.name}`);
    }

    // Seed Log Sources
    console.log('\n📡 Seeding Log Sources...');
    const createdSources = [];
    for (const sourceData of seedData.logSources) {
      const org = createdOrgs.find(o => o.name === sourceData.organizationName);
      if (!org) {
        console.log(`  ⚠️ Organization not found for ${sourceData.sourceName}, skipping...`);
        continue;
      }

      const asset = createdAssets.find(a => 
        a.hostname === sourceData.assetHostname && 
        a.organization.toString() === org._id.toString()
      );
      
      if (!asset) {
        console.log(`  ⚠️ Asset not found for ${sourceData.assetHostname}, skipping...`);
        continue;
      }

      const source = new LogSource({
        ...sourceData,
        organization: org._id,
        asset: asset._id,
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
      const org = createdOrgs[0]; // Acme Corporation
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
    console.log('\n🚨 Seeding Alerts...');
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
    console.log('\n📋 Seeding Incidents...');
    const createdIncidents = [];
    for (const incidentData of seedData.incidents) {
      const org = createdOrgs[0];
      
      const incident = new Incident({
        ...incidentData,
        organization: org._id,
        createdBy: superadmin?._id,
        discoveredAt: randomDate(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), new Date()),
        alerts: createdAlerts.slice(0, 2).map(a => a._id),
        affectedAssets: incidentData.affectedAssets?.map(asset => ({
          ...asset,
          asset: createdAssets[0]?._id
        })) || []
      });
      await incident.save();
      createdIncidents.push(incident);
      console.log(`  ✅ Created: ${incident.title} (${incident.severity})`);
    }

    // Seed IOCs
    console.log('\n🔍 Seeding IOCs...');
    const createdIOCs = [];
    for (const iocData of seedData.iocs) {
      const org = createdOrgs[0];
      
      const ioc = new IOC({
        ...iocData,
        organization: org._id,
        createdBy: superadmin?._id,
        firstSeen: randomDate(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), new Date())
      });
      await ioc.save();
      createdIOCs.push(ioc);
      console.log(`  ✅ Created: ${ioc.indicator} (${ioc.type})`);
    }

    // Seed Threat Rules
    console.log('\n📏 Seeding Threat Rules...');
    for (const ruleData of seedData.threatRules) {
      const org = createdOrgs[0];
      
      const rule = new ThreatRule({
        ...ruleData,
        organization: org._id,
        createdBy: superadmin?._id
      });
      await rule.save();
      console.log(`  ✅ Created: ${rule.name} (${rule.type})`);
    }

    // Seed Reports
    console.log('\n📊 Seeding Reports...');
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
    console.log('\n📝 Seeding Audit Logs...');
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
    console.log(`📊 Summary:`);
    console.log(`  📋 Organizations: ${createdOrgs.length}`);
    console.log(`  👤 Users: ${createdUsers.length}`);
    console.log(`  💻 Assets: ${createdAssets.length}`);
    console.log(`  📡 Log Sources: ${createdSources.length}`);
    console.log(`  📝 Logs: ${createdLogs.length}`);
    console.log(`  🚨 Alerts: ${createdAlerts.length}`);
    console.log(`  📋 Incidents: ${createdIncidents.length}`);
    console.log(`  🔍 IOCs: ${createdIOCs.length}`);
    console.log(`  📏 Threat Rules: ${seedData.threatRules.length}`);
    console.log(`  📊 Reports: ${seedData.reports.length}`);
    console.log(`  📝 Audit Logs: ${seedData.auditLogs.length}`);

    // Print authentication details for simulators
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