/**
 * Database Seed Script - Updated with better error handling
 * Populates the database with initial data for testing
 * 
 * Run: node src/seed.js
 */

const mongoose = require('mongoose');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Import models
const User = require('./models/User');
const Organization = require('./models/Organization');
const Asset = require('./models/Asset');
const LogSource = require('./models/LogSource');
const { ROLES, ASSET_TYPES } = require('./config/constants');

// Import logger
const logger = require('./config/logger');

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

  // Users (passwords are hashed automatically by the model)
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
    // Acme Corporation - Windows
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
    // Acme Corporation - Linux
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
    // Acme Corporation - Apache
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
    // Acme Corporation - Nginx
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
    // Acme Corporation - pfSense
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
    // Global Finance Inc - Windows
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
    // Global Finance Inc - Linux
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
    // Healthcare Systems - Windows
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
  ]
};

/**
 * Main seed function
 */
async function seedDatabase() {
  try {
    console.log('🌱 Starting database seed...');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

    // Get MongoDB URI from environment or use default
    let mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/sentinel_soc';
    
    // If using localhost and connection fails, try 127.0.0.1 instead of ::1
    if (mongoURI.includes('localhost')) {
      console.log('📡 Using localhost, will try 127.0.0.1 if connection fails...');
    }

    console.log(`📡 Connecting to MongoDB at: ${mongoURI}`);
    
    // Connect with timeout options
    await mongoose.connect(mongoURI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    
    console.log('✅ Connected to MongoDB');

    // Clear existing data (optional - comment out if you want to keep existing data)
    console.log('🗑️ Clearing existing data...');
    await Organization.deleteMany({});
    await User.deleteMany({});
    await Asset.deleteMany({});
    await LogSource.deleteMany({});
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
        createdBy: null // Will be set later if needed
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

      // Find asset by hostname
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
        createdBy: superadmin?._id
      });
      await source.save();
      createdSources.push(source);
      console.log(`  ✅ Created: ${source.sourceName} (${source.sourceType}) - ${org.name}`);
      console.log(`     🔑 Auth Token: ${source.authenticationToken}`);
      console.log(`     🆔 Source ID: ${source._id}`);
    }

    // Print summary
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('✅ Database seeding completed successfully!');
    console.log(`📊 Summary:`);
    console.log(`  📋 Organizations: ${createdOrgs.length}`);
    console.log(`  👤 Users: ${createdUsers.length}`);
    console.log(`  💻 Assets: ${createdAssets.length}`);
    console.log(`  📡 Log Sources: ${createdSources.length}`);
    
    // Print authentication details for simulators
    console.log('\n🔑 Log Source Authentication Tokens for Simulators:');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    for (const source of createdSources) {
      if (source.sourceType === 'Windows' || source.sourceType === 'Linux' || 
          source.sourceType === 'Apache' || source.sourceType === 'Nginx') {
        const type = source.sourceType.toUpperCase();
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
    console.error('💡 Troubleshooting tips:');
    console.error('   1. Make sure MongoDB is running: "net start MongoDB"');
    console.error('   2. Check if MongoDB is installed: "mongod --version"');
    console.error('   3. Try connecting to 127.0.0.1 instead of localhost');
    console.error('   4. Check your MONGODB_URI in .env file');
    console.error('   5. If using MongoDB Atlas, make sure IP is whitelisted');
    process.exit(1);
  }
}

// Run the seed script
if (require.main === module) {
  seedDatabase();
}

module.exports = { seedDatabase };