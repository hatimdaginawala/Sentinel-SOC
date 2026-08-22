// config.js
const dotenv = require('dotenv');
const path = require('path');

// Load .env from the same directory
dotenv.config({ path: path.join(__dirname, '.env') });

// Default API URL
const DEFAULT_API_URL = process.env.API_URL || 'http://localhost:3000/api/v1/logs/ingest';

// Build LOG_SOURCES from environment variables
const LOG_SOURCES = {};

// Helper to add sources for an organization
function addOrgSources(orgCode) {
  const prefix = orgCode.toUpperCase();
  const org = {
    windows: {
      sourceId: process.env[`${prefix}_WINDOWS_SOURCE_ID`],
      authToken: process.env[`${prefix}_WINDOWS_AUTH_TOKEN`]
    },
    linux: {
      sourceId: process.env[`${prefix}_LINUX_SOURCE_ID`],
      authToken: process.env[`${prefix}_LINUX_AUTH_TOKEN`]
    },
    apache: {
      sourceId: process.env[`${prefix}_APACHE_SOURCE_ID`],
      authToken: process.env[`${prefix}_APACHE_AUTH_TOKEN`]
    },
    nginx: {
      sourceId: process.env[`${prefix}_NGINX_SOURCE_ID`],
      authToken: process.env[`${prefix}_NGINX_AUTH_TOKEN`]
    },
    suricata: {
      sourceId: process.env[`${prefix}_SURICATA_SOURCE_ID`],
      authToken: process.env[`${prefix}_SURICATA_AUTH_TOKEN`]
    },
    snort: {
      sourceId: process.env[`${prefix}_SNORT_SOURCE_ID`],
      authToken: process.env[`${prefix}_SNORT_AUTH_TOKEN`]
    },
    firewall: {
      sourceId: process.env[`${prefix}_FIREWALL_SOURCE_ID`],
      authToken: process.env[`${prefix}_FIREWALL_AUTH_TOKEN`]
    }
  };
  
  // Filter out sources that don't have IDs
  const filteredOrg = {};
  for (const [type, source] of Object.entries(org)) {
    if (source.sourceId && source.authToken) {
      filteredOrg[type] = source;
    }
  }
  
  return filteredOrg;
}

// Add all organizations
const orgs = ['acme', 'gfi', 'hcs'];
for (const org of orgs) {
  const sources = addOrgSources(org);
  if (Object.keys(sources).length > 0) {
    LOG_SOURCES[org] = sources;
  }
}

// Add generic sources (fallback)
const GENERIC_SOURCES = {
  windows: {
    sourceId: process.env.WINDOWS_SOURCE_ID,
    authToken: process.env.WINDOWS_AUTH_TOKEN
  },
  linux: {
    sourceId: process.env.LINUX_SOURCE_ID,
    authToken: process.env.LINUX_AUTH_TOKEN
  },
  apache: {
    sourceId: process.env.APACHE_SOURCE_ID,
    authToken: process.env.APACHE_AUTH_TOKEN
  },
  nginx: {
    sourceId: process.env.NGINX_SOURCE_ID,
    authToken: process.env.NGINX_AUTH_TOKEN
  },
  suricata: {
    sourceId: process.env.SURICATA_SOURCE_ID,
    authToken: process.env.SURICATA_AUTH_TOKEN
  },
  snort: {
    sourceId: process.env.SNORT_SOURCE_ID,
    authToken: process.env.SNORT_AUTH_TOKEN
  },
  firewall: {
    sourceId: process.env.FIREWALL_SOURCE_ID,
    authToken: process.env.FIREWALL_AUTH_TOKEN
  }
};

// Validate and filter generic sources
const VALID_GENERIC_SOURCES = {};
for (const [type, source] of Object.entries(GENERIC_SOURCES)) {
  if (source.sourceId && source.authToken) {
    VALID_GENERIC_SOURCES[type] = source;
  }
}

// Log missing sources
console.log('🔍 Config loaded:');
console.log(`  Organizations: ${Object.keys(LOG_SOURCES).join(', ')}`);
console.log(`  Generic sources: ${Object.keys(VALID_GENERIC_SOURCES).join(', ')}`);

// Get random organization
function getRandomOrganization() {
  const orgs = Object.keys(LOG_SOURCES);
  if (orgs.length === 0) {
    console.warn('⚠️ No organizations found in .env file!');
    return null;
  }
  return orgs[Math.floor(Math.random() * orgs.length)];
}

// Get random source for a specific organization and type
function getRandomSourceForOrg(org, type) {
  // First try to get the specific source for the organization
  const orgSources = LOG_SOURCES[org];
  if (orgSources) {
    if (type && orgSources[type]) {
      return orgSources[type];
    }
    // If type not found, return random source from this org
    const types = Object.keys(orgSources);
    if (types.length > 0) {
      const randomType = types[Math.floor(Math.random() * types.length)];
      return orgSources[randomType];
    }
  }
  
  // Fallback to generic source
  if (type && VALID_GENERIC_SOURCES[type]) {
    console.log(`⚠️ Using generic ${type} source for ${org}`);
    return VALID_GENERIC_SOURCES[type];
  }
  
  // Last resort: try to find any generic source
  const genericTypes = Object.keys(VALID_GENERIC_SOURCES);
  if (genericTypes.length > 0) {
    const fallbackType = genericTypes[0];
    console.log(`⚠️ Using generic ${fallbackType} source as fallback for ${org}`);
    return VALID_GENERIC_SOURCES[fallbackType];
  }
  
  console.log(`❌ No source found for ${org} (${type})`);
  return null;
}

// Get random source for any organization
function getRandomSource(type) {
  const org = getRandomOrganization();
  if (!org) return null;
  const source = getRandomSourceForOrg(org, type);
  if (source) {
    return { ...source, organization: org };
  }
  return null;
}

// Validate all sources
function validateSources() {
  let valid = true;
  
  for (const org of Object.keys(LOG_SOURCES)) {
    const sources = LOG_SOURCES[org];
    for (const [type, source] of Object.entries(sources)) {
      if (!source.sourceId || !source.authToken) {
        console.log(`⚠️ Missing ${type} source for ${org}`);
        valid = false;
      }
    }
  }
  
  // Check generic sources
  for (const [type, source] of Object.entries(VALID_GENERIC_SOURCES)) {
    if (!source.sourceId || !source.authToken) {
      console.log(`⚠️ Missing generic ${type} source`);
      valid = false;
    }
  }
  
  return valid;
}

// Export configuration
module.exports = {
  DEFAULT_API_URL,
  LOG_SOURCES,
  GENERIC_SOURCES: VALID_GENERIC_SOURCES,
  getRandomOrganization,
  getRandomSourceForOrg,
  getRandomSource,
  getRandomSourceForType: getRandomSource,
  validateSources
};