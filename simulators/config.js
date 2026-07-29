// config.js
const dotenv = require('dotenv');
const path = require('path');

// Load .env from the same directory
dotenv.config({ path: path.join(__dirname, '.env') });

// Default API URL
const DEFAULT_API_URL = 'http://localhost:3000/api/v1/logs/ingest';

// Multiple organization log sources with their IDs and tokens
const LOG_SOURCES = {
  acme: {
    windows: {
      sourceId: '6a6a3673aca2a6961c838026',
      authToken: '2f1ef8ee761d37ad889c66b39ac8f1acdedd605b5c529abd8f42f81b7a75fa3b'
    },
    linux: {
      sourceId: '6a6a3673aca2a6961c838028',
      authToken: '8d547e86bedc86ea3be59e5a4ba1458e1514570e11c8a41395e3ae17ace9731b'
    },
    apache: {
      sourceId: '6a6a3673aca2a6961c83802a',
      authToken: 'af51f588cf471d65940f2369fd7f464c631c3b6576c194d3fc89135b110209e3'
    },
    nginx: {
      sourceId: '6a6a3673aca2a6961c83802c',
      authToken: 'a464a2fde41ff41e5be958772cd01436d5a470808427bd11c951e9493d15cf0d'
    },
    suricata: {
      sourceId: '6a6a3673aca2a6961c83802e',
      authToken: '8ce2534c76f37e721edbccbab0814654c74c54a323ae7deedf4a55bab7e32768'
    },
    snort: {
      sourceId: '6a6a3673aca2a6961c838030',
      authToken: '124497f3d61ede8f99be28061ecfae8530e60c12681e75595e3da2fef766a019'
    },
    firewall: {
      sourceId: '6a6a3673aca2a6961c838032',
      authToken: '02fee53c80fa83d50a8762abf814ce4695c4c596049b62cb06361e156c27b0d2'
    }
  },
  gfi: {
windows: {
      sourceId: '6a6a3673aca2a6961c838026',
      authToken: '2f1ef8ee761d37ad889c66b39ac8f1acdedd605b5c529abd8f42f81b7a75fa3b'
    },
    linux: {
      sourceId: '6a6a3673aca2a6961c838028',
      authToken: '8d547e86bedc86ea3be59e5a4ba1458e1514570e11c8a41395e3ae17ace9731b'
    },
    apache: {
      sourceId: '6a6a3673aca2a6961c83802a',
      authToken: 'af51f588cf471d65940f2369fd7f464c631c3b6576c194d3fc89135b110209e3'
    },
    nginx: {
      sourceId: '6a6a3673aca2a6961c83802c',
      authToken: 'a464a2fde41ff41e5be958772cd01436d5a470808427bd11c951e9493d15cf0d'
    },
    suricata: {
      sourceId: '6a6a3673aca2a6961c83802e',
      authToken: '8ce2534c76f37e721edbccbab0814654c74c54a323ae7deedf4a55bab7e32768'
    },
    snort: {
      sourceId: '6a6a3673aca2a6961c838030',
      authToken: '124497f3d61ede8f99be28061ecfae8530e60c12681e75595e3da2fef766a019'
    },
    firewall: {
      sourceId: '6a6a3673aca2a6961c838032',
      authToken: '02fee53c80fa83d50a8762abf814ce4695c4c596049b62cb06361e156c27b0d2'
    }
    // GFI only has Windows and Linux sources
  },
  hcs: {
windows: {
      sourceId: '6a6a3673aca2a6961c838026',
      authToken: '2f1ef8ee761d37ad889c66b39ac8f1acdedd605b5c529abd8f42f81b7a75fa3b'
    },
    linux: {
      sourceId: '6a6a3673aca2a6961c838028',
      authToken: '8d547e86bedc86ea3be59e5a4ba1458e1514570e11c8a41395e3ae17ace9731b'
    },
    apache: {
      sourceId: '6a6a3673aca2a6961c83802a',
      authToken: 'af51f588cf471d65940f2369fd7f464c631c3b6576c194d3fc89135b110209e3'
    },
    nginx: {
      sourceId: '6a6a3673aca2a6961c83802c',
      authToken: 'a464a2fde41ff41e5be958772cd01436d5a470808427bd11c951e9493d15cf0d'
    },
    suricata: {
      sourceId: '6a6a3673aca2a6961c83802e',
      authToken: '8ce2534c76f37e721edbccbab0814654c74c54a323ae7deedf4a55bab7e32768'
    },
    snort: {
      sourceId: '6a6a3673aca2a6961c838030',
      authToken: '124497f3d61ede8f99be28061ecfae8530e60c12681e75595e3da2fef766a019'
    },
    firewall: {
      sourceId: '6a6a3673aca2a6961c838032',
      authToken: '02fee53c80fa83d50a8762abf814ce4695c4c596049b62cb06361e156c27b0d2'
    }
    // HCS only has Windows source
  }
};

// Get random organization
function getRandomOrganization() {
  const orgs = Object.keys(LOG_SOURCES);
  return orgs[Math.floor(Math.random() * orgs.length)];
}

// Get random source for a specific organization and type
function getRandomSourceForOrg(org, type) {
  const orgSources = LOG_SOURCES[org];
  if (!orgSources) return null;
  
  // If specific type requested, return that
  if (type && orgSources[type]) {
    return orgSources[type];
  }
  
  // Otherwise return random source from this org
  const types = Object.keys(orgSources);
  const randomType = types[Math.floor(Math.random() * types.length)];
  return orgSources[randomType];
}

// Get random source for any organization
function getRandomSource(type) {
  const org = getRandomOrganization();
  const source = getRandomSourceForOrg(org, type);
  return { ...source, organization: org };
}

// Export configuration
module.exports = {
  DEFAULT_API_URL,
  LOG_SOURCES,
  getRandomOrganization,
  getRandomSourceForOrg,
  getRandomSource,
  getRandomSourceForType: getRandomSource
};