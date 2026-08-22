// setup-simulators.js
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const API_BASE_URL = 'http://localhost:3000/api/v1';
const LOGIN_CREDENTIALS = {
  identifier: 'superadmin@sentinel-soc.com',
  password: 'SuperAdmin@2024!'
};

async function setupSimulators() {
  try {
    console.log('🔐 Logging in...');
    const loginRes = await axios.post(`${API_BASE_URL}/auth/login`, LOGIN_CREDENTIALS);
    const token = loginRes.data.data.accessToken;
    console.log('✅ Login successful');

    // Get organizations
    console.log('\n📋 Getting organizations...');
    const orgRes = await axios.get(`${API_BASE_URL}/organizations`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    const organizations = orgRes.data.data.items || [];
    console.log(`✅ Found ${organizations.length} organizations`);

    // Get all existing log sources
    console.log('\n📊 Fetching existing log sources...');
    const sourcesRes = await axios.get(`${API_BASE_URL}/log-sources`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const existingSources = sourcesRes.data.data.items || [];
    console.log(`✅ Found ${existingSources.length} existing log sources`);

    // Create a map of existing sources by organization and type
    const sourceMap = {};
    for (const source of existingSources) {
      const orgId = source.organization;
      const type = source.sourceType;
      if (!sourceMap[orgId]) sourceMap[orgId] = {};
      if (!sourceMap[orgId][type]) sourceMap[orgId][type] = [];
      sourceMap[orgId][type].push(source);
    }

    const sourceTypes = ['Windows', 'Linux', 'Apache', 'Nginx', 'Suricata', 'Snort', 'pfSense'];
    const envVars = {};

    for (const org of organizations) {
      console.log(`\n📋 Processing organization: ${org.name} (${org.code})`);
      
      // Find or create asset
      let orgAsset = null;
      try {
        const assetRes = await axios.get(`${API_BASE_URL}/assets?organization=${org._id}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const assets = assetRes.data.data.items || [];
        orgAsset = assets.length > 0 ? assets[0] : null;
      } catch (e) {}

      if (!orgAsset) {
        console.log(`  ⚠️ No asset found for ${org.name}, creating one...`);
        try {
          const newAsset = await axios.post(`${API_BASE_URL}/assets`, {
            name: `${org.code}-Simulator-Server`,
            type: 'server',
            organization: org._id,
            hostname: `${org.code.toLowerCase()}-sim-01`,
            ipAddress: org.code === 'ACME' ? '192.168.1.50' : 
                       org.code === 'GFI' ? '10.0.0.50' : '172.16.0.50',
            status: 'active',
            criticality: 'medium'
          }, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          orgAsset = newAsset.data.data;
          console.log(`   ✅ Created asset: ${orgAsset.name}`);
        } catch (e) {
          console.log(`   ❌ Failed to create asset: ${e.message}`);
          continue;
        }
      } else {
        console.log(`   ✅ Using existing asset: ${orgAsset.name}`);
      }

      // Create sources for each type
      for (const type of sourceTypes) {
        const sourceName = `${org.code}-${type}-Simulator`;
        const typeKey = type.toLowerCase() === 'pfsense' ? 'firewall' : type.toLowerCase();
        const envKey = `${org.code.toLowerCase()}_${typeKey}`.toUpperCase();
        
        // Check if source already exists
        const existing = sourceMap[org._id]?.[type]?.find(s => s.sourceName === sourceName);
        
        if (existing) {
          console.log(`  ⏭️ ${type} source already exists, skipping...`);
          envVars[envKey] = {
            id: existing._id,
            token: existing.authenticationToken
          };
          continue;
        }

        try {
          console.log(`  📝 Creating ${type} source for ${org.name}...`);
          
          const sourceData = {
            organization: org._id,
            asset: orgAsset._id,
            sourceName: sourceName,
            sourceType: type,
            hostname: `${type.toLowerCase()}-${org.code.toLowerCase()}-01`,
            ipAddress: org.code === 'ACME' ? `192.168.1.${100 + sourceTypes.indexOf(type) * 10}` :
                       org.code === 'GFI' ? `10.0.0.${100 + sourceTypes.indexOf(type) * 10}` :
                       `172.16.0.${100 + sourceTypes.indexOf(type) * 10}`,
            protocol: 'REST',
            description: `${type} simulator for ${org.name}`,
            status: 'Online',
            configuration: { logLevel: 'info', enabled: true }
          };

          const res = await axios.post(
            `${API_BASE_URL}/log-sources`,
            sourceData,
            { headers: { 'Authorization': `Bearer ${token}` } }
          );

          const source = res.data.data;
          envVars[envKey] = {
            id: source._id,
            token: source.authenticationToken
          };
          
          console.log(`   ✅ ${type} created: ${source._id}`);
        } catch (error) {
          if (error.response?.status === 409) {
            console.log(`   ⏭️ ${type} already exists (409), skipping...`);
          } else {
            console.log(`   ❌ Failed to create ${type}: ${error.message}`);
          }
        }
      }
    }

    // Write .env file
    const envFilePath = path.join(__dirname, '.env');
    let envContent = `# SentinelSOC Simulator Configuration - Multiple Organizations\n`;
    envContent += `# Generated on ${new Date().toISOString()}\n\n`;
    envContent += `API_URL=http://localhost:3000/api/v1/logs/ingest\n\n`;
    
    // Add all sources with organization prefix
    for (const [key, value] of Object.entries(envVars)) {
      envContent += `${key}_SOURCE_ID=${value.id}\n`;
      envContent += `${key}_AUTH_TOKEN=${value.token}\n`;
    }

    // Add organization list for reference
    envContent += `\n# Organizations\n`;
    for (const org of organizations) {
      envContent += `# ${org.code}: ${org.name}\n`;
    }

    fs.writeFileSync(envFilePath, envContent);
    console.log('\n✅ .env file created successfully!');
    console.log(`📁 Location: ${envFilePath}`);
    console.log('\n📋 Environment file contents:');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(fs.readFileSync(envFilePath, 'utf8'));
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  } catch (error) {
    console.error('\n❌ Error:', error.message);
    if (error.response) {
      console.error(`📥 Response status: ${error.response.status}`);
      console.error('📥 Response data:', JSON.stringify(error.response.data, null, 2));
    }
  }
}

setupSimulators();