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
    console.log(' Login successful');

    // Get organizations
    console.log('\n📋 Getting organizations...');
    const orgRes = await axios.get(`${API_BASE_URL}/organizations`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    const organizations = orgRes.data.data.items || [];
    console.log(` Found ${organizations.length} organizations`);

    // Get assets
    console.log('\n💻 Getting assets...');
    const assetRes = await axios.get(`${API_BASE_URL}/assets`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    const assets = assetRes.data.data.items || [];
    console.log(` Found ${assets.length} assets`);

    // Create log sources for each organization and type
    const sourceTypes = ['Windows', 'Linux', 'Apache', 'Nginx', 'Suricata', 'Snort', 'pfSense'];
    const envVars = {};

    for (const org of organizations) {
      console.log(`\n📋 Processing organization: ${org.name} (${org.code})`);
      
      // Find asset for this organization
      const orgAsset = assets.find(a => a.organization === org._id);
      if (!orgAsset) {
        console.log(`  ⚠️ No asset found for ${org.name}, creating one...`);
        // Create asset
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
        console.log(`   Created asset: ${newAsset.data.data.name}`);
      }

      // Create sources for each type
      for (const type of sourceTypes) {
        try {
          console.log(`  📝 Creating ${type} source for ${org.name}...`);
          
          const sourceData = {
            organization: org._id,
            asset: orgAsset?._id || (await axios.post(`${API_BASE_URL}/assets`, {
              name: `${org.code}-Simulator-Server`,
              type: 'server',
              organization: org._id,
              hostname: `${org.code.toLowerCase()}-sim-01`,
              ipAddress: org.code === 'ACME' ? '192.168.1.50' : 
                         org.code === 'GFI' ? '10.0.0.50' : '172.16.0.50',
              status: 'active',
              criticality: 'medium'
            }, { headers: { 'Authorization': `Bearer ${token}` } })).data.data._id,
            sourceName: `${org.code}-${type}-Simulator`,
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
          const orgKey = org.code.toLowerCase();
          const typeKey = type.toLowerCase() === 'pfsense' ? 'firewall' : type.toLowerCase();
          const envKey = `${orgKey}_${typeKey}`.toUpperCase();
          
          envVars[envKey] = {
            id: source._id,
            token: source.authenticationToken
          };
          
          console.log(`     ${type} created: ${source._id}`);
        } catch (error) {
          console.log(`    ❌ Failed to create ${type}: ${error.message}`);
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
    console.log('\n .env file created successfully!');
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