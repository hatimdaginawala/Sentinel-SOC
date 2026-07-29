// setup-simulators.js (Updated to handle undefined tokens)
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const API_BASE_URL = 'http://localhost:5000/api/v1';
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
    
    let organizationId;
    let organizationName;
    
    if (orgRes.data.data && orgRes.data.data.items && orgRes.data.data.items.length > 0) {
      organizationId = orgRes.data.data.items[0]._id;
      organizationName = orgRes.data.data.items[0].name;
      console.log(`✅ Found organization: ${organizationName} (${organizationId})`);
    } else {
      console.log('⚠️ No organizations found. Creating one...');
      const newOrg = await axios.post(`${API_BASE_URL}/organizations`, {
        name: 'Simulator Org',
        code: 'SIMORG',
        description: 'Organization for simulators',
        status: 'active'
      }, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      organizationId = newOrg.data.data._id;
      organizationName = newOrg.data.data.name;
      console.log(`✅ Created organization: ${organizationName} (${organizationId})`);
    }

    // Create asset
    console.log('\n💻 Creating asset...');
    const assetRes = await axios.post(`${API_BASE_URL}/assets`, {
      name: 'Simulator-Server',
      type: 'server',
      organization: organizationId,
      hostname: 'sim-server-01',
      ipAddress: '192.168.1.50',
      status: 'active',
      criticality: 'medium'
    }, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const assetId = assetRes.data.data._id;
    console.log(`✅ Asset created: ${assetRes.data.data.name} (${assetId})`);

    // Create log sources
    const sourceTypes = ['Windows', 'Linux', 'Apache', 'Nginx'];
    const envVars = {};

    for (const type of sourceTypes) {
      console.log(`\n📝 Creating ${type} log source...`);
      
      const sourceData = {
        organization: organizationId,
        asset: assetId,
        sourceName: `${type}-Simulator-${Date.now()}`,
        sourceType: type,
        hostname: `${type.toLowerCase()}-sim-01`,
        ipAddress: `192.168.1.${100 + sourceTypes.indexOf(type) * 10}`,
        protocol: 'REST',
        description: `${type} event simulator for SentinelSOC`,
        status: 'Online',
        configuration: { 
          logLevel: 'info', 
          enabled: true,
          batchSize: 100,
          flushInterval: 60
        }
      };

      const res = await axios.post(
        `${API_BASE_URL}/log-sources`,
        sourceData,
        { headers: { 'Authorization': `Bearer ${token}` } }
      );

      const source = res.data.data;
      const envKey = type.toUpperCase();
      
      // Get the token from the source
      let authToken = source.authenticationToken;
      
      // If token is undefined, generate one using the same logic as the model
      if (!authToken) {
        console.log(`⚠️ Token not returned for ${type}, generating fallback token...`);
        const crypto = require('crypto');
        authToken = crypto.randomBytes(32).toString('hex');
        
        // Update the log source with the generated token
        await axios.patch(
          `${API_BASE_URL}/log-sources/${source._id}`,
          { authenticationToken: authToken },
          { headers: { 'Authorization': `Bearer ${token}` } }
        ).catch(() => {
          console.log(`⚠️ Could not update token for ${type}, using temporary token`);
        });
      }
      
      envVars[`${envKey}_SOURCE_ID`] = source._id;
      envVars[`${envKey}_AUTH_TOKEN`] = authToken || `TEMP_TOKEN_${Date.now()}_${type}`;
      console.log(`✅ ${type} created successfully!`);
      console.log(`   🆔 ID: ${source._id}`);
      console.log(`   🔑 Token: ${authToken || '⚠️ GENERATED TEMPORARY TOKEN'}`);
    }

    // Write .env file
    const envFilePath = path.join(__dirname, '.env');
    let envContent = `# SentinelSOC Simulator Configuration\n`;
    envContent += `# Generated on ${new Date().toISOString()}\n\n`;
    envContent += `API_URL=http://localhost:5000/api/v1/logs/ingest\n\n`;
    
    for (const [key, value] of Object.entries(envVars)) {
      envContent += `${key}=${value}\n`;
    }

    fs.writeFileSync(envFilePath, envContent);
    console.log('\n✅ .env file created successfully!');
    console.log(`📁 Location: ${envFilePath}`);
    console.log('\n📋 Environment file contents:');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(fs.readFileSync(envFilePath, 'utf8'));
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    
    console.log('\n🎉 Setup complete! You can now run the simulators:');
    console.log('  npm run windows');
    console.log('  npm run linux');
    console.log('  npm run apache');
    console.log('  npm run nginx');
    console.log('  npm run all');

  } catch (error) {
    console.error('\n❌ Error:', error.message);
    if (error.response) {
      console.error(`📥 Response status: ${error.response.status}`);
      console.error('📥 Response data:', JSON.stringify(error.response.data, null, 2));
    }
    if (error.request) {
      console.error('📤 No response received. Make sure the server is running.');
    }
  }
}

setupSimulators();