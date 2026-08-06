// scripts/test-simple-audit.js
const axios = require('axios');

const API_BASE = 'http://localhost:3000/api/v1';
const LOGIN_CREDENTIALS = {
  identifier: 'superadmin@sentinel-soc.com',
  password: 'SuperAdmin@2024!'
};

async function testSimpleAudit() {
  try {
    console.log(' Simple Audit Test\n');

    // Login
    console.log('1. Logging in...');
    const loginRes = await axios.post(`${API_BASE}/auth/login`, LOGIN_CREDENTIALS);
    const token = loginRes.data.data.accessToken;
    console.log(' Login successful\n');

    const headers = { 
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    };

    // Get organization
    const orgRes = await axios.get(`${API_BASE}/organizations`, { headers });
    const orgId = orgRes.data.data.items[0]._id;
    console.log(` Organization: ${orgId}\n`);

    // Create a test asset
    const timestamp = Date.now();
    console.log('2. Creating asset...');
    const assetRes = await axios.post(`${API_BASE}/assets`, {
      name: `Simple-Test-Asset-${timestamp}`,
      type: 'server',
      organization: orgId,
      hostname: `simple-test-${timestamp}`,
      ipAddress: '192.168.1.99',
      status: 'active'
    }, { headers });
    console.log(` Asset created: ${assetRes.data.data._id}\n`);

    // Create a test incident
    console.log('3. Creating incident...');
    const incidentRes = await axios.post(`${API_BASE}/incidents`, {
      organization: orgId,
      title: `Simple-Test-Incident-${timestamp}`,
      description: 'Simple test incident for audit',
      severity: 'medium',
      category: 'unauthorized_access',
      status: 'new'
    }, { headers });
    console.log(` Incident created: ${incidentRes.data.data._id}\n`);

    // Wait a moment for async logging
    console.log('4. Waiting for audit logs...');
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Check audit logs
    console.log('5. Checking audit logs...');
    const auditRes = await axios.get(`${API_BASE}/audit-logs?limit=20`, { headers });
    
    console.log(` Found ${auditRes.data.data.items.length} audit logs\n`);
    
    // Find recent logs
    const recentLogs = auditRes.data.data.items.slice(0, 10);
    console.log(' Recent audit logs:');
    recentLogs.forEach((log, i) => {
      console.log(`  ${i+1}. ${log.createdAt} | ${log.action} | ${log.resource} | ${log.resourceName || 'N/A'}`);
    });

    console.log('\n Test complete!');

  } catch (error) {
    console.error(' Error:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
  }
}

testSimpleAudit();