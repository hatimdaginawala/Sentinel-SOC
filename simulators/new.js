// sync-tokens.js - Fixed version that gets all sources
const { MongoClient } = require('mongodb');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// MongoDB connection string
const MONGODB_URI = 'mongodb://127.0.0.1:27017';
const DB_NAME = 'sentinel_soc';

async function syncTokens() {
  let client = null;
  
  try {
    console.log('🔄 Syncing authentication tokens...');
    
    // Connect to MongoDB
    client = new MongoClient(MONGODB_URI, {
      connectTimeoutMS: 3000,
      socketTimeoutMS: 3000,
      serverSelectionTimeoutMS: 3000
    });
    
    await client.connect();
    console.log('✅ Connected to MongoDB');
    
    const db = client.db(DB_NAME);
    const collection = db.collection('logsources');
    
    // Get ALL log sources
    const allSources = await collection.find({}).toArray();
    console.log(`✅ Found ${allSources.length} log sources in database`);
    
    const tokens = {};
    const sourceTypes = ['Windows', 'Linux', 'Apache', 'Nginx', 'Suricata', 'Snort', 'pfSense'];
    
    // Process each source
    for (const source of allSources) {
      // Generate new token if missing
      if (!source.authenticationToken) {
        const token = crypto.randomBytes(32).toString('hex');
        await collection.updateOne(
          { _id: source._id },
          { $set: { authenticationToken: token } }
        );
        source.authenticationToken = token;
        console.log(`   🔑 Generated token for ${source.sourceName}`);
      }
      
      // Get organization code
      let orgCode = 'unknown';
      try {
        const org = await db.collection('organizations').findOne({ _id: source.organization });
        if (org) orgCode = org.code.toLowerCase();
      } catch (e) {}
      
      const typeKey = source.sourceType.toLowerCase() === 'pfsense' ? 'firewall' : source.sourceType.toLowerCase();
      const envKey = `${orgCode}_${typeKey}`.toUpperCase();
      
      tokens[envKey] = {
        id: source._id.toString(),
        token: source.authenticationToken,
        name: source.sourceName,
        type: source.sourceType
      };
    }
    
    // Also create generic tokens (without org prefix) for backward compatibility
    // Use the first source of each type found
    const usedTypes = {};
    for (const [key, value] of Object.entries(tokens)) {
      const type = value.type;
      if (!usedTypes[type]) {
        usedTypes[type] = value;
      }
    }
    
    // Update .env file
    if (Object.keys(tokens).length > 0) {
      const envPath = path.join(__dirname, '.env');
      
      // Build new env content
      let envContent = '# SentinelSOC Simulator Configuration\n';
      envContent += `# Generated on ${new Date().toISOString()}\n\n`;
      envContent += `API_URL=http://localhost:3000/api/v1/logs/ingest\n\n`;
      
      // Add organization-prefixed tokens
      envContent += '# Organization-specific sources\n';
      for (const [key, value] of Object.entries(tokens)) {
        envContent += `${key}_SOURCE_ID=${value.id}\n`;
        envContent += `${key}_AUTH_TOKEN=${value.token}\n`;
      }
      
      // Add generic tokens (without org prefix) for backward compatibility
      envContent += '\n# Generic sources (backward compatibility)\n';
      for (const [type, value] of Object.entries(usedTypes)) {
        const typeKey = type.toLowerCase() === 'pfsense' ? 'firewall' : type.toLowerCase();
        const envKey = typeKey.toUpperCase();
        envContent += `${envKey}_SOURCE_ID=${value.id}\n`;
        envContent += `${envKey}_AUTH_TOKEN=${value.token}\n`;
      }

      fs.writeFileSync(envPath, envContent);
      console.log('\n✅ .env file updated successfully!');
      
      console.log('\n📋 Updated tokens:');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      for (const [key, value] of Object.entries(tokens)) {
        console.log(`${key}_SOURCE_ID=${value.id}`);
        console.log(`${key}_AUTH_TOKEN=${value.token}`);
        console.log(`   (${value.name})`);
        console.log('---');
      }
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    } else {
      console.log('\n⚠️ No tokens were found. Please run setup-simulators.js first.');
    }

    await client.close();
    console.log('\n🔌 Disconnected from MongoDB');

  } catch (error) {
    console.error('❌ Error:', error.message);
    console.error(error.stack);
    if (client) {
      await client.close();
    }
    process.exit(1);
  }
}

// Run the sync
syncTokens();