// sync-tokens.js - Fixed version with direct MongoDB connection
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
    console.log(' Connected to MongoDB');
    
    const db = client.db(DB_NAME);
    const collection = db.collection('logsources');
    
    // Find the three sources
    const sourceIds = [
      '6a698ee07add140875bc145b',
      '6a698ee07add140875bc1474',
      '6a698ee07add140875bc148d'
    ];
    
    const tokens = {};
    
    for (const id of sourceIds) {
      const objectId = new ObjectId(id);
      
      // Check if source exists
      const source = await collection.findOne({ _id: objectId });
      
      if (source) {
        // Generate new token
        const token = crypto.randomBytes(32).toString('hex');
        
        // Update the source with new token
        await collection.updateOne(
          { _id: objectId },
          { $set: { authenticationToken: token } }
        );
        
        const key = source.sourceType.toUpperCase();
        tokens[key] = {
          id: source._id.toString(),
          token: token,
          name: source.sourceName
        };
        
        console.log(` Updated ${source.sourceName} (${source.sourceType})`);
        console.log(`   ID: ${source._id}`);
        console.log(`   Token: ${token}`);
      } else {
        console.log(`❌ Source not found: ${id}`);
        
        // Try to find it by the old IDs
        const oldIds = {
          '6a698eb57add140875bc1426': 'Suricata',
          '6a698eb57add140875bc1433': 'Snort',
          '6a698eb57add140875bc1440': 'pfSense'
        };
        
        if (oldIds[id]) {
          console.log(`   Looking for ${oldIds[id]} by name...`);
          const altSource = await collection.findOne({ 
            sourceType: oldIds[id],
            sourceName: { $regex: `${oldIds[id]}-Simulator` }
          });
          
          if (altSource) {
            const token = crypto.randomBytes(32).toString('hex');
            await collection.updateOne(
              { _id: altSource._id },
              { $set: { authenticationToken: token } }
            );
            
            const key = altSource.sourceType.toUpperCase();
            tokens[key] = {
              id: altSource._id.toString(),
              token: token,
              name: altSource.sourceName
            };
            
            console.log(`    Found and updated: ${altSource.sourceName}`);
            console.log(`   ID: ${altSource._id}`);
            console.log(`   Token: ${token}`);
          }
        }
      }
    }
    
    // Also check for any sources without tokens
    console.log('\n🔍 Checking for sources without tokens...');
    const sourcesWithoutTokens = await collection.find({
      $or: [
        { authenticationToken: { $exists: false } },
        { authenticationToken: null }
      ]
    }).toArray();
    
    for (const source of sourcesWithoutTokens) {
      const token = crypto.randomBytes(32).toString('hex');
      await collection.updateOne(
        { _id: source._id },
        { $set: { authenticationToken: token } }
      );
      
      const key = source.sourceType.toUpperCase();
      tokens[key] = {
        id: source._id.toString(),
        token: token,
        name: source.sourceName
      };
      
      console.log(` Fixed ${source.sourceName} (${source.sourceType})`);
      console.log(`   ID: ${source._id}`);
      console.log(`   Token: ${token}`);
    }

    // Update .env file
    if (Object.keys(tokens).length > 0) {
      const envPath = path.join(__dirname, '.env');
      let envContent = fs.readFileSync(envPath, 'utf8');
      
      // Remove old entries for these sources
      const lines = envContent.split('\n');
      const filteredLines = lines.filter(line => {
        return !line.startsWith('SURICATA_') && 
               !line.startsWith('SNORT_') && 
               !line.startsWith('PFSENSE_') &&
               !line.startsWith('FIREWALL_');
      });
      envContent = filteredLines.join('\n');
      
      // Add new entries
      envContent += '\n# Security Simulator Sources\n';
      envContent += `# Synced on ${new Date().toISOString()}\n\n`;
      
      for (const [key, value] of Object.entries(tokens)) {
        envContent += `${key}_SOURCE_ID=${value.id}\n`;
        envContent += `${key}_AUTH_TOKEN=${value.token}\n`;
      }

      fs.writeFileSync(envPath, envContent);
      console.log('\n .env file updated successfully!');
      
      console.log('\n📋 Updated tokens:');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      for (const [key, value] of Object.entries(tokens)) {
        console.log(`${key}_SOURCE_ID=${value.id}`);
        console.log(`${key}_AUTH_TOKEN=${value.token}`);
        console.log('---');
      }
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    } else {
      console.log('\n⚠️ No tokens were updated. Please check your source IDs.');
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

// ObjectId helper
function ObjectId(id) {
  return new (require('mongodb').ObjectId)(id);
}

// Run the sync
syncTokens();