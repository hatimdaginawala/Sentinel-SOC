const mongoose = require('mongoose');
const crypto = require('crypto');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '../.env') });

const LogSource = require('./models/LogSource');

async function fixTokens() {
  try {
    console.log('🔧 Fixing authentication tokens...');
    
    let mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/sentinel_soc';
    if (mongoURI.includes('localhost')) {
      mongoURI = mongoURI.replace('localhost', '127.0.0.1');
    }
    
    await mongoose.connect(mongoURI, {
      serverSelectionTimeoutMS: 5000,
      family: 4
    });
    
    console.log('✅ Connected to MongoDB');

    // Find all log sources
    const sources = await LogSource.find({});
    console.log(`📋 Found ${sources.length} log sources`);

    let updatedCount = 0;
    for (const source of sources) {
      // Generate a new token if none exists
      if (!source.authenticationToken) {
        const token = crypto.randomBytes(32).toString('hex');
        source.authenticationToken = token;
        await source.save();
        updatedCount++;
        console.log(`✅ Updated ${source.sourceName} (${source._id})`);
        console.log(`   🔑 Token: ${token}`);
      } else {
        console.log(`ℹ️ ${source.sourceName} already has token: ${source.authenticationToken}`);
      }
    }

    console.log(`\n✅ Fixed tokens for ${updatedCount} sources`);

    // Display all tokens for simulators
    console.log('\n📋 All Log Source Tokens for Simulators:');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    
    const allSources = await LogSource.find({});
    for (const source of allSources) {
      const type = source.sourceType.toUpperCase();
      console.log(`${type}_SOURCE_ID=${source._id}`);
      console.log(`${type}_AUTH_TOKEN=${source.authenticationToken}`);
      console.log('---');
    }

    await mongoose.disconnect();
    console.log('\n🔌 Disconnected from MongoDB');

  } catch (error) {
    console.error('❌ Error:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

fixTokens();