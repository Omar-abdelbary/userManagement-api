const bcrypt = require('bcrypt');

// Generate hash for admin123
async function generateAdminHash() {
  try {
    const password = 'admin123';
    const saltRounds = 10;
    
    console.log('🔐 Generating hash for password:', password);
    
    const hash = await bcrypt.hash(password, saltRounds);
    
    console.log('\n✅ Generated hash:');
    console.log(hash);
    
    console.log('\n📋 Copy this hash and replace the admin user password in your server.js:');
    console.log(`password: '${hash}',`);
    
    // Verify the hash works
    const isValid = await bcrypt.compare(password, hash);
    console.log('\n🧪 Verification test:', isValid ? '✅ PASS' : '❌ FAIL');
    
    return hash;
    
  } catch (error) {
    console.error('❌ Error generating hash:', error);
  }
}

// Test with the current fake hash
async function testCurrentHash() {
  const fakeHash = '$2b$10$rQZ9YmfS.GGg4g4g4g4g4g4g4g4g4g4g4g4g4g4g4g4g4g4g4g4g4g4';
  const password = 'admin123';
  
  try {
    const result = await bcrypt.compare(password, fakeHash);
    console.log('🧪 Testing fake hash:', result ? '✅ PASS' : '❌ FAIL (This is why login fails!)');
  } catch (error) {
    console.log('❌ Fake hash test failed:', error.message);
  }
}

// Run both tests
async function runTests() {
  console.log('🔍 Testing current (fake) hash...\n');
  await testCurrentHash();
  
  console.log('\n' + '='.repeat(50) + '\n');
  
  console.log('🛠️ Generating correct hash...\n');
  await generateAdminHash();
}

// Quick fix function - generates multiple passwords
async function generateMultipleHashes() {
  const passwords = ['admin123', 'password123', 'test123'];
  
  console.log('🔐 Generating hashes for common passwords:\n');
  
  for (const pwd of passwords) {
    const hash = await bcrypt.hash(pwd, 10);
    console.log(`Password: ${pwd}`);
    console.log(`Hash: ${hash}`);
    console.log('---');
  }
}

// Export functions for use
module.exports = {
  generateAdminHash,
  testCurrentHash,
  runTests,
  generateMultipleHashes
};

// Run if called directly
if (require.main === module) {
  runTests();
}