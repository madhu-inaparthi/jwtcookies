// Test script for JWT encryption and decryption
const { encrypt, decrypt } = require('./script');

// Define a test payload
const testPayload = {
  userId: 123,
  role: 'admin',
  permissions: ['read', 'write', 'delete'],
  timestamp: new Date().toISOString()
};

console.log('Original Payload:', testPayload);

try {
  // Encrypt the payload
  console.log('\nEncrypting payload...');
  const token = encrypt(testPayload);
  console.log('Encrypted Token:', token);
  
  // Decrypt the token
  console.log('\nDecrypting token...');
  const decryptedPayload = decrypt(token);
  console.log('Decrypted Payload:', decryptedPayload);
  
  // Verify the result
  const originalStr = JSON.stringify(testPayload);
  const decryptedStr = JSON.stringify(decryptedPayload);
  
  if (originalStr === decryptedStr) {
    console.log('\n✅ SUCCESS: The decrypted payload matches the original payload!');
  } else {
    console.log('\n❌ FAILURE: The decrypted payload does not match the original payload.');
    console.log('Original:', originalStr);
    console.log('Decrypted:', decryptedStr);
  }
} catch (error) {
  console.error('\n❌ ERROR:', error.message);
}
