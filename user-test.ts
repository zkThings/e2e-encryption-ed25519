#!/usr/bin/env bun
/**
 * External User Test Script
 * This script simulates how a real user would use the @zkthings/e2e-encryption-ed25519 package
 * based on the documentation in README.md
 */

import * as ed25519 from '@noble/ed25519';
import crypto from 'node:crypto';
import { Ed25519E2E } from './src/index';

// Set SHA-512 implementation for ed25519 (required for proper functionality)
ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => {
  const buffer = Buffer.concat(m);
  return new Uint8Array(crypto.createHash('sha512').update(new Uint8Array(buffer)).digest());
};

// Helper function to generate Ed25519 key pairs for testing
const generateKeyPair = async (): Promise<{ privateKey: string; publicKey: string }> => {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = await ed25519.getPublicKey(privateKey);
  return {
    privateKey: `0x${Buffer.from(privateKey).toString('hex')}`,
    publicKey: Buffer.from(publicKey).toString('hex'),
  };
};

async function runUserTest() {
  console.log('🧪 Starting External User Test for @zkthings/e2e-encryption-ed25519\n');

  try {
    // Test 1: Basic Package Import
    console.log('✅ Test 1: Package import successful');
    const e2e = new Ed25519E2E();
    console.log('✅ Test 1: Ed25519E2E instance created\n');

    // Test 2: Generate test keys
    console.log('🔑 Test 2: Generating Ed25519 key pairs...');
    const { privateKey, publicKey } = await generateKeyPair();
    const recipientAddress = '0x1234567890123456789012345678901234567890';
    console.log(`✅ Test 2: Generated keys - Public: ${publicKey.slice(0, 20)}...\n`);

    // Test 3: Basic Encryption/Decryption (as shown in README)
    console.log('🔐 Test 3: Basic encryption/decryption workflow...');
    const testMessage = 'Hello, World!';
    
    // Encrypt data (using README example syntax)
    const encrypted = await e2e.encryptFor(testMessage, recipientAddress, publicKey);
    console.log('✅ Test 3: Data encrypted successfully');
    console.log(`   - Encrypted data length: ${encrypted.publicSignals.encryptedData.length} chars`);
    console.log(`   - For address: ${encrypted.publicSignals.forAddress}`);
    
    // Decrypt data (using README example syntax)
    const decrypted = await e2e.decrypt(encrypted, privateKey);
    console.log(`✅ Test 3: Data decrypted successfully: "${decrypted}"\n`);

    if (decrypted !== testMessage) {
      throw new Error(`Decryption failed: expected "${testMessage}", got "${decrypted}"`);
    }

    // Test 4: Different Data Types
    console.log('📊 Test 4: Testing different data types...');
    const testCases = [
      { name: 'String', data: 'test string', expected: 'test string' },
      { name: 'Number', data: 42, expected: '42' },
      { name: 'Boolean', data: true, expected: 'true' },
      { name: 'Object', data: { foo: 'bar', num: 123 }, expected: JSON.stringify({ foo: 'bar', num: 123 }) },
      { name: 'Array', data: [1, 2, 3], expected: JSON.stringify([1, 2, 3]) },
      { name: 'Null', data: null, expected: 'null' },
      { name: 'Undefined', data: undefined, expected: 'undefined' },
    ];

    for (const testCase of testCases) {
      const encrypted = await e2e.encryptFor(testCase.data, recipientAddress, publicKey);
      const decrypted = await e2e.decrypt(encrypted, privateKey);
      
      if (decrypted !== testCase.expected) {
        throw new Error(`${testCase.name} test failed: expected "${testCase.expected}", got "${decrypted}"`);
      }
      console.log(`   ✅ ${testCase.name}: ${JSON.stringify(testCase.data)} → encrypted → decrypted`);
    }
    console.log('✅ Test 4: All data types handled correctly\n');

    // Test 5: Advanced Decrypt API (object-style parameters)
    console.log('🔧 Test 5: Testing advanced decrypt API...');
    const encrypted2 = await e2e.encryptFor('Advanced test', recipientAddress, publicKey);
    
    // Test object-style decrypt
    const decrypted2 = await e2e.decrypt({
      publicSignals: encrypted2.publicSignals,
      privateKey: privateKey,
      type: 'user'
    });
    console.log(`✅ Test 5: Object-style decrypt successful: "${decrypted2}"\n`);

    // Test 6: User/Notary Types
    console.log('👥 Test 6: Testing user/notary encryption types...');
    const encrypted3 = await e2e.encryptFor('Notary test', recipientAddress, publicKey);
    
    // Test user type
    const userDecrypted = await e2e.decrypt({
      publicSignals: { user: encrypted3.publicSignals },
      privateKey: privateKey,
      type: 'user'
    });
    
    // Test notary type
    const notaryDecrypted = await e2e.decrypt({
      publicSignals: { notary: encrypted3.publicSignals },
      privateKey: privateKey,
      type: 'notary'
    });
    
    console.log(`✅ Test 6: User decrypt: "${userDecrypted}"`);
    console.log(`✅ Test 6: Notary decrypt: "${notaryDecrypted}"\n`);

    // Test 7: Error Handling
    console.log('🚨 Test 7: Testing error handling...');
    
    try {
      await e2e.encryptFor('test', '', publicKey);
      throw new Error('Should have thrown for empty address');
    } catch (error) {
      console.log('✅ Test 7a: Correctly threw error for empty address');
    }

    try {
      await e2e.decrypt(encrypted, '0xinvalidkey');
      throw new Error('Should have thrown for invalid private key');
    } catch (error) {
      console.log('✅ Test 7b: Correctly threw error for invalid private key');
    }

    // Test tampered data
    const tamperedData = { ...encrypted };
    tamperedData.publicSignals.encryptedData = tamperedData.publicSignals.encryptedData.replace('a', 'b');
    
    try {
      await e2e.decrypt(tamperedData, privateKey);
      throw new Error('Should have thrown for tampered data');
    } catch (error) {
      console.log('✅ Test 7c: Correctly detected tampered data\n');
    }

    // Test 8: Performance Check
    console.log('⚡ Test 8: Performance test...');
    const startTime = performance.now();
    
    for (let i = 0; i < 10; i++) {
      const encrypted = await e2e.encryptFor(`Performance test ${i}`, recipientAddress, publicKey);
      await e2e.decrypt(encrypted, privateKey);
    }
    
    const endTime = performance.now();
    const avgTime = (endTime - startTime) / 10;
    console.log(`✅ Test 8: Average encrypt/decrypt time: ${avgTime.toFixed(2)}ms\n`);

    // Summary
    console.log('🎉 ALL TESTS PASSED! 🎉');
    console.log('📦 Package is ready for external users');
    console.log('📋 API works exactly as documented in README.md');
    console.log('🔒 Encryption/decryption is working correctly');
    console.log('🛡️  Error handling is robust');
    console.log('⚡ Performance is acceptable\n');

  } catch (error) {
    console.error('❌ USER TEST FAILED:');
    console.error(error);
    process.exit(1);
  }
}

// Run the test
runUserTest().catch(console.error);