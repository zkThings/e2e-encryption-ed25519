import * as ed25519 from '@noble/ed25519';
import { describe, expect, test } from 'bun:test';
import crypto from 'node:crypto';
import type { PublicSignals } from '../src/encyrption/ed25519E2E';
import Ed25519E2E from '../src/encyrption/ed25519E2E';

// Set SHA-512 implementation for ed25519
ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => {
  const buffer = Buffer.concat(m);
  return new Uint8Array(crypto.createHash('sha512').update(new Uint8Array(buffer)).digest());
};

describe('Ed25519E2E', () => {
  // Test setup helper
  const generateKeyPair = async (): Promise<{ privateKey: string; publicKey: string }> => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = await ed25519.getPublicKey(privateKey);
    return {
      privateKey: `0x${Buffer.from(privateKey).toString('hex')}`,
      publicKey: Buffer.from(publicKey).toString('hex'),
    };
  };

  test('should successfully encrypt and decrypt data', async () => {
    const e2e = new Ed25519E2E();
    const { privateKey, publicKey } = await generateKeyPair();
    const testData = 'Hello, World!';
    const recipientAddress = '0x1234567890123456789012345678901234567890';

    // Encrypt the data
    const encrypted = await e2e.encrypt(testData, recipientAddress, publicKey);

    // Verify the encrypted result structure
    expect(encrypted).toHaveProperty('publicSignals');
    expect(encrypted.publicSignals).toHaveProperty('encryptedData');
    expect(encrypted.publicSignals).toHaveProperty('initVector');
    expect(encrypted.publicSignals).toHaveProperty('verificationTag');
    expect(encrypted.publicSignals).toHaveProperty('ephemeralPublicKey');
    expect(encrypted.publicSignals.forAddress).toBe(recipientAddress.toLowerCase());
    expect(encrypted.publicSignals.version).toBe('1.0');

    // Decrypt the data
    const decrypted = await e2e.decrypt({
      publicSignals: encrypted.publicSignals,
      privateKey: privateKey,
    });

    expect(decrypted).toBe(testData);
  });

  test('should handle different data types for encryption', async () => {
    const e2e = new Ed25519E2E();
    const { privateKey, publicKey } = await generateKeyPair();
    const recipientAddress = '0x1234567890123456789012345678901234567890';

    const testCases = [
      { input: { test: 'object' }, expected: JSON.stringify({ test: 'object' }) },
      { input: null, expected: 'null' },
      { input: undefined, expected: 'undefined' },
      { input: 123, expected: '123' },
      { input: true, expected: 'true' },
    ];

    for (const { input, expected } of testCases) {
      const encrypted = await e2e.encrypt(input, recipientAddress, publicKey);

      const decrypted = await e2e.decrypt({
        publicSignals: encrypted.publicSignals,
        privateKey: privateKey,
      });

      expect(decrypted).toBe(expected);
    }
  });

  test('should throw error for invalid inputs during encryption', async () => {
    const e2e = new Ed25519E2E();
    const { publicKey } = await generateKeyPair();
    // const recipientAddress = '0x1234567890123456789012345678901234567890';

    await expect(e2e.encrypt(null, '', publicKey)).rejects.toThrow('Invalid input');
  });

  test('should throw error for invalid inputs during decryption', async () => {
    const e2e = new Ed25519E2E();

    await expect(
      e2e.decrypt({
        publicSignals: {} as PublicSignals,
        privateKey: '0xinvalid',
        type: 'user',
      })
    ).rejects.toThrow('Invalid public signals format');
  });

  test('should throw error for tampered data', async () => {
    const e2e = new Ed25519E2E();
    const { privateKey, publicKey } = await generateKeyPair();
    const testData = 'Hello, World!';
    const recipientAddress = '0x1234567890123456789012345678901234567890';

    const encrypted = await e2e.encrypt(testData, recipientAddress, publicKey);

    // Tamper with the encrypted data
    encrypted.publicSignals.encryptedData = encrypted.publicSignals.encryptedData.replace('a', 'b');

    await expect(
      e2e.decrypt({
        publicSignals: encrypted.publicSignals,
        privateKey: privateKey,
      })
    ).rejects.toThrow('Data integrity check failed - possible tampering detected');
  });

  test('should handle user and notary types correctly', async () => {
    const e2e = new Ed25519E2E();
    const { privateKey, publicKey } = await generateKeyPair();
    const testData = 'Hello, World!';
    const recipientAddress = '0x1234567890123456789012345678901234567890';

    const encrypted = await e2e.encrypt(testData, recipientAddress, publicKey);

    // Test user type
    const decryptedUser = await e2e.decrypt({
      publicSignals: { user: encrypted.publicSignals },
      privateKey: privateKey,
      type: 'user',
    });
    expect(decryptedUser).toBe(testData);

    // Test notary type
    const decryptedNotary = await e2e.decrypt({
      publicSignals: { notary: encrypted.publicSignals },
      privateKey: privateKey,
      type: 'notary',
    });
    expect(decryptedNotary).toBe(testData);
  });
});
