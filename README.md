# @zkthings/e2e-encryption-ed25519

End-to-end encryption library using Ed25519 keys with X25519 key exchange for secure data transmission.

## Features

- Encrypt/decrypt data using Ed25519 key pairs
- Support for multiple data types (strings, numbers, objects, etc.)
- Secure key exchange using X25519
- AES-256-GCM encryption with authentication
- Support for user and notary type encryption
- Data integrity verification
- TypeScript support

## Installation

```bash
bun install @zkthings/e2e-encryption-ed25519
```

## Usage

```typescript
import Ed25519E2E from '@zkthings/e2e-encryption-ed25519';

// Initialize
const e2e = new Ed25519E2E();

// Encrypt data
const encrypted = await e2e.encrypt(
  'Hello, World!',
  '0x1234...', // recipient address
  publicKey    // recipient's Ed25519 public key
);

// Decrypt data
const decrypted = await e2e.decrypt({
  publicSignals: encrypted.publicSignals,
  privateKey: '0x...', // your private key
  type: 'user'         // or 'notary'
});
```

## Development

To install dependencies:
```bash
bun install
```

To run tests:
```bash
bun test
```

## License

MIT License - see LICENSE file for details.
