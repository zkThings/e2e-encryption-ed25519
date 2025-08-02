import { edwardsToMontgomeryPriv, edwardsToMontgomeryPub, x25519 } from '@noble/curves/ed25519';
import * as ed25519 from '@noble/ed25519';
import crypto from 'node:crypto';

export type PublicSignals = {
  encryptedData: string;
  initVector: string;
  verificationTag: string;
  ephemeralPublicKey: string;
  forAddress: string;
  version: string;
};

type DecryptParams = {
  publicSignals: PublicSignals | { user?: PublicSignals; notary?: PublicSignals };
  privateKey: string;
  type?: 'user' | 'notary';
};

type EncryptedData = {
  publicSignals: PublicSignals;
};

class Ed25519E2E {
  private algorithm: crypto.CipherGCMTypes;

  constructor() {
    this.algorithm = 'aes-256-gcm';
  }

  /**
   * Encrypts the data for the specified recipient using the provided public key.
   * @param {string | number | boolean | object | null | undefined} data - The data to encrypt
   * @param {string} recipientAddress - The address of the recipient
   * @param {Uint8Array | Buffer | string} recipientPublicKey - The public key of the recipient
   * @returns {Promise<{ publicSignals: PublicSignals }>} An object containing the encrypted data and public signals
   * @throws {Error} If the input is invalid or encryption fails
   */
  async encryptFor(
    data: string | number | boolean | object | null | undefined,
    recipientAddress: string,
    recipientPublicKey: Uint8Array | Buffer | string
  ): Promise<{ publicSignals: PublicSignals }> {
    if (!recipientAddress || !recipientPublicKey) {
      throw new Error('Invalid input');
    }

    // TODO: Check the recipient public key is valid
    // TODO: Try registry if public key not provided

    // TODO: Validate public key
    if (!recipientPublicKey.length) {
      throw new Error('Recipient public key is required');
    }

    // Generate ephemeral keypair with verification
    const ephemeralPrivateKey = ed25519.utils.randomPrivateKey();
    const ephemeralPublicKey = ed25519.getPublicKey(ephemeralPrivateKey);

    // Generate shared secret using X25519
    const sharedSecret = x25519.getSharedSecret(edwardsToMontgomeryPriv(ephemeralPrivateKey), edwardsToMontgomeryPub(this._toHex(recipientPublicKey)));

    // const sharedSecret = await x25519.getSharedSecret(publicKey, privateKey);
    // const signature = await sign(message, sharedSecret);

    // Generate encryption key using HKDF
    const encryptionKey = crypto.createHmac('sha256', sharedSecret).update('ENCRYPTION_KEY').digest();
    const iv = new Uint8Array(crypto.randomBytes(12)); // 96 bits for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', new Uint8Array(encryptionKey), iv);

    // Standardize data format
    const stringData = this._normalizeData(data);

    // Add associated data for additional security
    const associatedData = new Uint8Array(Buffer.from(recipientAddress.toLowerCase()));
    cipher.setAAD(associatedData);

    let encrypted = cipher.update(stringData, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    return {
      publicSignals: {
        encryptedData: encrypted,
        initVector: Buffer.from(iv).toString('hex'),
        verificationTag: authTag.toString('hex'),
        ephemeralPublicKey: Buffer.from(ephemeralPublicKey).toString('hex'),
        forAddress: recipientAddress.toLowerCase(),
        version: '1.0',
      },
    };
  }

  /**
   * Decrypts the data using the provided public signals and private key.
   * @param {DecryptParams} params - The parameters for decryption
   * @returns {Promise<string>} The decrypted data
   * @throws {Error} If the input is invalid or decryption fails
   */
  async decrypt(encryptedData: EncryptedData, privateKey: string): Promise<unknown>;
  async decrypt({ publicSignals, privateKey, type = 'user' }: DecryptParams): Promise<unknown>;
  async decrypt(encryptedDataOrParams: EncryptedData | DecryptParams, privateKey?: string): Promise<unknown> {
    // Handle both API signatures for compatibility
    let publicSignals: PublicSignals | { user?: PublicSignals; notary?: PublicSignals };
    let key: string;
    let type: 'user' | 'notary' = 'user';

    if (privateKey && 'publicSignals' in encryptedDataOrParams) {
      // Legacy API: decrypt(encryptedData, privateKey)
      publicSignals = (encryptedDataOrParams as EncryptedData).publicSignals;
      key = privateKey;
    } else {
      // New API: decrypt({ publicSignals, privateKey, type })
      const params = encryptedDataOrParams as DecryptParams;
      publicSignals = params.publicSignals;
      key = params.privateKey;
      type = params.type || 'user';
    }
    if (!publicSignals || !key) {
      throw new Error('Invalid input');
    }

    const signals = type === 'user' ? (publicSignals as { user?: PublicSignals }).user || publicSignals : (publicSignals as { notary?: PublicSignals }).notary;

    if (!this._isPublicSignals(signals)) {
      throw new Error('Invalid public signals format');
    }

    // Validate all required fields
    this._validateSignals(signals);

    try {
      const privateKeyBuffer = this._validateAndFormatPrivateKey(key);

      // Generate shared secret using X25519
      const sharedSecret = x25519.getSharedSecret(edwardsToMontgomeryPriv(new Uint8Array(privateKeyBuffer)), edwardsToMontgomeryPub(this._toHex(signals.ephemeralPublicKey)));

      // Derive decryption key using HKDF
      const decryptionKey = crypto.createHmac('sha256', sharedSecret).update('ENCRYPTION_KEY').digest();

      const decipher = crypto.createDecipheriv(this.algorithm, new Uint8Array(decryptionKey), new Uint8Array(Buffer.from(signals.initVector, 'hex')));

      // Add associated data for verification
      const associatedData = new Uint8Array(Buffer.from(signals.forAddress.toLowerCase()));
      decipher.setAAD(associatedData);

      decipher.setAuthTag(new Uint8Array(Buffer.from(signals.verificationTag, 'hex')));

      try {
        let decrypted = decipher.update(signals.encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return this._denormalizeData(decrypted);
      } catch {
        throw new Error('Data integrity check failed - possible tampering detected');
      }
    } catch (error) {
      throw new Error(`Decryption failed: ${(error as Error).message}`);
    }
  }

  private _toHex(input: Uint8Array | Buffer | string): Uint8Array {
    if (typeof input === 'string') {
      // If it's already a hex string, remove '0x' prefix if present
      const hex = input.startsWith('0x') ? input.slice(2) : input;
      return new Uint8Array(Buffer.from(hex, 'hex'));
    }
    // If it's Buffer or Uint8Array, convert to Uint8Array
    return new Uint8Array(input);
  }

  private _normalizeData(data: unknown): string {
    if (data === null) return 'null';
    if (data === undefined) return 'undefined';
    return typeof data === 'object' ? JSON.stringify(data) : String(data);
  }

  private _denormalizeData(data: string): string {
    if (data === 'null') return 'null';
    if (data === 'undefined') return 'undefined';
    try {
      const parsed = JSON.parse(data);
      return typeof parsed === 'string' ? parsed : JSON.stringify(parsed);
    } catch {
      return data;
    }
  }

  private _isPublicSignals(signals: unknown): signals is PublicSignals {
    return signals !== null && typeof signals === 'object' && signals !== null && 'encryptedData' in (signals as object);
  }

  private _validateSignals(signals: PublicSignals): void {
    if (!signals.encryptedData) throw new Error('Missing required field: encryptedData');
    if (!signals.initVector) throw new Error('Missing required field: initVector');
    if (!signals.verificationTag) throw new Error('Missing required field: verificationTag');
    if (!signals.ephemeralPublicKey) throw new Error('Missing required field: ephemeralPublicKey');
    if (!signals.forAddress) throw new Error('Missing required field: forAddress');
  }

  private _validateAndFormatPrivateKey(privateKey: string): Uint8Array {
    if (typeof privateKey !== 'string' || !privateKey.startsWith('0x')) {
      throw new Error('Invalid private key format');
    }

    return new Uint8Array(Buffer.from(privateKey.slice(2), 'hex'));
  }
}

export default Ed25519E2E;
