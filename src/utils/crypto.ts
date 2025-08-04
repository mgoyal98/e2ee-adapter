import * as crypto from 'node:crypto';

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export interface EncryptionResult {
  encryptedData: string;
  nonce: string;
}

export interface DecryptionResult {
  decryptedData: string;
  nonce: string;
  aesKey?: Buffer;
  iv?: Buffer;
}

/**
 * Generate RSA key pair
 * @param keySize - Key size in bits (default: 2048)
 * @returns Promise<KeyPair>
 */
export async function generateKeyPair(
  keySize: number = 2048,
): Promise<KeyPair> {
  return new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      'rsa',
      {
        modulusLength: keySize,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      },
      (err, publicKey, privateKey) => {
        if (err) {
          reject(new Error(`Key generation failed: ${err.message}`));
        } else {
          resolve({ publicKey, privateKey });
        }
      },
    );
  });
}

/**
 * Encrypt data using hybrid encryption (AES-CBC + RSA)
 * @param data - Data to encrypt
 * @param publicKey - RSA public key
 * @returns Promise<{ encryptedData: string, aesKey: Buffer, iv: Buffer, originalAesKey: Buffer }>
 */
export async function encrypt(
  data: string,
  publicKey: string,
): Promise<{
  encryptedData: string;
  aesKey: Buffer;
  iv: Buffer;
  originalAesKey: Buffer;
}> {
  try {
    // 1. Generate AES key (32 bytes) and IV (16 bytes)
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    // 2. Encrypt the data using AES-CBC
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    // 3. Encrypt the AES key using RSA
    const encryptedKey = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      aesKey,
    );

    return {
      encryptedData: encrypted,
      aesKey: encryptedKey,
      iv: iv,
      originalAesKey: aesKey, // Return the original AES key for response decryption
    };
  } catch (error) {
    throw new Error(
      `Encryption failed: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`,
    );
  }
}

/**
 * Decrypt only the AES key from the encrypted key header (for empty request bodies)
 * @param encryptedKey - Encrypted AES key (base64)
 * @param privateKey - RSA private key
 * @returns Promise<{ aesKey: Buffer, iv: Buffer }>
 */
export async function decryptAESKey(
  encryptedKey: string,
  iv: string,
  privateKey: string,
): Promise<{ aesKey: Buffer; iv: Buffer }> {
  try {
    // Decrypt only the AES key using RSA
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encryptedKey, 'base64'),
    );

    return {
      aesKey: aesKey,
      iv: Buffer.from(iv, 'base64'),
    };
  } catch (error) {
    throw new Error(
      `AES key decryption failed: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`,
    );
  }
}

/**
 * Decrypt data using hybrid decryption (AES-CBC + RSA)
 * @param encryptedData - Encrypted data (base64)
 * @param encryptedKey - RSA encrypted AES key (base64)
 * @param iv - Initialization vector (base64)
 * @param privateKey - RSA private key
 * @returns Promise<DecryptionResult>
 */
export async function decrypt(
  encryptedData: string,
  encryptedKey: string,
  iv: string,
  privateKey: string,
): Promise<DecryptionResult> {
  try {
    // 1. Decrypt the AES key using RSA
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encryptedKey, 'base64'),
    );

    // 2. Decrypt the data using AES-CBC
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      aesKey,
      Buffer.from(iv, 'base64'),
    );
    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return {
      decryptedData: decrypted,
      nonce: '', // Not used in this implementation
      aesKey: aesKey,
      iv: Buffer.from(iv, 'base64'),
    };
  } catch (error) {
    throw new Error(
      `Decryption failed: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`,
    );
  }
}

/**
 * Encrypt data using AES-CBC (for server responses)
 * @param data - Data to encrypt
 * @param aesKey - AES key
 * @param iv - Initialization vector
 * @returns string - Encrypted data (base64)
 */
export function encryptAES(data: string, aesKey: Buffer, iv: Buffer): string {
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  let encrypted = cipher.update(data, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

/**
 * Decrypt data using AES-CBC (for client responses)
 * @param encryptedData - Encrypted data (base64)
 * @param aesKey - AES key
 * @param iv - Initialization vector
 * @returns string - Decrypted data
 */
export function decryptAES(
  encryptedData: string,
  aesKey: Buffer,
  iv: Buffer,
): string {
  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Generate a secure random string
 * @param length - Length of the string
 * @returns string
 */
export function generateNonce(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Hash data using SHA-256
 * @param data - Data to hash
 * @returns string
 */
export function hash(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Generate multiple RSA key pairs for multi-domain support
 * @param keyIds - Array of key IDs to generate
 * @param keySize - Key size in bits (default: 2048)
 * @returns Promise<{ [keyId: string]: KeyPair }>
 */
export async function generateMultipleKeyPairs(
  keyIds: string[],
  keySize: number = 2048,
): Promise<{ [keyId: string]: KeyPair }> {
  const keyPairs: { [keyId: string]: KeyPair } = {};

  for (const keyId of keyIds) {
    keyPairs[keyId] = await generateKeyPair(keySize);
  }

  return keyPairs;
}
