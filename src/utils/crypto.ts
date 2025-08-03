import * as crypto from 'crypto';
import { KeyPair, EncryptionResult, DecryptionResult } from '../types';

/**
 * Generate RSA key pair
 * @param keySize - Key size in bits (default: 2048)
 * @returns Promise<KeyPair>
 */
export async function generateKeyPair(keySize: number = 2048): Promise<KeyPair> {
  return new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      'rsa',
      {
        modulusLength: keySize,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      },
      (err, publicKey, privateKey) => {
        if (err) {
          reject(err);
        } else {
          resolve({
            publicKey: publicKey as string,
            privateKey: privateKey as string
          });
        }
      }
    );
  });
}

/**
 * Encrypt data using RSA public key
 * @param data - Data to encrypt
 * @param publicKey - RSA public key
 * @param algorithm - Encryption algorithm (default: RSA-OAEP)
 * @returns Promise<EncryptionResult>
 */
export async function encrypt(
  data: string,
  publicKey: string
): Promise<EncryptionResult> {
  try {
    // Generate a random nonce for additional security
    const nonce = crypto.randomBytes(32).toString('hex');
    
    // Create a hybrid encryption approach
    // 1. Generate a random AES key
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    // 2. Encrypt the data with AES
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();
    
    // 3. Encrypt the AES key with RSA
    const encryptedKey = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      aesKey
    );
    
    // 4. Combine all encrypted data
    const encryptedData = {
      encryptedKey: encryptedKey.toString('base64'),
      encryptedData: encrypted,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      nonce
    };
    
    return {
      encryptedData: JSON.stringify(encryptedData),
      nonce
    };
  } catch (error) {
    throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Decrypt data using RSA private key
 * @param encryptedData - Encrypted data
 * @param privateKey - RSA private key
 * @param algorithm - Decryption algorithm (default: RSA-OAEP)
 * @returns Promise<DecryptionResult>
 */
export async function decrypt(
  encryptedData: string,
  privateKey: string
): Promise<DecryptionResult> {
  try {
    const encryptedObj = JSON.parse(encryptedData);
    
    // 1. Decrypt the AES key with RSA
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(encryptedObj.encryptedKey, 'base64')
    );
    
    // 2. Decrypt the data with AES
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(encryptedObj.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(encryptedObj.authTag, 'base64'));
    
    let decrypted = decipher.update(encryptedObj.encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return {
      decryptedData: decrypted,
      nonce: encryptedObj.nonce
    };
  } catch (error) {
    throw new Error(`Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Sign data using RSA private key
 * @param data - Data to sign
 * @param privateKey - RSA private key
 * @param algorithm - Signing algorithm (default: RSA-SHA256)
 * @returns Promise<string>
 */
export async function sign(
  data: string,
  privateKey: string,
  algorithm: string = 'RSA-SHA256'
): Promise<string> {
  try {
    const sign = crypto.createSign(algorithm);
    sign.update(data);
    return sign.sign(privateKey, 'base64');
  } catch (error) {
    throw new Error(`Signing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Verify signature using RSA public key
 * @param data - Original data
 * @param signature - Signature to verify
 * @param publicKey - RSA public key
 * @param algorithm - Verification algorithm (default: RSA-SHA256)
 * @returns Promise<boolean>
 */
export async function verify(
  data: string,
  signature: string,
  publicKey: string,
  algorithm: string = 'RSA-SHA256'
): Promise<boolean> {
  try {
    const verify = crypto.createVerify(algorithm);
    verify.update(data);
    return verify.verify(publicKey, signature, 'base64');
  } catch (error) {
    throw new Error(`Verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
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