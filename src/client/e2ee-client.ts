import { encrypt, decryptAES } from '../utils/crypto';
import { KeyPair } from '../types';

export interface E2EEClientConfig {
  /** Multiple server keys for multi-domain support */
  serverKeys: { [keyId: string]: string };
  /** Key ID for versioning */
  keyId?: string;
}

export interface E2EEClientRequest {
  url: string;
  method: string;
  data?: any;
  headers?: Record<string, string>;
  keyId: string; // Required key ID to use for this request
}

export interface E2EEClientResponse {
  data: any;
  headers: Record<string, string>;
  status: number;
  statusText: string;
}

export class E2EEClient {
  private readonly serverKeys: { [keyId: string]: string };

  constructor(config: E2EEClientConfig) {
    // Validate configuration
    if (!config.serverKeys || Object.keys(config.serverKeys).length === 0) {
      throw new Error('serverKeys must be provided with at least one key');
    }

    // Build server keys map
    this.serverKeys = { ...config.serverKeys };
  }

  /**
   * Get server public key for a specific keyId
   */
  private getServerPublicKey(keyId: string): string {
    const publicKey = this.serverKeys[keyId];
    
    if (!publicKey) {
      throw new Error(`Server public key not found for keyId: ${keyId}`);
    }
    
    return publicKey;
  }

  /**
   * Encrypt request data using hybrid encryption (AES-CBC + RSA)
   * @param data - Data to encrypt
   * @param keyId - Key ID to use for encryption
   * @returns Promise<{ encryptedData: string, encryptedKey: string, iv: string, originalAesKey: Buffer, originalIv: Buffer }>
   */
  async encryptRequest(data: any, keyId: string): Promise<{ encryptedData: string, encryptedKey: string, iv: string, originalAesKey: Buffer, originalIv: Buffer }> {
    try {
      const dataString = JSON.stringify(data);
      const serverPublicKey = this.getServerPublicKey(keyId);

      // Encrypt the data using hybrid encryption
      const encryptionResult = await encrypt(dataString, serverPublicKey);

      return {
        encryptedData: encryptionResult.encryptedData,
        encryptedKey: encryptionResult.aesKey.toString('base64'),
        iv: encryptionResult.iv.toString('base64'),
        originalAesKey: encryptionResult.originalAesKey, // Use the original AES key for response decryption
        originalIv: encryptionResult.iv // Store the original IV for response decryption
      };
    } catch (error) {
      throw new Error(`Request encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Decrypt response data using AES-CBC
   * @param encryptedData - Encrypted data (base64)
   * @param aesKey - AES key (Buffer)
   * @param iv - Initialization vector (Buffer)
   * @returns Promise<any>
   */
  async decryptResponse(encryptedData: string, aesKey: Buffer, iv: Buffer): Promise<any> {
    try {
      const decryptedData = decryptAES(encryptedData, aesKey, iv);
      return JSON.parse(decryptedData);
    } catch (error) {
      throw new Error(`Response decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Make an encrypted HTTP request
   * @param requestConfig - Request configuration
   * @returns Promise<E2EEClientResponse>
   */
  async request(requestConfig: E2EEClientRequest): Promise<E2EEClientResponse> {
    try {
      const { url, method, data, headers = {}, keyId } = requestConfig;

      // Validate keyId is provided
      if (!keyId) {
        throw new Error('keyId is required for encrypted requests');
      }

      // Prepare request headers
      const requestHeaders: Record<string, string> = {
        'Content-Type': 'application/json',
        ...headers
      };

      let requestBody: string = '';
      let aesKey: Buffer | undefined;
      let iv: Buffer | undefined;

      // Encrypt request data if provided
      if (data) {
        const { encryptedData, encryptedKey, iv: ivString, originalAesKey, originalIv } = await this.encryptRequest(data, keyId);
        
        // Set encryption headers
        requestHeaders['x-custom-key'] = encryptedKey;
        requestHeaders['x-custom-iv'] = ivString;
        requestHeaders['x-key-id'] = keyId;
        
        // Store AES key and IV for response decryption
        aesKey = originalAesKey;
        iv = originalIv;
        
        // Set encrypted data as request body
        requestBody = encryptedData;
      }

      // Make the HTTP request
      const fetchOptions: RequestInit = {
        method,
        headers: requestHeaders
      };
      
      if (data) {
        fetchOptions.body = requestBody;
      }

      const response = await fetch(url, fetchOptions);

      // Parse response headers
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      // Get response data
      const responseData = await response.text();

      // Decrypt response if we have the AES key and IV
      let decryptedData = responseData;
      if (aesKey && iv && responseData) {
        try {
          decryptedData = await this.decryptResponse(responseData, aesKey, iv);
        } catch (error) {
          console.warn('Failed to decrypt response, returning raw data:', error);
          decryptedData = responseData;
        }
      }

      return {
        data: decryptedData,
        headers: responseHeaders,
        status: response.status,
        statusText: response.statusText
      };
    } catch (error) {
      console.log(error)
      throw new Error(`Request failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Generate a new key pair (for testing purposes only)
   * Note: In production, clients don't generate their own keys
   */
  static async generateKeyPair(keySize: number = 2048): Promise<KeyPair> {
    const { generateKeyPair } = await import('../utils/crypto');
    return generateKeyPair(keySize);
  }
} 