import { encrypt, decrypt } from '../utils/crypto';
import { EncryptedData, KeyPair } from '../types';

export interface E2EEClientConfig {
  /** Server's public key for encryption */
  serverPublicKey: string;
  /** Algorithm for encryption (default: RSA-OAEP) */
  algorithm?: string;
  /** Enable response verification (default: false - client doesn't verify server signatures) */
  enableResponseVerification?: boolean;
}

export interface E2EEClientRequest {
  url: string;
  method: string;
  data?: any;
  headers?: Record<string, string>;
}

export interface E2EEClientResponse {
  data: any;
  headers: Record<string, string>;
  status: number;
  statusText: string;
}

export class E2EEClient {
  private readonly config: Required<E2EEClientConfig>;

  constructor(config: E2EEClientConfig) {
    this.config = {
      serverPublicKey: config.serverPublicKey,
      algorithm: config.algorithm || 'RSA-OAEP',
      enableResponseVerification: config.enableResponseVerification || false
    };
  }

  /**
   * Encrypt request data using server's public key
   * @param data - Data to encrypt
   * @returns Promise<{ encryptedData: string }>
   */
  async encryptRequest(data: any): Promise<{ encryptedData: string }> {
    try {
      const dataString = JSON.stringify(data);
      const timestamp = Date.now();

      // Encrypt the data using server's public key
      const encryptionResult = await encrypt(
        dataString,
        this.config.serverPublicKey
      );

      const encryptedData: EncryptedData = {
        data: encryptionResult.encryptedData,
        timestamp,
        nonce: encryptionResult.nonce
      };

      return {
        encryptedData: JSON.stringify(encryptedData)
      };
    } catch (error) {
      throw new Error(`Request encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Decrypt response data (if client has server's private key - not typical)
   * Note: In typical client-server architecture, client doesn't decrypt server responses
   * @param encryptedData - Encrypted data
   * @param serverPrivateKey - Server's private key (not typically available to client)
   * @returns Promise<any>
   */
  async decryptResponse(encryptedData: string, serverPrivateKey?: string): Promise<any> {
    if (!serverPrivateKey) {
      throw new Error('Server private key required for decryption (not typically available to client)');
    }

    try {
      const encryptedObj = JSON.parse(encryptedData);
      
      // Verify timestamp to prevent replay attacks (5 minutes window)
      const now = Date.now();
      const timeDiff = Math.abs(now - encryptedObj.timestamp);
      if (timeDiff > 5 * 60 * 1000) { // 5 minutes
        throw new Error('Response timestamp is too old or too new');
      }

      // Decrypt the data using server's private key
      const decryptionResult = await decrypt(
        encryptedObj.data,
        serverPrivateKey
      );

      return JSON.parse(decryptionResult.decryptedData);
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
      const { url, method, data, headers = {} } = requestConfig;

      // Prepare request headers
      const requestHeaders: Record<string, string> = {
        'Content-Type': 'application/json',
        ...headers
      };

      let requestBody: any = {};

      // Encrypt request data if provided
      if (data) {
        const { encryptedData } = await this.encryptRequest(data);
        requestHeaders['x-encrypted-data'] = encryptedData;
        requestBody = { encrypted: true, data: encryptedData };
      }

      // Make the HTTP request
      const fetchOptions: RequestInit = {
        method,
        headers: requestHeaders
      };
      
      if (data) {
        fetchOptions.body = JSON.stringify(requestBody);
      }
      
      const response = await fetch(url, fetchOptions);

      // Parse response headers
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      // Get response data
      const responseData = await response.json() as any;

      // In typical client-server architecture, client doesn't decrypt server responses
      // The server response is already in plain text or handled by the application layer
      let decryptedData = responseData;
      
      // Only decrypt if explicitly configured and server private key is available
      if (responseData.encrypted && responseData.data && this.config.enableResponseVerification) {
        console.warn('⚠️ Client-side response decryption is not typical in client-server architecture');
        // In real scenarios, the server would send plain text responses
        // or the application would handle encrypted responses differently
      }

      return {
        data: decryptedData,
        headers: responseHeaders,
        status: response.status,
        statusText: response.statusText
      };
    } catch (error) {
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