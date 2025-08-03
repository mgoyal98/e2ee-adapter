// import { Request, Response, NextFunction } from 'express';

export interface KeyPair {
  /** RSA public key in PEM format */
  publicKey: string;
  /** RSA private key in PEM format */
  privateKey: string;
}

export interface KeyStore {
  /** Mapping of keyId to key pair */
  [keyId: string]: KeyPair;
}

export interface E2EEConfig {
  /** Multiple keys store for multi-domain support */
  keys: KeyStore;
  /** Custom key header name (default: x-custom-key) */
  customKeyHeader?: string;
  /** Custom IV header name (default: x-custom-iv) */
  customIVHeader?: string;
  /** Key ID header name (default: x-key-id) */
  keyIdHeader?: string;
  /** Enable request decryption (default: true) */
  enableRequestDecryption?: boolean;
  /** Enable response encryption (default: true) */
  enableResponseEncryption?: boolean;
  /** Paths to exclude from encryption (default: ['/health', '/keys', '/e2ee.json']) */
  excludePaths?: string[];
  /** HTTP methods to exclude from encryption (default: ['GET', 'HEAD', 'OPTIONS']) */
  excludeMethods?: string[];
}

export interface EncryptedData {
  /** Encrypted data (base64) */
  data: string;
  /** Timestamp for replay protection */
  timestamp: number;
  /** Nonce for additional security */
  nonce: string;
}

export interface DecryptedData {
  /** Decrypted data */
  data: any;
  /** Timestamp */
  timestamp: number;
  /** Nonce */
  nonce: string;
  /** AES key for response encryption */
  aesKey?: Buffer;
  /** Initialization vector for response encryption */
  iv?: Buffer;
}

export interface E2EEMiddlewareOptions {
  /** E2EE configuration */
  config: E2EEConfig;
  /** Error callback */
  onError?: (error: Error, req: any, res: any) => void;
  /** Decryption callback */
  onDecrypt?: (decryptedData: DecryptedData, req: any) => void;
  /** Encryption callback */
  onEncrypt?: (encryptedData: EncryptedData, res: any) => void;
}

export interface E2EEError extends Error {
  code: string;
  statusCode?: number;
}

export type E2EEMiddleware = (req: any, res: any, next: any) => void;

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
}

export interface E2EEClientResponse {
  data: any;
  headers: Record<string, string>;
  status: number;
  statusText: string;
}
