import { Request, Response, NextFunction } from 'express';

export interface E2EEConfig {
  /** RSA private key for decryption */
  privateKey: string;
  /** RSA public key for encryption */
  publicKey: string;
  /** Algorithm for encryption (default: RSA-OAEP) */
  algorithm?: string;
  /** Encoding for keys (default: 'base64') */
  encoding?: 'ascii' | 'utf8' | 'utf-8' | 'utf16le' | 'ucs2' | 'ucs-2' | 'base64' | 'base64url' | 'latin1' | 'binary' | 'hex';
  /** Custom headers for encrypted data */
  encryptedDataHeader?: string;
  /** Custom headers for signature */
  signatureHeader?: string;
  /** Enable request decryption (default: true) */
  enableRequestDecryption?: boolean;
  /** Enable response encryption (default: true) */
  enableResponseEncryption?: boolean;
  /** Enable signature verification (default: true) */
  enableSignatureVerification?: boolean;
  /** Enable response signing (default: true) */
  enableResponseSigning?: boolean;
  /** Paths to exclude from encryption/decryption */
  excludePaths?: string[];
  /** Methods to exclude from encryption/decryption */
  excludeMethods?: string[];
}

export interface EncryptedData {
  data: string;
  signature?: string;
  timestamp: number;
  nonce: string;
}

export interface DecryptedData {
  data: any;
  signature?: string;
  timestamp: number;
  nonce: string;
}

export interface E2EEMiddlewareOptions {
  config: E2EEConfig;
  onError?: (error: Error, req: Request, res: Response) => void;
  onDecrypt?: (decryptedData: DecryptedData, req: Request) => void;
  onEncrypt?: (encryptedData: EncryptedData, res: Response) => void;
}

export interface E2EEError extends Error {
  code: string;
  statusCode: number;
}

export type E2EEMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => void | Promise<void>;

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export interface EncryptionResult {
  encryptedData: string;
  signature?: string;
  nonce: string;
}

export interface DecryptionResult {
  decryptedData: any;
  signature?: string;
  nonce: string;
}

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