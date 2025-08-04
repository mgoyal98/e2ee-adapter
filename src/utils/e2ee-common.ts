import { Request } from 'express';
import { E2EEConfig, DecryptedData, E2EEError } from '../types';
import { decrypt, encryptAES, decryptAESKey } from './crypto';

export interface E2EECommonOptions {
  config: Required<E2EEConfig>;
  createError: (message: string, code: string, statusCode?: number) => E2EEError;
}

export interface E2EEContext {
  decryptedData: DecryptedData;
  originalBody: any;
  aesKey: Buffer;
  iv: Buffer;
}

export interface RequestProcessingResult {
  shouldContinue: boolean;
  e2eeContext?: E2EEContext;
}

/**
 * Check if request should be processed by E2EE
 */
export function shouldProcessRequest(
  req: Request,
  config: Required<E2EEConfig>
): boolean {
  // Skip excluded paths
  if (config.excludePaths.some((path) => req.path.startsWith(path))) {
    return false;
  }

  // Skip excluded methods
  if (config.excludeMethods.includes(req.method.toUpperCase())) {
    return false;
  }

  return true;
}

/**
 * Check if request has encryption headers
 */
export function hasEncryptionHeaders(
  req: Request,
  config: Required<E2EEConfig>
): boolean {
  const encryptedKeyHeader = req.headers[
    config.customKeyHeader.toLowerCase()
  ] as string;
  const ivHeader = req.headers[
    config.customIVHeader.toLowerCase()
  ] as string;
  const keyIdHeader = req.headers[
    config.keyIdHeader.toLowerCase()
  ] as string;

  return !!(encryptedKeyHeader && ivHeader && keyIdHeader);
}

/**
 * Get key pair for a specific keyId
 */
export function getKeyPair(
  keyId: string,
  config: Required<E2EEConfig>,
  createError: (message: string, code: string, statusCode?: number) => E2EEError
): { privateKey: string; publicKey: string } {
  const keyPair = config.keys[keyId];

  if (!keyPair) {
    throw createError(
      `Key pair not found for keyId: ${keyId}`,
      'INVALID_KEY_ID',
      400
    );
  }

  return keyPair;
}

/**
 * Extract AES key from headers for response encryption (without decryption)
 */
export async function extractAESKeyFromHeaders(
  req: Request,
  config: Required<E2EEConfig>,
  createError: (message: string, code: string, statusCode?: number) => E2EEError
): Promise<{ aesKey: Buffer; iv: Buffer }> {
  const encryptedKeyHeader = req.headers[
    config.customKeyHeader.toLowerCase()
  ] as string;
  const ivHeader = req.headers[
    config.customIVHeader.toLowerCase()
  ] as string;
  const keyIdHeader = req.headers[
    config.keyIdHeader.toLowerCase()
  ] as string;

  if (!encryptedKeyHeader || !ivHeader || !keyIdHeader) {
    throw createError(
      'Missing encryption headers',
      'MISSING_ENCRYPTION_HEADERS'
    );
  }

  const keyPair = getKeyPair(keyIdHeader, config, createError);
  
  // Decrypt only the AES key from the header (no data decryption)
  const { aesKey, iv } = await decryptAESKey(
    encryptedKeyHeader,
    ivHeader,
    keyPair.privateKey
  );

  return { aesKey, iv };
}

/**
 * Decrypt request using headers
 */
export async function decryptRequest(
  req: Request,
  config: Required<E2EEConfig>,
  createError: (message: string, code: string, statusCode?: number) => E2EEError
): Promise<DecryptedData> {
  try {
    // Extract headers
    const encryptedKeyHeader = req.headers[
      config.customKeyHeader.toLowerCase()
    ] as string;
    const ivHeader = req.headers[
      config.customIVHeader.toLowerCase()
    ] as string;
    const keyIdHeader = req.headers[
      config.keyIdHeader.toLowerCase()
    ] as string;

    if (!encryptedKeyHeader || !ivHeader) {
      throw createError(
        'Missing encryption headers',
        'MISSING_ENCRYPTION_HEADERS'
      );
    }

    if (!keyIdHeader) {
      throw createError('Missing keyId header', 'MISSING_KEY_ID_HEADER');
    }

    // Handle empty request body case
    if (!req.body || typeof req.body !== 'string') {
      if (config.allowEmptyRequestBody) {
        // For empty request bodies, extract AES key from headers for response encryption
        const { aesKey, iv } = await extractAESKeyFromHeaders(req, config, createError);

        const decryptedData: DecryptedData = {
          data: {}, // Empty object for empty request body
          timestamp: Date.now(),
          nonce: '',
          aesKey,
          iv,
        };

        return decryptedData;
      } else {
        throw createError(
          'Missing encrypted data in request body',
          'MISSING_ENCRYPTED_DATA'
        );
      }
    }

    // Get the appropriate key pair based on keyId
    const keyPair = getKeyPair(keyIdHeader, config, createError);

    // Decrypt the data
    const decryptionResult = await decrypt(
      req.body,
      encryptedKeyHeader,
      ivHeader,
      keyPair.privateKey
    );

    const decryptedData: DecryptedData = {
      data: JSON.parse(decryptionResult.decryptedData),
      timestamp: Date.now(),
      nonce: decryptionResult.nonce,
      ...(decryptionResult.aesKey && { aesKey: decryptionResult.aesKey }),
      ...(decryptionResult.iv && { iv: decryptionResult.iv }),
    };

    return decryptedData;
  } catch (error) {
    if (error instanceof Error && 'code' in error) {
      throw error; // Re-throw E2EE errors
    }
    throw createError(
      `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      'DECRYPTION_FAILED'
    );
  }
}

/**
 * Encrypt response data
 */
export async function encryptResponse(
  data: any,
  aesKey: Buffer,
  iv: Buffer,
  createError: (message: string, code: string, statusCode?: number) => E2EEError
): Promise<string> {
  try {
    const dataString = JSON.stringify(data);
    return encryptAES(dataString, aesKey, iv);
  } catch (error) {
    throw createError(
      `Encryption failed: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`,
      'ENCRYPTION_FAILED'
    );
  }
}

/**
 * Merge configuration with defaults
 */
export function mergeConfigWithDefaults(config: E2EEConfig): Required<E2EEConfig> {
  return {
    keys: config.keys,
    customKeyHeader: config.customKeyHeader || 'x-custom-key',
    customIVHeader: config.customIVHeader || 'x-custom-iv',
    keyIdHeader: config.keyIdHeader || 'x-key-id',
    enableRequestDecryption: config.enableRequestDecryption !== false,
    enableResponseEncryption: config.enableResponseEncryption !== false,
    excludePaths: config.excludePaths || ['/health', '/keys', '/e2ee.json'],
    excludeMethods: config.excludeMethods || ['GET', 'HEAD', 'OPTIONS'],
    enforced: config.enforced || false,
    allowEmptyRequestBody: config.allowEmptyRequestBody || false,
  };
}

/**
 * Validate configuration
 */
export function validateConfig(config: E2EEConfig): void {
  if (!config.keys || Object.keys(config.keys).length === 0) {
    throw new Error('At least one key pair must be provided in config.keys');
  }
}

/**
 * Create E2EE error with consistent structure
 */
export function createE2EEError(
  message: string,
  code: string,
  statusCode: number = 400
): E2EEError {
  const error = new Error(message) as E2EEError;
  error.code = code;
  error.statusCode = statusCode;
  return error;
}

/**
 * Process request and determine if it should be handled by E2EE
 */
export function processRequest(
  req: Request,
  config: Required<E2EEConfig>,
  createError: (message: string, code: string, statusCode?: number) => E2EEError
): RequestProcessingResult {
  // Check if request should be processed
  if (!shouldProcessRequest(req, config)) {
    return { shouldContinue: true };
  }

  // Check enforcement mode
  if (config.enforced) {
    // In enforced mode, all requests must be encrypted
    if (!hasEncryptionHeaders(req, config)) {
      throw createError(
        'Encryption is enforced. All requests must include encryption headers.',
        'ENCRYPTION_ENFORCED',
        400
      );
    }
  } else {
    // In non-enforced mode, only process requests that have encryption headers
    if (!hasEncryptionHeaders(req, config)) {
      return { shouldContinue: true };
    }
  }

  return { shouldContinue: false };
}

/**
 * Handle request decryption and setup encryption context
 */
export async function handleRequestDecryption(
  req: Request,
  config: Required<E2EEConfig>,
  createError: (message: string, code: string, statusCode?: number) => E2EEError,
  onDecrypt?: (decryptedData: DecryptedData, req: Request) => void
): Promise<E2EEContext | undefined> {
  // Decrypt request if there's a string body or if empty body is allowed
  if (config.enableRequestDecryption && typeof req.body === 'string') {
    const decryptedData = await decryptRequest(req, config, createError);

    req.body = decryptedData.data;

    const e2eeContext: E2EEContext = {
      decryptedData,
      originalBody: req.body,
      aesKey: decryptedData.aesKey!,
      iv: decryptedData.iv!,
    };

    // Call onDecrypt callback if provided
    if (onDecrypt) {
      onDecrypt(decryptedData, req);
    }

    return e2eeContext;
  } else if (
    config.enableRequestDecryption &&
    hasEncryptionHeaders(req, config) &&
    (typeof req.body === 'undefined' ||
      Object.keys(req.body)?.length === 0 ||
      !req.body) &&
    !config.allowEmptyRequestBody
  ) {
    // If request has encryption headers but empty body is not allowed, throw error
    throw createError(
      'Missing encrypted data in request body',
      'MISSING_ENCRYPTED_DATA',
      400
    );
  } else if (
    config.enableRequestDecryption &&
    config.allowEmptyRequestBody &&
    (!req.body ||
      Object.keys(req.body)?.length === 0 ||
      typeof req.body === 'undefined')
  ) {
    // Handle empty request body with encryption headers for response encryption
    const { aesKey, iv } = await extractAESKeyFromHeaders(req, config, createError);

    const e2eeContext: E2EEContext = {
      decryptedData: {
        data: {},
        timestamp: Date.now(),
        nonce: '',
        aesKey,
        iv,
      },
      originalBody: {},
      aesKey,
      iv,
    };

    // Call onDecrypt callback if provided
    if (onDecrypt) {
      onDecrypt(e2eeContext.decryptedData, req);
    }

    return e2eeContext;
  } else if (config.enableRequestDecryption) {
    throw createError('Invalid request body', 'INVALID_REQUEST_BODY', 400);
  }

  return undefined;
}

/**
 * Setup encryption context for response-only encryption
 */
export async function setupResponseEncryptionContext(
  req: Request,
  config: Required<E2EEConfig>,
  createError: (message: string, code: string, statusCode?: number) => E2EEError
): Promise<E2EEContext> {
  const { aesKey, iv } = await extractAESKeyFromHeaders(req, config, createError);

  const e2eeContext: E2EEContext = {
    decryptedData: {
      data: {},
      timestamp: Date.now(),
      nonce: '',
      aesKey,
      iv,
    },
    originalBody: {},
    aesKey,
    iv,
  };

  return e2eeContext;
}

/**
 * Handle response encryption with consistent error handling
 */
export async function handleResponseEncryption(
  data: any,
  e2eeContext: E2EEContext,
  createError: (message: string, code: string, statusCode?: number) => E2EEError,
  onEncrypt?: (encryptedData: any, res: any) => void,
  res?: any
): Promise<string> {
  if (!e2eeContext || !e2eeContext.aesKey || !e2eeContext.iv) {
    throw createError(
      'Missing encryption context for response',
      'MISSING_ENCRYPTION_CONTEXT',
      500
    );
  }

  const encryptedData = await encryptResponse(
    data,
    e2eeContext.aesKey,
    e2eeContext.iv,
    createError
  );

  // Call onEncrypt callback if provided
  if (onEncrypt) {
    onEncrypt(
      { data: encryptedData, timestamp: Date.now(), nonce: '' },
      res
    );
  }

  return encryptedData;
} 