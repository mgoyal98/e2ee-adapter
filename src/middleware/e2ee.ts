import { Request, Response, NextFunction } from 'express';
import {
  E2EEMiddlewareOptions,
  E2EEMiddleware,
  E2EEConfig,
  E2EEError,
  DecryptedData,
} from '../types';
import { decrypt, encryptAES, decryptAESKey } from '../utils/crypto';

/**
 * Create E2EE middleware for Express.js
 * @param options - Middleware configuration options
 * @returns E2EEMiddleware
 */
export function createE2EEMiddleware(
  options: E2EEMiddlewareOptions
): E2EEMiddleware {
  const { config, onError, onDecrypt, onEncrypt } = options;

  // Validate that we have keys
  if (!config.keys || Object.keys(config.keys).length === 0) {
    throw new Error('At least one key pair must be provided in config.keys');
  }

  // Merge configuration with defaults
  const finalConfig: Required<E2EEConfig> = {
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

  /**
   * Check if request should be processed by E2EE
   */
  function shouldProcessRequest(req: Request): boolean {
    // Skip excluded paths
    if (finalConfig.excludePaths.some((path) => req.path.startsWith(path))) {
      return false;
    }

    // Skip excluded methods
    if (finalConfig.excludeMethods.includes(req.method.toUpperCase())) {
      return false;
    }

    return true;
  }

  /**
   * Check if request has encryption headers
   */
  function hasEncryptionHeaders(req: Request): boolean {
    const encryptedKeyHeader = req.headers[
      finalConfig.customKeyHeader.toLowerCase()
    ] as string;
    const ivHeader = req.headers[
      finalConfig.customIVHeader.toLowerCase()
    ] as string;
    const keyIdHeader = req.headers[
      finalConfig.keyIdHeader.toLowerCase()
    ] as string;

    return !!(encryptedKeyHeader && ivHeader && keyIdHeader);
  }

  /**
   * Create E2EE error
   */
  function createError(
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
   * Get key pair for a specific keyId
   */
  function getKeyPair(keyId: string): {
    privateKey: string;
    publicKey: string;
  } {
    const keyPair = finalConfig.keys[keyId];

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
  async function extractAESKeyFromHeaders(
    req: Request
  ): Promise<{ aesKey: Buffer; iv: Buffer }> {
    const encryptedKeyHeader = req.headers[
      finalConfig.customKeyHeader.toLowerCase()
    ] as string;
    const ivHeader = req.headers[
      finalConfig.customIVHeader.toLowerCase()
    ] as string;
    const keyIdHeader = req.headers[
      finalConfig.keyIdHeader.toLowerCase()
    ] as string;

    if (!encryptedKeyHeader || !ivHeader || !keyIdHeader) {
      throw createError(
        'Missing encryption headers',
        'MISSING_ENCRYPTION_HEADERS'
      );
    }

    const keyPair = getKeyPair(keyIdHeader);
    
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
  async function decryptRequest(req: Request): Promise<DecryptedData> {
    try {
      // Extract headers
      const encryptedKeyHeader = req.headers[
        finalConfig.customKeyHeader.toLowerCase()
      ] as string;
      const ivHeader = req.headers[
        finalConfig.customIVHeader.toLowerCase()
      ] as string;
      const keyIdHeader = req.headers[
        finalConfig.keyIdHeader.toLowerCase()
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
        if (finalConfig.allowEmptyRequestBody) {
          // For empty request bodies, extract AES key from headers for response encryption
          const { aesKey, iv } = await extractAESKeyFromHeaders(req);

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
      const keyPair = getKeyPair(keyIdHeader);

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
      if (error instanceof Error) {
        throw createError(
          `Decryption failed: ${error.message}`,
          'DECRYPTION_FAILED'
        );
      }
      throw createError('Decryption failed', 'DECRYPTION_FAILED');
    }
  }

  /**
   * Encrypt response data
   */
  async function encryptResponse(
    data: any,
    aesKey: Buffer,
    iv: Buffer
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
   * Main middleware function
   */
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      // Check if request should be processed
      if (!shouldProcessRequest(req)) {
        return next();
      }

      // Check enforcement mode
      if (finalConfig.enforced) {
        // In enforced mode, all requests must be encrypted
        if (!hasEncryptionHeaders(req)) {
          throw createError(
            'Encryption is enforced. All requests must include encryption headers.',
            'ENCRYPTION_ENFORCED',
            400
          );
        }
      } else {
        // In non-enforced mode, only process requests that have encryption headers
        if (!hasEncryptionHeaders(req)) {
          return next();
        }
      }

      // Decrypt request if enabled and has body
      if (finalConfig.enableRequestDecryption && req.body) {
        const decryptedData = await decryptRequest(req);

        // Update request body with decrypted data
        req.body = decryptedData.data;

        // Store decrypted data and encryption details for response
        (req as any).e2ee = {
          decryptedData,
          originalBody: req.body,
          aesKey: decryptedData.aesKey,
          iv: decryptedData.iv,
        };

        // Call onDecrypt callback if provided
        if (onDecrypt) {
          onDecrypt(decryptedData, req);
        }
      } else if (
        finalConfig.enableRequestDecryption &&
        hasEncryptionHeaders(req) &&
        !finalConfig.allowEmptyRequestBody &&
        !req.body
      ) {
        // If request has encryption headers but empty body is not allowed and there's no body
        throw createError(
          'Missing encrypted data in request body',
          'MISSING_ENCRYPTED_DATA'
        );
      } else if (
        finalConfig.enableRequestDecryption &&
        hasEncryptionHeaders(req) &&
        finalConfig.allowEmptyRequestBody &&
        !req.body
      ) {
        // Handle empty request body with encryption headers for response encryption
        const { aesKey, iv } = await extractAESKeyFromHeaders(req);

        // Store encryption context for response
        (req as any).e2ee = {
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
          onDecrypt((req as any).e2ee.decryptedData, req);
        }
      }

      // Add encryption capability to response object
      if (finalConfig.enableResponseEncryption) {
        (res as any).encryptAndSend = async function (
          data: any
        ): Promise<void> {
          try {
            // Get AES key and IV from request context
            const e2eeContext = (req as any).e2ee;
            if (!e2eeContext || !e2eeContext.aesKey || !e2eeContext.iv) {
              throw new Error('Missing encryption context for response');
            }

            const encryptedData = await encryptResponse(
              data,
              e2eeContext.aesKey,
              e2eeContext.iv
            );

            // Call onEncrypt callback if provided
            if (onEncrypt) {
              onEncrypt(
                { data: encryptedData, timestamp: Date.now(), nonce: '' },
                res
              );
            }

            // Send encrypted data in response body
            res.send(encryptedData);
          } catch (error) {
            if (onError) {
              onError(error as Error, req, res);
            }
            res.status(500).json({
              error: 'Encryption failed',
              message: error instanceof Error ? error.message : 'Unknown error',
            });
          }
        };
      }

      next();
    } catch (error) {
      if (onError) {
        onError(error as Error, req, res);
      }

      const e2eeError = error as E2EEError;
      res.status(e2eeError.statusCode || 400).json({
        error: 'E2EE Error',
        code: e2eeError.code || 'UNKNOWN_ERROR',
        message: e2eeError.message,
      });
    }
  };
}
