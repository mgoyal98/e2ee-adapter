import { Request, Response, NextFunction } from 'express';
import {
  E2EEMiddlewareOptions,
  E2EEMiddleware,
  E2EEConfig,
  E2EEError,
  DecryptedData
} from '../types';
import { decrypt, encryptAES } from '../utils/crypto';

/**
 * Create E2EE middleware for Express.js
 * @param options - Middleware configuration options
 * @returns E2EEMiddleware
 */
export function createE2EEMiddleware(options: E2EEMiddlewareOptions): E2EEMiddleware {
  const { config, onError, onDecrypt, onEncrypt } = options;

  // Merge configuration with defaults
  const finalConfig: Required<E2EEConfig> = {
    privateKey: config.privateKey,
    publicKey: config.publicKey,
    algorithm: config.algorithm || 'RSA-OAEP',
    encoding: config.encoding || 'base64',
    customKeyHeader: config.customKeyHeader || 'x-custom-key',
    customIVHeader: config.customIVHeader || 'x-custom-iv',
    keyIdHeader: config.keyIdHeader || 'x-key-id',
    enableRequestDecryption: config.enableRequestDecryption !== false,
    enableResponseEncryption: config.enableResponseEncryption !== false,
    excludePaths: config.excludePaths || ['/health', '/keys', '/e2ee.json'],
    excludeMethods: config.excludeMethods || ['GET', 'HEAD', 'OPTIONS']
  };

  /**
   * Check if request should be processed by E2EE
   */
  function shouldProcessRequest(req: Request): boolean {
    // Skip excluded paths
    if (finalConfig.excludePaths.some(path => req.path.startsWith(path))) {
      return false;
    }

    // Skip excluded methods
    if (finalConfig.excludeMethods.includes(req.method.toUpperCase())) {
      return false;
    }

    return true;
  }

  /**
   * Create E2EE error
   */
  function createError(message: string, code: string, statusCode: number = 400): E2EEError {
    const error = new Error(message) as E2EEError;
    error.code = code;
    error.statusCode = statusCode;
    return error;
  }

  /**
   * Decrypt request using headers
   */
  async function decryptRequest(req: Request): Promise<DecryptedData> {
    try {
      // Extract headers
      const encryptedKeyHeader = req.headers[finalConfig.customKeyHeader.toLowerCase()] as string;
      const ivHeader = req.headers[finalConfig.customIVHeader.toLowerCase()] as string;
      // const keyIdHeader = req.headers[finalConfig.keyIdHeader.toLowerCase()] as string;

      if (!encryptedKeyHeader || !ivHeader) {
        throw createError('Missing encryption headers', 'MISSING_ENCRYPTION_HEADERS');
      }

      // Get encrypted data from request body
      if (!req.body || typeof req.body !== 'string') {
        throw createError('Missing encrypted data in request body', 'MISSING_ENCRYPTED_DATA');
      }

      // Decrypt the data
      const decryptionResult = await decrypt(
        req.body,
        encryptedKeyHeader,
        ivHeader,
        finalConfig.privateKey
      );

      const decryptedData: DecryptedData = {
        data: JSON.parse(decryptionResult.decryptedData),
        timestamp: Date.now(),
        nonce: decryptionResult.nonce,
        ...(decryptionResult.aesKey && { aesKey: decryptionResult.aesKey }),
        ...(decryptionResult.iv && { iv: decryptionResult.iv })
      };

      return decryptedData;
    } catch (error) {
      if (error instanceof Error && 'code' in error) {
        throw error;
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
  async function encryptResponse(data: any, aesKey: Buffer, iv: Buffer): Promise<string> {
    try {
      const dataString = JSON.stringify(data);
      return encryptAES(dataString, aesKey, iv);
    } catch (error) {
      throw createError(
        `Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'ENCRYPTION_FAILED'
      );
    }
  }

  /**
   * Main middleware function
   */
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Check if request should be processed
      if (!shouldProcessRequest(req)) {
        return next();
      }

      // Decrypt request if enabled
      if (finalConfig.enableRequestDecryption && req.body) {
        const decryptedData = await decryptRequest(req);
        
        // Update request body with decrypted data
        req.body = decryptedData.data;
        
        // Store decrypted data and encryption details for response
        (req as any).e2ee = {
          decryptedData,
          originalBody: req.body,
          aesKey: decryptedData.aesKey,
          iv: decryptedData.iv
        };

        // Call onDecrypt callback if provided
        if (onDecrypt) {
          onDecrypt(decryptedData, req);
        }
      }

      // Add encryption capability to response object
      if (finalConfig.enableResponseEncryption) {
        (res as any).encryptAndSend = async function(data: any): Promise<void> {
          try {
            // Get AES key and IV from request context
            const e2eeContext = (req as any).e2ee;
            if (!e2eeContext || !e2eeContext.aesKey || !e2eeContext.iv) {
              throw new Error('Missing encryption context for response');
            }

            const encryptedData = await encryptResponse(data, e2eeContext.aesKey, e2eeContext.iv);
            
            // Call onEncrypt callback if provided
            if (onEncrypt) {
              onEncrypt({ data: encryptedData, timestamp: Date.now(), nonce: '' }, res);
            }

            // Send encrypted data in response body
            res.send(encryptedData);
          } catch (error) {
            if (onError) {
              onError(error as Error, req, res);
            }
            res.status(500).json({
              error: 'Encryption failed',
              message: error instanceof Error ? error.message : 'Unknown error'
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
        message: e2eeError.message
      });
    }
  };
} 