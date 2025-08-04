import { Request, Response, NextFunction } from 'express';
import {
  E2EEMiddlewareOptions,
  E2EEMiddleware,
  E2EEError,
} from '../types';
import {
  shouldProcessRequest,
  hasEncryptionHeaders,
  decryptRequest,
  encryptResponse,
  mergeConfigWithDefaults,
  validateConfig,
  extractAESKeyFromHeaders,
} from '../utils/e2ee-common';

/**
 * Create E2EE middleware for Express.js
 * @param options - Middleware configuration options
 * @returns E2EEMiddleware
 */
export function createE2EEMiddleware(
  options: E2EEMiddlewareOptions
): E2EEMiddleware {
  const { config, onError, onDecrypt, onEncrypt } = options;

  // Validate configuration
  validateConfig(config);

  // Merge configuration with defaults
  const finalConfig = mergeConfigWithDefaults(config);

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
   * Main middleware function
   */
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      // Check if request should be processed
      if (!shouldProcessRequest(req, finalConfig)) {
        return next();
      }

      // Check enforcement mode
      if (finalConfig.enforced) {
        // In enforced mode, all requests must be encrypted
        if (!hasEncryptionHeaders(req, finalConfig)) {
          throw createError(
            'Encryption is enforced. All requests must include encryption headers.',
            'ENCRYPTION_ENFORCED',
            400
          );
        }
      } else {
        // In non-enforced mode, only process requests that have encryption headers
        if (!hasEncryptionHeaders(req, finalConfig)) {
          return next();
        }
      }

      // Decrypt request if enabled and has body
      if (finalConfig.enableRequestDecryption && req.body) {
        const decryptedData = await decryptRequest(req, finalConfig, createError);

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
        hasEncryptionHeaders(req, finalConfig) &&
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
        hasEncryptionHeaders(req, finalConfig) &&
        finalConfig.allowEmptyRequestBody &&
        !req.body
      ) {
        // Handle empty request body with encryption headers for response encryption
        const { aesKey, iv } = await extractAESKeyFromHeaders(req, finalConfig, createError);

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
