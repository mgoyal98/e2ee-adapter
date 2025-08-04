import { Request, Response, NextFunction } from 'express';
import { E2EEMiddlewareOptions, E2EEMiddleware, E2EEError } from '../types';
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

      // Decrypt request if there's a string body or if empty body is allowed
      if (finalConfig.enableRequestDecryption && typeof req.body === 'string') {
        const decryptedData = await decryptRequest(
          req,
          finalConfig,
          createError
        );

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
        (typeof req.body === 'undefined' ||
          Object.keys(req.body)?.length === 0 ||
          !req.body) &&
        !finalConfig.allowEmptyRequestBody
      ) {
        // If request has encryption headers but empty body is not allowed, throw error
        throw createError(
          'Missing encrypted data in request body',
          'MISSING_ENCRYPTED_DATA',
          400
        );
      } else if (
        finalConfig.enableRequestDecryption &&
        finalConfig.allowEmptyRequestBody &&
        (!req.body ||
          Object.keys(req.body)?.length === 0 ||
          typeof req.body === 'undefined')
      ) {
        // Handle empty request body with encryption headers for response encryption
        const { aesKey, iv } = await extractAESKeyFromHeaders(
          req,
          finalConfig,
          createError
        );

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
      } else if (finalConfig.enableRequestDecryption) {
        throw createError('Invalid request body', 'INVALID_REQUEST_BODY', 400);
      }

      if (
        !finalConfig.enableRequestDecryption &&
        finalConfig.enableResponseEncryption
      ) {
        const { aesKey, iv } = await extractAESKeyFromHeaders(
          req,
          finalConfig,
          createError
        );

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
      }

      // Handle response encryption only
      if (finalConfig.enableResponseEncryption) {
        // Store original send method
        const originalSend = res.send;

        // Override send method to encrypt response data
        res.send = function (data: any): Response {
          const e2eeContext = (req as any).e2ee;
          if (!e2eeContext || !e2eeContext.aesKey || !e2eeContext.iv) {
            // If no encryption context, send original data
            return originalSend.call(this, data);
          }

          // Handle encryption asynchronously
          encryptResponse(data, e2eeContext.aesKey, e2eeContext.iv, createError)
            .then((encryptedData) => {
              // Call onEncrypt callback if provided
              if (onEncrypt) {
                onEncrypt(
                  { data: encryptedData, timestamp: Date.now(), nonce: '' },
                  res
                );
              }

              // Send the encrypted data
              originalSend.call(this, encryptedData);
            })
            .catch((error) => {
              if (onError) {
                onError(error as Error, req, res);
              }

              // Send error response
              originalSend.call(this, {
                error: 'Encryption failed',
                message:
                  error instanceof Error ? error.message : 'Unknown error',
              });
            });

          // Return the response object for chaining
          return this;
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
