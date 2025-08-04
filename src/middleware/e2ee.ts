import { Request, Response, NextFunction } from 'express';
import { E2EEMiddlewareOptions, E2EEMiddleware, E2EEError } from '../types';
import {
  processRequest,
  handleRequestDecryption,
  setupResponseEncryptionContext,
  handleResponseEncryption,
  mergeConfigWithDefaults,
  validateConfig,
  createE2EEError,
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
    return createE2EEError(message, code, statusCode);
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
      // Process request and check if it should be handled
      const processingResult = processRequest(req, finalConfig, createError);
      if (processingResult.shouldContinue) {
        return next();
      }

      // Handle request decryption
      let e2eeContext = await handleRequestDecryption(
        req,
        finalConfig,
        createError,
        onDecrypt
      );

      // Setup encryption context for response-only encryption if needed
      if (
        !finalConfig.enableRequestDecryption &&
        finalConfig.enableResponseEncryption
      ) {
        e2eeContext = await setupResponseEncryptionContext(
          req,
          finalConfig,
          createError
        );
      }

      // Store encryption context for response
      if (e2eeContext) {
        (req as any).e2ee = e2eeContext;
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
          handleResponseEncryption(
            data,
            e2eeContext,
            createError,
            onEncrypt,
            res
          )
            .then((encryptedData) => {
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
