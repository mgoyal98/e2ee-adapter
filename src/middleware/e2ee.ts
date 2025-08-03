import { Request, Response, NextFunction } from 'express';
import { 
  E2EEConfig, 
  E2EEMiddlewareOptions, 
  E2EEMiddleware, 
  E2EEError,
  EncryptedData,
  DecryptedData
} from '../types';
import { encrypt, decrypt, sign, verify } from '../utils/crypto';

/**
 * Create E2EE middleware for Express.js
 * @param options - Middleware configuration options
 * @returns E2EEMiddleware function
 */
export function createE2EEMiddleware(options: E2EEMiddlewareOptions): E2EEMiddleware {
  const {
    config,
    onError,
    onDecrypt,
    onEncrypt
  } = options;

  // Set default values
  const finalConfig: Required<E2EEConfig> = {
    privateKey: config.privateKey,
    publicKey: config.publicKey,
    algorithm: config.algorithm || 'RSA-OAEP',
    encoding: config.encoding || 'base64',
    encryptedDataHeader: config.encryptedDataHeader || 'x-encrypted-data',
    signatureHeader: config.signatureHeader || 'x-signature',
    enableRequestDecryption: config.enableRequestDecryption !== false,
    enableResponseEncryption: config.enableResponseEncryption !== false,
    enableSignatureVerification: config.enableSignatureVerification !== false,
    enableResponseSigning: config.enableResponseSigning !== false,
    excludePaths: config.excludePaths || [],
    excludeMethods: config.excludeMethods || ['GET', 'HEAD', 'OPTIONS']
  };

  /**
   * Check if the request should be processed by E2EE
   */
  function shouldProcessRequest(req: Request): boolean {
    const path = req.path;
    const method = req.method.toUpperCase();

    // Check if path is excluded
    if (finalConfig.excludePaths.some(excludedPath => 
      path.startsWith(excludedPath) || path === excludedPath
    )) {
      return false;
    }

    // Check if method is excluded
    if (finalConfig.excludeMethods.includes(method)) {
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
   * Decrypt request body
   */
  async function decryptRequest(req: Request): Promise<DecryptedData> {
    try {
      const encryptedDataHeader = req.headers[finalConfig.encryptedDataHeader.toLowerCase()] as string;
      const signatureHeader = req.headers[finalConfig.signatureHeader.toLowerCase()] as string;

      if (!encryptedDataHeader) {
        throw createError('Missing encrypted data header', 'MISSING_ENCRYPTED_DATA');
      }

      // Parse encrypted data
      const encryptedData: EncryptedData = JSON.parse(encryptedDataHeader);
      
      // Verify timestamp to prevent replay attacks (5 minutes window)
      const now = Date.now();
      const timeDiff = Math.abs(now - encryptedData.timestamp);
      if (timeDiff > 5 * 60 * 1000) { // 5 minutes
        throw createError('Request timestamp is too old or too new', 'INVALID_TIMESTAMP');
      }

      // Verify signature if enabled
      if (finalConfig.enableSignatureVerification && signatureHeader) {
        const isValid = await verify(
          encryptedData.data,
          signatureHeader,
          finalConfig.publicKey,
          'RSA-SHA256'
        );
        
        if (!isValid) {
          throw createError('Invalid signature', 'INVALID_SIGNATURE', 401);
        }
      }

      // Decrypt the data
      const decryptionResult = await decrypt(
        encryptedData.data,
        finalConfig.privateKey
      );

      const decryptedData: DecryptedData = {
        data: JSON.parse(decryptionResult.decryptedData),
        signature: signatureHeader,
        timestamp: encryptedData.timestamp,
        nonce: decryptionResult.nonce
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
  async function encryptResponse(data: any): Promise<EncryptedData> {
    try {
      const dataString = JSON.stringify(data);
      const timestamp = Date.now();

      // Encrypt the data
      const encryptionResult = await encrypt(
        dataString,
        finalConfig.publicKey
      );

      const encryptedData: EncryptedData = {
        data: encryptionResult.encryptedData,
        timestamp,
        nonce: encryptionResult.nonce
      };

      // Sign the encrypted data if enabled
      if (finalConfig.enableResponseSigning) {
        encryptedData.signature = await sign(
          encryptionResult.encryptedData,
          finalConfig.privateKey,
          'RSA-SHA256'
        );
      }

      return encryptedData;
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
        
        // Store decrypted data for potential use
        (req as any).e2ee = {
          decryptedData,
          originalBody: req.body
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
            const encryptedData = await encryptResponse(data);
            
            // Set headers
            res.set(finalConfig.encryptedDataHeader, JSON.stringify(encryptedData));
            if (encryptedData.signature) {
              res.set(finalConfig.signatureHeader, encryptedData.signature);
            }
            
            // Call onEncrypt callback if provided
            if (onEncrypt) {
              onEncrypt(encryptedData, res);
            }

            // Send encrypted data in response body
            res.json({
              encrypted: true,
              data: encryptedData.data,
              timestamp: encryptedData.timestamp,
              nonce: encryptedData.nonce
            });
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