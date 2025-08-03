import { Injectable, NestInterceptor, ExecutionContext, CallHandler, HttpException, HttpStatus } from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { map, catchError } from 'rxjs/operators';
import { Request, Response } from 'express';
import {
  E2EEConfig,
  EncryptedData,
  DecryptedData
} from '../types';
import { decrypt, encryptAES } from '../utils/crypto';

export interface E2EEInterceptorOptions {
  config: E2EEConfig;
  onError?: (error: Error, req: Request, res: Response) => void;
  onDecrypt?: (decryptedData: DecryptedData, req: Request) => void;
  onEncrypt?: (encryptedData: EncryptedData, res: Response) => void;
}

@Injectable()
export class E2EEInterceptor implements NestInterceptor {
  private readonly config: Required<E2EEConfig>;

  constructor(private readonly options: E2EEInterceptorOptions) {
    // Validate that we have keys
    if (!options.config.keys || Object.keys(options.config.keys).length === 0) {
      throw new Error('At least one key pair must be provided in config.keys');
    }

    // Merge configuration with defaults
    this.config = {
      keys: options.config.keys,
      customKeyHeader: options.config.customKeyHeader || 'x-custom-key',
      customIVHeader: options.config.customIVHeader || 'x-custom-iv',
      keyIdHeader: options.config.keyIdHeader || 'x-key-id',
      enableRequestDecryption: options.config.enableRequestDecryption !== false,
      enableResponseEncryption: options.config.enableResponseEncryption !== false,
      excludePaths: options.config.excludePaths || ['/health', '/keys', '/e2ee.json'],
      excludeMethods: options.config.excludeMethods || ['GET', 'HEAD', 'OPTIONS']
    };
  }

  /**
   * Check if request should be processed by E2EE
   */
  private shouldProcessRequest(req: Request): boolean {
    // Skip excluded paths
    if (this.config.excludePaths.some(path => req.path.startsWith(path))) {
      return false;
    }

    // Skip excluded methods
    if (this.config.excludeMethods.includes(req.method.toUpperCase())) {
      return false;
    }

    return true;
  }

  /**
   * Get key pair for a specific keyId
   */
  private getKeyPair(keyId: string): { privateKey: string; publicKey: string } {
    const keyPair = this.config.keys[keyId];
    
    if (!keyPair) {
      throw new HttpException(`Key pair not found for keyId: ${keyId}`, HttpStatus.BAD_REQUEST);
    }
    
    return keyPair;
  }

  /**
   * Decrypt request using headers
   */
  private async decryptRequest(req: Request): Promise<DecryptedData> {
    try {
      // Extract headers
      const encryptedKeyHeader = req.headers[this.config.customKeyHeader.toLowerCase()] as string;
      const ivHeader = req.headers[this.config.customIVHeader.toLowerCase()] as string;
      const keyIdHeader = req.headers[this.config.keyIdHeader.toLowerCase()] as string;

      if (!encryptedKeyHeader || !ivHeader) {
        throw new HttpException('Missing encryption headers', HttpStatus.BAD_REQUEST);
      }

      if (!keyIdHeader) {
        throw new HttpException('Missing keyId header', HttpStatus.BAD_REQUEST);
      }

      // Get encrypted data from request body
      if (!req.body || typeof req.body !== 'string') {
        throw new HttpException('Missing encrypted data in request body', HttpStatus.BAD_REQUEST);
      }

      // Get the appropriate key pair based on keyId
      const keyPair = this.getKeyPair(keyIdHeader);

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
        ...(decryptionResult.iv && { iv: decryptionResult.iv })
      };

      return decryptedData;
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        HttpStatus.BAD_REQUEST
      );
    }
  }

  /**
   * Encrypt response data
   */
  private async encryptResponse(data: any, aesKey: Buffer, iv: Buffer): Promise<string> {
    try {
      const dataString = JSON.stringify(data);
      return encryptAES(dataString, aesKey, iv);
    } catch (error) {
      throw new HttpException(
        `Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();

    // Check if request should be processed
    if (!this.shouldProcessRequest(request)) {
      return next.handle();
    }

    // Handle both request decryption and response encryption
    if (this.config.enableRequestDecryption && this.config.enableResponseEncryption) {
      return next.handle().pipe(
        map(async (data: any) => {
          try {
            // Decrypt request
            const decryptedData = await this.decryptRequest(request);
            
            // Update request body with decrypted data
            request.body = decryptedData.data;
            
            // Store decrypted data and encryption details for response
            (request as any).e2ee = {
              decryptedData,
              originalBody: request.body,
              aesKey: decryptedData.aesKey,
              iv: decryptedData.iv
            };

            // Call onDecrypt callback if provided
            if (this.options.onDecrypt) {
              this.options.onDecrypt(decryptedData, request);
            }

            // Encrypt response if enabled
            if (this.config.enableResponseEncryption) {
              const e2eeContext = (request as any).e2ee;
              if (!e2eeContext || !e2eeContext.aesKey || !e2eeContext.iv) {
                throw new Error('Missing encryption context for response');
              }

              const encryptedData = await this.encryptResponse(data, e2eeContext.aesKey, e2eeContext.iv);
              
              // Call onEncrypt callback if provided
              if (this.options.onEncrypt) {
                this.options.onEncrypt({ data: encryptedData, timestamp: Date.now(), nonce: '' }, response);
              }

              // Return encrypted data
              return encryptedData;
            }

            return data;
          } catch (error) {
            if (this.options.onError) {
              this.options.onError(error as Error, request, response);
            }
            throw error;
          }
        }),
        catchError((error: any) => {
          if (this.options.onError) {
            this.options.onError(error, request, response);
          }
          return throwError(() => error);
        })
      );
    }

    // Handle response encryption only
    if (this.config.enableResponseEncryption) {
      return next.handle().pipe(
        map(async (data: any) => {
          try {
            const e2eeContext = (request as any).e2ee;
            if (!e2eeContext || !e2eeContext.aesKey || !e2eeContext.iv) {
              throw new Error('Missing encryption context for response');
            }

            const encryptedData = await this.encryptResponse(data, e2eeContext.aesKey, e2eeContext.iv);
            
            // Call onEncrypt callback if provided
            if (this.options.onEncrypt) {
              this.options.onEncrypt({ data: encryptedData, timestamp: Date.now(), nonce: '' }, response);
            }

            // Return encrypted data
            return encryptedData;
          } catch (error) {
            if (this.options.onError) {
              this.options.onError(error as Error, request, response);
            }
            throw error;
          }
        }),
        catchError((error: any) => {
          if (this.options.onError) {
            this.options.onError(error, request, response);
          }
          return throwError(() => error);
        })
      );
    }

    return next.handle();
  }
} 