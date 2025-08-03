import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  HttpException,
  HttpStatus
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { map, catchError } from 'rxjs/operators';
import { Request, Response } from 'express';
import { 
  E2EEConfig, 
  EncryptedData, 
  DecryptedData 
} from '../types';
import { encrypt, decrypt, sign, verify } from '../utils/crypto';

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
    // Set default values
    this.config = {
      privateKey: options.config.privateKey,
      publicKey: options.config.publicKey,
      algorithm: options.config.algorithm || 'RSA-OAEP',
      encoding: options.config.encoding || 'base64',
      encryptedDataHeader: options.config.encryptedDataHeader || 'x-encrypted-data',
      signatureHeader: options.config.signatureHeader || 'x-signature',
      enableRequestDecryption: options.config.enableRequestDecryption !== false,
      enableResponseEncryption: options.config.enableResponseEncryption !== false,
      enableSignatureVerification: options.config.enableSignatureVerification !== false,
      enableResponseSigning: options.config.enableResponseSigning !== false,
      excludePaths: options.config.excludePaths || [],
      excludeMethods: options.config.excludeMethods || ['GET', 'HEAD', 'OPTIONS']
    };
  }

  /**
   * Check if the request should be processed by E2EE
   */
  private shouldProcessRequest(req: Request): boolean {
    const path = req.path;
    const method = req.method.toUpperCase();

    // Check if path is excluded
    if (this.config.excludePaths.some(excludedPath => 
      path.startsWith(excludedPath) || path === excludedPath
    )) {
      return false;
    }

    // Check if method is excluded
    if (this.config.excludeMethods.includes(method)) {
      return false;
    }

    return true;
  }

  /**
   * Decrypt request body
   */
  private async decryptRequest(req: Request): Promise<DecryptedData> {
    try {
      const encryptedDataHeader = req.headers[this.config.encryptedDataHeader.toLowerCase()] as string;
      const signatureHeader = req.headers[this.config.signatureHeader.toLowerCase()] as string;

      if (!encryptedDataHeader) {
        throw new HttpException('Missing encrypted data header', HttpStatus.BAD_REQUEST);
      }

      // Parse encrypted data
      const encryptedData: EncryptedData = JSON.parse(encryptedDataHeader);
      
      // Verify timestamp to prevent replay attacks (5 minutes window)
      const now = Date.now();
      const timeDiff = Math.abs(now - encryptedData.timestamp);
      if (timeDiff > 5 * 60 * 1000) { // 5 minutes
        throw new HttpException('Request timestamp is too old or too new', HttpStatus.BAD_REQUEST);
      }

      // Verify signature if enabled
      if (this.config.enableSignatureVerification && signatureHeader) {
        const isValid = await verify(
          encryptedData.data,
          signatureHeader,
          this.config.publicKey,
          'RSA-SHA256'
        );
        
        if (!isValid) {
          throw new HttpException('Invalid signature', HttpStatus.UNAUTHORIZED);
        }
      }

      // Decrypt the data
      const decryptionResult = await decrypt(
        encryptedData.data,
        this.config.privateKey
      );

      const decryptedData: DecryptedData = {
        data: JSON.parse(decryptionResult.decryptedData),
        signature: signatureHeader,
        timestamp: encryptedData.timestamp,
        nonce: decryptionResult.nonce
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
  private async encryptResponse(data: any): Promise<EncryptedData> {
    try {
      const dataString = JSON.stringify(data);
      const timestamp = Date.now();

      // Encrypt the data
      const encryptionResult = await encrypt(
        dataString,
        this.config.publicKey
      );

      const encryptedData: EncryptedData = {
        data: encryptionResult.encryptedData,
        timestamp,
        nonce: encryptionResult.nonce
      };

      // Sign the encrypted data if enabled
      if (this.config.enableResponseSigning) {
        encryptedData.signature = await sign(
          encryptionResult.encryptedData,
          this.config.privateKey,
          'RSA-SHA256'
        );
      }

      return encryptedData;
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

    // Decrypt request if enabled
    if (this.config.enableRequestDecryption && request.body) {
      return next.handle().pipe(
        map(async (data: any) => {
          try {
            const decryptedData = await this.decryptRequest(request);
            
            // Update request body with decrypted data
            request.body = decryptedData.data;
            
            // Store decrypted data for potential use
            (request as any).e2ee = {
              decryptedData,
              originalBody: request.body
            };

            // Call onDecrypt callback if provided
            if (this.options.onDecrypt) {
              this.options.onDecrypt(decryptedData, request);
            }

            // Encrypt response if enabled
            if (this.config.enableResponseEncryption) {
              const encryptedData = await this.encryptResponse(data);
              
              // Set headers
              response.set(this.config.encryptedDataHeader, JSON.stringify(encryptedData));
              if (encryptedData.signature) {
                response.set(this.config.signatureHeader, encryptedData.signature);
              }
              
              // Call onEncrypt callback if provided
              if (this.options.onEncrypt) {
                this.options.onEncrypt(encryptedData, response);
              }

              // Return encrypted data
              return {
                encrypted: true,
                data: encryptedData.data,
                timestamp: encryptedData.timestamp,
                nonce: encryptedData.nonce
              };
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
            const encryptedData = await this.encryptResponse(data);
            
            // Set headers
            response.set(this.config.encryptedDataHeader, JSON.stringify(encryptedData));
            if (encryptedData.signature) {
              response.set(this.config.signatureHeader, encryptedData.signature);
            }
            
            // Call onEncrypt callback if provided
            if (this.options.onEncrypt) {
              this.options.onEncrypt(encryptedData, response);
            }

            // Return encrypted data
            return {
              encrypted: true,
              data: encryptedData.data,
              timestamp: encryptedData.timestamp,
              nonce: encryptedData.nonce
            };
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