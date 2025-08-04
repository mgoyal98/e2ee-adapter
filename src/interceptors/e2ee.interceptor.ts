import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { throwError } from 'rxjs';
import { map } from 'rxjs/operators';
import { Request, Response } from 'express';
import { E2EEConfig, EncryptedData, DecryptedData, E2EEError } from '../types';
import {
  shouldProcessRequest,
  hasEncryptionHeaders,
  decryptRequest,
  encryptResponse,
  mergeConfigWithDefaults,
  validateConfig,
  extractAESKeyFromHeaders,
} from '../utils/e2ee-common';

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
    // Validate configuration
    validateConfig(options.config);

    // Merge configuration with defaults
    this.config = mergeConfigWithDefaults(options.config);
  }

  /**
   * Create E2EE error for NestJS
   */
  private createError(
    message: string,
    code: string,
    statusCode: number = 400
  ): E2EEError {
    const error = new Error(message) as E2EEError;
    error.code = code;
    error.statusCode = statusCode;
    return error;
  }

  async intercept(context: ExecutionContext, next: CallHandler): Promise<any> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();

    // Check if request should be processed
    if (!shouldProcessRequest(request, this.config)) {
      return next.handle();
    }

    // Check enforcement mode
    if (this.config.enforced) {
      // In enforced mode, all requests must be encrypted
      if (!hasEncryptionHeaders(request, this.config)) {
        return throwError(
          () =>
            new HttpException(
              'Encryption is enforced. All requests must include encryption headers.',
              HttpStatus.BAD_REQUEST
            )
        );
      }
    } else {
      // In non-enforced mode, only process requests that have encryption headers
      if (!hasEncryptionHeaders(request, this.config)) {
        return next.handle();
      }
    }

    if (this.config.enableRequestDecryption) {
      // Decrypt request if there's a string body or if empty body is allowed
      if (typeof request.body === 'string') {
        const decryptedData = await decryptRequest(request, this.config, this.createError.bind(this));


        request.body = decryptedData.data;

        // Store decrypted data and encryption details for response
        (request as any).e2ee = {
          decryptedData,
          originalBody: request.body,
          aesKey: decryptedData.aesKey,
          iv: decryptedData.iv,
        };

        // Call onDecrypt callback if provided
        if (this.options.onDecrypt) {
          this.options.onDecrypt(decryptedData, request);
        }
      } else if (
        hasEncryptionHeaders(request, this.config) &&
        (typeof request.body === 'undefined' ||
          Object.keys(request.body)?.length === 0) &&
        !this.config.allowEmptyRequestBody
      ) {
        // If request has encryption headers but empty body is not allowed, throw error
        throw new HttpException(
          'Missing encrypted data in request body',
          HttpStatus.BAD_REQUEST
        );
      } else if (
        this.config.allowEmptyRequestBody &&
        (!request.body || Object.keys(request.body)?.length === 0)
      ) {
        // Handle empty request body with encryption headers for response encryption
        const { aesKey, iv } = await extractAESKeyFromHeaders(request, this.config, this.createError.bind(this));

        // Store encryption context for response
        (request as any).e2ee = {
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
        if (this.options.onDecrypt) {
          this.options.onDecrypt((request as any).e2ee.decryptedData, request);
        }
      } else {
        throw new HttpException('Invalid request body', HttpStatus.BAD_REQUEST);
      }
    }

    // Handle response encryption only
    if (this.config.enableResponseEncryption) {
      if (!this.config.enableRequestDecryption) {
        const { aesKey, iv } = await extractAESKeyFromHeaders(request, this.config, this.createError.bind(this));

        // Store encryption context for response
        (request as any).e2ee = {
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

      return next.handle().pipe(
        map(async (data: any) => {
          try {
            const e2eeContext = (request as any).e2ee;
            if (!e2eeContext || !e2eeContext.aesKey || !e2eeContext.iv) {
              throw new Error('Missing encryption context for response');
            }

            const encryptedData = await encryptResponse(
              data,
              e2eeContext.aesKey,
              e2eeContext.iv,
              this.createError.bind(this)
            );

            // Call onEncrypt callback if provided
            if (this.options.onEncrypt) {
              this.options.onEncrypt(
                { data: encryptedData, timestamp: Date.now(), nonce: '' },
                response
              );
            }

            // Return encrypted data
            return encryptedData;
          } catch (error) {
            if (this.options.onError) {
              this.options.onError(error as Error, request, response);
            }
            throw error;
          }
        })
      );
    }

    return next.handle();
  }
}
