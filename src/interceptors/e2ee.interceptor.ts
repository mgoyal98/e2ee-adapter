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
  processRequest,
  handleRequestDecryption,
  setupResponseEncryptionContext,
  handleResponseEncryption,
  mergeConfigWithDefaults,
  validateConfig,
  createE2EEError,
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
    return createE2EEError(message, code, statusCode);
  }

  async intercept(context: ExecutionContext, next: CallHandler): Promise<any> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();

    try {
      // Process request and check if it should be handled
      const processingResult = processRequest(request, this.config, this.createError.bind(this));
      if (processingResult.shouldContinue) {
        return next.handle();
      }

      // Handle request decryption
      let e2eeContext = await handleRequestDecryption(
        request,
        this.config,
        this.createError.bind(this),
        this.options.onDecrypt
      );

      // Setup encryption context for response-only encryption if needed
      if (
        !this.config.enableRequestDecryption &&
        this.config.enableResponseEncryption
      ) {
        e2eeContext = await setupResponseEncryptionContext(
          request,
          this.config,
          this.createError.bind(this)
        );
      }

      // Store encryption context for response
      if (e2eeContext) {
        (request as any).e2ee = e2eeContext;
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

              const encryptedData = await handleResponseEncryption(
                data,
                e2eeContext,
                this.createError.bind(this),
                this.options.onEncrypt,
                response
              );

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
    } catch (error) {
      if (this.options.onError) {
        this.options.onError(error as Error, request, response);
      }

      // Convert E2EE errors to HttpException for NestJS
      const e2eeError = error as E2EEError;
      if (e2eeError.code) {
        return throwError(
          () =>
            new HttpException(
              e2eeError.message,
              e2eeError.statusCode || HttpStatus.BAD_REQUEST
            )
        );
      }

      // Re-throw other errors
      throw error;
    }
  }
}
