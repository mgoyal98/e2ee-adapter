import { ExecutionContext, CallHandler } from '@nestjs/common';
import { of } from 'rxjs';
import { E2EEInterceptor } from './e2ee.interceptor';
import { generateMultipleKeyPairs } from '../utils/crypto';

// Mock the crypto module
jest.mock('../utils/crypto', () => ({
  generateMultipleKeyPairs: jest.requireActual('../utils/crypto').generateMultipleKeyPairs,
  decrypt: jest.fn().mockResolvedValue({
    decryptedData: JSON.stringify({ test: 'data' }),
    nonce: 'test-nonce',
    aesKey: Buffer.from('test-aes-key'),
    iv: Buffer.from('test-iv')
  }),
  encryptAES: jest.fn().mockResolvedValue('encrypted-response')
}));

describe('E2EE Interceptor - Enforcement Mode', () => {
  let keys: any;
  let mockExecutionContext: ExecutionContext;
  let mockCallHandler: CallHandler;

  beforeEach(async () => {
    keys = await generateMultipleKeyPairs(['domain1']);
    
    mockExecutionContext = {
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue({
          path: '/api/test',
          method: 'POST',
          headers: {},
          body: 'encrypted-data'
        }),
        getResponse: jest.fn().mockReturnValue({
          status: jest.fn().mockReturnThis(),
          json: jest.fn().mockReturnThis(),
          send: jest.fn().mockReturnThis()
        })
      })
    } as any;
    
    mockCallHandler = {
      handle: jest.fn().mockReturnValue(of({ success: true }))
    };
  });

  describe('Non-Enforced Mode (default)', () => {
    it('should process requests with encryption headers', (done) => {
      const interceptor = new E2EEInterceptor({
        config: {
          keys,
          enforced: false
        }
      });

      // Mock request with encryption headers
      const request = mockExecutionContext.switchToHttp().getRequest();
      request.headers = {
        'x-custom-key': 'encrypted-key',
        'x-custom-iv': 'encrypted-iv',
        'x-key-id': 'domain1'
      };

      interceptor.intercept(mockExecutionContext, mockCallHandler).subscribe({
        next: (result) => {
          expect(result).toBeDefined();
          done();
        },
        error: done
      });
    });

    it('should pass through requests without encryption headers', (done) => {
      const interceptor = new E2EEInterceptor({
        config: {
          keys,
          enforced: false
        }
      });

      // Mock request without encryption headers
      const request = mockExecutionContext.switchToHttp().getRequest();
      request.headers = {};

      interceptor.intercept(mockExecutionContext, mockCallHandler).subscribe({
        next: (result) => {
          expect(result).toEqual({ success: true });
          done();
        },
        error: done
      });
    });
  });

  describe('Enforced Mode', () => {
    it('should reject requests without encryption headers', (done) => {
      const interceptor = new E2EEInterceptor({
        config: {
          keys,
          enforced: true
        }
      });

      // Mock request without encryption headers
      const request = mockExecutionContext.switchToHttp().getRequest();
      request.headers = {};

      interceptor.intercept(mockExecutionContext, mockCallHandler).subscribe({
        next: () => {
          done(new Error('Should have thrown an error'));
        },
        error: (error) => {
          expect(error.status).toBe(400);
          expect(error.message).toBe('Encryption is enforced. All requests must include encryption headers.');
          done();
        }
      });
    });

    it('should process requests with encryption headers', (done) => {
      const interceptor = new E2EEInterceptor({
        config: {
          keys,
          enforced: true
        }
      });

      // Mock request with encryption headers
      const request = mockExecutionContext.switchToHttp().getRequest();
      request.headers = {
        'x-custom-key': 'encrypted-key',
        'x-custom-iv': 'encrypted-iv',
        'x-key-id': 'domain1'
      };

      interceptor.intercept(mockExecutionContext, mockCallHandler).subscribe({
        next: (result) => {
          expect(result).toBeDefined();
          done();
        },
        error: done
      });
    });
  });

  describe('Excluded paths and methods', () => {
    it('should skip processing for excluded paths', (done) => {
      const interceptor = new E2EEInterceptor({
        config: {
          keys,
          enforced: true
        }
      });

      // Mock request to excluded path
      const request = mockExecutionContext.switchToHttp().getRequest();
      request.path = '/health';
      request.headers = {};

      interceptor.intercept(mockExecutionContext, mockCallHandler).subscribe({
        next: (result) => {
          expect(result).toEqual({ success: true });
          done();
        },
        error: done
      });
    });

    it('should skip processing for excluded methods', (done) => {
      const interceptor = new E2EEInterceptor({
        config: {
          keys,
          enforced: true
        }
      });

      // Mock request with excluded method
      const request = mockExecutionContext.switchToHttp().getRequest();
      request.method = 'GET';
      request.headers = {};

      interceptor.intercept(mockExecutionContext, mockCallHandler).subscribe({
        next: (result) => {
          expect(result).toEqual({ success: true });
          done();
        },
        error: done
      });
    });
  });
}); 