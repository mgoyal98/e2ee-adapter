import { Request, Response, NextFunction } from 'express';
import { createE2EEMiddleware } from './e2ee';
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

describe('E2EE Middleware - Enforcement Mode', () => {
  let keys: any;
  let mockRequest: any;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(async () => {
    keys = await generateMultipleKeyPairs(['domain1']);
    
    mockRequest = {
      path: '/api/test',
      method: 'POST',
      headers: {},
      body: 'encrypted-data'
    };
    
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis()
    };
    
    mockNext = jest.fn();
  });

  describe('Non-Enforced Mode (default)', () => {
    it('should process requests with encryption headers', async () => {
      const middleware = createE2EEMiddleware({
        config: {
          keys,
          enforced: false
        }
      });

      // Mock request with encryption headers
      mockRequest.headers = {
        'x-custom-key': 'encrypted-key',
        'x-custom-iv': 'encrypted-iv',
        'x-key-id': 'domain1'
      };

      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      // Should call next() after processing
      expect(mockNext).toHaveBeenCalled();
    });

    it('should pass through requests without encryption headers', async () => {
      const middleware = createE2EEMiddleware({
        config: {
          keys,
          enforced: false
        }
      });

      // Mock request without encryption headers
      mockRequest.headers = {};

      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      // Should call next() without processing
      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });
  });

  describe('Enforced Mode', () => {
    it('should reject requests without encryption headers', async () => {
      const middleware = createE2EEMiddleware({
        config: {
          keys,
          enforced: true
        }
      });

      // Mock request without encryption headers
      mockRequest.headers = {};

      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      // Should not call next() and should return error
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'E2EE Error',
        code: 'ENCRYPTION_ENFORCED',
        message: 'Encryption is enforced. All requests must include encryption headers.'
      });
    });

    it('should process requests with encryption headers', async () => {
      const middleware = createE2EEMiddleware({
        config: {
          keys,
          enforced: true
        }
      });

      // Mock request with encryption headers
      mockRequest.headers = {
        'x-custom-key': 'encrypted-key',
        'x-custom-iv': 'encrypted-iv',
        'x-key-id': 'domain1'
      };

      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      // Should call next() after processing
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Excluded paths and methods', () => {
    it('should skip processing for excluded paths', async () => {
      const middleware = createE2EEMiddleware({
        config: {
          keys,
          enforced: true
        }
      });

      // Mock request to excluded path
      mockRequest.path = '/health';
      mockRequest.headers = {};

      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      // Should call next() without processing
      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should skip processing for excluded methods', async () => {
      const middleware = createE2EEMiddleware({
        config: {
          keys,
          enforced: true
        }
      });

      // Mock request with excluded method
      mockRequest.method = 'GET';
      mockRequest.headers = {};

      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      // Should call next() without processing
      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });
  });
}); 