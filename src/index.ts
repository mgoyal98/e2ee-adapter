// Core types and interfaces
export * from './types';

// Cryptographic utilities
export * from './utils/crypto';

// Express.js middleware
export { createE2EEMiddleware } from './middleware/e2ee';

// NestJS interceptor
export { E2EEInterceptor, E2EEInterceptorOptions } from './interceptors/e2ee.interceptor';

// Client utilities
export { E2EEClient, E2EEClientConfig, E2EEClientRequest, E2EEClientResponse } from './client/e2ee-client';

// Re-export commonly used types for convenience
export type { 
  E2EEConfig, 
  E2EEMiddlewareOptions, 
  E2EEMiddleware,
  KeyPair,
  EncryptionResult,
  DecryptionResult,
  EncryptedData,
  DecryptedData
} from './types'; 