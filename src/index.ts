// Core exports
export { createE2EEMiddleware } from './middleware/e2ee';
export { E2EEInterceptor } from './interceptors/e2ee.interceptor';
export { E2EEClient } from './client/e2ee-client';

// Crypto utilities
export { 
  generateKeyPair, 
  encrypt, 
  decrypt, 
  encryptAES, 
  decryptAES, 
  generateNonce, 
  hash 
} from './utils/crypto';

// Types
export type {
  E2EEConfig,
  E2EEMiddlewareOptions,
  E2EEMiddleware,
  E2EEError,
  EncryptedData,
  DecryptedData,
  KeyPair,
  E2EEClientConfig,
  E2EEClientRequest,
  E2EEClientResponse
} from './types'; 