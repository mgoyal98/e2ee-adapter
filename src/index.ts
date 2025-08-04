// Crypto utilities
export {
  generateKeyPair,
  generateMultipleKeyPairs,
  encrypt,
  decrypt,
  encryptAES,
  decryptAES,
  decryptAESKey,
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
  KeyStore,
  E2EEClientConfig,
  E2EEClientRequest,
  E2EEClientResponse,
} from './types';

// Interceptors
export { E2EEInterceptor } from './interceptors/e2ee.interceptor';

// Middleware
export { createE2EEMiddleware } from './middleware/e2ee';

// Client
export { E2EEClient } from './client/e2ee-client';
