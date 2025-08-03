// Crypto utilities
export {
  generateKeyPair,
  generateMultipleKeyPairs,
  encrypt,
  decrypt,
  encryptAES,
  decryptAES,
  generateNonce,
  hash,
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
