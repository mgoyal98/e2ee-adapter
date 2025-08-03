# E2EE Middleware

A secure, production-ready TypeScript package for implementing End-to-End Encryption (E2EE) in Express.js and NestJS applications using RSA-256 encryption.

## 🔐 Features

- **RSA-256 Encryption**: Uses RSA-OAEP with SHA-256 for secure encryption
- **Hybrid Encryption**: Combines RSA and AES-GCM for optimal performance and security
- **Digital Signatures**: RSA-SHA256 signing for message authenticity
- **Replay Attack Protection**: Timestamp validation with configurable windows
- **Express.js Middleware**: Drop-in middleware for Express applications
- **NestJS Interceptor**: Native NestJS interceptor support
- **Client SDK**: Easy-to-use client library for encrypted communication
- **TypeScript Support**: Full TypeScript support with comprehensive type definitions
- **Configurable Security**: Flexible configuration for different security requirements
- **100% Secure**: Implements industry-standard cryptographic practices

## 🚀 Quick Start

### Installation

```bash
npm install e2ee-middleware
```

### Basic Express.js Setup

```typescript
import express from 'express';
import { createE2EEMiddleware, generateKeyPair } from 'e2ee-middleware';

const app = express();

// Generate RSA key pair
const keys = await generateKeyPair(2048);

// Create E2EE middleware
const e2eeMiddleware = createE2EEMiddleware({
  config: {
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    enableRequestDecryption: true,
    enableResponseEncryption: true,
    enableSignatureVerification: true,
    enableResponseSigning: true
  }
});

// Apply middleware
app.use(e2eeMiddleware);

// Your routes here...
app.post('/api/users', (req, res) => {
  // req.body is automatically decrypted
  const user = req.body;
  
  // Use res.encryptAndSend for encrypted responses
  res.encryptAndSend({
    success: true,
    user: { id: 1, ...user }
  });
});
```

### Basic NestJS Setup

```typescript
import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { E2EEInterceptor } from 'e2ee-middleware';

@Module({
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: E2EEInterceptor,
    },
  ],
})
export class AppModule {}
```

### Client Usage

```typescript
import { E2EEClient } from 'e2ee-middleware';

// Create client with server's public key only
const client = new E2EEClient({
  serverPublicKey: 'server-public-key-here'
});

// Make encrypted request
const response = await client.request({
  url: 'http://localhost:3000/api/users',
  method: 'POST',
  data: {
    name: 'John Doe',
    email: 'john@example.com'
  }
});

console.log('Response:', response.data);
```

## 📚 API Reference

### Configuration Options

```typescript
interface E2EEConfig {
  /** RSA private key for decryption */
  privateKey: string;
  /** RSA public key for encryption */
  publicKey: string;
  /** Algorithm for encryption (default: RSA-OAEP) */
  algorithm?: string;
  /** Encoding for keys (default: 'base64') */
  encoding?: BufferEncoding;
  /** Custom headers for encrypted data */
  encryptedDataHeader?: string;
  /** Custom headers for signature */
  signatureHeader?: string;
  /** Enable request decryption (default: true) */
  enableRequestDecryption?: boolean;
  /** Enable response encryption (default: true) */
  enableResponseEncryption?: boolean;
  /** Enable signature verification (default: true) */
  enableSignatureVerification?: boolean;
  /** Enable response signing (default: true) */
  enableResponseSigning?: boolean;
  /** Paths to exclude from encryption/decryption */
  excludePaths?: string[];
  /** Methods to exclude from encryption/decryption */
  excludeMethods?: string[];
}
```

### Express.js Middleware

```typescript
import { createE2EEMiddleware, E2EEMiddlewareOptions } from 'e2ee-middleware';

const middleware = createE2EEMiddleware({
  config: E2EEConfig,
  onError?: (error: Error, req: Request, res: Response) => void,
  onDecrypt?: (decryptedData: DecryptedData, req: Request) => void,
  onEncrypt?: (encryptedData: EncryptedData, res: Response) => void
});
```

### NestJS Interceptor

```typescript
import { E2EEInterceptor, E2EEInterceptorOptions } from 'e2ee-middleware';

const interceptor = new E2EEInterceptor({
  config: E2EEConfig,
  onError?: (error: Error, req: Request, res: Response) => void,
  onDecrypt?: (decryptedData: DecryptedData, req: Request) => void,
  onEncrypt?: (encryptedData: EncryptedData, res: Response) => void
});
```

### Client SDK

```typescript
import { E2EEClient, E2EEClientConfig } from 'e2ee-middleware';

const client = new E2EEClient({
  serverPublicKey: string,
  algorithm?: string,
  enableResponseVerification?: boolean
});

// Methods
await client.encryptRequest(data: any): Promise<{ encryptedData: string }>;
await client.decryptResponse(encryptedData: string, serverPrivateKey?: string): Promise<any>;
await client.request(config: E2EEClientRequest): Promise<E2EEClientResponse>;
```

## 🔧 Examples

### Express.js Server Example

```bash
cd examples/express-server
npm install
npm start
```

### Client Example

```bash
cd examples/client-example
node client.js
```

### NestJS Server Example

```bash
cd examples/nestjs-server
npm install
npm run build
npm start
```

## 🏗️ Architecture

### Client-Server E2EE Flow

```
┌─────────┐                    ┌─────────┐
│ Client  │                    │ Server  │
│         │                    │         │
│ Public  │◄───────────────────┤ Private │
│ Key     │                    │ Key     │
└─────────┘                    └─────────┘
     │                              │
     │ 1. Encrypt Request           │
     │    (using server public key) │
     ├──────────────────────────────►│
     │                              │
     │                              │ 2. Decrypt Request
     │                              │    (using server private key)
     │                              │
     │                              │ 3. Process Request
     │                              │
     │                              │ 4. Encrypt Response
     │                              │    (using server private key)
     │◄─────────────────────────────┤
     │                              │
     │ 5. Receive Response          │
     │    (application handles)     │
     │                              │
```

### Key Distribution
- **Client**: Only has server's public key
- **Server**: Has its own private key
- **No Client Keys**: Clients don't generate or store private keys

## 🛡️ Security Features

### Encryption
- **RSA-OAEP**: Optimal Asymmetric Encryption Padding
- **AES-256-GCM**: Authenticated encryption for data
- **Hybrid Approach**: RSA for key exchange, AES for data encryption

### Authentication
- **RSA-SHA256**: Digital signatures for message authenticity
- **Timestamp Validation**: Prevents replay attacks
- **Nonce Generation**: Ensures message uniqueness

### Configuration
- **Path Exclusion**: Exclude specific paths from encryption
- **Method Exclusion**: Exclude specific HTTP methods
- **Custom Headers**: Configurable header names
- **Callback Support**: Custom error handling and logging

## 📋 Requirements

- Node.js >= 16.0.0
- TypeScript >= 5.0.0 (for TypeScript projects)
- Express.js >= 4.17.0 (for Express middleware)
- NestJS >= 10.0.0 (for NestJS interceptor)

## 🔑 Key Management

### Generating Keys

```typescript
import { generateKeyPair } from 'e2ee-middleware';

// Generate 2048-bit RSA key pair
const keys = await generateKeyPair(2048);

console.log('Public Key:', keys.publicKey);
console.log('Private Key:', keys.privateKey);
```

### Key Storage

- **Public Keys**: Can be shared publicly
- **Private Keys**: Must be kept secure and never shared
- **Environment Variables**: Store private keys in environment variables
- **Key Rotation**: Implement regular key rotation for production use

## 🚨 Security Best Practices

1. **Key Management**: Store private keys securely, never in code
2. **Key Rotation**: Implement regular key rotation
3. **HTTPS**: Always use HTTPS in production
4. **Validation**: Validate all decrypted data
5. **Error Handling**: Don't expose sensitive information in errors
6. **Logging**: Be careful with logging encrypted data
7. **Testing**: Test encryption/decryption thoroughly

## 🧪 Testing

```bash
npm test
```

## 📄 License

MIT License - see LICENSE file for details

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📞 Support

For support and questions:
- Open an issue on GitHub
- Check the examples folder
- Review the API documentation

## 🔄 Version History

- **1.0.0**: Initial release with Express.js and NestJS support 