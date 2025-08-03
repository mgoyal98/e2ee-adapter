# E2EE Adapter

A TypeScript package providing End-to-End Encryption (E2EE) middleware for Express.js and NestJS applications using hybrid encryption (AES-CBC + RSA).

## 🚀 Features

- **Hybrid Encryption**: AES-CBC for data encryption + RSA for key exchange
- **Express.js Middleware**: Easy integration with Express applications
- **NestJS Interceptor**: Seamless integration with NestJS applications
- **Client SDK**: TypeScript client for making encrypted requests
- **Header-based Flow**: Secure transmission using custom headers
- **Automatic Key Management**: Server generates and manages RSA key pairs
- **Response Encryption**: Full bidirectional encryption support

## 🔐 Security Features

- **AES-256-CBC**: Symmetric encryption for data
- **RSA-2048-OAEP**: Asymmetric encryption for key exchange
- **Random IV Generation**: Unique initialization vectors for each request
- **Replay Attack Protection**: Timestamp validation
- **Secure Key Exchange**: RSA encryption for AES key transmission

## 📦 Installation

### For Express.js Applications

```bash
npm install e2ee-adapter express
```

### For NestJS Applications

```bash
npm install e2ee-adapter @nestjs/common rxjs
```

## 🏗️ Architecture

The middleware implements a secure hybrid encryption flow:

```
+-------------------------+                                  +-------------------------+
|        CLIENT           |                                  |         SERVER          |
+-------------------------+                                  +-------------------------+
|                                                         ▲
| 1. Fetch server's public key from /e2ee.json            |
|    → key: RSA public PEM                                |
|    → key_id: version info                               |
|                                                         |
| 2. Generate AES key (32 bytes) and IV (16 bytes)        |
|                                                         |
| 3. Encrypt request payload using:                       |
|    AES-CBC(payload, AES_key, IV)                        |
|                                                         |
| 4. Encrypt AES key using server's RSA public key        |
|    RSA_encrypt(AES_key, server_pubkey)                  |
|                                                         |
| 5. Send HTTPS request:                                  |
|    ----------------------------------------------       |
|    Headers:                                             |
|      x-custom-key: RSA_encrypted_AES_key (base64)       |
|      x-custom-iv:  IV (base64)                          |
|      x-key-id:     key_id                               |
|      Content-Type: application/json                     |
|    Body:                                                |
|      Encrypted AES payload (base64)                     |
|    ----------------------------------------------       |
|                                                         |
|                                                         ▼
|                                         +------------------------------------------+
|                                         | 6. Decrypt x-custom-key using RSA private|
|                                         |    AES_key = RSA_decrypt(x-custom-key)   |
|                                         +------------------------------------------+
|                                                         ▼
|                                         +------------------------------------------+
|                                         | 7. Decrypt payload using AES-CBC         |
|                                         |    plaintext = AES_decrypt(body, AES_key,|
|                                         |                                        IV)|
|                                         +------------------------------------------+
|                                                         ▼
|                                         +------------------------------------------+
|                                         | 8. Process request, prepare response JSON |
|                                         +------------------------------------------+
|                                                         ▼
|                                         +------------------------------------------+
|                                         | 9. Encrypt response using AES-CBC        |
|                                         |    response_encrypted = AES_encrypt(     |
|                                         |            JSON, AES_key, IV)            |
|                                         +------------------------------------------+
|                                                         ▼
|                                         +------------------------------------------+
|                                         | 10. Send encrypted response              |
|                                         |     Body: response_encrypted (base64)    |
|                                         +------------------------------------------+
|                                                         ▲
| 11. Decrypt response using AES_key and IV              |
|     plaintext_response = AES_decrypt(body, key, IV)    |
|                                                         |
+-------------------------+                                  +-------------------------+
```

## 🛠️ Usage

### Module Paths

The package provides specific module paths for middleware, client, and interceptor:

```typescript
// Main exports (everything)
import { createE2EEMiddleware, E2EEClient, E2EEInterceptor, generateMultipleKeyPairs } from 'e2ee-adapter';

// Specific modules (optional)
import { createE2EEMiddleware } from 'e2ee-adapter/middleware';
import { E2EEClient } from 'e2ee-adapter/client';
import { E2EEInterceptor } from 'e2ee-adapter/interceptor';
```

### Express.js Setup

```typescript
import express from 'express';
import { generateMultipleKeyPairs } from 'e2ee-adapter';
import { createE2EEMiddleware } from 'e2ee-adapter/middleware';

const app = express();

// Generate multiple RSA key pairs
const keys = await generateMultipleKeyPairs(['domain1', 'domain2', 'domain3']);

// Create E2EE middleware
const e2eeMiddleware = createE2EEMiddleware({
  config: {
    keys,
    enableRequestDecryption: true,
    enableResponseEncryption: true,
    excludePaths: ['/health', '/keys', '/e2ee.json'],
    excludeMethods: ['GET', 'HEAD', 'OPTIONS'],
    enforced: false // Allow both encrypted and non-encrypted requests
  },
  onError: (error, req, res) => {
    console.error('E2EE Error:', error.message);
  },
  onDecrypt: (decryptedData, req) => {
    console.log('Request decrypted successfully');
  },
  onEncrypt: (encryptedData, res) => {
    console.log('Response encrypted successfully');
  }
});

// Apply middleware
app.use(e2eeMiddleware);

// Add server configuration endpoint
app.get('/e2ee.json', (req, res) => {
  res.json({
    keys: {
      domain1: keys.domain1.publicKey,
      domain2: keys.domain2.publicKey,
      domain3: keys.domain3.publicKey
    },
    keySize: 2048
  });
});

// Protected endpoints
app.post('/api/users', (req, res) => {
  // req.body contains decrypted data
  const user = { id: Date.now(), ...req.body };
  
  // Use encryptAndSend for encrypted responses
  if (res.encryptAndSend) {
    res.encryptAndSend({ success: true, user });
  } else {
    res.json({ success: true, user });
  }
});
```

### NestJS Setup

```typescript
import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { E2EEInterceptor } from 'e2ee-adapter/interceptor';

@Injectable()
export class E2EEInterceptor extends E2EEInterceptor {
  constructor() {
    super({
      config: {
        keys: {
          domain1: {
            privateKey: process.env.E2EE_DOMAIN1_PRIVATE_KEY,
            publicKey: process.env.E2EE_DOMAIN1_PUBLIC_KEY
          },
          domain2: {
            privateKey: process.env.E2EE_DOMAIN2_PRIVATE_KEY,
            publicKey: process.env.E2EE_DOMAIN2_PUBLIC_KEY
          }
        },

        enableRequestDecryption: true,
        enableResponseEncryption: true,
        enforced: true // Strictly require encryption for all requests
      }
    });
  }
}

// Apply to controller or globally
@UseInterceptors(E2EEInterceptor)
@Controller('api')
export class UsersController {
  @Post('users')
  createUser(@Body() userData: any) {
    // userData is automatically decrypted
    return { success: true, user: userData };
  }
}
```

### Client Usage

```typescript
import { E2EEClient } from 'e2ee-adapter/client';

// Create client with multiple server keys
const client = new E2EEClient({
  serverKeys: {
    domain1: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
    domain2: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----'
  }
});

// Make encrypted requests
const response = await client.request({
  url: 'https://api.example.com/api/users',
  method: 'POST',
  data: {
    name: 'John Doe',
    email: 'john@example.com'
  },
  keyId: 'domain1' // Required: specify which key to use
});

console.log(response.data); // Automatically decrypted response
```

## 📋 API Reference

### Configuration Options

```typescript
interface KeyPair {
  /** RSA public key in PEM format */
  publicKey: string;
  /** RSA private key in PEM format */
  privateKey: string;
}

interface KeyStore {
  /** Mapping of keyId to key pair */
  [keyId: string]: KeyPair;
}

interface E2EEConfig {
  /** Multiple keys store for multi-domain support */
  keys: KeyStore;
  /** Custom key header name (default: x-custom-key) */
  customKeyHeader?: string;
  /** Custom IV header name (default: x-custom-iv) */
  customIVHeader?: string;
  /** Key ID header name (default: x-key-id) */
  keyIdHeader?: string;
  /** Enable request decryption (default: true) */
  enableRequestDecryption?: boolean;
  /** Enable response encryption (default: true) */
  enableResponseEncryption?: boolean;
  /** Paths to exclude from encryption */
  excludePaths?: string[];
  /** HTTP methods to exclude from encryption */
  excludeMethods?: string[];
  /** If true, strictly enforce encryption for all requests. If false, only check for encryption after identifying headers (default: false) */
  enforced?: boolean;
}
```

### Client Configuration

```typescript
interface E2EEClientConfig {
  /** Multiple server keys for multi-domain support */
  serverKeys: { [keyId: string]: string };
  /** Key ID for versioning */
  keyId?: string;
}
```

## 🔧 Examples

### Complete Express.js Example

See `examples/express-server/server.js` for a complete working example.

### Complete Client Example

See `examples/client-example/client.js` for a complete working example.

### Vanilla JavaScript Client Example

See `examples/vanilla-js-client/` for a browser-based vanilla JavaScript client with interactive UI.



## 🚀 Quick Start

1. **Install the package:**
   ```bash
   # For Express.js
   npm install e2ee-adapter express
   
   # For NestJS
   npm install e2ee-adapter @nestjs/common rxjs
   ```

2. **Generate multiple key pairs:**
   ```typescript
   import { generateMultipleKeyPairs } from 'e2ee-adapter';
   
   const keys = await generateMultipleKeyPairs(['domain1', 'domain2', 'domain3']);
   ```

3. **Set up Express middleware:**
   ```typescript
   import { createE2EEMiddleware } from 'e2ee-adapter/middleware';
   
   const e2eeMiddleware = createE2EEMiddleware({
     config: { 
       keys
     }
   });
   
   app.use(e2eeMiddleware);
   ```

4. **Create client:**
   ```typescript
   import { E2EEClient } from 'e2ee-adapter/client';
   
   const client = new E2EEClient({
     serverKeys: {
       domain1: keys.domain1.publicKey,
       domain2: keys.domain2.publicKey,
       domain3: keys.domain3.publicKey
     }
   });
   ```

5. **Make encrypted requests:**
   ```typescript
   const response = await client.request({
     url: 'http://localhost:3000/api/users',
     method: 'POST',
     data: { name: 'John Doe' },
     keyId: 'domain1' // Required: specify which key to use
   });


## 🌐 Multi-Domain Support

The library supports multiple encryption keys for different domains or tenants sharing the same server infrastructure. This is useful for:

- **Multi-tenant applications** where each tenant has their own encryption keys
- **Domain-specific encryption** where different domains use different keys
- **Key rotation** where new keys can be added while old ones remain valid
- **Isolation** ensuring data encrypted with one key cannot be decrypted with another
- **Explicit key selection** requiring users to specify which key to use for each request

### How it works:

1. **Server Configuration**: Configure multiple key pairs with unique keyIds
2. **Client Configuration**: Store public keys for all domains you need to communicate with
3. **Request-Level Key Selection**: Specify which keyId to use for each request (required)
4. **Automatic Key Resolution**: Server automatically selects the correct private key based on the keyId header

### Example Use Case:

```typescript
// Server setup for multiple domains
const keys = await generateMultipleKeyPairs(['tenant1', 'tenant2', 'tenant3']);

const middleware = createE2EEMiddleware({
  config: { keys }
});

// Client setup for multiple domains
const client = new E2EEClient({
  serverKeys: {
    tenant1: keys.tenant1.publicKey,
    tenant2: keys.tenant2.publicKey,
    tenant3: keys.tenant3.publicKey
  }
});

// Use different keys for different requests (keyId is required)
await client.request({ url: '/api/data', method: 'POST', data: data1, keyId: 'tenant1' });
await client.request({ url: '/api/data', method: 'POST', data: data2, keyId: 'tenant2' });
```

## 🔒 Security Considerations

- **Key Management**: Store private keys securely and never expose them
- **Key Rotation**: Implement key rotation mechanisms for production use
- **HTTPS**: Always use HTTPS in production to protect against MITM attacks
- **Key Size**: Use 2048-bit RSA keys minimum for production
- **Algorithm**: The middleware uses RSA-OAEP with SHA-256 for optimal security
- **Key Isolation**: Ensure proper key isolation between different domains/tenants

## 🛡️ Enforcement Mode

The library supports two enforcement modes to control how encryption is handled:

### Non-Enforced Mode (Default: `enforced: false`)
- Only processes requests that include encryption headers
- Allows both encrypted and non-encrypted requests to coexist
- Useful for gradual migration or mixed environments
- Requests without encryption headers are passed through unchanged

### Enforced Mode (`enforced: true`)
- Strictly requires all requests to include encryption headers
- Rejects requests without proper encryption headers with a 400 error
- Ensures complete end-to-end encryption compliance
- Recommended for production environments with strict security requirements

### Example Configuration:

```typescript
// Non-enforced mode (default) - allows mixed requests
const middleware = createE2EEMiddleware({
  config: {
    keys,
    enforced: false // or omit this line
  }
});

// Enforced mode - requires all requests to be encrypted
const middleware = createE2EEMiddleware({
  config: {
    keys,
    enforced: true
  }
});
```

### Use Cases:

- **Development/Testing**: Use non-enforced mode to test both encrypted and non-encrypted endpoints
- **Gradual Migration**: Start with non-enforced mode and gradually migrate clients
- **Production**: Use enforced mode to ensure all traffic is encrypted
- **Mixed Environments**: Use non-enforced mode when some clients cannot support encryption

## 📝 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 