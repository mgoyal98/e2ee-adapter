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

```bash
npm install e2ee-middleware
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

### Express.js Setup

```typescript
import express from 'express';
import { createE2EEMiddleware, generateKeyPair } from 'e2ee-middleware';

const app = express();

// Generate RSA key pair
const { publicKey, privateKey } = await generateKeyPair(2048);

// Create E2EE middleware
const e2eeMiddleware = createE2EEMiddleware({
  config: {
    privateKey,
    publicKey,
    algorithm: 'RSA-OAEP',
    enableRequestDecryption: true,
    enableResponseEncryption: true,
    excludePaths: ['/health', '/keys', '/e2ee.json'],
    excludeMethods: ['GET', 'HEAD', 'OPTIONS']
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
    key: publicKey,
    key_id: 'v1',
    algorithm: 'RSA-OAEP',
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
import { E2EEInterceptor } from 'e2ee-middleware';

@Injectable()
export class E2EEInterceptor extends E2EEInterceptor {
  constructor() {
    super({
      config: {
        privateKey: process.env.E2EE_PRIVATE_KEY,
        publicKey: process.env.E2EE_PUBLIC_KEY,
        enableRequestDecryption: true,
        enableResponseEncryption: true
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
import { E2EEClient } from 'e2ee-middleware';

// Create client with server's public key
const client = new E2EEClient({
  serverPublicKey: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
  keyId: 'v1'
});

// Make encrypted requests
const response = await client.request({
  url: 'https://api.example.com/api/users',
  method: 'POST',
  data: {
    name: 'John Doe',
    email: 'john@example.com'
  }
});

console.log(response.data); // Automatically decrypted response
```

## 📋 API Reference

### Configuration Options

```typescript
interface E2EEConfig {
  /** RSA private key for decryption */
  privateKey: string;
  /** RSA public key for encryption */
  publicKey: string;
  /** Encryption algorithm (default: RSA-OAEP) */
  algorithm?: string;
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
}
```

### Client Configuration

```typescript
interface E2EEClientConfig {
  /** Server's public key for encryption */
  serverPublicKey: string;
  /** Key ID for versioning */
  keyId?: string;
  /** Algorithm for encryption (default: RSA-OAEP) */
  algorithm?: string;
}
```

## 🔧 Examples

### Complete Express.js Example

See `examples/express-server/server.js` for a complete working example.

### Complete Client Example

See `examples/client-example/client.js` for a complete working example.

## 🚀 Quick Start

1. **Install the package:**
   ```bash
   npm install e2ee-middleware
   ```

2. **Generate RSA keys:**
   ```typescript
   import { generateKeyPair } from 'e2ee-middleware';
   const { publicKey, privateKey } = await generateKeyPair(2048);
   ```

3. **Set up Express middleware:**
   ```typescript
   import { createE2EEMiddleware } from 'e2ee-middleware';
   
   const e2eeMiddleware = createE2EEMiddleware({
     config: { privateKey, publicKey }
   });
   
   app.use(e2eeMiddleware);
   ```

4. **Create client:**
   ```typescript
   import { E2EEClient } from 'e2ee-middleware';
   
   const client = new E2EEClient({
     serverPublicKey: publicKey
   });
   ```

5. **Make encrypted requests:**
   ```typescript
   const response = await client.request({
     url: 'http://localhost:3000/api/users',
     method: 'POST',
     data: { name: 'John Doe' }
   });
   ```

## 🔒 Security Considerations

- **Key Management**: Store private keys securely and never expose them
- **Key Rotation**: Implement key rotation mechanisms for production use
- **HTTPS**: Always use HTTPS in production to protect against MITM attacks
- **Key Size**: Use 2048-bit RSA keys minimum for production
- **Algorithm**: The middleware uses RSA-OAEP with SHA-256 for optimal security

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