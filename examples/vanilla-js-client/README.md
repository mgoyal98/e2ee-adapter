# Vanilla JavaScript E2EE Client Example

This example demonstrates how to use the E2EE client functionality in a vanilla JavaScript environment (browser) without any framework dependencies.

## Features

- 🔐 **Hybrid Encryption**: AES-CBC for data + RSA-OAEP for key exchange
- 🌐 **Multi-Domain Support**: Use different keys for different domains
- 📡 **Interactive UI**: Web-based interface for testing E2EE functionality
- 🧪 **Test Suite**: Automated testing of different scenarios
- 🔑 **Key Management**: Fetch and manage server public keys

## Files

- `index.html` - Web interface for the E2EE client
- `client.js` - Vanilla JavaScript E2EE client implementation
- `README.md` - This documentation

## Setup

1. **Start the Express server** (from the express-server example):
   ```bash
   cd examples/express-server
   npm install
   node server.js
   ```

2. **Open the vanilla JS client**:
   - Open `examples/vanilla-js-client/index.html` in your browser
   - Or serve it using a local server:
     ```bash
     cd examples/vanilla-js-client
     python -m http.server 8080
     # Then open http://localhost:8080
     ```

## Usage

### 1. Server Configuration

1. Enter the server URL (default: `http://localhost:3000`)
2. Click "🔑 Fetch Server Keys" to retrieve the server's public keys
3. The keys will be displayed and automatically populated in the client configuration

### 2. Client Configuration

1. The server keys will be automatically populated after fetching
2. Click "🚀 Initialize Client" to create the E2EE client instance
3. The client will be ready to make encrypted requests

### 3. Making API Requests

1. Select a **Key ID** from the dropdown (required)
2. Choose the **HTTP Method** (GET, POST, PUT, DELETE)
3. Enter the **Request URL** (e.g., `/api/users`)
4. Optionally enter **Request Data** as JSON
5. Click "📤 Make Request" to send an encrypted request

### 4. Test Suite

Click "🧪 Run Test Suite" to automatically test:
- Creating users with different domain keys
- Getting users with different domain keys
- Updating users with different domain keys

### 5. Manual Encryption

1. Select a **Key ID** for encryption
2. Enter **Data to Encrypt** as JSON
3. Click "🔒 Encrypt Data" to see the encryption process

## Technical Details

### Dependencies

- **Node Forge**: Used for cryptographic operations (loaded via CDN)
- **Fetch API**: For HTTP requests (built into modern browsers)

### Encryption Process

1. **Key Generation**: Generate a random 256-bit AES key and 128-bit IV
2. **Data Encryption**: Encrypt the data using AES-CBC with the generated key
3. **Key Encryption**: Encrypt the AES key using RSA-OAEP with the server's public key
4. **Request**: Send encrypted data in the request body and encrypted key in headers

### Headers

- `x-custom-key`: Base64-encoded RSA-encrypted AES key
- `x-custom-iv`: Base64-encoded initialization vector
- `x-key-id`: Key identifier for multi-domain support

### Response Decryption

1. Use the same AES key and IV from the request
2. Decrypt the response using AES-CBC
3. Parse the decrypted JSON data

## Example Workflow

1. **Fetch Server Keys**:
   ```
   GET http://localhost:3000/keys
   Response: {
     "keys": {
       "domain1": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
       "domain2": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
     }
   }
   ```

2. **Make Encrypted Request**:
   ```
   POST http://localhost:3000/api/users
   Headers: {
     "x-custom-key": "base64-encoded-encrypted-aes-key",
     "x-custom-iv": "base64-encoded-iv",
     "x-key-id": "domain1"
   }
   Body: "base64-encoded-encrypted-data"
   ```

3. **Receive Encrypted Response**:
   ```
   Response Body: "base64-encoded-encrypted-response"
   ```

## Browser Compatibility

This example works in modern browsers that support:
- ES6+ features (async/await, classes, arrow functions)
- Fetch API
- Web Crypto API (for random number generation)

## Security Notes

- The client uses the same cryptographic algorithms as the Node.js implementation
- All encryption/decryption happens in the browser
- Server public keys are fetched over HTTP (use HTTPS in production)
- Private keys are never exposed to the client

## Troubleshooting

### CORS Issues
If you encounter CORS errors, make sure the server is configured to allow requests from your client origin.

### Key Not Found
Ensure the keyId you're using exists in the server's key configuration.

### Encryption Errors
Check that the server public key is valid and in the correct PEM format.

## Next Steps

- Implement HTTPS for production use
- Add key rotation support
- Implement client-side key caching
- Add request/response signing
- Implement error retry logic 