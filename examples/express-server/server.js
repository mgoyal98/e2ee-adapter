const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const {
  createE2EEMiddleware,
  generateMultipleKeyPairs,
} = require('../../dist');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.text({ type: 'text/plain' })); // Parse as text for encrypted data

// Generate RSA key pairs for the server
let serverKeys;

async function setupE2EE() {
  try {
    // Generate keys for different domains
    serverKeys = await generateMultipleKeyPairs(
      ['domain1', 'domain2', 'domain3'],
      2048
    );
    console.log('✅ RSA key pairs generated successfully');
    console.log('📋 Server Public Keys (share these with clients):');
    Object.keys(serverKeys).forEach((domain) => {
      console.log(`\n🔑 ${domain}:`);
      console.log(serverKeys[domain].publicKey);
    });
    console.log('\n🔐 Server Private Keys (keep these secure):');
    Object.keys(serverKeys).forEach((domain) => {
      console.log(`\n🔐 ${domain}:`);
      console.log(serverKeys[domain].privateKey);
    });
  } catch (error) {
    console.error('❌ Failed to generate key pairs:', error);
    process.exit(1);
  }
}

// E2EE middleware configuration
const e2eeConfig = {
  keys: {}, // Will be set after key generation
  enableRequestDecryption: true,
  enableResponseEncryption: true,
  excludePaths: ['/health', '/keys'],
  excludeMethods: ['HEAD', 'OPTIONS'], // Remove GET to enable empty request body support
  allowEmptyRequestBody: true, // Enable empty request body support
};

// Health check endpoint (unencrypted)
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Public keys endpoint (unencrypted)
app.get('/keys', (req, res) => {
  const publicKeys = {};
  Object.keys(serverKeys).forEach((domain) => {
    publicKeys[domain] = serverKeys[domain].publicKey;
  });

  res.json({
    keys: publicKeys,
    keySize: 2048,
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('❌ Server error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: error.message,
  });
});

// Start server
async function startServer() {
  await setupE2EE();

  // Update E2EE config with generated keys
  e2eeConfig.keys = serverKeys;

  // Create E2EE middleware
  const e2eeMiddleware = createE2EEMiddleware({
    config: e2eeConfig,
    onError: (error, req, res) => {
      console.error('🔒 E2EE Error:', error.message);
    },
    onDecrypt: (decryptedData, req) => {
      console.log('🔓 Request decrypted successfully');
      console.log('🔑 AES Key length:', decryptedData.aesKey?.length);
      console.log('🔑 IV length:', decryptedData.iv?.length);
    },
    onEncrypt: (encryptedData, res) => {
      console.log('🔒 Response encrypted successfully');
    },
  });

  // Apply E2EE middleware BEFORE defining routes
  app.use(e2eeMiddleware);

  // Protected endpoints (encrypted) - defined AFTER middleware
  app.post('/api/users', (req, res) => {
    console.log('📝 Creating user with data:', req.body);

    const user = {
      id: Date.now(),
      name: req.body.name,
      email: req.body.email,
      createdAt: new Date().toISOString(),
    };

    // The middleware will automatically encrypt the response
    res.send({
      success: true,
      user,
      message: 'User created successfully',
    });
  });

  app.get('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    console.log('👤 Fetching user with ID:', userId);

    const user = {
      id: parseInt(userId),
      name: 'John Doe',
      email: 'john@example.com',
      createdAt: new Date().toISOString(),
    };

    res.send({
      success: true,
      user,
    });
  });

  // New endpoint to demonstrate empty request body support
  app.get('/api/users', (req, res) => {
    console.log(
      '👥 Fetching all users (empty request body, encrypted response)'
    );

    const users = [
      {
        id: 1,
        name: 'John Doe',
        email: 'john@example.com',
        createdAt: new Date().toISOString(),
      },
      {
        id: 2,
        name: 'Jane Smith',
        email: 'jane@example.com',
        createdAt: new Date().toISOString(),
      },
      {
        id: 3,
        name: 'Bob Johnson',
        email: 'bob@example.com',
        createdAt: new Date().toISOString(),
      },
    ];

    res.send({
      success: true,
      users,
      count: users.length,
      message: 'Users retrieved successfully (encrypted response)',
    });
  });

  app.put('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    console.log('✏️ Updating user with ID:', userId, 'Data:', req.body);

    const updatedUser = {
      id: parseInt(userId),
      name: req.body.name,
      email: req.body.email,
      updatedAt: new Date().toISOString(),
    };

    res.send({
      success: true,
      user: updatedUser,
      message: 'User updated successfully',
    });
  });

  app.delete('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    console.log('🗑️ Deleting user with ID:', userId);

    res.send({
      success: true,
      message: `User ${userId} deleted successfully`,
    });
  });

  app.listen(PORT, () => {
    console.log(`🚀 E2EE Express server running on http://localhost:${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🔑 Public keys: http://localhost:${PORT}/keys`);
    console.log(`🔐 E2EE config: http://localhost:${PORT}/e2ee.json`);
    console.log(`\n📖 API Endpoints:`);
    console.log(`   POST /api/users - Create user (encrypted)`);
    console.log(
      `   GET  /api/users - Get all users (empty body, encrypted response)`
    );
    console.log(
      `   GET  /api/users/:id - Get user (empty body, encrypted response)`
    );
    console.log(`   PUT  /api/users/:id - Update user (encrypted)`);
    console.log(`   DELETE /api/users/:id - Delete user (encrypted)`);
    console.log(
      `\n🌐 Available domains: ${Object.keys(serverKeys).join(', ')}`
    );
    console.log(`\n✨ Features:`);
    console.log(`   🔐 Hybrid encryption (AES-CBC + RSA)`);
    console.log(`   🌍 Multi-domain key support`);
    console.log(`   📤 Empty request body support for GET requests`);
    console.log(`   🔒 Encrypted responses for all endpoints`);
  });
}

startServer().catch(console.error);
