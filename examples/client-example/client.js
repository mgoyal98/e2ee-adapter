const { E2EEClient } = require('../../dist');

async function runClientExample() {
  console.log('🚀 Starting E2EE Client Example (Multi-Key Support)\n');

  try {
    // Step 1: Fetch server's public keys from /e2ee.json
    console.log('1️⃣ Fetching server configuration from /e2ee.json...');
    const configResponse = await fetch('http://localhost:3000/keys');
    const configData = await configResponse.json();
    const serverKeys = configData.keys;
    
    console.log('✅ Server configuration fetched successfully');
    console.log('   Available domains:', Object.keys(serverKeys));
    console.log('   Key size:', configData.keySize);

    // Step 2: Create E2EE client with server's public keys
    const client = new E2EEClient({
      serverKeys: serverKeys
    });

    console.log('\n🔒 E2EE Client initialized successfully');
    console.log('📋 Client uses hybrid encryption (AES-CBC + RSA)');
    console.log('🔐 Client encrypts requests using server public keys\n');

    // Example 1: Create a user with domain1 key
    console.log('📝 Example 1: Creating a user with domain1 key...');
    try {
      const createUserResponse = await client.request({
        url: 'http://localhost:3000/api/users',
        method: 'POST',
        data: {
          name: 'John Doe',
          email: 'john@example.com'
        },
        keyId: 'domain1' // Required: specify which key to use
      });

      console.log('✅ User created successfully:');
      console.log('   Status:', createUserResponse.status);
      console.log('   Data:', JSON.stringify(createUserResponse.data, null, 2));
      console.log('   Headers:', Object.keys(createUserResponse.headers));
    } catch (error) {
      console.error('❌ Failed to create user:', error.message);
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Example 2: Create a user with specific domain key
    console.log('📝 Example 2: Creating a user with domain2 key...');
    try {
      const createUserResponse = await client.request({
        url: 'http://localhost:3000/api/users',
        method: 'POST',
        data: {
          name: 'Jane Smith',
          email: 'jane@example.com'
        },
        keyId: 'domain2' // Use specific domain key
      });

      console.log('✅ User created successfully with domain2:');
      console.log('   Status:', createUserResponse.status);
      console.log('   Data:', JSON.stringify(createUserResponse.data, null, 2));
      console.log('   Headers:', Object.keys(createUserResponse.headers));
    } catch (error) {
      console.error('❌ Failed to create user with domain2:', error.message);
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Example 3: Get a user with domain3 key (demonstrates empty request body support)
    console.log('👤 Example 3: Getting a user with domain3 key (empty request body, encrypted response)...');
    try {
      const getUserResponse = await client.request({
        url: 'http://localhost:3000/api/users/123',
        method: 'GET',
        // No data provided - demonstrates empty request body support
        keyId: 'domain3' // Use specific domain key
      });

      console.log('✅ User retrieved successfully with domain3:');
      console.log('   Status:', getUserResponse.status);
      console.log('   Data:', JSON.stringify(getUserResponse.data, null, 2));
      console.log('   Note: Request had no body, but response was encrypted using headers');
    } catch (error) {
      console.error('❌ Failed to get user with domain3:', error.message);
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Example 3.5: GET request with empty body (new example)
    console.log('🔍 Example 3.5: GET request with empty body but encrypted response...');
    try {
      const getUsersResponse = await client.request({
        url: 'http://localhost:3000/api/users',
        method: 'GET',
        // No data - empty request body
        keyId: 'domain1'
      });

      console.log('✅ Users list retrieved successfully:');
      console.log('   Status:', getUsersResponse.status);
      console.log('   Data:', JSON.stringify(getUsersResponse.data, null, 2));
      console.log('   Note: GET request with no body, but response encrypted using AES key from headers');
    } catch (error) {
      console.error('❌ Failed to get users list:', error.message);
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Example 4: Update a user with domain1 key
    console.log('✏️ Example 4: Updating a user with domain1 key...');
    try {
      const updateUserResponse = await client.request({
        url: 'http://localhost:3000/api/users/123',
        method: 'PUT',
        data: {
          name: 'John Smith',
          email: 'johnsmith@example.com'
        },
        keyId: 'domain1' // Required: specify which key to use
      });

      console.log('✅ User updated successfully:');
      console.log('   Status:', updateUserResponse.status);
      console.log('   Data:', JSON.stringify(updateUserResponse.data, null, 2));
    } catch (error) {
      console.error('❌ Failed to update user:', error.message);
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Example 5: Delete a user with domain1 key
    console.log('🗑️ Example 5: Deleting a user with domain1 key...');
    try {
      const deleteUserResponse = await client.request({
        url: 'http://localhost:3000/api/users/123',
        method: 'DELETE',
        keyId: 'domain1' // Use specific domain key
      });

      console.log('✅ User deleted successfully with domain1:');
      console.log('   Status:', deleteUserResponse.status);
      console.log('   Data:', JSON.stringify(deleteUserResponse.data, null, 2));
    } catch (error) {
      console.error('❌ Failed to delete user with domain1:', error.message);
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Example 6: Manual encryption demonstration
    console.log('🔐 Example 6: Manual encryption demonstration...');
    try {
      const testData = {
        message: 'Hello, E2EE World!',
        timestamp: new Date().toISOString(),
        secret: 'This is a secret message'
      };

      console.log('   Original data:', JSON.stringify(testData, null, 2));
      
      const { encryptedData, encryptedKey, iv } = await client.encryptRequest(testData, "domain1");
      
      console.log('   ✅ Data encrypted using hybrid encryption:');
      console.log('      - AES-CBC encrypted data length:', encryptedData.length);
      console.log('      - RSA encrypted AES key length:', encryptedKey.length);
      console.log('      - IV length:', iv.length);
      
      console.log('   ✅ Manual encryption successful');
      console.log('   Note: Client can decrypt responses using the same AES key');
    } catch (error) {
      console.error('❌ Manual encryption failed:', error.message);
    }

    console.log('\n' + '='.repeat(50) + '\n');

    // Architecture Summary
    console.log('🏗️ Architecture Summary:');
    console.log('   🔐 Client: Fetches server public keys from /e2ee.json');
    console.log('   🔑 Server: Has multiple RSA private/public key pairs for different domains');
    console.log('   📤 Client: Generates AES key, encrypts data with AES-CBC');
    console.log('   📤 Client: Encrypts AES key with server RSA public key (based on keyId)');
    console.log('   📤 Client: Sends encrypted data in body, encrypted key and keyId in headers');
    console.log('   📤 Client: For GET requests, sends only headers (no body) but still generates AES key');
    console.log('   📥 Server: Decrypts AES key with RSA private key (based on keyId header)');
    console.log('   📥 Server: Decrypts data with AES key (or handles empty body)');
    console.log('   📤 Server: Encrypts response with same AES key');
    console.log('   📥 Client: Decrypts response with stored AES key');
    console.log('   ✅ This is a secure hybrid encryption approach with multi-domain support');
    console.log('   ✅ Empty request body support allows GET requests with encrypted responses');

  } catch (error) {
    console.error('❌ Client example failed:', error.message);
    console.error('Stack trace:', error.stack);
  }
}

runClientExample().catch(console.error); 