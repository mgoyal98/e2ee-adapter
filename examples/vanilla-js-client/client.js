// E2EE Vanilla JavaScript Client
class E2EEClient {
  constructor(serverKeys) {
    this.serverKeys = serverKeys;
    this.availableKeyIds = Object.keys(serverKeys);

    if (this.availableKeyIds.length === 0) {
      throw new Error('At least one server key must be provided');
    }

    console.log('🔒 E2EE Client initialized with keys:', this.availableKeyIds);
  }

  /**
   * Get server public key for a specific keyId
   */
  getServerPublicKey(keyId) {
    const publicKey = this.serverKeys[keyId];

    if (!publicKey) {
      throw new Error(`Server public key not found for keyId: ${keyId}`);
    }

    return publicKey;
  }

  /**
   * Generate AES key and IV
   */
  generateAESKey() {
    const aesKey = forge.random.getBytesSync(32); // 256-bit key
    const iv = forge.random.getBytesSync(16); // 128-bit IV
    return { aesKey, iv };
  }

  /**
   * Encrypt data using hybrid encryption (AES-CBC + RSA)
   */
  async encryptRequest(data, keyId) {
    try {
      const dataString = JSON.stringify(data);
      const serverPublicKey = this.getServerPublicKey(keyId);

      // Generate AES key and IV
      const { aesKey, iv } = this.generateAESKey();

      // Encrypt data with AES-CBC
      const cipher = forge.cipher.createCipher('AES-CBC', aesKey);
      cipher.start({ iv: iv });
      cipher.update(forge.util.createBuffer(dataString, 'utf8'));
      cipher.finish();
      const encryptedData = forge.util.encode64(cipher.output.getBytes());

      // Encrypt AES key with RSA
      const publicKey = forge.pki.publicKeyFromPem(serverPublicKey);
      const encryptedKey = publicKey.encrypt(aesKey, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
      });
      const encryptedKeyBase64 = forge.util.encode64(encryptedKey);

      return {
        encryptedData,
        encryptedKey: encryptedKeyBase64,
        iv: forge.util.encode64(iv),
        originalAesKey: aesKey,
        originalIv: iv,
      };
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt response data using AES-CBC
   */
  decryptResponse(encryptedData, aesKey, iv) {
    try {
      const decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
      decipher.start({ iv: iv });
      decipher.update(
        forge.util.createBuffer(forge.util.decode64(encryptedData))
      );
      decipher.finish();
      const decryptedData = decipher.output.toString('utf8');
      return JSON.parse(decryptedData);
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Make an encrypted HTTP request
   */
  async request(requestConfig) {
    const { url, method, data, keyId } = requestConfig;

    // Validate keyId is provided
    if (!keyId) {
      throw new Error('keyId is required for encrypted requests');
    }

    try {
      let requestBody = '';
      let aesKey, iv;

      // Prepare headers
      const headers = {
        'Content-Type': 'application/json',
      };

      // Always set the key ID header
      headers['x-key-id'] = keyId;

      // Encrypt request data if provided
      const encryptionResult = await this.encryptRequest(data || {}, keyId);

      // Set encrypted data as request body
      requestBody = encryptionResult.encryptedData;
      aesKey = encryptionResult.originalAesKey;
      iv = encryptionResult.originalIv;

      headers['x-custom-key'] = encryptionResult.encryptedKey;
      headers['x-custom-iv'] = encryptionResult.iv;

      // Make the HTTP request
      const fetchOptions = {
        method,
        headers,
      };

      if (data) {
        console.log('requestBody', requestBody);
        fetchOptions.body = requestBody;
        fetchOptions.headers['Content-Type'] = 'text/plain';
      }

      const response = await fetch(url, fetchOptions);

      // Parse response headers
      const responseHeaders = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      // Get response data
      const responseData = await response.text();

      // Decrypt response if we have the AES key and IV
      let decryptedData = responseData;
      if (aesKey && iv && responseData) {
        try {
          decryptedData = this.decryptResponse(responseData, aesKey, iv);
        } catch (error) {
          console.warn(
            'Failed to decrypt response, returning raw data:',
            error
          );
          decryptedData = responseData;
        }
      }

      return {
        data: decryptedData,
        headers: responseHeaders,
        status: response.status,
        statusText: response.statusText,
      };
    } catch (error) {
      throw new Error(`Request failed: ${error.message}`);
    }
  }
}

// Global variables
let e2eeClient = null;
let serverKeys = null;

// Utility functions
function showResult(elementId, message, type = 'info') {
  const element = document.getElementById(elementId);
  element.innerHTML = `<div class="result ${type}">${message}</div>`;
}

function updateStatus(connected) {
  const statusElement = document.getElementById('status');
  if (connected) {
    statusElement.className = 'status connected';
    statusElement.textContent = '🟢 Connected to server';
  } else {
    statusElement.className = 'status disconnected';
    statusElement.textContent = '🔴 Disconnected from server';
  }
}

function updateKeySelects() {
  if (!serverKeys) return;

  const keyIds = Object.keys(serverKeys);
  const selects = ['requestKeyId', 'encryptKeyId'];

  selects.forEach((selectId) => {
    const select = document.getElementById(selectId);
    select.innerHTML = '<option value="">Select a key ID...</option>';
    keyIds.forEach((keyId) => {
      const option = document.createElement('option');
      option.value = keyId;
      option.textContent = keyId;
      select.appendChild(option);
    });
  });
}

// UI Functions
async function fetchServerKeys() {
  const serverUrl = document.getElementById('serverUrl').value;

  try {
    showResult('serverKeysResult', '🔍 Fetching server keys...', 'info');

    const response = await fetch(`${serverUrl}/keys`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const configData = await response.json();
    serverKeys = configData.keys;

    // Update the server keys textarea
    document.getElementById('serverKeys').value = JSON.stringify(
      serverKeys,
      null,
      2
    );

    // Update key selects
    updateKeySelects();

    // Show server keys info
    const keyInfo = Object.keys(serverKeys)
      .map(
        (keyId) => `
            <div class="key-card">
                <h4>🔑 ${keyId}</h4>
                <div class="key-value">${serverKeys[keyId]}</div>
            </div>
        `
      )
      .join('');

    showResult(
      'serverKeysResult',
      `
✅ Server keys fetched successfully!

Available domains: ${Object.keys(serverKeys).join(', ')}

<div class="key-info">
    ${keyInfo}
</div>
        `,
      'success'
    );

    updateStatus(true);
  } catch (error) {
    showResult(
      'serverKeysResult',
      `❌ Failed to fetch server keys: ${error.message}`,
      'error'
    );
    updateStatus(false);
  }
}

function initializeClient() {
  try {
    const serverKeysText = document.getElementById('serverKeys').value;
    if (!serverKeysText.trim()) {
      throw new Error('Please provide server keys');
    }

    const keys = JSON.parse(serverKeysText);
    e2eeClient = new E2EEClient(keys);

    // Update key selects
    serverKeys = keys;
    updateKeySelects();

    showResult(
      'clientResult',
      `
✅ E2EE Client initialized successfully!

Available key IDs: ${Object.keys(keys).join(', ')}

Client is ready to make encrypted requests!
        `,
      'success'
    );

    updateStatus(true);
  } catch (error) {
    showResult(
      'clientResult',
      `❌ Failed to initialize client: ${error.message}`,
      'error'
    );
    updateStatus(false);
  }
}

async function makeRequest() {
  if (!e2eeClient) {
    showResult(
      'requestResult',
      '❌ Please initialize the client first',
      'error'
    );
    return;
  }

  const keyId = document.getElementById('requestKeyId').value;
  const method = document.getElementById('requestMethod').value;
  const url = document.getElementById('requestUrl').value;
  const dataText = document.getElementById('requestData').value;

  if (!keyId) {
    showResult('requestResult', '❌ Please select a key ID', 'error');
    return;
  }

  try {
    const serverUrl = document.getElementById('serverUrl').value;
    const fullUrl = `${serverUrl}${url}`;

    let data = null;
    if (dataText.trim()) {
      data = JSON.parse(dataText);
    }

    showResult('requestResult', '📤 Making encrypted request...', 'info');

    const response = await e2eeClient.request({
      url: fullUrl,
      method,
      data,
      keyId,
    });

    showResult(
      'requestResult',
      `
✅ Request successful!

Status: ${response.status} ${response.statusText}
Key ID: ${keyId}
Method: ${method}
URL: ${fullUrl}

Response Data:
${JSON.stringify(response.data, null, 2)}

Response Headers:
${JSON.stringify(response.headers, null, 2)}
        `,
      'success'
    );
  } catch (error) {
    showResult('requestResult', `❌ Request failed: ${error.message}`, 'error');
  }
}

async function makeTestRequests() {
  if (!e2eeClient) {
    showResult(
      'requestResult',
      '❌ Please initialize the client first',
      'error'
    );
    return;
  }

  const serverUrl = document.getElementById('serverUrl').value;
  const keyIds = Object.keys(serverKeys);

  if (keyIds.length === 0) {
    showResult('requestResult', '❌ No key IDs available', 'error');
    return;
  }

  showResult('requestResult', '🧪 Running test suite...', 'info');

  const tests = [
    {
      name: 'Create user with domain1',
      method: 'POST',
      url: '/api/users',
      data: { name: 'John Doe', email: 'john@example.com' },
      keyId: keyIds[0],
    },
    {
      name: 'Create user with domain2',
      method: 'POST',
      url: '/api/users',
      data: { name: 'Jane Smith', email: 'jane@example.com' },
      keyId: keyIds[1] || keyIds[0],
    },
    {
      name: 'Get user with domain3',
      method: 'GET',
      url: '/api/users/123',
      data: null,
      keyId: keyIds[2] || keyIds[0],
    },
    {
      name: 'Update user with domain1',
      method: 'PUT',
      url: '/api/users/123',
      data: { name: 'John Updated', email: 'john.updated@example.com' },
      keyId: keyIds[0],
    },
  ];

  let results = [];

  for (const test of tests) {
    try {
      const fullUrl = `${serverUrl}${test.url}`;
      const response = await e2eeClient.request({
        url: fullUrl,
        method: test.method,
        data: test.data,
        keyId: test.keyId,
      });

      results.push(
        `✅ ${test.name}: ${response.status} ${response.statusText}`
      );
    } catch (error) {
      results.push(`❌ ${test.name}: ${error.message}`);
    }
  }

  showResult(
    'requestResult',
    `
🧪 Test Suite Results:

${results.join('\n')}

All tests completed!
    `,
    'success'
  );
}

async function encryptData() {
  if (!e2eeClient) {
    showResult(
      'encryptResult',
      '❌ Please initialize the client first',
      'error'
    );
    return;
  }

  const keyId = document.getElementById('encryptKeyId').value;
  const dataText = document.getElementById('dataToEncrypt').value;

  if (!keyId) {
    showResult('encryptResult', '❌ Please select a key ID', 'error');
    return;
  }

  if (!dataText.trim()) {
    showResult('encryptResult', '❌ Please provide data to encrypt', 'error');
    return;
  }

  try {
    const data = JSON.parse(dataText);

    showResult('encryptResult', '🔒 Encrypting data...', 'info');

    const encryptionResult = await e2eeClient.encryptRequest(data, keyId);

    showResult(
      'encryptResult',
      `
✅ Data encrypted successfully!

Key ID: ${keyId}
Original Data: ${JSON.stringify(data, null, 2)}

Encrypted Data (Base64): ${encryptionResult.encryptedData}
Encrypted AES Key (Base64): ${encryptionResult.encryptedKey}
IV (Base64): ${encryptionResult.iv}

Encryption Details:
- AES-CBC encryption for data
- RSA-OAEP encryption for AES key
- 256-bit AES key
- 128-bit IV
        `,
      'success'
    );
  } catch (error) {
    showResult(
      'encryptResult',
      `❌ Encryption failed: ${error.message}`,
      'error'
    );
  }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function () {
  console.log('🔐 E2EE Vanilla JS Client Example loaded');
  updateStatus(false);
});
