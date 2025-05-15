// Secret key for JWT signing and encryption
const SECRET_KEY = 'your-secret-key-for-jwt-signing';

// Check if we're in Node.js environment
const isNode = typeof window === 'undefined' && typeof process !== 'undefined';

// Import or define necessary functions for Node.js
let crypto, Buffer;
if (isNode) {
  crypto = require('crypto');
  Buffer = global.Buffer;
}

// Base64 encoding/decoding functions that work in both browser and Node.js
const base64Encode = (str) => {
  if (isNode) {
    return Buffer.from(str).toString('base64');
  } else {
    return btoa(str);
  }
};

const base64Decode = (str) => {
  if (isNode) {
    return Buffer.from(str, 'base64').toString();
  } else {
    return atob(str);
  }
};

/**
 * Encrypts a payload into a JWT token with additional encryption
 * @param {Object} payload - The data to encrypt
 * @return {String} - The encrypted JWT token
 */
const encrypt = (payload) => {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Payload must be a valid object');
  }

  try {
    // Step 1: Convert payload to string
    const payloadStr = JSON.stringify(payload);

    // Step 2: Create a JWT-like structure manually
    // Header: algorithm and token type
    const header = {
      alg: "HS256",
      typ: "JWT"
    };

    // Base64 encode the header and payload
    const encodedHeader = base64Encode(JSON.stringify(header));
    const encodedPayload = base64Encode(payloadStr);

    // Step 3: Create signature
    let signature;
    if (isNode) {
      // Node.js environment
      const dataToSign = encodedHeader + "." + encodedPayload;
      signature = crypto.createHmac('sha256', SECRET_KEY)
        .update(dataToSign)
        .digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    } else if (typeof CryptoJS !== 'undefined') {
      // Browser environment with CryptoJS
      const dataToSign = encodedHeader + "." + encodedPayload;
      signature = CryptoJS.HmacSHA256(dataToSign, SECRET_KEY).toString(CryptoJS.enc.Base64);
      // Make the signature URL safe
      signature = signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    } else {
      // Simple fallback for demo purposes
      signature = "signature-placeholder";
    }

    // Step 4: Combine to form the JWT token
    const token = encodedHeader + "." + encodedPayload + "." + signature;

    // Step 5: For additional security, encrypt the entire token
    let encryptedToken;
    if (isNode) {
      // Node.js environment - using newer crypto API
      // Generate a random initialization vector
      const iv = crypto.randomBytes(16);
      // Create a key from the secret
      const key = crypto.scryptSync(SECRET_KEY, 'salt', 32);
      // Create cipher
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      // Encrypt the token
      let encrypted = cipher.update(token, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      // Combine IV and encrypted data
      encryptedToken = iv.toString('hex') + ':' + encrypted;
    } else if (typeof CryptoJS !== 'undefined') {
      // Browser environment with CryptoJS
      encryptedToken = CryptoJS.AES.encrypt(token, SECRET_KEY).toString();
    } else {
      // Simple fallback for demo purposes
      encryptedToken = token;
    }

    return encryptedToken;
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt payload');
  }
};

/**
 * Decrypts a JWT token and returns the original payload
 * @param {String} encryptedToken - The encrypted JWT token
 * @return {Object} - The decrypted payload
 */
const decrypt = (encryptedToken) => {
  if (!encryptedToken || typeof encryptedToken !== 'string') {
    throw new Error('Token must be a valid string');
  }

  try {
    // Step 1: Decrypt the token
    let token;
    if (isNode) {
      // Node.js environment - using newer crypto API
      try {
        // Split the IV and encrypted data
        const parts = encryptedToken.split(':');
        if (parts.length !== 2) {
          throw new Error('Invalid encrypted token format');
        }

        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = parts[1];

        // Create a key from the secret
        const key = crypto.scryptSync(SECRET_KEY, 'salt', 32);

        // Create decipher
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

        // Decrypt
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        token = decrypted;
      } catch (err) {
        // If decryption fails, try treating it as an unencrypted token
        console.warn('Decryption failed, trying as unencrypted token:', err.message);
        token = encryptedToken;
      }
    } else if (typeof CryptoJS !== 'undefined') {
      // Browser environment with CryptoJS
      try {
        const bytes = CryptoJS.AES.decrypt(encryptedToken, SECRET_KEY);
        token = bytes.toString(CryptoJS.enc.Utf8);
      } catch (err) {
        // If decryption fails, try treating it as an unencrypted token
        console.warn('Decryption failed, trying as unencrypted token:', err.message);
        token = encryptedToken;
      }
    } else {
      // Simple fallback for demo purposes
      token = encryptedToken;
    }

    // Step 2: Split the JWT token into its parts
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid token format');
    }

    // Step 3: Decode the payload
    const encodedPayload = parts[1];
    const decodedPayload = base64Decode(encodedPayload);

    // Step 4: Parse the JSON payload
    return JSON.parse(decodedPayload);
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt token or token is invalid');
  }
};

// Export functions for Node.js environment
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    encrypt,
    decrypt
  };
}
