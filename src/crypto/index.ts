/**
 * @fileoverview Cryptographic Utilities
 * @module @engjts/auth/crypto
 * @description Native Node.js cryptographic implementations for the Janus Token System (JTS).
 * Provides key generation, signing, verification, encryption, and utility functions.
 * 
 * Supports multiple cryptographic algorithms:
 * - **RSA**: RS256, RS384, RS512 (PKCS#1 v1.5)
 * - **ECDSA**: ES256, ES384, ES512 (Elliptic Curve Digital Signature Algorithm)
 * - **RSA-PSS**: PS256, PS384, PS512 (Probabilistic Signature Scheme)
 * 
 * @example
 * ```typescript
 * import { generateKeyPair, sign, verify } from '@engjts/auth/crypto';
 * 
 * // Generate a key pair
 * const keyPair = await generateKeyPair('my-key-id', 'RS256');
 * 
 * // Sign data
 * const data = 'Hello, World!';
 * const signature = sign(data, keyPair.privateKey, 'RS256');
 * 
 * // Verify signature
 * const isValid = verify(data, signature, keyPair.publicKey, 'RS256');
 * console.log(isValid); // true
 * ```
 */

import * as crypto from 'crypto';
import { JTSAlgorithm } from '../types';
import type { JTSKeyPair, JWKSKey, JWKS } from '../types';
import { ALGORITHM_CONFIG, AlgorithmConfig, ANCHOR_ID_PREFIX, DEFAULT_CEK_LENGTH, DEFAULT_IV_LENGTH, DEFAULT_RANDOM_STRING_LENGTH, DEFAULT_RSA_MODULUS_LENGTH, DEVICE_FINGERPRINT_HASH_LENGTH, DEVICE_FINGERPRINT_PREFIX, EC_SIGNATURE_SIZES, ECCurve, JWKCurve, KeyType, STATE_PROOF_PREFIX, TOKEN_ID_PREFIX } from './AlgorithmConfig';


// ============================================================================
// BASE64URL ENCODING/DECODING UTILITIES
// ============================================================================

/**
 * @function base64urlEncode
 * @description Encodes a Buffer or string to base64url format.
 * Base64url is a URL-safe variant of base64 that replaces '+' with '-',
 * '/' with '_', and removes padding '=' characters.
 * 
 * @param data - The data to encode (Buffer or string)
 * @returns The base64url-encoded string
 * 
 * @example
 * ```typescript
 * const encoded = base64urlEncode('Hello, World!');
 * console.log(encoded); // SGVsbG8sIFdvcmxkIQ
 * ```
 */
export function base64urlEncode(data: Buffer | string): string {
  const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * @function base64urlDecode
 * @description Decodes a base64url string to a Buffer.
 * Handles padding automatically by adding '=' characters as needed.
 * 
 * @param str - The base64url string to decode
 * @returns The decoded Buffer
 * 
 * @example
 * ```typescript
 * const decoded = base64urlDecode('SGVsbG8sIFdvcmxkIQ');
 * console.log(decoded.toString()); // Hello, World!
 * ```
 */
export function base64urlDecode(str: string): Buffer {
  // Add padding if needed
  let padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = padded.length % 4;
  if (padding === 2) {
    padded += '==';
  } else if (padding === 3) {
    padded += '=';
  }
  return Buffer.from(padded, 'base64');
}

/**
 * @function encodeJSON
 * @description Encodes a JavaScript object to a base64url-encoded JSON string.
 * Useful for encoding JWS header and payload segments.
 * 
 * @param obj - The object to encode
 * @returns The base64url-encoded JSON string
 * 
 * @example
 * ```typescript
 * const header = { alg: 'RS256', typ: 'JTS-S/v1' };
 * const encoded = encodeJSON(header);
 * console.log(encoded); // eyJhbGciOiJSUzI1NiIsInR5cCI6IkpUUy1TL3YxIn0
 * ```
 */
export function encodeJSON(obj: unknown): string {
  return base64urlEncode(JSON.stringify(obj));
}

/**
 * @function decodeJSON
 * @description Decodes a base64url-encoded JSON string to a JavaScript object.
 * Useful for decoding JWS header and payload segments.
 * 
 * @template T - The expected type of the decoded object
 * @param str - The base64url-encoded JSON string
 * @returns The decoded object
 * 
 * @example
 * ```typescript
 * const encoded = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpUUy1TL3YxIn0';
 * const decoded = decodeJSON<{ alg: string; typ: string }>(encoded);
 * console.log(decoded); // { alg: 'RS256', typ: 'JTS-S/v1' }
 * ```
 */
export function decodeJSON<T = unknown>(str: string): T {
  return JSON.parse(base64urlDecode(str).toString('utf8'));
}

// ============================================================================
// KEY GENERATION
// ============================================================================

/**
 * @function generateRSAKeyPair
 * @description Generates a new RSA key pair for use with JTS.
 * Supports RS256, RS384, RS512, PS256, PS384, and PS512 algorithms.
 * Keys are generated in PEM format with SPKI encoding for public keys
 * and PKCS#8 encoding for private keys.
 * 
 * @param kid - Key ID to associate with the key pair
 * @param algorithm - RSA algorithm to use (default: JTSAlgorithm.RS256)
 * @param modulusLength - RSA key size in bits (default: DEFAULT_RSA_MODULUS_LENGTH)
 * @returns Promise resolving to a JTSKeyPair object
 * 
 * @example
 * ```typescript
 * // Generate a 2048-bit RSA key pair
 * const keyPair = await generateRSAKeyPair('my-rsa-key', JTSAlgorithm.RS256);
 * 
 * // Generate a 4096-bit RSA key pair
 * const strongKeyPair = await generateRSAKeyPair('strong-rsa-key', JTSAlgorithm.RS512, 4096);
 * ```
 */
export async function generateRSAKeyPair(
  kid: string,
  algorithm: JTSAlgorithm.RS256 | JTSAlgorithm.RS384 | JTSAlgorithm.RS512 | JTSAlgorithm.PS256 | JTSAlgorithm.PS384 | JTSAlgorithm.PS512 = JTSAlgorithm.RS256,
  modulusLength: number = DEFAULT_RSA_MODULUS_LENGTH
): Promise<JTSKeyPair> {
  return new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      KeyType.RSA,
      {
        modulusLength,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, publicKey, privateKey) => {
        if (err) {
          reject(err);
        } else {
          resolve({
            kid,
            algorithm,
            publicKey,
            privateKey,
          });
        }
      }
    );
  });
}

/**
 * @function generateECKeyPair
 * @description Generates a new Elliptic Curve (EC) key pair for use with JTS.
 * Supports ES256, ES384, and ES512 algorithms with NIST-standardized curves.
 * Keys are generated in PEM format with SPKI encoding for public keys
 * and PKCS#8 encoding for private keys.
 * 
 * @param kid - Key ID to associate with the key pair
 * @param algorithm - EC algorithm to use (default: JTSAlgorithm.ES256)
 * @returns Promise resolving to a JTSKeyPair object
 * 
 * @example
 * ```typescript
 * // Generate an ES256 key pair (NIST P-256 curve)
 * const ecKeyPair = await generateECKeyPair('my-ec-key', JTSAlgorithm.ES256);
 * 
 * // Generate an ES384 key pair (NIST P-384 curve)
 * const strongECKeyPair = await generateECKeyPair('strong-ec-key', JTSAlgorithm.ES384);
 * ```
 */
export async function generateECKeyPair(
  kid: string,
  algorithm: JTSAlgorithm.ES256 | JTSAlgorithm.ES384 | JTSAlgorithm.ES512 = JTSAlgorithm.ES256
): Promise<JTSKeyPair> {
  const config = ALGORITHM_CONFIG[algorithm];
  if (config.type !== KeyType.EC || !config.curve) {
    throw new Error(`Invalid EC algorithm: ${algorithm}`);
  }

  return new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      KeyType.EC,
      {
        namedCurve: config.curve!,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, publicKey, privateKey) => {
        if (err) {
          reject(err);
        } else {
          resolve({
            kid,
            algorithm,
            publicKey,
            privateKey,
          });
        }
      }
    );
  });
}

/**
 * @function generateKeyPair
 * @description Generates a new key pair based on the specified algorithm.
 * Automatically selects the appropriate key generation function based on
 * the algorithm type (RSA, EC, or RSA-PSS).
 * 
 * @param kid - Key ID to associate with the key pair
 * @param algorithm - Algorithm to use for key generation (default: JTSAlgorithm.RS256)
 * @returns Promise resolving to a JTSKeyPair object
 * 
 * @example
 * ```typescript
 * // Generate an RSA key pair
 * const rsaKey = await generateKeyPair('rsa-key', JTSAlgorithm.RS256);
 * 
 * // Generate an EC key pair
 * const ecKey = await generateKeyPair('ec-key', JTSAlgorithm.ES256);
 * 
 * // Generate an RSA-PSS key pair
 * const pssKey = await generateKeyPair('pss-key', JTSAlgorithm.PS256);
 * ```
 */
export async function generateKeyPair(
  kid: string,
  algorithm: JTSAlgorithm = JTSAlgorithm.RS256
): Promise<JTSKeyPair> {
  const config = ALGORITHM_CONFIG[algorithm];
  if (config.type === KeyType.EC) {
    return generateECKeyPair(kid, algorithm as JTSAlgorithm.ES256 | JTSAlgorithm.ES384 | JTSAlgorithm.ES512);
  } else {
    return generateRSAKeyPair(kid, algorithm as JTSAlgorithm.RS256 | JTSAlgorithm.RS384 | JTSAlgorithm.RS512 | JTSAlgorithm.PS256 | JTSAlgorithm.PS384 | JTSAlgorithm.PS512);
  }
}

// ============================================================================
// DIGITAL SIGNING AND VERIFICATION
// ============================================================================

/**
 * @function sign
 * @description Signs data using the specified private key and algorithm.
 * Supports RSA, RSA-PSS, and ECDSA algorithms with automatic signature
 * format conversion for ECDSA (DER to R||S format as required by JWS).
 * 
 * @param data - The data to sign (string or Buffer)
 * @param privateKey - The private key in PEM format (string or Buffer)
 * @param algorithm - The JTS algorithm to use for signing
 * @returns The signature as a Buffer
 * 
 * @example
 * ```typescript
 * import { generateKeyPair, sign, JTSAlgorithm } from '@engjts/auth/crypto';
 * 
 * const keyPair = await generateKeyPair('my-key', JTSAlgorithm.RS256);
 * const data = 'Hello, World!';
 * const signature = sign(data, keyPair.privateKey, JTSAlgorithm.RS256);
 * console.log(signature.toString('base64')); // Signature in base64
 * ```
 */
export function sign(
  data: string | Buffer,
  privateKey: string | Buffer,
  algorithm: JTSAlgorithm
): Buffer {
  const config = ALGORITHM_CONFIG[algorithm];
  const key = typeof privateKey === 'string' ? privateKey : privateKey.toString('utf8');
  
  const signer = crypto.createSign(config.hash);
  signer.update(data);
  signer.end();

  if (config.type === KeyType.RSA_PSS) {
    return signer.sign({
      key,
      padding: config.padding,
      saltLength: config.saltLength,
    });
  } else if (config.type === KeyType.RSA) {
    return signer.sign({
      key,
      padding: config.padding,
    });
  } else {
    // EC signature needs to be converted from DER to R||S format
    const derSignature = signer.sign(key);
    return derToRS(derSignature, algorithm);
  }
}

/**
 * @function verify
 * @description Verifies a signature using the specified public key and algorithm.
 * Supports RSA, RSA-PSS, and ECDSA algorithms with automatic signature
 * format conversion for ECDSA (R||S to DER format as required by Node.js).
 * 
 * @param data - The original data that was signed (string or Buffer)
 * @param signature - The signature to verify
 * @param publicKey - The public key in PEM format (string or Buffer)
 * @param algorithm - The JTS algorithm used for signing
 * @returns True if the signature is valid, false otherwise
 * 
 * @example
 * ```typescript
 * import { generateKeyPair, sign, verify, JTSAlgorithm } from '@engjts/auth/crypto';
 * 
 * const keyPair = await generateKeyPair('my-key', JTSAlgorithm.RS256);
 * const data = 'Hello, World!';
 * const signature = sign(data, keyPair.privateKey, JTSAlgorithm.RS256);
 * 
 * const isValid = verify(data, signature, keyPair.publicKey, JTSAlgorithm.RS256);
 * console.log(isValid); // true
 * ```
 */
export function verify(
  data: string | Buffer,
  signature: Buffer,
  publicKey: string | Buffer,
  algorithm: JTSAlgorithm
): boolean {
  const config = ALGORITHM_CONFIG[algorithm];
  const key = typeof publicKey === 'string' ? publicKey : publicKey.toString('utf8');

  const verifier = crypto.createVerify(config.hash);
  verifier.update(data);
  verifier.end();

  try {
    if (config.type === KeyType.RSA_PSS) {
      return verifier.verify(
        {
          key,
          padding: config.padding,
          saltLength: config.saltLength,
        },
        signature
      );
    } else if (config.type === KeyType.RSA) {
      return verifier.verify(
        {
          key,
          padding: config.padding,
        },
        signature
      );
    } else {
      // EC signature needs to be converted from R||S to DER format
      const derSignature = rsToDer(signature, algorithm);
      return verifier.verify(key, derSignature);
    }
  } catch {
    return false;
  }
}

// ============================================================================
// EC SIGNATURE FORMAT CONVERSION
// ============================================================================

/**
 * @function getECSignatureSize
 * @description Gets the byte size for EC signatures based on the algorithm.
 * Used for converting between DER-encoded and R||S signature formats.
 * 
 * @param algorithm - The EC algorithm (ES256, ES384, or ES512)
 * @returns The signature size in bytes
 * 
 * @private
 */
function getECSignatureSize(algorithm: JTSAlgorithm): number {
  const size = EC_SIGNATURE_SIZES[algorithm as JTSAlgorithm.ES256 | JTSAlgorithm.ES384 | JTSAlgorithm.ES512];
  if (size === undefined) {
    throw new Error(`Not an EC algorithm: ${algorithm}`);
  }
  return size;
}

/**
 * @function derToRS
 * @description Converts a DER-encoded EC signature to R||S format as required by JWS.
 * JWS requires EC signatures in the concatenation of the R and S values,
 * while Node.js crypto produces DER-encoded signatures by default.
 * 
 * @param derSignature - The DER-encoded signature
 * @param algorithm - The EC algorithm used
 * @returns The R||S format signature
 * 
 * @private
 */
function derToRS(derSignature: Buffer, algorithm: JTSAlgorithm): Buffer {
  const size = getECSignatureSize(algorithm);
  
  // Parse DER structure
  let offset = 0;
  if (derSignature[offset++] !== 0x30) {
    throw new Error('Invalid DER signature');
  }
  
  // Skip length byte(s)
  let length = derSignature[offset++];
  if (length & 0x80) {
    const lenBytes = length & 0x7f;
    offset += lenBytes;
  }
  
  // Parse R
  if (derSignature[offset++] !== 0x02) {
    throw new Error('Invalid DER signature: expected INTEGER for R');
  }
  const rLen = derSignature[offset++];
  let rStart = offset;
  offset += rLen;
  
  // Parse S
  if (derSignature[offset++] !== 0x02) {
    throw new Error('Invalid DER signature: expected INTEGER for S');
  }
  const sLen = derSignature[offset++];
  let sStart = offset;
  
  // Extract R and S, handling leading zeros
  let r = derSignature.subarray(rStart, rStart + rLen);
  let s = derSignature.subarray(sStart, sStart + sLen);
  
  // Remove leading zeros if present
  while (r.length > size && r[0] === 0) {
    r = r.subarray(1);
  }
  while (s.length > size && s[0] === 0) {
    s = s.subarray(1);
  }
  
  // Pad with zeros if needed
  const result = Buffer.alloc(size * 2);
  r.copy(result, size - r.length);
  s.copy(result, size * 2 - s.length);
  
  return result;
}

/**
 * @function rsToDer
 * @description Converts an R||S format EC signature to DER encoding as required by Node.js crypto.
 * Node.js crypto expects DER-encoded signatures for verification, while JWS uses R||S format.
 * 
 * @param rsSignature - The R||S format signature
 * @param algorithm - The EC algorithm used
 * @returns The DER-encoded signature
 * 
 * @private
 */
function rsToDer(rsSignature: Buffer, algorithm: JTSAlgorithm): Buffer {
  const size = getECSignatureSize(algorithm);
  
  if (rsSignature.length !== size * 2) {
    throw new Error(`Invalid signature length for ${algorithm}`);
  }
  
  let r = rsSignature.subarray(0, size);
  let s = rsSignature.subarray(size);
  
  // Remove leading zeros
  while (r.length > 1 && r[0] === 0 && !(r[1] & 0x80)) {
    r = r.subarray(1);
  }
  while (s.length > 1 && s[0] === 0 && !(s[1] & 0x80)) {
    s = s.subarray(1);
  }
  
  // Add leading zero if high bit is set (to prevent negative interpretation)
  if (r[0] & 0x80) {
    r = Buffer.concat([Buffer.from([0]), r]);
  }
  if (s[0] & 0x80) {
    s = Buffer.concat([Buffer.from([0]), s]);
  }
  
  // Build DER structure
  const rLen = r.length;
  const sLen = s.length;
  const contentLen = 2 + rLen + 2 + sLen;
  
  // Calculate header size: for lengths > 127, use long form
  const lengthBytes = contentLen > 127 ? 2 : 1;
  const der = Buffer.alloc(1 + lengthBytes + contentLen);
  let offset = 0;
  
  der[offset++] = 0x30; // SEQUENCE
  if (contentLen > 127) {
    // Long form: 0x81 followed by length byte
    der[offset++] = 0x81;
    der[offset++] = contentLen;
  } else {
    der[offset++] = contentLen;
  }
  der[offset++] = 0x02; // INTEGER
  der[offset++] = rLen;
  r.copy(der, offset);
  offset += rLen;
  der[offset++] = 0x02; // INTEGER
  der[offset++] = sLen;
  s.copy(der, offset);
  
  return der;
}

// ============================================================================
// ENCRYPTION UTILITIES (FOR JTS-C CONFIDENTIALITY PROFILE)
// ============================================================================

/**
 * @function rsaEncrypt
 * @description Encrypts data using RSA-OAEP with SHA-256.
 * Used in JTS-C for encrypting Content Encryption Keys (CEKs).
 * 
 * @param data - The data to encrypt
 * @param publicKey - The RSA public key in PEM format
 * @returns The encrypted data
 * 
 * @example
 * ```typescript
 * import { generateKeyPair, rsaEncrypt } from '@engjts/auth/crypto';
 * 
 * const keyPair = await generateKeyPair('encryption-key', 'RS256');
 * const data = Buffer.from('Secret message');
 * const encrypted = rsaEncrypt(data, keyPair.publicKey);
 * ```
 */
export function rsaEncrypt(data: Buffer, publicKey: string | Buffer): Buffer {
  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    data
  );
}

/**
 * @function rsaDecrypt
 * @description Decrypts data using RSA-OAEP with SHA-256.
 * Used in JTS-C for decrypting Content Encryption Keys (CEKs).
 * 
 * @param data - The data to decrypt
 * @param privateKey - The RSA private key in PEM format
 * @returns The decrypted data
 * 
 * @example
 * ```typescript
 * import { generateKeyPair, rsaEncrypt, rsaDecrypt } from '@engjts/auth/crypto';
 * 
 * const keyPair = await generateKeyPair('encryption-key', 'RS256');
 * const data = Buffer.from('Secret message');
 * const encrypted = rsaEncrypt(data, keyPair.publicKey);
 * const decrypted = rsaDecrypt(encrypted, keyPair.privateKey);
 * console.log(decrypted.toString()); // Secret message
 * ```
 */
export function rsaDecrypt(data: Buffer, privateKey: string | Buffer): Buffer {
  return crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    data
  );
}

/**
 * @function generateCEK
 * @description Generates a cryptographically secure random Content Encryption Key.
 * Used in JTS-C for AES-GCM encryption of token payloads.
 * 
 * @param length - The key length in bytes (default: DEFAULT_CEK_LENGTH for AES-256)
 * @returns A random CEK
 * 
 * @example
 * ```typescript
 * const cek = generateCEK(); // 32-byte key for AES-256
 * const shortCek = generateCEK(16); // 16-byte key for AES-128
 * ```
 */
export function generateCEK(length: number = DEFAULT_CEK_LENGTH): Buffer {
  return crypto.randomBytes(length);
}

/**
 * @function generateIV
 * @description Generates a cryptographically secure random Initialization Vector.
 * Used in JTS-C for AES-GCM encryption of token payloads.
 * 
 * @param length - The IV length in bytes (default: DEFAULT_IV_LENGTH for AES-GCM)
 * @returns A random IV
 * 
 * @example
 * ```typescript
 * const iv = generateIV(); // 12-byte IV for AES-GCM
 * const longIV = generateIV(16); // 16-byte IV
 * ```
 */
export function generateIV(length: number = DEFAULT_IV_LENGTH): Buffer {
  return crypto.randomBytes(length);
}

/**
 * @function aesGcmEncrypt
 * @description Encrypts data using AES-GCM mode.
 * Used in JTS-C for encrypting token payloads with authenticated encryption.
 * 
 * @param plaintext - The data to encrypt
 * @param key - The AES encryption key
 * @param iv - The Initialization Vector
 * @param aad - Additional Authenticated Data (optional)
 * @returns Object containing ciphertext and authentication tag
 * 
 * @example
 * ```typescript
 * const plaintext = Buffer.from('Secret payload');
 * const key = generateCEK();
 * const iv = generateIV();
 * const result = aesGcmEncrypt(plaintext, key, iv);
 * console.log(result.ciphertext.toString('base64')); // Encrypted data
 * ```
 */
export function aesGcmEncrypt(
  plaintext: Buffer,
  key: Buffer,
  iv: Buffer,
  aad?: Buffer
): { ciphertext: Buffer; tag: Buffer } {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) {
    cipher.setAAD(aad);
  }
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, tag };
}

/**
 * @function aesGcmDecrypt
 * @description Decrypts data using AES-GCM mode.
 * Used in JTS-C for decrypting token payloads with authenticated decryption.
 * 
 * @param ciphertext - The encrypted data
 * @param key - The AES encryption key
 * @param iv - The Initialization Vector
 * @param tag - The authentication tag
 * @param aad - Additional Authenticated Data (optional)
 * @returns The decrypted plaintext
 * 
 * @example
 * ```typescript
 * // Assuming we have ciphertext, key, iv, and tag from encryption
 * const decrypted = aesGcmDecrypt(ciphertext, key, iv, tag);
 * console.log(decrypted.toString()); // Original plaintext
 * ```
 */
export function aesGcmDecrypt(
  ciphertext: Buffer,
  key: Buffer,
  iv: Buffer,
  tag: Buffer,
  aad?: Buffer
): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  if (aad) {
    decipher.setAAD(aad);
  }
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ============================================================================
// RANDOM STRING GENERATION AND HASHING UTILITIES
// ============================================================================

/**
 * @function generateRandomString
 * @description Generates a cryptographically secure random string using base64url encoding.
 * Used for creating unique identifiers and secure tokens.
 * 
 * @param length - The length of the random data in bytes (default: DEFAULT_RANDOM_STRING_LENGTH)
 * @returns A base64url-encoded random string
 * 
 * @example
 * ```typescript
 * const randomStr = generateRandomString(); // 32-byte random string
 * const shortStr = generateRandomString(16); // 16-byte random string
 * ```
 */
export function generateRandomString(length: number = DEFAULT_RANDOM_STRING_LENGTH): string {
  return base64urlEncode(crypto.randomBytes(length));
}

/**
 * @function generateTokenId
 * @description Generates a unique token identifier with 'tkn_' prefix.
 * Used in JTS-S and JTS-C profiles for token tracking and revocation.
 * 
 * @returns A unique token ID
 * 
 * @example
 * ```typescript
 * const tokenId = generateTokenId();
 * console.log(tokenId); // tkn_xxx...xxx (36 characters total)
 * ```
 */
export function generateTokenId(): string {
  return `${TOKEN_ID_PREFIX}${generateRandomString(24)}`;
}

/**
 * @function generateAnchorId
 * @description Generates a unique session/anchor identifier with 'aid_' prefix.
 * Used to reference sessions in the JTS session store.
 * 
 * @returns A unique anchor ID
 * 
 * @example
 * ```typescript
 * const anchorId = generateAnchorId();
 * console.log(anchorId); // aid_xxx...xxx (36 characters total)
 * ```
 */
export function generateAnchorId(): string {
  return `${ANCHOR_ID_PREFIX}${generateRandomString(24)}`;
}

/**
 * @function generateStateProof
 * @description Generates a StateProof token for session renewal and revocation.
 * Opaque, cryptographically secure random string with 'sp_' prefix.
 * 
 * @returns A StateProof token
 * 
 * @example
 * ```typescript
 * const stateProof = generateStateProof();
 * console.log(stateProof); // sp_xxx...xxx (67 characters total)
 * ```
 */
export function generateStateProof(): string {
  return `${STATE_PROOF_PREFIX}${generateRandomString(48)}`;
}

/**
 * @function sha256
 * @description Creates a SHA-256 hash of the input data.
 * Used for creating deterministic hashes for various purposes.
 * 
 * @param data - The data to hash (string or Buffer)
 * @returns The SHA-256 hash as a Buffer
 * 
 * @example
 * ```typescript
 * const hash = sha256('Hello, World!');
 * console.log(hash.toString('hex')); // a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
 * ```
 */
export function sha256(data: string | Buffer): Buffer {
  return crypto.createHash('sha256').update(data).digest();
}

/**
 * @function sha256Hex
 * @description Creates a SHA-256 hash of the input data and returns it as a hex string.
 * Convenience function for cases where hex representation is preferred.
 * 
 * @param data - The data to hash (string or Buffer)
 * @returns The SHA-256 hash as a hex string
 * 
 * @example
 * ```typescript
 * const hash = sha256Hex('Hello, World!');
 * console.log(hash); // a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
 * ```
 */
export function sha256Hex(data: string | Buffer): string {
  return sha256(data).toString('hex');
}

/**
 * @function createDeviceFingerprint
 * @description Creates a device fingerprint hash from browser/device characteristics.
 * Used for device binding in JTS-S and JTS-C profiles to prevent token misuse.
 * 
 * @param components - Object containing device characteristics
 * @returns A device fingerprint string in the format 'sha256:hash'
 * 
 * @example
 * ```typescript
 * const fingerprint = createDeviceFingerprint({
 *   userAgent: navigator.userAgent,
 *   acceptLanguage: navigator.language,
 *   timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
 * });
 * console.log(fingerprint); // sha256:xxxx...xxxx (39 characters total)
 * ```
 */
export function createDeviceFingerprint(components: {
  userAgent?: string;
  acceptLanguage?: string;
  screenResolution?: string;
  timezone?: string;
  [key: string]: string | undefined;
}): string {
  const data = Object.entries(components)
    .filter(([, v]) => v)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}:${v}`)
    .join('|');
  return `${DEVICE_FINGERPRINT_PREFIX}${sha256Hex(data).substring(0, DEVICE_FINGERPRINT_HASH_LENGTH)}`;
}

// ============================================================================
// JSON WEB KEY SET (JWKS) UTILITIES
// ============================================================================

/**
 * @function pemToJwk
 * @description Converts a PEM-formatted public key to JWK (JSON Web Key) format.
 * Used for distributing public keys to resource servers via JWKS endpoints.
 * 
 * @param pem - The PEM-formatted public key
 * @param kid - The Key ID to assign to the JWK
 * @param algorithm - The JTS algorithm associated with the key
 * @returns A JWK representation of the public key
 * 
 * @example
 * ```typescript
 * import { generateKeyPair, pemToJwk, JTSAlgorithm } from '@engjts/auth/crypto';
 * 
 * const keyPair = await generateKeyPair('my-key', JTSAlgorithm.RS256);
 * const jwk = pemToJwk(keyPair.publicKey, 'my-key', JTSAlgorithm.RS256);
 * console.log(jwk); // { kty: 'RSA', kid: 'my-key', use: 'sig', alg: 'RS256', ... }
 * ```
 */
export function pemToJwk(
  pem: string | Buffer,
  kid: string,
  algorithm: JTSAlgorithm
): JWKSKey {
  const key = crypto.createPublicKey(pem);
  const exported = key.export({ format: 'jwk' });
  
  const config = ALGORITHM_CONFIG[algorithm];
  
  const jwk: JWKSKey = {
    kty: config.type === KeyType.EC ? 'EC' : 'RSA',
    kid,
    use: 'sig',
    alg: algorithm,
  };

  if (config.type === KeyType.EC) {
    jwk.crv = curveToJwkCurve(config.curve!);
    jwk.x = exported.x;
    jwk.y = exported.y;
  } else {
    jwk.n = exported.n;
    jwk.e = exported.e;
  }

  return jwk;
}

/**
 * @function keyPairToJwks
 * @description Converts an array of JTS key pairs to JWKS (JSON Web Key Set) format.
 * Used for creating JWKS endpoints that distribute multiple public keys.
 * 
 * @param keyPairs - Array of JTS key pairs
 * @returns A JWKS object containing all public keys
 * 
 * @example
 * ```typescript
 * import { generateKeyPair, keyPairToJwks } from '@engjts/auth/crypto';
 * 
 * const currentKey = await generateKeyPair('current-key', 'RS256');
 * const previousKey = await generateKeyPair('previous-key', 'RS256');
 * const jwks = keyPairToJwks([currentKey, previousKey]);
 * console.log(jwks); // { keys: [...] }
 * ```
 */
export function keyPairToJwks(keyPairs: JTSKeyPair[]): JWKS {
  return {
    keys: keyPairs.map(kp => {
      const jwk = pemToJwk(kp.publicKey, kp.kid, kp.algorithm);
      if (kp.expiresAt) {
        jwk.exp = kp.expiresAt;
      }
      return jwk;
    }),
  };
}

/**
 * @constant CURVE_TO_JWK_MAPPING
 * @description Maps OpenSSL elliptic curve names to JWK curve names.
 * 
 * @private
 */
const CURVE_TO_JWK_MAPPING: Readonly<Record<ECCurve, JWKCurve>> = {
  [ECCurve.P256]: JWKCurve.P256,
  [ECCurve.P384]: JWKCurve.P384,
  [ECCurve.P521]: JWKCurve.P521,
} as const;

/**
 * @function curveToJwkCurve
 * @description Maps OpenSSL elliptic curve names to JWK curve names.
 * 
 * @param opensslCurve - The OpenSSL curve name
 * @returns The corresponding JWK curve name
 * 
 * @private
 */
function curveToJwkCurve(opensslCurve: ECCurve): JWKCurve {
  return CURVE_TO_JWK_MAPPING[opensslCurve] || opensslCurve;
}

/**
 * @function jwkToPem
 * @description Converts a JWK (JSON Web Key) to PEM format.
 * Used by resource servers to import public keys from JWKS endpoints.
 * 
 * @param jwk - The JWK to convert
 * @returns The PEM-formatted public key
 * 
 * @example
 * ```typescript
 * // Assuming we have a JWK from a JWKS endpoint
 * const pem = jwkToPem(jwk);
 * console.log(pem); // -----BEGIN PUBLIC KEY-----...
 * ```
 */
export function jwkToPem(jwk: JWKSKey): string {
  const key = crypto.createPublicKey({ key: jwk as unknown as crypto.JsonWebKey, format: 'jwk' });
  return key.export({ type: 'spki', format: 'pem' }) as string;
}
