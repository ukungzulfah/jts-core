/**
 * @engjts/auth - Crypto Utilities
 * Native Node.js crypto implementation for JTS
 */

import * as crypto from 'crypto';
import type { JTSAlgorithm, JTSKeyPair, JWKSKey, JWKS } from '../types';

// ============================================================================
// CONSTANTS
// ============================================================================

const ALGORITHM_CONFIG: Record<JTSAlgorithm, {
  type: 'rsa' | 'ec' | 'rsa-pss';
  hash: string;
  curve?: string;
  padding?: number;
  saltLength?: number;
}> = {
  RS256: { type: 'rsa', hash: 'sha256', padding: crypto.constants.RSA_PKCS1_PADDING },
  RS384: { type: 'rsa', hash: 'sha384', padding: crypto.constants.RSA_PKCS1_PADDING },
  RS512: { type: 'rsa', hash: 'sha512', padding: crypto.constants.RSA_PKCS1_PADDING },
  ES256: { type: 'ec', hash: 'sha256', curve: 'prime256v1' },
  ES384: { type: 'ec', hash: 'sha384', curve: 'secp384r1' },
  ES512: { type: 'ec', hash: 'sha512', curve: 'secp521r1' },
  PS256: { type: 'rsa-pss', hash: 'sha256', padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
  PS384: { type: 'rsa-pss', hash: 'sha384', padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 },
  PS512: { type: 'rsa-pss', hash: 'sha512', padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 },
};

// ============================================================================
// BASE64URL UTILITIES
// ============================================================================

/**
 * Encode buffer to base64url
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
 * Decode base64url to buffer
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
 * Encode object to base64url JSON
 */
export function encodeJSON(obj: unknown): string {
  return base64urlEncode(JSON.stringify(obj));
}

/**
 * Decode base64url JSON to object
 */
export function decodeJSON<T = unknown>(str: string): T {
  return JSON.parse(base64urlDecode(str).toString('utf8'));
}

// ============================================================================
// KEY GENERATION
// ============================================================================

/**
 * Generate a new RSA key pair
 */
export async function generateRSAKeyPair(
  kid: string,
  algorithm: 'RS256' | 'RS384' | 'RS512' | 'PS256' | 'PS384' | 'PS512' = 'RS256',
  modulusLength: number = 2048
): Promise<JTSKeyPair> {
  return new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      'rsa',
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
 * Generate a new EC key pair
 */
export async function generateECKeyPair(
  kid: string,
  algorithm: 'ES256' | 'ES384' | 'ES512' = 'ES256'
): Promise<JTSKeyPair> {
  const config = ALGORITHM_CONFIG[algorithm];
  if (config.type !== 'ec' || !config.curve) {
    throw new Error(`Invalid EC algorithm: ${algorithm}`);
  }

  return new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      'ec',
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
 * Generate a key pair based on algorithm
 */
export async function generateKeyPair(
  kid: string,
  algorithm: JTSAlgorithm = 'RS256'
): Promise<JTSKeyPair> {
  const config = ALGORITHM_CONFIG[algorithm];
  if (config.type === 'ec') {
    return generateECKeyPair(kid, algorithm as 'ES256' | 'ES384' | 'ES512');
  } else {
    return generateRSAKeyPair(kid, algorithm as 'RS256' | 'RS384' | 'RS512' | 'PS256' | 'PS384' | 'PS512');
  }
}

// ============================================================================
// SIGNING
// ============================================================================

/**
 * Sign data with private key
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

  if (config.type === 'rsa-pss') {
    return signer.sign({
      key,
      padding: config.padding,
      saltLength: config.saltLength,
    });
  } else if (config.type === 'rsa') {
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
 * Verify signature with public key
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
    if (config.type === 'rsa-pss') {
      return verifier.verify(
        {
          key,
          padding: config.padding,
          saltLength: config.saltLength,
        },
        signature
      );
    } else if (config.type === 'rsa') {
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
 * Get the byte size for EC signatures based on algorithm
 */
function getECSignatureSize(algorithm: JTSAlgorithm): number {
  switch (algorithm) {
    case 'ES256': return 32;
    case 'ES384': return 48;
    case 'ES512': return 66;
    default: throw new Error(`Not an EC algorithm: ${algorithm}`);
  }
}

/**
 * Convert DER-encoded signature to R||S format (for JWT)
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
 * Convert R||S format to DER-encoded signature
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
// ENCRYPTION (for JTS-C)
// ============================================================================

/**
 * Encrypt data using RSA-OAEP
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
 * Decrypt data using RSA-OAEP
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
 * Generate a random content encryption key
 */
export function generateCEK(length: number = 32): Buffer {
  return crypto.randomBytes(length);
}

/**
 * Generate a random IV
 */
export function generateIV(length: number = 12): Buffer {
  return crypto.randomBytes(length);
}

/**
 * AES-GCM encryption
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
 * AES-GCM decryption
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
// RANDOM & HASH UTILITIES
// ============================================================================

/**
 * Generate a cryptographically secure random string
 */
export function generateRandomString(length: number = 32): string {
  return base64urlEncode(crypto.randomBytes(length));
}

/**
 * Generate a unique token ID
 */
export function generateTokenId(): string {
  return `tkn_${generateRandomString(24)}`;
}

/**
 * Generate a unique session/anchor ID
 */
export function generateAnchorId(): string {
  return `aid_${generateRandomString(24)}`;
}

/**
 * Generate a StateProof token (opaque, random)
 */
export function generateStateProof(): string {
  return `sp_${generateRandomString(48)}`;
}

/**
 * Create SHA-256 hash
 */
export function sha256(data: string | Buffer): Buffer {
  return crypto.createHash('sha256').update(data).digest();
}

/**
 * Create SHA-256 hash as hex string
 */
export function sha256Hex(data: string | Buffer): string {
  return sha256(data).toString('hex');
}

/**
 * Create device fingerprint hash
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
  return `sha256:${sha256Hex(data).substring(0, 32)}`;
}

// ============================================================================
// JWKS UTILITIES
// ============================================================================

/**
 * Convert PEM public key to JWK format
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
    kty: config.type === 'ec' ? 'EC' : 'RSA',
    kid,
    use: 'sig',
    alg: algorithm,
  };

  if (config.type === 'ec') {
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
 * Convert key pair to JWKS format
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
 * Convert OpenSSL curve name to JWK curve name
 */
function curveToJwkCurve(opensslCurve: string): string {
  const mapping: Record<string, string> = {
    'prime256v1': 'P-256',
    'secp384r1': 'P-384',
    'secp521r1': 'P-521',
  };
  return mapping[opensslCurve] || opensslCurve;
}

/**
 * Import JWK to crypto key
 */
export function jwkToPem(jwk: JWKSKey): string {
  const key = crypto.createPublicKey({ key: jwk as unknown as crypto.JsonWebKey, format: 'jwk' });
  return key.export({ type: 'spki', format: 'pem' }) as string;
}
