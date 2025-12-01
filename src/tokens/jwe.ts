/**
 * @engjts/auth - JWE Handler for JTS-C Profile
 * Create and decrypt encrypted BearerPass tokens
 */

import {
  base64urlEncode,
  base64urlDecode,
  encodeJSON,
  decodeJSON,
  rsaEncrypt,
  rsaDecrypt,
  generateCEK,
  generateIV,
  aesGcmEncrypt,
  aesGcmDecrypt,
} from '../crypto';
import { createBearerPass, CreateBearerPassOptions, verifyBearerPass, VerifyBearerPassOptions } from './bearer-pass';
import { JTSCHeader, JWEAlgorithm, JWEEncryption, JTSKeyPair, JTSError, VerificationResult } from '../types';

// ============================================================================
// JWE CREATION (Signed-then-Encrypted)
// ============================================================================

export interface CreateJWEOptions extends Omit<CreateBearerPassOptions, 'profile'> {
  /** Encryption algorithm */
  encryptionAlgorithm?: JWEAlgorithm;
  /** Content encryption */
  contentEncryption?: JWEEncryption;
  /** Resource Server's public key for encryption */
  encryptionKey: {
    kid: string;
    publicKey: string | Buffer;
  };
}

/**
 * Create an encrypted BearerPass (JWE) for JTS-C profile
 * Uses signed-then-encrypted approach
 */
export function createEncryptedBearerPass(options: CreateJWEOptions): string {
  const {
    encryptionAlgorithm = 'RSA-OAEP-256',
    contentEncryption = 'A256GCM',
    encryptionKey,
    ...bearerPassOptions
  } = options;

  // 1. Create the JWS (BearerPass) first
  const jws = createBearerPass({
    ...bearerPassOptions,
    profile: 'JTS-C/v1',
  });

  // 2. Build JWE header
  const jweHeader: JTSCHeader = {
    alg: encryptionAlgorithm,
    enc: contentEncryption,
    typ: 'JTS-C/v1',
    kid: encryptionKey.kid,
  };

  // 3. Generate Content Encryption Key (CEK)
  const cek = generateCEK(32); // 256 bits for A256GCM

  // 4. Encrypt CEK with recipient's public key
  const encryptedKey = rsaEncrypt(cek, encryptionKey.publicKey);

  // 5. Generate IV
  const iv = generateIV(12); // 96 bits for GCM

  // 6. Encode header for AAD
  const headerEncoded = encodeJSON(jweHeader);
  const aad = Buffer.from(headerEncoded, 'ascii');

  // 7. Encrypt JWS payload
  const plaintext = Buffer.from(jws, 'utf8');
  const { ciphertext, tag } = aesGcmEncrypt(plaintext, cek, iv, aad);

  // 8. Assemble JWE token
  // Format: BASE64URL(Header).BASE64URL(EncryptedKey).BASE64URL(IV).BASE64URL(Ciphertext).BASE64URL(Tag)
  const parts = [
    headerEncoded,
    base64urlEncode(encryptedKey),
    base64urlEncode(iv),
    base64urlEncode(ciphertext),
    base64urlEncode(tag),
  ];

  return parts.join('.');
}

// ============================================================================
// JWE DECRYPTION (Decrypted-then-Verified)
// ============================================================================

export interface DecryptJWEOptions {
  /** The JWE token */
  token: string;
  /** Private key for decryption */
  decryptionKey: {
    kid: string;
    privateKey: string | Buffer;
  };
}

export interface DecryptJWEResult {
  jws: string;
  header: JTSCHeader;
}

/**
 * Decrypt a JWE token to get the inner JWS
 */
export function decryptJWE(options: DecryptJWEOptions): DecryptJWEResult {
  const { token, decryptionKey } = options;

  // 1. Split token into parts
  const parts = token.split('.');
  if (parts.length !== 5) {
    throw new JTSError('JTS-400-01', 'JWE must have 5 parts');
  }

  const [headerEncoded, encryptedKeyEncoded, ivEncoded, ciphertextEncoded, tagEncoded] = parts;

  // 2. Decode header
  let header: JTSCHeader;
  try {
    header = decodeJSON<JTSCHeader>(headerEncoded);
  } catch {
    throw new JTSError('JTS-400-01', 'Invalid JWE header');
  }

  // 3. Verify header
  if (header.typ !== 'JTS-C/v1') {
    throw new JTSError('JTS-400-01', 'Expected JTS-C/v1 token type');
  }

  if (header.kid !== decryptionKey.kid) {
    throw new JTSError('JTS-500-01', `Key ${header.kid} not available, expected ${decryptionKey.kid}`);
  }

  // 4. Decode components
  const encryptedKey = base64urlDecode(encryptedKeyEncoded);
  const iv = base64urlDecode(ivEncoded);
  const ciphertext = base64urlDecode(ciphertextEncoded);
  const tag = base64urlDecode(tagEncoded);

  // 5. Decrypt CEK
  let cek: Buffer;
  try {
    cek = rsaDecrypt(encryptedKey, decryptionKey.privateKey);
  } catch {
    throw new JTSError('JTS-401-02', 'Failed to decrypt content encryption key');
  }

  // 6. Decrypt content
  const aad = Buffer.from(headerEncoded, 'ascii');
  let plaintext: Buffer;
  try {
    plaintext = aesGcmDecrypt(ciphertext, cek, iv, tag, aad);
  } catch {
    throw new JTSError('JTS-401-02', 'Failed to decrypt token content');
  }

  // 7. Return decrypted JWS
  return {
    jws: plaintext.toString('utf8'),
    header,
  };
}

// ============================================================================
// FULL JWE VERIFICATION
// ============================================================================

export interface VerifyEncryptedBearerPassOptions extends Omit<VerifyBearerPassOptions, 'token'> {
  /** The JWE token */
  token: string;
  /** Private key for decryption */
  decryptionKey: {
    kid: string;
    privateKey: string | Buffer;
  };
}

/**
 * Decrypt and verify a JTS-C BearerPass
 * Performs decrypted-then-verified flow
 */
export function verifyEncryptedBearerPass(options: VerifyEncryptedBearerPassOptions): VerificationResult {
  const { token, decryptionKey, ...verifyOptions } = options;

  try {
    // 1. Decrypt JWE to get JWS
    const { jws } = decryptJWE({ token, decryptionKey });

    // 2. Verify the JWS
    const result = verifyBearerPass({
      token: jws,
      ...verifyOptions,
    });

    return result;

  } catch (error) {
    if (error instanceof JTSError) {
      return { valid: false, error };
    }
    return {
      valid: false,
      error: new JTSError('JTS-400-01', 'Failed to process encrypted token'),
    };
  }
}

/**
 * Check if a token is JWE (encrypted) format
 */
export function isEncryptedToken(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 5) return false;
  
  try {
    const header = decodeJSON<{ typ?: string }>(parts[0]);
    return header.typ === 'JTS-C/v1';
  } catch {
    return false;
  }
}
