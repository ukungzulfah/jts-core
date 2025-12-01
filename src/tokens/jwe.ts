/**
 * @fileoverview JWE Encryption for JTS-C Profile
 * @module @engjts/auth/tokens/jwe
 * @description Functions for creating and decrypting JWE-encrypted BearerPass tokens for the JTS-C confidentiality profile.
 * 
 * Implements the signed-then-encrypted approach where a BearerPass token is first signed as a JWS,
 * then encrypted as a JWE to provide payload confidentiality.
 * 
 * @example
 * ```typescript
 * // Creating an encrypted token
 * import { createEncryptedBearerPass } from '@engjts/auth/tokens/jwe';
 * 
 * const encryptedToken = createEncryptedBearerPass({
 *   prn: 'user123',
 *   aid: 'session456',
 *   kid: 'signing-key',
 *   privateKey: '-----BEGIN PRIVATE KEY-----...',
 *   encryptionKey: {
 *     kid: 'encryption-key',
 *     publicKey: '-----BEGIN PUBLIC KEY-----...'
 *   }
 * });
 * 
 * // Decrypting and verifying a token
 * import { verifyEncryptedBearerPass } from '@engjts/auth/tokens/jwe';
 * 
 * const result = verifyEncryptedBearerPass({
 *   token: encryptedToken,
 *   decryptionKey: {
 *     kid: 'encryption-key',
 *     privateKey: '-----BEGIN PRIVATE KEY-----...'
 *   },
 *   publicKeys: new Map([['signing-key', signingKeyPair]])
 * });
 * ```
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
import { JTSCHeader, JWEAlgorithm, JWEEncryption, JTSKeyPair, JTSError, JTS_ERRORS, JTS_ERROR_MESSAGES, JTS_ERROR_MESSAGE_HELPERS, JTS_PROFILES, VerificationResult } from '../types';

// ============================================================================
// JWE CREATION OPTIONS
// ============================================================================

/**
 * @interface CreateJWEOptions
 * @description Options for creating an encrypted BearerPass token (JWE).
 * Extends CreateBearerPassOptions but omits the profile field since JWE is always JTS-C.
 */
export interface CreateJWEOptions extends Omit<CreateBearerPassOptions, 'profile'> {
  /**
   * @property {JWEAlgorithm} [encryptionAlgorithm='RSA-OAEP-256'] - Encryption algorithm
   * Algorithm used to encrypt the Content Encryption Key (CEK).
   */
  encryptionAlgorithm?: JWEAlgorithm;
  
  /**
   * @property {JWEEncryption} [contentEncryption='A256GCM'] - Content encryption
   * Algorithm used to encrypt the JWS payload.
   */
  contentEncryption?: JWEEncryption;
  
  /**
   * @property {Object} encryptionKey - Resource Server's public key for encryption
   * The public key used to encrypt the Content Encryption Key (CEK).
   */
  encryptionKey: {
    /**
     * @property {string} kid - Key ID
     * Identifier for the encryption key.
     */
    kid: string;
    
    /**
     * @property {string|Buffer} publicKey - Public key for encryption
     * The public key in PEM format used to encrypt the CEK.
     */
    publicKey: string | Buffer;
  };
}

/**
 * @function createEncryptedBearerPass
 * @description Creates an encrypted BearerPass token (JWE) for the JTS-C confidentiality profile.
 * 
 * Implements the signed-then-encrypted approach:
 * 1. Creates a signed BearerPass token (JWS) with JTS-C profile
 * 2. Generates a Content Encryption Key (CEK)
 * 3. Encrypts the CEK with the recipient's public key
 * 4. Encrypts the JWS payload with the CEK
 * 5. Assembles all components into a compact JWE format
 * 
 * @param options - Configuration options for encrypted token creation
 * @returns An encrypted BearerPass token as a compact JWE string
 * 
 * @example
 * ```typescript
 * const encryptedToken = createEncryptedBearerPass({
 *   prn: 'user123',
 *   aid: 'session456',
 *   kid: 'signing-key',
 *   privateKey: '-----BEGIN PRIVATE KEY-----...',
 *   encryptionKey: {
 *     kid: 'encryption-key',
 *     publicKey: '-----BEGIN PUBLIC KEY-----...'
 *   }
 * });
 * 
 * console.log(encryptedToken); // eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwidHlwIjoiSlRTLUMvdjEiLCJraWQiOiJlbmNyeXB0aW9uLWtleSJ9.encrypted_key.iv.ciphertext.tag
 * ```
 * 
 * @throws {Error} If an invalid algorithm is specified
 */
export function createEncryptedBearerPass(options: CreateJWEOptions): string {
  const {
    encryptionAlgorithm = JWEAlgorithm.RSA_OAEP_256,
    contentEncryption = JWEEncryption.A256GCM,
    encryptionKey,
    ...bearerPassOptions
  } = options;

  const jws = createBearerPass({
    ...bearerPassOptions,
    profile: JTS_PROFILES.CONFIDENTIAL,
  });

  const jweHeader: JTSCHeader = {
    alg: encryptionAlgorithm,
    enc: contentEncryption,
    typ: JTS_PROFILES.CONFIDENTIAL,
    kid: encryptionKey.kid,
  };

  const cek = generateCEK(32); // 256 bits for A256GCM

  const encryptedKey = rsaEncrypt(cek, encryptionKey.publicKey);

  const iv = generateIV(12); // 96 bits for GCM

  const headerEncoded = encodeJSON(jweHeader);
  const aad = Buffer.from(headerEncoded, 'ascii');

  const plaintext = Buffer.from(jws, 'utf8');
  const { ciphertext, tag } = aesGcmEncrypt(plaintext, cek, iv, aad);

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
// JWE DECRYPTION OPTIONS AND RESULT
// ============================================================================

/**
 * @interface DecryptJWEOptions
 * @description Options for decrypting a JWE token.
 */
export interface DecryptJWEOptions {
  /**
   * @property {string} token - The JWE token
   * The compact JWE string to be decrypted.
   */
  token: string;
  
  /**
   * @property {Object} decryptionKey - Private key for decryption
   * The private key used to decrypt the Content Encryption Key (CEK).
   */
  decryptionKey: {
    /**
     * @property {string} kid - Key ID
     * Identifier for the decryption key.
     */
    kid: string;
    
    /**
     * @property {string|Buffer} privateKey - Private key for decryption
     * The private key in PEM format used to decrypt the CEK.
     */
    privateKey: string | Buffer;
  };
}

/**
 * @interface DecryptJWEResult
 * @description Result of decrypting a JWE token.
 */
export interface DecryptJWEResult {
  /**
   * @property {string} jws - The decrypted JWS token
   * The inner BearerPass token that was encrypted.
   */
  jws: string;
  
  /**
   * @property {JTSCHeader} header - The JWE header
   * The header of the decrypted JWE token.
   */
  header: JTSCHeader;
}

/**
 * @function decryptJWE
 * @description Decrypts a JWE token to extract the inner JWS.
 * 
 * Performs the following steps:
 * 1. Parses and validates the JWE structure
 * 2. Decrypts the Content Encryption Key (CEK) using the provided private key
 * 3. Decrypts the JWS payload using the CEK
 * 4. Returns the decrypted JWS and JWE header
 * 
 * @param options - Decryption options including the token and decryption key
 * @returns The decrypted JWS token and JWE header
 * 
 * @example
 * ```typescript
 * const result = decryptJWE({
 *   token: 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwidHlwIjoiSlRTLUMvdjEiLCJraWQiOiJlbmNyeXB0aW9uLWtleSJ9.encrypted_key.iv.ciphertext.tag',
 *   decryptionKey: {
 *     kid: 'encryption-key',
 *     privateKey: '-----BEGIN PRIVATE KEY-----...'
 *   }
 * });
 * 
 * console.log(result.jws); // The decrypted BearerPass token
 * console.log(result.header.alg); // RSA-OAEP-256
 * ```
 * 
 * @throws {JTSError} If decryption fails or token format is invalid
 */
export function decryptJWE(options: DecryptJWEOptions): DecryptJWEResult {
  const { token, decryptionKey } = options;

  const parts = token.split('.');
  if (parts.length !== 5) {
    throw new JTSError(JTS_ERRORS.MALFORMED_TOKEN, JTS_ERROR_MESSAGES.JWE_MUST_HAVE_5_PARTS);
  }

  const [headerEncoded, encryptedKeyEncoded, ivEncoded, ciphertextEncoded, tagEncoded] = parts;

  let header: JTSCHeader;
  try {
    header = decodeJSON<JTSCHeader>(headerEncoded);
  } catch {
    throw new JTSError(JTS_ERRORS.MALFORMED_TOKEN, JTS_ERROR_MESSAGES.INVALID_JWE_HEADER);
  }

  if (header.typ !== JTS_PROFILES.CONFIDENTIAL) {
    throw new JTSError(JTS_ERRORS.MALFORMED_TOKEN, JTS_ERROR_MESSAGES.EXPECTED_JTS_C_TOKEN_TYPE);
  }

  if (header.kid !== decryptionKey.kid) {
    throw new JTSError(JTS_ERRORS.KEY_UNAVAILABLE, JTS_ERROR_MESSAGE_HELPERS.keyMismatch(header.kid, decryptionKey.kid));
  }

  const encryptedKey = base64urlDecode(encryptedKeyEncoded);
  const iv = base64urlDecode(ivEncoded);
  const ciphertext = base64urlDecode(ciphertextEncoded);
  const tag = base64urlDecode(tagEncoded);

  let cek: Buffer;
  try {
    cek = rsaDecrypt(encryptedKey, decryptionKey.privateKey);
  } catch {
    throw new JTSError(JTS_ERRORS.SIGNATURE_INVALID, JTS_ERROR_MESSAGES.FAILED_TO_DECRYPT_CONTENT_ENCRYPTION_KEY);
  }

  const aad = Buffer.from(headerEncoded, 'ascii');
  let plaintext: Buffer;
  try {
    plaintext = aesGcmDecrypt(ciphertext, cek, iv, tag, aad);
  } catch {
    throw new JTSError(JTS_ERRORS.SIGNATURE_INVALID, JTS_ERROR_MESSAGES.FAILED_TO_DECRYPT_TOKEN_CONTENT);
  }

  return {
    jws: plaintext.toString('utf8'),
    header,
  };
}

// ============================================================================
// FULL JWE VERIFICATION OPTIONS
// ============================================================================

/**
 * @interface VerifyEncryptedBearerPassOptions
 * @description Options for decrypting and verifying a JTS-C BearerPass token.
 * Extends VerifyBearerPassOptions but replaces the token field with a JWE token
 * and adds decryption key information.
 */
export interface VerifyEncryptedBearerPassOptions extends Omit<VerifyBearerPassOptions, 'token'> {
  /**
   * @property {string} token - The JWE token
   * The encrypted BearerPass token to decrypt and verify.
   */
  token: string;
  
  /**
   * @property {Object} decryptionKey - Private key for decryption
   * The private key used to decrypt the Content Encryption Key (CEK).
   */
  decryptionKey: {
    /**
     * @property {string} kid - Key ID
     * Identifier for the decryption key.
     */
    kid: string;
    
    /**
     * @property {string|Buffer} privateKey - Private key for decryption
     * The private key in PEM format used to decrypt the CEK.
     */
    privateKey: string | Buffer;
  };
}

/**
 * @function verifyEncryptedBearerPass
 * @description Decrypts and verifies a JTS-C BearerPass token.
 * 
 * Performs the decrypted-then-verified flow:
 * 1. Decrypts the JWE token to extract the inner JWS
 * 2. Verifies the JWS signature and claims
 * 
 * @param options - Verification options including the encrypted token and decryption key
 * @returns Verification result with payload if valid, error if invalid
 * 
 * @example
 * ```typescript
 * const result = verifyEncryptedBearerPass({
 *   token: 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwidHlwIjoiSlRTLUMvdjEiLCJraWQiOiJlbmNyeXB0aW9uLWtleSJ9.encrypted_key.iv.ciphertext.tag',
 *   decryptionKey: {
 *     kid: 'encryption-key',
 *     privateKey: '-----BEGIN PRIVATE KEY-----...'
 *   },
 *   publicKeys: new Map([['signing-key', signingKeyPair]]),
 *   audience: 'https://api.example.com'
 * });
 * 
 * if (result.valid) {
 *   console.log('Token is valid for user:', result.payload!.prn);
 * } else {
 *   console.log('Token verification failed:', result.error!.message);
 * }
 * ```
 */
export function verifyEncryptedBearerPass(options: VerifyEncryptedBearerPassOptions): VerificationResult {
  const { token, decryptionKey, ...verifyOptions } = options;

  try {
    const { jws } = decryptJWE({ token, decryptionKey });

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
      error: new JTSError(JTS_ERRORS.MALFORMED_TOKEN, JTS_ERROR_MESSAGES.FAILED_TO_PROCESS_ENCRYPTED_TOKEN),
    };
  }
}

/**
 * Determines if a given token is an encrypted JWE token.
 * 
 * This function checks if the provided token follows the JWE Compact Serialization format
 * and has the correct type identifier for confidential JTS tokens.
 * 
 * @param token - The token string to check
 * @returns True if the token is an encrypted JWE token, false otherwise
 * 
 * @remarks
 * The function validates:
 * 1. The token has exactly 5 parts separated by dots (JWE Compact format)
 * 2. The header can be decoded as JSON
 * 3. The token type in the header matches JTS_CONFIDENTIAL profile
 * 
 * @example
 * ```typescript
 * const token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..3L9aq4DQV9LVFdDc.sN3Cz6zROxnkKp0D.DF9_vE1-7EG8hKr5wdIB3g";
 * if (isEncryptedToken(token)) {
 *   // Handle encrypted token
 * }
 * ```
 */
export function isEncryptedToken(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 5) return false;
  
  try {
    const header = decodeJSON<{ typ?: string }>(parts[0]);
    return header.typ === JTS_PROFILES.CONFIDENTIAL;
  } catch {
    return false;
  }
}
