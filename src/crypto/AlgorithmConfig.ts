// ============================================================================
// CRYPTOGRAPHIC CONSTANTS
// ============================================================================

import { JTSAlgorithm } from "../types";
import * as crypto from 'crypto';

/**
 * @enum KeyType
 * @description Supported cryptographic key types.
 */
export enum KeyType {
  RSA = 'rsa',
  EC = 'ec',
  RSA_PSS = 'rsa-pss',
}

/**
 * @enum HashAlgorithm
 * @description Supported hash algorithms for cryptographic operations.
 */
export enum HashAlgorithm {
  SHA256 = 'sha256',
  SHA384 = 'sha384',
  SHA512 = 'sha512',
}

/**
 * @enum ECCurve
 * @description Supported elliptic curves for EC key generation.
 */
export enum ECCurve {
  P256 = 'prime256v1',
  P384 = 'secp384r1',
  P521 = 'secp521r1',
}

/**
 * @enum JWKCurve
 * @description JWK curve names corresponding to OpenSSL curve names.
 */
export enum JWKCurve {
  P256 = 'P-256',
  P384 = 'P-384',
  P521 = 'P-521',
}

/**
 * @constant EC_SIGNATURE_SIZES
 * @description Byte sizes for EC signatures based on the curve.
 */
export const EC_SIGNATURE_SIZES: Readonly<Record<JTSAlgorithm.ES256 | JTSAlgorithm.ES384 | JTSAlgorithm.ES512, number>> = {
  [JTSAlgorithm.ES256]: 32,
  [JTSAlgorithm.ES384]: 48,
  [JTSAlgorithm.ES512]: 66,
} as const;

/**
 * @constant SALT_LENGTHS
 * @description Salt lengths for RSA-PSS algorithms.
 */
export const SALT_LENGTHS: Readonly<Record<JTSAlgorithm.PS256 | JTSAlgorithm.PS384 | JTSAlgorithm.PS512, number>> = {
  [JTSAlgorithm.PS256]: 32,
  [JTSAlgorithm.PS384]: 48,
  [JTSAlgorithm.PS512]: 64,
} as const;

/**
 * @constant DEFAULT_RSA_MODULUS_LENGTH
 * @description Default RSA key size in bits.
 */
export const DEFAULT_RSA_MODULUS_LENGTH = 2048;

/**
 * @constant DEFAULT_CEK_LENGTH
 * @description Default Content Encryption Key length in bytes (for AES-256).
 */
export const DEFAULT_CEK_LENGTH = 32;

/**
 * @constant DEFAULT_IV_LENGTH
 * @description Default Initialization Vector length in bytes (for AES-GCM).
 */
export const DEFAULT_IV_LENGTH = 12;

/**
 * @constant DEFAULT_RANDOM_STRING_LENGTH
 * @description Default length for random string generation in bytes.
 */
export const DEFAULT_RANDOM_STRING_LENGTH = 32;

/**
 * @constant TOKEN_ID_PREFIX
 * @description Prefix for token identifiers.
 */
export const TOKEN_ID_PREFIX = 'tkn_';

/**
 * @constant ANCHOR_ID_PREFIX
 * @description Prefix for anchor/session identifiers.
 */
export const ANCHOR_ID_PREFIX = 'aid_';

/**
 * @constant STATE_PROOF_PREFIX
 * @description Prefix for StateProof tokens.
 */
export const STATE_PROOF_PREFIX = 'sp_';

/**
 * @constant DEVICE_FINGERPRINT_PREFIX
 * @description Prefix for device fingerprint hashes.
 */
export const DEVICE_FINGERPRINT_PREFIX = 'sha256:';

/**
 * @constant DEVICE_FINGERPRINT_HASH_LENGTH
 * @description Length of the device fingerprint hash substring.
 */
export const DEVICE_FINGERPRINT_HASH_LENGTH = 32;

// ============================================================================
// ALGORITHM CONFIGURATION
// ============================================================================
/**
 * @interface AlgorithmConfig
 * @description Configuration for a cryptographic algorithm.
 */

export interface AlgorithmConfig {
  type: KeyType;
  hash: HashAlgorithm;
  curve?: ECCurve;
  padding?: number;
  saltLength?: number;
}

/**
 * @constant ALGORITHM_CONFIG
 * @description Configuration mapping for JTS-supported cryptographic algorithms.
 * Defines the cryptographic parameters for each algorithm including key type,
 * hashing algorithm, curve parameters (for EC), and padding schemes.
 * 
 * @private
 */
export const ALGORITHM_CONFIG: Readonly<Record<JTSAlgorithm, AlgorithmConfig>> = {
  [JTSAlgorithm.RS256]: { type: KeyType.RSA, hash: HashAlgorithm.SHA256, padding: crypto.constants.RSA_PKCS1_PADDING },
  [JTSAlgorithm.RS384]: { type: KeyType.RSA, hash: HashAlgorithm.SHA384, padding: crypto.constants.RSA_PKCS1_PADDING },
  [JTSAlgorithm.RS512]: { type: KeyType.RSA, hash: HashAlgorithm.SHA512, padding: crypto.constants.RSA_PKCS1_PADDING },
  [JTSAlgorithm.ES256]: { type: KeyType.EC, hash: HashAlgorithm.SHA256, curve: ECCurve.P256 },
  [JTSAlgorithm.ES384]: { type: KeyType.EC, hash: HashAlgorithm.SHA384, curve: ECCurve.P384 },
  [JTSAlgorithm.ES512]: { type: KeyType.EC, hash: HashAlgorithm.SHA512, curve: ECCurve.P521 },
  [JTSAlgorithm.PS256]: { type: KeyType.RSA_PSS, hash: HashAlgorithm.SHA256, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: SALT_LENGTHS[JTSAlgorithm.PS256] },
  [JTSAlgorithm.PS384]: { type: KeyType.RSA_PSS, hash: HashAlgorithm.SHA384, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: SALT_LENGTHS[JTSAlgorithm.PS384] },
  [JTSAlgorithm.PS512]: { type: KeyType.RSA_PSS, hash: HashAlgorithm.SHA512, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: SALT_LENGTHS[JTSAlgorithm.PS512] },
} as const;