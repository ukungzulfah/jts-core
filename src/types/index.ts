/**
 * @engjts/auth - Janus Token System Types
 *
 * This module defines the core TypeScript types, interfaces, and error helpers
 * used throughout the Janus Token System (JTS) implementation. The types in
 * this file are the canonical source of truth for:
 *
 * - JTS token profiles and cryptographic algorithms
 * - BearerPass and StateProof claim structures
 * - Session model and validation results
 * - Standardized error codes and error handling helpers
 * - Configuration contracts for Auth Server, Resource Server, and Client SDK
 * - Result types for token generation, renewal, and verification
 *
 * These definitions are intentionally stable and versioned via the JTS
 * specification. Any breaking change should be coordinated with the spec and
 * reflected in the public documentation.
 */

// ============================================================================
// PROFILE TYPES
// ============================================================================

/**
 * Constant identifiers for JTS profiles.
 *
 * Use these constants instead of magic strings throughout the codebase
 * for better maintainability and type safety.
 *
 * @example
 * ```typescript
 * import { JTS_PROFILES } from '@engjts/auth';
 *
 * const config = {
 *   profile: JTS_PROFILES.STANDARD, // 'JTS-S/v1'
 * };
 * ```
 */
export const JTS_PROFILES = {
  /** Lite profile – minimal claims and streamlined flows. */
  LITE: 'JTS-L/v1',
  /** Standard profile – full BearerPass / StateProof semantics. */
  STANDARD: 'JTS-S/v1',
  /** Confidential profile – encrypted BearerPass payloads (JWE). */
  CONFIDENTIAL: 'JTS-C/v1',
} as const;

/**
 * Supported JTS profile identifiers.
 *
 * - `JTS-L/v1`: Lite profile – minimal claims and streamlined flows.
 * - `JTS-S/v1`: Standard profile – full BearerPass / StateProof semantics.
 * - `JTS-C/v1`: Confidential profile – encrypted BearerPass payloads (JWE).
 */
export type JTSProfile = (typeof JTS_PROFILES)[keyof typeof JTS_PROFILES];

/**
 * Supported asymmetric signing algorithms for JTS tokens.
 *
 * Only asymmetric algorithms are allowed in order to support secure
 * verification across services without sharing private keys.
 * 
 * @enum {string}
 * @property {string} RS256 - RSA using SHA-256 hash algorithm (PKCS#1 v1.5)
 * @property {string} RS384 - RSA using SHA-384 hash algorithm (PKCS#1 v1.5)
 * @property {string} RS512 - RSA using SHA-512 hash algorithm (PKCS#1 v1.5)
 * @property {string} ES256 - ECDSA using P-256 curve and SHA-256 hash algorithm
 * @property {string} ES384 - ECDSA using P-384 curve and SHA-384 hash algorithm
 * @property {string} ES512 - ECDSA using P-521 curve and SHA-512 hash algorithm
 * @property {string} PS256 - RSA-PSS using SHA-256 hash algorithm
 * @property {string} PS384 - RSA-PSS using SHA-384 hash algorithm
 * @property {string} PS512 - RSA-PSS using SHA-512 hash algorithm
 */
export enum JTSAlgorithm {
  // RSA (PKCS#1 v1.5)
  RS256 = 'RS256',
  RS384 = 'RS384',
  RS512 = 'RS512',
  // ECDSA (Elliptic Curve Digital Signature Algorithm)
  ES256 = 'ES256',
  ES384 = 'ES384',
  ES512 = 'ES512',
  // RSA-PSS (Probabilistic Signature Scheme)
  PS256 = 'PS256',
  PS384 = 'PS384',
  PS512 = 'PS512',
}

/**
 * Supported JWE key management algorithms for the confidential JTS-C profile.
 * 
 * @enum {string}
 * @property {string} RSA_OAEP - RSA-OAEP using default parameters
 * @property {string} RSA_OAEP_256 - RSA-OAEP using SHA-256 and MGF1 with SHA-256
 * @property {string} ECDH_ES - Elliptic Curve Diffie-Hellman Ephemeral Static key agreement
 * @property {string} ECDH_ES_A256KW - ECDH-ES using Concat KDF and A256KW wrapping
 */
export enum JWEAlgorithm {
  RSA_OAEP = 'RSA-OAEP',
  RSA_OAEP_256 = 'RSA-OAEP-256',
  ECDH_ES = 'ECDH-ES',
  ECDH_ES_A256KW = 'ECDH-ES+A256KW',
}

/**
 * Supported JWE content encryption algorithms for the confidential JTS-C profile.
 * 
 * @enum {string}
 * @property {string} A256GCM - AES GCM using 256-bit key
 * @property {string} A256CBC_HS512 - AES CBC using 256-bit key with HMAC SHA-512
 */
export enum JWEEncryption {
  A256GCM = 'A256GCM',
  A256CBC_HS512 = 'A256CBC-HS512',
}

// ============================================================================
// CLAIM TYPES
// ============================================================================

/**
 * JTS header structure for signed BearerPass and StateProof tokens.
 *
 * This header is conceptually similar to a JOSE header, but restricted to the
 * subset defined by the JTS specification.
 */
export interface JTSHeader {
  alg: JTSAlgorithm;
  typ: JTSProfile;
  kid: string;
}

/**
 * JTS-C (Confidential) profile JWE header.
 *
 * Used when the BearerPass payload is encrypted (JTS-C) instead of only signed.
 */
export interface JTSCHeader {
  alg: JWEAlgorithm;
  enc: JWEEncryption;
  typ: typeof JTS_PROFILES.CONFIDENTIAL;
  kid: string;
}

/**
 * Core BearerPass payload claims.
 *
 * These claims are required for all JTS profiles and represent the minimal
 * contract for a valid BearerPass:
 *
 * - `prn`: Principal identifier (subject / user / client).
 * - `aid`: Anchor ID linking the BearerPass to a server-side session record.
 * - `exp`: Expiration time as a UNIX timestamp (seconds).
 * - `iat`: Issued-at time as a UNIX timestamp (seconds).
 */
export interface JTSCoreClaims {
  /** Unique identifier for the authenticated principal (user, client, or entity). */
  prn: string;
  /** Anchor ID linking this BearerPass to a persistent session record. */
  aid: string;
  /** Expiration time of the BearerPass as a UNIX timestamp (seconds). */
  exp: number;
  /** Issued-at time of the BearerPass as a UNIX timestamp (seconds). */
  iat: number;
}

/**
 * Standard BearerPass payload (JTS-S required claims).
 *
 * Extends the core claims with additional identifiers and audience scoping:
 *
 * - `tkn_id`: Unique identifier for this specific BearerPass instance.
 * - `aud`: Intended recipient(s) of the token (optional for some flows).
 */
export interface JTSStandardClaims extends JTSCoreClaims {
  /** Unique identifier for this specific BearerPass instance. */
  tkn_id: string;
  /** Intended audience(s) for this BearerPass (service, API, or resource). */
  aud?: string | string[];
}

/**
 * Optional extended BearerPass claims.
 *
 * These claims provide richer context for risk-based authentication,
 * authorization, and session management. All properties are optional and may
 * be omitted when not relevant to a given deployment.
 */
export interface JTSExtendedClaims {
  /** Device fingerprint (hash or opaque identifier of device characteristics). */
  dfp?: string;
  /** Effective permissions granted to the principal, as arbitrary strings. */
  perm?: string[];
  /** Per-token grace period tolerance in seconds beyond `exp`. */
  grc?: number;
  /** Tenant or organization identifier for multi-tenant scenarios. */
  org?: string;
  /**
   * Authentication method used to obtain the BearerPass.
   *
   * Common values:
   * - `pwd`: password-based authentication
   * - `mfa:totp`: multi-factor with TOTP
   * - `mfa:sms`: multi-factor with SMS
   * - `sso`: federated single sign-on
   * - `passkey`: WebAuthn / FIDO2 passkey
   * - `client_credentials`: non-user client authentication
   *
   * Custom string values are allowed for implementation-specific methods.
   */
  atm?: 'pwd' | 'mfa:totp' | 'mfa:sms' | 'sso' | 'passkey' | 'client_credentials' | string;
  /** UNIX timestamp (seconds) when the principal last performed an active auth event. */
  ath?: number;
  /**
   * Effective concurrent session policy applied to this BearerPass.
   *
   * - `allow_all`: unlimited concurrent sessions.
   * - `single`: only one active session at a time.
   * - `notify`: multiple sessions allowed, but anomalous activity should be surfaced.
   * - `max:<n>`: implementation-defined maximum concurrent sessions.
   */
  spl?: 'allow_all' | 'single' | 'notify' | `max:${number}`;
}

/**
 * Full BearerPass payload (all standard and extended claims).
 *
 * Implementations may attach additional namespaced or custom claims; those are
 * represented via the catch-all index signature.
 */
export interface JTSPayload extends JTSStandardClaims, Partial<JTSExtendedClaims> {
  [key: string]: unknown;
}

/**
 * Lite profile BearerPass payload.
 *
 * This profile keeps only the minimal set of claims (`JTSCoreClaims`) and
 * optional identifiers that are useful in simpler deployments.
 */
export interface JTSLitePayload extends JTSCoreClaims {
  /** Optional token identifier for the lite profile. */
  tkn_id?: string;
  /** Optional audience for the lite profile. */
  aud?: string | string[];
}

// ============================================================================
// SESSION TYPES
// ============================================================================

/**
 * Server-side session record persisted in the session store.
 *
 * Each session is uniquely identified by an Anchor ID (`aid`) and maintains a
 * versioned StateProof chain for rotation, along with metadata about the
 * device, lifecycle, and context in which the session was created.
 */
export interface JTSSession {
  /** Anchor ID (primary key) that links BearerPass and StateProof to the session. */
  aid: string;
  /** Principal identifier associated with this session. */
  prn: string;
  /** Current StateProof token (opaque signed artifact). */
  currentStateProof: string;
  /**
   * Previous StateProof token (used for rotation grace windows in JTS-S).
   * Present only when a rotation has recently occurred.
   */
  previousStateProof?: string;
  /** Monotonically increasing StateProof version counter. */
  stateProofVersion: number;
  /** Timestamp of the most recent StateProof rotation, if any. */
  rotationTimestamp?: Date;
  /** Device fingerprint bound to this session, if device binding is enabled. */
  deviceFingerprint?: string;
  /** Timestamp indicating when the session was created. */
  createdAt: Date;
  /** Timestamp indicating when the session will expire server-side. */
  expiresAt: Date;
  /** Timestamp of the last observed activity for this session. */
  lastActive: Date;
  /** Optional user-agent string captured at session creation. */
  userAgent?: string;
  /** Optional full IP address observed at session creation. */
  ipAddress?: string;
  /** Arbitrary implementation-defined metadata associated with the session. */
  metadata?: Record<string, unknown>;
}

/**
 * Input parameters for creating a new server-side session.
 *
 * Only the principal identifier (`prn`) is required; all other properties are
 * optional and can be used to enrich the session record with contextual data.
 */
export interface CreateSessionInput {
  prn: string;
  /**
   * Desired session lifetime, in seconds.
   *
   * If omitted, the implementation should fall back to a sensible default
   * (typically 7 days).
   */
  expiresIn?: number;
  deviceFingerprint?: string;
  userAgent?: string;
  ipAddress?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Result of validating a session and (optionally) its associated tokens.
 */
export interface SessionValidationResult {
  /** Indicates whether the session is currently valid. */
  valid: boolean;
  /** The resolved session record, if validation succeeded. */
  session?: JTSSession;
  /**
   * Indicates whether the session is within a configured grace window
   * (for example, immediately after rotation or shortly after expiry).
   */
  withinGraceWindow?: boolean;
  /** Optional standardized error code indicating why validation failed. */
  error?: JTSErrorCode;
}

// ============================================================================
// ERROR TYPES
// ============================================================================

/**
 * JTS error codes as defined by the public specification.
 *
 * Each error code is a stable, machine-readable identifier that maps to:
 * - a human-readable key (`JTS_ERROR_KEYS`)
 * - an HTTP status code (`JTS_ERROR_STATUS`)
 * - a recommended client action (`JTS_ERROR_ACTIONS`)
 */
export type JTSErrorCode =
  | 'JTS-400-01' // malformed_token
  | 'JTS-400-02' // missing_claims
  | 'JTS-401-01' // bearer_expired
  | 'JTS-401-02' // signature_invalid
  | 'JTS-401-03' // stateproof_invalid
  | 'JTS-401-04' // session_terminated
  | 'JTS-401-05' // session_compromised
  | 'JTS-401-06' // device_mismatch
  | 'JTS-403-01' // audience_mismatch
  | 'JTS-403-02' // permission_denied
  | 'JTS-403-03' // org_mismatch
  | 'JTS-500-01'; // key_unavailable

/**
 * Constant helpers for JTS error codes.
 *
 * Prefer referencing these constants instead of hard-coded string literals
 * throughout the codebase to improve maintainability and discoverability.
 */
export const JTS_ERRORS = {
  // 400 - Bad Request
  MALFORMED_TOKEN: 'JTS-400-01' as const,
  MISSING_CLAIMS: 'JTS-400-02' as const,
  // 401 - Unauthorized
  BEARER_EXPIRED: 'JTS-401-01' as const,
  SIGNATURE_INVALID: 'JTS-401-02' as const,
  STATEPROOF_INVALID: 'JTS-401-03' as const,
  SESSION_TERMINATED: 'JTS-401-04' as const,
  SESSION_COMPROMISED: 'JTS-401-05' as const,
  DEVICE_MISMATCH: 'JTS-401-06' as const,
  // 403 - Forbidden
  AUDIENCE_MISMATCH: 'JTS-403-01' as const,
  PERMISSION_DENIED: 'JTS-403-02' as const,
  ORG_MISMATCH: 'JTS-403-03' as const,
  // 500 - Server Error
  KEY_UNAVAILABLE: 'JTS-500-01' as const,
} as const;

/**
 * Constant error messages for JTSError.
 * 
 * Prefer referencing these constants instead of hard-coded string literals
 * throughout the codebase to improve maintainability and avoid magic values.
 */
export const JTS_ERROR_MESSAGES = {
  // Token-related
  NO_TOKEN_PROVIDED: 'No token provided',
  TOKEN_VERIFICATION_FAILED: 'Token verification failed',
  TOKEN_MUST_HAVE_3_PARTS: 'Token must have 3 parts',
  FAILED_TO_DECODE_TOKEN: 'Failed to decode token',
  FAILED_TO_VERIFY_TOKEN: 'Failed to verify token',
  NO_VALID_TOKEN_AVAILABLE: 'No valid token available',
  
  // JWE-related
  JWE_MUST_HAVE_5_PARTS: 'JWE must have 5 parts',
  INVALID_JWE_HEADER: 'Invalid JWE header',
  EXPECTED_JTS_C_TOKEN_TYPE: 'Expected JTS-C/v1 token type',
  FAILED_TO_DECRYPT_CONTENT_ENCRYPTION_KEY: 'Failed to decrypt content encryption key',
  FAILED_TO_DECRYPT_TOKEN_CONTENT: 'Failed to decrypt token content',
  FAILED_TO_PROCESS_ENCRYPTED_TOKEN: 'Failed to process encrypted token',
  
  // Key-related
  NO_PUBLIC_KEYS_AVAILABLE: 'No public keys available',
  DECRYPTION_KEY_NOT_CONFIGURED: 'Decryption key not configured for JTS-C tokens',
  
  // Profile-related
  // Note: Profile-related messages with dynamic values use helper functions
  
  // Authentication-related
  AUTHENTICATION_REQUIRED: 'Authentication required',
  STATEPROOF_NOT_PROVIDED: 'StateProof not provided',
  
  // Claims-related
  MISSING_REQUIRED_CLAIMS: 'Missing required claims',
  MISSING_TKN_ID_CLAIM: 'Missing tkn_id claim for JTS-S/JTS-C',
  
  // Expiration-related
  TOKEN_HAS_EXPIRED: 'Token has expired',
  
  // Validation-related
  SIGNATURE_VERIFICATION_FAILED: 'Signature verification failed',
  AUDIENCE_MISMATCH: 'Audience mismatch',
  ORGANIZATION_MISMATCH: 'Organization mismatch',
  DEVICE_FINGERPRINT_MISMATCH: 'Device fingerprint mismatch',
  SESSION_COMPROMISED_REPLAY_ATTACK: 'Session compromised - replay attack detected',
  INVALID_STATEPROOF: 'Invalid StateProof',
  
  // Permission-related
  PERMISSION_DENIED: 'Permission denied',
  PERMISSION_CHECK_FAILED: 'Permission check failed',
  MISSING_REQUIRED_PERMISSIONS: 'Missing required permissions',
} as const;

/**
 * Helper functions for dynamic error messages.
 */
export const JTS_ERROR_MESSAGE_HELPERS = {
  /**
   * Creates a message for key not found error.
   * @param kid - The key ID that was not found
   * @returns Error message string
   */
  keyNotFound: (kid: string): string => `Key ${kid} not found`,
  
  /**
   * Creates a message for key mismatch error.
   * @param actualKid - The key ID found in the header
   * @param expectedKid - The expected key ID
   * @returns Error message string
   */
  keyMismatch: (actualKid: string, expectedKid: string): string => 
    `Key ${actualKid} not available, expected ${expectedKid}`,
  
  /**
   * Creates a message for profile not accepted error.
   * @param profile - The profile that was not accepted
   * @returns Error message string
   */
  profileNotAccepted: (profile: string): string => `Profile ${profile} not accepted`,
  
  /**
   * Creates a message for missing required permissions error.
   * @param permissions - Array of missing permissions
   * @returns Error message string
   */
  missingRequiredPermissions: (permissions: string[]): string => 
    `Missing required permissions: ${permissions.join(', ')}`,
  
  /**
   * Creates a message for requires one of permissions error.
   * @param permissions - Array of required permissions (any one)
   * @returns Error message string
   */
  requiresOneOf: (permissions: string[]): string => 
    `Requires one of: ${permissions.join(', ')}`,
} as const;

/**
 * Canonical JTS HTTP header names.
 *
 * These headers are used by both clients and servers to coordinate CSRF
 * protection, StateProof transport, and device fingerprint binding.
 */
export const JTS_HEADERS = {
  /**
   * CSRF protection header.
   *
   * For mutating requests (e.g. `POST`, `PUT`, `DELETE`), the client should
   * explicitly set this header to `'1'` to indicate an intentional JTS call.
   */
  REQUEST: 'X-JTS-Request',
  /**
   * StateProof header.
   *
   * Used by clients that cannot rely on HTTP cookies (e.g. mobile, native, or
   * cross-origin contexts) to transport the StateProof alongside requests.
   */
  STATE_PROOF: 'X-JTS-StateProof',
  /** Device fingerprint header, for propagating a client-generated identifier. */
  DEVICE_FINGERPRINT: 'X-JTS-Device-Fingerprint',
} as const;

/**
 * Lowercase variants of the canonical JTS headers.
 *
 * These are convenient when looking up headers in environments where header
 * names are normalized to lowercase (for example, Node.js `IncomingMessage`).
 */
export const JTS_HEADERS_LOWERCASE = {
  REQUEST: 'x-jts-request',
  STATE_PROOF: 'x-jts-stateproof',
  DEVICE_FINGERPRINT: 'x-jts-device-fingerprint',
} as const;

/**
 * Recommended client action for a given error.
 *
 * - `renew`: attempt to renew the BearerPass / StateProof.
 * - `reauth`: require an explicit re-authentication from the principal.
 * - `retry`: retry the request after a short delay or backoff.
 * - `none`: no automated action is recommended.
 */
export type JTSErrorAction = 'renew' | 'reauth' | 'retry' | 'none';

/**
 * Maps JTS error codes to stable, human-readable error keys.
 *
 * These keys are suitable for use in API responses and client-side
 * internationalization / error message mapping.
 */
export const JTS_ERROR_KEYS: Record<JTSErrorCode, string> = {
  'JTS-400-01': 'malformed_token',
  'JTS-400-02': 'missing_claims',
  'JTS-401-01': 'bearer_expired',
  'JTS-401-02': 'signature_invalid',
  'JTS-401-03': 'stateproof_invalid',
  'JTS-401-04': 'session_terminated',
  'JTS-401-05': 'session_compromised',
  'JTS-401-06': 'device_mismatch',
  'JTS-403-01': 'audience_mismatch',
  'JTS-403-02': 'permission_denied',
  'JTS-403-03': 'org_mismatch',
  'JTS-500-01': 'key_unavailable',
};

/**
 * Maps JTS error codes to HTTP status codes.
 *
 * This provides a consistent and spec-aligned way to translate internal
 * error conditions into HTTP responses.
 */
export const JTS_ERROR_STATUS: Record<JTSErrorCode, number> = {
  'JTS-400-01': 400,
  'JTS-400-02': 400,
  'JTS-401-01': 401,
  'JTS-401-02': 401,
  'JTS-401-03': 401,
  'JTS-401-04': 401,
  'JTS-401-05': 401,
  'JTS-401-06': 401,
  'JTS-403-01': 403,
  'JTS-403-02': 403,
  'JTS-403-03': 403,
  'JTS-500-01': 500,
};

/**
 * Maps JTS error codes to recommended high-level client actions.
 *
 * The action is intended as a hint for automated and human-driven clients
 * about what the next step should be when this error is encountered.
 */
export const JTS_ERROR_ACTIONS: Record<JTSErrorCode, JTSErrorAction> = {
  'JTS-400-01': 'reauth',
  'JTS-400-02': 'reauth',
  'JTS-401-01': 'renew',
  'JTS-401-02': 'reauth',
  'JTS-401-03': 'reauth',
  'JTS-401-04': 'reauth',
  'JTS-401-05': 'reauth',
  'JTS-401-06': 'reauth',
  'JTS-403-01': 'none',
  'JTS-403-02': 'none',
  'JTS-403-03': 'none',
  'JTS-500-01': 'retry',
};

/**
 * Structured JTS error type.
 *
 * This error encapsulates a standardized JTS error code and exposes derived
 * metadata such as the error key, corresponding HTTP status, recommended
 * action, and a timestamp. It is the primary error type thrown by JTS
 * components when something goes wrong in a spec-defined way.
 */
export class JTSError extends Error {
  public readonly errorCode: JTSErrorCode;
  public readonly errorKey: string;
  public readonly httpStatus: number;
  public readonly action: JTSErrorAction;
  public readonly retryAfter?: number;
  public readonly timestamp: number;

  constructor(code: JTSErrorCode, message?: string, retryAfter?: number) {
    super(message || JTS_ERROR_KEYS[code]);
    this.name = 'JTSError';
    this.errorCode = code;
    this.errorKey = JTS_ERROR_KEYS[code];
    this.httpStatus = JTS_ERROR_STATUS[code];
    this.action = JTS_ERROR_ACTIONS[code];
    this.retryAfter = retryAfter;
    this.timestamp = Math.floor(Date.now() / 1000);
  }

  toJSON() {
    /**
     * Serializes the error into a JSON-friendly structure suitable for
     * returning from HTTP APIs or logging pipelines.
     */
    return {
      error: this.errorKey,
      error_code: this.errorCode,
      message: this.message,
      action: this.action,
      retry_after: this.retryAfter ?? 0,
      timestamp: this.timestamp,
    };
  }
}

// ============================================================================
// CONFIGURATION TYPES
// ============================================================================

/**
 * Key pair for signing/verification
 */
export interface JTSKeyPair {
  /** Key identifier used to correlate tokens with a specific key in a JWKS. */
  kid: string;
  /** Algorithm associated with this key pair. */
  algorithm: JTSAlgorithm;
  /** Public key in PEM format, used for verification and JWKS exposure. */
  publicKey: string | Buffer;
  /**
   * Private key in PEM format, used for signing.
   *
   * This should be present only on components that are responsible for
   * issuing tokens (for example, the auth server) and MUST NOT be shared
   * with resource servers.
   */
  privateKey?: string | Buffer;
  /** Optional UNIX timestamp (seconds) indicating when this key should expire. */
  expiresAt?: number;
}

/**
 * JWKS Key entry
 */
export interface JWKSKey {
  /** Key type (e.g. `RSA`, `EC`). */
  kty: 'RSA' | 'EC';
  /** Key identifier, matching the `kid` in JTS headers. */
  kid: string;
  /** Intended use of the key (`sig` for signing, `enc` for encryption). */
  use: 'sig' | 'enc';
  /** JOSE algorithm identifier associated with this key. */
  alg: string;
  /** RSA modulus (base64url-encoded). */
  n?: string;
  /** RSA public exponent (base64url-encoded). */
  e?: string;
  /** Elliptic curve X coordinate (base64url-encoded). */
  x?: string;
  /** Elliptic curve Y coordinate (base64url-encoded). */
  y?: string;
  /** Elliptic curve name (e.g. `P-256`). */
  crv?: string;
  /** Optional expiration time for the key as a UNIX timestamp (seconds). */
  exp?: number;
}

/**
 * JWKS response
 */
export interface JWKS {
  /** Array of JSON Web Key (JWK) entries. */
  keys: JWKSKey[];
}

/**
 * Session policy options for controlling concurrent sessions.
 * 
 * - `ALLOW_ALL`: Unlimited concurrent sessions.
 * - `SINGLE`: Only one active session at a time.
 * - `NOTIFY`: Multiple sessions allowed, but anomalous activity should be surfaced.
 * - `MAX_N`: Maximum of N concurrent sessions.
 */
export enum SessionPolicy {
  /** Unlimited concurrent sessions. */
  ALLOW_ALL = 'allow_all',
  /** Only one active session at a time. */
  SINGLE = 'single',
  /** Multiple sessions allowed, but anomalous activity should be surfaced. */
  NOTIFY = 'notify',
}/**
 * Auth Server configuration
 */
export interface JTSAuthServerConfig {
  /** JTS profile to use for issued tokens. */
  profile: JTSProfile;
  /** Primary signing key pair used for BearerPass and StateProof issuance. */
  signingKey: JTSKeyPair;
  /** Previous signing keys, used to validate tokens issued before key rotation. */
  previousKeys?: JTSKeyPair[];
  /** Optional encryption key pair, required for the JTS-C (confidential) profile. */
  encryptionKey?: JTSKeyPair;
  /** BearerPass lifetime in seconds (default implementation: 300 seconds / 5 minutes). */
  bearerPassLifetime?: number;
  /** StateProof lifetime in seconds (default implementation: 604800 seconds / 7 days). */
  stateProofLifetime?: number;
  /** Grace period for expired tokens in seconds (default implementation: 30 seconds). */
  gracePeriod?: number;
  /** Rotation grace window in seconds (default implementation: 10 seconds). */
  rotationGraceWindow?: number;
  /** Default concurrent session policy applied by the auth server. */
  sessionPolicy?: SessionPolicy | `max:${number}` | string;  /** Default audience value(s) to embed in issued BearerPass tokens. */
  audience?: string | string[];
  /** Issuer identifier (for example, base URL of the auth server). */
  issuer?: string;
}
/**
 * Resource Server configuration
 */
export interface JTSResourceServerConfig {
  /** JTS profiles that this resource server will accept. */
  acceptedProfiles?: JTSProfile[];
  /** JWKS endpoint URL from which the resource server can fetch public keys. */
  jwksUri?: string;
  /** Static public keys, used as an alternative to a remote JWKS endpoint. */
  publicKeys?: JTSKeyPair[];
  /** Expected audience value(s) that must match the BearerPass `aud` claim. */
  audience?: string | string[];
  /** Grace period tolerance in seconds for expired tokens. */
  gracePeriodTolerance?: number;
  /** Whether the resource server should validate the device fingerprint claim/header. */
  validateDeviceFingerprint?: boolean;
  /** JWKS cache time-to-live in seconds. */
  jwksCacheTTL?: number;
}

/**
 * Client SDK configuration
 */
export interface JTSClientConfig {
  /** Base URL of the auth server hosting the JTS endpoints. */
  authServerUrl: string;
  /** Token endpoint path (default implementation: `/jts/login`). */
  tokenEndpoint?: string;
  /** Renewal endpoint path (default implementation: `/jts/renew`). */
  renewalEndpoint?: string;
  /** Logout endpoint path (default implementation: `/jts/logout`). */
  logoutEndpoint?: string;
  /**
   * Number of seconds before actual expiry when the client should proactively
   * attempt to renew the BearerPass.
   */
  autoRenewBefore?: number;
  /** Token storage adapter implementation. */
  storage?: TokenStorage;
}

/**
 * Token storage interface (for client SDK)
 */
export interface TokenStorage {
  getBearerPass(): Promise<string | null>;
  setBearerPass(token: string): Promise<void>;
  getStateProof(): Promise<string | null>;
  setStateProof(token: string): Promise<void>;
  clear(): Promise<void>;
}

// ============================================================================
// RESULT TYPES
// ============================================================================

/**
 * Token generation result
 */
export interface TokenGenerationResult {
  bearerPass: string;
  stateProof: string;
  expiresAt: number;
  sessionId: string;
}

/**
 * Token renewal result
 */
export interface TokenRenewalResult {
  bearerPass: string;
  stateProof?: string; // Only present if rotated (JTS-S)
  expiresAt: number;
}

/**
 * BearerPass verification result
 */
export interface VerificationResult {
  valid: boolean;
  payload?: JTSPayload;
  header?: JTSHeader;
  error?: JTSError;
}

/**
 * Decoded token (without verification)
 */
export interface DecodedToken {
  header: JTSHeader;
  payload: JTSPayload;
  signature: string;
}

// ============================================================================
// MIDDLEWARE TYPES
// ============================================================================

/**
 * Express request with JTS context
 */
export interface JTSRequest {
  jts?: {
    payload: JTSPayload;
    header: JTSHeader;
    bearerPass: string;
  };
}

/**
 * Cookie options for StateProof
 */
export interface StateProofCookieOptions {
  name?: string;        // default: 'jts_state_proof'
  path?: string;        // default: '/jts'
  maxAge?: number;      // in seconds
  sameSite?: 'strict' | 'lax' | 'none';
  secure?: boolean;
  domain?: string;
}

/**
 * Session list response
 */
export interface SessionListResponse {
  sessions: {
    aid: string;
    device: string;
    ipPrefix: string;
    createdAt: number;
    lastActive: number;
    current: boolean;
  }[];
}

/**
 * JTS Configuration metadata (discovery)
 */
export interface JTSConfigurationMetadata {
  issuer: string;
  jwks_uri: string;
  token_endpoint: string;
  renewal_endpoint: string;
  revocation_endpoint: string;
  supported_profiles: JTSProfile[];
  supported_algorithms: JTSAlgorithm[];
}
