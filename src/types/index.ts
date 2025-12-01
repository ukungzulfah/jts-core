/**
 * @engjts/auth - Janus Token System Types
 * Core type definitions for JTS implementation
 */

// ============================================================================
// PROFILE TYPES
// ============================================================================

/**
 * JTS Profile types
 */
export type JTSProfile = 'JTS-L/v1' | 'JTS-S/v1' | 'JTS-C/v1';

/**
 * Supported signing algorithms (asymmetric only, per spec)
 */
export type JTSAlgorithm = 
  | 'RS256' | 'RS384' | 'RS512'  // RSA
  | 'ES256' | 'ES384' | 'ES512'  // ECDSA
  | 'PS256' | 'PS384' | 'PS512'; // RSASSA-PSS

/**
 * Supported encryption algorithms for JTS-C
 */
export type JWEAlgorithm = 'RSA-OAEP' | 'RSA-OAEP-256' | 'ECDH-ES' | 'ECDH-ES+A256KW';
export type JWEEncryption = 'A256GCM' | 'A256CBC-HS512';

// ============================================================================
// CLAIM TYPES
// ============================================================================

/**
 * JTS Header structure
 */
export interface JTSHeader {
  alg: JTSAlgorithm;
  typ: JTSProfile;
  kid: string;
}

/**
 * JTS-C (Confidentiality) JWE Header
 */
export interface JTSCHeader {
  alg: JWEAlgorithm;
  enc: JWEEncryption;
  typ: 'JTS-C/v1';
  kid: string;
}

/**
 * Core BearerPass payload claims (required)
 */
export interface JTSCoreClaims {
  /** Principal - Unique identifier for the authenticated entity */
  prn: string;
  /** Anchor ID - Links BearerPass to session record */
  aid: string;
  /** Expiration Time - Unix timestamp */
  exp: number;
  /** Issued At - Unix timestamp */
  iat: number;
}

/**
 * Standard BearerPass payload (JTS-S required)
 */
export interface JTSStandardClaims extends JTSCoreClaims {
  /** Token ID - Unique identifier for this specific token */
  tkn_id: string;
  /** Audience - Intended recipient */
  aud?: string | string[];
}

/**
 * Extended claims (optional)
 */
export interface JTSExtendedClaims {
  /** Device Fingerprint - Hash of device characteristics */
  dfp?: string;
  /** Permissions - Array of permission strings */
  perm?: string[];
  /** Grace Period - Tolerance time in seconds after exp */
  grc?: number;
  /** Organization - Tenant/org identifier */
  org?: string;
  /** Auth Method - How user authenticated */
  atm?: 'pwd' | 'mfa:totp' | 'mfa:sms' | 'sso' | 'passkey' | 'client_credentials' | string;
  /** Auth Time - When user last actively authenticated */
  ath?: number;
  /** Session Policy - Concurrent session policy */
  spl?: 'allow_all' | 'single' | 'notify' | `max:${number}`;
}

/**
 * Full BearerPass payload (all claims)
 */
export interface JTSPayload extends JTSStandardClaims, Partial<JTSExtendedClaims> {
  [key: string]: unknown;
}

/**
 * Lite profile payload (minimal)
 */
export interface JTSLitePayload extends JTSCoreClaims {
  tkn_id?: string;
  aud?: string | string[];
}

// ============================================================================
// SESSION TYPES
// ============================================================================

/**
 * Session record stored in database
 */
export interface JTSSession {
  /** Anchor ID - Primary key */
  aid: string;
  /** Principal - User/entity ID */
  prn: string;
  /** Current StateProof token */
  currentStateProof: string;
  /** Previous StateProof (for grace window) - JTS-S only */
  previousStateProof?: string;
  /** StateProof version counter */
  stateProofVersion: number;
  /** When rotation occurred */
  rotationTimestamp?: Date;
  /** Device fingerprint */
  deviceFingerprint?: string;
  /** Session created at */
  createdAt: Date;
  /** Session expires at */
  expiresAt: Date;
  /** Last activity timestamp */
  lastActive: Date;
  /** User agent string */
  userAgent?: string;
  /** IP address */
  ipAddress?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Session creation input
 */
export interface CreateSessionInput {
  prn: string;
  expiresIn?: number; // seconds, default 7 days
  deviceFingerprint?: string;
  userAgent?: string;
  ipAddress?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Session validation result
 */
export interface SessionValidationResult {
  valid: boolean;
  session?: JTSSession;
  withinGraceWindow?: boolean;
  error?: JTSErrorCode;
}

// ============================================================================
// ERROR TYPES
// ============================================================================

/**
 * JTS Error codes per specification
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
 * Error action hint
 */
export type JTSErrorAction = 'renew' | 'reauth' | 'retry' | 'none';

/**
 * Error key mapping
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
 * Error HTTP status mapping
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
 * Error action mapping
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
 * JTS Error class
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
  kid: string;
  algorithm: JTSAlgorithm;
  publicKey: string | Buffer;  // PEM format
  privateKey?: string | Buffer; // PEM format (only needed for signing)
  expiresAt?: number;
}

/**
 * JWKS Key entry
 */
export interface JWKSKey {
  kty: 'RSA' | 'EC';
  kid: string;
  use: 'sig' | 'enc';
  alg: string;
  n?: string;  // RSA modulus
  e?: string;  // RSA exponent
  x?: string;  // EC x coordinate
  y?: string;  // EC y coordinate
  crv?: string; // EC curve
  exp?: number;
}

/**
 * JWKS response
 */
export interface JWKS {
  keys: JWKSKey[];
}

/**
 * Auth Server configuration
 */
export interface JTSAuthServerConfig {
  /** JTS Profile to use */
  profile: JTSProfile;
  /** Signing key pair */
  signingKey: JTSKeyPair;
  /** Previous signing keys (for rotation) */
  previousKeys?: JTSKeyPair[];
  /** Encryption key pair (JTS-C only) */
  encryptionKey?: JTSKeyPair;
  /** BearerPass lifetime in seconds (default: 300 = 5 minutes) */
  bearerPassLifetime?: number;
  /** StateProof lifetime in seconds (default: 604800 = 7 days) */
  stateProofLifetime?: number;
  /** Grace period for expired tokens in seconds (default: 30) */
  gracePeriod?: number;
  /** Rotation grace window in seconds (default: 10) */
  rotationGraceWindow?: number;
  /** Session policy */
  sessionPolicy?: 'allow_all' | 'single' | 'notify' | `max:${number}`;
  /** Default audience */
  audience?: string | string[];
  /** Issuer identifier */
  issuer?: string;
}

/**
 * Resource Server configuration
 */
export interface JTSResourceServerConfig {
  /** Expected JTS profiles */
  acceptedProfiles?: JTSProfile[];
  /** JWKS endpoint URL */
  jwksUri?: string;
  /** Static public keys (alternative to JWKS) */
  publicKeys?: JTSKeyPair[];
  /** Expected audience */
  audience?: string | string[];
  /** Grace period tolerance in seconds */
  gracePeriodTolerance?: number;
  /** Whether to validate device fingerprint */
  validateDeviceFingerprint?: boolean;
  /** Cache JWKS for this many seconds */
  jwksCacheTTL?: number;
}

/**
 * Client SDK configuration
 */
export interface JTSClientConfig {
  /** Auth server base URL */
  authServerUrl: string;
  /** Token endpoint path (default: /jts/login) */
  tokenEndpoint?: string;
  /** Renewal endpoint path (default: /jts/renew) */
  renewalEndpoint?: string;
  /** Logout endpoint path (default: /jts/logout) */
  logoutEndpoint?: string;
  /** Auto-renew before expiry (seconds) */
  autoRenewBefore?: number;
  /** Storage adapter */
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
