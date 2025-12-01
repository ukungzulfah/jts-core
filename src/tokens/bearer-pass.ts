/**
 * @fileoverview BearerPass Token Creation and Verification
 * @module @engjts/auth/tokens/bearer-pass
 * @description Functions for creating and verifying BearerPass tokens (JWS) according to the JTS specification.
 * Implements the three JTS security profiles: JTS-L (Lite), JTS-S (Standard), and JTS-C (Confidentiality).
 * 
 * BearerPass tokens are JSON Web Signatures (JWS) with JTS-specific claims and verification logic.
 * 
 * @example
 * ```typescript
 * import { createBearerPass, verifyBearerPass } from '@engjts/auth/tokens/bearer-pass';
 * 
 * // Create a token
 * const token = createBearerPass({
 *   prn: 'user123',
 *   aid: 'session456',
 *   kid: 'signing-key',
 *   privateKey: '-----BEGIN PRIVATE KEY-----...',
 *   profile: 'JTS-S/v1',
 *   expiresIn: 300 // 5 minutes
 * });
 * 
 * // Verify a token
 * const result = verifyBearerPass({
 *   token,
 *   publicKeys: new Map([['signing-key', keyPair]])
 * });
 * 
 * if (result.valid) {
 *   console.log('Token is valid for user:', result.payload!.prn);
 * }
 * ```
 */

import {
  base64urlEncode,
  base64urlDecode,
  encodeJSON,
  decodeJSON,
  sign,
  verify,
  generateTokenId,
} from '../crypto';
import {
  JTSHeader,
  JTSPayload,
  JTSLitePayload,
  JTSProfile,
  JTS_PROFILES,
  JTSAlgorithm,
  JTSKeyPair,
  JTSError,
  JTS_ERRORS,
  JTS_ERROR_MESSAGES,
  JTS_ERROR_MESSAGE_HELPERS,
  DecodedToken,
  VerificationResult,
  JTSExtendedClaims,
} from '../types';

// ============================================================================
// BEARER PASS CREATION OPTIONS
// ============================================================================

/**
 * @interface CreateBearerPassOptions
 * @description Options for creating a BearerPass token.
 * 
 * The options vary slightly depending on the JTS profile being used:
 * - **JTS-L**: Minimal payload, no token ID
 * - **JTS-S**: Full payload with token ID for revocation
 * - **JTS-C**: Same as JTS-S but wrapped in JWE encryption
 */
export interface CreateBearerPassOptions {
  /**
   * @property {string} prn - Principal (user/entity ID)
   * The subject of the token, typically a user ID or service name.
   */
  prn: string;
  
  /**
   * @property {string} aid - Anchor ID (session reference)
   * Reference to the session in the session store. Required for JTS-S and JTS-C.
   */
  aid: string;
  
  /**
   * @property {JTSAlgorithm} [algorithm='RS256'] - Algorithm to use for signing
   * Supported algorithms: RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512
   */
  algorithm?: JTSAlgorithm;
  
  /**
   * @property {JTSProfile} [profile='JTS-S/v1'] - Profile type
   * Determines the token structure and claims included.
   */
  profile?: JTSProfile;
  
  /**
   * @property {string} kid - Key ID
   * Identifier for the signing key, used by verifiers to select the correct public key.
   */
  kid: string;
  
  /**
   * @property {string|Buffer} privateKey - Private key for signing
   * The private key in PEM format used to sign the token.
   */
  privateKey: string | Buffer;
  
  /**
   * @property {number} [expiresIn=300] - Token lifetime in seconds
   * Time until the token expires, relative to the current time (iat claim).
   * Default is 300 seconds (5 minutes).
   */
  expiresIn?: number;
  
  /**
   * @property {string|string[]} [aud] - Audience
   * Intended recipient(s) of the token. Can be a string or array of strings.
   */
  aud?: string | string[];
  
  /**
   * @property {Partial<JTSExtendedClaims>} [extended={}] - Extended claims
   * Additional JTS-defined claims like device fingerprint, permissions, etc.
   */
  extended?: Partial<JTSExtendedClaims>;
  
  /**
   * @property {Record<string, unknown>} [customClaims={}] - Custom claims
   * Application-specific claims to include in the token payload.
   */
  customClaims?: Record<string, unknown>;
}

/**
 * @function createBearerPass
 * @description Creates a BearerPass token (JWS) according to the specified JTS profile.
 * 
 * The function generates a signed JWT with JTS-specific claims based on the security profile:
 * - **JTS-L (Lite)**: Minimal payload with no token ID for stateless verification
 * - **JTS-S (Standard)**: Full payload with token ID for stateful revocation
 * - **JTS-C (Confidentiality)**: Same as JTS-S but intended for JWE encryption
 * 
 * @param options - Configuration options for token creation
 * @returns A signed BearerPass token as a compact JWS string
 * 
 * @example
 * ```typescript
 * // Create a JTS-S token
 * const token = createBearerPass({
 *   prn: 'user123',
 *   aid: 'session456',
 *   kid: 'signing-key',
 *   privateKey: '-----BEGIN PRIVATE KEY-----...',
 *   profile: 'JTS-S/v1',
 *   expiresIn: 300,
 *   extended: {
 *     perm: ['read', 'write'],
 *     dfp: 'sha256:abc123...'
 *   }
 * });
 * 
 * console.log(token); // eyJhbGciOiJSUzI1NiIsInR5cCI6IkpUUy1TL3YxIiwia2lkIjoic2lnbmluZy1rZXkifQ.eyJwcm4iOiJ1c2VyMTIzIiwiYWlkIjoic2Vzc2lvbjQ1NiIsInRrbl9pZCI6InRrbl94eXo3ODkiLCJleHAiOjE2MTQ1MDQ0MDAsImlhdCI6MTYxNDUwNDcwMCwiZGZwIjoic2hhMjU2OmFiYzEyMy4uLiIsInBlcm0iOlsicmVhZCIsIndyaXRlIl19.signature
 * ```
 * 
 * @throws {Error} If an invalid algorithm or profile is specified
 */
export function createBearerPass(options: CreateBearerPassOptions): string {
  const {
    prn,
    aid,
    algorithm = JTSAlgorithm.RS256,
    profile = JTS_PROFILES.STANDARD,
    kid,
    privateKey,
    expiresIn = 300, // 5 minutes default
    aud,
    extended = {},
    customClaims = {},
  } = options;
  const now = Math.floor(Date.now() / 1000);
  const exp = now + expiresIn;

  // Build header
  const header: JTSHeader = {
    alg: algorithm,
    typ: profile,
    kid,
  };

  // Build payload based on profile
  let payload: JTSPayload;

  if (profile === JTS_PROFILES.LITE) {
    // JTS-L: minimal payload
    payload = {
      prn,
      aid,
      tkn_id: '', // Will be overwritten if needed
      exp,
      iat: now,
    };
    
    if (aud) payload.aud = aud;
    // tkn_id is optional in JTS-L, so we delete it
    delete (payload as Partial<JTSPayload>).tkn_id;
    if (extended.grc !== undefined) payload.grc = extended.grc;
  } else {
    // JTS-S/JTS-C: full payload with tkn_id
    payload = {
      prn,
      aid,
      tkn_id: generateTokenId(),
      exp,
      iat: now,
      ...customClaims,
    };

    if (aud) payload.aud = aud;
    
    // Add extended claims if provided
    if (extended.dfp) payload.dfp = extended.dfp;
    if (extended.perm) payload.perm = extended.perm;
    if (extended.grc !== undefined) payload.grc = extended.grc;
    if (extended.org) payload.org = extended.org;
    if (extended.atm) payload.atm = extended.atm;
    if (extended.ath) payload.ath = extended.ath;
    if (extended.spl) payload.spl = extended.spl;
  }

  // Create JWS
  const headerEncoded = encodeJSON(header);
  const payloadEncoded = encodeJSON(payload);
  const signingInput = `${headerEncoded}.${payloadEncoded}`;
  
  const signature = sign(signingInput, privateKey, algorithm);
  const signatureEncoded = base64urlEncode(signature);

  return `${signingInput}.${signatureEncoded}`;
}

// ============================================================================
// BEARER PASS DECODING
// ============================================================================

/**
 * @function decodeBearerPass
 * @description Decodes a BearerPass token without verification.
 * Useful for inspecting token contents, debugging, or extracting claims
 * without performing cryptographic verification.
 * 
 * @param token - The BearerPass token to decode
 * @returns The decoded token components (header, payload, signature)
 * 
 * @example
 * ```typescript
 * const token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpUUy1TL3YxIiwia2lkIjoic2lnbmluZy1rZXkifQ.eyJwcm4iOiJ1c2VyMTIzIiwiYWlkIjoic2Vzc2lvbjQ1NiIsInRrbl9pZCI6InRrbl94eXo3ODkiLCJleHAiOjE2MTQ1MDQ0MDAsImlhdCI6MTYxNDUwNDcwMH0.signature';
 * 
 * const decoded = decodeBearerPass(token);
 * console.log(decoded.header.typ); // JTS-S/v1
 * console.log(decoded.payload.prn); // user123
 * console.log(decoded.payload.exp); // 1614504400
 * ```
 * 
 * @throws {JTSError} If the token format is invalid or decoding fails
 */
export function decodeBearerPass(token: string): DecodedToken {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new JTSError(JTS_ERRORS.MALFORMED_TOKEN, JTS_ERROR_MESSAGES.TOKEN_MUST_HAVE_3_PARTS);
  }

  try {
    const header = decodeJSON<JTSHeader>(parts[0]);
    const payload = decodeJSON<JTSPayload>(parts[1]);
    
    return {
      header,
      payload,
      signature: parts[2],
    };
  } catch (error) {
    throw new JTSError(JTS_ERRORS.MALFORMED_TOKEN, JTS_ERROR_MESSAGES.FAILED_TO_DECODE_TOKEN);
  }
}

// ============================================================================
// BEARER PASS VERIFICATION OPTIONS
// ============================================================================

/**
 * @interface VerifyBearerPassOptions
 * @description Options for verifying a BearerPass token.
 * 
 * Verification includes cryptographic signature validation, claim verification,
 * and optional checks like audience, organization, and device fingerprint.
 */
export interface VerifyBearerPassOptions {
  /**
   * @property {string} token - The BearerPass token to verify
   * The compact JWS string to be verified.
   */
  token: string;
  
  /**
   * @property {Map<string, JTSKeyPair> | JTSKeyPair[]} publicKeys - Public key(s) for verification
   * Keys used to verify the token signature, keyed by kid. Can be provided as a Map or array.
   */
  publicKeys: Map<string, JTSKeyPair> | JTSKeyPair[];
  
  /**
   * @property {string|string[]} [audience] - Expected audience
   * If provided, the token's audience claim must match one of these values.
   */
  audience?: string | string[];
  
  /**
   * @property {string} [organization] - Expected organization
   * For multi-tenant applications, verifies the token is for the expected organization.
   */
  organization?: string;
  
  /**
   * @property {number} [gracePeriodTolerance=0] - Grace period tolerance in seconds
   * Additional time to allow for token expiration, useful for clock skew compensation.
   */
  gracePeriodTolerance?: number;
  
  /**
   * @property {string} [expectedDeviceFingerprint] - Validate device fingerprint
   * If provided, the token's device fingerprint must match this value.
   */
  expectedDeviceFingerprint?: string;
  
  /**
   * @property {JTSProfile[]} [acceptedProfiles] - Accepted profiles
   * If provided, the token's profile must be in this list.
   */
  acceptedProfiles?: JTSProfile[];
  
  /**
   * @property {number} [clockSkewTolerance=0] - Clock skew tolerance in seconds
   * Additional time to allow for clock differences between systems.
   */
  clockSkewTolerance?: number;
}

/**
 * @function verifyBearerPass
 * @description Verifies a BearerPass token according to JTS specification.
 * 
 * Performs comprehensive validation including:
 * 1. Token structure and decoding
 * 2. Profile validation (if restricted)
 * 3. Key lookup and signature verification
 * 4. Required claim validation
 * 5. Expiration checking with grace period support
 * 6. Optional audience, organization, and device fingerprint validation
 * 
 * @param options - Verification options and constraints
 * @returns Verification result with payload if valid, error if invalid
 * 
 * @example
 * ```typescript
 * const result = verifyBearerPass({
 *   token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpUUy1TL3YxIiwia2lkIjoic2lnbmluZy1rZXkifQ.eyJwcm4iOiJ1c2VyMTIzIiwiYWlkIjoic2Vzc2lvbjQ1NiIsInRrbl9pZCI6InRrbl94eXo3ODkiLCJleHAiOjE2MTQ1MDQ0MDAsImlhdCI6MTYxNDUwNDcwMH0.signature',
 *   publicKeys: new Map([['signing-key', keyPair]]),
 *   audience: 'https://api.example.com',
 *   expectedDeviceFingerprint: 'sha256:abc123...'
 * });
 * 
 * if (result.valid) {
 *   console.log('Token is valid for user:', result.payload!.prn);
 * } else {
 *   console.log('Token verification failed:', result.error!.message);
 * }
 * ```
 */
export function verifyBearerPass(options: VerifyBearerPassOptions): VerificationResult {
  const {
    token,
    publicKeys,
    audience,
    organization,
    gracePeriodTolerance = 0,
    expectedDeviceFingerprint,
    acceptedProfiles,
    clockSkewTolerance = 0,
  } = options;

  try {
    // 1. Decode token
    const decoded = decodeBearerPass(token);
    const { header, payload } = decoded;

    // 2. Validate profile if restricted
    if (acceptedProfiles && !acceptedProfiles.includes(header.typ)) {
      return {
        valid: false,
        error: new JTSError(JTS_ERRORS.MALFORMED_TOKEN, JTS_ERROR_MESSAGE_HELPERS.profileNotAccepted(header.typ)),
      };
    }

    // 3. Find the appropriate key
    const keyMap = Array.isArray(publicKeys)
      ? new Map(publicKeys.map(k => [k.kid, k]))
      : publicKeys;
    
    const keyPair = keyMap.get(header.kid);
    if (!keyPair) {
      return {
        valid: false,
        error: new JTSError(JTS_ERRORS.KEY_UNAVAILABLE, JTS_ERROR_MESSAGE_HELPERS.keyNotFound(header.kid)),
      };
    }

    // 4. Verify signature
    const parts = token.split('.');
    const signingInput = `${parts[0]}.${parts[1]}`;
    const signature = base64urlDecode(parts[2]);

    const isValidSignature = verify(
      signingInput,
      signature,
      keyPair.publicKey,
      header.alg
    );

    if (!isValidSignature) {
      return {
        valid: false,
        error: new JTSError(JTS_ERRORS.SIGNATURE_INVALID, JTS_ERROR_MESSAGES.SIGNATURE_VERIFICATION_FAILED),
      };
    }

    // 5. Validate required claims
    if (!payload.prn || !payload.aid || !payload.exp || !payload.iat) {
      return {
        valid: false,
        error: new JTSError(JTS_ERRORS.MISSING_CLAIMS, JTS_ERROR_MESSAGES.MISSING_REQUIRED_CLAIMS),
      };
    }

    // 6. Validate JTS-S specific claims
    if (header.typ === JTS_PROFILES.STANDARD || header.typ === JTS_PROFILES.CONFIDENTIAL) {
      if (!payload.tkn_id) {
        return {
          valid: false,
          error: new JTSError(JTS_ERRORS.MISSING_CLAIMS, JTS_ERROR_MESSAGES.MISSING_TKN_ID_CLAIM),
        };
      }
    }

    // 7. Check expiration with grace period
    const now = Math.floor(Date.now() / 1000);
    const gracePeriod = payload.grc ?? 0;
    const effectiveGrace = Math.min(gracePeriod, gracePeriodTolerance, 60); // Max 60 seconds per spec
    const effectiveExpiry = payload.exp + effectiveGrace + clockSkewTolerance;

    if (now > effectiveExpiry) {
      return {
        valid: false,
        error: new JTSError(JTS_ERRORS.BEARER_EXPIRED, JTS_ERROR_MESSAGES.TOKEN_HAS_EXPIRED),
      };
    }

    // 8. Validate audience if specified
    if (audience) {
      const tokenAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      const expectedAud = Array.isArray(audience) ? audience : [audience];
      
      const hasValidAudience = tokenAud.some(a => expectedAud.includes(a!));
      if (!hasValidAudience) {
        return {
          valid: false,
          error: new JTSError(JTS_ERRORS.AUDIENCE_MISMATCH, JTS_ERROR_MESSAGES.AUDIENCE_MISMATCH),
        };
      }
    }

    // 9. Validate organization if specified
    if (organization && payload.org && payload.org !== organization) {
      return {
        valid: false,
        error: new JTSError(JTS_ERRORS.ORG_MISMATCH, JTS_ERROR_MESSAGES.ORGANIZATION_MISMATCH),
      };
    }

    // 10. Validate device fingerprint if specified
    if (expectedDeviceFingerprint && payload.dfp && payload.dfp !== expectedDeviceFingerprint) {
      return {
        valid: false,
        error: new JTSError(JTS_ERRORS.DEVICE_MISMATCH, JTS_ERROR_MESSAGES.DEVICE_FINGERPRINT_MISMATCH),
      };
    }

    // All validations passed
    return {
      valid: true,
      payload,
      header,
    };

  } catch (error) {
    if (error instanceof JTSError) {
      return { valid: false, error };
    }
    return {
      valid: false,
      error: new JTSError(JTS_ERRORS.MALFORMED_TOKEN, JTS_ERROR_MESSAGES.FAILED_TO_VERIFY_TOKEN),
    };
  }
}

// ============================================================================
// TOKEN UTILITY FUNCTIONS
// ============================================================================

/**
 * @function isTokenExpired
 * @description Checks if a token is expired without performing full verification.
 * Useful for quick checks before attempting to use a token.
 * 
 * @param token - The BearerPass token to check
 * @param gracePeriod - Additional grace period in seconds (default: 0)
 * @returns True if the token is expired, false otherwise
 * 
 * @example
 * ```typescript
 * const token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpUUy1TL3YxIiwia2lkIjoic2lnbmluZy1rZXkifQ.eyJwcm4iOiJ1c2VyMTIzIiwiYWlkIjoic2Vzc2lvbjQ1NiIsInRrbl9pZCI6InRrbl94eXo3ODkiLCJleHAiOjE2MTQ1MDQ0MDAsImlhdCI6MTYxNDUwNDcwMH0.signature';
 * 
 * if (isTokenExpired(token)) {
 *   console.log('Token has expired');
 * } else {
 *   console.log('Token is still valid');
 * }
 * ```
 */
export function isTokenExpired(token: string, gracePeriod: number = 0): boolean {
  try {
    const decoded = decodeBearerPass(token);
    const now = Math.floor(Date.now() / 1000);
    const tokenGrace = decoded.payload.grc ?? 0;
    const effectiveGrace = Math.min(gracePeriod, tokenGrace, 60);
    return now > decoded.payload.exp + effectiveGrace;
  } catch {
    return true;
  }
}

/**
 * @function getTokenExpiration
 * @description Gets the expiration time of a token as a Date object.
 * 
 * @param token - The BearerPass token to check
 * @returns The expiration date, or null if the token is invalid
 * 
 * @example
 * ```typescript
 * const token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpUUy1TL3YxIiwia2lkIjoic2lnbmluZy1rZXkifQ.eyJwcm4iOiJ1c2VyMTIzIiwiYWlkIjoic2Vzc2lvbjQ1NiIsInRrbl9pZCI6InRrbl94eXo3ODkiLCJleHAiOjE2MTQ1MDQ0MDAsImlhdCI6MTYxNDUwNDcwMH0.signature';
 * 
 * const expiration = getTokenExpiration(token);
 * if (expiration) {
 *   console.log('Token expires at:', expiration.toISOString());
 * }
 * ```
 */
export function getTokenExpiration(token: string): Date | null {
  try {
    const decoded = decodeBearerPass(token);
    return new Date(decoded.payload.exp * 1000);
  } catch {
    return null;
  }
}

/**
 * @function getTimeUntilExpiration
 * @description Gets the time remaining until token expiration in seconds.
 * 
 * @param token - The BearerPass token to check
 * @returns Seconds until expiration, or 0 if the token is invalid or expired
 * 
 * @example
 * ```typescript
 * const token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpUUy1TL3YxIiwia2lkIjoic2lnbmluZy1rZXkifQ.eyJwcm4iOiJ1c2VyMTIzIiwiYWlkIjoic2Vzc2lvbjQ1NiIsInRrbl9pZCI6InRrbl94eXo3ODkiLCJleHAiOjE2MTQ1MDQ0MDAsImlhdCI6MTYxNDUwNDcwMH0.signature';
 * 
 * const secondsLeft = getTimeUntilExpiration(token);
 * console.log(`Token expires in ${secondsLeft} seconds`);
 * ```
 */
export function getTimeUntilExpiration(token: string): number {
  try {
    const decoded = decodeBearerPass(token);
    const now = Math.floor(Date.now() / 1000);
    return Math.max(0, decoded.payload.exp - now);
  } catch {
    return 0;
  }
}

/**
 * @function hasPermission
 * @description Checks if a token has a specific permission.
 * 
 * @param token - The BearerPass token to check
 * @param permission - The permission to check for
 * @returns True if the token has the permission, false otherwise
 * 
 * @example
 * ```typescript
 * const token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpUUy1TL3YxIiwia2lkIjoic2lnbmluZy1rZXkifQ.eyJwcm4iOiJ1c2VyMTIzIiwiYWlkIjoic2Vzc2lvbjQ1NiIsInRrbl9pZCI6InRrbl94eXo3ODkiLCJleHAiOjE2MTQ1MDQ0MDAsImlhdCI6MTYxNDUwNDcwMCwicGVybSI6WyJyZWFkIiwid3JpdGUiXX0.signature';
 * 
 * if (hasPermission(token, 'write')) {
 *   console.log('User has write permission');
 * }
 * ```
 */
export function hasPermission(token: string, permission: string): boolean {
  try {
    const decoded = decodeBearerPass(token);
    return decoded.payload.perm?.includes(permission) ?? false;
  } catch {
    return false;
  }
}

/**
 * @function hasAllPermissions
 * @description Checks if a token has all of the specified permissions.
 * 
 * @param token - The BearerPass token to check
 * @param permissions - Array of permissions to check for
 * @returns True if the token has all permissions, false otherwise
 * 
 * @example
 * ```typescript
 * const token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpUUy1TL3YxIiwia2lkIjoic2lnbmluZy1rZXkifQ.eyJwcm4iOiJ1c2VyMTIzIiwiYWlkIjoic2Vzc2lvbjQ1NiIsInRrbl9pZCI6InRrbl94eXo3ODkiLCJleHAiOjE2MTQ1MDQ0MDAsImlhdCI6MTYxNDUwNDcwMCwicGVybSI6WyJyZWFkIiwid3JpdGUiXX0.signature';
 * 
 * if (hasAllPermissions(token, ['read', 'write'])) {
 *   console.log('User has both read and write permissions');
 * }
 * ```
 */
export function hasAllPermissions(token: string, permissions: string[]): boolean {
  try {
    const decoded = decodeBearerPass(token);
    const tokenPerms = decoded.payload.perm ?? [];
    return permissions.every(p => tokenPerms.includes(p));
  } catch {
    return false;
  }
}

/**
 * @function hasAnyPermission
 * @description Checks if a token has any of the specified permissions.
 * 
 * @param token - The BearerPass token to check
 * @param permissions - Array of permissions to check for
 * @returns True if the token has at least one of the permissions, false otherwise
 * 
 * @example
 * ```typescript
 * const token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpUUy1TL3YxIiwia2lkIjoic2lnbmluZy1rZXkifQ.eyJwcm4iOiJ1c2VyMTIzIiwiYWlkIjoic2Vzc2lvbjQ1NiIsInRrbl9pZCI6InRrbl94eXo3ODkiLCJleHAiOjE2MTQ1MDQ0MDAsImlhdCI6MTYxNDUwNDcwMCwicGVybSI6WyJyZWFkIiwid3JpdGUiXX0.signature';
 * 
 * if (hasAnyPermission(token, ['admin', 'write'])) {
 *   console.log('User has either admin or write permission');
 * }
 * ```
 */
export function hasAnyPermission(token: string, permissions: string[]): boolean {
  try {
    const decoded = decodeBearerPass(token);
    const tokenPerms = decoded.payload.perm ?? [];
    return permissions.some(p => tokenPerms.includes(p));
  } catch {
    return false;
  }
}
