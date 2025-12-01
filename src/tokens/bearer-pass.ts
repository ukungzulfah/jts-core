/**
 * jts-core - BearerPass Token Handler
 * Create and verify BearerPass tokens (JWS)
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
  JTSAlgorithm,
  JTSKeyPair,
  JTSError,
  DecodedToken,
  VerificationResult,
  JTSExtendedClaims,
} from '../types';

// ============================================================================
// BEARER PASS CREATION
// ============================================================================

export interface CreateBearerPassOptions {
  /** Principal (user/entity ID) */
  prn: string;
  /** Anchor ID (session reference) */
  aid: string;
  /** Algorithm to use */
  algorithm?: JTSAlgorithm;
  /** Profile type */
  profile?: JTSProfile;
  /** Key ID */
  kid: string;
  /** Private key for signing */
  privateKey: string | Buffer;
  /** Token lifetime in seconds (default: 300) */
  expiresIn?: number;
  /** Audience */
  aud?: string | string[];
  /** Extended claims */
  extended?: Partial<JTSExtendedClaims>;
  /** Custom claims */
  customClaims?: Record<string, unknown>;
}

/**
 * Create a BearerPass token (JWS)
 */
export function createBearerPass(options: CreateBearerPassOptions): string {
  const {
    prn,
    aid,
    algorithm = 'RS256',
    profile = 'JTS-S/v1',
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

  if (profile === 'JTS-L/v1') {
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
 * Decode a BearerPass without verification
 * Useful for inspecting token contents
 */
export function decodeBearerPass(token: string): DecodedToken {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new JTSError('JTS-400-01', 'Token must have 3 parts');
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
    throw new JTSError('JTS-400-01', 'Failed to decode token');
  }
}

// ============================================================================
// BEARER PASS VERIFICATION
// ============================================================================

export interface VerifyBearerPassOptions {
  /** The BearerPass token to verify */
  token: string;
  /** Public key(s) for verification (keyed by kid) */
  publicKeys: Map<string, JTSKeyPair> | JTSKeyPair[];
  /** Expected audience (optional) */
  audience?: string | string[];
  /** Expected organization (optional, for multi-tenant) */
  organization?: string;
  /** Grace period tolerance in seconds (default: 0) */
  gracePeriodTolerance?: number;
  /** Validate device fingerprint against this value (optional) */
  expectedDeviceFingerprint?: string;
  /** Accepted profiles (default: all) */
  acceptedProfiles?: JTSProfile[];
  /** Clock skew tolerance in seconds (default: 0) */
  clockSkewTolerance?: number;
}

/**
 * Verify a BearerPass token
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
        error: new JTSError('JTS-400-01', `Profile ${header.typ} not accepted`),
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
        error: new JTSError('JTS-500-01', `Key ${header.kid} not found`),
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
        error: new JTSError('JTS-401-02', 'Signature verification failed'),
      };
    }

    // 5. Validate required claims
    if (!payload.prn || !payload.aid || !payload.exp || !payload.iat) {
      return {
        valid: false,
        error: new JTSError('JTS-400-02', 'Missing required claims'),
      };
    }

    // 6. Validate JTS-S specific claims
    if (header.typ === 'JTS-S/v1' || header.typ === 'JTS-C/v1') {
      if (!payload.tkn_id) {
        return {
          valid: false,
          error: new JTSError('JTS-400-02', 'Missing tkn_id claim for JTS-S/JTS-C'),
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
        error: new JTSError('JTS-401-01', 'Token has expired'),
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
          error: new JTSError('JTS-403-01', 'Audience mismatch'),
        };
      }
    }

    // 9. Validate organization if specified
    if (organization && payload.org && payload.org !== organization) {
      return {
        valid: false,
        error: new JTSError('JTS-403-03', 'Organization mismatch'),
      };
    }

    // 10. Validate device fingerprint if specified
    if (expectedDeviceFingerprint && payload.dfp && payload.dfp !== expectedDeviceFingerprint) {
      return {
        valid: false,
        error: new JTSError('JTS-401-06', 'Device fingerprint mismatch'),
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
      error: new JTSError('JTS-400-01', 'Failed to verify token'),
    };
  }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Check if a token is expired (without full verification)
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
 * Get token expiration time
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
 * Get time until token expires (in seconds)
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
 * Check if token has a specific permission
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
 * Check if token has all specified permissions
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
 * Check if token has any of specified permissions
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
