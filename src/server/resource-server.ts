/**
 * jts-core - Resource Server SDK
 * Verify and validate BearerPass tokens
 */

import {
  JTSResourceServerConfig,
  JTSProfile,
  JTSKeyPair,
  JTSPayload,
  JTSHeader,
  JTSError,
  VerificationResult,
  JWKS,
  JWKSKey,
} from '../types';
import {
  verifyBearerPass,
  decodeBearerPass,
  isTokenExpired,
  getTimeUntilExpiration,
  hasPermission,
  hasAllPermissions,
  hasAnyPermission,
} from '../tokens/bearer-pass';
import {
  verifyEncryptedBearerPass,
  isEncryptedToken,
} from '../tokens/jwe';
import { jwkToPem } from '../crypto';

// ============================================================================
// JWKS CACHE
// ============================================================================

interface CachedJWKS {
  keys: Map<string, JTSKeyPair>;
  fetchedAt: number;
  etag?: string;
}

// ============================================================================
// RESOURCE SERVER CLASS
// ============================================================================

export interface ResourceServerOptions extends JTSResourceServerConfig {
  /** Decryption key for JTS-C (if needed) */
  decryptionKey?: {
    kid: string;
    privateKey: string | Buffer;
  };
}

/**
 * JTS Resource Server
 * Verifies BearerPass tokens for protected resources
 */
export class JTSResourceServer {
  private config: JTSResourceServerConfig;
  private staticKeys: Map<string, JTSKeyPair>;
  private jwksCache: CachedJWKS | null = null;
  private decryptionKey?: {
    kid: string;
    privateKey: string | Buffer;
  };

  constructor(options: ResourceServerOptions) {
    this.config = {
      acceptedProfiles: options.acceptedProfiles ?? ['JTS-L/v1', 'JTS-S/v1', 'JTS-C/v1'],
      jwksUri: options.jwksUri,
      publicKeys: options.publicKeys ?? [],
      audience: options.audience,
      gracePeriodTolerance: options.gracePeriodTolerance ?? 30,
      validateDeviceFingerprint: options.validateDeviceFingerprint ?? false,
      jwksCacheTTL: options.jwksCacheTTL ?? 3600, // 1 hour default
    };

    this.decryptionKey = options.decryptionKey;

    // Build static key map
    this.staticKeys = new Map();
    for (const key of this.config.publicKeys ?? []) {
      this.staticKeys.set(key.kid, key);
    }
  }

  // ==========================================================================
  // TOKEN VERIFICATION
  // ==========================================================================

  /**
   * Verify a BearerPass token
   */
  async verify(
    token: string,
    options: {
      audience?: string | string[];
      organization?: string;
      deviceFingerprint?: string;
      requiredPermissions?: string[];
      anyPermissions?: string[];
    } = {}
  ): Promise<VerificationResult> {
    try {
      // 1. Get public keys
      const publicKeys = await this.getPublicKeys();

      if (publicKeys.size === 0) {
        return {
          valid: false,
          error: new JTSError('JTS-500-01', 'No public keys available'),
        };
      }

      // 2. Check if encrypted (JTS-C)
      if (isEncryptedToken(token)) {
        if (!this.decryptionKey) {
          return {
            valid: false,
            error: new JTSError('JTS-500-01', 'Decryption key not configured for JTS-C tokens'),
          };
        }

        const result = verifyEncryptedBearerPass({
          token,
          decryptionKey: this.decryptionKey,
          publicKeys,
          audience: options.audience ?? this.config.audience,
          organization: options.organization,
          gracePeriodTolerance: this.config.gracePeriodTolerance,
          expectedDeviceFingerprint: this.config.validateDeviceFingerprint 
            ? options.deviceFingerprint 
            : undefined,
          acceptedProfiles: this.config.acceptedProfiles,
        });

        if (!result.valid) {
          return result;
        }

        // Check permissions
        return this.checkPermissions(result, options.requiredPermissions, options.anyPermissions);
      }

      // 3. Verify JWS token (JTS-L or JTS-S)
      const result = verifyBearerPass({
        token,
        publicKeys,
        audience: options.audience ?? this.config.audience,
        organization: options.organization,
        gracePeriodTolerance: this.config.gracePeriodTolerance,
        expectedDeviceFingerprint: this.config.validateDeviceFingerprint 
          ? options.deviceFingerprint 
          : undefined,
        acceptedProfiles: this.config.acceptedProfiles,
      });

      if (!result.valid) {
        return result;
      }

      // 4. Check permissions
      return this.checkPermissions(result, options.requiredPermissions, options.anyPermissions);

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

  /**
   * Quick check if token is expired (without full verification)
   */
  isExpired(token: string): boolean {
    return isTokenExpired(token, this.config.gracePeriodTolerance);
  }

  /**
   * Get time until token expires
   */
  getTimeUntilExpiry(token: string): number {
    return getTimeUntilExpiration(token);
  }

  /**
   * Decode token without verification (for debugging)
   */
  decode(token: string): { header: JTSHeader; payload: JTSPayload } | null {
    try {
      const decoded = decodeBearerPass(token);
      return {
        header: decoded.header,
        payload: decoded.payload,
      };
    } catch {
      return null;
    }
  }

  // ==========================================================================
  // PERMISSION CHECKING
  // ==========================================================================

  /**
   * Check if token has specific permission
   */
  tokenHasPermission(token: string, permission: string): boolean {
    return hasPermission(token, permission);
  }

  /**
   * Check if token has all permissions
   */
  tokenHasAllPermissions(token: string, permissions: string[]): boolean {
    return hasAllPermissions(token, permissions);
  }

  /**
   * Check if token has any of the permissions
   */
  tokenHasAnyPermission(token: string, permissions: string[]): boolean {
    return hasAnyPermission(token, permissions);
  }

  // ==========================================================================
  // KEY MANAGEMENT
  // ==========================================================================

  /**
   * Add a static public key
   */
  addPublicKey(key: JTSKeyPair): void {
    this.staticKeys.set(key.kid, key);
  }

  /**
   * Remove a public key
   */
  removePublicKey(kid: string): boolean {
    return this.staticKeys.delete(kid);
  }

  /**
   * Force refresh JWKS cache
   */
  async refreshJWKS(): Promise<void> {
    if (this.config.jwksUri) {
      this.jwksCache = null;
      await this.fetchJWKS();
    }
  }

  // ==========================================================================
  // PRIVATE HELPERS
  // ==========================================================================

  /**
   * Get all available public keys
   */
  private async getPublicKeys(): Promise<Map<string, JTSKeyPair>> {
    const keys = new Map(this.staticKeys);

    // Fetch from JWKS if configured
    if (this.config.jwksUri) {
      const jwksKeys = await this.fetchJWKS();
      for (const [kid, key] of jwksKeys) {
        keys.set(kid, key);
      }
    }

    return keys;
  }

  /**
   * Fetch JWKS from remote endpoint
   */
  private async fetchJWKS(): Promise<Map<string, JTSKeyPair>> {
    // Check cache
    if (this.jwksCache) {
      const age = (Date.now() - this.jwksCache.fetchedAt) / 1000;
      if (age < (this.config.jwksCacheTTL ?? 3600)) {
        return this.jwksCache.keys;
      }
    }

    if (!this.config.jwksUri) {
      return new Map();
    }

    try {
      const response = await fetch(this.config.jwksUri, {
        headers: this.jwksCache?.etag 
          ? { 'If-None-Match': this.jwksCache.etag }
          : {},
      });

      // Not modified - use cache
      if (response.status === 304 && this.jwksCache) {
        this.jwksCache.fetchedAt = Date.now();
        return this.jwksCache.keys;
      }

      if (!response.ok) {
        throw new Error(`JWKS fetch failed: ${response.status}`);
      }

      const jwks: JWKS = await response.json() as JWKS;
      const keys = new Map<string, JTSKeyPair>();

      for (const jwk of jwks.keys) {
        if (jwk.use === 'sig') {
          const pem = jwkToPem(jwk);
          keys.set(jwk.kid, {
            kid: jwk.kid,
            algorithm: jwk.alg as JTSKeyPair['algorithm'],
            publicKey: pem,
          });
        }
      }

      // Update cache
      this.jwksCache = {
        keys,
        fetchedAt: Date.now(),
        etag: response.headers.get('etag') ?? undefined,
      };

      return keys;

    } catch (error) {
      // Return cached keys if available, even if stale
      if (this.jwksCache) {
        return this.jwksCache.keys;
      }
      throw error;
    }
  }

  /**
   * Check required/optional permissions
   */
  private checkPermissions(
    result: VerificationResult,
    requiredPermissions?: string[],
    anyPermissions?: string[]
  ): VerificationResult {
    if (!result.valid || !result.payload) {
      return result;
    }

    const tokenPerms = result.payload.perm ?? [];

    // Check required permissions (all must be present)
    if (requiredPermissions && requiredPermissions.length > 0) {
      const hasAll = requiredPermissions.every(p => tokenPerms.includes(p));
      if (!hasAll) {
        return {
          valid: false,
          error: new JTSError('JTS-403-02', 'Missing required permissions'),
        };
      }
    }

    // Check any permissions (at least one must be present)
    if (anyPermissions && anyPermissions.length > 0) {
      const hasAny = anyPermissions.some(p => tokenPerms.includes(p));
      if (!hasAny) {
        return {
          valid: false,
          error: new JTSError('JTS-403-02', 'Missing required permissions'),
        };
      }
    }

    return result;
  }
}
