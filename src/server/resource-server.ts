/**
 * @fileoverview JTS Resource Server SDK
 * @module @engjts/auth/server/resource-server
 * 
 * This module provides a comprehensive Resource Server implementation for the JTS (JSON Token Standard)
 * authentication system. It handles verification and validation of BearerPass tokens across all JTS profiles:
 * - JTS-L/v1: Long-lived tokens with standard JWT structure
 * - JTS-S/v1: Short-lived session tokens for enhanced security
 * - JTS-C/v1: Confidential tokens with JWE encryption layer
 * 
 * Key Features:
 * - Multi-profile token verification with automatic format detection
 * - JWKS (JSON Web Key Set) integration with intelligent caching
 * - Permission-based access control with granular validation
 * - Device fingerprint verification for enhanced security
 * - Graceful expiration handling with configurable tolerance
 * - Static and dynamic public key management
 * 
 * @see {@link https://jts-spec.org} for JTS specification details
 * @version 1.0.0
 * @license MIT
 */

import {
  JTSResourceServerConfig,
  JTSProfile,
  JTS_PROFILES,
  JTSKeyPair,
  JTSPayload,
  JTSHeader,
  JTSError,
  JTS_ERRORS,
  JTS_ERROR_MESSAGES,
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
// JWKS CACHE INTERFACE
// ============================================================================
// This section defines the structure for caching JWKS (JSON Web Key Set) data
// to minimize remote endpoint calls and improve performance.

/**
 * Represents a cached JWKS response with metadata for cache management.
 * 
 * This interface stores the fetched public keys along with cache control information
 * to implement efficient cache invalidation strategies using TTL and ETag mechanisms.
 * 
 * @interface CachedJWKS
 * @internal
 */
interface CachedJWKS {
  /** Map of key ID (kid) to JTS key pairs containing public keys */
  keys: Map<string, JTSKeyPair>;

  /** Unix timestamp (milliseconds) when the JWKS was fetched */
  fetchedAt: number;

  /** HTTP ETag header value for conditional requests (304 Not Modified support) */
  etag?: string;
}

// ============================================================================
// RESOURCE SERVER CONFIGURATION & CLASS
// ============================================================================
// This section defines the Resource Server class and its configuration options
// for token verification, key management, and security policies.

/**
 * Configuration options for initializing a JTS Resource Server instance.
 * 
 * Extends the base JTSResourceServerConfig with additional options specific to
 * the Resource Server implementation, including support for encrypted tokens.
 * 
 * @interface ResourceServerOptions
 * @extends {JTSResourceServerConfig}
 * @public
 */
export interface ResourceServerOptions extends JTSResourceServerConfig {
  /**
   * Optional decryption key configuration for handling JTS-C (Confidential) encrypted tokens.
   * 
   * Required when your application needs to verify JWE-encrypted tokens. The private key
   * must correspond to a public key that the Authorization Server uses for encryption.
   * 
   * @property {string} kid - Key ID that matches the encryption key used by Auth Server
   * @property {string | Buffer} privateKey - PEM-encoded RSA private key for decryption
   */
  decryptionKey?: {
    kid: string;
    privateKey: string | Buffer;
  };
}

/**
 * Primary Resource Server class for verifying and validating JTS BearerPass tokens.
 * 
 * This class serves as the main entry point for token verification in resource server applications.
 * It orchestrates the entire verification process including:
 * - Token format detection (JWS vs JWE)
 * - Cryptographic signature/encryption verification
 * - Claims validation (audience, organization, expiration)
 * - Permission-based authorization checks
 * - Public key retrieval and caching from JWKS endpoints
 * 
 * The Resource Server supports both static key configuration and dynamic key discovery
 * via JWKS URIs, with intelligent caching to minimize network overhead.
 * 
 * @class JTSResourceServer
 * @public
 * 
 * @example
 * ```typescript
 * const server = new JTSResourceServer({
 *   jwksUri: 'https://auth.example.com/.well-known/jwks.json',
 *   audience: 'https://api.example.com',
 *   acceptedProfiles: ['JTS-S/v1', 'JTS-L/v1'],
 *   gracePeriodTolerance: 30,
 * });
 * 
 * const result = await server.verify(token, {
 *   audience: 'https://api.example.com',
 *   requiredPermissions: ['read:users'],
 * });
 * 
 * if (result.valid) {
 *   console.log('Token is valid:', result.payload);
 * } else {
 *   console.error('Verification failed:', result.error);
 * }
 * ```
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
      acceptedProfiles: options.acceptedProfiles ?? [JTS_PROFILES.LITE, JTS_PROFILES.STANDARD, JTS_PROFILES.CONFIDENTIAL],
      jwksUri: options.jwksUri,
      publicKeys: options.publicKeys ?? [],
      audience: options.audience,
      gracePeriodTolerance: options.gracePeriodTolerance ?? 30,
      validateDeviceFingerprint: options.validateDeviceFingerprint ?? false,
      jwksCacheTTL: options.jwksCacheTTL ?? 3600, // 1 hour default
    };

    this.decryptionKey = options.decryptionKey;

    // Initialize static public key map from configuration
    // These keys are immediately available and don't require remote fetching
    this.staticKeys = new Map();
    for (const key of this.config.publicKeys ?? []) {
      this.staticKeys.set(key.kid, key);
    }
  }

  // ==========================================================================
  // PUBLIC API - TOKEN VERIFICATION METHODS
  // ==========================================================================
  // These methods provide the primary interface for token verification and validation.
  // They handle both encrypted (JWE) and signed (JWS) token formats automatically.

  /**
   * Verifies a BearerPass token with comprehensive validation.
   * 
   * This method performs complete token verification including:
   * 1. Automatic detection of token format (JWE for JTS-C, JWS for JTS-L/S)
   * 2. Cryptographic signature/encryption verification using public keys
   * 3. Claims validation (issuer, audience, expiration, organization)
   * 4. Device fingerprint verification (if enabled)
   * 5. Permission-based authorization checks
   * 
   * The method automatically retrieves public keys from configured sources:
   * - Static keys provided during initialization
   * - Dynamic keys fetched from JWKS URI (with caching)
   * 
   * @async
   * @param {string} token - The BearerPass token to verify (JWT/JWE format)
   * @param {Object} options - Verification options to customize validation behavior
   * @param {string | string[]} [options.audience] - Expected audience claim(s) to validate
   * @param {string} [options.organization] - Expected organization claim to validate
   * @param {string} [options.deviceFingerprint] - Expected device fingerprint for binding validation
   * @param {string[]} [options.requiredPermissions] - Permissions that must ALL be present in token
   * @param {string[]} [options.anyPermissions] - Permissions where at least ONE must be present
   * 
   * @returns {Promise<VerificationResult>} Result object containing validation status, payload, and any errors
   * @returns {boolean} result.valid - Whether the token passed all verification checks
   * @returns {JTSPayload} [result.payload] - Decoded token payload (only if valid)
   * @returns {JTSHeader} [result.header] - Decoded token header (only if valid)
   * @returns {JTSError} [result.error] - Error details (only if invalid)
   * 
   * @throws {JTSError} Does not throw - all errors are returned in the result object
   * 
   * @example
   * ```typescript
   * // Basic verification
   * const result = await server.verify(token);
   * 
   * // With audience and permission checks
   * const result = await server.verify(token, {
   *   audience: 'https://api.example.com',
   *   requiredPermissions: ['read:users', 'write:users'],
   * });
   * 
   * // With device binding
   * const result = await server.verify(token, {
   *   deviceFingerprint: computedFingerprint,
   * });
   * ```
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
      // Step 1: Retrieve all available public keys (static + JWKS)
      // This ensures we have the necessary keys for signature verification
      const publicKeys = await this.getPublicKeys();

      if (publicKeys.size === 0) {
        return {
          valid: false,
          error: new JTSError(JTS_ERRORS.KEY_UNAVAILABLE, JTS_ERROR_MESSAGES.NO_PUBLIC_KEYS_AVAILABLE),
        };
      }

      // Step 2: Detect token format and route to appropriate verification method
      // JTS-C tokens use JWE encryption and require decryption before verification
      if (isEncryptedToken(token)) {
        if (!this.decryptionKey) {
          return {
            valid: false,
            error: new JTSError(JTS_ERRORS.KEY_UNAVAILABLE, JTS_ERROR_MESSAGES.DECRYPTION_KEY_NOT_CONFIGURED),
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

        // Step 2b: Validate permissions after successful decryption and verification
        return this.checkPermissions(result, options.requiredPermissions, options.anyPermissions);
      }

      // Step 3: Verify standard JWS tokens (JTS-L and JTS-S profiles)
      // These tokens use digital signatures without encryption
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

      // Step 4: Validate permissions after successful signature verification
      return this.checkPermissions(result, options.requiredPermissions, options.anyPermissions);

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

  /**
   * Performs a quick expiration check without full cryptographic verification.
   * 
   * This method provides a lightweight way to check token expiration before performing
   * expensive cryptographic operations. Useful for early rejection of expired tokens.
   * 
   * Note: This only checks expiration and does NOT verify signatures or other claims.
   * Always use verify() for complete validation before granting access.
   * 
   * @param {string} token - The BearerPass token to check
   * @returns {boolean} True if the token is expired, false otherwise
   * 
   * @example
   * ```typescript
   * if (server.isExpired(token)) {
   *   return res.status(401).json({ error: 'Token expired' });
   * }
   * // Proceed with full verification
   * const result = await server.verify(token);
   * ```
   */
  isExpired(token: string): boolean {
    return isTokenExpired(token, this.config.gracePeriodTolerance);
  }

  /**
   * Calculates the remaining time until token expiration.
   * 
   * Returns the number of seconds until the token's 'exp' (expiration) claim.
   * Negative values indicate the token has already expired.
   * 
   * @param {string} token - The BearerPass token to analyze
   * @returns {number} Seconds until expiration (negative if already expired)
   * 
   * @example
   * ```typescript
   * const timeLeft = server.getTimeUntilExpiry(token);
   * if (timeLeft < 300) {
   *   console.log('Token expires in less than 5 minutes');
   * }
   * ```
   */
  getTimeUntilExpiry(token: string): number {
    return getTimeUntilExpiration(token);
  }

  /**
   * Decodes a token to extract header and payload WITHOUT cryptographic verification.
   * 
   * WARNING: This method does NOT verify signatures or validate claims. The returned
   * data should NEVER be trusted for authorization decisions. Use verify() instead.
   * 
   * This is primarily useful for:
   * - Debugging and development
   * - Logging token metadata
   * - Inspecting token structure before verification
   * 
   * @param {string} token - The BearerPass token to decode
   * @returns {{ header: JTSHeader; payload: JTSPayload } | null} Decoded token parts or null if malformed
   * 
   * @example
   * ```typescript
   * const decoded = server.decode(token);
   * if (decoded) {
   *   console.log('Token issuer:', decoded.payload.iss);
   *   console.log('Token subject:', decoded.payload.sub);
   * }
   * ```
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
  // PUBLIC API - PERMISSION VALIDATION METHODS
  // ==========================================================================
  // These convenience methods provide quick permission checks on tokens.
  // They internally decode the token and examine the 'perm' claim array.

  /**
   * Checks if a token contains a specific permission.
   * 
   * Note: This method only checks the 'perm' claim in the token payload.
   * It does NOT perform signature verification. Use verify() with requiredPermissions
   * for secure permission checking.
   * 
   * @param {string} token - The BearerPass token to check
   * @param {string} permission - The permission string to look for
   * @returns {boolean} True if the permission exists in the token's 'perm' claim
   * 
   * @example
   * ```typescript
   * if (server.tokenHasPermission(token, 'read:users')) {
   *   // Token claims to have read:users permission
   * }
   * ```
   */
  tokenHasPermission(token: string, permission: string): boolean {
    return hasPermission(token, permission);
  }

  /**
   * Checks if a token contains all specified permissions.
   * 
   * All permissions in the array must be present in the token's 'perm' claim.
   * 
   * Note: This method only checks the 'perm' claim without signature verification.
   * Use verify() with requiredPermissions for secure permission checking.
   * 
   * @param {string} token - The BearerPass token to check
   * @param {string[]} permissions - Array of permissions that must all be present
   * @returns {boolean} True if ALL permissions exist in the token's 'perm' claim
   * 
   * @example
   * ```typescript
   * const requiredPerms = ['read:users', 'write:users', 'delete:users'];
   * if (server.tokenHasAllPermissions(token, requiredPerms)) {
   *   // Token has full user management permissions
   * }
   * ```
   */
  tokenHasAllPermissions(token: string, permissions: string[]): boolean {
    return hasAllPermissions(token, permissions);
  }

  /**
   * Checks if a token contains at least one of the specified permissions.
   * 
   * Returns true if ANY of the permissions in the array exist in the token's 'perm' claim.
   * 
   * Note: This method only checks the 'perm' claim without signature verification.
   * Use verify() with anyPermissions for secure permission checking.
   * 
   * @param {string} token - The BearerPass token to check
   * @param {string[]} permissions - Array of permissions where at least one must be present
   * @returns {boolean} True if at least ONE permission exists in the token's 'perm' claim
   * 
   * @example
   * ```typescript
   * const readPerms = ['read:users', 'read:admins', 'read:all'];
   * if (server.tokenHasAnyPermission(token, readPerms)) {
   *   // Token has at least one read permission
   * }
   * ```
   */
  tokenHasAnyPermission(token: string, permissions: string[]): boolean {
    return hasAnyPermission(token, permissions);
  }

  // ==========================================================================
  // PUBLIC API - KEY MANAGEMENT METHODS
  // ==========================================================================
  // These methods allow runtime management of public keys for token verification.
  // Useful for key rotation, adding trusted issuers, or testing scenarios.

  /**
   * Adds a new public key to the static key collection.
   * 
   * This key will be immediately available for token verification and will persist
   * for the lifetime of the ResourceServer instance. Static keys take precedence
   * over JWKS-fetched keys when key IDs match.
   * 
   * @param {JTSKeyPair} key - The public key pair to add (must include kid and publicKey)
   * 
   * @example
   * ```typescript
   * server.addPublicKey({
   *   kid: 'key-2024-01',
   *   algorithm: 'RS256',
   *   publicKey: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
   * });
   * ```
   */
  addPublicKey(key: JTSKeyPair): void {
    this.staticKeys.set(key.kid, key);
  }

  /**
   * Removes a public key from the static key collection.
   * 
   * Note: This only removes static keys added via constructor or addPublicKey().
   * It does NOT affect keys cached from JWKS endpoints.
   * 
   * @param {string} kid - The key ID of the public key to remove
   * @returns {boolean} True if the key was found and removed, false otherwise
   * 
   * @example
   * ```typescript
   * if (server.removePublicKey('deprecated-key-2023')) {
   *   console.log('Key successfully removed');
   * }
   * ```
   */
  removePublicKey(kid: string): boolean {
    return this.staticKeys.delete(kid);
  }

  /**
   * Forces an immediate refresh of the JWKS cache.
   * 
   * Clears the current cache and fetches fresh keys from the JWKS URI.
   * Useful for scenarios like:
   * - Key rotation events
   * - Recovery from verification failures
   * - Manual cache invalidation
   * 
   * If no JWKS URI is configured, this method has no effect.
   * 
   * @async
   * @returns {Promise<void>}
   * 
   * @example
   * ```typescript
   * // Force refresh after key rotation
   * await server.refreshJWKS();
   * const result = await server.verify(newToken);
   * ```
   */
  async refreshJWKS(): Promise<void> {
    if (this.config.jwksUri) {
      this.jwksCache = null;
      await this.fetchJWKS();
    }
  }

  // ==========================================================================
  // PRIVATE HELPER METHODS
  // ==========================================================================
  // Internal methods for key retrieval, JWKS management, and permission validation.
  // These methods are not part of the public API and should not be called directly.

  /**
   * Retrieves all available public keys from static and JWKS sources.
   * 
   * This method aggregates keys from two sources:
   * 1. Static keys configured during initialization or added via addPublicKey()
   * 2. Dynamic keys fetched from the JWKS URI (if configured)
   * 
   * Static keys take precedence when key IDs overlap.
   * 
   * @private
   * @async
   * @returns {Promise<Map<string, JTSKeyPair>>} Map of all available public keys indexed by kid
   */
  private async getPublicKeys(): Promise<Map<string, JTSKeyPair>> {
    const keys = new Map(this.staticKeys);

    // Augment static keys with dynamically fetched JWKS keys
    if (this.config.jwksUri) {
      const jwksKeys = await this.fetchJWKS();
      for (const [kid, key] of jwksKeys) {
        keys.set(kid, key);
      }
    }

    return keys;
  }

  /**
   * Fetches public keys from the JWKS URI with intelligent caching.
   * 
   * Implements a multi-layered caching strategy:
   * 1. TTL-based cache (default 1 hour) to minimize network requests
   * 2. ETag-based conditional requests (304 Not Modified) to reduce bandwidth
   * 3. Stale-while-revalidate pattern for resilience during fetch failures
   * 
   * The method will:
   * - Return cached keys if within TTL
   * - Use ETag for conditional requests to save bandwidth
   * - Convert JWK format to PEM format for cryptographic operations
   * - Return stale cache on fetch failure for high availability
   * 
   * @private
   * @async
   * @returns {Promise<Map<string, JTSKeyPair>>} Map of public keys fetched from JWKS
   * @throws {Error} Only throws if fetch fails AND no cached keys are available
   */
  private async fetchJWKS(): Promise<Map<string, JTSKeyPair>> {
    // Check if cached keys are still fresh (within TTL)
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

      // HTTP 304 Not Modified - server indicates our cached version is current
      // Update fetchedAt timestamp to extend the TTL window
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

      // Store fetched keys with metadata for future cache decisions
      this.jwksCache = {
        keys,
        fetchedAt: Date.now(),
        etag: response.headers.get('etag') ?? undefined,
      };

      return keys;

    } catch (error) {
      // Fallback to stale cache for resilience during network failures
      // Better to use older keys than to fail completely
      if (this.jwksCache) {
        return this.jwksCache.keys;
      }
      throw error;
    }
  }

  /**
   * Validates token permissions against required and optional permission sets.
   * 
   * Implements two validation modes:
   * 1. Required permissions (all must be present) - AND logic
   * 2. Any permissions (at least one must be present) - OR logic
   * 
   * Both checks can be combined for complex authorization scenarios.
   * 
   * @private
   * @param {VerificationResult} result - The verification result containing token payload
   * @param {string[]} [requiredPermissions] - Permissions that must ALL be present
   * @param {string[]} [anyPermissions] - Permissions where at least ONE must be present
   * @returns {VerificationResult} Updated result with permission validation status
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

    if (requiredPermissions && requiredPermissions.length > 0) {
      const hasAll = requiredPermissions.every(p => tokenPerms.includes(p));
      if (!hasAll) {
        return {
          valid: false,
          error: new JTSError(JTS_ERRORS.PERMISSION_DENIED, JTS_ERROR_MESSAGES.MISSING_REQUIRED_PERMISSIONS),
        };
      }
    }

    if (anyPermissions && anyPermissions.length > 0) {
      const hasAny = anyPermissions.some(p => tokenPerms.includes(p));
      if (!hasAny) {
        return {
          valid: false,
          error: new JTSError(JTS_ERRORS.PERMISSION_DENIED, JTS_ERROR_MESSAGES.MISSING_REQUIRED_PERMISSIONS),
        };
      }
    }

    return result;
  }
}
