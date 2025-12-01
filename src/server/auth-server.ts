/**
 * @fileoverview JTS Authentication Server SDK
 * 
 * This module provides a complete, production-ready authentication server
 * implementation following the JTS (JSON Token Specification) protocol.
 * 
 * @module @engjts/auth/server
 * @version 1.0.0
 * @license MIT
 * 
 * @description
 * The JTSAuthServer class implements a stateful authentication system with:
 * - Secure session management with configurable policies
 * - BearerPass token generation and validation
 * - StateProof-based token renewal with replay attack protection
 * - Multi-profile support (JTS-L, JTS-S, JTS-C)
 * - JWKS endpoint for public key distribution
 * - Flexible session storage adapters
 * 
 * @example
 * ```typescript
 * import { JTSAuthServer, generateKeyPair } from '@engjts/auth';
 * 
 * const keyPair = await generateKeyPair('ES256');
 * const authServer = new JTSAuthServer({
 *   profile: 'JTS-S/v1',
 *   signingKey: keyPair,
 *   issuer: 'https://auth.example.com',
 * });
 * 
 * // Authenticate user
 * const tokens = await authServer.login({ prn: 'user-123' });
 * ```
 * 
 * @see {@link https://jts-spec.org} JTS Specification
 */

import {
  JTSAuthServerConfig,
  JTSProfile,
  JTS_PROFILES,
  JTSKeyPair,
  JTSSession,
  JTSPayload,
  JTSError,
  JTS_ERRORS,
  JTS_ERROR_MESSAGES,
  TokenGenerationResult,
  TokenRenewalResult,
  JTSExtendedClaims,
  JWKS,
  SessionPolicy,
} from '../types';import { SessionStore, InMemorySessionStore } from '../stores';
import { 
  createBearerPass, 
  verifyBearerPass,
} from '../tokens/bearer-pass';
import {
  createEncryptedBearerPass,
} from '../tokens/jwe';
import {
  keyPairToJwks,
} from '../crypto';

/* ============================================================================
 * TYPE DEFINITIONS & INTERFACES
 * ============================================================================ */

/**
 * Configuration options for initializing the JTS Authentication Server.
 * 
 * @interface AuthServerOptions
 * @extends {JTSAuthServerConfig}
 * 
 * @example
 * ```typescript
 * const options: AuthServerOptions = {
 *   profile: 'JTS-S/v1',
 *   signingKey: keyPair,
 *   sessionStore: new RedisSessionStore(redisClient),
 *   bearerPassLifetime: 300,
 *   stateProofLifetime: 604800,
 * };
 * ```
 */
export interface AuthServerOptions extends JTSAuthServerConfig {
  /**
   * Custom session store implementation for persistent session management.
   * If not provided, an in-memory store will be used (not recommended for production).
   * 
   * @type {SessionStore}
   * @default InMemorySessionStore
   */
  sessionStore?: SessionStore;
}

/**
 * Options for authenticating a user and creating a new session.
 * 
 * @interface LoginOptions
 * 
 * @example
 * ```typescript
 * const loginOptions: LoginOptions = {
 *   prn: 'user-12345',
 *   deviceFingerprint: 'fp_abc123',
 *   userAgent: 'Mozilla/5.0...',
 *   ipAddress: '192.168.1.1',
 *   permissions: ['read:profile', 'write:settings'],
 *   authMethod: 'mfa',
 * };
 * ```
 */
export interface LoginOptions {
  /**
   * Principal identifier - the unique user ID being authenticated.
   * This value will be embedded in the BearerPass token as the `prn` claim.
   * 
   * @type {string}
   * @required
   */
  prn: string;

  /**
   * Device fingerprint for binding the session to a specific device.
   * When provided, subsequent token renewals can validate device consistency.
   * 
   * @type {string}
   * @optional
   */
  deviceFingerprint?: string;

  /**
   * User agent string from the client's HTTP request.
   * Stored in session metadata for audit and security monitoring.
   * 
   * @type {string}
   * @optional
   */
  userAgent?: string;

  /**
   * Client IP address from the originating request.
   * Stored in session metadata for audit trails and anomaly detection.
   * 
   * @type {string}
   * @optional
   */
  ipAddress?: string;

  /**
   * Custom metadata to associate with this session.
   * Can include application-specific data such as login source, geo-location, etc.
   * 
   * @type {Record<string, unknown>}
   * @optional
   */
  metadata?: Record<string, unknown>;

  /**
   * Permission scopes to include in the BearerPass token.
   * Overrides any default permissions configured at the server level.
   * 
   * @type {string[]}
   * @optional
   */
  permissions?: string[];

  /**
   * Intended audience(s) for the generated BearerPass token.
   * Can be a single audience string or an array for multi-audience tokens.
   * 
   * @type {string | string[]}
   * @optional
   */
  audience?: string | string[];

  /**
   * Authentication method used to verify the user's identity.
   * Common values: 'pwd' (password), 'mfa' (multi-factor), 'sso' (single sign-on).
   * 
   * @type {JTSExtendedClaims['atm']}
   * @optional
   */
  authMethod?: JTSExtendedClaims['atm'];

  /**
   * Organization identifier for multi-tenant deployments.
   * Enables scoping sessions and permissions to specific tenants.
   * 
   * @type {string}
   * @optional
   */
  organization?: string;
}

/**
 * Options for renewing a BearerPass token using a StateProof.
 * 
 * @interface RenewOptions
 * 
 * @example
 * ```typescript
 * const renewOptions: RenewOptions = {
 *   stateProof: 'sp_xyz789...',
 *   deviceFingerprint: 'fp_abc123',
 *   permissions: ['read:profile'],
 * };
 * ```
 */
export interface RenewOptions {
  /**
   * The StateProof token received from a previous login or renewal.
   * This opaque token is validated against the session store.
   * 
   * @type {string}
   * @required
   */
  stateProof: string;

  /**
   * Device fingerprint for validation against the stored session.
   * If the session has a bound device fingerprint, this must match.
   * 
   * @type {string}
   * @optional
   */
  deviceFingerprint?: string;

  /**
   * Updated permission scopes for the new BearerPass token.
   * Allows dynamic permission adjustment during token renewal.
   * 
   * @type {string[]}
   * @optional
   */
  permissions?: string[];

  /**
   * Updated audience(s) for the new BearerPass token.
   * 
   * @type {string | string[]}
   * @optional
   */
  audience?: string | string[];
}

/* ============================================================================
 * AUTHENTICATION SERVER IMPLEMENTATION
 * ============================================================================ */

/**
 * JTS Authentication Server - Enterprise-grade authentication service.
 * 
 * @class JTSAuthServer
 * 
 * @description
 * The JTSAuthServer provides a complete authentication solution implementing
 * the JTS (JSON Token Specification) protocol. It manages the full lifecycle
 * of user authentication including:
 * 
 * - **Login**: Authenticates users and issues BearerPass + StateProof tokens
 * - **Token Renewal**: Securely refreshes BearerPass tokens using StateProof
 * - **Logout**: Invalidates sessions and revokes associated tokens
 * - **Session Management**: Tracks active sessions with configurable policies
 * - **Key Management**: Supports key rotation with backward compatibility
 * 
 * ## Security Features
 * 
 * - **Replay Attack Protection**: StateProof rotation prevents token reuse
 * - **Device Binding**: Optional fingerprint validation for session integrity
 * - **Session Policies**: Configurable limits (single, max:N, allow_all)
 * - **Grace Periods**: Configurable tolerance for clock skew and network latency
 * 
 * ## Profile Support
 * 
 * - `JTS-L/v1`: Lightweight profile for simple use cases
 * - `JTS-S/v1`: Standard profile with full security features (default)
 * - `JTS-C/v1`: Confidential profile with encrypted tokens
 * 
 * @example
 * ```typescript
 * // Initialize the auth server
 * const authServer = new JTSAuthServer({
 *   profile: 'JTS-S/v1',
 *   signingKey: await generateKeyPair('ES256'),
 *   issuer: 'https://auth.example.com',
 *   audience: 'https://api.example.com',
 *   bearerPassLifetime: 300,      // 5 minutes
 *   stateProofLifetime: 604800,   // 7 days
 *   sessionPolicy: 'max:5',       // Max 5 concurrent sessions
 * });
 * 
 * // Authenticate a user
 * const tokens = await authServer.login({
 *   prn: 'user-12345',
 *   deviceFingerprint: 'device-fp-hash',
 *   authMethod: 'mfa',
 * });
 * 
 * // Later: Renew the token
 * const renewed = await authServer.renew({
 *   stateProof: tokens.stateProof,
 *   deviceFingerprint: 'device-fp-hash',
 * });
 * ```
 * 
 * @see {@link AuthServerOptions} for configuration options
 * @see {@link LoginOptions} for login parameters
 * @see {@link RenewOptions} for renewal parameters
 */
export class JTSAuthServer {
  /**
   * Server configuration including profile, keys, and lifetime settings.
   * @private
   * @readonly
   */
  private config: JTSAuthServerConfig;

  /**
   * Session persistence layer for managing active user sessions.
   * @private
   * @readonly
   */
  private sessionStore: SessionStore;

  /**
   * Key registry mapping Key IDs (kid) to their corresponding key pairs.
   * Includes both current and previous keys for seamless rotation.
   * @private
   * @readonly
   */
  private allKeys: Map<string, JTSKeyPair>;

  /**
   * Creates a new JTS Authentication Server instance.
   * 
   * @constructor
   * @param {AuthServerOptions} options - Server configuration options
   * 
   * @throws {Error} If signingKey is not provided or invalid
   * 
   * @example
   * ```typescript
   * const server = new JTSAuthServer({
   *   profile: 'JTS-S/v1',
   *   signingKey: keyPair,
   *   bearerPassLifetime: 300,
   *   stateProofLifetime: 604800,
   * });
   * ```
   */
  constructor(options: AuthServerOptions) {
    this.config = {
      profile: options.profile ?? JTS_PROFILES.STANDARD,
      signingKey: options.signingKey,
      previousKeys: options.previousKeys ?? [],
      encryptionKey: options.encryptionKey,
      bearerPassLifetime: options.bearerPassLifetime ?? 300,
      stateProofLifetime: options.stateProofLifetime ?? 7 * 24 * 60 * 60,
      gracePeriod: options.gracePeriod ?? 30,
      rotationGraceWindow: options.rotationGraceWindow ?? 10,
      sessionPolicy: options.sessionPolicy ?? SessionPolicy.ALLOW_ALL,
      audience: options.audience,
      issuer: options.issuer,
    };
    // Initialize session store with fallback to in-memory implementation
    this.sessionStore = options.sessionStore ?? new InMemorySessionStore({
      rotationGraceWindow: this.config.rotationGraceWindow,
      defaultSessionLifetime: this.config.stateProofLifetime,
    });

    // Build comprehensive key registry for token verification
    this.allKeys = new Map();
    this.allKeys.set(this.config.signingKey.kid, this.config.signingKey);
    for (const key of this.config.previousKeys ?? []) {
      this.allKeys.set(key.kid, key);
    }
  }

  /* ==========================================================================
   * AUTHENTICATION METHODS
   * ========================================================================== */

  /**
   * Authenticates a user and creates a new session with associated tokens.
   * 
   * This method performs the following operations:
   * 1. Enforces the configured session policy (single, max:N, or allow_all)
   * 2. Creates a new session in the session store
   * 3. Generates a signed BearerPass token
   * 4. Returns the BearerPass, StateProof, and session metadata
   * 
   * @async
   * @param {LoginOptions} options - Login configuration and user data
   * @returns {Promise<TokenGenerationResult>} Generated tokens and session info
   * 
   * @throws {JTSError} If session policy enforcement fails
   * @throws {Error} If token generation fails
   * 
   * @example
   * ```typescript
   * const result = await authServer.login({
   *   prn: 'user-12345',
   *   deviceFingerprint: 'fp_abc123',
   *   permissions: ['read:data', 'write:data'],
   *   authMethod: 'mfa',
   * });
   * 
   * console.log(result.bearerPass);  // JWT token
   * console.log(result.stateProof);  // Opaque refresh token
   * console.log(result.expiresAt);   // Unix timestamp
   * console.log(result.sessionId);   // Anchor ID
   * ```
   */
  async login(options: LoginOptions): Promise<TokenGenerationResult> {
    const { prn, permissions, audience, authMethod, organization, ...sessionOptions } = options;

    // Step 1: Enforce session policy to manage concurrent sessions
    await this.enforceSessionPolicy(prn);

    // Step 2: Persist new session to the session store
    const session = await this.sessionStore.createSession({
      prn,
      expiresIn: this.config.stateProofLifetime,
      ...sessionOptions,
    });

    // Step 3: Generate cryptographically signed BearerPass token
    const bearerPass = this.generateBearerPass(session, {
      permissions,
      audience,
      authMethod,
      organization,
    });

    // Step 4: Assemble and return the complete token response
    return {
      bearerPass,
      stateProof: session.currentStateProof,
      expiresAt: Math.floor(Date.now() / 1000) + (this.config.bearerPassLifetime ?? 300),
      sessionId: session.aid,
    };
  }

  /* ==========================================================================
   * TOKEN RENEWAL
   * ========================================================================== */

  /**
   * Renews a BearerPass token using a valid StateProof.
   * 
   * This method implements secure token renewal with replay attack protection:
   * 1. Validates the StateProof against the session store
   * 2. Detects and handles potential replay attacks
   * 3. Optionally validates device fingerprint consistency
   * 4. Rotates the StateProof (for JTS-S and JTS-C profiles)
   * 5. Issues a fresh BearerPass token
   * 
   * ## Security Considerations
   * 
   * - **Replay Detection**: If a used StateProof is presented, the entire
   *   session is marked as compromised and all user sessions are revoked.
   * - **Grace Window**: A brief window allows for network latency where
   *   the old StateProof remains valid.
   * - **Device Binding**: When enabled, prevents token theft across devices.
   * 
   * @async
   * @param {RenewOptions} options - Renewal configuration
   * @returns {Promise<TokenRenewalResult>} New tokens and metadata
   * 
   * @throws {JTSError} SESSION_COMPROMISED - If replay attack detected
   * @throws {JTSError} STATEPROOF_INVALID - If StateProof is invalid/expired
   * @throws {JTSError} DEVICE_MISMATCH - If device fingerprint doesn't match
   * 
   * @example
   * ```typescript
   * try {
   *   const renewed = await authServer.renew({
   *     stateProof: previousTokens.stateProof,
   *     deviceFingerprint: 'fp_abc123',
   *   });
   *   // Store renewed.stateProof for next renewal
   * } catch (error) {
   *   if (error.code === 'SESSION_COMPROMISED') {
   *     // Force re-authentication
   *   }
   * }
   * ```
   */
  async renew(options: RenewOptions): Promise<TokenRenewalResult> {
    const { stateProof, deviceFingerprint, permissions, audience } = options;

    // Step 1: Validate StateProof and retrieve associated session
    const validationResult = await this.sessionStore.getSessionByStateProof(stateProof);

    if (!validationResult.valid || !validationResult.session) {
      if (validationResult.error === JTS_ERRORS.SESSION_COMPROMISED) {
        // SECURITY: Replay attack detected - immediately revoke all user sessions
        if (validationResult.session) {
          await this.sessionStore.deleteAllSessionsForPrincipal(validationResult.session.prn);
        }
        throw new JTSError(JTS_ERRORS.SESSION_COMPROMISED, JTS_ERROR_MESSAGES.SESSION_COMPROMISED_REPLAY_ATTACK);
      }
      throw new JTSError(validationResult.error ?? JTS_ERRORS.STATEPROOF_INVALID, JTS_ERROR_MESSAGES.INVALID_STATEPROOF);
    }

    const session = validationResult.session;

    // Step 2: Validate device fingerprint for session binding (JTS-S and JTS-C only)
    if (this.config.profile !== JTS_PROFILES.LITE) {
      if (session.deviceFingerprint && deviceFingerprint) {
        if (session.deviceFingerprint !== deviceFingerprint) {
          throw new JTSError(JTS_ERRORS.DEVICE_MISMATCH, JTS_ERROR_MESSAGES.DEVICE_FINGERPRINT_MISMATCH);
        }
      }
    }

    // Step 3: Handle StateProof rotation based on profile and grace window
    let newStateProof: string | undefined;
    let updatedSession = session;

    if (this.config.profile !== JTS_PROFILES.LITE && !validationResult.withinGraceWindow) {
      // Perform StateProof rotation for enhanced security
      updatedSession = await this.sessionStore.rotateStateProof(session.aid);
      newStateProof = updatedSession.currentStateProof;
    } else if (validationResult.withinGraceWindow) {
      // Grace window active - return current StateProof to handle network latency
      newStateProof = session.currentStateProof;
    }

    // Step 4: Update session activity timestamp
    await this.sessionStore.touchSession(session.aid);

    // Step 5: Generate fresh BearerPass with updated claims
    const bearerPass = this.generateBearerPass(updatedSession, {
      permissions,
      audience,
    });

    return {
      bearerPass,
      stateProof: newStateProof,
      expiresAt: Math.floor(Date.now() / 1000) + (this.config.bearerPassLifetime ?? 300),
    };
  }

  /* ==========================================================================
   * SESSION REVOCATION & LOGOUT
   * ========================================================================== */

  /**
   * Logs out a user by invalidating their session.
   * 
   * This method terminates the session associated with the provided StateProof,
   * effectively invalidating both the StateProof and any BearerPass tokens
   * that depend on this session.
   * 
   * @async
   * @param {string} stateProof - The StateProof token to invalidate
   * @returns {Promise<boolean>} True if session was successfully deleted, false otherwise
   * 
   * @example
   * ```typescript
   * const success = await authServer.logout(userStateProof);
   * if (success) {
   *   console.log('User logged out successfully');
   * }
   * ```
   */
  async logout(stateProof: string): Promise<boolean> {
    const validationResult = await this.sessionStore.getSessionByStateProof(stateProof);
    
    if (!validationResult.session) {
      return false;
    }

    return this.sessionStore.deleteSession(validationResult.session.aid);
  }

  /**
   * Revokes all active sessions for a specific principal (user).
   * 
   * Use this method for:
   * - Password changes requiring global re-authentication
   * - Account security concerns (suspected compromise)
   * - User-initiated "logout all devices" functionality
   * 
   * @async
   * @param {string} prn - The principal identifier to revoke sessions for
   * @returns {Promise<number>} The number of sessions that were revoked
   * 
   * @example
   * ```typescript
   * const revokedCount = await authServer.revokeAllSessions('user-12345');
   * console.log(`Revoked ${revokedCount} sessions`);
   * ```
   */
  async revokeAllSessions(prn: string): Promise<number> {
    return this.sessionStore.deleteAllSessionsForPrincipal(prn);
  }

  /**
   * Revokes a specific session by its anchor ID.
   * 
   * This allows targeted session revocation, useful for:
   * - Admin-initiated session termination
   * - User removing a specific device from their account
   * - Automated security policy enforcement
   * 
   * @async
   * @param {string} aid - The anchor ID (session identifier) to revoke
   * @returns {Promise<boolean>} True if session was found and deleted
   * 
   * @example
   * ```typescript
   * const revoked = await authServer.revokeSession('session-aid-xyz');
   * ```
   */
  async revokeSession(aid: string): Promise<boolean> {
    return this.sessionStore.deleteSession(aid);
  }

  /* ==========================================================================
   * SESSION QUERY & MANAGEMENT
   * ========================================================================== */

  /**
   * Retrieves all active sessions for a specific principal.
   * 
   * Useful for building "active sessions" UI where users can view
   * and manage their logged-in devices.
   * 
   * @async
   * @param {string} prn - The principal identifier to query sessions for
   * @returns {Promise<JTSSession[]>} Array of active session objects
   * 
   * @example
   * ```typescript
   * const sessions = await authServer.getSessions('user-12345');
   * sessions.forEach(session => {
   *   console.log(`Device: ${session.userAgent}, Last active: ${session.lastActiveAt}`);
   * });
   * ```
   */
  async getSessions(prn: string): Promise<JTSSession[]> {
    return this.sessionStore.getSessionsForPrincipal(prn);
  }

  /**
   * Retrieves a specific session by its anchor ID.
   * 
   * @async
   * @param {string} aid - The anchor ID (unique session identifier)
   * @returns {Promise<JTSSession | null>} The session object if found, null otherwise
   * 
   * @example
   * ```typescript
   * const session = await authServer.getSession('session-aid-xyz');
   * if (session) {
   *   console.log(`Session created at: ${session.createdAt}`);
   * }
   * ```
   */
  async getSession(aid: string): Promise<JTSSession | null> {
    return this.sessionStore.getSessionByAid(aid);
  }

  /* ==========================================================================
   * JWKS & KEY MANAGEMENT
   * ========================================================================== */

  /**
   * Returns the JSON Web Key Set (JWKS) for public key distribution.
   * 
   * The JWKS endpoint is essential for resource servers to verify
   * BearerPass tokens. It includes:
   * - Current signing key (for token verification)
   * - Previous keys (for grace period during key rotation)
   * 
   * @returns {JWKS} The complete JWKS object with all public keys
   * 
   * @example
   * ```typescript
   * // Expose via HTTP endpoint
   * app.get('/.well-known/jts-jwks', (req, res) => {
   *   res.json(authServer.getJWKS());
   * });
   * ```
   */
  getJWKS(): JWKS {
    const keys = [this.config.signingKey, ...(this.config.previousKeys ?? [])];
    return keyPairToJwks(keys);
  }

  /**
   * Returns JTS discovery metadata for automatic client configuration.
   * 
   * This implements the JTS discovery protocol, allowing clients to
   * automatically configure themselves by fetching this metadata.
   * 
   * @param {string} baseUrl - The base URL of this authentication server
   * @returns {object} JTS configuration metadata
   * 
   * @example
   * ```typescript
   * // Expose via HTTP endpoint
   * app.get('/.well-known/jts-configuration', (req, res) => {
   *   const baseUrl = `${req.protocol}://${req.get('host')}`;
   *   res.json(authServer.getConfiguration(baseUrl));
   * });
   * ```
   */
  getConfiguration(baseUrl: string): object {
    return {
      issuer: this.config.issuer ?? baseUrl,
      jwks_uri: `${baseUrl}/.well-known/jts-jwks`,
      token_endpoint: `${baseUrl}/jts/login`,
      renewal_endpoint: `${baseUrl}/jts/renew`,
      revocation_endpoint: `${baseUrl}/jts/logout`,
      supported_profiles: [this.config.profile],
      supported_algorithms: [this.config.signingKey.algorithm],
    };
  }

  /**
   * Rotates the signing key for enhanced security.
   * 
   * Key rotation is a critical security practice that limits the impact
   * of potential key compromise. This method:
   * 1. Moves the current key to the previous keys list
   * 2. Sets the new key as the active signing key
   * 3. Updates the internal key registry
   * 
   * **Important**: The previous keys are retained to allow verification
   * of tokens issued before the rotation. Only the last 2 previous keys
   * are kept to balance security and compatibility.
   * 
   * @param {JTSKeyPair} newKey - The new key pair to use for signing
   * 
   * @example
   * ```typescript
   * // Generate new key and rotate
   * const newKeyPair = await generateKeyPair('ES256');
   * authServer.rotateSigningKey(newKeyPair);
   * 
   * // Update JWKS endpoint to include new key
   * // Existing tokens remain valid until expiration
   * ```
   */
  rotateSigningKey(newKey: JTSKeyPair): void {
    // Preserve current key in the previous keys list for backward compatibility
    this.config.previousKeys = [
      this.config.signingKey,
      ...(this.config.previousKeys ?? []).slice(0, 2),
    ];
    
    // Activate the new signing key
    this.config.signingKey = newKey;
    
    // Update the key registry for token verification
    this.allKeys.set(newKey.kid, newKey);
  }

  /* ==========================================================================
   * TOKEN VERIFICATION & INTROSPECTION
   * ========================================================================== */

  /**
   * Verifies and introspects a BearerPass token.
   * 
   * This method performs cryptographic verification of the token signature
   * and validates all claims including expiration, audience, and profile.
   * 
   * Use cases:
   * - Token introspection endpoint implementation
   * - Debugging and token inspection
   * - Custom authorization logic requiring payload access
   * 
   * @param {string} token - The BearerPass token to verify
   * @returns {{ valid: boolean; payload?: JTSPayload; error?: JTSError }} Verification result
   * 
   * @example
   * ```typescript
   * const result = authServer.verifyBearerPass(token);
   * if (result.valid) {
   *   console.log('User:', result.payload?.prn);
   *   console.log('Permissions:', result.payload?.perm);
   * } else {
   *   console.error('Invalid token:', result.error?.message);
   * }
   * ```
   */
  verifyBearerPass(token: string): { valid: boolean; payload?: JTSPayload; error?: JTSError } {
    const result = verifyBearerPass({
      token,
      publicKeys: this.allKeys,
      audience: this.config.audience,
      gracePeriodTolerance: this.config.gracePeriod,
    });

    return {
      valid: result.valid,
      payload: result.payload,
      error: result.error,
    };
  }

  /* ==========================================================================
   * PRIVATE HELPER METHODS
   * ========================================================================== */

  /**
   * Generates a cryptographically signed BearerPass token for a session.
   * 
   * This internal method constructs the token payload with all required
   * and extended claims, then signs it using the configured algorithm.
   * For JTS-C profile, the token is additionally encrypted.
   * 
   * @private
   * @param {JTSSession} session - The session to generate a token for
   * @param {object} options - Additional token options
   * @returns {string} The signed (and optionally encrypted) BearerPass token
   */
  private generateBearerPass(
    session: JTSSession,
    options: {
      permissions?: string[];
      audience?: string | string[];
      authMethod?: JTSExtendedClaims['atm'];
      organization?: string;
    } = {}
  ): string {
    const extended: Partial<JTSExtendedClaims> = {
      grc: this.config.gracePeriod,
      spl: this.config.sessionPolicy as JTSExtendedClaims['spl'],
    };
    if (session.deviceFingerprint) {
      extended.dfp = session.deviceFingerprint;
    }
    if (options.permissions) {
      extended.perm = options.permissions;
    }
    if (options.authMethod) {
      extended.atm = options.authMethod;
    }
    if (options.organization) {
      extended.org = options.organization;
    }

    const baseOptions = {
      prn: session.prn,
      aid: session.aid,
      algorithm: this.config.signingKey.algorithm,
      profile: this.config.profile,
      kid: this.config.signingKey.kid,
      privateKey: this.config.signingKey.privateKey!,
      expiresIn: this.config.bearerPassLifetime,
      aud: options.audience ?? this.config.audience,
      extended,
    };

    // JTS-C Profile: Apply JWE encryption for confidential tokens
    if (this.config.profile === JTS_PROFILES.CONFIDENTIAL && this.config.encryptionKey) {
      return createEncryptedBearerPass({
        ...baseOptions,
        encryptionKey: {
          kid: this.config.encryptionKey.kid,
          publicKey: this.config.encryptionKey.publicKey,
        },
      });
    }

    return createBearerPass(baseOptions);
  }

  /**
   * Enforces the configured session policy for a principal.
   * 
   * Session policies control concurrent session behavior:
   * - `allow_all`: No limits on concurrent sessions
   * - `single`: Only one active session allowed (previous revoked)
   * - `max:N`: Maximum N concurrent sessions (oldest removed when exceeded)
   * 
   * @private
   * @async
   * @param {string} prn - The principal identifier to enforce policy for
   */
  private async enforceSessionPolicy(prn: string): Promise<void> {
    const policy = this.config.sessionPolicy ?? SessionPolicy.ALLOW_ALL;

    if (policy === SessionPolicy.ALLOW_ALL) {
      return;
    }
    const sessionCount = await this.sessionStore.countSessionsForPrincipal(prn);

    if (policy === 'single') {
      if (sessionCount > 0) {
        await this.sessionStore.deleteAllSessionsForPrincipal(prn);
      }
    } else if (policy.startsWith('max:')) {
      const maxSessions = parseInt(policy.split(':')[1], 10);
      while (sessionCount >= maxSessions) {
        await this.sessionStore.deleteOldestSessionForPrincipal(prn);
      }
    }
  }

  /**
   * Returns the underlying session store for advanced operations.
   * 
   * **Warning**: Direct access to the session store bypasses the
   * server's security logic. Use with caution.
   * 
   * @returns {SessionStore} The session store instance
   */
  getSessionStore(): SessionStore {
    return this.sessionStore;
  }

  /**
   * Returns the currently configured JTS profile.
   * 
   * @returns {JTSProfile} The active profile ('JTS-L/v1', 'JTS-S/v1', or 'JTS-C/v1')
   */
  getProfile(): JTSProfile {
    return this.config.profile;
  }

  /**
   * Performs a health check on the authentication server.
   * 
   * Verifies connectivity to the session store and overall server health.
   * Useful for Kubernetes liveness/readiness probes.
   * 
   * @async
   * @returns {Promise<boolean>} True if the server is healthy
   * 
   * @example
   * ```typescript
   * app.get('/health', async (req, res) => {
   *   const healthy = await authServer.healthCheck();
   *   res.status(healthy ? 200 : 503).json({ healthy });
   * });
   * ```
   */
  async healthCheck(): Promise<boolean> {
    return this.sessionStore.healthCheck();
  }

  /**
   * Cleans up expired sessions from the session store.
   * 
   * This method should be called periodically (e.g., via cron job)
   * to remove expired sessions and free up storage resources.
   * 
   * @async
   * @returns {Promise<number>} The number of expired sessions removed
   * 
   * @example
   * ```typescript
   * // Run cleanup every hour
   * setInterval(async () => {
   *   const removed = await authServer.cleanup();
   *   console.log(`Cleaned up ${removed} expired sessions`);
   * }, 60 * 60 * 1000);
   * ```
   */
  async cleanup(): Promise<number> {
    return this.sessionStore.cleanupExpiredSessions();
  }

  /**
   * Gracefully shuts down the authentication server.
   * 
   * Closes all connections to the session store and releases resources.
   * Should be called during application shutdown.
   * 
   * @async
   * @returns {Promise<void>}
   * 
   * @example
   * ```typescript
   * process.on('SIGTERM', async () => {
   *   await authServer.close();
   *   process.exit(0);
   * });
   * ```
   */
  async close(): Promise<void> {
    await this.sessionStore.close();
  }
}
