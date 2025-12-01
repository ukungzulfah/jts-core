/**
 * jts-core - Auth Server SDK
 * Complete authentication server implementation
 */

import {
  JTSAuthServerConfig,
  JTSProfile,
  JTSKeyPair,
  JTSSession,
  JTSPayload,
  JTSError,
  TokenGenerationResult,
  TokenRenewalResult,
  JTSExtendedClaims,
  JWKS,
} from '../types';
import { SessionStore, InMemorySessionStore } from '../stores';
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

// ============================================================================
// INTERFACES
// ============================================================================

export interface AuthServerOptions extends JTSAuthServerConfig {
  /** Session store instance */
  sessionStore?: SessionStore;
}

export interface LoginOptions {
  /** Principal (user ID) */
  prn: string;
  /** Device fingerprint (optional) */
  deviceFingerprint?: string;
  /** User agent string (optional) */
  userAgent?: string;
  /** Client IP address (optional) */
  ipAddress?: string;
  /** Custom session metadata */
  metadata?: Record<string, unknown>;
  /** Override permissions */
  permissions?: string[];
  /** Override audience */
  audience?: string | string[];
  /** Auth method used */
  authMethod?: JTSExtendedClaims['atm'];
  /** Organization (for multi-tenant) */
  organization?: string;
}

export interface RenewOptions {
  /** StateProof token */
  stateProof: string;
  /** Device fingerprint for validation (optional) */
  deviceFingerprint?: string;
  /** Override permissions */
  permissions?: string[];
  /** Override audience */
  audience?: string | string[];
}

// ============================================================================
// AUTH SERVER CLASS
// ============================================================================

/**
 * JTS Authentication Server
 * Handles login, token generation, renewal, and logout
 */
export class JTSAuthServer {
  private config: JTSAuthServerConfig;
  private sessionStore: SessionStore;
  private allKeys: Map<string, JTSKeyPair>;

  constructor(options: AuthServerOptions) {
    this.config = {
      profile: options.profile ?? 'JTS-S/v1',
      signingKey: options.signingKey,
      previousKeys: options.previousKeys ?? [],
      encryptionKey: options.encryptionKey,
      bearerPassLifetime: options.bearerPassLifetime ?? 300, // 5 minutes
      stateProofLifetime: options.stateProofLifetime ?? 7 * 24 * 60 * 60, // 7 days
      gracePeriod: options.gracePeriod ?? 30,
      rotationGraceWindow: options.rotationGraceWindow ?? 10,
      sessionPolicy: options.sessionPolicy ?? 'allow_all',
      audience: options.audience,
      issuer: options.issuer,
    };

    this.sessionStore = options.sessionStore ?? new InMemorySessionStore({
      rotationGraceWindow: this.config.rotationGraceWindow,
      defaultSessionLifetime: this.config.stateProofLifetime,
    });

    // Build key map for verification
    this.allKeys = new Map();
    this.allKeys.set(this.config.signingKey.kid, this.config.signingKey);
    for (const key of this.config.previousKeys ?? []) {
      this.allKeys.set(key.kid, key);
    }
  }

  // ==========================================================================
  // AUTHENTICATION (LOGIN)
  // ==========================================================================

  /**
   * Authenticate user and create new session
   */
  async login(options: LoginOptions): Promise<TokenGenerationResult> {
    const { prn, permissions, audience, authMethod, organization, ...sessionOptions } = options;

    // 1. Check session policy
    await this.enforceSessionPolicy(prn);

    // 2. Create session
    const session = await this.sessionStore.createSession({
      prn,
      expiresIn: this.config.stateProofLifetime,
      ...sessionOptions,
    });

    // 3. Generate BearerPass
    const bearerPass = this.generateBearerPass(session, {
      permissions,
      audience,
      authMethod,
      organization,
    });

    // 4. Return tokens
    return {
      bearerPass,
      stateProof: session.currentStateProof,
      expiresAt: Math.floor(Date.now() / 1000) + (this.config.bearerPassLifetime ?? 300),
      sessionId: session.aid,
    };
  }

  // ==========================================================================
  // TOKEN RENEWAL
  // ==========================================================================

  /**
   * Renew BearerPass using StateProof
   */
  async renew(options: RenewOptions): Promise<TokenRenewalResult> {
    const { stateProof, deviceFingerprint, permissions, audience } = options;

    // 1. Validate StateProof
    const validationResult = await this.sessionStore.getSessionByStateProof(stateProof);

    if (!validationResult.valid || !validationResult.session) {
      if (validationResult.error === 'JTS-401-05') {
        // Replay attack detected - revoke all sessions for this user
        if (validationResult.session) {
          await this.sessionStore.deleteAllSessionsForPrincipal(validationResult.session.prn);
        }
        throw new JTSError('JTS-401-05', 'Session compromised - replay attack detected');
      }
      throw new JTSError(validationResult.error ?? 'JTS-401-03', 'Invalid StateProof');
    }

    const session = validationResult.session;

    // 2. Validate device fingerprint if configured
    if (this.config.profile !== 'JTS-L/v1') {
      if (session.deviceFingerprint && deviceFingerprint) {
        if (session.deviceFingerprint !== deviceFingerprint) {
          throw new JTSError('JTS-401-06', 'Device fingerprint mismatch');
        }
      }
    }

    // 3. Rotate StateProof (for JTS-S and JTS-C)
    let newStateProof: string | undefined;
    let updatedSession = session;

    if (this.config.profile !== 'JTS-L/v1' && !validationResult.withinGraceWindow) {
      // Rotate StateProof
      updatedSession = await this.sessionStore.rotateStateProof(session.aid);
      newStateProof = updatedSession.currentStateProof;
    } else if (validationResult.withinGraceWindow) {
      // Within grace window - return existing StateProof
      newStateProof = session.currentStateProof;
    }

    // 4. Update last active
    await this.sessionStore.touchSession(session.aid);

    // 5. Generate new BearerPass
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

  // ==========================================================================
  // LOGOUT / REVOCATION
  // ==========================================================================

  /**
   * Logout and invalidate session
   */
  async logout(stateProof: string): Promise<boolean> {
    const validationResult = await this.sessionStore.getSessionByStateProof(stateProof);
    
    if (!validationResult.session) {
      return false;
    }

    return this.sessionStore.deleteSession(validationResult.session.aid);
  }

  /**
   * Revoke all sessions for a principal
   */
  async revokeAllSessions(prn: string): Promise<number> {
    return this.sessionStore.deleteAllSessionsForPrincipal(prn);
  }

  /**
   * Revoke specific session by anchor ID
   */
  async revokeSession(aid: string): Promise<boolean> {
    return this.sessionStore.deleteSession(aid);
  }

  // ==========================================================================
  // SESSION MANAGEMENT
  // ==========================================================================

  /**
   * Get all active sessions for a principal
   */
  async getSessions(prn: string): Promise<JTSSession[]> {
    return this.sessionStore.getSessionsForPrincipal(prn);
  }

  /**
   * Get session by anchor ID
   */
  async getSession(aid: string): Promise<JTSSession | null> {
    return this.sessionStore.getSessionByAid(aid);
  }

  // ==========================================================================
  // JWKS / KEY MANAGEMENT
  // ==========================================================================

  /**
   * Get JWKS for public key distribution
   */
  getJWKS(): JWKS {
    const keys = [this.config.signingKey, ...(this.config.previousKeys ?? [])];
    return keyPairToJwks(keys);
  }

  /**
   * Get JTS configuration metadata
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
   * Add a new signing key (for rotation)
   */
  rotateSigningKey(newKey: JTSKeyPair): void {
    // Move current key to previous
    this.config.previousKeys = [
      this.config.signingKey,
      ...(this.config.previousKeys ?? []).slice(0, 2), // Keep last 2
    ];
    
    // Set new key
    this.config.signingKey = newKey;
    
    // Update key map
    this.allKeys.set(newKey.kid, newKey);
  }

  // ==========================================================================
  // TOKEN VERIFICATION (for introspection)
  // ==========================================================================

  /**
   * Verify a BearerPass token
   * Useful for introspection endpoint
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

  // ==========================================================================
  // PRIVATE HELPERS
  // ==========================================================================

  /**
   * Generate a BearerPass for a session
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
      spl: this.config.sessionPolicy,
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

    // For JTS-C, create encrypted token
    if (this.config.profile === 'JTS-C/v1' && this.config.encryptionKey) {
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
   * Enforce session policy
   */
  private async enforceSessionPolicy(prn: string): Promise<void> {
    const policy = this.config.sessionPolicy ?? 'allow_all';

    if (policy === 'allow_all') {
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
   * Get session store for direct access
   */
  getSessionStore(): SessionStore {
    return this.sessionStore;
  }

  /**
   * Get current profile
   */
  getProfile(): JTSProfile {
    return this.config.profile;
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    return this.sessionStore.healthCheck();
  }

  /**
   * Cleanup expired sessions
   */
  async cleanup(): Promise<number> {
    return this.sessionStore.cleanupExpiredSessions();
  }

  /**
   * Close connections
   */
  async close(): Promise<void> {
    await this.sessionStore.close();
  }
}
