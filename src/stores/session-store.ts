/**
 * @fileoverview Session Store Interface and Base Implementation
 * 
 * This module provides the abstract interface and base implementation for session
 * storage backends in the JTS (JSON Token Session) authentication framework.
 * 
 * @module @jts-core/stores/session-store
 * @version 1.0.0
 * @license MIT
 * 
 * @description
 * The SessionStore interface defines a contract for persistent session management,
 * enabling pluggable storage backends (Redis, PostgreSQL, MongoDB, etc.) while
 * maintaining consistent session lifecycle operations.
 * 
 * Key Features:
 * - StateProof rotation with configurable grace window
 * - Replay attack detection and prevention
 * - Multi-device session management per principal
 * - Automatic session expiration and cleanup
 * - Health monitoring for production readiness
 * 
 * @example
 * ```typescript
 * import { SessionStore, BaseSessionStore } from '@jts-core/stores';
 * 
 * class CustomSessionStore extends BaseSessionStore {
 *   async createSession(input: CreateSessionInput): Promise<JTSSession> {
 *     const sessionData = this.createSessionData(input);
 *     // Persist to your database
 *     return sessionData;
 *   }
 *   // ... implement other abstract methods
 * }
 * ```
 */

import { JTSSession, CreateSessionInput, SessionValidationResult, JTSError, JTS_ERRORS } from '../types';
import { generateAnchorId, generateStateProof } from '../crypto';

/* ============================================================================
 * SESSION STORE INTERFACE
 * ============================================================================
 * 
 * Abstract contract for session persistence layer implementations.
 * Provides a unified API for CRUD operations on session entities.
 * ========================================================================= */

/**
 * Abstract interface defining the contract for session storage implementations.
 * 
 * @description
 * This interface provides a standardized API for session management operations,
 * allowing different storage backends to be used interchangeably. Implementations
 * should handle connection pooling, error recovery, and data serialization.
 * 
 * @remarks
 * All methods are asynchronous to support non-blocking I/O operations with
 * external storage systems. Implementations should ensure thread-safety for
 * concurrent access patterns.
 * 
 * @interface SessionStore
 * 
 * @example
 * ```typescript
 * // Implementing a custom session store
 * class RedisSessionStore implements SessionStore {
 *   private client: RedisClient;
 *   
 *   async createSession(input: CreateSessionInput): Promise<JTSSession> {
 *     // Implementation details...
 *   }
 * }
 * ```
 */
export interface SessionStore {
  /**
   * Creates and persists a new session for a given principal.
   * 
   * @description
   * Initializes a new session with cryptographically secure identifiers,
   * including the anchor ID (aid) and initial StateProof. The session is
   * immediately active upon creation.
   * 
   * @param input - Session creation parameters including principal identifier
   * @returns Promise resolving to the newly created session object
   * 
   * @throws {JTSError} If session creation fails due to storage errors
   * 
   * @example
   * ```typescript
   * const session = await store.createSession({
   *   prn: 'user:12345',
   *   deviceFingerprint: 'fp_abc123',
   *   userAgent: 'Mozilla/5.0...',
   *   ipAddress: '192.168.1.1'
   * });
   * ```
   */
  createSession(input: CreateSessionInput): Promise<JTSSession>;

  /**
   * Retrieves a session by its unique anchor identifier.
   * 
   * @description
   * Performs a direct lookup using the session's immutable anchor ID.
   * This is the most efficient method for session retrieval when the
   * anchor ID is known.
   * 
   * @param aid - The unique anchor identifier of the session
   * @returns Promise resolving to the session if found, or null if not exists
   * 
   * @example
   * ```typescript
   * const session = await store.getSessionByAid('anc_xK9mN2pQ...');
   * if (session) {
   *   console.log(`Session for principal: ${session.prn}`);
   * }
   * ```
   */
  getSessionByAid(aid: string): Promise<JTSSession | null>;

  /**
   * Validates and retrieves a session using its StateProof token.
   * 
   * @description
   * Validates the provided StateProof against both current and previous
   * StateProofs (within the grace window). This method implements replay
   * attack detection by identifying usage of expired previous StateProofs.
   * 
   * @param stateProof - The StateProof token to validate
   * @returns Promise resolving to validation result with session if valid
   * 
   * @remarks
   * - Returns `withinGraceWindow: true` if matched against previous StateProof
   * - Returns `SESSION_COMPROMISED` error if replay attack detected
   * - Returns `STATEPROOF_INVALID` error if no match found
   * 
   * @example
   * ```typescript
   * const result = await store.getSessionByStateProof('sp_aBcDeF...');
   * if (result.valid) {
   *   if (result.withinGraceWindow) {
   *     console.log('Using previous StateProof during rotation');
   *   }
   * } else {
   *   console.error('Validation failed:', result.error);
   * }
   * ```
   */
  getSessionByStateProof(stateProof: string): Promise<SessionValidationResult>;

  /**
   * Rotates the session's StateProof for enhanced security.
   * 
   * @description
   * Implements the StateProof rotation mechanism by generating a new StateProof,
   * moving the current one to previousStateProof, and recording the rotation
   * timestamp for grace window calculations.
   * 
   * @param aid - The anchor identifier of the session to rotate
   * @param newStateProof - Optional custom StateProof (auto-generated if not provided)
   * @returns Promise resolving to the updated session with new StateProof
   * 
   * @throws {JTSError} If session not found or rotation fails
   * 
   * @example
   * ```typescript
   * const rotatedSession = await store.rotateStateProof('anc_xK9mN2pQ...');
   * console.log(`New StateProof: ${rotatedSession.currentStateProof}`);
   * ```
   */
  rotateStateProof(aid: string, newStateProof?: string): Promise<JTSSession>;

  /**
   * Updates the session's last active timestamp.
   * 
   * @description
   * Refreshes the lastActive field to indicate recent activity. This is used
   * for session timeout calculations and activity tracking without modifying
   * the session's security properties.
   * 
   * @param aid - The anchor identifier of the session to touch
   * @returns Promise resolving when the update is complete
   * 
   * @example
   * ```typescript
   * await store.touchSession('anc_xK9mN2pQ...');
   * ```
   */
  touchSession(aid: string): Promise<void>;

  /**
   * Permanently deletes a session (logout/revocation).
   * 
   * @description
   * Removes the session from storage, effectively logging out the user
   * from the associated device. This operation is irreversible.
   * 
   * @param aid - The anchor identifier of the session to delete
   * @returns Promise resolving to true if deleted, false if not found
   * 
   * @example
   * ```typescript
   * const deleted = await store.deleteSession('anc_xK9mN2pQ...');
   * if (deleted) {
   *   console.log('Session successfully revoked');
   * }
   * ```
   */
  deleteSession(aid: string): Promise<boolean>;

  /**
   * Revokes all sessions for a specific principal (user).
   * 
   * @description
   * Performs a bulk deletion of all sessions associated with the given
   * principal identifier. Useful for "logout from all devices" functionality
   * or account security measures.
   * 
   * @param prn - The principal identifier (user ID)
   * @returns Promise resolving to the count of deleted sessions
   * 
   * @example
   * ```typescript
   * const count = await store.deleteAllSessionsForPrincipal('user:12345');
   * console.log(`Revoked ${count} sessions`);
   * ```
   */
  deleteAllSessionsForPrincipal(prn: string): Promise<number>;

  /**
   * Retrieves all active sessions for a specific principal.
   * 
   * @description
   * Returns a list of all sessions associated with the principal,
   * enabling features like "view logged-in devices" in user settings.
   * 
   * @param prn - The principal identifier (user ID)
   * @returns Promise resolving to array of active sessions
   * 
   * @example
   * ```typescript
   * const sessions = await store.getSessionsForPrincipal('user:12345');
   * sessions.forEach(s => {
   *   console.log(`Device: ${s.userAgent}, Last active: ${s.lastActive}`);
   * });
   * ```
   */
  getSessionsForPrincipal(prn: string): Promise<JTSSession[]>;

  /**
   * Counts active sessions for a specific principal.
   * 
   * @description
   * Returns the total number of active sessions for the principal,
   * useful for enforcing maximum session limits per user.
   * 
   * @param prn - The principal identifier (user ID)
   * @returns Promise resolving to the session count
   * 
   * @example
   * ```typescript
   * const count = await store.countSessionsForPrincipal('user:12345');
   * if (count >= MAX_SESSIONS) {
   *   // Enforce session limit policy
   * }
   * ```
   */
  countSessionsForPrincipal(prn: string): Promise<number>;

  /**
   * Deletes the oldest session for a principal.
   * 
   * @description
   * Removes the session with the earliest creation timestamp for the
   * given principal. Used to enforce session limits by removing the
   * oldest session when a new one is created.
   * 
   * @param prn - The principal identifier (user ID)
   * @returns Promise resolving to true if a session was deleted
   * 
   * @example
   * ```typescript
   * if (await store.countSessionsForPrincipal(prn) >= limit) {
   *   await store.deleteOldestSessionForPrincipal(prn);
   * }
   * ```
   */
  deleteOldestSessionForPrincipal(prn: string): Promise<boolean>;

  /**
   * Removes all expired sessions from storage.
   * 
   * @description
   * Performs garbage collection by deleting sessions that have exceeded
   * their expiration time. Should be called periodically via scheduled
   * job or background task.
   * 
   * @returns Promise resolving to the count of cleaned up sessions
   * 
   * @example
   * ```typescript
   * // Run cleanup every hour
   * setInterval(async () => {
   *   const cleaned = await store.cleanupExpiredSessions();
   *   console.log(`Cleaned up ${cleaned} expired sessions`);
   * }, 60 * 60 * 1000);
   * ```
   */
  cleanupExpiredSessions(): Promise<number>;

  /**
   * Verifies the health and connectivity of the storage backend.
   * 
   * @description
   * Performs a lightweight check to verify the storage backend is
   * accessible and operational. Used for health monitoring, load
   * balancer checks, and startup validation.
   * 
   * @returns Promise resolving to true if healthy, false otherwise
   * 
   * @example
   * ```typescript
   * app.get('/health', async (req, res) => {
   *   const healthy = await store.healthCheck();
   *   res.status(healthy ? 200 : 503).json({ status: healthy });
   * });
   * ```
   */
  healthCheck(): Promise<boolean>;

  /**
   * Gracefully closes connections and releases resources.
   * 
   * @description
   * Performs cleanup operations including closing database connections,
   * flushing pending writes, and releasing any held resources. Should
   * be called during application shutdown.
   * 
   * @returns Promise resolving when cleanup is complete
   * 
   * @example
   * ```typescript
   * process.on('SIGTERM', async () => {
   *   await store.close();
   *   process.exit(0);
   * });
   * ```
   */
  close(): Promise<void>;
}

/* ============================================================================
 * BASE SESSION STORE IMPLEMENTATION
 * ============================================================================
 * 
 * Abstract base class providing common session management logic.
 * Extend this class to implement custom storage backends with minimal effort.
 * ========================================================================= */

/**
 * Abstract base class providing shared session management functionality.
 * 
 * @description
 * BaseSessionStore implements common session logic that is storage-agnostic,
 * including session data generation, StateProof validation, and grace window
 * calculations. Concrete implementations only need to handle persistence.
 * 
 * @abstract
 * @class BaseSessionStore
 * @implements {SessionStore}
 * 
 * @remarks
 * This class follows the Template Method pattern, defining the skeleton of
 * session operations while delegating storage-specific steps to subclasses.
 * 
 * @example
 * ```typescript
 * class PostgresSessionStore extends BaseSessionStore {
 *   private pool: Pool;
 *   
 *   constructor(pool: Pool, options?: BaseSessionStoreOptions) {
 *     super(options);
 *     this.pool = pool;
 *   }
 *   
 *   async createSession(input: CreateSessionInput): Promise<JTSSession> {
 *     const data = this.createSessionData(input);
 *     await this.pool.query('INSERT INTO sessions...', [data]);
 *     return data;
 *   }
 *   // ... implement other abstract methods
 * }
 * ```
 */
export abstract class BaseSessionStore implements SessionStore {
  /**
   * Duration in seconds during which the previous StateProof remains valid
   * after rotation. This allows in-flight requests to complete successfully.
   * 
   * @protected
   * @default 10 seconds
   */
  protected rotationGraceWindow: number;

  /**
   * Default session lifetime in seconds if not specified during creation.
   * Sessions will automatically expire after this duration.
   * 
   * @protected
   * @default 604800 (7 days)
   */
  protected defaultSessionLifetime: number;

  /**
   * Creates a new BaseSessionStore instance with optional configuration.
   * 
   * @param options - Configuration options for session management
   * @param options.rotationGraceWindow - Grace period for StateProof rotation (seconds)
   * @param options.defaultSessionLifetime - Default session expiration time (seconds)
   * 
   * @example
   * ```typescript
   * class MyStore extends BaseSessionStore {
   *   constructor() {
   *     super({
   *       rotationGraceWindow: 30,        // 30 second grace window
   *       defaultSessionLifetime: 86400   // 24 hour sessions
   *     });
   *   }
   * }
   * ```
   */
  constructor(options: {
    rotationGraceWindow?: number;
    defaultSessionLifetime?: number;
  } = {}) {
    this.rotationGraceWindow = options.rotationGraceWindow ?? 10; // 10 seconds
    this.defaultSessionLifetime = options.defaultSessionLifetime ?? 7 * 24 * 60 * 60; // 7 days
  }

  /**
   * Generates a complete session data object from creation input.
   * 
   * @description
   * Creates a new session object with all required fields populated,
   * including cryptographically secure anchor ID and initial StateProof.
   * This method is used by concrete implementations during session creation.
   * 
   * @protected
   * @param input - The session creation input parameters
   * @returns Complete session data object ready for persistence
   * 
   * @remarks
   * The returned object includes:
   * - `aid`: Cryptographically secure anchor identifier
   * - `currentStateProof`: Initial StateProof for authentication
   * - `stateProofVersion`: Starts at 1, incremented on each rotation
   * - Calculated `expiresAt` based on input or default lifetime
   * 
   * @example
   * ```typescript
   * // In a concrete implementation:
   * async createSession(input: CreateSessionInput): Promise<JTSSession> {
   *   const sessionData = this.createSessionData(input);
   *   await this.database.insert('sessions', sessionData);
   *   return sessionData;
   * }
   * ```
   */
  protected createSessionData(input: CreateSessionInput): Omit<JTSSession, 'aid'> & { aid: string } {
    const now = new Date();
    const expiresIn = input.expiresIn ?? this.defaultSessionLifetime;
    const expiresAt = new Date(now.getTime() + expiresIn * 1000);

    return {
      aid: generateAnchorId(),
      prn: input.prn,
      currentStateProof: generateStateProof(),
      previousStateProof: undefined,
      stateProofVersion: 1,
      rotationTimestamp: undefined,
      deviceFingerprint: input.deviceFingerprint,
      createdAt: now,
      expiresAt,
      lastActive: now,
      userAgent: input.userAgent,
      ipAddress: input.ipAddress,
      metadata: input.metadata,
    };
  }

  /**
   * Determines if the session is within the StateProof rotation grace window.
   * 
   * @description
   * Checks whether the time elapsed since the last StateProof rotation is
   * less than the configured grace window. During this period, both current
   * and previous StateProofs are considered valid.
   * 
   * @protected
   * @param session - The session to check for grace window status
   * @returns True if within grace window, false otherwise
   * 
   * @remarks
   * Returns false if `rotationTimestamp` is undefined (no rotation has occurred).
   * The grace window prevents request failures during concurrent operations
   * where one request rotates the StateProof while another is in-flight.
   * 
   * @example
   * ```typescript
   * if (this.isWithinGraceWindow(session)) {
   *   // Accept previous StateProof
   *   return { valid: true, withinGraceWindow: true };
   * }
   * ```
   */
  protected isWithinGraceWindow(session: JTSSession): boolean {
    if (!session.rotationTimestamp) return false;
    const elapsed = (Date.now() - session.rotationTimestamp.getTime()) / 1000;
    return elapsed < this.rotationGraceWindow;
  }

  /**
   * Validates a StateProof against a session with replay attack detection.
   * 
   * @description
   * Implements the core StateProof validation algorithm that:
   * 1. Checks for exact match with current StateProof (valid)
   * 2. Checks for match with previous StateProof within grace window (valid, flagged)
   * 3. Detects replay attacks (previous StateProof used outside grace window)
   * 4. Rejects unknown StateProofs
   * 
   * @protected
   * @param session - The session to validate against
   * @param stateProof - The StateProof token to validate
   * @returns Validation result indicating success or specific failure reason
   * 
   * @remarks
   * This method implements a critical security mechanism. When a previous
   * StateProof is used outside the grace window, it indicates a potential
   * token theft scenario where the legitimate user has already rotated their
   * token but an attacker is using the stolen previous token.
   * 
   * @example
   * ```typescript
   * const result = this.validateStateProofLogic(session, providedStateProof);
   * if (!result.valid && result.error === JTS_ERRORS.SESSION_COMPROMISED) {
   *   // Immediately revoke session - potential attack detected
   *   await this.deleteSession(session.aid);
   * }
   * ```
   */
  protected validateStateProofLogic(
    session: JTSSession,
    stateProof: string
  ): SessionValidationResult {
    // Check if it matches current StateProof
    if (session.currentStateProof === stateProof) {
      return { valid: true, session, withinGraceWindow: false };
    }

    // Check if it matches previous StateProof (during grace window)
    if (session.previousStateProof === stateProof) {
      if (this.isWithinGraceWindow(session)) {
        return { valid: true, session, withinGraceWindow: true };
      } else {
        // Replay attack detected!
        return {
          valid: false,
          session,
          error: JTS_ERRORS.SESSION_COMPROMISED,
        };
      }
    }

    // Invalid StateProof
    return {
      valid: false,
      error: JTS_ERRORS.STATEPROOF_INVALID,
    };
  }

  /* ==========================================================================
   * ABSTRACT METHODS
   * ==========================================================================
   * 
   * The following methods must be implemented by concrete storage backends.
   * Each method handles the persistence layer for its respective operation.
   * ======================================================================= */

  /**
   * @inheritdoc
   * @abstract
   */
  abstract createSession(input: CreateSessionInput): Promise<JTSSession>;

  /**
   * @inheritdoc
   * @abstract
   */
  abstract getSessionByAid(aid: string): Promise<JTSSession | null>;

  /**
   * @inheritdoc
   * @abstract
   */
  abstract getSessionByStateProof(stateProof: string): Promise<SessionValidationResult>;

  /**
   * @inheritdoc
   * @abstract
   */
  abstract rotateStateProof(aid: string, newStateProof: string): Promise<JTSSession>;

  /**
   * @inheritdoc
   * @abstract
   */
  abstract touchSession(aid: string): Promise<void>;

  /**
   * @inheritdoc
   * @abstract
   */
  abstract deleteSession(aid: string): Promise<boolean>;

  /**
   * @inheritdoc
   * @abstract
   */
  abstract deleteAllSessionsForPrincipal(prn: string): Promise<number>;

  /**
   * @inheritdoc
   * @abstract
   */
  abstract getSessionsForPrincipal(prn: string): Promise<JTSSession[]>;

  /**
   * @inheritdoc
   * @abstract
   */
  abstract countSessionsForPrincipal(prn: string): Promise<number>;

  /**
   * @inheritdoc
   * @abstract
   */
  abstract deleteOldestSessionForPrincipal(prn: string): Promise<boolean>;

  /**
   * @inheritdoc
   * @abstract
   */
  abstract cleanupExpiredSessions(): Promise<number>;

  /**
   * @inheritdoc
   * @abstract
   */
  abstract healthCheck(): Promise<boolean>;

  /**
   * @inheritdoc
   * @abstract
   */
  abstract close(): Promise<void>;
}
