/**
 * jts-core - Session Store Interface
 * Abstract interface for session storage backends
 */

import { JTSSession, CreateSessionInput, SessionValidationResult, JTSError } from '../types';
import { generateAnchorId, generateStateProof } from '../crypto';

// ============================================================================
// SESSION STORE INTERFACE
// ============================================================================

/**
 * Abstract interface for session storage
 * Implement this for your database of choice
 */
export interface SessionStore {
  /**
   * Create a new session
   */
  createSession(input: CreateSessionInput): Promise<JTSSession>;

  /**
   * Get session by anchor ID
   */
  getSessionByAid(aid: string): Promise<JTSSession | null>;

  /**
   * Get session by StateProof (current or previous)
   */
  getSessionByStateProof(stateProof: string): Promise<SessionValidationResult>;

  /**
   * Update session's StateProof (rotation)
   */
  rotateStateProof(aid: string, newStateProof?: string): Promise<JTSSession>;

  /**
   * Update last active timestamp
   */
  touchSession(aid: string): Promise<void>;

  /**
   * Delete session (logout/revoke)
   */
  deleteSession(aid: string): Promise<boolean>;

  /**
   * Delete all sessions for a principal (user)
   */
  deleteAllSessionsForPrincipal(prn: string): Promise<number>;

  /**
   * Get all active sessions for a principal
   */
  getSessionsForPrincipal(prn: string): Promise<JTSSession[]>;

  /**
   * Count active sessions for a principal
   */
  countSessionsForPrincipal(prn: string): Promise<number>;

  /**
   * Delete oldest session for a principal
   */
  deleteOldestSessionForPrincipal(prn: string): Promise<boolean>;

  /**
   * Clean up expired sessions
   */
  cleanupExpiredSessions(): Promise<number>;

  /**
   * Check if store is healthy/connected
   */
  healthCheck(): Promise<boolean>;

  /**
   * Close connection (cleanup)
   */
  close(): Promise<void>;
}

// ============================================================================
// BASE SESSION STORE
// ============================================================================

/**
 * Base class with common session logic
 */
export abstract class BaseSessionStore implements SessionStore {
  protected rotationGraceWindow: number;
  protected defaultSessionLifetime: number;

  constructor(options: {
    rotationGraceWindow?: number;
    defaultSessionLifetime?: number;
  } = {}) {
    this.rotationGraceWindow = options.rotationGraceWindow ?? 10; // 10 seconds
    this.defaultSessionLifetime = options.defaultSessionLifetime ?? 7 * 24 * 60 * 60; // 7 days
  }

  /**
   * Generate new session data
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
   * Check if within rotation grace window
   */
  protected isWithinGraceWindow(session: JTSSession): boolean {
    if (!session.rotationTimestamp) return false;
    const elapsed = (Date.now() - session.rotationTimestamp.getTime()) / 1000;
    return elapsed < this.rotationGraceWindow;
  }

  /**
   * Validate StateProof and detect replay attacks
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
          error: 'JTS-401-05', // session_compromised
        };
      }
    }

    // Invalid StateProof
    return {
      valid: false,
      error: 'JTS-401-03', // stateproof_invalid
    };
  }

  // Abstract methods to be implemented by concrete stores
  abstract createSession(input: CreateSessionInput): Promise<JTSSession>;
  abstract getSessionByAid(aid: string): Promise<JTSSession | null>;
  abstract getSessionByStateProof(stateProof: string): Promise<SessionValidationResult>;
  abstract rotateStateProof(aid: string, newStateProof: string): Promise<JTSSession>;
  abstract touchSession(aid: string): Promise<void>;
  abstract deleteSession(aid: string): Promise<boolean>;
  abstract deleteAllSessionsForPrincipal(prn: string): Promise<number>;
  abstract getSessionsForPrincipal(prn: string): Promise<JTSSession[]>;
  abstract countSessionsForPrincipal(prn: string): Promise<number>;
  abstract deleteOldestSessionForPrincipal(prn: string): Promise<boolean>;
  abstract cleanupExpiredSessions(): Promise<number>;
  abstract healthCheck(): Promise<boolean>;
  abstract close(): Promise<void>;
}
