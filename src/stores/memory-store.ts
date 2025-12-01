import { JTSSession, CreateSessionInput, SessionValidationResult, JTS_ERRORS } from '../types';
import { BaseSessionStore } from './session-store';
import { generateStateProof } from '../crypto';

/**
 * In-memory implementation of the JTS session store.
 *
 * This store keeps all session data in memory using `Map` collections and is
 * intended primarily for **development**, **testing**, or **low-volume**
 * ephemeral environments. Since all data is stored in-process, any restart
 * of the Node.js process will permanently remove all sessions.
 *
 * For production workloads, you should use a persistent store implementation
 * such as the Postgres or Redis adapters instead.
 *
 * Responsibilities:
 * - Create and manage `JTSSession` instances.
 * - Index sessions by AID and by state proof for fast lookups.
 * - Handle rotation and validation of state proofs.
 * - Enforce session expiration and perform garbage collection for expired entries.
 */
export class InMemorySessionStore extends BaseSessionStore {
  private sessions: Map<string, JTSSession> = new Map();
  // Index mapping `stateProof` -> `aid` to support efficient state proof lookups.
  private stateProofIndex: Map<string, string> = new Map();

  constructor(options: {
    rotationGraceWindow?: number;
    defaultSessionLifetime?: number;
  } = {}) {
    super(options);
  }

  /**
   * Create and persist a new session in memory.
   *
   * The core session fields are derived from the `CreateSessionInput` via
   * `BaseSessionStore.createSessionData`. The resulting session is indexed by
   * both AID and its current state proof.
   *
   * @param input - Parameters required to construct a new `JTSSession`.
   * @returns The newly created `JTSSession` instance.
   */
  async createSession(input: CreateSessionInput): Promise<JTSSession> {
    const sessionData = this.createSessionData(input);
    const session: JTSSession = sessionData;
    this.sessions.set(session.aid, session);
    this.stateProofIndex.set(session.currentStateProof, session.aid);

    return session;
  }

  /**
   * Retrieve a session by its authorization identifier (AID).
   *
   * If the session exists but is already expired, it will be deleted and
   * `null` will be returned.
   *
   * @param aid - The authorization identifier of the session.
   * @returns The corresponding `JTSSession` or `null` if not found or expired.
   */
  async getSessionByAid(aid: string): Promise<JTSSession | null> {
    const session = this.sessions.get(aid);
    if (!session) return null;
    if (new Date() > session.expiresAt) {
      await this.deleteSession(aid);
      return null;
    }

    return session;
  }

  /**
   * Look up and validate a session by its state proof.
   *
   * This method first attempts a fast lookup using the current state proof
   * index. If that fails, it falls back to scanning in-memory sessions to
   * locate a matching previous state proof (to support grace periods during
   * state proof rotation).
   *
   * If a candidate session is found and not expired, the shared validation
   * logic implemented in `BaseSessionStore.validateStateProofLogic` is used
   * to determine whether the state proof is still valid under the rotation
   * rules.
   *
   * @param stateProof - The state proof presented by the client.
   * @returns A `SessionValidationResult` describing whether the proof is valid.
   */
  async getSessionByStateProof(stateProof: string): Promise<SessionValidationResult> {
    const aidByCurrent = this.stateProofIndex.get(stateProof);
    if (aidByCurrent) {
      const session = await this.getSessionByAid(aidByCurrent);
      if (session) {
        return this.validateStateProofLogic(session, stateProof);
      }
    }

    // Fallback: scan for a matching previous state proof (less efficient, but
    // required to support the rotation grace window).
    for (const session of this.sessions.values()) {
      if (session.previousStateProof === stateProof) {
        if (new Date() > session.expiresAt) {
          await this.deleteSession(session.aid);
          continue;
        }
        return this.validateStateProofLogic(session, stateProof);
      }
    }

    return {
      valid: false,
      error: JTS_ERRORS.STATEPROOF_INVALID,
    };
  }

  /**
   * Rotate the state proof for the specified session.
   *
   * The rotation algorithm:
   * - Generates (or accepts) a new state proof.
   * - Moves the existing `currentStateProof` to `previousStateProof`.
   * - Increments the state proof version.
   * - Updates the rotation and last active timestamps.
   * - Refreshes the state proof indexes for fast lookup during the grace window.
   *
   * @param aid - The authorization identifier of the session to update.
   * @param newStateProof - Optional externally generated state proof. If not
   *   provided, a new one is generated internally.
   * @throws If the session cannot be found.
   * @returns The updated `JTSSession` with the rotated state proof.
   */
  async rotateStateProof(aid: string, newStateProof?: string): Promise<JTSSession> {
    const session = await this.getSessionByAid(aid);
    if (!session) {
      throw new Error('Session not found');
    }
    const newSP = newStateProof ?? generateStateProof();
    this.stateProofIndex.delete(session.currentStateProof);
    if (session.previousStateProof) {
      this.stateProofIndex.delete(session.previousStateProof);
    }
    session.previousStateProof = session.currentStateProof;
    session.currentStateProof = newSP;
    session.stateProofVersion += 1;
    session.rotationTimestamp = new Date();
    session.lastActive = new Date();
    this.stateProofIndex.set(newSP, aid);
    if (session.previousStateProof) {
      this.stateProofIndex.set(session.previousStateProof, aid);
    }
    this.sessions.set(aid, session);
    
    return session;
  }

  /**
   * Update the `lastActive` timestamp for a session.
   *
   * This is typically invoked when the holder of the session performs an
   * authenticated action and we want to track recency for UI or cleanup
   * purposes. If the session does not exist, this operation is a no-op.
   *
   * @param aid - The authorization identifier of the session to touch.
   */
  async touchSession(aid: string): Promise<void> {
    const session = this.sessions.get(aid);
    if (session) {
      session.lastActive = new Date();
      this.sessions.set(aid, session);
    }
  }

  /**
   * Delete a single session by AID.
   *
   * This will also remove any associated state proof index entries for
   * both the current and previous state proofs.
   *
   * @param aid - The authorization identifier of the session to delete.
   * @returns `true` if a session was removed, otherwise `false`.
   */
  async deleteSession(aid: string): Promise<boolean> {
    const session = this.sessions.get(aid);
    if (!session) return false;
    this.stateProofIndex.delete(session.currentStateProof);
    if (session.previousStateProof) {
      this.stateProofIndex.delete(session.previousStateProof);
    }

    return this.sessions.delete(aid);
  }

  /**
   * Delete all sessions belonging to a given principal.
   *
   * The operation scans the in-memory store, collects all sessions whose `prn`
   * matches the provided principal identifier, and then deletes each of them.
   *
   * @param prn - Principal identifier (typically the subject of the session).
   * @returns The number of sessions that were successfully deleted.
   */
  async deleteAllSessionsForPrincipal(prn: string): Promise<number> {
    let count = 0;
    const toDelete: string[] = [];
    for (const [aid, session] of this.sessions) {
      if (session.prn === prn) {
        toDelete.push(aid);
      }
    }
    for (const aid of toDelete) {
      if (await this.deleteSession(aid)) {
        count++;
      }
    }

    return count;
  }

  /**
   * Retrieve all active (non-expired) sessions for a given principal.
   *
   * The returned list is sorted by `lastActive` in descending order so that
   * the most recently used session appears first.
   *
   * @param prn - Principal identifier for which sessions should be listed.
   * @returns An array of active `JTSSession` instances associated with `prn`.
   */
  async getSessionsForPrincipal(prn: string): Promise<JTSSession[]> {
    const sessions: JTSSession[] = [];
    const now = new Date();
    for (const session of this.sessions.values()) {
      if (session.prn === prn && session.expiresAt > now) {
        sessions.push(session);
      }
    }
    return sessions.sort((a, b) => 
      b.lastActive.getTime() - a.lastActive.getTime()
    );
  }

  /**
   * Count the number of active (non-expired) sessions for a principal.
   *
   * This is a convenience wrapper around `getSessionsForPrincipal`.
   *
   * @param prn - Principal identifier.
   * @returns The number of active sessions associated with `prn`.
   */
  async countSessionsForPrincipal(prn: string): Promise<number> {
    const sessions = await this.getSessionsForPrincipal(prn);
    return sessions.length;
  }

  /**
   * Delete the oldest (by `createdAt`) active session for a principal.
   *
   * This is useful in scenarios where you want to enforce a maximum number
   * of parallel sessions per principal and need to evict the least recent one.
   *
   * @param prn - Principal identifier.
   * @returns `true` if a session was deleted, otherwise `false` if none existed.
   */
  async deleteOldestSessionForPrincipal(prn: string): Promise<boolean> {
    const sessions = await this.getSessionsForPrincipal(prn);
    if (sessions.length === 0) return false;
    sessions.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
    
    return this.deleteSession(sessions[0].aid);
  }

  /**
   * Remove all sessions that have passed their expiration time.
   *
   * This provides a simple in-memory garbage collection mechanism that can be
   * invoked on a schedule by the hosting application.
   *
   * @returns The number of sessions that were removed.
   */
  async cleanupExpiredSessions(): Promise<number> {
    let count = 0;
    const now = new Date();
    const toDelete: string[] = [];
    for (const [aid, session] of this.sessions) {
      if (session.expiresAt < now) {
        toDelete.push(aid);
      }
    }
    for (const aid of toDelete) {
      if (await this.deleteSession(aid)) {
        count++;
      }
    }

    return count;
  }

  /**
   * Lightweight health check for the in-memory store.
   *
   * Since this implementation is entirely in-process, the health check simply
   * returns `true` to indicate that the store is available.
   *
   * @returns Always `true`.
   */
  async healthCheck(): Promise<boolean> {
    return true;
  }

  /**
   * Close the in-memory store and release all in-process resources.
   *
   * This clears both the session map and the state proof index. All sessions
   * will be irretrievably lost after this call.
   */
  async close(): Promise<void> {
    this.sessions.clear();
    this.stateProofIndex.clear();
  }

  /**
   * Get the current number of sessions stored in memory.
   *
   * This is primarily intended for diagnostics, metrics, and testing.
   *
   * @returns The number of sessions currently tracked by the store.
   */
  getSize(): number {
    return this.sessions.size;
  }

  /**
   * Remove all sessions and indexes from the in-memory store.
   *
   * This is a convenience wrapper used mainly in test suites to ensure a
   * clean slate between test cases.
   */
  async clear(): Promise<void> {
    await this.close();
  }
}
