/**
 * jts-core - In-Memory Session Store
 * For development and testing purposes
 */

import { JTSSession, CreateSessionInput, SessionValidationResult } from '../types';
import { BaseSessionStore } from './session-store';
import { generateStateProof } from '../crypto';

/**
 * In-memory session store implementation
 * NOT recommended for production use
 */
export class InMemorySessionStore extends BaseSessionStore {
  private sessions: Map<string, JTSSession> = new Map();
  private stateProofIndex: Map<string, string> = new Map(); // stateProof -> aid

  constructor(options: {
    rotationGraceWindow?: number;
    defaultSessionLifetime?: number;
  } = {}) {
    super(options);
  }

  async createSession(input: CreateSessionInput): Promise<JTSSession> {
    const sessionData = this.createSessionData(input);
    const session: JTSSession = sessionData;
    
    this.sessions.set(session.aid, session);
    this.stateProofIndex.set(session.currentStateProof, session.aid);
    
    return session;
  }

  async getSessionByAid(aid: string): Promise<JTSSession | null> {
    const session = this.sessions.get(aid);
    if (!session) return null;
    
    // Check if expired
    if (new Date() > session.expiresAt) {
      await this.deleteSession(aid);
      return null;
    }
    
    return session;
  }

  async getSessionByStateProof(stateProof: string): Promise<SessionValidationResult> {
    // Find session by current StateProof
    const aidByCurrent = this.stateProofIndex.get(stateProof);
    if (aidByCurrent) {
      const session = await this.getSessionByAid(aidByCurrent);
      if (session) {
        return this.validateStateProofLogic(session, stateProof);
      }
    }

    // Search for previous StateProof (less efficient but necessary)
    for (const session of this.sessions.values()) {
      if (session.previousStateProof === stateProof) {
        // Check expiration
        if (new Date() > session.expiresAt) {
          await this.deleteSession(session.aid);
          continue;
        }
        return this.validateStateProofLogic(session, stateProof);
      }
    }

    return {
      valid: false,
      error: 'JTS-401-03',
    };
  }

  async rotateStateProof(aid: string, newStateProof?: string): Promise<JTSSession> {
    const session = await this.getSessionByAid(aid);
    if (!session) {
      throw new Error('Session not found');
    }

    const newSP = newStateProof ?? generateStateProof();
    
    // Remove old index entries
    this.stateProofIndex.delete(session.currentStateProof);
    if (session.previousStateProof) {
      this.stateProofIndex.delete(session.previousStateProof);
    }

    // Update session
    session.previousStateProof = session.currentStateProof;
    session.currentStateProof = newSP;
    session.stateProofVersion += 1;
    session.rotationTimestamp = new Date();
    session.lastActive = new Date();

    // Update index
    this.stateProofIndex.set(newSP, aid);
    // Keep previous in index for grace window lookups
    if (session.previousStateProof) {
      this.stateProofIndex.set(session.previousStateProof, aid);
    }

    this.sessions.set(aid, session);
    
    return session;
  }

  async touchSession(aid: string): Promise<void> {
    const session = this.sessions.get(aid);
    if (session) {
      session.lastActive = new Date();
      this.sessions.set(aid, session);
    }
  }

  async deleteSession(aid: string): Promise<boolean> {
    const session = this.sessions.get(aid);
    if (!session) return false;

    // Clean up indexes
    this.stateProofIndex.delete(session.currentStateProof);
    if (session.previousStateProof) {
      this.stateProofIndex.delete(session.previousStateProof);
    }

    return this.sessions.delete(aid);
  }

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

  async countSessionsForPrincipal(prn: string): Promise<number> {
    const sessions = await this.getSessionsForPrincipal(prn);
    return sessions.length;
  }

  async deleteOldestSessionForPrincipal(prn: string): Promise<boolean> {
    const sessions = await this.getSessionsForPrincipal(prn);
    if (sessions.length === 0) return false;

    // Sort by createdAt ascending (oldest first)
    sessions.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
    
    return this.deleteSession(sessions[0].aid);
  }

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

  async healthCheck(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {
    this.sessions.clear();
    this.stateProofIndex.clear();
  }

  /**
   * Get current store size (for debugging)
   */
  getSize(): number {
    return this.sessions.size;
  }

  /**
   * Clear all sessions (for testing)
   */
  async clear(): Promise<void> {
    await this.close();
  }
}
