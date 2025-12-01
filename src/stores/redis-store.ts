/**
 * jts-core - Redis Session Store
 * Production-ready Redis implementation
 */

import { JTSSession, CreateSessionInput, SessionValidationResult } from '../types';
import { BaseSessionStore } from './session-store';
import { generateStateProof } from '../crypto';

// Type for ioredis (optional dependency)
interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: (string | number)[]): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  keys(pattern: string): Promise<string[]>;
  expire(key: string, seconds: number): Promise<number>;
  ping(): Promise<string>;
  quit(): Promise<string>;
  sadd(key: string, ...members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
  srem(key: string, ...members: string[]): Promise<number>;
  scard(key: string): Promise<number>;
}

export interface RedisSessionStoreOptions {
  /** Redis client instance (ioredis) */
  client: RedisClient;
  /** Key prefix for all session keys */
  keyPrefix?: string;
  /** Rotation grace window in seconds */
  rotationGraceWindow?: number;
  /** Default session lifetime in seconds */
  defaultSessionLifetime?: number;
}

/**
 * Redis-based session store implementation
 * Requires ioredis as a peer dependency
 */
export class RedisSessionStore extends BaseSessionStore {
  private redis: RedisClient;
  private keyPrefix: string;

  constructor(options: RedisSessionStoreOptions) {
    super({
      rotationGraceWindow: options.rotationGraceWindow,
      defaultSessionLifetime: options.defaultSessionLifetime,
    });
    this.redis = options.client;
    this.keyPrefix = options.keyPrefix ?? 'jts:session:';
  }

  private sessionKey(aid: string): string {
    return `${this.keyPrefix}${aid}`;
  }

  private stateProofKey(stateProof: string): string {
    return `${this.keyPrefix}sp:${stateProof}`;
  }

  private principalKey(prn: string): string {
    return `${this.keyPrefix}prn:${prn}`;
  }

  private serializeSession(session: JTSSession): string {
    return JSON.stringify({
      ...session,
      createdAt: session.createdAt.toISOString(),
      expiresAt: session.expiresAt.toISOString(),
      lastActive: session.lastActive.toISOString(),
      rotationTimestamp: session.rotationTimestamp?.toISOString(),
    });
  }

  private deserializeSession(data: string): JTSSession {
    const parsed = JSON.parse(data);
    return {
      ...parsed,
      createdAt: new Date(parsed.createdAt),
      expiresAt: new Date(parsed.expiresAt),
      lastActive: new Date(parsed.lastActive),
      rotationTimestamp: parsed.rotationTimestamp 
        ? new Date(parsed.rotationTimestamp) 
        : undefined,
    };
  }

  async createSession(input: CreateSessionInput): Promise<JTSSession> {
    const sessionData = this.createSessionData(input);
    const session: JTSSession = sessionData;
    
    const ttl = Math.ceil((session.expiresAt.getTime() - Date.now()) / 1000);
    
    // Store session data
    await this.redis.set(
      this.sessionKey(session.aid),
      this.serializeSession(session),
      'EX',
      ttl
    );

    // Create StateProof -> aid mapping
    await this.redis.set(
      this.stateProofKey(session.currentStateProof),
      session.aid,
      'EX',
      ttl
    );

    // Add to principal's session set
    await this.redis.sadd(this.principalKey(session.prn), session.aid);

    return session;
  }

  async getSessionByAid(aid: string): Promise<JTSSession | null> {
    const data = await this.redis.get(this.sessionKey(aid));
    if (!data) return null;
    
    const session = this.deserializeSession(data);
    
    // Check if expired (Redis TTL should handle this, but double-check)
    if (new Date() > session.expiresAt) {
      await this.deleteSession(aid);
      return null;
    }
    
    return session;
  }

  async getSessionByStateProof(stateProof: string): Promise<SessionValidationResult> {
    // Try to find aid by StateProof
    const aid = await this.redis.get(this.stateProofKey(stateProof));
    
    if (aid) {
      const session = await this.getSessionByAid(aid);
      if (session) {
        return this.validateStateProofLogic(session, stateProof);
      }
    }

    // StateProof not found - could be expired or invalid
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
    const ttl = Math.ceil((session.expiresAt.getTime() - Date.now()) / 1000);
    const graceTTL = Math.min(ttl, this.rotationGraceWindow + 5); // Add buffer

    // Delete old StateProof mapping after grace window
    // (or keep for grace window duration)
    if (session.previousStateProof) {
      await this.redis.del(this.stateProofKey(session.previousStateProof));
    }

    // Update session
    const oldStateProof = session.currentStateProof;
    session.previousStateProof = oldStateProof;
    session.currentStateProof = newSP;
    session.stateProofVersion += 1;
    session.rotationTimestamp = new Date();
    session.lastActive = new Date();

    // Save updated session
    await this.redis.set(
      this.sessionKey(aid),
      this.serializeSession(session),
      'EX',
      ttl
    );

    // Create new StateProof mapping
    await this.redis.set(
      this.stateProofKey(newSP),
      aid,
      'EX',
      ttl
    );

    // Keep old StateProof mapping for grace window
    await this.redis.set(
      this.stateProofKey(oldStateProof),
      aid,
      'EX',
      graceTTL
    );

    return session;
  }

  async touchSession(aid: string): Promise<void> {
    const session = await this.getSessionByAid(aid);
    if (session) {
      session.lastActive = new Date();
      const ttl = Math.ceil((session.expiresAt.getTime() - Date.now()) / 1000);
      await this.redis.set(
        this.sessionKey(aid),
        this.serializeSession(session),
        'EX',
        ttl
      );
    }
  }

  async deleteSession(aid: string): Promise<boolean> {
    const session = await this.getSessionByAid(aid);
    if (!session) return false;

    // Delete StateProof mappings
    const keysToDelete = [
      this.sessionKey(aid),
      this.stateProofKey(session.currentStateProof),
    ];
    
    if (session.previousStateProof) {
      keysToDelete.push(this.stateProofKey(session.previousStateProof));
    }

    // Remove from principal's session set
    await this.redis.srem(this.principalKey(session.prn), aid);

    const deleted = await this.redis.del(...keysToDelete);
    return deleted > 0;
  }

  async deleteAllSessionsForPrincipal(prn: string): Promise<number> {
    const aids = await this.redis.smembers(this.principalKey(prn));
    let count = 0;

    for (const aid of aids) {
      if (await this.deleteSession(aid)) {
        count++;
      }
    }

    // Clean up principal key
    await this.redis.del(this.principalKey(prn));

    return count;
  }

  async getSessionsForPrincipal(prn: string): Promise<JTSSession[]> {
    const aids = await this.redis.smembers(this.principalKey(prn));
    const sessions: JTSSession[] = [];

    for (const aid of aids) {
      const session = await this.getSessionByAid(aid);
      if (session) {
        sessions.push(session);
      } else {
        // Clean up stale reference
        await this.redis.srem(this.principalKey(prn), aid);
      }
    }

    return sessions.sort((a, b) => 
      b.lastActive.getTime() - a.lastActive.getTime()
    );
  }

  async countSessionsForPrincipal(prn: string): Promise<number> {
    // This might be slightly inaccurate if there are stale references
    return this.redis.scard(this.principalKey(prn));
  }

  async deleteOldestSessionForPrincipal(prn: string): Promise<boolean> {
    const sessions = await this.getSessionsForPrincipal(prn);
    if (sessions.length === 0) return false;

    // Sort by createdAt ascending (oldest first)
    sessions.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
    
    return this.deleteSession(sessions[0].aid);
  }

  async cleanupExpiredSessions(): Promise<number> {
    // Redis TTL handles most cleanup automatically
    // This method is mainly for cleaning up stale principal references
    const principalKeys = await this.redis.keys(`${this.keyPrefix}prn:*`);
    let cleaned = 0;

    for (const prnKey of principalKeys) {
      const aids = await this.redis.smembers(prnKey);
      for (const aid of aids) {
        const exists = await this.redis.get(this.sessionKey(aid));
        if (!exists) {
          await this.redis.srem(prnKey, aid);
          cleaned++;
        }
      }
    }

    return cleaned;
  }

  async healthCheck(): Promise<boolean> {
    try {
      const result = await this.redis.ping();
      return result === 'PONG';
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.redis.quit();
  }
}
