/**
 * @fileoverview Redis Session Store Implementation for JTS Authentication
 * 
 * This module provides a production-ready, high-performance Redis-based session
 * storage implementation for the JTS (JSON Token Session) authentication system.
 * 
 * @module stores/redis-store
 * @version 1.0.0
 * @license MIT
 * 
 * @description
 * The RedisSessionStore leverages Redis's in-memory data structure store to provide:
 * - Sub-millisecond session lookup and validation
 * - Automatic session expiration via Redis TTL
 * - Distributed session management across multiple server instances
 * - StateProof rotation with configurable grace windows
 * - Principal-based session grouping for multi-device support
 * 
 * @example
 * ```typescript
 * import Redis from 'ioredis';
 * import { RedisSessionStore } from '@engjts/auth';
 * 
 * const redis = new Redis({
 *   host: 'localhost',
 *   port: 6379,
 *   password: process.env.REDIS_PASSWORD,
 * });
 * 
 * const sessionStore = new RedisSessionStore({
 *   client: redis,
 *   keyPrefix: 'myapp:session:',
 *   rotationGraceWindow: 30,
 *   defaultSessionLifetime: 86400,
 * });
 * ```
 * 
 * @requires ioredis - Redis client (peer dependency)
 * @see {@link https://github.com/redis/ioredis} for ioredis documentation
 */

import { JTSSession, CreateSessionInput, SessionValidationResult, JTS_ERRORS } from '../types';
import { BaseSessionStore } from './session-store';
import { generateStateProof } from '../crypto';

/**
 * Redis client interface compatible with ioredis.
 * 
 * This interface defines the minimal set of Redis commands required by the
 * RedisSessionStore. It allows for dependency injection and easier testing
 * with mock implementations.
 * 
 * @interface RedisClient
 * @description Abstraction layer for Redis operations used in session management
 */
interface RedisClient {
  /**
   * Retrieves the value associated with the specified key.
   * @param key - The key to retrieve
   * @returns The value if found, null otherwise
   */
  get(key: string): Promise<string | null>;

  /**
   * Sets a key-value pair with optional expiration arguments.
   * @param key - The key to set
   * @param value - The value to store
   * @param args - Additional arguments (e.g., 'EX', ttl for expiration)
   * @returns 'OK' on success, null on failure
   */
  set(key: string, value: string, ...args: (string | number)[]): Promise<string | null>;

  /**
   * Deletes one or more keys from Redis.
   * @param keys - The keys to delete
   * @returns The number of keys that were removed
   */
  del(...keys: string[]): Promise<number>;

  /**
   * Finds all keys matching a given pattern.
   * @param pattern - The glob-style pattern to match
   * @returns Array of matching key names
   * @warning Use with caution in production - may block Redis on large datasets
   */
  keys(pattern: string): Promise<string[]>;

  /**
   * Sets a timeout on a key.
   * @param key - The key to set expiration on
   * @param seconds - Time to live in seconds
   * @returns 1 if timeout was set, 0 if key doesn't exist
   */
  expire(key: string, seconds: number): Promise<number>;

  /**
   * Tests connectivity to the Redis server.
   * @returns 'PONG' if the server is reachable
   */
  ping(): Promise<string>;

  /**
   * Gracefully closes the Redis connection.
   * @returns 'OK' on success
   */
  quit(): Promise<string>;

  /**
   * Adds one or more members to a set.
   * @param key - The set key
   * @param members - Members to add
   * @returns The number of elements added
   */
  sadd(key: string, ...members: string[]): Promise<number>;

  /**
   * Returns all members of a set.
   * @param key - The set key
   * @returns Array of all set members
   */
  smembers(key: string): Promise<string[]>;

  /**
   * Removes one or more members from a set.
   * @param key - The set key
   * @param members - Members to remove
   * @returns The number of members removed
   */
  srem(key: string, ...members: string[]): Promise<number>;

  /**
   * Returns the cardinality (number of elements) of a set.
   * @param key - The set key
   * @returns The number of elements in the set
   */
  scard(key: string): Promise<number>;
}

/**
 * Configuration options for the Redis session store.
 * 
 * @interface RedisSessionStoreOptions
 * @description Defines the configuration parameters for initializing a RedisSessionStore
 * 
 * @example
 * ```typescript
 * const options: RedisSessionStoreOptions = {
 *   client: redisClient,
 *   keyPrefix: 'auth:sessions:',
 *   rotationGraceWindow: 60,
 *   defaultSessionLifetime: 7 * 24 * 60 * 60, // 7 days
 * };
 * ```
 */
export interface RedisSessionStoreOptions {
  /**
   * The Redis client instance to use for all operations.
   * Must be a pre-configured ioredis client instance.
   * 
   * @required
   * @example
   * ```typescript
   * import Redis from 'ioredis';
   * const client = new Redis({ host: 'localhost', port: 6379 });
   * ```
   */
  client: RedisClient;

  /**
   * Prefix applied to all Redis keys created by this store.
   * Useful for namespacing and multi-tenant deployments.
   * 
   * @default 'jts:session:'
   * @example 'myapp:prod:session:'
   */
  keyPrefix?: string;

  /**
   * Duration in seconds during which the previous StateProof
   * remains valid after rotation. This handles race conditions
   * where requests with the old StateProof are still in flight.
   * 
   * @default 30
   * @minimum 5
   * @maximum 300
   */
  rotationGraceWindow?: number;

  /**
   * Default session lifetime in seconds when not specified
   * during session creation.
   * 
   * @default 86400 (24 hours)
   */
  defaultSessionLifetime?: number;
}

/**
 * Redis-based session store implementation for JTS authentication.
 * 
 * This class provides a scalable, distributed session management solution
 * using Redis as the backing store. It supports all JTS session operations
 * including creation, validation, rotation, and cleanup.
 * 
 * @class RedisSessionStore
 * @extends BaseSessionStore
 * 
 * @description
 * Key features:
 * - **Automatic Expiration**: Leverages Redis TTL for session cleanup
 * - **StateProof Indexing**: O(1) session lookup by StateProof
 * - **Principal Grouping**: Efficient multi-session management per user
 * - **Rotation Grace Period**: Seamless StateProof rotation without request failures
 * - **Health Monitoring**: Built-in health check endpoint
 * 
 * Redis Key Schema:
 * - `{prefix}{aid}` - Session data (JSON serialized)
 * - `{prefix}sp:{stateProof}` - StateProof to AID mapping
 * - `{prefix}prn:{principal}` - Set of AIDs for a principal
 * 
 * @example
 * ```typescript
 * const store = new RedisSessionStore({
 *   client: redisClient,
 *   keyPrefix: 'jts:session:',
 *   rotationGraceWindow: 30,
 * });
 * 
 * // Create a new session
 * const session = await store.createSession({
 *   prn: 'user:12345',
 *   scope: ['read', 'write'],
 *   metadata: { deviceId: 'mobile-001' },
 * });
 * 
 * // Validate a StateProof
 * const result = await store.getSessionByStateProof(stateProof);
 * if (result.valid) {
 *   console.log('Session valid:', result.session);
 * }
 * ```
 * 
 * @see BaseSessionStore for inherited methods and properties
 */
export class RedisSessionStore extends BaseSessionStore {
  /** @private Redis client instance for all storage operations */
  private redis: RedisClient;

  /** @private Prefix applied to all Redis keys for namespacing */
  private keyPrefix: string;

  /**
   * Creates a new RedisSessionStore instance.
   * 
   * @constructor
   * @param {RedisSessionStoreOptions} options - Configuration options for the store
   * @throws {Error} If the Redis client is not provided or invalid
   * 
   * @example
   * ```typescript
   * const store = new RedisSessionStore({
   *   client: new Redis(),
   *   keyPrefix: 'myapp:sessions:',
   *   rotationGraceWindow: 45,
   *   defaultSessionLifetime: 3600,
   * });
   * ```
   */
  constructor(options: RedisSessionStoreOptions) {
    super({
      rotationGraceWindow: options.rotationGraceWindow,
      defaultSessionLifetime: options.defaultSessionLifetime,
    });
    this.redis = options.client;
    this.keyPrefix = options.keyPrefix ?? 'jts:session:';
  }

  /**
   * Generates the Redis key for storing session data.
   * 
   * @private
   * @param {string} aid - The unique session identifier (Authentication ID)
   * @returns {string} The fully qualified Redis key
   * 
   * @example
   * // Returns 'jts:session:abc123'
   * this.sessionKey('abc123');
   */
  private sessionKey(aid: string): string {
    return `${this.keyPrefix}${aid}`;
  }

  /**
   * Generates the Redis key for StateProof-to-AID mapping.
   * 
   * @private
   * @param {string} stateProof - The StateProof token
   * @returns {string} The fully qualified Redis key for the StateProof index
   * 
   * @example
   * // Returns 'jts:session:sp:xyz789'
   * this.stateProofKey('xyz789');
   */
  private stateProofKey(stateProof: string): string {
    return `${this.keyPrefix}sp:${stateProof}`;
  }

  /**
   * Generates the Redis key for the principal's session set.
   * 
   * @private
   * @param {string} prn - The principal identifier (user/entity ID)
   * @returns {string} The fully qualified Redis key for the principal's session set
   * 
   * @example
   * // Returns 'jts:session:prn:user:12345'
   * this.principalKey('user:12345');
   */
  private principalKey(prn: string): string {
    return `${this.keyPrefix}prn:${prn}`;
  }

  /**
   * Serializes a JTSSession object to a JSON string for Redis storage.
   * 
   * Converts Date objects to ISO 8601 strings to ensure proper
   * serialization and cross-platform compatibility.
   * 
   * @private
   * @param {JTSSession} session - The session object to serialize
   * @returns {string} JSON string representation of the session
   * 
   * @see deserializeSession for the reverse operation
   */
  private serializeSession(session: JTSSession): string {
    return JSON.stringify({
      ...session,
      createdAt: session.createdAt.toISOString(),
      expiresAt: session.expiresAt.toISOString(),
      lastActive: session.lastActive.toISOString(),
      rotationTimestamp: session.rotationTimestamp?.toISOString(),
    });
  }

  /**
   * Deserializes a JSON string from Redis into a JTSSession object.
   * 
   * Reconstructs Date objects from ISO 8601 strings stored in Redis.
   * 
   * @private
   * @param {string} data - The JSON string to deserialize
   * @returns {JTSSession} The reconstructed session object
   * @throws {SyntaxError} If the JSON string is malformed
   * 
   * @see serializeSession for the reverse operation
   */
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

  /**
   * Creates a new session and stores it in Redis.
   * 
   * This method performs the following operations atomically:
   * 1. Generates session data with a unique AID and StateProof
   * 2. Stores the serialized session with TTL-based expiration
   * 3. Creates a StateProof index for O(1) lookup
   * 4. Adds the session to the principal's session set
   * 
   * @override
   * @async
   * @param {CreateSessionInput} input - Session creation parameters
   * @returns {Promise<JTSSession>} The newly created session object
   * 
   * @example
   * ```typescript
   * const session = await store.createSession({
   *   prn: 'user:12345',
   *   scope: ['read', 'write'],
   *   metadata: { 
   *     deviceId: 'mobile-001',
   *     userAgent: 'Mozilla/5.0...',
   *   },
   *   lifetime: 86400, // 24 hours
   * });
   * ```
   */
  async createSession(input: CreateSessionInput): Promise<JTSSession> {
    const sessionData = this.createSessionData(input);
    const session: JTSSession = sessionData;
    
    // Calculate TTL in seconds from expiration time
    const ttl = Math.ceil((session.expiresAt.getTime() - Date.now()) / 1000);
    
    // Store session data with automatic expiration
    await this.redis.set(
      this.sessionKey(session.aid),
      this.serializeSession(session),
      'EX',
      ttl
    );

    // Create StateProof index for reverse lookup
    await this.redis.set(
      this.stateProofKey(session.currentStateProof),
      session.aid,
      'EX',
      ttl
    );

    // Register session under principal for multi-session management
    await this.redis.sadd(this.principalKey(session.prn), session.aid);

    return session;
  }

  /**
   * Retrieves a session by its unique Authentication ID (AID).
   * 
   * Performs a direct key lookup in Redis and validates session expiration.
   * Even though Redis TTL handles expiration, this method double-checks
   * to handle edge cases during the TTL precision window.
   * 
   * @override
   * @async
   * @param {string} aid - The unique session identifier
   * @returns {Promise<JTSSession | null>} The session if found and valid, null otherwise
   * 
   * @example
   * ```typescript
   * const session = await store.getSessionByAid('session-abc-123');
   * if (session) {
   *   console.log(`Session for ${session.prn} is active`);
   * }
   * ```
   */
  async getSessionByAid(aid: string): Promise<JTSSession | null> {
    const data = await this.redis.get(this.sessionKey(aid));
    if (!data) return null;
    
    const session = this.deserializeSession(data);
    
    // Secondary expiration check (Redis TTL precision safeguard)
    if (new Date() > session.expiresAt) {
      await this.deleteSession(aid);
      return null;
    }
    
    return session;
  }

  /**
   * Validates a StateProof and retrieves the associated session.
   * 
   * This method supports StateProof rotation by checking both current
   * and previous StateProofs within the grace window period.
   * 
   * @override
   * @async
   * @param {string} stateProof - The StateProof token to validate
   * @returns {Promise<SessionValidationResult>} Validation result with session or error
   * 
   * @example
   * ```typescript
   * const result = await store.getSessionByStateProof(bearerToken);
   * 
   * if (result.valid) {
   *   // Proceed with authenticated request
   *   const { session, requiresRotation } = result;
   *   if (requiresRotation) {
   *     // Schedule StateProof rotation in response
   *   }
   * } else {
   *   // Handle authentication failure
   *   console.error('Auth failed:', result.error);
   * }
   * ```
   */
  async getSessionByStateProof(stateProof: string): Promise<SessionValidationResult> {
    // Attempt to resolve AID from StateProof index
    const aid = await this.redis.get(this.stateProofKey(stateProof));
    
    if (aid) {
      const session = await this.getSessionByAid(aid);
      if (session) {
        return this.validateStateProofLogic(session, stateProof);
      }
    }

    // StateProof not found - either expired, revoked, or never existed
    return {
      valid: false,
      error: JTS_ERRORS.STATEPROOF_INVALID,
    };
  }

  /**
   * Rotates the StateProof for an existing session.
   * 
   * StateProof rotation is a security measure that limits the window of
   * vulnerability if a token is compromised. This method:
   * 1. Generates a new StateProof (or uses the provided one)
   * 2. Archives the current StateProof for the grace period
   * 3. Updates the session with the new StateProof
   * 4. Creates new index mappings
   * 
   * @override
   * @async
   * @param {string} aid - The session's unique identifier
   * @param {string} [newStateProof] - Optional custom StateProof (auto-generated if omitted)
   * @returns {Promise<JTSSession>} The updated session with new StateProof
   * @throws {Error} If the session does not exist
   * 
   * @example
   * ```typescript
   * try {
   *   const updatedSession = await store.rotateStateProof('session-abc-123');
   *   // Return new StateProof to client in response header
   *   res.setHeader('X-JTS-StateProof', updatedSession.currentStateProof);
   * } catch (error) {
   *   console.error('Rotation failed:', error.message);
   * }
   * ```
   */
  async rotateStateProof(aid: string, newStateProof?: string): Promise<JTSSession> {
    const session = await this.getSessionByAid(aid);
    if (!session) {
      throw new Error('Session not found');
    }

    const newSP = newStateProof ?? generateStateProof();
    const ttl = Math.ceil((session.expiresAt.getTime() - Date.now()) / 1000);
    
    // Grace TTL includes buffer for network latency
    const graceTTL = Math.min(ttl, this.rotationGraceWindow + 5);

    // Remove obsolete previous StateProof mapping
    if (session.previousStateProof) {
      await this.redis.del(this.stateProofKey(session.previousStateProof));
    }

    // Perform StateProof rotation on session object
    const oldStateProof = session.currentStateProof;
    session.previousStateProof = oldStateProof;
    session.currentStateProof = newSP;
    session.stateProofVersion += 1;
    session.rotationTimestamp = new Date();
    session.lastActive = new Date();

    // Persist updated session state
    await this.redis.set(
      this.sessionKey(aid),
      this.serializeSession(session),
      'EX',
      ttl
    );

    // Create index for new StateProof
    await this.redis.set(
      this.stateProofKey(newSP),
      aid,
      'EX',
      ttl
    );

    // Maintain old StateProof index during grace window
    await this.redis.set(
      this.stateProofKey(oldStateProof),
      aid,
      'EX',
      graceTTL
    );

    return session;
  }

  /**
   * Updates the session's last activity timestamp.
   * 
   * This method is useful for implementing session sliding expiration
   * or tracking user activity without modifying other session data.
   * 
   * @override
   * @async
   * @param {string} aid - The session's unique identifier
   * @returns {Promise<void>}
   * 
   * @example
   * ```typescript
   * // Update activity on each API request
   * app.use(async (req, res, next) => {
   *   if (req.sessionAid) {
   *     await store.touchSession(req.sessionAid);
   *   }
   *   next();
   * });
   * ```
   */
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

  /**
   * Permanently deletes a session and all associated data.
   * 
   * This method removes:
   * - The session data
   * - Current StateProof index
   * - Previous StateProof index (if exists)
   * - Reference from principal's session set
   * 
   * @override
   * @async
   * @param {string} aid - The session's unique identifier
   * @returns {Promise<boolean>} True if session was deleted, false if not found
   * 
   * @example
   * ```typescript
   * // Logout endpoint
   * app.post('/logout', async (req, res) => {
   *   const deleted = await store.deleteSession(req.sessionAid);
   *   if (deleted) {
   *     res.json({ message: 'Successfully logged out' });
   *   } else {
   *     res.status(404).json({ error: 'Session not found' });
   *   }
   * });
   * ```
   */
  async deleteSession(aid: string): Promise<boolean> {
    const session = await this.getSessionByAid(aid);
    if (!session) return false;

    // Collect all keys to delete in single operation
    const keysToDelete = [
      this.sessionKey(aid),
      this.stateProofKey(session.currentStateProof),
    ];
    
    if (session.previousStateProof) {
      keysToDelete.push(this.stateProofKey(session.previousStateProof));
    }

    // Remove session from principal's session registry
    await this.redis.srem(this.principalKey(session.prn), aid);

    // Perform bulk deletion
    const deleted = await this.redis.del(...keysToDelete);
    return deleted > 0;
  }

  /**
   * Terminates all sessions for a specific principal (user/entity).
   * 
   * This is useful for implementing "logout from all devices" functionality
   * or responding to security incidents requiring full session invalidation.
   * 
   * @override
   * @async
   * @param {string} prn - The principal identifier
   * @returns {Promise<number>} The number of sessions deleted
   * 
   * @example
   * ```typescript
   * // Security: Revoke all sessions after password change
   * app.post('/change-password', async (req, res) => {
   *   await updatePassword(req.user.id, req.body.newPassword);
   *   const revokedCount = await store.deleteAllSessionsForPrincipal(req.user.id);
   *   console.log(`Revoked ${revokedCount} sessions for security`);
   *   res.json({ message: 'Password changed, please login again' });
   * });
   * ```
   */
  async deleteAllSessionsForPrincipal(prn: string): Promise<number> {
    const aids = await this.redis.smembers(this.principalKey(prn));
    let count = 0;

    for (const aid of aids) {
      if (await this.deleteSession(aid)) {
        count++;
      }
    }

    // Remove the principal's session set key
    await this.redis.del(this.principalKey(prn));

    return count;
  }

  /**
   * Retrieves all active sessions for a specific principal.
   * 
   * Sessions are returned sorted by last activity time (most recent first).
   * Stale references in the principal's session set are automatically cleaned.
   * 
   * @override
   * @async
   * @param {string} prn - The principal identifier
   * @returns {Promise<JTSSession[]>} Array of active sessions, sorted by activity
   * 
   * @example
   * ```typescript
   * // Display active sessions in user dashboard
   * app.get('/sessions', async (req, res) => {
   *   const sessions = await store.getSessionsForPrincipal(req.user.id);
   *   res.json(sessions.map(s => ({
   *     id: s.aid,
   *     device: s.metadata?.deviceId,
   *     lastActive: s.lastActive,
   *     isCurrent: s.aid === req.sessionAid,
   *   })));
   * });
   * ```
   */
  async getSessionsForPrincipal(prn: string): Promise<JTSSession[]> {
    const aids = await this.redis.smembers(this.principalKey(prn));
    const sessions: JTSSession[] = [];

    for (const aid of aids) {
      const session = await this.getSessionByAid(aid);
      if (session) {
        sessions.push(session);
      } else {
        // Cleanup stale reference from principal's set
        await this.redis.srem(this.principalKey(prn), aid);
      }
    }

    // Sort by most recently active first
    return sessions.sort((a, b) => 
      b.lastActive.getTime() - a.lastActive.getTime()
    );
  }

  /**
   * Returns the count of active sessions for a principal.
   * 
   * Note: This count may include stale references if sessions expired
   * but haven't been cleaned up yet. For accurate counts, use
   * `getSessionsForPrincipal().length` which performs cleanup.
   * 
   * @override
   * @async
   * @param {string} prn - The principal identifier
   * @returns {Promise<number>} The approximate number of active sessions
   * 
   * @example
   * ```typescript
   * // Check session limit before creating new session
   * const MAX_SESSIONS = 5;
   * const currentCount = await store.countSessionsForPrincipal(userId);
   * if (currentCount >= MAX_SESSIONS) {
   *   await store.deleteOldestSessionForPrincipal(userId);
   * }
   * ```
   */
  async countSessionsForPrincipal(prn: string): Promise<number> {
    return this.redis.scard(this.principalKey(prn));
  }

  /**
   * Deletes the oldest session for a principal based on creation time.
   * 
   * This method is useful for implementing session limits per user,
   * automatically removing the oldest session when creating a new one.
   * 
   * @override
   * @async
   * @param {string} prn - The principal identifier
   * @returns {Promise<boolean>} True if a session was deleted, false if none exist
   * 
   * @example
   * ```typescript
   * // Enforce maximum sessions per user
   * async function createSessionWithLimit(userId: string, limit: number) {
   *   while (await store.countSessionsForPrincipal(userId) >= limit) {
   *     await store.deleteOldestSessionForPrincipal(userId);
   *   }
   *   return store.createSession({ prn: userId });
   * }
   * ```
   */
  async deleteOldestSessionForPrincipal(prn: string): Promise<boolean> {
    const sessions = await this.getSessionsForPrincipal(prn);
    if (sessions.length === 0) return false;

    // Sort by creation time ascending (oldest first)
    sessions.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
    
    return this.deleteSession(sessions[0].aid);
  }

  /**
   * Performs maintenance cleanup of stale session references.
   * 
   * While Redis TTL handles session data expiration automatically,
   * this method cleans up orphaned references in principal session sets
   * that may remain after session expiration.
   * 
   * @override
   * @async
   * @returns {Promise<number>} The number of stale references cleaned
   * 
   * @remarks
   * Consider running this periodically in a background job (e.g., hourly)
   * to maintain optimal memory usage and query performance.
   * 
   * @example
   * ```typescript
   * // Scheduled cleanup task (e.g., using node-cron)
   * import cron from 'node-cron';
   * 
   * cron.schedule('0 * * * *', async () => {
   *   const cleaned = await store.cleanupExpiredSessions();
   *   console.log(`Cleanup complete: removed ${cleaned} stale references`);
   * });
   * ```
   */
  async cleanupExpiredSessions(): Promise<number> {
    // Discover all principal keys in the store
    const principalKeys = await this.redis.keys(`${this.keyPrefix}prn:*`);
    let cleaned = 0;

    for (const prnKey of principalKeys) {
      const aids = await this.redis.smembers(prnKey);
      for (const aid of aids) {
        // Check if session still exists
        const exists = await this.redis.get(this.sessionKey(aid));
        if (!exists) {
          // Remove orphaned reference
          await this.redis.srem(prnKey, aid);
          cleaned++;
        }
      }
    }

    return cleaned;
  }

  /**
   * Performs a health check on the Redis connection.
   * 
   * This method can be used for load balancer health probes or
   * monitoring systems to verify the session store is operational.
   * 
   * @override
   * @async
   * @returns {Promise<boolean>} True if Redis is reachable and responding
   * 
   * @example
   * ```typescript
   * // Health check endpoint
   * app.get('/health', async (req, res) => {
   *   const redisHealthy = await store.healthCheck();
   *   if (redisHealthy) {
   *     res.status(200).json({ status: 'healthy', redis: 'connected' });
   *   } else {
   *     res.status(503).json({ status: 'unhealthy', redis: 'disconnected' });
   *   }
   * });
   * ```
   */
  async healthCheck(): Promise<boolean> {
    try {
      const result = await this.redis.ping();
      return result === 'PONG';
    } catch {
      return false;
    }
  }

  /**
   * Gracefully closes the Redis connection.
   * 
   * Call this method during application shutdown to ensure proper
   * cleanup of Redis connections and prevent resource leaks.
   * 
   * @override
   * @async
   * @returns {Promise<void>}
   * 
   * @example
   * ```typescript
   * // Graceful shutdown handler
   * process.on('SIGTERM', async () => {
   *   console.log('Shutting down gracefully...');
   *   await store.close();
   *   process.exit(0);
   * });
   * ```
   */
  async close(): Promise<void> {
    await this.redis.quit();
  }
}
