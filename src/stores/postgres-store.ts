/**
 * @fileoverview PostgreSQL Session Store Implementation
 * 
 * This module provides a production-ready PostgreSQL-based session store
 * for the JTS authentication system. It implements the SessionStore interface
 * with full support for session lifecycle management, state proof rotation,
 * and concurrent session handling.
 * 
 * @module stores/postgres-store
 * @requires pg - PostgreSQL client (peer dependency)
 * @author JTS Core Team
 * @license MIT
 * @since 1.0.0
 * 
 * @example
 * ```typescript
 * import { Pool } from 'pg';
 * import { PostgresSessionStore } from '@engjts/auth';
 * 
 * const pool = new Pool({ connectionString: process.env.DATABASE_URL });
 * const store = new PostgresSessionStore({ pool });
 * await store.initialize();
 * ```
 */

import { JTSSession, CreateSessionInput, SessionValidationResult, JTS_ERRORS } from '../types';
import { BaseSessionStore } from './session-store';
import { generateStateProof } from '../crypto';

/**
 * PostgreSQL Pool Interface
 * 
 * Defines the minimal interface required for PostgreSQL pool operations.
 * This abstraction allows compatibility with any pg-compatible library
 * without creating a hard dependency on the `pg` package.
 * 
 * @interface PgPool
 * @description Minimal PostgreSQL pool contract for database operations
 */
interface PgPool {
  /**
   * Executes a parameterized SQL query against the database.
   * 
   * @template T - The expected row type returned by the query
   * @param {string} text - The SQL query string with $1, $2... placeholders
   * @param {unknown[]} [values] - Array of parameter values to bind
   * @returns {Promise<{rows: T[], rowCount: number}>} Query result with rows and affected count
   */
  query<T = unknown>(text: string, values?: unknown[]): Promise<{ rows: T[]; rowCount: number }>;
  
  /**
   * Gracefully closes all connections in the pool.
   * Should be called during application shutdown.
   * 
   * @returns {Promise<void>} Resolves when all connections are closed
   */
  end(): Promise<void>;
}

/**
 * Configuration options for PostgresSessionStore
 * 
 * @interface PostgresSessionStoreOptions
 * @description Defines all configurable parameters for initializing
 * a PostgreSQL-based session store instance.
 * 
 * @example
 * ```typescript
 * const options: PostgresSessionStoreOptions = {
 *   pool: new Pool({ connectionString: 'postgresql://...' }),
 *   tableName: 'user_sessions',
 *   schema: 'auth',
 *   rotationGraceWindow: 60,
 *   defaultSessionLifetime: 86400
 * };
 * ```
 */
export interface PostgresSessionStoreOptions {
  /**
   * PostgreSQL connection pool instance.
   * Must implement the PgPool interface with query() and end() methods.
   * 
   * @type {PgPool}
   * @required
   */
  pool: PgPool;
  
  /**
   * Name of the database table for storing sessions.
   * The table will be created automatically if it doesn't exist.
   * 
   * @type {string}
   * @default 'jts_sessions'
   */
  tableName?: string;
  
  /**
   * PostgreSQL schema name where the sessions table resides.
   * Useful for multi-tenant applications or schema separation.
   * 
   * @type {string}
   * @default 'public'
   */
  schema?: string;
  
  /**
   * Grace period (in seconds) during which the previous state proof
   * remains valid after rotation. This prevents race conditions
   * in distributed systems where requests may use stale tokens.
   * 
   * @type {number}
   * @default 30
   */
  rotationGraceWindow?: number;
  
  /**
   * Default session lifetime in seconds.
   * Sessions will automatically expire after this duration.
   * 
   * @type {number}
   * @default 86400 (24 hours)
   */
  defaultSessionLifetime?: number;
}

/**
 * PostgreSQL Session Store Implementation
 * 
 * A production-ready, scalable session store that persists session data
 * in PostgreSQL. This implementation provides:
 * 
 * - **ACID Compliance**: Full transactional integrity for session operations
 * - **State Proof Rotation**: Secure token rotation with grace period support
 * - **Concurrent Access**: Safe for use in distributed/clustered environments
 * - **Automatic Cleanup**: Built-in expired session purging
 * - **Index Optimization**: Pre-configured indexes for common query patterns
 * 
 * @class PostgresSessionStore
 * @extends {BaseSessionStore}
 * @implements {SessionStore}
 * 
 * @example
 * ```typescript
 * // Basic initialization
 * const store = new PostgresSessionStore({
 *   pool: pgPool,
 *   tableName: 'sessions',
 *   schema: 'auth'
 * });
 * 
 * // Initialize database schema
 * await store.initialize();
 * 
 * // Create a new session
 * const session = await store.createSession({
 *   prn: 'user:123',
 *   deviceFingerprint: 'abc123',
 *   userAgent: 'Mozilla/5.0...'
 * });
 * ```
 * 
 * @requires pg - PostgreSQL client library (peer dependency)
 * @see {@link BaseSessionStore} for inherited functionality
 * @since 1.0.0
 */
export class PostgresSessionStore extends BaseSessionStore {
  /** @private PostgreSQL connection pool */
  private pool: PgPool;
  
  /** @private Configured table name for sessions */
  private tableName: string;
  
  /** @private Database schema name */
  private schema: string;

  /**
   * Creates a new PostgresSessionStore instance.
   * 
   * @constructor
   * @param {PostgresSessionStoreOptions} options - Configuration options
   * @throws {Error} If pool is not provided or invalid
   * 
   * @example
   * ```typescript
   * const store = new PostgresSessionStore({
   *   pool: new Pool({ connectionString: DATABASE_URL }),
   *   tableName: 'app_sessions',
   *   rotationGraceWindow: 120
   * });
   * ```
   */
  constructor(options: PostgresSessionStoreOptions) {
    super({
      rotationGraceWindow: options.rotationGraceWindow,
      defaultSessionLifetime: options.defaultSessionLifetime,
    });
    this.pool = options.pool;
    this.tableName = options.tableName ?? 'jts_sessions';
    this.schema = options.schema ?? 'public';
  }

  /**
   * Gets the fully qualified table name with schema.
   * Uses double quotes to handle reserved words and special characters.
   * 
   * @private
   * @readonly
   * @returns {string} Fully qualified table name (e.g., "public"."jts_sessions")
   */
  private get table(): string {
    return `"${this.schema}"."${this.tableName}"`;
  }

  /**
   * Initializes the database schema for session storage.
   * 
   * Creates the sessions table and required indexes if they don't exist.
   * This method is idempotent and safe to call multiple times.
   * 
   * **Table Schema:**
   * - `aid` (PK): Unique session identifier
   * - `prn`: Principal reference (user identifier)
   * - `current_state_proof`: Active authentication token
   * - `previous_state_proof`: Previous token (for rotation grace period)
   * - `state_proof_version`: Incremental version counter
   * - `rotation_timestamp`: Last token rotation time
   * - `device_fingerprint`: Client device identifier
   * - `created_at`: Session creation timestamp
   * - `expires_at`: Session expiration timestamp
   * - `last_active`: Last activity timestamp
   * - `user_agent`: Client user agent string
   * - `ip_address`: Client IP address
   * - `metadata`: Additional JSON metadata
   * 
   * **Created Indexes:**
   * - `idx_*_prn`: For user session lookups
   * - `idx_*_current_sp`: For state proof validation
   * - `idx_*_previous_sp`: For grace period lookups
   * - `idx_*_expires`: For cleanup operations
   * 
   * @async
   * @returns {Promise<void>} Resolves when initialization is complete
   * @throws {Error} If database connection fails or SQL execution errors
   * 
   * @example
   * ```typescript
   * const store = new PostgresSessionStore({ pool });
   * await store.initialize(); // Safe to call on every app start
   * ```
   */
  async initialize(): Promise<void> {
    const createTableSQL = `
      CREATE TABLE IF NOT EXISTS ${this.table} (
        aid VARCHAR(64) PRIMARY KEY,
        prn VARCHAR(256) NOT NULL,
        current_state_proof VARCHAR(256) NOT NULL,
        previous_state_proof VARCHAR(256),
        state_proof_version INTEGER DEFAULT 1,
        rotation_timestamp TIMESTAMPTZ,
        device_fingerprint VARCHAR(128),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        last_active TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        user_agent TEXT,
        ip_address VARCHAR(45),
        metadata JSONB
      );
      
      CREATE INDEX IF NOT EXISTS idx_${this.tableName}_prn ON ${this.table}(prn);
      CREATE INDEX IF NOT EXISTS idx_${this.tableName}_current_sp ON ${this.table}(current_state_proof);
      CREATE INDEX IF NOT EXISTS idx_${this.tableName}_previous_sp ON ${this.table}(previous_state_proof);
      CREATE INDEX IF NOT EXISTS idx_${this.tableName}_expires ON ${this.table}(expires_at);
    `;

    await this.pool.query(createTableSQL);
  }

  /**
   * Transforms a database row into a JTSSession object.
   * 
   * Handles type conversion for dates, optional fields, and ensures
   * consistent data structure across all session retrieval operations.
   * 
   * @private
   * @param {Record<string, unknown>} row - Raw database row from query result
   * @returns {JTSSession} Properly typed session object
   */
  private rowToSession(row: Record<string, unknown>): JTSSession {
    return {
      aid: row.aid as string,
      prn: row.prn as string,
      currentStateProof: row.current_state_proof as string,
      previousStateProof: row.previous_state_proof as string | undefined,
      stateProofVersion: row.state_proof_version as number,
      rotationTimestamp: row.rotation_timestamp 
        ? new Date(row.rotation_timestamp as string) 
        : undefined,
      deviceFingerprint: row.device_fingerprint as string | undefined,
      createdAt: new Date(row.created_at as string),
      expiresAt: new Date(row.expires_at as string),
      lastActive: new Date(row.last_active as string),
      userAgent: row.user_agent as string | undefined,
      ipAddress: row.ip_address as string | undefined,
      metadata: row.metadata as Record<string, unknown> | undefined,
    };
  }

  /**
   * Creates a new session in the database.
   * 
   * Generates a unique session ID (aid) and initial state proof,
   * then persists the session with all provided metadata.
   * 
   * @async
   * @param {CreateSessionInput} input - Session creation parameters
   * @param {string} input.prn - Principal reference (user identifier)
   * @param {string} [input.deviceFingerprint] - Client device fingerprint
   * @param {string} [input.userAgent] - HTTP User-Agent header
   * @param {string} [input.ipAddress] - Client IP address
   * @param {Record<string, unknown>} [input.metadata] - Additional session data
   * @param {number} [input.lifetimeSeconds] - Custom session lifetime
   * 
   * @returns {Promise<JTSSession>} The newly created session object
   * @throws {Error} If database insertion fails
   * 
   * @example
   * ```typescript
   * const session = await store.createSession({
   *   prn: 'user:abc123',
   *   deviceFingerprint: 'fp_xyz',
   *   userAgent: req.headers['user-agent'],
   *   ipAddress: req.ip,
   *   metadata: { role: 'admin' }
   * });
   * ```
   */
  async createSession(input: CreateSessionInput): Promise<JTSSession> {
    const sessionData = this.createSessionData(input);

    const sql = `
      INSERT INTO ${this.table} (
        aid, prn, current_state_proof, state_proof_version,
        device_fingerprint, expires_at, user_agent, ip_address, metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `;

    const result = await this.pool.query(sql, [
      sessionData.aid,
      sessionData.prn,
      sessionData.currentStateProof,
      sessionData.stateProofVersion,
      sessionData.deviceFingerprint ?? null,
      sessionData.expiresAt.toISOString(),
      sessionData.userAgent ?? null,
      sessionData.ipAddress ?? null,
      sessionData.metadata ? JSON.stringify(sessionData.metadata) : null,
    ]);

    return this.rowToSession(result.rows[0] as Record<string, unknown>);
  }

  /**
   * Retrieves a session by its unique identifier (aid).
   * 
   * Only returns non-expired sessions. Use this method when you have
   * the session ID and need to fetch the full session data.
   * 
   * @async
   * @param {string} aid - The unique session identifier
   * @returns {Promise<JTSSession | null>} The session if found and valid, null otherwise
   * 
   * @example
   * ```typescript
   * const session = await store.getSessionByAid('sess_abc123');
   * if (session) {
   *   console.log(`Session for user: ${session.prn}`);
   * }
   * ```
   */
  async getSessionByAid(aid: string): Promise<JTSSession | null> {
    const sql = `
      SELECT * FROM ${this.table}
      WHERE aid = $1 AND expires_at > NOW()
    `;

    const result = await this.pool.query(sql, [aid]);
    if (result.rows.length === 0) return null;

    return this.rowToSession(result.rows[0] as Record<string, unknown>);
  }

  /**
   * Validates and retrieves a session by its state proof token.
   * 
   * This is the primary authentication method. It checks both current
   * and previous state proofs to support graceful token rotation.
   * 
   * **Validation Logic:**
   * 1. Search for session matching current OR previous state proof
   * 2. If found with current proof → valid, return session
   * 3. If found with previous proof → check rotation grace window
   *    - Within grace period → valid (needs rotation)
   *    - Outside grace period → invalid (possible replay attack)
   * 4. If not found → invalid token
   * 
   * @async
   * @param {string} stateProof - The state proof token to validate
   * @returns {Promise<SessionValidationResult>} Validation result with session or error
   * 
   * @example
   * ```typescript
   * const result = await store.getSessionByStateProof(token);
   * if (result.valid) {
   *   // Session is valid
   *   const session = result.session;
   *   if (result.needsRotation) {
   *     // Token should be rotated
   *   }
   * } else {
   *   // Handle invalid token
   *   console.error(result.error);
   * }
   * ```
   */
  async getSessionByStateProof(stateProof: string): Promise<SessionValidationResult> {
    const sql = `
      SELECT * FROM ${this.table}
      WHERE (current_state_proof = $1 OR previous_state_proof = $1)
        AND expires_at > NOW()
    `;

    const result = await this.pool.query(sql, [stateProof]);
    
    if (result.rows.length === 0) {
      return {
        valid: false,
        error: JTS_ERRORS.STATEPROOF_INVALID,
      };
    }

    const session = this.rowToSession(result.rows[0] as Record<string, unknown>);
    return this.validateStateProofLogic(session, stateProof);
  }

  /**
   * Rotates the state proof for a session.
   * 
   * Implements secure token rotation by:
   * 1. Moving current state proof to previous (for grace period)
   * 2. Setting new state proof as current
   * 3. Incrementing version counter
   * 4. Recording rotation timestamp
   * 
   * This ensures continuous authentication while preventing token reuse.
   * 
   * @async
   * @param {string} aid - The session identifier to rotate
   * @param {string} [newStateProof] - Optional custom state proof (auto-generated if not provided)
   * @returns {Promise<JTSSession>} Updated session with new state proof
   * @throws {Error} If session not found or expired
   * 
   * @example
   * ```typescript
   * // Auto-generate new state proof
   * const updatedSession = await store.rotateStateProof('sess_abc123');
   * 
   * // Or provide custom state proof
   * const customSession = await store.rotateStateProof('sess_abc123', 'custom_sp_xyz');
   * ```
   */
  async rotateStateProof(aid: string, newStateProof?: string): Promise<JTSSession> {
    const newSP = newStateProof ?? generateStateProof();

    const sql = `
      UPDATE ${this.table}
      SET 
        previous_state_proof = current_state_proof,
        current_state_proof = $1,
        state_proof_version = state_proof_version + 1,
        rotation_timestamp = NOW(),
        last_active = NOW()
      WHERE aid = $2 AND expires_at > NOW()
      RETURNING *
    `;

    const result = await this.pool.query(sql, [newSP, aid]);
    
    if (result.rows.length === 0) {
      throw new Error('Session not found');
    }

    return this.rowToSession(result.rows[0] as Record<string, unknown>);
  }

  /**
   * Updates the last activity timestamp for a session.
   * 
   * Call this method on each authenticated request to track user activity.
   * Useful for implementing idle timeout policies.
   * 
   * @async
   * @param {string} aid - The session identifier to update
   * @returns {Promise<void>} Resolves when update is complete
   * 
   * @example
   * ```typescript
   * // In authentication middleware
   * await store.touchSession(session.aid);
   * ```
   */
  async touchSession(aid: string): Promise<void> {
    const sql = `
      UPDATE ${this.table}
      SET last_active = NOW()
      WHERE aid = $1
    `;

    await this.pool.query(sql, [aid]);
  }

  /**
   * Deletes a specific session from the store.
   * 
   * Use this for explicit logout functionality. The session is
   * immediately invalidated and cannot be used for authentication.
   * 
   * @async
   * @param {string} aid - The session identifier to delete
   * @returns {Promise<boolean>} True if session was deleted, false if not found
   * 
   * @example
   * ```typescript
   * // Logout endpoint
   * const deleted = await store.deleteSession(session.aid);
   * if (deleted) {
   *   res.json({ message: 'Logged out successfully' });
   * }
   * ```
   */
  async deleteSession(aid: string): Promise<boolean> {
    const sql = `
      DELETE FROM ${this.table}
      WHERE aid = $1
    `;

    const result = await this.pool.query(sql, [aid]);
    return result.rowCount > 0;
  }

  /**
   * Deletes all sessions for a specific user (principal).
   * 
   * Use this for:
   * - "Logout from all devices" functionality
   * - Account security actions (password change, suspected compromise)
   * - Account deletion cleanup
   * 
   * @async
   * @param {string} prn - The principal reference (user identifier)
   * @returns {Promise<number>} Number of sessions deleted
   * 
   * @example
   * ```typescript
   * // Logout all devices
   * const count = await store.deleteAllSessionsForPrincipal('user:123');
   * console.log(`Terminated ${count} sessions`);
   * ```
   */
  async deleteAllSessionsForPrincipal(prn: string): Promise<number> {
    const sql = `
      DELETE FROM ${this.table}
      WHERE prn = $1
    `;

    const result = await this.pool.query(sql, [prn]);
    return result.rowCount;
  }

  /**
   * Retrieves all active sessions for a specific user.
   * 
   * Returns sessions ordered by last activity (most recent first).
   * Useful for displaying active sessions in user account settings.
   * 
   * @async
   * @param {string} prn - The principal reference (user identifier)
   * @returns {Promise<JTSSession[]>} Array of active sessions
   * 
   * @example
   * ```typescript
   * // User account page - show active sessions
   * const sessions = await store.getSessionsForPrincipal('user:123');
   * sessions.forEach(s => {
   *   console.log(`${s.userAgent} - Last active: ${s.lastActive}`);
   * });
   * ```
   */
  async getSessionsForPrincipal(prn: string): Promise<JTSSession[]> {
    const sql = `
      SELECT * FROM ${this.table}
      WHERE prn = $1 AND expires_at > NOW()
      ORDER BY last_active DESC
    `;

    const result = await this.pool.query(sql, [prn]);
    return result.rows.map(row => this.rowToSession(row as Record<string, unknown>));
  }

  /**
   * Counts the number of active sessions for a user.
   * 
   * Use this to enforce session limits before creating new sessions.
   * More efficient than fetching all sessions when you only need the count.
   * 
   * @async
   * @param {string} prn - The principal reference (user identifier)
   * @returns {Promise<number>} Number of active sessions
   * 
   * @example
   * ```typescript
   * const MAX_SESSIONS = 5;
   * const count = await store.countSessionsForPrincipal('user:123');
   * if (count >= MAX_SESSIONS) {
   *   await store.deleteOldestSessionForPrincipal('user:123');
   * }
   * ```
   */
  async countSessionsForPrincipal(prn: string): Promise<number> {
    const sql = `
      SELECT COUNT(*) as count FROM ${this.table}
      WHERE prn = $1 AND expires_at > NOW()
    `;

    const result = await this.pool.query<{ count: string }>(sql, [prn]);
    return parseInt(result.rows[0].count, 10);
  }

  /**
   * Deletes the oldest session for a user.
   * 
   * Implements FIFO (First-In-First-Out) session eviction policy.
   * Call this when a user exceeds their maximum allowed sessions
   * to make room for a new session.
   * 
   * @async
   * @param {string} prn - The principal reference (user identifier)
   * @returns {Promise<boolean>} True if a session was deleted, false if none existed
   * 
   * @example
   * ```typescript
   * // Enforce session limit with automatic eviction
   * if (await store.countSessionsForPrincipal(prn) >= MAX_SESSIONS) {
   *   await store.deleteOldestSessionForPrincipal(prn);
   * }
   * const newSession = await store.createSession({ prn });
   * ```
   */
  async deleteOldestSessionForPrincipal(prn: string): Promise<boolean> {
    const sql = `
      DELETE FROM ${this.table}
      WHERE aid = (
        SELECT aid FROM ${this.table}
        WHERE prn = $1 AND expires_at > NOW()
        ORDER BY created_at ASC
        LIMIT 1
      )
    `;

    const result = await this.pool.query(sql, [prn]);
    return result.rowCount > 0;
  }

  /**
   * Removes all expired sessions from the database.
   * 
   * Should be called periodically (e.g., via cron job or scheduled task)
   * to prevent database bloat and maintain performance.
   * 
   * **Recommended Schedule:**
   * - High-traffic apps: Every 15-30 minutes
   * - Medium-traffic apps: Every 1-2 hours
   * - Low-traffic apps: Daily
   * 
   * @async
   * @returns {Promise<number>} Number of expired sessions removed
   * 
   * @example
   * ```typescript
   * // Scheduled cleanup job
   * import cron from 'node-cron';
   * 
   * cron.schedule('0 * * * *', async () => {
   *   const cleaned = await store.cleanupExpiredSessions();
   *   console.log(`Cleaned up ${cleaned} expired sessions`);
   * });
   * ```
   */
  async cleanupExpiredSessions(): Promise<number> {
    const sql = `
      DELETE FROM ${this.table}
      WHERE expires_at < NOW()
    `;

    const result = await this.pool.query(sql);
    return result.rowCount;
  }

  /**
   * Performs a database connectivity health check.
   * 
   * Executes a simple query to verify the database connection is alive.
   * Use this for:
   * - Kubernetes/Docker health probes
   * - Load balancer health checks
   * - Monitoring and alerting systems
   * 
   * @async
   * @returns {Promise<boolean>} True if database is reachable, false otherwise
   * 
   * @example
   * ```typescript
   * // Express health endpoint
   * app.get('/health', async (req, res) => {
   *   const healthy = await store.healthCheck();
   *   res.status(healthy ? 200 : 503).json({ 
   *     status: healthy ? 'healthy' : 'unhealthy',
   *     store: 'postgres'
   *   });
   * });
   * ```
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.pool.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Gracefully closes the database connection pool.
   * 
   * Should be called during application shutdown to properly
   * release database connections and prevent resource leaks.
   * 
   * **Important:** After calling close(), the store instance
   * cannot be used. Create a new instance if needed.
   * 
   * @async
   * @returns {Promise<void>} Resolves when all connections are closed
   * 
   * @example
   * ```typescript
   * // Graceful shutdown handler
   * process.on('SIGTERM', async () => {
   *   console.log('Shutting down...');
   *   await store.close();
   *   process.exit(0);
   * });
   * ```
   */
  async close(): Promise<void> {
    await this.pool.end();
  }
}
