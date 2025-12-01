/**
 * jts-core - PostgreSQL Session Store
 * Production-ready PostgreSQL implementation
 */

import { JTSSession, CreateSessionInput, SessionValidationResult } from '../types';
import { BaseSessionStore } from './session-store';
import { generateStateProof } from '../crypto';

// Type for pg (optional dependency)
interface PgPool {
  query<T = unknown>(text: string, values?: unknown[]): Promise<{ rows: T[]; rowCount: number }>;
  end(): Promise<void>;
}

export interface PostgresSessionStoreOptions {
  /** PostgreSQL pool instance */
  pool: PgPool;
  /** Table name for sessions */
  tableName?: string;
  /** Schema name (default: public) */
  schema?: string;
  /** Rotation grace window in seconds */
  rotationGraceWindow?: number;
  /** Default session lifetime in seconds */
  defaultSessionLifetime?: number;
}

/**
 * PostgreSQL-based session store implementation
 * Requires pg as a peer dependency
 */
export class PostgresSessionStore extends BaseSessionStore {
  private pool: PgPool;
  private tableName: string;
  private schema: string;

  constructor(options: PostgresSessionStoreOptions) {
    super({
      rotationGraceWindow: options.rotationGraceWindow,
      defaultSessionLifetime: options.defaultSessionLifetime,
    });
    this.pool = options.pool;
    this.tableName = options.tableName ?? 'jts_sessions';
    this.schema = options.schema ?? 'public';
  }

  private get table(): string {
    return `"${this.schema}"."${this.tableName}"`;
  }

  /**
   * Create the sessions table if it doesn't exist
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

  async getSessionByAid(aid: string): Promise<JTSSession | null> {
    const sql = `
      SELECT * FROM ${this.table}
      WHERE aid = $1 AND expires_at > NOW()
    `;

    const result = await this.pool.query(sql, [aid]);
    if (result.rows.length === 0) return null;

    return this.rowToSession(result.rows[0] as Record<string, unknown>);
  }

  async getSessionByStateProof(stateProof: string): Promise<SessionValidationResult> {
    // Look for session by current or previous StateProof
    const sql = `
      SELECT * FROM ${this.table}
      WHERE (current_state_proof = $1 OR previous_state_proof = $1)
        AND expires_at > NOW()
    `;

    const result = await this.pool.query(sql, [stateProof]);
    
    if (result.rows.length === 0) {
      return {
        valid: false,
        error: 'JTS-401-03',
      };
    }

    const session = this.rowToSession(result.rows[0] as Record<string, unknown>);
    return this.validateStateProofLogic(session, stateProof);
  }

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

  async touchSession(aid: string): Promise<void> {
    const sql = `
      UPDATE ${this.table}
      SET last_active = NOW()
      WHERE aid = $1
    `;

    await this.pool.query(sql, [aid]);
  }

  async deleteSession(aid: string): Promise<boolean> {
    const sql = `
      DELETE FROM ${this.table}
      WHERE aid = $1
    `;

    const result = await this.pool.query(sql, [aid]);
    return result.rowCount > 0;
  }

  async deleteAllSessionsForPrincipal(prn: string): Promise<number> {
    const sql = `
      DELETE FROM ${this.table}
      WHERE prn = $1
    `;

    const result = await this.pool.query(sql, [prn]);
    return result.rowCount;
  }

  async getSessionsForPrincipal(prn: string): Promise<JTSSession[]> {
    const sql = `
      SELECT * FROM ${this.table}
      WHERE prn = $1 AND expires_at > NOW()
      ORDER BY last_active DESC
    `;

    const result = await this.pool.query(sql, [prn]);
    return result.rows.map(row => this.rowToSession(row as Record<string, unknown>));
  }

  async countSessionsForPrincipal(prn: string): Promise<number> {
    const sql = `
      SELECT COUNT(*) as count FROM ${this.table}
      WHERE prn = $1 AND expires_at > NOW()
    `;

    const result = await this.pool.query<{ count: string }>(sql, [prn]);
    return parseInt(result.rows[0].count, 10);
  }

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

  async cleanupExpiredSessions(): Promise<number> {
    const sql = `
      DELETE FROM ${this.table}
      WHERE expires_at < NOW()
    `;

    const result = await this.pool.query(sql);
    return result.rowCount;
  }

  async healthCheck(): Promise<boolean> {
    try {
      await this.pool.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
