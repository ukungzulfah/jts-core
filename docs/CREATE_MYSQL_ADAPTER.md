# Guide to Creating @engjts/mysql-adapter

This document contains the complete steps to create the `@engjts/mysql-adapter` package.

---

## 📋 Prerequisites

- Node.js >= 18.0.0
- An npm account with access to the `@engjts` scope
- A MySQL Server for testing

---

## 🚀 Step 1: Create a New Project

```bash
# Create the project folder
mkdir engjts-mysql-adapter
cd engjts-mysql-adapter

# Initialize npm
npm init -y
```

---

## 📝 Step 2: Set up package.json

Edit `package.json`:

```json
{
  "name": "@engjts/mysql-adapter",
  "version": "1.0.0",
  "description": "MySQL session store adapter for @engjts/auth (JTS - Janus Token System)",
  "type": "module",
  "main": "./dist/index.cjs",
  "module": "./dist/index.mjs",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.mjs",
      "require": "./dist/index.cjs",
      "default": "./dist/index.mjs"
    }
  },
  "files": [
    "dist",
    "README.md",
    "LICENSE"
  ],
  "publishConfig": {
    "access": "public"
  },
  "scripts": {
    "build": "rm -rf dist && rollup -c",
    "test": "vitest run",
    "test:watch": "vitest",
    "prepublishOnly": "npm run build && npm run test"
  },
  "keywords": [
    "jts",
    "janus",
    "token",
    "authentication",
    "mysql",
    "session",
    "adapter",
    "engjts"
  ],
  "author": "Your Name",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/ukungzulfah/engjts-mysql-adapter.git"
  },
  "peerDependencies": {
    "@engjts/auth": ">=1.0.0",
    "mysql2": ">=3.0.0"
  },
  "devDependencies": {
    "@engjts/auth": "^1.0.0",
    "@rollup/plugin-commonjs": "^29.0.0",
    "@rollup/plugin-node-resolve": "^16.0.0",
    "@rollup/plugin-typescript": "^12.0.0",
    "@types/node": "^22.0.0",
    "mysql2": "^3.11.0",
    "rollup": "^4.0.0",
    "rollup-plugin-dts": "^6.0.0",
    "tslib": "^2.8.0",
    "typescript": "^5.0.0",
    "vitest": "^4.0.0"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
```

---

## 📦 Step 3: Install Dependencies

```bash
npm install
```

---

## ⚙️ Step 4: Set up TypeScript (tsconfig.json)

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "lib": ["ES2022"]
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

---

## 🔧 Step 5: Set up Rollup (rollup.config.js)

```javascript
import typescript from '@rollup/plugin-typescript';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import dts from 'rollup-plugin-dts';

const external = ['@engjts/auth', '@engjts/auth/adapter', 'mysql2', 'mysql2/promise'];

export default [
  // ESM build
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/index.mjs',
      format: 'esm',
      sourcemap: true,
    },
    external,
    plugins: [
      resolve({ preferBuiltins: true }),
      commonjs(),
      typescript({ tsconfig: './tsconfig.json', declaration: false }),
    ],
  },
  // CJS build
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/index.cjs',
      format: 'cjs',
      sourcemap: true,
      exports: 'named',
    },
    external,
    plugins: [
      resolve({ preferBuiltins: true }),
      commonjs(),
      typescript({ tsconfig: './tsconfig.json', declaration: false }),
    ],
  },
  // Type definitions
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/index.d.ts',
      format: 'esm',
    },
    external,
    plugins: [dts()],
  },
];
```

---

## 📂 Step 6: Create the Folder Structure

```
engjts-mysql-adapter/
├── src/
│   ├── index.ts
│   └── mysql-store.ts
├── tests/
│   └── mysql-store.test.ts
├── package.json
├── tsconfig.json
├── rollup.config.js
├── vitest.config.ts
├── README.md
└── LICENSE
```

---

## 💻 Step 7: Implement the MySQL Store

### src/mysql-store.ts

```typescript
/**
 * @engjts/mysql-adapter - MySQL Session Store
 * Production-ready MySQL implementation for JTS
 */

import {
  BaseSessionStore,
  JTSSession,
  CreateSessionInput,
  SessionValidationResult,
  generateStateProof,
} from '@engjts/auth/adapter';

// Type for mysql2/promise
interface MySQLPool {
  execute<T = unknown>(
    sql: string,
    values?: unknown[]
  ): Promise<[T[], unknown]>;
  query<T = unknown>(sql: string): Promise<[T[], unknown]>;
  end(): Promise<void>;
}

export interface MySQLSessionStoreOptions {
  /** MySQL pool instance (from mysql2/promise) */
  pool: MySQLPool;
  /** Table name for sessions (default: jts_sessions) */
  tableName?: string;
  /** Database name */
  database?: string;
  /** Rotation grace window in seconds */
  rotationGraceWindow?: number;
  /** Default session lifetime in seconds */
  defaultSessionLifetime?: number;
}

/**
 * MySQL-based session store implementation
 * Requires mysql2 as a peer dependency
 */
export class MySQLSessionStore extends BaseSessionStore {
  private pool: MySQLPool;
  private tableName: string;
  private database?: string;

  constructor(options: MySQLSessionStoreOptions) {
    super({
      rotationGraceWindow: options.rotationGraceWindow,
      defaultSessionLifetime: options.defaultSessionLifetime,
    });
    this.pool = options.pool;
    this.tableName = options.tableName ?? 'jts_sessions';
    this.database = options.database;
  }

  private get table(): string {
    return this.database 
      ? `\`${this.database}\`.\`${this.tableName}\``
      : `\`${this.tableName}\``;
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
        state_proof_version INT DEFAULT 1,
        rotation_timestamp DATETIME(3),
        device_fingerprint VARCHAR(128),
        created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        expires_at DATETIME(3) NOT NULL,
        last_active DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        user_agent TEXT,
        ip_address VARCHAR(45),
        metadata JSON,
        
        INDEX idx_prn (prn),
        INDEX idx_current_sp (current_state_proof),
        INDEX idx_previous_sp (previous_state_proof),
        INDEX idx_expires (expires_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
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
      metadata: row.metadata
        ? (typeof row.metadata === 'string'
            ? JSON.parse(row.metadata)
            : row.metadata)
        : undefined,
    };
  }

  async createSession(input: CreateSessionInput): Promise<JTSSession> {
    const sessionData = this.createSessionData(input);

    const sql = `
      INSERT INTO ${this.table} (
        aid, prn, current_state_proof, state_proof_version,
        device_fingerprint, expires_at, user_agent, ip_address, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    await this.pool.execute(sql, [
      sessionData.aid,
      sessionData.prn,
      sessionData.currentStateProof,
      sessionData.stateProofVersion,
      sessionData.deviceFingerprint ?? null,
      sessionData.expiresAt,
      sessionData.userAgent ?? null,
      sessionData.ipAddress ?? null,
      sessionData.metadata ? JSON.stringify(sessionData.metadata) : null,
    ]);

    return sessionData;
  }

  async getSessionByAid(aid: string): Promise<JTSSession | null> {
    const sql = `
      SELECT * FROM ${this.table}
      WHERE aid = ? AND expires_at > NOW()
    `;

    const [rows] = await this.pool.execute<Record<string, unknown>[]>(sql, [aid]);
    if (rows.length === 0) return null;

    return this.rowToSession(rows[0]);
  }

  async getSessionByStateProof(stateProof: string): Promise<SessionValidationResult> {
    const sql = `
      SELECT * FROM ${this.table}
      WHERE (current_state_proof = ? OR previous_state_proof = ?)
        AND expires_at > NOW()
    `;

    const [rows] = await this.pool.execute<Record<string, unknown>[]>(sql, [
      stateProof,
      stateProof,
    ]);

    if (rows.length === 0) {
      return {
        valid: false,
        error: 'JTS-401-03',
      };
    }

    const session = this.rowToSession(rows[0]);
    return this.validateStateProofLogic(session, stateProof);
  }

  async rotateStateProof(aid: string, newStateProof?: string): Promise<JTSSession> {
    const newSP = newStateProof ?? generateStateProof();

    const sql = `
      UPDATE ${this.table}
      SET 
        previous_state_proof = current_state_proof,
        current_state_proof = ?,
        state_proof_version = state_proof_version + 1,
        rotation_timestamp = NOW(3),
        last_active = NOW(3)
      WHERE aid = ? AND expires_at > NOW()
    `;

    await this.pool.execute(sql, [newSP, aid]);

    const session = await this.getSessionByAid(aid);
    if (!session) {
      throw new Error('Session not found');
    }

    return session;
  }

  async touchSession(aid: string): Promise<void> {
    const sql = `
      UPDATE ${this.table}
      SET last_active = NOW(3)
      WHERE aid = ?
    `;

    await this.pool.execute(sql, [aid]);
  }

  async deleteSession(aid: string): Promise<boolean> {
    const sql = `DELETE FROM ${this.table} WHERE aid = ?`;

    const [result] = await this.pool.execute<{ affectedRows: number }>(sql, [aid]);
    return (result as unknown as { affectedRows: number }).affectedRows > 0;
  }

  async deleteAllSessionsForPrincipal(prn: string): Promise<number> {
    const sql = `DELETE FROM ${this.table} WHERE prn = ?`;

    const [result] = await this.pool.execute<{ affectedRows: number }>(sql, [prn]);
    return (result as unknown as { affectedRows: number }).affectedRows;
  }

  async getSessionsForPrincipal(prn: string): Promise<JTSSession[]> {
    const sql = `
      SELECT * FROM ${this.table}
      WHERE prn = ? AND expires_at > NOW()
      ORDER BY last_active DESC
    `;

    const [rows] = await this.pool.execute<Record<string, unknown>[]>(sql, [prn]);
    return rows.map((row) => this.rowToSession(row));
  }

  async countSessionsForPrincipal(prn: string): Promise<number> {
    const sql = `
      SELECT COUNT(*) as count FROM ${this.table}
      WHERE prn = ? AND expires_at > NOW()
    `;

    const [rows] = await this.pool.execute<{ count: number }[]>(sql, [prn]);
    return rows[0].count;
  }

  async deleteOldestSessionForPrincipal(prn: string): Promise<boolean> {
    const sql = `
      DELETE FROM ${this.table}
      WHERE aid = (
        SELECT aid FROM (
          SELECT aid FROM ${this.table}
          WHERE prn = ? AND expires_at > NOW()
          ORDER BY created_at ASC
          LIMIT 1
        ) AS oldest
      )
    `;

    const [result] = await this.pool.execute<{ affectedRows: number }>(sql, [prn]);
    return (result as unknown as { affectedRows: number }).affectedRows > 0;
  }

  async cleanupExpiredSessions(): Promise<number> {
    const sql = `DELETE FROM ${this.table} WHERE expires_at < NOW()`;

    const [result] = await this.pool.execute<{ affectedRows: number }>(sql);
    return (result as unknown as { affectedRows: number }).affectedRows;
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
```

### src/index.ts

```typescript
/**
 * @engjts/mysql-adapter
 * MySQL session store adapter for @engjts/auth
 */

export { MySQLSessionStore, MySQLSessionStoreOptions } from './mysql-store';

// Re-export types that users might need
export type {
  JTSSession,
  CreateSessionInput,
  SessionValidationResult,
  SessionStore,
} from '@engjts/auth/adapter';
```

---

## 🧪 Step 8: Create Tests

### vitest.config.ts

```typescript
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
  },
});
```

### tests/mysql-store.test.ts

```typescript
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import mysql from 'mysql2/promise';
import { MySQLSessionStore } from '../src/mysql-store';

describe('MySQLSessionStore', () => {
  let pool: mysql.Pool;
  let store: MySQLSessionStore;

  beforeAll(async () => {
    // Connect to the test database
    pool = mysql.createPool({
      host: process.env.MYSQL_HOST || 'localhost',
      port: parseInt(process.env.MYSQL_PORT || '3306'),
      user: process.env.MYSQL_USER || 'root',
      password: process.env.MYSQL_PASSWORD || '',
      database: process.env.MYSQL_DATABASE || 'jts_test',
    });

    store = new MySQLSessionStore({ pool });
    await store.initialize();
  });

  afterAll(async () => {
    await store.close();
  });

  beforeEach(async () => {
    // Clean up sessions before each test
    await pool.query('DELETE FROM jts_sessions');
  });

  describe('createSession', () => {
    it('should create a new session', async () => {
      const session = await store.createSession({
        prn: 'user:123',
        deviceFingerprint: 'test-device',
      });

      expect(session.aid).toBeDefined();
      expect(session.prn).toBe('user:123');
      expect(session.currentStateProof).toBeDefined();
      expect(session.stateProofVersion).toBe(1);
    });
  });

  describe('getSessionByAid', () => {
    it('should retrieve a session by aid', async () => {
      const created = await store.createSession({ prn: 'user:456' });
      const retrieved = await store.getSessionByAid(created.aid);

      expect(retrieved).not.toBeNull();
      expect(retrieved?.prn).toBe('user:456');
    });

    it('should return null for a non-existent session', async () => {
      const result = await store.getSessionByAid('non-existent');
      expect(result).toBeNull();
    });
  });

  describe('getSessionByStateProof', () => {
    it('should validate the current StateProof', async () => {
      const session = await store.createSession({ prn: 'user:789' });
      const result = await store.getSessionByStateProof(session.currentStateProof);

      expect(result.valid).toBe(true);
      expect(result.session?.aid).toBe(session.aid);
    });

    it('should return invalid for an unknown StateProof', async () => {
      const result = await store.getSessionByStateProof('unknown-sp');
      expect(result.valid).toBe(false);
      expect(result.error).toBe('JTS-401-03');
    });
  });

  describe('rotateStateProof', () => {
    it('should rotate the StateProof and keep the previous one', async () => {
      const session = await store.createSession({ prn: 'user:101' });
      const originalSP = session.currentStateProof;

      const rotated = await store.rotateStateProof(session.aid);

      expect(rotated.currentStateProof).not.toBe(originalSP);
      expect(rotated.previousStateProof).toBe(originalSP);
      expect(rotated.stateProofVersion).toBe(2);
    });
  });

  describe('deleteSession', () => {
    it('should delete a session', async () => {
      const session = await store.createSession({ prn: 'user:202' });
      const deleted = await store.deleteSession(session.aid);

      expect(deleted).toBe(true);

      const retrieved = await store.getSessionByAid(session.aid);
      expect(retrieved).toBeNull();
    });
  });

  describe('getSessionsForPrincipal', () => {
    it('should get all sessions for a principal', async () => {
      await store.createSession({ prn: 'user:multi' });
      await store.createSession({ prn: 'user:multi' });
      await store.createSession({ prn: 'user:other' });

      const sessions = await store.getSessionsForPrincipal('user:multi');
      expect(sessions).toHaveLength(2);
    });
  });

  describe('countSessionsForPrincipal', () => {
    it('should count sessions correctly', async () => {
      await store.createSession({ prn: 'user:count' });
      await store.createSession({ prn: 'user:count' });

      const count = await store.countSessionsForPrincipal('user:count');
      expect(count).toBe(2);
    });
  });

  describe('healthCheck', () => {
    it('should return true when connected', async () => {
      const healthy = await store.healthCheck();
      expect(healthy).toBe(true);
    });
  });
});
```

---

## 📖 Step 9: Create README.md

```markdown
# @engjts/mysql-adapter

A MySQL session store adapter for [@engjts/auth](https://www.npmjs.com/package/@engjts/auth) (JTS - Janus Token System).

## Installation

```bash
npm install @engjts/mysql-adapter mysql2
```

## Usage

```typescript
import mysql from 'mysql2/promise';
import { JTSAuthServer } from '@engjts/auth';
import { MySQLSessionStore } from '@engjts/mysql-adapter';

// Create a MySQL pool
const pool = mysql.createPool({
  host: 'localhost',
  port: 3306,
  user: 'root',
  password: 'password',
  database: 'myapp',
});

// Create a session store
const sessionStore = new MySQLSessionStore({ pool });

// Initialize the table (run once)
await sessionStore.initialize();

// Use with JTSAuthServer
const authServer = new JTSAuthServer({
  profile: 'JTS-S/v1',
  signingKey: mySigningKey,
  sessionStore,
});
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| pool | MySQLPool | required | A mysql2/promise pool instance |
| tableName | string | 'jts_sessions' | The table name for sessions |
| database | string | undefined | The database name (optional) |
| rotationGraceWindow | number | 10 | The grace window in seconds |
| defaultSessionLifetime | number | 604800 | The session lifetime (7 days) |

## Requirements

- Node.js >= 18.0.0
- MySQL >= 5.7 or MariaDB >= 10.2
- @engjts/auth >= 1.0.0
- mysql2 >= 3.0.0

## License

MIT
```

---

## 🚀 Step 10: Build & Publish

```bash
# Build
npm run build

# Test locally
npm run test

# Login to npm (if not already logged in)
npm login

# Publish
npm publish
```

---

## ✅ Pre-publish Checklist

- [ ] All tests passed
- [ ] README.md is complete with documentation
- [ ] The LICENSE file exists
- [ ] The package.json version is correct
- [ ] The build succeeds without errors
- [ ] Type definitions (.d.ts) are generated correctly

---

## 📚 Resources

- [JTS Specification](https://github.com/ukungzulfah/jts-core/blob/main/JTS_Specification_v1-en.md)
- [@engjts/auth Documentation](https://github.com/ukungzulfah/jts-core)
- [mysql2 Documentation](https://github.com/sidorares/node-mysql2)