# JTS Adapter Development Guide

A guide to creating custom database adapters for `@engjts/auth`.

## Overview

`@engjts/auth` uses an adapter system that allows you to create a session store for any database. This library already provides:

- `InMemorySessionStore` - For development/testing
- `PostgresSessionStore` - PostgreSQL adapter
- `RedisSessionStore` - Redis adapter

You can create additional adapters like MySQL, MongoDB, SQLite, etc.

## Quick Start

### 1. Import Adapter SDK

```typescript
import {
  BaseSessionStore,
  SessionStore,
  JTSSession,
  CreateSessionInput,
  SessionValidationResult,
  generateStateProof,
  generateAnchorId,
} from '@engjts/auth/adapter';
```

### 2. Extend BaseSessionStore

```typescript
export class MyCustomSessionStore extends BaseSessionStore {
  // Implement all abstract methods
}
```

## SessionStore Interface

All adapters must implement the `SessionStore` interface:

```typescript
interface SessionStore {
  // Create a new session
  createSession(input: CreateSessionInput): Promise<JTSSession>;

  // Get a session by its anchor ID
  getSessionByAid(aid: string): Promise<JTSSession | null>;

  // Get a session by its StateProof (current or previous)
  getSessionByStateProof(stateProof: string): Promise<SessionValidationResult>;

  // Update a session's StateProof (rotation)
  rotateStateProof(aid: string, newStateProof?: string): Promise<JTSSession>;

  // Update the last active timestamp
  touchSession(aid: string): Promise<void>;

  // Delete a session (logout/revoke)
  deleteSession(aid: string): Promise<boolean>;

  // Delete all sessions for a principal (user)
  deleteAllSessionsForPrincipal(prn: string): Promise<number>;

  // Get all active sessions for a principal
  getSessionsForPrincipal(prn: string): Promise<JTSSession[]>;

  // Count active sessions for a principal
  countSessionsForPrincipal(prn: string): Promise<number>;

  // Delete the oldest session for a principal
  deleteOldestSessionForPrincipal(prn: string): Promise<boolean>;

  // Clean up expired sessions
  cleanupExpiredSessions(): Promise<number>;

  // Check if the store is healthy/connected
  healthCheck(): Promise<boolean>;

  // Close the connection (cleanup)
  close(): Promise<void>;
}
```

## JTSSession Structure

```typescript
interface JTSSession {
  aid: string;                    // Anchor ID - Primary key
  prn: string;                    // Principal - User/entity ID
  currentStateProof: string;      // Current StateProof token
  previousStateProof?: string;    // Previous StateProof (for grace window)
  stateProofVersion: number;      // StateProof version counter
  rotationTimestamp?: Date;       // When rotation occurred
  deviceFingerprint?: string;     // Device fingerprint
  createdAt: Date;                // Session created at
  expiresAt: Date;                // Session expires at
  lastActive: Date;               // Last activity timestamp
  userAgent?: string;             // User agent string
  ipAddress?: string;             // IP address
  metadata?: Record<string, unknown>;  // Additional metadata
}
```

## BaseSessionStore Helper Methods

`BaseSessionStore` provides several helper methods that are already implemented:

```typescript
abstract class BaseSessionStore {
  // Configuration
  protected rotationGraceWindow: number;      // Default: 10 seconds
  protected defaultSessionLifetime: number;   // Default: 7 days

  // Generate new session data from input
  protected createSessionData(input: CreateSessionInput): JTSSession;

  // Check if within the rotation grace window
  protected isWithinGraceWindow(session: JTSSession): boolean;

  // Validate StateProof and detect replay attacks
  protected validateStateProofLogic(
    session: JTSSession,
    stateProof: string
  ): SessionValidationResult;
}
```

## Database Schema Requirements

Your adapter must be able to store data with the following structure:

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| aid | VARCHAR(64) | Primary Key - Anchor ID | ✅ |
| prn | VARCHAR(256) | Principal (user ID) | ✅ |
| current_state_proof | VARCHAR(256) | Current StateProof token | ✅ |
| previous_state_proof | VARCHAR(256) | Previous StateProof | ❌ |
| state_proof_version | INTEGER | Version counter | ✅ |
| rotation_timestamp | TIMESTAMP | Last rotation time | ❌ |
| device_fingerprint | VARCHAR(128) | Device hash | ❌ |
| created_at | TIMESTAMP | Creation time | ✅ |
| expires_at | TIMESTAMP | Expiration time | ✅ |
| last_active | TIMESTAMP | Last activity | ✅ |
| user_agent | TEXT | Browser/client info | ❌ |
| ip_address | VARCHAR(45) | IPv4/IPv6 address | ❌ |
| metadata | JSON/JSONB | Custom metadata | ❌ |

### Recommended Indexes

```sql
CREATE INDEX idx_sessions_prn ON sessions(prn);
CREATE INDEX idx_sessions_current_sp ON sessions(current_state_proof);
CREATE INDEX idx_sessions_previous_sp ON sessions(previous_state_proof);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
```

## Example Implementation

See the complete implementation examples at:
- `src/stores/postgres-store.ts` - PostgreSQL adapter
- `src/stores/redis-store.ts` - Redis adapter
- `src/stores/memory-store.ts` - In-memory adapter

## Publishing Your Adapter

If you create a new adapter, publish it with the naming convention:

```
@engjts/<database>-adapter
```

Examples:
- `@engjts/mysql-adapter`
- `@engjts/mongodb-adapter`
- `@engjts/sqlite-adapter`

### Package.json Template

```json
{
  "name": "@engjts/mysql-adapter",
  "version": "1.0.0",
  "peerDependencies": {
    "@engjts/auth": ">=1.0.0",
    "mysql2": ">=3.0.0"
  }
}
```

## Testing Your Adapter

Create test cases for all methods:

```typescript
describe('MySessionStore', () => {
  it('should create a session', async () => {
    const session = await store.createSession({
      prn: 'user:123',
      deviceFingerprint: 'abc123',
    });
    expect(session.aid).toBeDefined();
    expect(session.currentStateProof).toBeDefined();
  });

  it('should validate StateProof', async () => {
    const session = await store.createSession({ prn: 'user:123' });
    const result = await store.getSessionByStateProof(session.currentStateProof);
    expect(result.valid).toBe(true);
  });

  it('should rotate StateProof', async () => {
    const session = await store.createSession({ prn: 'user:123' });
    const rotated = await store.rotateStateProof(session.aid);
    expect(rotated.currentStateProof).not.toBe(session.currentStateProof);
    expect(rotated.previousStateProof).toBe(session.currentStateProof);
  });

  // Add more tests...
});
```

## Error Handling

Use standard JTS error codes:

- `JTS-401-03` - Invalid StateProof
- `JTS-401-04` - Session terminated
- `JTS-401-05` - Session compromised (replay attack detected)

```typescript
return {
  valid: false,
  error: 'JTS-401-03', // stateproof_invalid
};
```