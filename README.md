# @engjts/auth

> **Janus Token System (JTS) SDK for TypeScript/Node.js**
>
> A two-component authentication architecture for secure, revocable, and confidential API authentication.

[![npm version](https://img.shields.io/npm/v/@engjts/auth.svg)](https://www.npmjs.com/package/@engjts/auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)

## 🌟 Features

- **Three Security Profiles**: JTS-L (Lite), JTS-S (Standard), JTS-C (Confidentiality)
- **Stateless Verification**: Fast BearerPass verification using asymmetric cryptography
- **Instant Revocation**: StateProof-based session management with database backing
- **Replay Detection**: Automatic detection and prevention of token reuse (JTS-S/C)
- **Device Binding**: Optional device fingerprint validation
- **Express Integration**: Ready-to-use middleware for Express.js
- **Multiple Storage Backends**: In-memory, Redis, and PostgreSQL adapters
- **CLI Tools**: Key generation, token inspection, and configuration utilities
- **Zero External JWT Dependencies**: Full cryptographic control using native Node.js crypto

## 📦 Installation

```bash
npm install @engjts/auth
```

For CLI tools globally:

```bash
npm install -g @engjts/auth
```

## 🚀 Quick Start

### 1. Setup Auth Server

```typescript
import {JTSAuthServer, generateKeyPair} from '@engjts/auth';

// Generate signing key
const signingKey = await generateKeyPair('my-key-2025', 'RS256');

// Create auth server
const authServer = new JTSAuthServer({
  profile: 'JTS-S/v1',
  signingKey,
  bearerPassLifetime: 300, // 5 minutes
  stateProofLifetime: 604800, // 7 days
});

// Login user
const tokens = await authServer.login({
  prn: 'user-123',
  permissions: ['read:profile', 'write:posts'],
});

console.log(tokens.bearerPass); // Use in Authorization header
console.log(tokens.stateProof); // Store in HttpOnly cookie
```

### 2. Setup Resource Server

```typescript
import {JTSResourceServer} from '@engjts/auth';

const resourceServer = new JTSResourceServer({
  publicKeys: [signingKey],
  audience: 'https://api.example.com',
});

// Verify token
const result = await resourceServer.verify(bearerPass);
if (result.valid) {
  console.log('User:', result.payload.prn);
  console.log('Permissions:', result.payload.perm);
}
```

### 3. Express Integration

```typescript
import express from 'express';
import {jtsAuth, jtsRequirePermissions, createJTSRoutes} from '@engjts/auth';

const app = express();

// Create routes
const routes = createJTSRoutes({
  authServer,
  validateCredentials: async (req) => {
    const {email, password} = req.body;
// Validate credentials...
    return {prn: email, permissions: ['read:profile']};
  },
});

// Mount auth endpoints
app.post('/jts/login', routes.loginHandler);
app.post('/jts/renew', routes.renewHandler);
app.post('/jts/logout', routes.logoutHandler);

// Protected routes
app.get('/api/profile',
  jtsAuth({resourceServer}),
  (req, res) => {
    res.json({user: req.jts.payload.prn});
  }
);

// Permission-protected routes
app.get('/api/admin',
  jtsAuth({resourceServer}),
  jtsRequirePermissions({required: ['admin:access']}),
  (req, res) => {
    res.json({message: 'Admin area'});
  }
);
```

## 🔧 CLI Tools

The `jts` CLI provides utilities for key management and token inspection.

### Installation

```bash

# Global installation

npm install -g @engjts/auth

# Or use with npx

npx @engjts/auth jts --help
```

### Commands

#### `jts keygen` - Generate Key Pairs

```bash

# Generate ES256 key pair (recommended)

jts keygen -a ES256 -o signing-key.pem

# Generate RS256 key with 4096 bits

jts keygen -a RS256 --bits 4096 -o rsa-key.pem

# Output as JWK format

jts keygen -a ES256 -f jwk -o signing-key.json

# Specify custom key ID

jts keygen -a ES256 --kid my-key-2025-001 -o key.pem
```

Options:

- `-a, --algorithm <alg>` - Algorithm (RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512)
- `-k, --kid <kid>` - Key ID (auto-generated if not specified)
- `-b, --bits <bits>` - RSA key size in bits (default: 2048)
- `-o, --output <file>` - Output file for private key
- `-p, --public-out <file>` - Output file for public key
- `-f, --format <format>` - Output format: `pem` or `jwk`

#### `jts inspect` - Decode Token Contents

```bash

# Inspect a token

jts inspect eyJhbGciOiJFUzI1NiIsInR5cCI6Ikp...

# Inspect from file

jts inspect ./token.jwt

# Output as JSON

jts inspect <token> --json
```

Output includes:

- Header (algorithm, type, key ID)
- Payload (principal, permissions, expiration)
- Timestamp information
- Expiration status

#### `jts verify` - Verify Token Signature

```bash

# Verify with public key file (PEM)

jts verify <token> --key public-key.pem

# Verify with JWK file

jts verify <token> --key public-key.json

# Verify with remote JWKS

jts verify <token> --jwks https://auth.example.com/.well-known/jwks.json

# Verify with local JWKS file

jts verify <token> --jwks ./jwks.json
```

Options:

- `-k, --key <file>` - Public key file (PEM or JWK)
- `--jwks <url-or-file>` - JWKS URL or file path

#### `jts jwks` - Convert to JWKS Format

```bash

# Convert single PEM to JWKS

jts jwks public-key.pem -o jwks.json

# Convert multiple keys

jts jwks key1.pem key2.pem key3.pem -o jwks.json

# Specify key ID for PEM files

jts jwks public-key.pem --kid my-key-2025
```

Options:

- `-o, --output <file>` - Output file
- `-k, --kid <kid>` - Key ID for PEM files

#### `jts init` - Initialize JTS Configuration

```bash

# Initialize with JTS-S profile (recommended for production)

jts init --profile JTS-S --algorithm ES256 --output ./config

# Initialize JTS-C profile (with encryption)

jts init --profile JTS-C --algorithm RS256 --output ./config

# Force overwrite existing

jts init --profile JTS-S -o ./config --force
```

Options:

- `--profile <profile>` - JTS profile: JTS-L, JTS-S, or JTS-C
- `-a, --algorithm <alg>` - Signing algorithm
- `-o, --output <dir>` - Output directory
- `-f, --force` - Overwrite existing directory

Generated files:

- `jts.config.json` - Configuration file
- `signing-key.pem` - Private signing key
- `signing-key.pub.pem` - Public signing key
- `jwks.json` - JWKS public keys
- `example.ts` - Example usage code
- `.gitignore` - Prevents committing private keys

## 📊 Profiles Comparison

| Feature             | JTS-L (Lite)        | JTS-S (Standard) | JTS-C (Confidentiality) |
|---------------------|---------------------|------------------|-------------------------|
| Use Case            | MVP, Internal Tools | Production Apps  | Fintech, Healthcare     |
| StateProof Rotation | ❌ Optional          | ✅ Required       | ✅ Required              |
| Replay Detection    | ❌ No                | ✅ Yes            | ✅ Yes                   |
| Device Binding      | ❌ No                | ✅ Optional       | ✅ Optional              |
| Payload Encryption  | ❌ No                | ❌ No             | ✅ Yes (JWE)             |
| Complexity          | Low                 | Medium           | High                    |

## 🔧 Storage Adapters

### In-Memory (Development)

```typescript
import {InMemorySessionStore} from '@engjts/auth';

const store = new InMemorySessionStore();
const authServer = new JTSAuthServer({
  sessionStore: store,
// ...other options
});
```

### Redis (Production)

```typescript
import {RedisSessionStore} from '@engjts/auth';
import Redis from 'ioredis';

const redis = new Redis();
const store = new RedisSessionStore({
  client: redis,
  keyPrefix: 'jts:',
});

const authServer = new JTSAuthServer({
  sessionStore: store,
// ...other options
});
```

### PostgreSQL (Production)

```typescript
import {PostgresSessionStore} from '@engjts/auth';
import {Pool} from 'pg';

const pool = new Pool({connectionString: process.env.DATABASE_URL});
const store = new PostgresSessionStore({
  pool,
  tableName: 'jts_sessions',
});

// Initialize table (run once)
await store.initialize();

const authServer = new JTSAuthServer({
  sessionStore: store,
// ...other options
});
```

## 🔑 Key Management

### Key Generation

```typescript
import {generateKeyPair, generateRSAKeyPair, generateECKeyPair} from '@engjts/auth';

// Auto-select based on algorithm
const key = await generateKeyPair('key-id', 'RS256');

// RSA specific
const rsaKey = await generateRSAKeyPair('rsa-key', 'RS256', 2048);

// EC specific (recommended for performance)
const ecKey = await generateECKeyPair('ec-key', 'ES256');
```

### Key Rotation

```typescript
// Generate new key
const newKey = await generateKeyPair('key-2025-002', 'RS256');

// Rotate (old key becomes "previous", new key becomes "current")
authServer.rotateSigningKey(newKey);

// Old tokens remain valid until they expire
```

### JWKS Endpoint

```typescript
// Get JWKS for distribution
const jwks = authServer.getJWKS();
// {
// keys: [
// { kty: 'RSA', kid: 'key-2025-002', use: 'sig', ... },
// { kty: 'RSA', kid: 'key-2025-001', use: 'sig', ... }
//   ]
// }
```

## 🛡️ Security Features

### CSRF Protection

All mutating endpoints require `X-JTS-Request: 1` header:

```typescript
fetch('/jts/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-JTS-Request': '1', // Required for CSRF protection
  },
  body: JSON.stringify(credentials),
});
```

### Device Fingerprint

```typescript
import {createDeviceFingerprint} from '@engjts/auth';

const fingerprint = createDeviceFingerprint({
  userAgent: navigator.userAgent,
  screenResolution: `${screen.width}x${screen.height}`,
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
});

// Include in login
const tokens = await authServer.login({
  prn: 'user-123',
  deviceFingerprint: fingerprint,
});
```

### Grace Period

Handle in-flight requests during token expiry:

```typescript
const resourceServer = new JTSResourceServer({
  gracePeriodTolerance: 30, // Accept tokens up to 30s after expiry
});
```

## 📱 Client SDK

```typescript
import {JTSClient} from '@engjts/auth';

const client = new JTSClient({
  authServerUrl: 'https://auth.example.com',
  autoRenewBefore: 60, // Renew 1 minute before expiry
});

// Login
const result = await client.login({
  email: 'user@example.com',
  password: 'password123',
});

// Auto-refreshing fetch
const response = await client.fetch('https://api.example.com/profile');

// Event handlers
client.onRefresh((token) => console.log('Token refreshed'));
client.onExpired(() => console.log('Session expired'));

// Logout
await client.logout();
```

## 🔴 Error Handling

```typescript
import {JTSError} from '@engjts/auth';

try {
  const result = await resourceServer.verify(token);
} catch (error) {
  if (error instanceof JTSError) {
    console.log(error.errorCode); // 'JTS-401-01'
    console.log(error.errorKey); // 'bearer_expired'
    console.log(error.action); // 'renew'
    console.log(error.httpStatus); // 401

    // Send standard error response
    res.status(error.httpStatus).json(error.toJSON());

  }
}
```

### Error Codes

| Code       | Key                 | Description                   | Action |
|------------|---------------------|-------------------------------|--------|
| JTS-400-01 | malformed_token     | Token cannot be parsed        | reauth |
| JTS-400-02 | missing_claims      | Required claims missing       | reauth |
| JTS-401-01 | bearer_expired      | BearerPass has expired        | renew  |
| JTS-401-02 | signature_invalid   | Signature verification failed | reauth |
| JTS-401-03 | stateproof_invalid  | StateProof not found/invalid  | reauth |
| JTS-401-04 | session_terminated  | Session ended (logout)        | reauth |
| JTS-401-05 | session_compromised | Replay attack detected        | reauth |
| JTS-401-06 | device_mismatch     | Device fingerprint mismatch   | reauth |
| JTS-403-01 | audience_mismatch   | Wrong audience                | none   |
| JTS-403-02 | permission_denied   | Missing permissions           | none   |
| JTS-403-03 | org_mismatch        | Wrong organization            | none   |
| JTS-500-01 | key_unavailable     | Public key not found          | retry  |

## 📄 API Reference

### Core Exports

#### Crypto

- `generateKeyPair(kid, algorithm)` - Generate signing key pair
- `generateRSAKeyPair(kid, algorithm, modulusLength)` - Generate RSA key pair
- `generateECKeyPair(kid, algorithm)` - Generate EC key pair
- `sign(data, privateKey, algorithm)` - Sign data
- `verify(data, signature, publicKey, algorithm)` - Verify signature
- `pemToJwk(pem, kid, algorithm)` - Convert PEM to JWK
- `jwkToPem(jwk)` - Convert JWK to PEM
- `keyPairToJwks(keyPairs)` - Convert key pairs to JWKS

#### Tokens

- `createBearerPass(options)` - Create a BearerPass token
- `verifyBearerPass(token, options)` - Verify and decode BearerPass
- `decodeBearerPass(token)` - Decode without verification
- `isTokenExpired(payload)` - Check if token is expired
- `hasPermission(payload, permission)` - Check single permission
- `hasAllPermissions(payload, permissions)` - Check all permissions
- `hasAnyPermission(payload, permissions)` - Check any permission

#### JWE (JTS-C)

- `createEncryptedBearerPass(options)` - Create encrypted JWE token
- `decryptJWE(jwe, options)` - Decrypt JWE token
- `verifyEncryptedBearerPass(jwe, options)` - Decrypt and verify
- `isEncryptedToken(token)` - Check if token is JWE

#### Server

- `JTSAuthServer` - Authentication server class
- `JTSResourceServer` - Resource server class

#### Client

- `JTSClient` - Client SDK class
- `InMemoryTokenStorage` - Simple token storage

#### Middleware

- `jtsAuth(options)` - Authentication middleware
- `jtsOptionalAuth(options)` - Optional auth middleware
- `jtsRequirePermissions(options)` - Permission middleware
- `createJTSRoutes(options)` - Create route handlers
- `mountJTSRoutes(app, options)` - Mount routes on Express app

#### Stores

- `InMemorySessionStore` - In-memory session store
- `RedisSessionStore` - Redis-backed session store
- `PostgresSessionStore` - PostgreSQL-backed session store

### JTS Claims

| Claim    | Name               | Description                 |
|----------|--------------------|-----------------------------|
| `prn`    | Principal          | User/entity identifier      |
| `aid`    | Anchor ID          | Links to session record     |
| `tkn_id` | Token ID           | Unique token identifier     |
| `exp`    | Expiration         | Token expiry timestamp      |
| `iat`    | Issued At          | Token creation timestamp    |
| `aud`    | Audience           | Intended recipient          |
| `dfp`    | Device Fingerprint | Device binding hash         |
| `perm`   | Permissions        | Array of permission strings |
| `grc`    | Grace Period       | Expiry tolerance (seconds)  |
| `org`    | Organization       | Tenant identifier           |
| `atm`    | Auth Method        | How user authenticated      |
| `spl`    | Session Policy     | Concurrent session policy   |

## �� Running the Example

```bash

# Clone and install

git clone https://github.com/ukungzulfah/jts-core.git
cd jts-core
npm install

# Run example server

npm run example

# Test with curl

curl -X POST http://localhost:3000/jts/login \
-H "Content-Type: application/json" \
-H "X-JTS-Request: 1" \
-d '{"email":"user@example.com","password":"password123"}'
```

## 🧪 Testing

```bash

# Run all tests

npm test

# Run with watch mode

npm run test:watch

# Run with coverage

npm run test:coverage
```

## 📖 Specification

This SDK implements the **Janus Token System (JTS) Specification v1.1**.

See [JTS_Specification_v1.md](./JTS_Specification_v1-en.md) for the full specification.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our GitHub repository.

## 📜 License

MIT License - see [LICENSE](./LICENSE) file for details.

## 🔗 Links

- [npm Package](https://www.npmjs.com/package/@engjts/auth)
- [GitHub Repository](https://github.com/ukungzulfah/jts-core.git)
- [Issue Tracker](https://github.com/ukungzulfah/jts-core/issues)
- [Changelog](./CHANGELOG.md)
