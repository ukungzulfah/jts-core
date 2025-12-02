# @engjts/auth

> **Janus Token System (JTS) SDK for TypeScript/Node.js**
>
> A two-component authentication architecture for secure, revocable, and confidential API authentication.

[![npm version](https://img.shields.io/npm/v/@engjts/auth.svg)](https://www.npmjs.com/package/@engjts/auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)

> 📖 **Read the Specification** | 🚀 **Try the Demo** | 📚 **View Examples**

## 📖 Technical Specification

The complete JTS specification is available in multiple languages:

- **[English](./JTS_Specification_v1-en.md)** - `JTS_Specification_v1-en.md`
- **[Spanish](./JTS_Specification_v1-es.md)** - `JTS_Specification_v1-es.md`
- **[Indonesian](./JTS_Specification_v1-id.md)** - `JTS_Specification_v1-id.md`
- **[Japanese](./JTS_Specification_v1-ja.md)** - `JTS_Specification_v1-ja.md`
- **[Korean](./JTS_Specification_v1-ko.md)** - `JTS_Specification_v1-ko.md`
- **[Portuguese (Brazil)](./JTS_Specification_v1-pt-BR.md)** - `JTS_Specification_v1-pt-BR.md`
- **[Russian](./JTS_Specification_v1-ru.md)** - `JTS_Specification_v1-ru.md`
- **[Chinese (Simplified)](./JTS_Specification_v1-zh-CN.md)** - `JTS_Specification_v1-zh-CN.md`

> **New to JTS?** Start with the specification in your preferred language to understand the architecture and security model.

## 🚀 Live Demo

See JTS in action with a complete production-ready example:

- **[JTS-C Demo with MySQL](https://github.com/ukungzulfah/demo-jts-c-mysql)** - Full-stack implementation with authentication, session management, and encrypted tokens
  - Complete Express.js server setup
  - MySQL integration with TypeScript
  - Device fingerprinting and multi-device sessions
  - Rate limiting and security best practices
  - [View Test Report](https://github.com/ukungzulfah/demo-jts-c-mysql/blob/main/TEST_REPORT.md)

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
import {JTSAuthServer, generateKeyPair, JTSAlgorithm, JTS_PROFILES} from '@engjts/auth';

// Generate signing key
const signingKey = await generateKeyPair('my-key-2025', JTSAlgorithm.RS256);

// Create auth server
const authServer = new JTSAuthServer({
  profile: JTS_PROFILES.STANDARD,
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
import {JTSResourceServer, JTS_PROFILES} from '@engjts/auth';

const resourceServer = new JTSResourceServer({
  publicKeys: [signingKey],
  audience: 'https://api.example.com',
  acceptedProfiles: [JTS_PROFILES.STANDARD, JTS_PROFILES.LITE],
  gracePeriodTolerance: 30, // seconds
  jwksCacheTTL: 3600, // 1 hour
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
import {jtsAuth, jtsRequirePermissions, createJTSRoutes, JTSAuthServer, JTSResourceServer, generateKeyPair, JTSAlgorithm, JTS_PROFILES} from '@engjts/auth';

const app = express();
app.use(express.json());

// Setup servers
const signingKey = await generateKeyPair('my-key-2025', JTSAlgorithm.ES256);

const authServer = new JTSAuthServer({
  profile: JTS_PROFILES.STANDARD,
  signingKey,
  bearerPassLifetime: 300,
  stateProofLifetime: 604800,
});

const resourceServer = new JTSResourceServer({
  publicKeys: [signingKey],
  acceptedProfiles: [JTS_PROFILES.STANDARD],
});

// Create routes
const routes = createJTSRoutes({
  authServer,
  validateCredentials: async (req) => {
    const {email, password} = req.body;
    // Validate credentials against your database...
    return {prn: email, permissions: ['read:profile']};
  },
});

// Mount auth endpoints
app.post('/jts/login', routes.loginHandler);
app.post('/jts/renew', routes.renewHandler);
app.post('/jts/logout', routes.logoutHandler);
app.get('/.well-known/jts-jwks', routes.jwksHandler);
app.get('/.well-known/jts-configuration', routes.configHandler);

// Protected routes
app.get('/api/profile',
  jtsAuth({resourceServer}),
  (req, res) => {
    res.json({user: req.jts?.payload.prn});
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

# Generate ES256 key pair (recommended for performance)

jts keygen -a ES256 -o signing-key.pem

# Generate RS256 key with 4096-bit modulus

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

jts init --profile JTS-S/v1 --algorithm ES256 --output ./config

# Initialize JTS-C profile (with encryption for confidential data)

jts init --profile JTS-C/v1 --algorithm RS256 --output ./config

# Force overwrite existing

jts init --profile JTS-S/v1 -o ./config --force
```

Options:

- `--profile <profile>` - JTS profile: JTS-L/v1, JTS-S/v1, or JTS-C/v1
- `-a, --algorithm <alg>` - Signing algorithm (RS256, ES256, etc.)
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
import {InMemorySessionStore, JTSAuthServer, generateKeyPair, JTSAlgorithm, JTS_PROFILES} from '@engjts/auth';

const store = new InMemorySessionStore({
  rotationGraceWindow: 10, // seconds
  defaultSessionLifetime: 604800, // 7 days
});

const signingKey = await generateKeyPair('my-key-2025', JTSAlgorithm.ES256);

const authServer = new JTSAuthServer({
  profile: JTS_PROFILES.STANDARD,
  signingKey,
  sessionStore: store,
  // ...other options
});
```

### Redis (Production)

```typescript
import {RedisSessionStore, JTSAuthServer, generateKeyPair, JTSAlgorithm, JTS_PROFILES} from '@engjts/auth';
import Redis from 'ioredis';

const redis = new Redis();
const store = new RedisSessionStore({
  client: redis,
  keyPrefix: 'jts:session:',
  rotationGraceWindow: 30, // seconds
  defaultSessionLifetime: 604800, // 7 days
});

const signingKey = await generateKeyPair('my-key-2025', JTSAlgorithm.ES256);

const authServer = new JTSAuthServer({
  profile: JTS_PROFILES.STANDARD,
  signingKey,
  sessionStore: store,
  // ...other options
});
```

### PostgreSQL (Production)

```typescript
import {PostgresSessionStore, JTSAuthServer, generateKeyPair, JTSAlgorithm, JTS_PROFILES} from '@engjts/auth';
import {Pool} from 'pg';

const pool = new Pool({connectionString: process.env.DATABASE_URL});
const store = new PostgresSessionStore({
  pool,
  tableName: 'jts_sessions',
  schema: 'public',
  rotationGraceWindow: 30, // seconds
  defaultSessionLifetime: 604800, // 7 days
});

// Initialize table (run once)
await store.initialize();

const signingKey = await generateKeyPair('my-key-2025', JTSAlgorithm.ES256);

const authServer = new JTSAuthServer({
  profile: JTS_PROFILES.STANDARD,
  signingKey,
  sessionStore: store,
  // ...other options
});
```

## 🔑 Key Management

### Key Generation

```typescript
import {generateKeyPair, generateRSAKeyPair, generateECKeyPair, JTSAlgorithm} from '@engjts/auth';

// Auto-select based on algorithm
const key = await generateKeyPair('key-id', JTSAlgorithm.RS256);

// RSA specific (with custom modulus length)
const rsaKey = await generateRSAKeyPair('rsa-key', JTSAlgorithm.RS256, 4096);

// EC specific (recommended for performance)
const ecKey = await generateECKeyPair('ec-key', JTSAlgorithm.ES256);
```

### Key Rotation

```typescript
import {generateKeyPair, JTSAlgorithm} from '@engjts/auth';

// Generate new key
const newKey = await generateKeyPair('key-2025-002', JTSAlgorithm.ES256);

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
import {JTSResourceServer, JTS_PROFILES} from '@engjts/auth';

const resourceServer = new JTSResourceServer({
  publicKeys: [signingKey],
  acceptedProfiles: [JTS_PROFILES.STANDARD],
  gracePeriodTolerance: 30, // Accept tokens up to 30s after expiry
});
```

## 📱 Client SDK

```typescript
import {JTSClient, InMemoryTokenStorage} from '@engjts/auth';

const client = new JTSClient({
  authServerUrl: 'https://auth.example.com',
  tokenEndpoint: '/jts/login',
  renewalEndpoint: '/jts/renew',
  logoutEndpoint: '/jts/logout',
  autoRenewBefore: 60, // Renew 1 minute before expiry
  storage: new InMemoryTokenStorage(), // or custom TokenStorage implementation
});

// Event handlers (set before login)
client.onRefresh((token) => console.log('Token refreshed'));
client.onExpired(() => console.log('Session expired'));

// Login
const result = await client.login({
  username: 'user@example.com',
  password: 'password123',
});

if (result.success) {
  console.log('Logged in as:', result.payload?.prn);
  console.log('Token expires at:', result.expiresAt);
}

// Auto-refreshing fetch with Authorization header
const response = await client.fetch('https://api.example.com/profile');

// Check authentication status
const isAuth = await client.isAuthenticated();
const timeLeft = await client.getTimeUntilExpiry();

// Get current token payload
const payload = await client.getPayload();

// Logout and cleanup
await client.logout();
client.destroy(); // cleanup timers
```

## 🔴 Error Handling

```typescript
import {JTSError, JTS_ERRORS} from '@engjts/auth';

try {
  const result = await resourceServer.verify(token);
  if (!result.valid && result.error) {
    throw result.error;
  }
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

- `generateKeyPair(kid, algorithm: JTSAlgorithm)` - Generate signing key pair
- `generateRSAKeyPair(kid, algorithm: JTSAlgorithm, modulusLength?)` - Generate RSA key pair
- `generateECKeyPair(kid, algorithm: JTSAlgorithm)` - Generate EC key pair
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

#### JWE (JTS-C Profile)

- `createEncryptedBearerPass(options)` - Create encrypted JWE token
- `decryptJWE(jwe, options)` - Decrypt JWE token
- `verifyEncryptedBearerPass(jwe, options)` - Decrypt and verify
- `isEncryptedToken(token)` - Check if token is JWE format

#### Server

- `JTSAuthServer` - Authentication server class
- `JTSResourceServer` - Resource server class

#### Client

- `JTSClient` - Client SDK class for browser/Node.js
- `InMemoryTokenStorage` - Simple in-memory token storage
- `TokenStorage` - Interface for custom token storage implementations

#### Middleware

- `jtsAuth(options)` - Required authentication middleware
- `jtsOptionalAuth(options)` - Optional auth middleware (allows anonymous)
- `jtsRequirePermissions(options)` - Permission check middleware
- `createJTSRoutes(options)` - Create route handlers for auth endpoints
- `mountJTSRoutes(app, options)` - Mount all routes on Express app

#### Stores

- `InMemorySessionStore` - In-memory session store (for development/testing)
- `RedisSessionStore` - Redis-backed session store (for production)
- `PostgresSessionStore` - PostgreSQL-backed session store (for production)
- `BaseSessionStore` - Abstract base class for custom session stores

#### Types & Constants

- `JTSAlgorithm` - Enum for supported signing algorithms (RS256, ES256, etc.)
- `JTS_PROFILES` - Constants for JTS profiles (LITE, STANDARD, CONFIDENTIAL)
- `JTS_ERRORS` - Constants for JTS error codes
- `JTS_ERROR_MESSAGES` - Constants for error messages
- `SessionPolicy` - Enum for session policies (ALLOW_ALL, SINGLE, NOTIFY)
- `JTSError` - Error class with standardized error handling

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

### Core
- [npm Package](https://www.npmjs.com/package/@engjts/auth)
- [GitHub Repository](https://github.com/ukungzulfah/jts-core.git)
- [Issue Tracker](https://github.com/ukungzulfah/jts-core/issues)
- [Changelog](./CHANGELOG.md)

### Related Projects
- [@engjts/mysql-adapter](https://github.com/ukungzulfah/engjts-mysql-adapter) - MySQL session store adapter for JTS
- [JTS-C Demo with MySQL](https://github.com/ukungzulfah/demo-jts-c-mysql) - Complete JTS-C implementation example with MySQL
- [Test Report (JTS-C)](https://github.com/ukungzulfah/demo-jts-c-mysql/blob/main/TEST_REPORT.md) - Comprehensive test coverage report
- [JTS Express Server Example](https://github.com/ukungzulfah/jts-express-example) - Production-ready Express.js integration example
