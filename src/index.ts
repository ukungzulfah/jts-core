/**
 * @fileoverview Janus Token System (JTS) SDK
 * @module @engjts/auth
 * @description Comprehensive authentication and authorization toolkit implementing the Janus Token System specification.
 * Provides secure, revocable, and confidential API authentication with support for three security profiles:
 * 
 * 1. **JTS-L (Lite)**: Stateless Bearer tokens with minimal overhead
 * 2. **JTS-S (Standard)**: Adds stateful revocation and replay detection
 * 3. **JTS-C (Confidentiality)**: Includes JWS encryption for payload confidentiality
 * 
 * The SDK consists of five primary components:
 * - **Crypto Utilities**: Native Node.js cryptographic implementations
 * - **Tokens**: BearerPass creation, verification, and JWE encryption
 * - **Stores**: Session storage with adapter pattern (Memory, Redis, PostgreSQL)
 * - **Servers**: Authentication and resource server implementations
 * - **Client**: Browser and Node.js client SDK with automatic token renewal
 * - **Middleware**: Express.js middleware for rapid API protection
 * 
 * @example
 * ```typescript
 * // Server-side usage
 * import { JTSAuthServer } from '@engjts/auth/server';
 * import { JTSResourceServer } from '@engjts/auth/server';
 * 
 * // Client-side usage
 * import { JTSClient } from '@engjts/auth/client';
 * 
 * // Individual utilities
 * import { generateKeyPair, createBearerPass } from '@engjts/auth';
 * ```
 * 
 * @packageDocumentation
 */

// ============================================================================
// TYPES & CONSTANTS
// ============================================================================

/**
 * @namespace Types
 * @description Shared type definitions used across all JTS components
 */
export * from './types';

/**
 * @namespace Constants
 * @description Shared constants for paths and well-known endpoints used across JTS.
 *
 * Exposing these makes it easy for users to discover and reuse official
 * JTS path values without relying on magic strings.
 */
export * from './middleware/constants';

// ============================================================================
// CRYPTO UTILITIES
// ============================================================================

/**
 * @namespace Crypto
 * @description Native Node.js cryptographic utilities for JTS token creation and verification
 */
export {
  // Key generation
  generateKeyPair,
  generateRSAKeyPair,
  generateECKeyPair,
  
  // Signing & verification
  sign,
  verify,
  
  // Token ID generation
  generateTokenId,
  generateAnchorId,
  generateStateProof,
  generateRandomString,
  
  // Hashing
  sha256,
  sha256Hex,
  createDeviceFingerprint,
  
  // Base64URL encoding/decoding
  base64urlEncode,
  base64urlDecode,
  encodeJSON,
  decodeJSON,
  
  // JWKS utilities
  pemToJwk,
  jwkToPem,
  keyPairToJwks,
  
  // Encryption utilities (for JTS-C)
  rsaEncrypt,
  rsaDecrypt,
  generateCEK,
  generateIV,
  aesGcmEncrypt,
  aesGcmDecrypt,
} from './crypto';

// ============================================================================
// TOKENS
// ============================================================================

/**
 * @namespace Tokens
 * @description BearerPass token creation, verification, and JWE encryption utilities
 */
export {
  // BearerPass utilities
  createBearerPass,
  verifyBearerPass,
  decodeBearerPass,
  isTokenExpired,
  getTokenExpiration,
  getTimeUntilExpiration,
  hasPermission,
  hasAllPermissions,
  hasAnyPermission,
  
  // JWE utilities (JTS-C)
  createEncryptedBearerPass,
  decryptJWE,
  verifyEncryptedBearerPass,
  isEncryptedToken,
} from './tokens';

/**
 * @namespace TokenTypes
 * @description Type definitions for token creation and verification options
 */
export type {
  CreateBearerPassOptions,
  VerifyBearerPassOptions,
  CreateJWEOptions,
  DecryptJWEOptions,
  DecryptJWEResult,
  VerifyEncryptedBearerPassOptions,
} from './tokens';

// ============================================================================
// SESSION STORES
// ============================================================================

/**
 * @namespace Stores
 * @description Session storage implementations with adapter pattern
 */
export {
  // Interface
  BaseSessionStore,
  
  // Implementations
  InMemorySessionStore,
  RedisSessionStore,
  PostgresSessionStore,
} from './stores';

/**
 * @namespace StoreTypes
 * @description Type definitions for session store implementations
 */
export type {
  SessionStore,
  RedisSessionStoreOptions,
  PostgresSessionStoreOptions,
} from './stores';

// ============================================================================
// SERVER SDK
// ============================================================================

/**
 * @namespace Server
 * @description Server-side authentication and resource server implementations
 */
export {
  JTSAuthServer,
  JTSResourceServer,
} from './server';

/**
 * @namespace ServerTypes
 * @description Type definitions for server configuration and options
 */
export type {
  AuthServerOptions,
  LoginOptions,
  RenewOptions,
  ResourceServerOptions,
} from './server';

// ============================================================================
// CLIENT SDK
// ============================================================================

/**
 * @namespace Client
 * @description Client-side SDK for token management and authenticated requests
 */
export {
  JTSClient,
  InMemoryTokenStorage,
} from './client';

/**
 * @namespace ClientTypes
 * @description Type definitions for client configuration and authentication results
 */
export type {
  LoginCredentials,
  ClientLoginResult,
  ClientRenewResult,
} from './client';

// ============================================================================
// EXPRESS MIDDLEWARE
// ============================================================================

/**
 * @namespace Middleware
 * @description Express.js middleware for protecting API endpoints
 */
export {
  jtsAuth,
  jtsOptionalAuth,
  jtsRequirePermissions,
  createJTSRoutes,
  mountJTSRoutes,
} from './middleware';

/**
 * @namespace MiddlewareTypes
 * @description Type definitions for middleware configuration and options
 */
export type {
  JTSMiddlewareOptions,
  PermissionOptions,
  JTSRoutesOptions,
} from './middleware';

// ============================================================================
// VERSION
// ============================================================================

/**
 * @constant VERSION
 * @description Current version of the JTS SDK
 */
export const VERSION = '1.0.0';

/**
 * @constant JTS_SPEC_VERSION
 * @description Supported version of the Janus Token System specification
 */
export const JTS_SPEC_VERSION = 'v1.1';
