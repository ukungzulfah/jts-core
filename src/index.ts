/**
 * jts-core - Janus Token System SDK
 * 
 * A two-component authentication architecture for secure, 
 * revocable, and confidential API authentication.
 * 
 * @packageDocumentation
 */

// ============================================================================
// TYPES
// ============================================================================

export * from './types';

// ============================================================================
// CRYPTO UTILITIES
// ============================================================================

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
  
  // Base64URL
  base64urlEncode,
  base64urlDecode,
  encodeJSON,
  decodeJSON,
  
  // JWKS
  pemToJwk,
  jwkToPem,
  keyPairToJwks,
  
  // Encryption (for JTS-C)
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

export {
  // BearerPass
  createBearerPass,
  verifyBearerPass,
  decodeBearerPass,
  isTokenExpired,
  getTokenExpiration,
  getTimeUntilExpiration,
  hasPermission,
  hasAllPermissions,
  hasAnyPermission,
  
  // JWE (JTS-C)
  createEncryptedBearerPass,
  decryptJWE,
  verifyEncryptedBearerPass,
  isEncryptedToken,
} from './tokens';

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

export {
  // Interface
  BaseSessionStore,
  
  // Implementations
  InMemorySessionStore,
  RedisSessionStore,
  PostgresSessionStore,
} from './stores';

export type {
  SessionStore,
  RedisSessionStoreOptions,
  PostgresSessionStoreOptions,
} from './stores';

// ============================================================================
// SERVER SDK
// ============================================================================

export {
  JTSAuthServer,
  JTSResourceServer,
} from './server';

export type {
  AuthServerOptions,
  LoginOptions,
  RenewOptions,
  ResourceServerOptions,
} from './server';

// ============================================================================
// CLIENT SDK
// ============================================================================

export {
  JTSClient,
  InMemoryTokenStorage,
} from './client';

export type {
  LoginCredentials,
  ClientLoginResult,
  ClientRenewResult,
} from './client';

// ============================================================================
// EXPRESS MIDDLEWARE
// ============================================================================

export {
  jtsAuth,
  jtsOptionalAuth,
  jtsRequirePermissions,
  createJTSRoutes,
  mountJTSRoutes,
} from './middleware';

export type {
  JTSMiddlewareOptions,
  PermissionOptions,
  JTSRoutesOptions,
} from './middleware';

// ============================================================================
// VERSION
// ============================================================================

export const VERSION = '1.0.0';
export const JTS_SPEC_VERSION = 'v1.1';
