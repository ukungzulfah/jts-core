/**
 * @fileoverview Token Creation and Verification
 * @module @engjts/auth/tokens
 * @description BearerPass token creation, verification, and JWE encryption utilities for the Janus Token System (JTS).
 * 
 * The tokens module provides functions for creating and verifying JTS tokens according to the three security profiles:
 * - **JTS-L (Lite)**: Stateless Bearer tokens
 * - **JTS-S (Standard)**: Stateful tokens with revocation and replay detection
 * - **JTS-C (Confidentiality)**: Encrypted tokens with payload confidentiality
 * 
 * @example
 * ```typescript
 * // Creating a BearerPass token
 * import { createBearerPass } from '@engjts/auth/tokens';
 * 
 * const token = createBearerPass({
 *   prn: 'user123',
 *   aid: 'session456',
 *   kid: 'key789',
 *   privateKey: '-----BEGIN PRIVATE KEY-----...',
 *   profile: 'JTS-S/v1'
 * });
 * 
 * // Verifying a BearerPass token
 * import { verifyBearerPass } from '@engjts/auth/tokens';
 * 
 * const result = verifyBearerPass({
 *   token,
 *   publicKeys: new Map([['key789', keyPair]])
 * });
 * 
 * // Creating an encrypted token (JTS-C)
 * import { createEncryptedBearerPass } from '@engjts/auth/tokens';
 * 
 * const encryptedToken = createEncryptedBearerPass({
 *   // ... options including encryption key
 * });
 * ```
 */

/**
 * @namespace BearerPass
 * @description Functions for creating and verifying BearerPass tokens (JWS)
 */
export * from './bearer-pass';

/**
 * @namespace JWE
 * @description Functions for creating and decrypting JWE-encrypted tokens (JTS-C)
 */
export * from './jwe';
