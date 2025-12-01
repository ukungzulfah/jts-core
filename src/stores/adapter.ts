/**
 * @engjts/auth - Adapter Development Kit
 * 
 * This module provides all the necessary exports for creating
 * custom database adapters for JTS session storage.
 * 
 * Usage:
 * ```typescript
 * import { 
 *   BaseSessionStore, 
 *   SessionStore,
 *   generateStateProof,
 *   generateAnchorId 
 * } from '@engjts/auth/adapter';
 * ```
 * 
 * @packageDocumentation
 */

// ============================================================================
// SESSION STORE INTERFACE & BASE CLASS
// ============================================================================

export { SessionStore, BaseSessionStore } from './session-store';

// ============================================================================
// TYPES FOR ADAPTER DEVELOPMENT
// ============================================================================

export type {
  JTSSession,
  CreateSessionInput,
  SessionValidationResult,
  JTSErrorCode,
} from '../types';

// ============================================================================
// CRYPTO UTILITIES FOR SESSION MANAGEMENT
// ============================================================================

export {
  generateAnchorId,
  generateStateProof,
  generateRandomString,
} from '../crypto';

// ============================================================================
// ADAPTER METADATA (for adapter registration)
// ============================================================================

/**
 * Adapter metadata interface for registration
 */
export interface AdapterMetadata {
  /** Adapter name (e.g., 'mysql', 'mongodb', 'sqlite') */
  name: string;
  /** Adapter version */
  version: string;
  /** Database driver name */
  driver: string;
  /** Minimum driver version supported */
  driverVersion?: string;
  /** Author/maintainer */
  author?: string;
  /** Repository URL */
  repository?: string;
}

/**
 * Base options for session store adapters
 */
export interface BaseSessionStoreOptions {
  /** Rotation grace window in seconds (default: 10) */
  rotationGraceWindow?: number;
  /** Default session lifetime in seconds (default: 7 days) */
  defaultSessionLifetime?: number;
}

/**
 * Adapter factory function type
 */
export type AdapterFactory<T, O extends BaseSessionStoreOptions> = (options: O) => T;

// ============================================================================
// VERSION INFO
// ============================================================================

export const ADAPTER_SDK_VERSION = '1.0.0';
export const JTS_SPEC_VERSION = 'v1.1';
