/**
 * @fileoverview JTS Client SDK Type Definitions
 * @module @engjts/auth/client/types
 * @description Type definitions for the JTS Client SDK, including authentication
 * credentials, login results, and token renewal responses.
 */

import { JTSPayload } from '../types';

/**
 * User credentials for authentication.
 * 
 * @description Flexible credential object that supports various authentication methods.
 * The `username` and `password` fields are optional to accommodate different auth strategies
 * such as OAuth, SSO, or custom authentication mechanisms.
 * 
 * @example
 * ```typescript
 * // Standard username/password login
 * const credentials: LoginCredentials = {
 *   username: 'john@example.com',
 *   password: 'securePassword123'
 * };
 * 
 * // Custom authentication with additional fields
 * const customCredentials: LoginCredentials = {
 *   email: 'john@example.com',
 *   otp: '123456',
 *   deviceId: 'mobile-device-001'
 * };
 * ```
 */
export interface LoginCredentials {
  /** User's username or email address */
  username?: string;
  /** User's password (should be transmitted over HTTPS only) */
  password?: string;
  /** Additional custom credential fields */
  [key: string]: unknown;
}

/**
 * Result of a login attempt from the client SDK.
 * 
 * @description Contains the outcome of an authentication request, including
 * the BearerPass token on success or error details on failure.
 * 
 * @example
 * ```typescript
 * const result = await client.login(credentials);
 * 
 * if (result.success) {
 *   console.log('Logged in! Token expires at:', result.expiresAt);
 *   console.log('User ID:', result.payload?.prn);
 * } else {
 *   console.error('Login failed:', result.error);
 * }
 * ```
 */
export interface ClientLoginResult {
  /** Whether the login attempt was successful */
  success: boolean;
  /** The BearerPass token (present on success) */
  bearerPass?: string;
  /** Decoded token payload containing user claims (present on success) */
  payload?: JTSPayload;
  /** Unix timestamp when the token expires (present on success) */
  expiresAt?: number;
  /** Error message describing why login failed (present on failure) */
  error?: string;
}

/**
 * Result of a token renewal attempt from the client SDK.
 * 
 * @description Contains the outcome of a token renewal request. On success,
 * provides the new BearerPass token and updated expiration. On failure,
 * includes error details that may indicate session termination.
 * 
 * @example
 * ```typescript
 * const result = await client.renew();
 * 
 * if (result.success) {
 *   console.log('Token renewed! New expiry:', result.expiresAt);
 * } else {
 *   // Handle renewal failure - may need to re-authenticate
 *   console.error('Renewal failed:', result.error);
 * }
 * ```
 */
export interface ClientRenewResult {
  /** Whether the renewal attempt was successful */
  success: boolean;
  /** The new BearerPass token (present on success) */
  bearerPass?: string;
  /** Decoded token payload containing user claims (present on success) */
  payload?: JTSPayload;
  /** Unix timestamp when the new token expires (present on success) */
  expiresAt?: number;
  /** Error message describing why renewal failed (present on failure) */
  error?: string;
}

// ══════════════════════════════════════════════════════════════════════════════
// CLIENT INTERFACE
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Interface for JTS Client implementations.
 * 
 * @description Defines the public contract for JTS client implementations.
 * Use this interface for dependency injection, mocking in tests, or creating
 * custom client implementations.
 * 
 * @example
 * ```typescript
 * // Dependency injection
 * class AuthService {
 *   constructor(private client: IJTSClient) {}
 *   
 *   async authenticate(credentials: LoginCredentials) {
 *     return this.client.login(credentials);
 *   }
 * }
 * 
 * // Mock implementation for testing
 * const mockClient: IJTSClient = {
 *   login: async () => ({ success: true, bearerPass: 'mock-token' }),
 *   logout: async () => true,
 *   // ... other methods
 * };
 * ```
 */
export interface IJTSClient {
  // ─────────────────────────────────────────────────────────────────────────
  // Event Handlers
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Registers a callback for token refresh events.
   * @param callback - Function to call with the new BearerPass token
   */
  onRefresh(callback: (token: string) => void): void;

  /**
   * Registers a callback for session expiration events.
   * @param callback - Function to call when the session expires
   */
  onExpired(callback: () => void): void;

  // ─────────────────────────────────────────────────────────────────────────
  // Authentication
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Authenticates the user with the provided credentials.
   * @param credentials - User credentials for authentication
   * @returns Promise resolving to login result
   */
  login(credentials: LoginCredentials): Promise<ClientLoginResult>;

  /**
   * Logs out the user and invalidates the current session.
   * @returns Promise resolving to `true` if logout succeeded
   */
  logout(): Promise<boolean>;

  // ─────────────────────────────────────────────────────────────────────────
  // Token Management
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Retrieves the current valid BearerPass token.
   * @returns Promise resolving to the token or `null`
   */
  getBearerPass(): Promise<string | null>;

  /**
   * Retrieves the decoded payload from the current token.
   * @returns Promise resolving to the payload or `null`
   */
  getPayload(): Promise<JTSPayload | null>;

  /**
   * Checks if the user is currently authenticated.
   * @returns Promise resolving to authentication status
   */
  isAuthenticated(): Promise<boolean>;

  /**
   * Gets the time remaining until the current token expires.
   * @returns Promise resolving to seconds until expiration
   */
  getTimeUntilExpiry(): Promise<number>;

  // ─────────────────────────────────────────────────────────────────────────
  // Token Renewal
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Manually triggers token renewal.
   * @returns Promise resolving to renewal result
   */
  renew(): Promise<ClientRenewResult>;

  // ─────────────────────────────────────────────────────────────────────────
  // HTTP Helpers
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Makes an authenticated HTTP request.
   * @param url - The URL to fetch
   * @param options - Standard Fetch API options
   * @returns Promise resolving to the Response
   */
  fetch(url: string, options?: RequestInit): Promise<Response>;

  /**
   * Gets the formatted Authorization header value.
   * @returns Promise resolving to the header value or `null`
   */
  getAuthHeader(): Promise<string | null>;

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Cleans up client resources.
   */
  destroy(): void;
}
