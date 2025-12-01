/**
 * @fileoverview JTS Client SDK
 * @module @engjts/auth/client
 * @description Client-side SDK for the Janus Token System (JTS). Provides seamless
 * token management with automatic renewal, secure storage abstractions, and
 * convenient HTTP helpers for authenticated requests.
 * 
 * @example
 * ```typescript
 * import { JTSClient } from '@engjts/auth/client';
 * 
 * const client = new JTSClient({
 *   authServerUrl: 'https://auth.example.com',
 * });
 * 
 * // Login
 * const result = await client.login({ username: 'user', password: 'pass' });
 * 
 * // Make authenticated requests
 * const response = await client.fetch('https://api.example.com/data');
 * ```
 */

import {
  JTSClientConfig,
  TokenStorage,
  JTSPayload,
  JTSError,
  JTS_ERRORS,
  JTS_ERROR_MESSAGES,
  JTS_HEADERS,
} from '../types';
import {
  decodeBearerPass,
  getTimeUntilExpiration,
  isTokenExpired,
} from '../tokens/bearer-pass';
import type { LoginCredentials, ClientLoginResult, ClientRenewResult, IJTSClient } from './types';
import { InMemoryTokenStorage } from './InMemoryTokenStorage';
export type { LoginCredentials, ClientLoginResult, ClientRenewResult, IJTSClient } from './types';
export { InMemoryTokenStorage } from './InMemoryTokenStorage';

// ============================================================================
// JTS CLIENT CLASS
// ============================================================================

/**
 * JTS Client SDK for managing authentication tokens.
 * 
 * @description The main client class for interacting with JTS authentication servers.
 * Handles login, logout, token storage, automatic renewal, and authenticated HTTP requests.
 * 
 * ## Features
 * - **Automatic Token Renewal**: Tokens are automatically renewed before expiration
 * - **Flexible Storage**: Pluggable storage adapters for different environments
 * - **Event Callbacks**: Subscribe to token refresh and session expiration events
 * - **HTTP Helpers**: Convenient methods for making authenticated requests
 * 
 * @example
 * ```typescript
 * // Initialize the client
 * const client = new JTSClient({
 *   authServerUrl: 'https://auth.example.com',
 *   autoRenewBefore: 120, // Renew 2 minutes before expiry
 * });
 * 
 * // Set up event handlers
 * client.onRefresh((token) => console.log('Token refreshed'));
 * client.onExpired(() => redirectToLogin());
 * 
 * // Authenticate
 * const result = await client.login({ username: 'user', password: 'pass' });
 * if (result.success) {
 *   // Make authenticated API calls
 *   const response = await client.fetch('/api/protected-resource');
 * }
 * 
 * // Clean up when done
 * client.destroy();
 * ```
 */
export class JTSClient implements IJTSClient {
  /** @internal Resolved configuration with defaults applied */
  private config: Required<JTSClientConfig>;
  /** @internal Token storage adapter */
  private storage: TokenStorage;
  /** @internal Timer handle for scheduled renewal */
  private renewalTimer: ReturnType<typeof setTimeout> | null = null;
  /** @internal Callback for token refresh events */
  private onTokenRefresh?: (token: string) => void;
  /** @internal Callback for session expiration events */
  private onSessionExpired?: () => void;

  /**
   * Creates a new JTS Client instance.
   * 
   * @param options - Client configuration options
   * 
   * @example
   * ```typescript
   * const client = new JTSClient({
   *   authServerUrl: 'https://auth.example.com',
   *   tokenEndpoint: '/api/auth/login',
   *   renewalEndpoint: '/api/auth/renew',
   *   autoRenewBefore: 60,
   * });
   * ```
   */
  constructor(options: JTSClientConfig) {
    this.config = {
      authServerUrl: options.authServerUrl.replace(/\/$/, ''),
      tokenEndpoint: options.tokenEndpoint ?? '/jts/login',
      renewalEndpoint: options.renewalEndpoint ?? '/jts/renew',
      logoutEndpoint: options.logoutEndpoint ?? '/jts/logout',
      autoRenewBefore: options.autoRenewBefore ?? 60,
      storage: options.storage ?? new InMemoryTokenStorage(),
    };

    this.storage = this.config.storage;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // EVENT HANDLERS
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Registers a callback for token refresh events.
   * 
   * @description Called whenever a token is successfully renewed, either
   * automatically or manually. Useful for updating UI state or syncing
   * tokens with other parts of your application.
   * 
   * @param callback - Function to call with the new BearerPass token
   * 
   * @example
   * ```typescript
   * client.onRefresh((newToken) => {
   *   console.log('Token was refreshed');
   *   // Update any cached token references
   *   updateStoredToken(newToken);
   * });
   * ```
   */
  onRefresh(callback: (token: string) => void): void {
    this.onTokenRefresh = callback;
  }

  /**
   * Registers a callback for session expiration events.
   * 
   * @description Called when the session can no longer be renewed, typically
   * due to StateProof invalidation, session termination, or security concerns.
   * Use this to redirect users to the login page or show a re-authentication prompt.
   * 
   * @param callback - Function to call when the session expires
   * 
   * @example
   * ```typescript
   * client.onExpired(() => {
   *   alert('Your session has expired. Please log in again.');
   *   window.location.href = '/login';
   * });
   * ```
   */
  onExpired(callback: () => void): void {
    this.onSessionExpired = callback;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // AUTHENTICATION
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Authenticates the user with the provided credentials.
   * 
   * @description Sends credentials to the auth server's token endpoint.
   * On success, stores the BearerPass and StateProof, sets up automatic
   * token renewal, and returns the decoded payload.
   * 
   * @param credentials - User credentials for authentication
   * @returns Promise resolving to login result with token details or error
   * 
   * @example
   * ```typescript
   * const result = await client.login({
   *   username: 'john@example.com',
   *   password: 'securePassword123',
   * });
   * 
   * if (result.success) {
   *   console.log('Welcome,', result.payload?.prn);
   *   console.log('Session expires at:', new Date(result.expiresAt! * 1000));
   * } else {
   *   console.error('Login failed:', result.error);
   * }
   * ```
   */
  async login(credentials: LoginCredentials): Promise<ClientLoginResult> {
    try {
      const response = await fetch(`${this.config.authServerUrl}${this.config.tokenEndpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          [JTS_HEADERS.REQUEST]: '1',
        },
        body: JSON.stringify(credentials),
        credentials: 'include',
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({})) as Record<string, unknown>;
        return {
          success: false,
          error: (error.message as string) ?? `Login failed: ${response.status}`,
        };
      }

      const data = await response.json() as {
        bearerPass: string;
        expiresAt: number;
        stateProof?: string;
      };

      await this.storage.setBearerPass(data.bearerPass);

      // Store StateProof if returned in body (for non-cookie environments)
      if (data.stateProof) {
        await this.storage.setStateProof(data.stateProof);
      }

      const decoded = decodeBearerPass(data.bearerPass);
      this.scheduleRenewal(data.expiresAt);

      return {
        success: true,
        bearerPass: data.bearerPass,
        payload: decoded.payload,
        expiresAt: data.expiresAt,
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Login failed',
      };
    }
  }

  /**
   * Logs out the user and invalidates the current session.
   * 
   * @description Cancels automatic renewal, notifies the auth server to
   * invalidate the session, and clears locally stored tokens. Returns `true`
   * if the server acknowledged the logout, `false` if the server call failed
   * (tokens are still cleared locally in either case).
   * 
   * @returns Promise resolving to `true` if server logout succeeded, `false` otherwise
   * 
   * @example
   * ```typescript
   * async function handleLogout() {
   *   const success = await client.logout();
   *   if (success) {
   *     console.log('Logged out successfully');
   *   } else {
   *     console.log('Server logout failed, but local session cleared');
   *   }
   *   redirectToLogin();
   * }
   * ```
   */
  async logout(): Promise<boolean> {
    try {
      this.cancelRenewal();

      const stateProof = await this.storage.getStateProof();

      const headers: Record<string, string> = {
        [JTS_HEADERS.REQUEST]: '1',
      };

      if (stateProof) {
        headers[JTS_HEADERS.STATE_PROOF] = stateProof;
      }

      await fetch(`${this.config.authServerUrl}${this.config.logoutEndpoint}`, {
        method: 'POST',
        headers,
        credentials: 'include',
      });

      await this.storage.clear();
      return true;

    } catch {
      // Ensure local cleanup even if server call fails
      await this.storage.clear();
      return false;
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // TOKEN MANAGEMENT
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Retrieves the current valid BearerPass token.
   * 
   * @description Returns the stored BearerPass if valid, or attempts automatic
   * renewal if the token has expired. Returns `null` if no token is available
   * or renewal fails.
   * 
   * @returns Promise resolving to the BearerPass token or `null`
   * 
   * @example
   * ```typescript
   * const token = await client.getBearerPass();
   * if (token) {
   *   headers.set('Authorization', `Bearer ${token}`);
   * }
   * ```
   */
  async getBearerPass(): Promise<string | null> {
    const token = await this.storage.getBearerPass();
    
    if (!token) {
      return null;
    }

    if (isTokenExpired(token)) {
      const result = await this.renew();
      return result.success ? result.bearerPass ?? null : null;
    }

    return token;
  }

  /**
   * Retrieves the decoded payload from the current token.
   * 
   * @description Decodes and returns the JTS payload containing user claims.
   * Automatically renews the token if expired before decoding.
   * 
   * @returns Promise resolving to the decoded payload or `null` if unavailable
   * 
   * @example
   * ```typescript
   * const payload = await client.getPayload();
   * if (payload) {
   *   console.log('User ID:', payload.prn);
   *   console.log('Permissions:', payload.perm);
   * }
   * ```
   */
  async getPayload(): Promise<JTSPayload | null> {
    const token = await this.getBearerPass();
    if (!token) return null;

    try {
      const decoded = decodeBearerPass(token);
      return decoded.payload;
    } catch {
      return null;
    }
  }

  /**
   * Checks if the user is currently authenticated with a valid token.
   * 
   * @description Returns `true` if a non-expired BearerPass token exists.
   * Does not attempt automatic renewal - use {@link getBearerPass} if renewal is desired.
   * 
   * @returns Promise resolving to authentication status
   * 
   * @example
   * ```typescript
   * if (await client.isAuthenticated()) {
   *   showDashboard();
   * } else {
   *   showLoginForm();
   * }
   * ```
   */
  async isAuthenticated(): Promise<boolean> {
    const token = await this.storage.getBearerPass();
    return token !== null && !isTokenExpired(token);
  }

  /**
   * Gets the time remaining until the current token expires.
   * 
   * @description Useful for displaying session timeout warnings or
   * implementing custom renewal logic.
   * 
   * @returns Promise resolving to seconds until expiration, or `0` if no token
   * 
   * @example
   * ```typescript
   * const secondsLeft = await client.getTimeUntilExpiry();
   * if (secondsLeft < 300) {
   *   showExpirationWarning(`Session expires in ${secondsLeft} seconds`);
   * }
   * ```
   */
  async getTimeUntilExpiry(): Promise<number> {
    const token = await this.storage.getBearerPass();
    if (!token) return 0;
    return getTimeUntilExpiration(token);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // TOKEN RENEWAL
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Manually triggers token renewal.
   * 
   * @description Requests a new BearerPass from the auth server using the
   * current StateProof. On success, stores the new tokens, notifies the
   * refresh callback, and reschedules automatic renewal.
   * 
   * If renewal fails due to session termination or compromise, the session
   * is cleared and the expiration callback is invoked.
   * 
   * @returns Promise resolving to renewal result with new token or error
   * 
   * @example
   * ```typescript
   * // Manual renewal (automatic renewal handles this normally)
   * const result = await client.renew();
   * if (!result.success) {
   *   if (result.error?.includes('terminated')) {
   *     redirectToLogin();
   *   }
   * }
   * ```
   */
  async renew(): Promise<ClientRenewResult> {
    try {
      const stateProof = await this.storage.getStateProof();

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        [JTS_HEADERS.REQUEST]: '1',
      };

      if (stateProof) {
        headers[JTS_HEADERS.STATE_PROOF] = stateProof;
      }

      const response = await fetch(`${this.config.authServerUrl}${this.config.renewalEndpoint}`, {
        method: 'POST',
        headers,
        credentials: 'include',
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({})) as Record<string, unknown>;
        
        // Handle session invalidation errors
        const errorCode = error.error_code as string;
        if (
          errorCode === JTS_ERRORS.SESSION_TERMINATED ||
          errorCode === JTS_ERRORS.SESSION_COMPROMISED ||
          errorCode === JTS_ERRORS.STATEPROOF_INVALID
        ) {
          await this.storage.clear();
          this.onSessionExpired?.();
        }

        return {
          success: false,
          error: (error.message as string) ?? `Renewal failed: ${response.status}`,
        };
      }

      const data = await response.json() as {
        bearerPass: string;
        expiresAt: number;
        stateProof?: string;
      };

      await this.storage.setBearerPass(data.bearerPass);

      if (data.stateProof) {
        await this.storage.setStateProof(data.stateProof);
      }

      const decoded = decodeBearerPass(data.bearerPass);
      this.onTokenRefresh?.(data.bearerPass);
      this.scheduleRenewal(data.expiresAt);

      return {
        success: true,
        bearerPass: data.bearerPass,
        payload: decoded.payload,
        expiresAt: data.expiresAt,
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Renewal failed',
      };
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // HTTP HELPERS
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Makes an authenticated HTTP request.
   * 
   * @description Wrapper around the Fetch API that automatically attaches
   * the current BearerPass token to the `Authorization` header. Handles
   * token renewal if the current token is expired.
   * 
   * @param url - The URL to fetch
   * @param options - Standard Fetch API options
   * @returns Promise resolving to the Response object
   * @throws {JTSError} If no valid token is available
   * 
   * @example
   * ```typescript
   * // Simple GET request
   * const response = await client.fetch('https://api.example.com/users');
   * const users = await response.json();
   * 
   * // POST request with body
   * const response = await client.fetch('https://api.example.com/users', {
   *   method: 'POST',
   *   headers: { 'Content-Type': 'application/json' },
   *   body: JSON.stringify({ name: 'John' }),
   * });
   * ```
   */
  async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    const token = await this.getBearerPass();

    if (!token) {
      throw new JTSError(JTS_ERRORS.STATEPROOF_INVALID, JTS_ERROR_MESSAGES.NO_VALID_TOKEN_AVAILABLE);
    }

    const headers = new Headers(options.headers);
    headers.set('Authorization', `Bearer ${token}`);

    return fetch(url, {
      ...options,
      headers,
    });
  }

  /**
   * Gets the formatted Authorization header value.
   * 
   * @description Returns the header value in `Bearer <token>` format,
   * suitable for manually setting headers in HTTP libraries that don't
   * support the client's fetch wrapper.
   * 
   * @returns Promise resolving to the Authorization header value or `null`
   * 
   * @example
   * ```typescript
   * // Using with Axios
   * const authHeader = await client.getAuthHeader();
   * axios.get('/api/data', {
   *   headers: { Authorization: authHeader },
   * });
   * ```
   */
  async getAuthHeader(): Promise<string | null> {
    const token = await this.getBearerPass();
    return token ? `Bearer ${token}` : null;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // LIFECYCLE
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Schedules automatic token renewal before expiration.
   * 
   * @internal
   * @param expiresAt - Unix timestamp when the token expires
   */
  private scheduleRenewal(expiresAt: number): void {
    this.cancelRenewal();

    const now = Math.floor(Date.now() / 1000);
    const renewAt = expiresAt - this.config.autoRenewBefore;
    const delay = Math.max(0, (renewAt - now) * 1000);

    if (delay > 0) {
      this.renewalTimer = setTimeout(async () => {
        const result = await this.renew();
        if (!result.success) {
          // Retry after 30 seconds on failure
          this.renewalTimer = setTimeout(() => this.renew(), 30000);
        }
      }, delay);
    }
  }

  /**
   * Cancels any scheduled automatic renewal.
   * 
   * @internal
   */
  private cancelRenewal(): void {
    if (this.renewalTimer) {
      clearTimeout(this.renewalTimer);
      this.renewalTimer = null;
    }
  }

  /**
   * Cleans up client resources.
   * 
   * @description Call this method when the client is no longer needed to
   * cancel any pending renewal timers and prevent memory leaks.
   * 
   */
  destroy(): void {
    this.cancelRenewal();
  }
}
