/**
 * jts-core - Client SDK
 * Client-side token management with auto-renewal
 */

import {
  JTSClientConfig,
  TokenStorage,
  JTSPayload,
  JTSError,
} from '../types';
import {
  decodeBearerPass,
  getTimeUntilExpiration,
  isTokenExpired,
} from '../tokens/bearer-pass';

// ============================================================================
// IN-MEMORY STORAGE (DEFAULT)
// ============================================================================

/**
 * Simple in-memory token storage
 * For browser apps, consider using a more persistent storage
 */
export class InMemoryTokenStorage implements TokenStorage {
  private bearerPass: string | null = null;
  private stateProof: string | null = null;

  async getBearerPass(): Promise<string | null> {
    return this.bearerPass;
  }

  async setBearerPass(token: string): Promise<void> {
    this.bearerPass = token;
  }

  async getStateProof(): Promise<string | null> {
    return this.stateProof;
  }

  async setStateProof(token: string): Promise<void> {
    this.stateProof = token;
  }

  async clear(): Promise<void> {
    this.bearerPass = null;
    this.stateProof = null;
  }
}

// ============================================================================
// JTS CLIENT CLASS
// ============================================================================

export interface LoginCredentials {
  username?: string;
  password?: string;
  [key: string]: unknown;
}

export interface ClientLoginResult {
  success: boolean;
  bearerPass?: string;
  payload?: JTSPayload;
  expiresAt?: number;
  error?: string;
}

export interface ClientRenewResult {
  success: boolean;
  bearerPass?: string;
  payload?: JTSPayload;
  expiresAt?: number;
  error?: string;
}

/**
 * JTS Client SDK
 * Manages tokens, auto-renewal, and API requests
 */
export class JTSClient {
  private config: Required<JTSClientConfig>;
  private storage: TokenStorage;
  private renewalTimer: ReturnType<typeof setTimeout> | null = null;
  private onTokenRefresh?: (token: string) => void;
  private onSessionExpired?: () => void;

  constructor(options: JTSClientConfig) {
    this.config = {
      authServerUrl: options.authServerUrl.replace(/\/$/, ''), // Remove trailing slash
      tokenEndpoint: options.tokenEndpoint ?? '/jts/login',
      renewalEndpoint: options.renewalEndpoint ?? '/jts/renew',
      logoutEndpoint: options.logoutEndpoint ?? '/jts/logout',
      autoRenewBefore: options.autoRenewBefore ?? 60, // 1 minute before expiry
      storage: options.storage ?? new InMemoryTokenStorage(),
    };

    this.storage = this.config.storage;
  }

  // ==========================================================================
  // EVENT HANDLERS
  // ==========================================================================

  /**
   * Set callback for token refresh events
   */
  onRefresh(callback: (token: string) => void): void {
    this.onTokenRefresh = callback;
  }

  /**
   * Set callback for session expiration
   */
  onExpired(callback: () => void): void {
    this.onSessionExpired = callback;
  }

  // ==========================================================================
  // AUTHENTICATION
  // ==========================================================================

  /**
   * Login with credentials
   */
  async login(credentials: LoginCredentials): Promise<ClientLoginResult> {
    try {
      const response = await fetch(`${this.config.authServerUrl}${this.config.tokenEndpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-JTS-Request': '1', // CSRF protection
        },
        body: JSON.stringify(credentials),
        credentials: 'include', // Include cookies for StateProof
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

      // Store BearerPass
      await this.storage.setBearerPass(data.bearerPass);

      // Store StateProof if returned in body (for non-cookie scenarios)
      if (data.stateProof) {
        await this.storage.setStateProof(data.stateProof);
      }

      // Decode payload
      const decoded = decodeBearerPass(data.bearerPass);

      // Setup auto-renewal
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
   * Logout and clear tokens
   */
  async logout(): Promise<boolean> {
    try {
      // Cancel auto-renewal
      this.cancelRenewal();

      // Get StateProof for header-based logout (mobile/native)
      const stateProof = await this.storage.getStateProof();

      const headers: Record<string, string> = {
        'X-JTS-Request': '1',
      };

      if (stateProof) {
        headers['X-JTS-StateProof'] = stateProof;
      }

      await fetch(`${this.config.authServerUrl}${this.config.logoutEndpoint}`, {
        method: 'POST',
        headers,
        credentials: 'include',
      });

      // Clear local storage
      await this.storage.clear();

      return true;

    } catch {
      // Still clear local storage even if server call fails
      await this.storage.clear();
      return false;
    }
  }

  // ==========================================================================
  // TOKEN MANAGEMENT
  // ==========================================================================

  /**
   * Get current BearerPass (or renew if expired)
   */
  async getBearerPass(): Promise<string | null> {
    const token = await this.storage.getBearerPass();
    
    if (!token) {
      return null;
    }

    // Check if expired
    if (isTokenExpired(token)) {
      const result = await this.renew();
      return result.success ? result.bearerPass ?? null : null;
    }

    return token;
  }

  /**
   * Get current payload (decoded)
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
   * Check if user is authenticated
   */
  async isAuthenticated(): Promise<boolean> {
    const token = await this.storage.getBearerPass();
    return token !== null && !isTokenExpired(token);
  }

  /**
   * Get time until token expires (seconds)
   */
  async getTimeUntilExpiry(): Promise<number> {
    const token = await this.storage.getBearerPass();
    if (!token) return 0;
    return getTimeUntilExpiration(token);
  }

  // ==========================================================================
  // TOKEN RENEWAL
  // ==========================================================================

  /**
   * Manually trigger token renewal
   */
  async renew(): Promise<ClientRenewResult> {
    try {
      // Get StateProof for header-based renewal (mobile/native)
      const stateProof = await this.storage.getStateProof();

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-JTS-Request': '1',
      };

      if (stateProof) {
        headers['X-JTS-StateProof'] = stateProof;
      }

      const response = await fetch(`${this.config.authServerUrl}${this.config.renewalEndpoint}`, {
        method: 'POST',
        headers,
        credentials: 'include',
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({})) as Record<string, unknown>;
        
        // Check if session is compromised or terminated
        const errorCode = error.error_code as string;
        if (errorCode === 'JTS-401-04' || errorCode === 'JTS-401-05' || errorCode === 'JTS-401-03') {
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

      // Store new BearerPass
      await this.storage.setBearerPass(data.bearerPass);

      // Store new StateProof if returned
      if (data.stateProof) {
        await this.storage.setStateProof(data.stateProof);
      }

      // Decode payload
      const decoded = decodeBearerPass(data.bearerPass);

      // Notify callback
      this.onTokenRefresh?.(data.bearerPass);

      // Reschedule renewal
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

  // ==========================================================================
  // HTTP HELPERS
  // ==========================================================================

  /**
   * Make an authenticated fetch request
   */
  async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    const token = await this.getBearerPass();

    if (!token) {
      throw new JTSError('JTS-401-03', 'No valid token available');
    }

    const headers = new Headers(options.headers);
    headers.set('Authorization', `Bearer ${token}`);

    return fetch(url, {
      ...options,
      headers,
    });
  }

  /**
   * Get authorization header value
   */
  async getAuthHeader(): Promise<string | null> {
    const token = await this.getBearerPass();
    return token ? `Bearer ${token}` : null;
  }

  // ==========================================================================
  // PRIVATE HELPERS
  // ==========================================================================

  /**
   * Schedule automatic token renewal
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
          // Try again in 30 seconds
          this.renewalTimer = setTimeout(() => this.renew(), 30000);
        }
      }, delay);
    }
  }

  /**
   * Cancel scheduled renewal
   */
  private cancelRenewal(): void {
    if (this.renewalTimer) {
      clearTimeout(this.renewalTimer);
      this.renewalTimer = null;
    }
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    this.cancelRenewal();
  }
}
