import { TokenStorage } from '../types';

// ============================================================================
// IN-MEMORY STORAGE (DEFAULT)
// ============================================================================
/**
 * Default in-memory token storage implementation.
 *
 * @description Provides a simple, volatile storage mechanism for JTS tokens.
 * Tokens are stored in memory and will be lost on page refresh or app restart.
 *
 * **Important:** For production browser applications, consider implementing
 * a persistent storage adapter using `localStorage`, `sessionStorage`, or
 * a secure storage solution like `@capacitor/secure-storage` for mobile apps.
 *
 * @implements {TokenStorage}
 *
 * @example
 * ```typescript
 * // Using default in-memory storage
 * const client = new JTSClient({
 *   authServerUrl: 'https://auth.example.com',
 * });
 *
 * // Using custom storage
 * const client = new JTSClient({
 *   authServerUrl: 'https://auth.example.com',
 *   storage: new LocalStorageAdapter(),
 * });
 * ```
 */

export class InMemoryTokenStorage implements TokenStorage {
  private bearerPass: string | null = null;
  private stateProof: string | null = null;

  /** @inheritdoc */
  async getBearerPass(): Promise<string | null> {
    return this.bearerPass;
  }

  /** @inheritdoc */
  async setBearerPass(token: string): Promise<void> {
    this.bearerPass = token;
  }

  /** @inheritdoc */
  async getStateProof(): Promise<string | null> {
    return this.stateProof;
  }

  /** @inheritdoc */
  async setStateProof(token: string): Promise<void> {
    this.stateProof = token;
  }

  /** @inheritdoc */
  async clear(): Promise<void> {
    this.bearerPass = null;
    this.stateProof = null;
  }
}
