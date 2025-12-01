/**
 * @fileoverview Shared constants for JTS paths and well-known endpoints.
 * Centralizes all public HTTP path values to avoid magic strings and
 * make them easy to discover for integrators.
 */

/**
 * Default base path for all JTS REST endpoints.
 *
 * Used by `mountJTSRoutes` in the Express middleware when the caller
 * does not provide a custom `basePath` option.
 *
 * @example
 * ```ts
 * // Default:
 * //   POST /jts/login
 * //   POST /jts/renew
 * //   POST /jts/logout
 * //   GET  /jts/sessions
 * //   DELETE /jts/sessions/:aid
 * ```
 */
export const JTS_DEFAULT_BASE_PATH = '/jts';

/**
 * Well-known JWKS endpoint path (relative to server origin).
 *
 * This path is referenced in OpenID-style discovery documents and should
 * remain stable for interoperability.
 *
 * @example
 * ```ts
 * app.get(JTS_WELL_KNOWN_JWKS_PATH, routes.jwksHandler);
 * ```
 */
export const JTS_WELL_KNOWN_JWKS_PATH = '/.well-known/jts-jwks';

/**
 * Well-known JTS configuration endpoint path (relative to server origin).
 *
 * Returns metadata such as `jwks_uri` and other service information.
 *
 * @example
 * ```ts
 * app.get(JTS_WELL_KNOWN_CONFIGURATION_PATH, routes.configHandler);
 * ```
 */
export const JTS_WELL_KNOWN_CONFIGURATION_PATH =
  '/.well-known/jts-configuration';

/**
 * Relative route paths (appended to `basePath`) for core authentication
 * operations exposed by `mountJTSRoutes`.
 */
export const JTS_LOGIN_ROUTE = '/login';
export const JTS_RENEW_ROUTE = '/renew';
export const JTS_LOGOUT_ROUTE = '/logout';
export const JTS_SESSIONS_ROUTE = '/sessions';
export const JTS_SESSION_REVOKE_ROUTE = '/sessions/:aid';



// ============================================================================
// HTTP STATUS CODE CONSTANTS
// ============================================================================

export const HTTP_STATUS_OK = 200;
export const HTTP_STATUS_BAD_REQUEST = 400;
export const HTTP_STATUS_UNAUTHORIZED = 401;
export const HTTP_STATUS_FORBIDDEN = 403;
export const HTTP_STATUS_NOT_FOUND = 404;
export const HTTP_STATUS_TOO_MANY_REQUESTS = 429;
export const HTTP_STATUS_INTERNAL_SERVER_ERROR = 500;

// ============================================================================
// ERROR RESPONSE CONSTANTS
// ============================================================================

export const ERROR_RATE_LIMITED = 'rate_limited';
export const ERROR_INVALID_CREDENTIALS = 'invalid_credentials';
export const ERROR_SERVER_ERROR = 'server_error';
export const ERROR_CSRF_INVALID = 'csrf_invalid';
export const ERROR_SESSION_NOT_FOUND = 'session_not_found';

export const MESSAGE_TOO_MANY_REQUESTS = 'Too many requests';
export const MESSAGE_INVALID_CREDENTIALS = 'Invalid credentials';
export const MESSAGE_LOGIN_FAILED = 'Login failed';
export const MESSAGE_INVALID_CSRF_TOKEN = 'Invalid CSRF token';
export const MESSAGE_RENEWAL_FAILED = 'Renewal failed';
export const MESSAGE_FAILED_TO_FETCH_SESSIONS = 'Failed to fetch sessions';
export const MESSAGE_SESSION_NOT_FOUND = 'Session not found';
export const MESSAGE_FAILED_TO_REVOKE_SESSION = 'Failed to revoke session';
export const CACHE_CONTROL_JWKS = 'public, max-age=3600, stale-while-revalidate=60';
