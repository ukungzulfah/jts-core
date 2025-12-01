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


