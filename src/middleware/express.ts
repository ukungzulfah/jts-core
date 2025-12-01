/**
 * @engjts/auth - Express Middleware
 * Enterprise-grade authentication and authorization middleware for Express.js applications
 * 
 * This module provides comprehensive JWT-based authentication with:
 * - Token validation and verification
 * - Role-based access control (RBAC)
 * - Session management with StateProof cookies
 * - Built-in CSRF protection
 * - Rate limiting support
 * - Comprehensive error handling
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  JTSPayload,
  JTSHeader,
  JTSError,
  JTS_ERRORS,
  JTS_ERROR_MESSAGES,
  JTS_ERROR_MESSAGE_HELPERS,
  JTS_HEADERS_LOWERCASE,
  JTSRequest,
  StateProofCookieOptions,
} from '../types';
import { JTSAuthServer, LoginOptions, RenewOptions } from '../server/auth-server';
import { JTSResourceServer } from '../server/resource-server';
import { JTS_DEFAULT_BASE_PATH, JTS_LOGIN_ROUTE, JTS_RENEW_ROUTE, JTS_LOGOUT_ROUTE, JTS_SESSIONS_ROUTE, JTS_SESSION_REVOKE_ROUTE, JTS_WELL_KNOWN_JWKS_PATH, JTS_WELL_KNOWN_CONFIGURATION_PATH } from './constants';



// ============================================================================
// HTTP STATUS CODE CONSTANTS
// ============================================================================

const HTTP_STATUS_OK = 200;
const HTTP_STATUS_BAD_REQUEST = 400;
const HTTP_STATUS_UNAUTHORIZED = 401;
const HTTP_STATUS_FORBIDDEN = 403;
const HTTP_STATUS_NOT_FOUND = 404;
const HTTP_STATUS_TOO_MANY_REQUESTS = 429;
const HTTP_STATUS_INTERNAL_SERVER_ERROR = 500;

// ============================================================================
// ERROR RESPONSE CONSTANTS
// ============================================================================

const ERROR_RATE_LIMITED = 'rate_limited';
const ERROR_INVALID_CREDENTIALS = 'invalid_credentials';
const ERROR_SERVER_ERROR = 'server_error';
const ERROR_CSRF_INVALID = 'csrf_invalid';
const ERROR_SESSION_NOT_FOUND = 'session_not_found';

const MESSAGE_TOO_MANY_REQUESTS = 'Too many requests';
const MESSAGE_INVALID_CREDENTIALS = 'Invalid credentials';
const MESSAGE_LOGIN_FAILED = 'Login failed';
const MESSAGE_INVALID_CSRF_TOKEN = 'Invalid CSRF token';
const MESSAGE_RENEWAL_FAILED = 'Renewal failed';
const MESSAGE_FAILED_TO_FETCH_SESSIONS = 'Failed to fetch sessions';
const MESSAGE_SESSION_NOT_FOUND = 'Session not found';
const MESSAGE_FAILED_TO_REVOKE_SESSION = 'Failed to revoke session';

const CACHE_CONTROL_JWKS = 'public, max-age=3600, stale-while-revalidate=60';

/**
 * Extend Express Request type to include JTS authentication context
 * This augmentation makes JTS authentication data available throughout the application
 */
declare global {
  namespace Express {
    interface Request {
      /**
       * JTS authentication context containing verified token data
       * Available after successful authentication middleware execution
       */
      jts?: {
        /** Verified JWT payload containing user claims and permissions */
        payload: JTSPayload;
        /** JWT header information including algorithm and key ID */
        header: JTSHeader;
        /** Raw BearerPass token string for downstream use */
        bearerPass: string;
      };
    }
  }
}


/**
 * Configuration options for JTS authentication middleware
 * Provides fine-grained control over authentication behavior and integration
 */
export interface JTSMiddlewareOptions {
  /** 
   * Resource server instance responsible for token verification
   * Must be configured with appropriate public keys for signature validation
   */
  resourceServer: JTSResourceServer;
  
  /** 
   * Custom token extraction strategy from incoming requests
   * Defaults to standard Authorization: Bearer header parsing
   * @param req - Express request object
   * @returns Token string or null if not found
   */
  extractToken?: (req: Request) => string | null;
  
  /** 
   * Custom error handling mechanism for authentication failures
   * Defaults to standardized JSON error responses with appropriate HTTP status codes
   * @param error - JTS error object with detailed failure information
   * @param req - Express request object
   * @param res - Express response object
   * @param next - Express next middleware function
   */
  onError?: (error: JTSError, req: Request, res: Response, next: NextFunction) => void;
}

/**
 * Default token extraction implementation
 * Retrieves Bearer token from Authorization HTTP header
 * 
 * @param req - Express request containing potential authorization header
 * @returns Bearer token string or null if not present or malformed
 * 
 * @example
 * // Valid header: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * // Returns: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 * 
 * @example
 * // Missing or malformed header
 * // Returns: null
 */
function defaultExtractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.substring(7);
}

/**
 * Standardized error response handler
 * Converts JTS errors into structured JSON responses with appropriate HTTP status codes
 * 
 * @param error - JTS error containing failure details and recommended HTTP status
 * @param req - Express request object (unused but required for interface compliance)
 * @param res - Express response object for sending error response
 * @param _next - Next middleware function (unused but required for interface compliance)
 * 
 * @example
 * // For PERMISSION_DENIED error:
 * // Response: { "errorCode": "PERMISSION_DENIED", "message": "...", "httpStatus": 403 }
 */
function defaultOnError(error: JTSError, req: Request, res: Response, _next: NextFunction): void {
  res.status(error.httpStatus).json(error.toJSON());
}

/**
 * Mandatory authentication middleware factory
 * Validates JWT tokens and attaches verified user context to requests
 * Rejects requests without valid authentication tokens
 * 
 * Security Features:
 * - Cryptographic token signature verification
 * - Expiration checking
 * - Audience and issuer validation
 * - Malformed token detection
 * 
 * @param options - Configuration for authentication behavior
 * @returns Express middleware function enforcing authentication
 * 
 * @example
 * ```typescript
 * app.use('/api/secure', jtsAuth({ resourceServer }));
 * ```
 * 
 * @throws {JTSError} With appropriate HTTP status for various failure modes:
 * - 401: Missing or invalid token
 * - 403: Expired or malformed token
 * - 500: Internal verification errors
 */
export function jtsAuth(options: JTSMiddlewareOptions): RequestHandler {
  const {
    resourceServer,
    extractToken = defaultExtractToken,
    onError = defaultOnError,
  } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = extractToken(req);
      
      if (!token) {
        const error = new JTSError(JTS_ERRORS.STATEPROOF_INVALID, JTS_ERROR_MESSAGES.NO_TOKEN_PROVIDED);
        onError(error, req, res, next);
        return;
      }

      const result = await resourceServer.verify(token);

      if (!result.valid || !result.payload || !result.header) {
        onError(result.error!, req, res, next);
        return;
      }

      req.jts = {
        payload: result.payload,
        header: result.header,
        bearerPass: token,
      };

      next();

    } catch (error) {
      if (error instanceof JTSError) {
        onError(error, req, res, next);
      } else {
        onError(new JTSError(JTS_ERRORS.MALFORMED_TOKEN, JTS_ERROR_MESSAGES.TOKEN_VERIFICATION_FAILED), req, res, next);
      }
    }
  };
}

/**
 * Optional authentication middleware factory
 * Validates JWT tokens when present but permits anonymous access
 * Attaches user context only when valid tokens are provided
 * 
 * Use Cases:
 * - Public endpoints with enhanced features for authenticated users
 * - Gradual migration of legacy systems to authenticated access
 * - Hybrid APIs serving both anonymous and authenticated clients
 * 
 * @param options - Configuration for authentication behavior
 * @returns Express middleware function enabling optional authentication
 * 
 * @example
 * ```typescript
 * app.use('/api/public', jtsOptionalAuth({ resourceServer }));
 * ```
 */
export function jtsOptionalAuth(options: JTSMiddlewareOptions): RequestHandler {
  const {
    resourceServer,
    extractToken = defaultExtractToken,
  } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = extractToken(req);
      
      if (token) {
        const result = await resourceServer.verify(token);
        
        if (result.valid && result.payload && result.header) {
          req.jts = {
            payload: result.payload,
            header: result.header,
            bearerPass: token,
          };
        }
      }

      next();

    } catch {
      next();
    }
  };
}


/**
 * Configuration options for permission enforcement middleware
 * Enables flexible role-based access control with multiple evaluation strategies
 */
export interface PermissionOptions {
  /** 
   * Required permissions - user must possess ALL specified permissions
   * Uses AND logic for permission evaluation
   */
  required?: string[];
  
  /** 
   * Alternative permissions - user must possess AT LEAST ONE specified permission
   * Uses OR logic for permission evaluation
   */
  any?: string[];
  
  /** 
   * Custom permission evaluation function for complex access control logic
   * Receives verified user payload and request context for dynamic evaluation
   * @param payload - Verified JWT payload containing user claims
   * @param req - Express request with potential additional context
   * @returns Boolean indicating permission grant or Promise resolving to boolean
   */
  check?: (payload: JTSPayload, req: Request) => boolean | Promise<boolean>;
  
  /** 
   * Custom error handling for permission denial
   * Defaults to standardized JSON responses with 403 Forbidden status
   * @param error - Permission denial error with details
   * @param req - Express request object
   * @param res - Express response object
   * @param next - Express next middleware function
   */
  onError?: (error: JTSError, req: Request, res: Response, next: NextFunction) => void;
}

/**
 * Permission enforcement middleware factory
 * Validates user permissions against configured requirements
 * Requires prior execution of authentication middleware to establish user context
 * 
 * Permission Evaluation Order:
 * 1. Required permissions (all must be present)
 * 2. Any permissions (at least one must be present)
 * 3. Custom permission check (if provided)
 * 
 * @param options - Permission requirements and evaluation configuration
 * @returns Express middleware function enforcing access control
 * 
 * @example
 * ```typescript
 * // Require specific permissions
 * app.get('/api/admin', 
 *   jtsAuth({ resourceServer }), 
 *   jtsRequirePermissions({ required: ['admin', 'user:read'] }),
 *   handler
 * );
 * 
 * // Alternative permissions
 * app.get('/api/reports', 
 *   jtsAuth({ resourceServer }), 
 *   jtsRequirePermissions({ any: ['reports:view', 'admin'] }),
 *   handler
 * );
 * ```
 * 
 * @throws {JTSError} With 403 Forbidden status for permission denials
 */
export function jtsRequirePermissions(options: PermissionOptions): RequestHandler {
  const { required, any, check, onError = defaultOnError } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.jts) {
        const error = new JTSError(JTS_ERRORS.STATEPROOF_INVALID, JTS_ERROR_MESSAGES.AUTHENTICATION_REQUIRED);
        onError(error, req, res, next);
        return;
      }

      const { payload } = req.jts;
      const tokenPerms = payload.perm ?? [];

      if (required && required.length > 0) {
        const hasAll = required.every(p => tokenPerms.includes(p));
        if (!hasAll) {
          const error = new JTSError(JTS_ERRORS.PERMISSION_DENIED, JTS_ERROR_MESSAGE_HELPERS.missingRequiredPermissions(required));
          onError(error, req, res, next);
          return;
        }
      }

      if (any && any.length > 0) {
        const hasAny = any.some(p => tokenPerms.includes(p));
        if (!hasAny) {
          const error = new JTSError(JTS_ERRORS.PERMISSION_DENIED, JTS_ERROR_MESSAGE_HELPERS.requiresOneOf(any));
          onError(error, req, res, next);
          return;
        }
      }

      if (check) {
        const allowed = await check(payload, req);
        if (!allowed) {
          const error = new JTSError(JTS_ERRORS.PERMISSION_DENIED, JTS_ERROR_MESSAGES.PERMISSION_DENIED);
          onError(error, req, res, next);
          return;
        }
      }

      next();

    } catch (error) {
      if (error instanceof JTSError) {
        onError(error, req, res, next);
      } else {
        onError(new JTSError(JTS_ERRORS.PERMISSION_DENIED, JTS_ERROR_MESSAGES.PERMISSION_CHECK_FAILED), req, res, next);
      }
    }
  };
}


/**
 * Configuration options for JTS authentication route handlers
 * Enables customization of authentication flows and security policies
 */
export interface JTSRoutesOptions {
  /** 
   * Authentication server instance for token generation and session management
   * Must be configured with appropriate signing keys and session storage
   */
  authServer: JTSAuthServer;
  
  /** 
   * Configuration for StateProof cookie behavior
   * Controls security properties of session persistence mechanism
   */
  cookieOptions?: StateProofCookieOptions;
  
  /** 
   * Credential validation function for authentication endpoint
   * Implementors determine authentication method (database, LDAP, OAuth, etc.)
   * @param req - Express request containing credentials
   * @returns Login options for authenticated user or null for rejection
   */
  validateCredentials: (req: Request) => Promise<LoginOptions | null>;
  
  /** 
   * Cross-Site Request Forgery protection validation
   * Defaults to checking X-JTS-Request header for API protection
   * @param req - Express request to validate
   * @returns Boolean indicating CSRF token validity
   */
  validateCSRF?: (req: Request) => boolean;
  
  /** 
   * Rate limiting function to prevent abuse
   * Implementors can integrate with external rate limiting services
   * @param req - Express request to evaluate
   * @returns Promise resolving to boolean indicating allowance
   */
  rateLimit?: (req: Request) => Promise<boolean>;
}

/**
 * Factory function for JTS authentication route handlers
 * Creates comprehensive authentication endpoints with enterprise security features
 * 
 * Endpoints Provided:
 * - POST /login: Authenticate credentials and generate tokens
 * - POST /renew: Refresh authentication using StateProof
 * - POST /logout: Terminate session and invalidate tokens
 * - GET /sessions: List active user sessions
 * - DELETE /sessions/:aid: Revoke specific session
 * - GET /.well-known/jts-jwks: Public key distribution
 * - GET /.well-known/jts-configuration: Service configuration
 * 
 * Security Features:
 * - Secure cookie-based session management
 * - Automatic session cleanup on compromise
 * - Device fingerprint binding
 * - CSRF protection
 * - Rate limiting support
 * - Comprehensive audit logging
 * 
 * @param options - Route configuration and security policies
 * @returns Object containing all route handlers for mounting
 * 
 * @example
 * ```typescript
 * const routes = createJTSRoutes({ 
 *   authServer, 
 *   validateCredentials: myValidator 
 * });
 * app.post('/jts/login', routes.loginHandler);
 * ```
 */
export function createJTSRoutes(options: JTSRoutesOptions) {
  const {
    authServer,
    cookieOptions = {},
    validateCredentials,
    validateCSRF = (req) => req.headers[JTS_HEADERS_LOWERCASE.REQUEST] === '1',
    rateLimit,
  } = options;

  const defaultCookieOptions: StateProofCookieOptions = {
    name: 'jts_state_proof',
    path: '/jts',
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    ...cookieOptions,
  };

  
  /**
   * Authentication endpoint handler
   * Validates credentials, creates session, and generates authentication tokens
   * 
   * Process Flow:
   * 1. Apply rate limiting if configured
   * 2. Validate provided credentials via custom validator
   * 3. Enforce session policy (single, max N, etc.)
   * 4. Create new session in persistent storage
   * 5. Generate cryptographically signed BearerPass
   * 6. Issue StateProof cookie for future renewal
   * 7. Return authentication tokens to client
   * 
   * Security Considerations:
   * - Credentials never persisted by framework
   * - Rate limiting prevents brute force attacks
   * - Session policies enforce business rules
   * - Secure cookie attributes prevent XSS/CSRF
   * - Client IP and User-Agent tracked for anomaly detection
   * 
   * @param req - Express request containing credentials
   * @param res - Express response for authentication tokens
   */
  const loginHandler: RequestHandler = async (req, res) => {
    try {
      if (rateLimit && !(await rateLimit(req))) {
        res.status(HTTP_STATUS_TOO_MANY_REQUESTS).json({
          error: ERROR_RATE_LIMITED,
          message: MESSAGE_TOO_MANY_REQUESTS,
        });
        return;
      }
      const loginOptions = await validateCredentials(req);
      
      if (!loginOptions) {
        res.status(HTTP_STATUS_UNAUTHORIZED).json({
          error: ERROR_INVALID_CREDENTIALS,
          message: MESSAGE_INVALID_CREDENTIALS,
        });
        return;
      }
      loginOptions.userAgent = req.headers['user-agent'];
      loginOptions.ipAddress = req.ip || req.socket.remoteAddress;
      const result = await authServer.login(loginOptions);
      res.cookie(defaultCookieOptions.name!, result.stateProof, {
        httpOnly: true,
        secure: defaultCookieOptions.secure,
        sameSite: defaultCookieOptions.sameSite,
        path: defaultCookieOptions.path,
        maxAge: (authServer['config'].stateProofLifetime ?? 604800) * 1000,
      });
      res.json({
        bearerPass: result.bearerPass,
        expiresAt: result.expiresAt,
        sessionId: result.sessionId,
      });

    } catch (error) {
      if (error instanceof JTSError) {
        res.status(error.httpStatus).json(error.toJSON());
      } else {
        res.status(HTTP_STATUS_INTERNAL_SERVER_ERROR).json({
          error: ERROR_SERVER_ERROR,
          message: MESSAGE_LOGIN_FAILED,
        });
      }
    }
  };

  
  /**
   * Token renewal endpoint handler
   * Exchanges StateProof for fresh BearerPass without re-authentication
   * 
   * Process Flow:
   * 1. Validate CSRF protection token
   * 2. Extract StateProof from cookie or header
   * 3. Verify StateProof validity and session status
   * 4. Rotate StateProof if security policy requires
   * 5. Generate new BearerPass with updated expiration
   * 6. Update session last-active timestamp
   * 7. Return refreshed tokens to client
   * 
   * Security Considerations:
   * - CSRF protection prevents unauthorized renewal
   * - StateProof rotation mitigates replay attacks
   * - Session compromise detection with automatic cleanup
   * - Device fingerprint binding prevents hijacking
   * 
   * @param req - Express request containing StateProof
   * @param res - Express response for renewed tokens
   */
  const renewHandler: RequestHandler = async (req, res) => {
    try {
      if (!validateCSRF(req)) {
        res.status(HTTP_STATUS_FORBIDDEN).json({
          error: ERROR_CSRF_INVALID,
          message: MESSAGE_INVALID_CSRF_TOKEN,
        });
        return;
      }
      const stateProof = req.cookies?.[defaultCookieOptions.name!] 
        || req.headers[JTS_HEADERS_LOWERCASE.STATE_PROOF] as string;

      if (!stateProof) {
        res.status(HTTP_STATUS_UNAUTHORIZED).json(new JTSError(JTS_ERRORS.STATEPROOF_INVALID, JTS_ERROR_MESSAGES.STATEPROOF_NOT_PROVIDED).toJSON());
        return;
      }
      const renewOptions: RenewOptions = {
        stateProof,
        deviceFingerprint: req.headers[JTS_HEADERS_LOWERCASE.DEVICE_FINGERPRINT] as string,
      };
      const result = await authServer.renew(renewOptions);
      if (result.stateProof) {
        res.cookie(defaultCookieOptions.name!, result.stateProof, {
          httpOnly: true,
          secure: defaultCookieOptions.secure,
          sameSite: defaultCookieOptions.sameSite,
          path: defaultCookieOptions.path,
          maxAge: (authServer['config'].stateProofLifetime ?? 604800) * 1000,
        });
      }
      res.json({
        bearerPass: result.bearerPass,
        expiresAt: result.expiresAt,
      });

    } catch (error) {
      if (error instanceof JTSError) {
        if (error.errorCode === JTS_ERRORS.SESSION_COMPROMISED || error.errorCode === JTS_ERRORS.SESSION_TERMINATED) {
          res.clearCookie(defaultCookieOptions.name!, {
            path: defaultCookieOptions.path,
          });
        }
        res.status(error.httpStatus).json(error.toJSON());
      } else {
        res.status(HTTP_STATUS_INTERNAL_SERVER_ERROR).json({
          error: ERROR_SERVER_ERROR,
          message: MESSAGE_RENEWAL_FAILED,
        });
      }
    }
  };

  
  /**
   * Session termination endpoint handler
   * Invalidates StateProof and terminates associated session
   * 
   * Process Flow:
   * 1. Validate CSRF protection token
   * 2. Extract StateProof from cookie or header
   * 3. Terminate associated session in persistent storage
   * 4. Clear StateProof cookie to prevent reuse
   * 5. Return confirmation to client
   * 
   * Security Considerations:
   * - CSRF protection prevents unauthorized logout
   * - Session termination revokes all associated tokens
   * - Cookie clearing prevents session resurrection
   * - Idempotent operation safe for repeated calls
   * 
   * @param req - Express request containing StateProof
   * @param res - Express response confirming termination
   */
  const logoutHandler: RequestHandler = async (req, res) => {
    try {
      if (!validateCSRF(req)) {
        res.status(HTTP_STATUS_FORBIDDEN).json({
          error: ERROR_CSRF_INVALID,
          message: MESSAGE_INVALID_CSRF_TOKEN,
        });
        return;
      }
      const stateProof = req.cookies?.[defaultCookieOptions.name!] 
        || req.headers[JTS_HEADERS_LOWERCASE.STATE_PROOF] as string;

      if (stateProof) {
        await authServer.logout(stateProof);
      }

      res.clearCookie(defaultCookieOptions.name!, {
        path: defaultCookieOptions.path,
      });

      res.json({ success: true });

    } catch (error) {
      res.clearCookie(defaultCookieOptions.name!, {
        path: defaultCookieOptions.path,
      });
      
      res.json({ success: true });
    }
  };

  
  /**
   * Active sessions enumeration endpoint handler
   * Lists all active sessions for authenticated user with metadata
   * 
   * Process Flow:
   * 1. Verify user authentication context
   * 2. Retrieve all sessions for user principal
   * 3. Anonymize sensitive session data
   * 4. Identify current session in result set
   * 5. Return session list to client
   * 
   * Privacy Considerations:
   * - IP addresses partially anonymized (last octet removed)
   * - User agent information preserved for device recognition
   * - Session timestamps converted to Unix format
   * - Current session clearly marked for UI indication
   * 
   * @param req - Express request with authenticated user context
   * @param res - Express response with session list
   */
  const sessionsHandler: RequestHandler = async (req, res) => {
    try {
      if (!req.jts) {
        res.status(HTTP_STATUS_UNAUTHORIZED).json(new JTSError(JTS_ERRORS.STATEPROOF_INVALID, JTS_ERROR_MESSAGES.AUTHENTICATION_REQUIRED).toJSON());
        return;
      }

      const sessions = await authServer.getSessions(req.jts.payload.prn);
      const currentAid = req.jts.payload.aid;

      res.json({
        sessions: sessions.map(s => ({
          aid: s.aid,
          device: s.userAgent ?? 'Unknown device',
          ipPrefix: s.ipAddress ? s.ipAddress.split('.').slice(0, 3).join('.') + '.x' : 'Unknown',
          createdAt: Math.floor(s.createdAt.getTime() / 1000),
          lastActive: Math.floor(s.lastActive.getTime() / 1000),
          current: s.aid === currentAid,
        })),
      });

    } catch (error) {
      res.status(HTTP_STATUS_INTERNAL_SERVER_ERROR).json({
        error: ERROR_SERVER_ERROR,
        message: MESSAGE_FAILED_TO_FETCH_SESSIONS,
      });
    }
  };

  /**
   * Individual session revocation endpoint handler
   * Terminates specific session for authenticated user by Anchor ID
   * 
   * Process Flow:
   * 1. Verify user authentication context
   * 2. Extract target session ID from URL parameters
   * 3. Confirm session ownership to prevent cross-account termination
   * 4. Revoke session in persistent storage
   * 5. Return confirmation to client
   * 
   * Security Considerations:
   * - Ownership verification prevents unauthorized session termination
   * - Session revocation cascades to all associated tokens
   * - Idempotent operation safe for repeated calls
   * - Immediate effect on subsequent authentication attempts
   * 
   * @param req - Express request with authenticated user and target session
   * @param res - Express response confirming revocation
   */
  const revokeSessionHandler: RequestHandler = async (req, res) => {
    try {
      if (!req.jts) {
        res.status(HTTP_STATUS_UNAUTHORIZED).json(new JTSError(JTS_ERRORS.STATEPROOF_INVALID, JTS_ERROR_MESSAGES.AUTHENTICATION_REQUIRED).toJSON());
        return;
      }

      const { aid } = req.params;
      
      const session = await authServer.getSession(aid);
      if (!session || session.prn !== req.jts.payload.prn) {
        res.status(HTTP_STATUS_NOT_FOUND).json({
          error: ERROR_SESSION_NOT_FOUND,
          message: MESSAGE_SESSION_NOT_FOUND,
        });
        return;
      }

      await authServer.revokeSession(aid);

      res.json({ success: true });

    } catch (error) {
      res.status(HTTP_STATUS_INTERNAL_SERVER_ERROR).json({
        error: ERROR_SERVER_ERROR,
        message: MESSAGE_FAILED_TO_REVOKE_SESSION,
      });
    }
  };

  /**
   * JSON Web Key Set endpoint handler
   * Provides public keys for token signature verification
   * 
   * Standards Compliance:
   * - RFC 7517 JSON Web Key (JWK) specification
   * - RFC 7518 JSON Web Algorithms (JWA) identifiers
   * - Appropriate caching headers for performance
   * 
   * @param req - Express request for public keys
   * @param res - Express response with JWK Set
   */
  const jwksHandler: RequestHandler = (req, res) => {
    res.setHeader('Cache-Control', CACHE_CONTROL_JWKS);
    res.json(authServer.getJWKS());
  };

  /**
   * Service configuration endpoint handler
   * Provides authentication service metadata for client configuration
   * 
   * Metadata Includes:
   * - Issuer identifier
   * - Supported algorithms
   * - Endpoint locations
   * - Service capabilities
   * 
   * @param req - Express request for service configuration
   * @param res - Express response with configuration metadata
   */
  const configHandler: RequestHandler = (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.json(authServer.getConfiguration(baseUrl));
  };

  return {
    loginHandler,
    renewHandler,
    logoutHandler,
    sessionsHandler,
    revokeSessionHandler,
    jwksHandler,
    configHandler,
  };
}

/**
 * Convenience function to mount all JTS routes on Express application
 * Automatically configures routing paths and middleware composition
 * 
 * Mounted Endpoints:
 * - POST /jts/login: User authentication
 * - POST /jts/renew: Token renewal
 * - POST /jts/logout: Session termination
 * - GET /jts/sessions: Session enumeration
 * - DELETE /jts/sessions/:aid: Session revocation
 * - GET /.well-known/jts-jwks: Public key distribution
 * - GET /.well-known/jts-configuration: Service metadata
 * 
 * @param app - Express application or router instance
 * @param options - Route configuration with required dependencies
 * 
 * @example
 * ```typescript
 * mountJTSRoutes(app, { 
 *   authServer, 
 *   resourceServer,
 *   validateCredentials: myValidator
 * });
 * ```
 */
export function mountJTSRoutes(
  app: { post: Function; get: Function; delete: Function },
  options: JTSRoutesOptions & { 
    resourceServer: JTSResourceServer;
    basePath?: string;
  }
): void {
  const { basePath = JTS_DEFAULT_BASE_PATH, resourceServer, ...routeOptions } = options;
  const routes = createJTSRoutes(routeOptions);
  app.post(`${basePath}${JTS_LOGIN_ROUTE}`, routes.loginHandler);
  app.post(`${basePath}${JTS_RENEW_ROUTE}`, routes.renewHandler);
  app.post(`${basePath}${JTS_LOGOUT_ROUTE}`, routes.logoutHandler);
  const authMiddleware = jtsAuth({ resourceServer });
  app.get(`${basePath}${JTS_SESSIONS_ROUTE}`, authMiddleware, routes.sessionsHandler);
  app.delete(`${basePath}${JTS_SESSION_REVOKE_ROUTE}`, authMiddleware, routes.revokeSessionHandler);
  app.get(JTS_WELL_KNOWN_JWKS_PATH, routes.jwksHandler);
  app.get(JTS_WELL_KNOWN_CONFIGURATION_PATH, routes.configHandler);
}