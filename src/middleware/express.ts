/**
 * jts-core - Express Middleware
 * Authentication and authorization middleware for Express.js
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  JTSPayload,
  JTSHeader,
  JTSError,
  JTSRequest,
  StateProofCookieOptions,
} from '../types';
import { JTSAuthServer, LoginOptions, RenewOptions } from '../server/auth-server';
import { JTSResourceServer } from '../server/resource-server';

// ============================================================================
// TYPE AUGMENTATION
// ============================================================================

declare global {
  namespace Express {
    interface Request {
      jts?: {
        payload: JTSPayload;
        header: JTSHeader;
        bearerPass: string;
      };
    }
  }
}

// ============================================================================
// MIDDLEWARE FACTORY
// ============================================================================

export interface JTSMiddlewareOptions {
  /** Resource server instance for verification */
  resourceServer: JTSResourceServer;
  /** Extract token from request (default: Authorization header) */
  extractToken?: (req: Request) => string | null;
  /** Handle errors (default: send JSON response) */
  onError?: (error: JTSError, req: Request, res: Response, next: NextFunction) => void;
}

/**
 * Extract bearer token from Authorization header
 */
function defaultExtractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.substring(7);
}

/**
 * Default error handler
 */
function defaultOnError(error: JTSError, req: Request, res: Response, _next: NextFunction): void {
  res.status(error.httpStatus).json(error.toJSON());
}

/**
 * Create JTS authentication middleware
 */
export function jtsAuth(options: JTSMiddlewareOptions): RequestHandler {
  const {
    resourceServer,
    extractToken = defaultExtractToken,
    onError = defaultOnError,
  } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // 1. Extract token
      const token = extractToken(req);
      
      if (!token) {
        const error = new JTSError('JTS-401-03', 'No token provided');
        onError(error, req, res, next);
        return;
      }

      // 2. Verify token
      const result = await resourceServer.verify(token);

      if (!result.valid || !result.payload || !result.header) {
        onError(result.error!, req, res, next);
        return;
      }

      // 3. Attach to request
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
        onError(new JTSError('JTS-400-01', 'Token verification failed'), req, res, next);
      }
    }
  };
}

/**
 * Create optional JTS authentication middleware
 * Attaches user info if valid token present, but doesn't reject if missing
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
      // Ignore errors for optional auth
      next();
    }
  };
}

// ============================================================================
// PERMISSION MIDDLEWARE
// ============================================================================

export interface PermissionOptions {
  /** Required permissions (all must be present) */
  required?: string[];
  /** Any of these permissions (at least one must be present) */
  any?: string[];
  /** Custom permission check function */
  check?: (payload: JTSPayload, req: Request) => boolean | Promise<boolean>;
  /** Error handler */
  onError?: (error: JTSError, req: Request, res: Response, next: NextFunction) => void;
}

/**
 * Create permission checking middleware
 * Must be used after jtsAuth middleware
 */
export function jtsRequirePermissions(options: PermissionOptions): RequestHandler {
  const { required, any, check, onError = defaultOnError } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.jts) {
        const error = new JTSError('JTS-401-03', 'Authentication required');
        onError(error, req, res, next);
        return;
      }

      const { payload } = req.jts;
      const tokenPerms = payload.perm ?? [];

      // Check required permissions
      if (required && required.length > 0) {
        const hasAll = required.every(p => tokenPerms.includes(p));
        if (!hasAll) {
          const error = new JTSError('JTS-403-02', `Missing required permissions: ${required.join(', ')}`);
          onError(error, req, res, next);
          return;
        }
      }

      // Check any permissions
      if (any && any.length > 0) {
        const hasAny = any.some(p => tokenPerms.includes(p));
        if (!hasAny) {
          const error = new JTSError('JTS-403-02', `Requires one of: ${any.join(', ')}`);
          onError(error, req, res, next);
          return;
        }
      }

      // Custom check
      if (check) {
        const allowed = await check(payload, req);
        if (!allowed) {
          const error = new JTSError('JTS-403-02', 'Permission denied');
          onError(error, req, res, next);
          return;
        }
      }

      next();

    } catch (error) {
      if (error instanceof JTSError) {
        onError(error, req, res, next);
      } else {
        onError(new JTSError('JTS-403-02', 'Permission check failed'), req, res, next);
      }
    }
  };
}

// ============================================================================
// AUTH SERVER ROUTES
// ============================================================================

export interface JTSRoutesOptions {
  /** Auth server instance */
  authServer: JTSAuthServer;
  /** Cookie options for StateProof */
  cookieOptions?: StateProofCookieOptions;
  /** Custom login handler (validate credentials) */
  validateCredentials: (req: Request) => Promise<LoginOptions | null>;
  /** CSRF validation (default: check X-JTS-Request header) */
  validateCSRF?: (req: Request) => boolean;
  /** Rate limiting (return true to allow, false to reject) */
  rateLimit?: (req: Request) => Promise<boolean>;
}

/**
 * Create Express router with JTS auth endpoints
 */
export function createJTSRoutes(options: JTSRoutesOptions) {
  const {
    authServer,
    cookieOptions = {},
    validateCredentials,
    validateCSRF = (req) => req.headers['x-jts-request'] === '1',
    rateLimit,
  } = options;

  const defaultCookieOptions: StateProofCookieOptions = {
    name: 'jts_state_proof',
    path: '/jts',
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    ...cookieOptions,
  };

  // ==========================================================================
  // LOGIN ENDPOINT
  // ==========================================================================

  const loginHandler: RequestHandler = async (req, res) => {
    try {
      // Rate limiting
      if (rateLimit && !(await rateLimit(req))) {
        res.status(429).json({
          error: 'rate_limited',
          message: 'Too many requests',
        });
        return;
      }

      // Validate credentials
      const loginOptions = await validateCredentials(req);
      
      if (!loginOptions) {
        res.status(401).json({
          error: 'invalid_credentials',
          message: 'Invalid credentials',
        });
        return;
      }

      // Add request info to login options
      loginOptions.userAgent = req.headers['user-agent'];
      loginOptions.ipAddress = req.ip || req.socket.remoteAddress;

      // Generate tokens
      const result = await authServer.login(loginOptions);

      // Set StateProof cookie
      res.cookie(defaultCookieOptions.name!, result.stateProof, {
        httpOnly: true,
        secure: defaultCookieOptions.secure,
        sameSite: defaultCookieOptions.sameSite,
        path: defaultCookieOptions.path,
        maxAge: (authServer['config'].stateProofLifetime ?? 604800) * 1000,
      });

      // Return BearerPass
      res.json({
        bearerPass: result.bearerPass,
        expiresAt: result.expiresAt,
        sessionId: result.sessionId,
      });

    } catch (error) {
      if (error instanceof JTSError) {
        res.status(error.httpStatus).json(error.toJSON());
      } else {
        res.status(500).json({
          error: 'server_error',
          message: 'Login failed',
        });
      }
    }
  };

  // ==========================================================================
  // RENEWAL ENDPOINT
  // ==========================================================================

  const renewHandler: RequestHandler = async (req, res) => {
    try {
      // CSRF check
      if (!validateCSRF(req)) {
        res.status(403).json({
          error: 'csrf_invalid',
          message: 'Invalid CSRF token',
        });
        return;
      }

      // Get StateProof from cookie or header
      const stateProof = req.cookies?.[defaultCookieOptions.name!] 
        || req.headers['x-jts-stateproof'] as string;

      if (!stateProof) {
        res.status(401).json(new JTSError('JTS-401-03', 'StateProof not provided').toJSON());
        return;
      }

      const renewOptions: RenewOptions = {
        stateProof,
        deviceFingerprint: req.headers['x-jts-device-fingerprint'] as string,
      };

      // Renew tokens
      const result = await authServer.renew(renewOptions);

      // Set new StateProof cookie if rotated
      if (result.stateProof) {
        res.cookie(defaultCookieOptions.name!, result.stateProof, {
          httpOnly: true,
          secure: defaultCookieOptions.secure,
          sameSite: defaultCookieOptions.sameSite,
          path: defaultCookieOptions.path,
          maxAge: (authServer['config'].stateProofLifetime ?? 604800) * 1000,
        });
      }

      // Return new BearerPass
      res.json({
        bearerPass: result.bearerPass,
        expiresAt: result.expiresAt,
      });

    } catch (error) {
      if (error instanceof JTSError) {
        // Clear cookie on session errors
        if (error.errorCode === 'JTS-401-05' || error.errorCode === 'JTS-401-04') {
          res.clearCookie(defaultCookieOptions.name!, {
            path: defaultCookieOptions.path,
          });
        }
        res.status(error.httpStatus).json(error.toJSON());
      } else {
        res.status(500).json({
          error: 'server_error',
          message: 'Renewal failed',
        });
      }
    }
  };

  // ==========================================================================
  // LOGOUT ENDPOINT
  // ==========================================================================

  const logoutHandler: RequestHandler = async (req, res) => {
    try {
      // CSRF check
      if (!validateCSRF(req)) {
        res.status(403).json({
          error: 'csrf_invalid',
          message: 'Invalid CSRF token',
        });
        return;
      }

      // Get StateProof from cookie or header
      const stateProof = req.cookies?.[defaultCookieOptions.name!] 
        || req.headers['x-jts-stateproof'] as string;

      if (stateProof) {
        await authServer.logout(stateProof);
      }

      // Clear cookie
      res.clearCookie(defaultCookieOptions.name!, {
        path: defaultCookieOptions.path,
      });

      res.json({ success: true });

    } catch (error) {
      // Clear cookie anyway
      res.clearCookie(defaultCookieOptions.name!, {
        path: defaultCookieOptions.path,
      });
      
      res.json({ success: true });
    }
  };

  // ==========================================================================
  // SESSIONS ENDPOINT
  // ==========================================================================

  const sessionsHandler: RequestHandler = async (req, res) => {
    try {
      if (!req.jts) {
        res.status(401).json(new JTSError('JTS-401-03', 'Authentication required').toJSON());
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
      res.status(500).json({
        error: 'server_error',
        message: 'Failed to fetch sessions',
      });
    }
  };

  // ==========================================================================
  // REVOKE SESSION ENDPOINT
  // ==========================================================================

  const revokeSessionHandler: RequestHandler = async (req, res) => {
    try {
      if (!req.jts) {
        res.status(401).json(new JTSError('JTS-401-03', 'Authentication required').toJSON());
        return;
      }

      const { aid } = req.params;
      
      // Verify the session belongs to the user
      const session = await authServer.getSession(aid);
      if (!session || session.prn !== req.jts.payload.prn) {
        res.status(404).json({
          error: 'session_not_found',
          message: 'Session not found',
        });
        return;
      }

      await authServer.revokeSession(aid);

      res.json({ success: true });

    } catch (error) {
      res.status(500).json({
        error: 'server_error',
        message: 'Failed to revoke session',
      });
    }
  };

  // ==========================================================================
  // JWKS ENDPOINT
  // ==========================================================================

  const jwksHandler: RequestHandler = (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=3600, stale-while-revalidate=60');
    res.json(authServer.getJWKS());
  };

  // ==========================================================================
  // CONFIGURATION ENDPOINT
  // ==========================================================================

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

// ============================================================================
// EXPRESS ROUTER HELPER
// ============================================================================

/**
 * Mount all JTS routes on an Express app
 */
export function mountJTSRoutes(
  app: { post: Function; get: Function; delete: Function },
  options: JTSRoutesOptions & { 
    resourceServer: JTSResourceServer;
    basePath?: string;
  }
): void {
  const { basePath = '/jts', resourceServer, ...routeOptions } = options;
  const routes = createJTSRoutes(routeOptions);

  // Public endpoints
  app.post(`${basePath}/login`, routes.loginHandler);
  app.post(`${basePath}/renew`, routes.renewHandler);
  app.post(`${basePath}/logout`, routes.logoutHandler);

  // Authenticated endpoints
  const authMiddleware = jtsAuth({ resourceServer });
  app.get(`${basePath}/sessions`, authMiddleware, routes.sessionsHandler);
  app.delete(`${basePath}/sessions/:aid`, authMiddleware, routes.revokeSessionHandler);

  // Well-known endpoints
  app.get('/.well-known/jts-jwks', routes.jwksHandler);
  app.get('/.well-known/jts-configuration', routes.configHandler);
}
