/**
 * @engjts/auth - Express Middleware Tests
 */

import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import {
  jtsAuth,
  jtsOptionalAuth,
  jtsRequirePermissions,
  createJTSRoutes,
} from '../../src/middleware/express';
import { JTSResourceServer } from '../../src/server/resource-server';
import { JTSAuthServer } from '../../src/server/auth-server';
import { createBearerPass } from '../../src/tokens/bearer-pass';
import { generateKeyPair } from '../../src/crypto';
import { JTSKeyPair } from '../../src/types';

// Mock Express request/response
function createMockRequest(options: {
  headers?: Record<string, string>;
  body?: Record<string, unknown>;
  cookies?: Record<string, string>;
  params?: Record<string, string>;
  ip?: string;
  protocol?: string;
}): Request {
  const headers = options.headers || {};
  return {
    headers,
    body: options.body || {},
    cookies: options.cookies || {},
    params: options.params || {},
    ip: options.ip || '127.0.0.1',
    protocol: options.protocol || 'https',
    socket: { remoteAddress: options.ip || '127.0.0.1' },
    get: (name: string) => headers[name.toLowerCase()],
  } as unknown as Request;
}

interface MockResponse extends Response {
  statusCode: number;
  data: unknown;
  cookieData: Record<string, { value: string; options: any }>;
}

function createMockResponse(): MockResponse {
  const res = {
    statusCode: 200,
    data: undefined as unknown,
    cookieData: {} as Record<string, { value: string; options: any }>,
  } as MockResponse;

  res.status = vi.fn((code: number) => {
    res.statusCode = code;
    return res;
  }) as any;

  res.json = vi.fn((data: unknown) => {
    res.data = data;
    return res;
  }) as any;

  res.cookie = vi.fn((name: string, value: string, options?: any) => {
    res.cookieData[name] = { value, options };
    return res;
  }) as any;

  res.clearCookie = vi.fn((name: string, options?: any) => {
    delete res.cookieData[name];
    return res;
  }) as any;

  res.setHeader = vi.fn(() => res) as any;

  return res;
}

describe('Express Middleware', () => {
  let signingKey: JTSKeyPair;
  let resourceServer: JTSResourceServer;

  beforeAll(async () => {
    signingKey = await generateKeyPair('middleware-key', 'RS256');
    resourceServer = new JTSResourceServer({
      publicKeys: [signingKey],
    });
  });

  describe('jtsAuth', () => {
    it('should authenticate valid token', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
      });

      const middleware = jtsAuth({ resourceServer });

      const req = createMockRequest({
        headers: { authorization: `Bearer ${token}` },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.jts).toBeDefined();
      expect(req.jts?.payload.prn).toBe('user123');
    });

    it('should reject request without token', async () => {
      const middleware = jtsAuth({ resourceServer });

      const req = createMockRequest({});
      const res = createMockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
    });

    it('should reject invalid token', async () => {
      const middleware = jtsAuth({ resourceServer });

      const req = createMockRequest({
        headers: { authorization: 'Bearer invalid-token' },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalled();
    });

    it('should reject malformed authorization header', async () => {
      const middleware = jtsAuth({ resourceServer });

      const req = createMockRequest({
        headers: { authorization: 'Basic sometoken' },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
    });

    it('should use custom token extractor', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
      });

      const middleware = jtsAuth({
        resourceServer,
        extractToken: (req) => req.headers['x-custom-token'] as string,
      });

      const req = createMockRequest({
        headers: { 'x-custom-token': token },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.jts?.payload.prn).toBe('user123');
    });

    it('should use custom error handler', async () => {
      const customErrorHandler = vi.fn();
      const middleware = jtsAuth({
        resourceServer,
        onError: customErrorHandler,
      });

      const req = createMockRequest({});
      const res = createMockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(customErrorHandler).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('jtsOptionalAuth', () => {
    it('should authenticate valid token', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
      });

      const middleware = jtsOptionalAuth({ resourceServer });

      const req = createMockRequest({
        headers: { authorization: `Bearer ${token}` },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.jts?.payload.prn).toBe('user123');
    });

    it('should continue without token', async () => {
      const middleware = jtsOptionalAuth({ resourceServer });

      const req = createMockRequest({});
      const res = createMockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.jts).toBeUndefined();
    });

    it('should continue with invalid token', async () => {
      const middleware = jtsOptionalAuth({ resourceServer });

      const req = createMockRequest({
        headers: { authorization: 'Bearer invalid-token' },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.jts).toBeUndefined();
    });
  });

  describe('jtsRequirePermissions', () => {
    it('should allow request with required permissions', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        extended: { perm: ['read', 'write'] },
      });

      const authMiddleware = jtsAuth({ resourceServer });
      const permMiddleware = jtsRequirePermissions({ required: ['read'] });

      const req = createMockRequest({
        headers: { authorization: `Bearer ${token}` },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await authMiddleware(req, res, next);
      next.mockClear();

      await permMiddleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should reject request missing required permissions', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        extended: { perm: ['read'] },
      });

      const authMiddleware = jtsAuth({ resourceServer });
      const permMiddleware = jtsRequirePermissions({ required: ['admin'] });

      const req = createMockRequest({
        headers: { authorization: `Bearer ${token}` },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await authMiddleware(req, res, next);
      next.mockClear();

      await permMiddleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it('should allow request with any of the permissions', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        extended: { perm: ['read'] },
      });

      const authMiddleware = jtsAuth({ resourceServer });
      const permMiddleware = jtsRequirePermissions({ any: ['read', 'admin'] });

      const req = createMockRequest({
        headers: { authorization: `Bearer ${token}` },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await authMiddleware(req, res, next);
      next.mockClear();

      await permMiddleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should reject request without any of the permissions', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        extended: { perm: ['read'] },
      });

      const authMiddleware = jtsAuth({ resourceServer });
      const permMiddleware = jtsRequirePermissions({ any: ['admin', 'superuser'] });

      const req = createMockRequest({
        headers: { authorization: `Bearer ${token}` },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await authMiddleware(req, res, next);
      next.mockClear();

      await permMiddleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it('should use custom check function', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
      });

      const authMiddleware = jtsAuth({ resourceServer });
      const permMiddleware = jtsRequirePermissions({
        check: (payload) => payload.prn === 'user123',
      });

      const req = createMockRequest({
        headers: { authorization: `Bearer ${token}` },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await authMiddleware(req, res, next);
      next.mockClear();

      await permMiddleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should reject without auth context', async () => {
      const permMiddleware = jtsRequirePermissions({ required: ['read'] });

      const req = createMockRequest({});
      const res = createMockResponse();
      const next = vi.fn();

      await permMiddleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
    });
  });

  describe('createJTSRoutes', () => {
    let authServer: JTSAuthServer;

    beforeEach(async () => {
      authServer = new JTSAuthServer({
        profile: 'JTS-S/v1',
        signingKey,
        bearerPassLifetime: 300,
        stateProofLifetime: 3600,
      });
    });

    it('should create login handler', async () => {
      const routes = createJTSRoutes({
        authServer,
        validateCredentials: async (req) => ({
          prn: (req.body as any).username,
        }),
      });

      const req = createMockRequest({
        body: { username: 'user123', password: 'secret' },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await routes.loginHandler(req, res, next);

      expect(res.data).toHaveProperty('bearerPass');
      expect(res.data).toHaveProperty('expiresAt');
      expect(res.cookieData.jts_state_proof).toBeDefined();
    });

    it('should reject invalid credentials', async () => {
      const routes = createJTSRoutes({
        authServer,
        validateCredentials: async () => null,
      });

      const req = createMockRequest({
        body: { username: 'invalid', password: 'wrong' },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await routes.loginHandler(req, res, next);

      expect(res.statusCode).toBe(401);
      expect((res.data as any).error).toBe('invalid_credentials');
    });

    it('should create renew handler', async () => {
      const routes = createJTSRoutes({
        authServer,
        validateCredentials: async (req) => ({
          prn: (req.body as any).username,
        }),
      });

      // First login
      const loginReq = createMockRequest({
        body: { username: 'user123' },
      });
      const loginRes = createMockResponse();
      await routes.loginHandler(loginReq, loginRes, vi.fn());

      const stateProof = loginRes.cookieData.jts_state_proof?.value;

      // Renew
      const renewReq = createMockRequest({
        cookies: { jts_state_proof: stateProof },
        headers: { 'x-jts-request': '1' },
      });
      const renewRes = createMockResponse();

      await routes.renewHandler(renewReq, renewRes, vi.fn());

      expect(renewRes.data).toHaveProperty('bearerPass');
    });

    it('should reject renewal without CSRF token', async () => {
      const routes = createJTSRoutes({
        authServer,
        validateCredentials: async () => ({ prn: 'user123' }),
      });

      const req = createMockRequest({
        cookies: { jts_state_proof: 'sp_test' },
        // Missing X-JTS-Request header
      });
      const res = createMockResponse();

      await routes.renewHandler(req, res, vi.fn());

      expect(res.statusCode).toBe(403);
      expect((res.data as any).error).toBe('csrf_invalid');
    });

    it('should create logout handler', async () => {
      const routes = createJTSRoutes({
        authServer,
        validateCredentials: async () => ({ prn: 'user123' }),
      });

      // Login first
      const loginReq = createMockRequest({
        body: { username: 'user123' },
      });
      const loginRes = createMockResponse();
      await routes.loginHandler(loginReq, loginRes, vi.fn());

      const stateProof = loginRes.cookieData.jts_state_proof?.value;

      // Logout
      const logoutReq = createMockRequest({
        cookies: { jts_state_proof: stateProof },
        headers: { 'x-jts-request': '1' },
      });
      const logoutRes = createMockResponse();

      await routes.logoutHandler(logoutReq, logoutRes, vi.fn());

      expect(logoutRes.data).toEqual({ success: true });
    });

    it('should create JWKS handler', () => {
      const routes = createJTSRoutes({
        authServer,
        validateCredentials: async () => ({ prn: 'user123' }),
      });

      const req = createMockRequest({});
      const res = createMockResponse();

      routes.jwksHandler(req, res, vi.fn());

      expect(res.data).toHaveProperty('keys');
      expect((res.data as any).keys).toHaveLength(1);
    });

    it('should create config handler', () => {
      const routes = createJTSRoutes({
        authServer,
        validateCredentials: async () => ({ prn: 'user123' }),
      });

      const req = createMockRequest({
        protocol: 'https',
        headers: { host: 'auth.example.com' },
      });
      const res = createMockResponse();

      routes.configHandler(req, res, vi.fn());

      expect(res.data).toHaveProperty('jwks_uri');
      expect(res.data).toHaveProperty('token_endpoint');
    });

    it('should apply rate limiting', async () => {
      const routes = createJTSRoutes({
        authServer,
        validateCredentials: async () => ({ prn: 'user123' }),
        rateLimit: async () => false, // Always reject
      });

      const req = createMockRequest({
        body: { username: 'user123' },
      });
      const res = createMockResponse();

      await routes.loginHandler(req, res, vi.fn());

      expect(res.statusCode).toBe(429);
    });

    it('should use custom CSRF validation', async () => {
      const routes = createJTSRoutes({
        authServer,
        validateCredentials: async () => ({ prn: 'user123' }),
        validateCSRF: (req) => req.headers['x-custom-csrf'] === 'valid',
      });

      // Login first
      const loginReq = createMockRequest({
        body: { username: 'user123' },
      });
      const loginRes = createMockResponse();
      await routes.loginHandler(loginReq, loginRes, vi.fn());

      const stateProof = loginRes.cookieData.jts_state_proof?.value;

      // Renew with custom CSRF
      const renewReq = createMockRequest({
        cookies: { jts_state_proof: stateProof },
        headers: { 'x-custom-csrf': 'valid' },
      });
      const renewRes = createMockResponse();

      await routes.renewHandler(renewReq, renewRes, vi.fn());

      expect(renewRes.data).toHaveProperty('bearerPass');
    });

    it('should use custom cookie options', async () => {
      const routes = createJTSRoutes({
        authServer,
        validateCredentials: async () => ({ prn: 'user123' }),
        cookieOptions: {
          name: 'custom_state',
          path: '/api',
          sameSite: 'lax',
          secure: true,
        },
      });

      const req = createMockRequest({
        body: { username: 'user123' },
      });
      const res = createMockResponse();

      await routes.loginHandler(req, res, vi.fn());

      expect(res.cookieData.custom_state).toBeDefined();
      expect(res.cookieData.custom_state.options.path).toBe('/api');
    });
  });
});
