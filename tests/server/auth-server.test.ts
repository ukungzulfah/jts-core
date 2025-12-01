/**
 * @engjts/auth - Auth Server Tests
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { JTSAuthServer } from '../../src/server/auth-server';
import { InMemorySessionStore } from '../../src/stores/memory-store';
import { generateECKeyPair } from '../../src/crypto';
import { decodeBearerPass } from '../../src/tokens/bearer-pass';
import type { JTSKeyPair } from '../../src/types';
import { JTS_PROFILES } from '../../src/types';

describe('JTSAuthServer', () => {
  let signingKey: JTSKeyPair;
  let encryptionKey: JTSKeyPair;
  let authServer: JTSAuthServer;
  let sessionStore: InMemorySessionStore;

  beforeAll(async () => {
    signingKey = await generateECKeyPair('auth-key', 'ES256');
    encryptionKey = await generateECKeyPair('enc-key', 'ES256');
  }, 5000);

  beforeEach(() => {
    sessionStore = new InMemorySessionStore();
    authServer = new JTSAuthServer({
      profile: JTS_PROFILES.STANDARD,
      signingKey,
      bearerPassLifetime: 300,
      stateProofLifetime: 3600,
      sessionStore,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('constructor', () => {
    it('should create server with config', () => {
      expect(authServer.getProfile()).toBe(JTS_PROFILES.STANDARD);
    });

    it('should support JTS-L profile', () => {
      const server = new JTSAuthServer({ profile: JTS_PROFILES.LITE, signingKey });
      expect(server.getProfile()).toBe(JTS_PROFILES.LITE);
    });

    it('should support JTS-C profile', () => {
      const server = new JTSAuthServer({ profile: JTS_PROFILES.CONFIDENTIAL, signingKey, encryptionKey });
      expect(server.getProfile()).toBe(JTS_PROFILES.CONFIDENTIAL);
    });
  });

  describe('login', () => {
    it('should generate tokens', async () => {
      const result = await authServer.login({ prn: 'user123' });
      expect(result.bearerPass).toBeDefined();
      expect(result.stateProof).toBeDefined();
      expect(result.sessionId).toBeDefined();
    });

    it('should include prn in token', async () => {
      const result = await authServer.login({ prn: 'user123' });
      const decoded = decodeBearerPass(result.bearerPass);
      expect(decoded.payload.prn).toBe('user123');
    });

    it('should include permissions', async () => {
      const result = await authServer.login({ prn: 'user123', permissions: ['read', 'write'] });
      const decoded = decodeBearerPass(result.bearerPass);
      expect(decoded.payload.perm).toEqual(['read', 'write']);
    });

    it('should include audience', async () => {
      const result = await authServer.login({ prn: 'user123', audience: 'api.example.com' });
      const decoded = decodeBearerPass(result.bearerPass);
      expect(decoded.payload.aud).toBe('api.example.com');
    });
  });

  describe('renew', () => {
    it('should renew with valid stateProof', async () => {
      const login = await authServer.login({ prn: 'user123' });
      const renewed = await authServer.renew({ stateProof: login.stateProof });
      expect(renewed.bearerPass).toBeDefined();
    });

    it('should reject invalid stateProof', async () => {
      await expect(authServer.renew({ stateProof: 'sp_invalid' })).rejects.toThrow();
    });
  });

  describe('logout', () => {
    it('should invalidate session', async () => {
      const login = await authServer.login({ prn: 'user123' });
      const success = await authServer.logout(login.stateProof);
      expect(success).toBe(true);
    });

    it('should return false for invalid stateProof', async () => {
      const success = await authServer.logout('sp_invalid');
      expect(success).toBe(false);
    });
  });

  describe('getJWKS', () => {
    it('should return JWKS', () => {
      const jwks = authServer.getJWKS();
      expect(jwks.keys).toBeDefined();
      expect(jwks.keys.length).toBeGreaterThan(0);
    });
  });

  describe('JTS-C profile', () => {
    it('should create encrypted tokens', async () => {
      // JTS-C needs RSA key for encryption (RSA-OAEP)
      const { generateRSAKeyPair } = await import('../../src/crypto');
      const rsaEncKey = await generateRSAKeyPair('rsa-enc', 'RS256');
      
      const server = new JTSAuthServer({ profile: JTS_PROFILES.CONFIDENTIAL, signingKey, encryptionKey: rsaEncKey });
      const result = await server.login({ prn: 'user123' });
      expect(result.bearerPass.split('.').length).toBe(5);
    });
  });
});
