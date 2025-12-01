/**
 * @engjts/auth - Resource Server Tests
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { JTSResourceServer } from '../../src/server/resource-server';
import { createBearerPass, decodeBearerPass } from '../../src/tokens/bearer-pass';
import { createEncryptedBearerPass } from '../../src/tokens/jwe';
import { generateKeyPair } from '../../src/crypto';
import { JTSKeyPair } from '../../src/types';

describe('JTSResourceServer', () => {
  let signingKey: JTSKeyPair;
  let encryptionKey: JTSKeyPair;
  let resourceServer: JTSResourceServer;

  beforeAll(async () => {
    signingKey = await generateKeyPair('resource-server-key', 'RS256');
    encryptionKey = await generateKeyPair('resource-enc-key', 'RS256');
  });

  beforeEach(() => {
    resourceServer = new JTSResourceServer({
      publicKeys: [signingKey],
      gracePeriodTolerance: 30,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('constructor', () => {
    it('should create server with minimal config', () => {
      const server = new JTSResourceServer({
        publicKeys: [signingKey],
      });
      expect(server).toBeDefined();
    });

    it('should create server with all options', () => {
      const server = new JTSResourceServer({
        acceptedProfiles: ['JTS-S/v1'],
        publicKeys: [signingKey],
        audience: 'https://api.example.com',
        gracePeriodTolerance: 60,
        validateDeviceFingerprint: true,
        jwksCacheTTL: 7200,
        decryptionKey: {
          kid: encryptionKey.kid,
          privateKey: encryptionKey.privateKey!,
        },
      });
      expect(server).toBeDefined();
    });
  });

  describe('verify', () => {
    it('should verify valid token', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
      });

      const result = await resourceServer.verify(token);

      expect(result.valid).toBe(true);
      expect(result.payload?.prn).toBe('user123');
      expect(result.header?.alg).toBe('RS256');
    });

    it('should reject token with unknown key', async () => {
      const otherKey = await generateKeyPair('other-key', 'RS256');
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: otherKey.kid,
        privateKey: otherKey.privateKey!,
      });

      const result = await resourceServer.verify(token);

      expect(result.valid).toBe(false);
      expect(result.error?.errorCode).toBe('JTS-500-01');
    });

    it('should reject expired token', async () => {
      vi.useFakeTimers();
      const now = Date.now();

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        expiresIn: 60,
      });

      vi.setSystemTime(now + 120 * 1000);

      const result = await resourceServer.verify(token);

      expect(result.valid).toBe(false);
      expect(result.error?.errorCode).toBe('JTS-401-01');
    });

    it('should accept token within grace period', async () => {
      vi.useFakeTimers();
      const now = Date.now();

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        expiresIn: 60,
        extended: { grc: 30 },
      });

      vi.setSystemTime(now + 70 * 1000); // Expired but within grace

      const result = await resourceServer.verify(token);

      expect(result.valid).toBe(true);
    });

    it('should validate audience', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        aud: 'https://api.example.com',
      });

      const validResult = await resourceServer.verify(token, {
        audience: 'https://api.example.com',
      });
      expect(validResult.valid).toBe(true);

      const invalidResult = await resourceServer.verify(token, {
        audience: 'https://other-api.com',
      });
      expect(invalidResult.valid).toBe(false);
    });

    it('should validate organization', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        extended: { org: 'org123' },
      });

      const validResult = await resourceServer.verify(token, {
        organization: 'org123',
      });
      expect(validResult.valid).toBe(true);

      const invalidResult = await resourceServer.verify(token, {
        organization: 'other-org',
      });
      expect(invalidResult.valid).toBe(false);
    });

    it('should check required permissions', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        extended: { perm: ['read', 'write'] },
      });

      const validResult = await resourceServer.verify(token, {
        requiredPermissions: ['read'],
      });
      expect(validResult.valid).toBe(true);

      const invalidResult = await resourceServer.verify(token, {
        requiredPermissions: ['admin'],
      });
      expect(invalidResult.valid).toBe(false);
      expect(invalidResult.error?.errorCode).toBe('JTS-403-02');
    });

    it('should check any permissions', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        extended: { perm: ['read'] },
      });

      const validResult = await resourceServer.verify(token, {
        anyPermissions: ['read', 'write'],
      });
      expect(validResult.valid).toBe(true);

      const invalidResult = await resourceServer.verify(token, {
        anyPermissions: ['admin', 'superuser'],
      });
      expect(invalidResult.valid).toBe(false);
    });

    it('should return error when no public keys available', async () => {
      const emptyServer = new JTSResourceServer({
        publicKeys: [],
      });

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
      });

      const result = await emptyServer.verify(token);
      expect(result.valid).toBe(false);
      expect(result.error?.errorCode).toBe('JTS-500-01');
    });
  });

  describe('JTS-C (Encrypted Token) Verification', () => {
    let encryptedServer: JTSResourceServer;

    beforeEach(() => {
      encryptedServer = new JTSResourceServer({
        publicKeys: [signingKey],
        decryptionKey: {
          kid: encryptionKey.kid,
          privateKey: encryptionKey.privateKey!,
        },
      });
    });

    it('should verify encrypted token', async () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      const result = await encryptedServer.verify(token);

      expect(result.valid).toBe(true);
      expect(result.payload?.prn).toBe('user123');
    });

    it('should reject encrypted token without decryption key', async () => {
      const serverWithoutDecryption = new JTSResourceServer({
        publicKeys: [signingKey],
        // No decryption key
      });

      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      const result = await serverWithoutDecryption.verify(token);

      expect(result.valid).toBe(false);
      expect(result.error?.errorCode).toBe('JTS-500-01');
    });

    it('should verify encrypted token permissions', async () => {
      const token = createEncryptedBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        extended: { perm: ['read', 'write'] },
        encryptionKey: {
          kid: encryptionKey.kid,
          publicKey: encryptionKey.publicKey,
        },
      });

      const result = await encryptedServer.verify(token, {
        requiredPermissions: ['read'],
      });

      expect(result.valid).toBe(true);
    });
  });

  describe('isExpired', () => {
    it('should return false for valid token', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        expiresIn: 300,
      });

      expect(resourceServer.isExpired(token)).toBe(false);
    });

    it('should return true for expired token', () => {
      vi.useFakeTimers();
      const now = Date.now();

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        expiresIn: 60,
      });

      vi.setSystemTime(now + 120 * 1000);

      expect(resourceServer.isExpired(token)).toBe(true);
    });
  });

  describe('getTimeUntilExpiry', () => {
    it('should return positive value for valid token', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        expiresIn: 300,
      });

      const ttl = resourceServer.getTimeUntilExpiry(token);
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(300);
    });

    it('should return 0 for expired token', () => {
      vi.useFakeTimers();
      const now = Date.now();

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        expiresIn: 60,
      });

      vi.setSystemTime(now + 120 * 1000);

      expect(resourceServer.getTimeUntilExpiry(token)).toBe(0);
    });
  });

  describe('decode', () => {
    it('should decode valid token', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
      });

      const decoded = resourceServer.decode(token);

      expect(decoded).toBeDefined();
      expect(decoded?.payload.prn).toBe('user123');
      expect(decoded?.header.alg).toBe('RS256');
    });

    it('should return null for invalid token', () => {
      expect(resourceServer.decode('invalid-token')).toBeNull();
    });
  });

  describe('Permission Checking Methods', () => {
    let tokenWithPerms: string;

    beforeEach(() => {
      tokenWithPerms = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        extended: { perm: ['read', 'write', 'delete'] },
      });
    });

    describe('tokenHasPermission', () => {
      it('should return true if permission present', () => {
        expect(resourceServer.tokenHasPermission(tokenWithPerms, 'read')).toBe(true);
        expect(resourceServer.tokenHasPermission(tokenWithPerms, 'write')).toBe(true);
      });

      it('should return false if permission missing', () => {
        expect(resourceServer.tokenHasPermission(tokenWithPerms, 'admin')).toBe(false);
      });
    });

    describe('tokenHasAllPermissions', () => {
      it('should return true if all permissions present', () => {
        expect(resourceServer.tokenHasAllPermissions(tokenWithPerms, ['read', 'write'])).toBe(true);
      });

      it('should return false if any permission missing', () => {
        expect(resourceServer.tokenHasAllPermissions(tokenWithPerms, ['read', 'admin'])).toBe(false);
      });
    });

    describe('tokenHasAnyPermission', () => {
      it('should return true if any permission present', () => {
        expect(resourceServer.tokenHasAnyPermission(tokenWithPerms, ['read', 'admin'])).toBe(true);
      });

      it('should return false if no permission matches', () => {
        expect(resourceServer.tokenHasAnyPermission(tokenWithPerms, ['admin', 'superuser'])).toBe(false);
      });
    });
  });

  describe('Key Management', () => {
    it('should add public key', async () => {
      const newKey = await generateKeyPair('new-key', 'RS256');

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: newKey.kid,
        privateKey: newKey.privateKey!,
      });

      // Should fail before adding key
      const beforeResult = await resourceServer.verify(token);
      expect(beforeResult.valid).toBe(false);

      // Add key
      resourceServer.addPublicKey(newKey);

      // Should succeed after adding key
      const afterResult = await resourceServer.verify(token);
      expect(afterResult.valid).toBe(true);
    });

    it('should remove public key', async () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
      });

      // Should succeed before removing key
      const beforeResult = await resourceServer.verify(token);
      expect(beforeResult.valid).toBe(true);

      // Remove key
      const removed = resourceServer.removePublicKey(signingKey.kid);
      expect(removed).toBe(true);

      // Should fail after removing key
      const afterResult = await resourceServer.verify(token);
      expect(afterResult.valid).toBe(false);
    });
  });

  describe('Profile Filtering', () => {
    it('should accept tokens with accepted profiles', async () => {
      const server = new JTSResourceServer({
        publicKeys: [signingKey],
        acceptedProfiles: ['JTS-S/v1'],
      });

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        profile: 'JTS-S/v1',
      });

      const result = await server.verify(token);
      expect(result.valid).toBe(true);
    });

    it('should reject tokens with non-accepted profiles', async () => {
      const server = new JTSResourceServer({
        publicKeys: [signingKey],
        acceptedProfiles: ['JTS-S/v1'],
      });

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        profile: 'JTS-L/v1',
      });

      const result = await server.verify(token);
      expect(result.valid).toBe(false);
    });
  });

  describe('Default Audience Validation', () => {
    it('should use default audience for validation', async () => {
      const server = new JTSResourceServer({
        publicKeys: [signingKey],
        audience: 'https://api.example.com',
      });

      const validToken = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        aud: 'https://api.example.com',
      });

      const invalidToken = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: signingKey.kid,
        privateKey: signingKey.privateKey!,
        aud: 'https://other-api.com',
      });

      expect((await server.verify(validToken)).valid).toBe(true);
      expect((await server.verify(invalidToken)).valid).toBe(false);
    });
  });
});
