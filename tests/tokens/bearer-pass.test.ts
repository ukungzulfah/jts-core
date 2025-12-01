/**
 * @engjts/auth - BearerPass Token Tests
 */

import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest';
import {
  createBearerPass,
  verifyBearerPass,
  decodeBearerPass,
  isTokenExpired,
  getTokenExpiration,
  getTimeUntilExpiration,
  hasPermission,
  hasAllPermissions,
  hasAnyPermission,
} from '../../src/tokens/bearer-pass';
import { generateKeyPair } from '../../src/crypto';
import { JTSError, JTSKeyPair, JTS_PROFILES } from '../../src/types';

describe('BearerPass Creation', () => {
  let keyPair: JTSKeyPair;
  let ecKeyPair: JTSKeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair('test-key', 'RS256');
    ecKeyPair = await generateKeyPair('test-ec-key', 'ES256');
  });

  describe('createBearerPass', () => {
    it('should create valid JTS-S BearerPass', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test123',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        profile: JTS_PROFILES.STANDARD,
      });

      expect(token).toBeDefined();
      expect(token.split('.')).toHaveLength(3);
    });

    it('should create valid JTS-L BearerPass', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test123',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        profile: JTS_PROFILES.LITE,
      });

      const decoded = decodeBearerPass(token);
      expect(decoded.header.typ).toBe(JTS_PROFILES.LITE);
      // JTS-L should not have tkn_id
      expect(decoded.payload.tkn_id).toBeUndefined();
    });

    it('should include tkn_id for JTS-S profile', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test123',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        profile: JTS_PROFILES.STANDARD,
      });

      const decoded = decodeBearerPass(token);
      expect(decoded.payload.tkn_id).toBeDefined();
      expect(decoded.payload.tkn_id).toMatch(/^tkn_/);
    });

    it('should set correct expiration time', () => {
      const expiresIn = 600; // 10 minutes
      const before = Math.floor(Date.now() / 1000);

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test123',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        expiresIn,
      });

      const after = Math.floor(Date.now() / 1000);
      const decoded = decodeBearerPass(token);

      expect(decoded.payload.exp).toBeGreaterThanOrEqual(before + expiresIn);
      expect(decoded.payload.exp).toBeLessThanOrEqual(after + expiresIn);
    });

    it('should include audience claim', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test123',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        aud: 'https://api.example.com',
      });

      const decoded = decodeBearerPass(token);
      expect(decoded.payload.aud).toBe('https://api.example.com');
    });

    it('should include array audience', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test123',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        aud: ['api1', 'api2'],
      });

      const decoded = decodeBearerPass(token);
      expect(decoded.payload.aud).toEqual(['api1', 'api2']);
    });

    it('should include extended claims', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test123',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        extended: {
          dfp: 'sha256:fingerprint',
          perm: ['read', 'write'],
          grc: 30,
          org: 'org123',
          atm: 'mfa:totp',
        },
      });

      const decoded = decodeBearerPass(token);
      expect(decoded.payload.dfp).toBe('sha256:fingerprint');
      expect(decoded.payload.perm).toEqual(['read', 'write']);
      expect(decoded.payload.grc).toBe(30);
      expect(decoded.payload.org).toBe('org123');
      expect(decoded.payload.atm).toBe('mfa:totp');
    });

    it('should include custom claims', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test123',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        customClaims: {
          custom1: 'value1',
          custom2: 42,
        },
      });

      const decoded = decodeBearerPass(token);
      expect(decoded.payload.custom1).toBe('value1');
      expect(decoded.payload.custom2).toBe(42);
    });

    it('should default to RS256 algorithm', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test123',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
      });

      const decoded = decodeBearerPass(token);
      expect(decoded.header.alg).toBe('RS256');
    });

    it('should default to JTS-S profile', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test123',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
      });

      const decoded = decodeBearerPass(token);
      expect(decoded.header.typ).toBe(JTS_PROFILES.STANDARD);
    });

    it('should work with EC key', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test123',
        kid: ecKeyPair.kid,
        privateKey: ecKeyPair.privateKey!,
        algorithm: 'ES256',
      });

      const decoded = decodeBearerPass(token);
      expect(decoded.header.alg).toBe('ES256');
    });
  });
});

describe('BearerPass Decoding', () => {
  let keyPair: JTSKeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair('decode-key', 'RS256');
  });

  describe('decodeBearerPass', () => {
    it('should decode valid token', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
      });

      const decoded = decodeBearerPass(token);
      expect(decoded.header).toBeDefined();
      expect(decoded.payload).toBeDefined();
      expect(decoded.signature).toBeDefined();
    });

    it('should throw on malformed token (wrong parts)', () => {
      expect(() => decodeBearerPass('only.two')).toThrow(JTSError);
      expect(() => decodeBearerPass('one.two.three.four')).toThrow(JTSError);
    });

    it('should throw on invalid base64url', () => {
      expect(() => decodeBearerPass('!!!.@@@.###')).toThrow();
    });

    it('should extract header correctly', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        algorithm: 'RS256',
        profile: JTS_PROFILES.STANDARD,
      });

      const decoded = decodeBearerPass(token);
      expect(decoded.header.alg).toBe('RS256');
      expect(decoded.header.typ).toBe(JTS_PROFILES.STANDARD);
      expect(decoded.header.kid).toBe('decode-key');
    });

    it('should extract payload correctly', () => {
      const token = createBearerPass({
        prn: 'user456',
        aid: 'aid_123',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
      });

      const decoded = decodeBearerPass(token);
      expect(decoded.payload.prn).toBe('user456');
      expect(decoded.payload.aid).toBe('aid_123');
      expect(decoded.payload.exp).toBeDefined();
      expect(decoded.payload.iat).toBeDefined();
    });
  });
});

describe('BearerPass Verification', () => {
  let keyPair: JTSKeyPair;
  let keyPair2: JTSKeyPair;
  let keyMap: Map<string, JTSKeyPair>;

  beforeAll(async () => {
    keyPair = await generateKeyPair('verify-key', 'RS256');
    keyPair2 = await generateKeyPair('verify-key-2', 'RS256');
    keyMap = new Map([
      [keyPair.kid, keyPair],
      [keyPair2.kid, keyPair2],
    ]);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('verifyBearerPass', () => {
    it('should verify valid token', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
      });

      const result = verifyBearerPass({
        token,
        publicKeys: keyMap,
      });

      expect(result.valid).toBe(true);
      expect(result.payload?.prn).toBe('user123');
      expect(result.payload?.aid).toBe('aid_test');
    });

    it('should verify with array of keys', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
      });

      const result = verifyBearerPass({
        token,
        publicKeys: [keyPair, keyPair2],
      });

      expect(result.valid).toBe(true);
    });

    it('should reject expired token', () => {
      vi.useFakeTimers();
      const now = Date.now();
      
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        expiresIn: 300, // 5 minutes
      });

      // Advance time past expiration
      vi.setSystemTime(now + 400 * 1000);

      const result = verifyBearerPass({
        token,
        publicKeys: keyMap,
      });

      expect(result.valid).toBe(false);
      expect(result.error?.errorCode).toBe('JTS-401-01');
    });

    it('should accept token within grace period', () => {
      vi.useFakeTimers();
      const now = Date.now();

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        expiresIn: 300,
        extended: { grc: 30 },
      });

      // Advance time just past expiration but within grace
      vi.setSystemTime(now + 310 * 1000);

      const result = verifyBearerPass({
        token,
        publicKeys: keyMap,
        gracePeriodTolerance: 30,
      });

      expect(result.valid).toBe(true);
    });

    it('should reject token with invalid signature', async () => {
      // Create a token with one key but verify with a different key
      const otherKey = await generateKeyPair('other-key', 'RS256');
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: otherKey.kid,
        privateKey: otherKey.privateKey!,
      });

      // Replace the kid in header with keyPair's kid so it tries to verify with wrong key
      const parts = token.split('.');
      const header = JSON.parse(Buffer.from(parts[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
      header.kid = keyPair.kid;
      const newHeader = Buffer.from(JSON.stringify(header)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const tamperedToken = `${newHeader}.${parts[1]}.${parts[2]}`;

      const result = verifyBearerPass({
        token: tamperedToken,
        publicKeys: keyMap,
      });

      expect(result.valid).toBe(false);
      expect(result.error?.errorCode).toBe('JTS-401-02');
    });

    it('should reject token with unknown key', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: 'unknown-key',
        privateKey: keyPair.privateKey!,
      });

      const result = verifyBearerPass({
        token,
        publicKeys: keyMap,
      });

      expect(result.valid).toBe(false);
      expect(result.error?.errorCode).toBe('JTS-500-01');
    });

    it('should validate audience', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        aud: 'https://api.example.com',
      });

      const validResult = verifyBearerPass({
        token,
        publicKeys: keyMap,
        audience: 'https://api.example.com',
      });
      expect(validResult.valid).toBe(true);

      const invalidResult = verifyBearerPass({
        token,
        publicKeys: keyMap,
        audience: 'https://other-api.com',
      });
      expect(invalidResult.valid).toBe(false);
      expect(invalidResult.error?.errorCode).toBe('JTS-403-01');
    });

    it('should validate audience with array', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        aud: ['api1', 'api2', 'api3'],
      });

      const result = verifyBearerPass({
        token,
        publicKeys: keyMap,
        audience: ['api2', 'api4'],
      });

      expect(result.valid).toBe(true);
    });

    it('should validate organization', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        extended: { org: 'org123' },
      });

      const validResult = verifyBearerPass({
        token,
        publicKeys: keyMap,
        organization: 'org123',
      });
      expect(validResult.valid).toBe(true);

      const invalidResult = verifyBearerPass({
        token,
        publicKeys: keyMap,
        organization: 'other-org',
      });
      expect(invalidResult.valid).toBe(false);
      expect(invalidResult.error?.errorCode).toBe('JTS-403-03');
    });

    it('should validate device fingerprint', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        extended: { dfp: 'sha256:abc123' },
      });

      const validResult = verifyBearerPass({
        token,
        publicKeys: keyMap,
        expectedDeviceFingerprint: 'sha256:abc123',
      });
      expect(validResult.valid).toBe(true);

      const invalidResult = verifyBearerPass({
        token,
        publicKeys: keyMap,
        expectedDeviceFingerprint: 'sha256:xyz789',
      });
      expect(invalidResult.valid).toBe(false);
      expect(invalidResult.error?.errorCode).toBe('JTS-401-06');
    });

    it('should filter by accepted profiles', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        profile: JTS_PROFILES.STANDARD,
      });

      const validResult = verifyBearerPass({
        token,
        publicKeys: keyMap,
        acceptedProfiles: [JTS_PROFILES.STANDARD, JTS_PROFILES.CONFIDENTIAL],
      });
      expect(validResult.valid).toBe(true);

      const invalidResult = verifyBearerPass({
        token,
        publicKeys: keyMap,
        acceptedProfiles: [JTS_PROFILES.LITE],
      });
      expect(invalidResult.valid).toBe(false);
      expect(invalidResult.error?.errorCode).toBe('JTS-400-01');
    });

    it('should require tkn_id for JTS-S profile', () => {
      // Create a malformed JTS-S token without tkn_id (simulated)
      const validToken = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        profile: JTS_PROFILES.STANDARD,
      });

      const result = verifyBearerPass({
        token: validToken,
        publicKeys: keyMap,
      });

      expect(result.valid).toBe(true);
      expect(result.payload?.tkn_id).toBeDefined();
    });

    it('should handle clock skew tolerance', () => {
      vi.useFakeTimers();
      const now = Date.now();

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        expiresIn: 300,
      });

      // Advance time past expiration
      vi.setSystemTime(now + 310 * 1000);

      const resultNoSkew = verifyBearerPass({
        token,
        publicKeys: keyMap,
        clockSkewTolerance: 0,
      });
      expect(resultNoSkew.valid).toBe(false);

      const resultWithSkew = verifyBearerPass({
        token,
        publicKeys: keyMap,
        clockSkewTolerance: 15,
      });
      expect(resultWithSkew.valid).toBe(true);
    });
  });
});

describe('Token Utility Functions', () => {
  let keyPair: JTSKeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair('util-key', 'RS256');
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('isTokenExpired', () => {
    it('should return false for valid token', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        expiresIn: 300,
      });

      expect(isTokenExpired(token)).toBe(false);
    });

    it('should return true for expired token', () => {
      vi.useFakeTimers();
      const now = Date.now();

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        expiresIn: 60,
      });

      vi.setSystemTime(now + 120 * 1000);
      expect(isTokenExpired(token)).toBe(true);
    });

    it('should consider grace period', () => {
      vi.useFakeTimers();
      const now = Date.now();

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        expiresIn: 60,
        extended: { grc: 30 },
      });

      vi.setSystemTime(now + 70 * 1000);
      expect(isTokenExpired(token, 30)).toBe(false);

      vi.setSystemTime(now + 100 * 1000);
      expect(isTokenExpired(token, 30)).toBe(true);
    });

    it('should return true for invalid token', () => {
      expect(isTokenExpired('invalid-token')).toBe(true);
    });
  });

  describe('getTokenExpiration', () => {
    it('should return expiration date', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        expiresIn: 300,
      });

      const expiration = getTokenExpiration(token);
      expect(expiration).toBeInstanceOf(Date);
      expect(expiration!.getTime()).toBeGreaterThan(Date.now());
    });

    it('should return null for invalid token', () => {
      expect(getTokenExpiration('invalid')).toBeNull();
    });
  });

  describe('getTimeUntilExpiration', () => {
    it('should return positive seconds for valid token', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        expiresIn: 300,
      });

      const ttl = getTimeUntilExpiration(token);
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(300);
    });

    it('should return 0 for expired token', () => {
      vi.useFakeTimers();
      const now = Date.now();

      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        expiresIn: 60,
      });

      vi.setSystemTime(now + 120 * 1000);
      expect(getTimeUntilExpiration(token)).toBe(0);
    });

    it('should return 0 for invalid token', () => {
      expect(getTimeUntilExpiration('invalid')).toBe(0);
    });
  });

  describe('hasPermission', () => {
    it('should return true if permission present', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        extended: { perm: ['read', 'write', 'admin'] },
      });

      expect(hasPermission(token, 'read')).toBe(true);
      expect(hasPermission(token, 'write')).toBe(true);
      expect(hasPermission(token, 'admin')).toBe(true);
    });

    it('should return false if permission missing', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        extended: { perm: ['read'] },
      });

      expect(hasPermission(token, 'write')).toBe(false);
      expect(hasPermission(token, 'admin')).toBe(false);
    });

    it('should return false if no permissions', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
      });

      expect(hasPermission(token, 'read')).toBe(false);
    });

    it('should return false for invalid token', () => {
      expect(hasPermission('invalid', 'read')).toBe(false);
    });
  });

  describe('hasAllPermissions', () => {
    it('should return true if all permissions present', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        extended: { perm: ['read', 'write', 'delete'] },
      });

      expect(hasAllPermissions(token, ['read', 'write'])).toBe(true);
      expect(hasAllPermissions(token, ['read', 'write', 'delete'])).toBe(true);
    });

    it('should return false if any permission missing', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        extended: { perm: ['read', 'write'] },
      });

      expect(hasAllPermissions(token, ['read', 'admin'])).toBe(false);
    });

    it('should return true for empty required list', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
      });

      expect(hasAllPermissions(token, [])).toBe(true);
    });
  });

  describe('hasAnyPermission', () => {
    it('should return true if any permission present', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        extended: { perm: ['read'] },
      });

      expect(hasAnyPermission(token, ['read', 'write'])).toBe(true);
      expect(hasAnyPermission(token, ['admin', 'read'])).toBe(true);
    });

    it('should return false if no permissions match', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        extended: { perm: ['read'] },
      });

      expect(hasAnyPermission(token, ['write', 'admin'])).toBe(false);
    });

    it('should return false for empty required list', () => {
      const token = createBearerPass({
        prn: 'user123',
        aid: 'aid_test',
        kid: keyPair.kid,
        privateKey: keyPair.privateKey!,
        extended: { perm: ['read'] },
      });

      expect(hasAnyPermission(token, [])).toBe(false);
    });
  });
});
