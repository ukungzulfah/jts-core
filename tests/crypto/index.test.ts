/**
 * @engjts/auth - Crypto Utilities Tests
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  base64urlEncode,
  base64urlDecode,
  encodeJSON,
  decodeJSON,
  generateKeyPair,
  generateRSAKeyPair,
  generateECKeyPair,
  sign,
  verify,
  rsaEncrypt,
  rsaDecrypt,
  generateCEK,
  generateIV,
  aesGcmEncrypt,
  aesGcmDecrypt,
  generateRandomString,
  generateTokenId,
  generateAnchorId,
  generateStateProof,
  sha256,
  sha256Hex,
  createDeviceFingerprint,
  pemToJwk,
  jwkToPem,
  keyPairToJwks,
} from '../../src/crypto';
import type { JTSKeyPair, JTSAlgorithm } from '../../src/types';

describe('Base64URL Utilities', () => {
  describe('base64urlEncode', () => {
    it('should encode string to base64url', () => {
      const encoded = base64urlEncode('Hello, World!');
      expect(encoded).toBe('SGVsbG8sIFdvcmxkIQ');
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).not.toContain('=');
    });

    it('should encode buffer to base64url', () => {
      const buffer = Buffer.from('Test Data');
      const encoded = base64urlEncode(buffer);
      expect(encoded).toBe('VGVzdCBEYXRh');
    });

    it('should handle special characters', () => {
      const data = '>>>???';
      const encoded = base64urlEncode(data);
      const decoded = base64urlDecode(encoded).toString('utf8');
      expect(decoded).toBe(data);
    });

    it('should handle empty string', () => {
      const encoded = base64urlEncode('');
      expect(encoded).toBe('');
    });

    it('should handle binary data', () => {
      const binary = Buffer.from([0xff, 0xfe, 0xfd, 0x00, 0x01, 0x02]);
      const encoded = base64urlEncode(binary);
      const decoded = base64urlDecode(encoded);
      expect(decoded).toEqual(binary);
    });
  });

  describe('base64urlDecode', () => {
    it('should decode base64url to buffer', () => {
      const decoded = base64urlDecode('SGVsbG8sIFdvcmxkIQ');
      expect(decoded.toString('utf8')).toBe('Hello, World!');
    });

    it('should handle padding correctly', () => {
      // Different padding scenarios
      const test1 = base64urlDecode('YQ'); // 1 byte -> needs ==
      expect(test1.toString('utf8')).toBe('a');

      const test2 = base64urlDecode('YWI'); // 2 bytes -> needs =
      expect(test2.toString('utf8')).toBe('ab');

      const test3 = base64urlDecode('YWJj'); // 3 bytes -> no padding
      expect(test3.toString('utf8')).toBe('abc');
    });
  });

  describe('encodeJSON / decodeJSON', () => {
    it('should encode and decode JSON objects', () => {
      const obj = { foo: 'bar', num: 42, arr: [1, 2, 3] };
      const encoded = encodeJSON(obj);
      const decoded = decodeJSON(encoded);
      expect(decoded).toEqual(obj);
    });

    it('should handle nested objects', () => {
      const obj = {
        level1: {
          level2: {
            value: 'deep',
          },
        },
      };
      const encoded = encodeJSON(obj);
      const decoded = decodeJSON(encoded);
      expect(decoded).toEqual(obj);
    });

    it('should handle special characters in JSON', () => {
      const obj = { message: 'Hello "World"\nNew Line' };
      const encoded = encodeJSON(obj);
      const decoded = decodeJSON<typeof obj>(encoded);
      expect(decoded).toEqual(obj);
    });
  });
});

describe('Key Generation', () => {
  describe('generateRSAKeyPair', () => {
    it('should generate RSA-256 key pair', async () => {
      const keyPair = await generateRSAKeyPair('test-rsa-256', 'RS256');
      
      expect(keyPair.kid).toBe('test-rsa-256');
      expect(keyPair.algorithm).toBe('RS256');
      expect(keyPair.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(keyPair.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
    });

    it('should generate RSA-384 key pair', async () => {
      const keyPair = await generateRSAKeyPair('test-rsa-384', 'RS384');
      expect(keyPair.algorithm).toBe('RS384');
    });

    it('should generate RSA-512 key pair', async () => {
      const keyPair = await generateRSAKeyPair('test-rsa-512', 'RS512');
      expect(keyPair.algorithm).toBe('RS512');
    });

    it('should generate PSS-256 key pair', async () => {
      const keyPair = await generateRSAKeyPair('test-ps256', 'PS256');
      expect(keyPair.algorithm).toBe('PS256');
    });

    it('should generate with custom modulus length', async () => {
      const keyPair = await generateRSAKeyPair('test-rsa-4096', 'RS256', 4096);
      expect(keyPair.publicKey).toBeDefined();
    });
  });

  describe('generateECKeyPair', () => {
    it('should generate ES256 key pair (P-256)', async () => {
      const keyPair = await generateECKeyPair('test-ec-256', 'ES256');
      
      expect(keyPair.kid).toBe('test-ec-256');
      expect(keyPair.algorithm).toBe('ES256');
      expect(keyPair.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(keyPair.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
    });

    it('should generate ES384 key pair (P-384)', async () => {
      const keyPair = await generateECKeyPair('test-ec-384', 'ES384');
      expect(keyPair.algorithm).toBe('ES384');
    });

    it('should generate ES512 key pair (P-521)', async () => {
      const keyPair = await generateECKeyPair('test-ec-512', 'ES512');
      expect(keyPair.algorithm).toBe('ES512');
    });
  });

  describe('generateKeyPair', () => {
    it('should auto-detect RSA algorithm', async () => {
      const keyPair = await generateKeyPair('auto-rsa', 'RS256');
      expect(keyPair.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
    });

    it('should auto-detect EC algorithm', async () => {
      const keyPair = await generateKeyPair('auto-ec', 'ES256');
      expect(keyPair.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
    });

    it('should default to RS256', async () => {
      const keyPair = await generateKeyPair('default-alg');
      expect(keyPair.algorithm).toBe('RS256');
    });
  });
});

describe('Signing and Verification', () => {
  let rsaKeyPair: JTSKeyPair;
  let ecKeyPair: JTSKeyPair;
  let psKeyPair: JTSKeyPair;
  const testData = 'test data to sign';

  beforeAll(async () => {
    rsaKeyPair = await generateRSAKeyPair('sign-test-rsa', 'RS256');
    ecKeyPair = await generateECKeyPair('sign-test-ec', 'ES256');
    psKeyPair = await generateRSAKeyPair('sign-test-ps', 'PS256');
  });

  describe('RSA Signing (RS256)', () => {
    it('should sign and verify data', () => {
      const signature = sign(testData, rsaKeyPair.privateKey!, 'RS256');
      const isValid = verify(testData, signature, rsaKeyPair.publicKey, 'RS256');
      expect(isValid).toBe(true);
    });

    it('should reject tampered data', () => {
      const signature = sign(testData, rsaKeyPair.privateKey!, 'RS256');
      const isValid = verify('tampered data', signature, rsaKeyPair.publicKey, 'RS256');
      expect(isValid).toBe(false);
    });

    it('should reject wrong public key', async () => {
      const signature = sign(testData, rsaKeyPair.privateKey!, 'RS256');
      const otherKey = await generateRSAKeyPair('other', 'RS256');
      const isValid = verify(testData, signature, otherKey.publicKey, 'RS256');
      expect(isValid).toBe(false);
    });
  });

  describe('ECDSA Signing (ES256)', () => {
    it('should sign and verify data', () => {
      const signature = sign(testData, ecKeyPair.privateKey!, 'ES256');
      const isValid = verify(testData, signature, ecKeyPair.publicKey, 'ES256');
      expect(isValid).toBe(true);
    });

    it('should produce correct signature length', () => {
      const signature = sign(testData, ecKeyPair.privateKey!, 'ES256');
      // ES256 signature is 64 bytes (32 + 32 for R||S format)
      expect(signature.length).toBe(64);
    });

    it('should reject tampered data', () => {
      const signature = sign(testData, ecKeyPair.privateKey!, 'ES256');
      const isValid = verify('tampered', signature, ecKeyPair.publicKey, 'ES256');
      expect(isValid).toBe(false);
    });
  });

  describe('RSA-PSS Signing (PS256)', () => {
    it('should sign and verify data', () => {
      const signature = sign(testData, psKeyPair.privateKey!, 'PS256');
      const isValid = verify(testData, signature, psKeyPair.publicKey, 'PS256');
      expect(isValid).toBe(true);
    });

    it('should reject tampered data', () => {
      const signature = sign(testData, psKeyPair.privateKey!, 'PS256');
      const isValid = verify('tampered', signature, psKeyPair.publicKey, 'PS256');
      expect(isValid).toBe(false);
    });
  });

  describe('All algorithm variations', () => {
    const algorithms: JTSAlgorithm[] = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];

    it.each(algorithms)('should sign and verify with %s', async (alg) => {
      const keyPair = await generateKeyPair(`test-${alg}`, alg);
      const signature = sign('test message', keyPair.privateKey!, alg);
      const isValid = verify('test message', signature, keyPair.publicKey, alg);
      expect(isValid).toBe(true);
    });
  });

  describe('Edge cases', () => {
    it('should handle Buffer input for data', () => {
      const bufferData = Buffer.from(testData);
      const signature = sign(bufferData, rsaKeyPair.privateKey!, 'RS256');
      const isValid = verify(bufferData, signature, rsaKeyPair.publicKey, 'RS256');
      expect(isValid).toBe(true);
    });

    it('should handle empty string', () => {
      const signature = sign('', rsaKeyPair.privateKey!, 'RS256');
      const isValid = verify('', signature, rsaKeyPair.publicKey, 'RS256');
      expect(isValid).toBe(true);
    });

    it('should handle large data', () => {
      const largeData = 'x'.repeat(100000);
      const signature = sign(largeData, rsaKeyPair.privateKey!, 'RS256');
      const isValid = verify(largeData, signature, rsaKeyPair.publicKey, 'RS256');
      expect(isValid).toBe(true);
    });

    it('should return false for invalid signature format', () => {
      const invalidSignature = Buffer.from('not a valid signature');
      const isValid = verify(testData, invalidSignature, rsaKeyPair.publicKey, 'RS256');
      expect(isValid).toBe(false);
    });
  });
});

describe('Encryption (JTS-C)', () => {
  let encryptionKeyPair: JTSKeyPair;

  beforeAll(async () => {
    encryptionKeyPair = await generateRSAKeyPair('enc-key', 'RS256', 2048);
  });

  describe('RSA-OAEP', () => {
    it('should encrypt and decrypt data', () => {
      const plaintext = Buffer.from('secret data');
      const encrypted = rsaEncrypt(plaintext, encryptionKeyPair.publicKey);
      const decrypted = rsaDecrypt(encrypted, encryptionKeyPair.privateKey!);
      expect(decrypted.toString()).toBe('secret data');
    });

    it('should produce different ciphertext each time (randomized)', () => {
      const plaintext = Buffer.from('test');
      const enc1 = rsaEncrypt(plaintext, encryptionKeyPair.publicKey);
      const enc2 = rsaEncrypt(plaintext, encryptionKeyPair.publicKey);
      expect(enc1).not.toEqual(enc2);
    });

    it('should fail with wrong private key', async () => {
      const plaintext = Buffer.from('secret');
      const encrypted = rsaEncrypt(plaintext, encryptionKeyPair.publicKey);
      const otherKey = await generateRSAKeyPair('other-enc', 'RS256');
      expect(() => rsaDecrypt(encrypted, otherKey.privateKey!)).toThrow();
    });
  });

  describe('AES-GCM', () => {
    it('should encrypt and decrypt with tag', () => {
      const key = generateCEK(32);
      const iv = generateIV(12);
      const plaintext = Buffer.from('Hello, AES-GCM!');

      const { ciphertext, tag } = aesGcmEncrypt(plaintext, key, iv);
      const decrypted = aesGcmDecrypt(ciphertext, key, iv, tag);

      expect(decrypted.toString()).toBe('Hello, AES-GCM!');
    });

    it('should encrypt and decrypt with AAD', () => {
      const key = generateCEK(32);
      const iv = generateIV(12);
      const plaintext = Buffer.from('Protected data');
      const aad = Buffer.from('additional authenticated data');

      const { ciphertext, tag } = aesGcmEncrypt(plaintext, key, iv, aad);
      const decrypted = aesGcmDecrypt(ciphertext, key, iv, tag, aad);

      expect(decrypted.toString()).toBe('Protected data');
    });

    it('should fail with wrong key', () => {
      const key = generateCEK(32);
      const wrongKey = generateCEK(32);
      const iv = generateIV(12);
      const plaintext = Buffer.from('test');

      const { ciphertext, tag } = aesGcmEncrypt(plaintext, key, iv);
      expect(() => aesGcmDecrypt(ciphertext, wrongKey, iv, tag)).toThrow();
    });

    it('should fail with wrong IV', () => {
      const key = generateCEK(32);
      const iv = generateIV(12);
      const wrongIv = generateIV(12);
      const plaintext = Buffer.from('test');

      const { ciphertext, tag } = aesGcmEncrypt(plaintext, key, iv);
      expect(() => aesGcmDecrypt(ciphertext, key, wrongIv, tag)).toThrow();
    });

    it('should fail with wrong tag', () => {
      const key = generateCEK(32);
      const iv = generateIV(12);
      const plaintext = Buffer.from('test');

      const { ciphertext } = aesGcmEncrypt(plaintext, key, iv);
      const wrongTag = Buffer.alloc(16);
      expect(() => aesGcmDecrypt(ciphertext, key, iv, wrongTag)).toThrow();
    });

    it('should fail if AAD mismatches', () => {
      const key = generateCEK(32);
      const iv = generateIV(12);
      const plaintext = Buffer.from('test');
      const aad = Buffer.from('correct aad');
      const wrongAad = Buffer.from('wrong aad');

      const { ciphertext, tag } = aesGcmEncrypt(plaintext, key, iv, aad);
      expect(() => aesGcmDecrypt(ciphertext, key, iv, tag, wrongAad)).toThrow();
    });
  });

  describe('Key/IV Generation', () => {
    it('should generate CEK of correct length', () => {
      const cek16 = generateCEK(16);
      const cek32 = generateCEK(32);
      expect(cek16.length).toBe(16);
      expect(cek32.length).toBe(32);
    });

    it('should generate IV of correct length', () => {
      const iv12 = generateIV(12);
      const iv16 = generateIV(16);
      expect(iv12.length).toBe(12);
      expect(iv16.length).toBe(16);
    });

    it('should generate unique values', () => {
      const cek1 = generateCEK(32);
      const cek2 = generateCEK(32);
      expect(cek1).not.toEqual(cek2);
    });
  });
});

describe('Random & Hash Utilities', () => {
  describe('generateRandomString', () => {
    it('should generate string of approximately correct length', () => {
      const str = generateRandomString(32);
      // Base64url encoding adds ~33% to size
      expect(str.length).toBeGreaterThanOrEqual(32);
    });

    it('should generate unique strings', () => {
      const str1 = generateRandomString(32);
      const str2 = generateRandomString(32);
      expect(str1).not.toBe(str2);
    });

    it('should only contain URL-safe characters', () => {
      const str = generateRandomString(100);
      expect(str).toMatch(/^[A-Za-z0-9_-]+$/);
    });
  });

  describe('generateTokenId', () => {
    it('should generate token ID with prefix', () => {
      const tokenId = generateTokenId();
      expect(tokenId).toMatch(/^tkn_/);
    });

    it('should generate unique IDs', () => {
      const ids = new Set(Array.from({ length: 100 }, () => generateTokenId()));
      expect(ids.size).toBe(100);
    });
  });

  describe('generateAnchorId', () => {
    it('should generate anchor ID with prefix', () => {
      const anchorId = generateAnchorId();
      expect(anchorId).toMatch(/^aid_/);
    });

    it('should generate unique IDs', () => {
      const ids = new Set(Array.from({ length: 100 }, () => generateAnchorId()));
      expect(ids.size).toBe(100);
    });
  });

  describe('generateStateProof', () => {
    it('should generate StateProof with prefix', () => {
      const sp = generateStateProof();
      expect(sp).toMatch(/^sp_/);
    });

    it('should generate unique StateProofs', () => {
      const sps = new Set(Array.from({ length: 100 }, () => generateStateProof()));
      expect(sps.size).toBe(100);
    });
  });

  describe('sha256', () => {
    it('should produce 32-byte hash', () => {
      const hash = sha256('test');
      expect(hash.length).toBe(32);
    });

    it('should produce consistent hash', () => {
      const hash1 = sha256('hello');
      const hash2 = sha256('hello');
      expect(hash1).toEqual(hash2);
    });

    it('should produce different hashes for different inputs', () => {
      const hash1 = sha256('hello');
      const hash2 = sha256('world');
      expect(hash1).not.toEqual(hash2);
    });

    it('should handle empty string', () => {
      const hash = sha256('');
      expect(hash.length).toBe(32);
    });
  });

  describe('sha256Hex', () => {
    it('should produce 64-character hex string', () => {
      const hash = sha256Hex('test');
      expect(hash.length).toBe(64);
      expect(hash).toMatch(/^[0-9a-f]+$/);
    });

    it('should match known hash', () => {
      const hash = sha256Hex('test');
      expect(hash).toBe('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
    });
  });

  describe('createDeviceFingerprint', () => {
    it('should create fingerprint with sha256 prefix', () => {
      const fp = createDeviceFingerprint({
        userAgent: 'Mozilla/5.0',
        screenResolution: '1920x1080',
      });
      expect(fp).toMatch(/^sha256:[0-9a-f]{32}$/);
    });

    it('should be consistent for same components', () => {
      const components = { userAgent: 'test', timezone: 'UTC' };
      const fp1 = createDeviceFingerprint(components);
      const fp2 = createDeviceFingerprint(components);
      expect(fp1).toBe(fp2);
    });

    it('should ignore undefined values', () => {
      const fp1 = createDeviceFingerprint({ userAgent: 'test' });
      const fp2 = createDeviceFingerprint({ userAgent: 'test', screenResolution: undefined });
      expect(fp1).toBe(fp2);
    });

    it('should produce different fingerprints for different components', () => {
      const fp1 = createDeviceFingerprint({ userAgent: 'Chrome' });
      const fp2 = createDeviceFingerprint({ userAgent: 'Firefox' });
      expect(fp1).not.toBe(fp2);
    });
  });
});

describe('JWKS Utilities', () => {
  let rsaKeyPair: JTSKeyPair;
  let ecKeyPair: JTSKeyPair;

  beforeAll(async () => {
    rsaKeyPair = await generateRSAKeyPair('jwks-rsa', 'RS256');
    ecKeyPair = await generateECKeyPair('jwks-ec', 'ES256');
  });

  describe('pemToJwk', () => {
    it('should convert RSA PEM to JWK', () => {
      const jwk = pemToJwk(rsaKeyPair.publicKey, rsaKeyPair.kid, 'RS256');
      
      expect(jwk.kty).toBe('RSA');
      expect(jwk.kid).toBe('jwks-rsa');
      expect(jwk.use).toBe('sig');
      expect(jwk.alg).toBe('RS256');
      expect(jwk.n).toBeDefined();
      expect(jwk.e).toBeDefined();
    });

    it('should convert EC PEM to JWK', () => {
      const jwk = pemToJwk(ecKeyPair.publicKey, ecKeyPair.kid, 'ES256');
      
      expect(jwk.kty).toBe('EC');
      expect(jwk.kid).toBe('jwks-ec');
      expect(jwk.use).toBe('sig');
      expect(jwk.alg).toBe('ES256');
      expect(jwk.crv).toBe('P-256');
      expect(jwk.x).toBeDefined();
      expect(jwk.y).toBeDefined();
    });

    it('should handle ES384 curve', async () => {
      const ec384 = await generateECKeyPair('ec384', 'ES384');
      const jwk = pemToJwk(ec384.publicKey, ec384.kid, 'ES384');
      expect(jwk.crv).toBe('P-384');
    });

    it('should handle ES512 curve', async () => {
      const ec512 = await generateECKeyPair('ec512', 'ES512');
      const jwk = pemToJwk(ec512.publicKey, ec512.kid, 'ES512');
      expect(jwk.crv).toBe('P-521');
    });
  });

  describe('jwkToPem', () => {
    it('should convert RSA JWK back to PEM', () => {
      const jwk = pemToJwk(rsaKeyPair.publicKey, rsaKeyPair.kid, 'RS256');
      const pem = jwkToPem(jwk);
      
      expect(pem).toContain('-----BEGIN PUBLIC KEY-----');
      // Verify the converted key works for verification
      const signature = sign('test', rsaKeyPair.privateKey!, 'RS256');
      const isValid = verify('test', signature, pem, 'RS256');
      expect(isValid).toBe(true);
    });

    it('should convert EC JWK back to PEM', () => {
      const jwk = pemToJwk(ecKeyPair.publicKey, ecKeyPair.kid, 'ES256');
      const pem = jwkToPem(jwk);
      
      expect(pem).toContain('-----BEGIN PUBLIC KEY-----');
      // Verify the converted key works for verification
      const signature = sign('test', ecKeyPair.privateKey!, 'ES256');
      const isValid = verify('test', signature, pem, 'ES256');
      expect(isValid).toBe(true);
    });
  });

  describe('keyPairToJwks', () => {
    it('should convert multiple key pairs to JWKS', () => {
      const jwks = keyPairToJwks([rsaKeyPair, ecKeyPair]);
      
      expect(jwks.keys).toHaveLength(2);
      expect(jwks.keys[0].kid).toBe('jwks-rsa');
      expect(jwks.keys[1].kid).toBe('jwks-ec');
    });

    it('should include expiration if set', () => {
      const keyWithExpiry: JTSKeyPair = {
        ...rsaKeyPair,
        kid: 'expiring-key',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      };
      
      const jwks = keyPairToJwks([keyWithExpiry]);
      expect(jwks.keys[0].exp).toBe(keyWithExpiry.expiresAt);
    });

    it('should handle empty array', () => {
      const jwks = keyPairToJwks([]);
      expect(jwks.keys).toHaveLength(0);
    });
  });
});
